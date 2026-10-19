/* Copyright (C) 2026 Chris Burdess <dog@gnu.org>

   This file is part of twist.

   twist is free software: you can redistribute it and/or modify it
   under the terms of the GNU General Public License as published
   by the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.

   twist is distributed in the hope that it will be useful, but
   WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   General Public License for more details.

   You should have received a copy of the GNU General Public
   License along with this program.  If not, see
   <https://www.gnu.org/licenses/>.  */

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include "check.h"
#include "twist-int.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct dns_saw
{
  int addrs;
  int tc;
  int nalpn;
  char alpn[4][16];
  int port;
  int err;
};

static void
saw_addr (void *user, const struct twist_dns_addr *addr)
{
  (void) addr;
  ((struct dns_saw *) user)->addrs++;
}

static void
saw_alpn (void *user, const char *id, size_t len)
{
  struct dns_saw *s = user;

  if (s->nalpn >= 4 || len >= 16)
    return;
  memcpy (s->alpn[s->nalpn], id, len);
  s->alpn[s->nalpn][len] = 0;
  s->nalpn++;
}

static void
saw_port (void *user, int port)
{
  ((struct dns_saw *) user)->port = port;
}

static void
saw_tc (void *user)
{
  ((struct dns_saw *) user)->tc = 1;
}

static void
saw_fail (void *user, int err)
{
  ((struct dns_saw *) user)->err = err;
}

static void
feed_stream (const uint8_t *msg, size_t n, size_t step, struct dns_saw *saw)
{
  uint8_t window[512];
  size_t have = 0;
  size_t off = 0;
  struct twist_dns_events ev;

  memset (&ev, 0, sizeof ev);
  ev.user = saw;
  ev.address = saw_addr;
  ev.https_alpn = saw_alpn;
  ev.https_port = saw_port;
  ev.truncated = saw_tc;
  ev.failure = saw_fail;
  while (off < n)
    {
      size_t chunk = step;
      size_t i;
      if (chunk > n - off)
        chunk = n - off;
      for (i = 0; i < chunk; i++)
        window[have++] = msg[off++];
      for (;;)
        {
          size_t c = twist_dns_stream_receive (window, have, &ev);
          if (c == 0)
            break;
          memmove (window, window + c, have - c);
          have -= c;
        }
    }
}

static void
test_dns (void)
{
  uint8_t *q = NULL;
  size_t qlen = 0;
  uint8_t *msg;
  struct twist_dns_addr *addrs = NULL;
  size_t n = 0;
  const char *name = "example.com";

  check (twist_dns_encode_query (name, 1, 0x1234, &q, &qlen) == TWIST_OK, "q");
  check (q != NULL && qlen > 12 && q[0] == 0x12 && q[1] == 0x34, "id");
  msg = realloc (q, qlen + 16);
  check (msg != NULL, "grow");
  msg[2] = 0x81;
  msg[3] = 0x80;
  msg[6] = 0;
  msg[7] = 1;
  msg[qlen + 0] = 0xc0;
  msg[qlen + 1] = 0x0c;
  msg[qlen + 2] = 0;
  msg[qlen + 3] = 1;
  msg[qlen + 4] = 0;
  msg[qlen + 5] = 1;
  msg[qlen + 6] = 0;
  msg[qlen + 7] = 0;
  msg[qlen + 8] = 0;
  msg[qlen + 9] = 0;
  msg[qlen + 10] = 0;
  msg[qlen + 11] = 4;
  msg[qlen + 12] = 93;
  msg[qlen + 13] = 184;
  msg[qlen + 14] = 216;
  msg[qlen + 15] = 34;
  check (twist_dns_decode (msg, qlen + 16, 1, &addrs, &n) == TWIST_OK, "dec");
  check (n == 1 && strcmp (addrs[0].text, "93.184.216.34") == 0, "addr");
  free (addrs);
  {
    uint8_t *framed = NULL;
    struct dns_saw saw;
    struct twist_dns_events ev;
    size_t flen = qlen + 16;
    size_t step;
    static const uint8_t https[] = {
      0x00, 0x01, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
      0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0x03, 'c', 'o', 'm', 0x00,
      0x00, 0x41, 0x00, 0x01,
      0xc0, 0x0c, 0x00, 0x41, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0d,
      0x00, 0x01, 0x00, 0x00, 0x01, 0x00, 0x06, 0x02, 'h', '3', 0x02, 'h', '2'
    };
    int plan[4];
    int order[4];
    int custom[2];
    size_t np = 0;
    const char *ids[2];

    framed = malloc (flen + 2 > sizeof https + 2 ? flen + 2
                     : sizeof https + 2);
    check (framed != NULL, "frame");
    if (framed == NULL)
      {
        free (msg);
        return;
      }
    framed[0] = (uint8_t) (flen >> 8);
    framed[1] = (uint8_t) flen;
    memcpy (framed + 2, msg, flen);
    for (step = 1; step <= flen + 2; step++)
      {
        memset (&saw, 0, sizeof saw);
        feed_stream (framed, flen + 2, step, &saw);
        check (saw.addrs == 1 && saw.err == 0, "stream split");
      }
    msg[2] = (uint8_t) (msg[2] | 0x02);
    memset (&saw, 0, sizeof saw);
    memset (&ev, 0, sizeof ev);
    ev.user = &saw;
    ev.address = saw_addr;
    ev.truncated = saw_tc;
    ev.failure = saw_fail;
    check (twist_dns_datagram_receive (msg, flen, &ev) == flen, "dgram");
    check (saw.tc == 1 && saw.addrs == 1, "tc");
    memset (&saw, 0, sizeof saw);
    framed[0] = 0;
    framed[1] = (uint8_t) sizeof https;
    memcpy (framed + 2, https, sizeof https);
    for (step = 1; step <= sizeof https + 2; step++)
      {
        memset (&saw, 0, sizeof saw);
        feed_stream (framed, sizeof https + 2, step, &saw);
        check (saw.nalpn == 2 && strcmp (saw.alpn[0], "h3") == 0
               && strcmp (saw.alpn[1], "h2") == 0, "https alpn");
      }
    check (twist_dns_transport_plan (NULL, 0, order, 4, &np) == TWIST_OK
           && np == 4 && order[0] == TWIST_DNS_DOQ && order[1] == TWIST_DNS_DOT
           && order[2] == TWIST_DNS_DOH && order[3] == TWIST_DNS_UDP,
           "dns default");
    custom[0] = TWIST_DNS_UDP;
    custom[1] = TWIST_DNS_DOQ;
    check (twist_dns_transport_plan (custom, 2, order, 4, &np) == TWIST_OK
           && np == 2 && order[0] == TWIST_DNS_UDP && order[1] == TWIST_DNS_DOQ,
           "dns override");
    check (twist_dns_parse_order ("gssapi", order, 4, &np) != TWIST_OK,
           "dns bad");
    ids[0] = "h2";
    (void) ids;
    (void) plan;
    check (twist_http_discover (TWIST_HTTP_VERSION_NONE, 1, 1, 1, 0, &plan[0])
           == TWIST_OK && plan[0] == TWIST_DISC_H3, "h3 from https rr");
    check (twist_http_discover (TWIST_HTTP_VERSION_NONE, 1, 0, 0, 0, &plan[0])
           == TWIST_OK && plan[0] == TWIST_DISC_ALPN, "no rr is alpn");
    check (twist_http_discover (TWIST_HTTP_VERSION_NONE, 1, 0, 0, 1, &plan[0])
           == TWIST_OK && plan[0] == TWIST_DISC_H3, "cached alt-svc h3");
    check (twist_http_discover (TWIST_HTTP_VERSION_NONE, 1, 0, 0, -1, &plan[0])
           == TWIST_OK && plan[0] == TWIST_DISC_ALPN, "h3 given up");
    check (twist_http_discover (TWIST_HTTP_VERSION_NONE, 1, 1, 0, 1, &plan[0])
           == TWIST_OK && plan[0] == TWIST_DISC_ALPN, "rr without h3");
    check (twist_http_discover (TWIST_HTTP_VERSION_NONE, 0, 0, 0, 0, &plan[0])
           == TWIST_OK && plan[0] == TWIST_DISC_H2C, "cleartext h2c");
    check (twist_http_discover (TWIST_HTTP_VERSION_2_PRIOR_KNOWLEDGE, 0, 0, 0,
                                0, &plan[0]) == TWIST_OK
           && plan[0] == TWIST_DISC_H2_PRIOR, "prior knowledge");
    check (twist_http_discover (TWIST_HTTP_VERSION_2_0, 1, 1, 1, 0, &plan[0])
           == TWIST_OK && plan[0] == TWIST_DISC_ALPN, "http2 stays alpn");
    check (twist_http_discover (TWIST_HTTP_VERSION_1_0, 1, 1, 1, 0, &plan[0])
           == TWIST_OK && plan[0] == TWIST_DISC_H1, "pin 1.0");
    check (twist_http_discover (TWIST_HTTP_VERSION_3ONLY, 0, 0, 0, 0, &plan[0])
           == TWIST_OK && plan[0] == TWIST_DISC_H3, "pin h3");
    check (twist_alt_svc_h3 ("h3=\":443\"; ma=60", 16, &plan[1], &plan[2]) == 1
           && plan[1] == 443 && plan[2] == 0, "alt-svc h3");
    check (twist_alt_svc_h3 ("clear", 5, &plan[1], &plan[2]) == 0
           && plan[2] == 1, "alt-svc clear");
    check (twist_alt_svc_h3 ("h2=\":443\"", 9, &plan[1], &plan[2]) == 0
           && plan[2] == 0, "alt-svc no h3");
    free (framed);
  }
  free (msg);
}

struct doh_saw
{
  int calls;
  int err;
  char text[64];
};

static int
bytes_have (const uint8_t *buf, size_t n, const char *lit)
{
  size_t ln = strlen (lit);
  size_t i;

  if (ln > n)
    return 0;
  for (i = 0; i + ln <= n; i++)
    if (memcmp (buf + i, lit, ln) == 0)
      return 1;
  return 0;
}

static void
on_literal (void *user, int err, const struct twist_dns_addr *addr)
{
  struct doh_saw *saw = user;

  saw->calls++;
  saw->err = err;
  saw->text[0] = 0;
  if (err == TWIST_OK && addr != NULL)
    snprintf (saw->text, sizeof saw->text, "%s", addr->text);
}

static void
on_doh_test (void *user, int err, const uint8_t *msg, size_t len)
{
  struct doh_saw *saw = user;
  struct twist_dns_addr *addrs = NULL;
  size_t n = 0;

  saw->calls++;
  saw->err = err;
  saw->text[0] = 0;
  if (err == TWIST_OK
      && twist_dns_decode (msg, len, 1, &addrs, &n) == TWIST_OK && n == 1)
    snprintf (saw->text, sizeof saw->text, "%s", addrs[0].text);
  free (addrs);
}

static int
feed_doh (struct twist_doh *d, const uint8_t *data, size_t len, size_t step)
{
  size_t off = 0;

  while (off < len)
    {
      size_t n = len - off;
      size_t got;

      if (n > step)
        n = step;
      got = twist_doh_receive (d, data + off, n);
      if (got == 0 || got > n)
        return 0;
      off += got;
    }
  return 1;
}

static void
test_doh (void)
{
  uint8_t *q = NULL;
  size_t qlen = 0;
  uint8_t *msg;
  uint8_t *http = NULL;
  size_t hlen = 0;
  uint8_t query[12];
  char head[160];
  uint8_t *resp = NULL;
  size_t rlen;
  struct doh_saw saw;
  struct twist_doh *doh;
  twist_easy *easy;
  int plan[4];
  int custom[2];
  size_t np = 0;
  int wr;
  size_t step;
  static const char not_found[] =
    "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n";

  memset (query, 0, sizeof query);
  check (twist_doh_encode_url ("http://dns.example/dns-query", query,
                               sizeof query, &http, &hlen) == TWIST_ERR_URL,
         "doh http");
  check (twist_doh_encode_url ("https://dns.example/dns-query?name=example.com",
                               query, sizeof query, &http, &hlen) == TWIST_OK,
         "doh post");
  check (http != NULL
         && bytes_have (http, hlen,
                        "POST /dns-query?name=example.com HTTP/1.1\r\n")
         && bytes_have (http, hlen, "Host: dns.example\r\n")
         && bytes_have (http, hlen, "Accept: application/dns-message\r\n")
         && bytes_have (http, hlen, "Content-Type: application/dns-message\r\n")
         && hlen >= sizeof query
         && memcmp (http + hlen - sizeof query, query, sizeof query) == 0,
         "doh bytes");
  free (http);
  http = NULL;
  check (twist_doh_encode_url ("https://dns.example:8443/dns-query", query,
                               sizeof query, &http, &hlen) == TWIST_OK
         && bytes_have (http, hlen, "Host: dns.example:8443\r\n"),
         "doh port");
  free (http);
  custom[0] = TWIST_DNS_UDP;
  custom[1] = TWIST_DNS_DOQ;
  check (twist_dns_plan_for (NULL, 0, 1, plan, 4, &np) == TWIST_OK
         && np == 1 && plan[0] == TWIST_DNS_DOH, "doh replaces");
  check (twist_dns_plan_for (custom, 2, 1, plan, 4, &np) == TWIST_OK
         && np == 2 && plan[0] == TWIST_DNS_UDP && plan[1] == TWIST_DNS_DOQ,
         "doh keeps order");
  check (twist_dns_bootstrap_plan (NULL, 0, plan, 4, &np) == TWIST_OK
         && np == 3 && plan[0] == TWIST_DNS_DOQ && plan[1] == TWIST_DNS_DOT
         && plan[2] == TWIST_DNS_UDP, "doh bootstrap");
  custom[0] = TWIST_DNS_DOH;
  check (twist_dns_bootstrap_plan (custom, 1, plan, 4, &np) == TWIST_OK
         && np == 1 && plan[0] == TWIST_DNS_UDP, "doh bootstrap udp");
  easy = twist_easy_init ();
  check (easy != NULL && easy->doh_verifypeer == 1, "doh verify default");
  twist_easy_setopt (easy, TWISTOPT_SSL_VERIFYPEER, 0L);
  check (easy->doh_verifypeer == 1, "doh ignores insecure");
  twist_easy_setopt (easy, TWISTOPT_DOH_SSL_VERIFYPEER, 0L);
  check (easy->doh_verifypeer == 0, "doh insecure");
  twist_easy_setopt (easy, TWISTOPT_DOH_URL, "https://dns.example/dns-query");
  check (easy->doh_url != NULL
         && strcmp (easy->doh_url, "https://dns.example/dns-query") == 0,
         "doh url");
  twist_easy_setopt (easy, TWISTOPT_DOH_URL, "");
  check (easy->doh_url == NULL, "doh url clear");
  twist_easy_setopt (easy, TWISTOPT_DOH_URL, "https://192.0.2.1/dns-query");
  memset (&saw, 0, sizeof saw);
  check (twist_dns_resolve_easy (easy, "192.0.2.10", on_literal, &saw) == TWIST_OK
         && saw.calls == 1 && saw.err == TWIST_OK
         && strcmp (saw.text, "192.0.2.10") == 0, "v4 needs no lookup");
  memset (&saw, 0, sizeof saw);
  check (twist_dns_resolve_easy (easy, "2001:db8::1", on_literal, &saw) == TWIST_OK
         && saw.calls == 1 && saw.err == TWIST_OK
         && strcmp (saw.text, "2001:db8::1") == 0, "v6 needs no lookup");
  twist_easy_cleanup (easy);

  check (twist_dns_encode_query ("example.com", 1, 0x1234, &q, &qlen) == TWIST_OK,
         "doh q");
  msg = realloc (q, qlen + 16);
  check (msg != NULL, "doh grow");
  if (msg == NULL)
    return;
  msg[2] = 0x81;
  msg[3] = 0x80;
  msg[6] = 0;
  msg[7] = 1;
  msg[qlen + 0] = 0xc0;
  msg[qlen + 1] = 0x0c;
  msg[qlen + 2] = 0;
  msg[qlen + 3] = 1;
  msg[qlen + 4] = 0;
  msg[qlen + 5] = 1;
  msg[qlen + 6] = 0;
  msg[qlen + 7] = 0;
  msg[qlen + 8] = 0;
  msg[qlen + 9] = 0;
  msg[qlen + 10] = 0;
  msg[qlen + 11] = 4;
  msg[qlen + 12] = 93;
  msg[qlen + 13] = 184;
  msg[qlen + 14] = 216;
  msg[qlen + 15] = 34;
  wr = snprintf (head, sizeof head,
                 "HTTP/1.1 200 OK\r\n"
                 "Content-Type: application/dns-message\r\n"
                 "Content-Length: %zu\r\n\r\n",
                 qlen + 16);
  check (wr > 0, "doh head");
  rlen = (size_t) wr + qlen + 16;
  resp = malloc (rlen);
  check (resp != NULL, "doh resp");
  if (resp == NULL)
    {
      free (msg);
      return;
    }
  memcpy (resp, head, (size_t) wr);
  memcpy (resp + wr, msg, qlen + 16);
  free (msg);
  memset (&saw, 0, sizeof saw);
  doh = twist_doh_new (on_doh_test, &saw);
  check (doh != NULL, "doh new");
  for (step = 1; step <= rlen; step++)
    {
      saw.calls = 0;
      saw.err = -1;
      saw.text[0] = 0;
      check (feed_doh (doh, resp, rlen, step), "doh feed");
      check (saw.calls == 1 && saw.err == TWIST_OK
             && strcmp (saw.text, "93.184.216.34") == 0, "doh answer");
    }
  saw.calls = 0;
  check (feed_doh (doh, (const uint8_t *) not_found, sizeof not_found - 1, 1),
         "doh 404 feed");
  check (saw.calls == 1 && saw.err == TWIST_ERR_RESOLVE, "doh 404");
  twist_doh_free (doh);
  free (resp);
}

struct svcb_saw
{
  int n;
  char target[64];
  char alpn[4][8];
  int nalpn;
  int port;
  int family;
  unsigned char addr[4];
};

static void
saw_svcb (void *user, const char *target, const char *alpn, size_t alpn_len,
          int port, int family, const uint8_t *hint)
{
  struct svcb_saw *s = user;

  if (s->n == 0 && target != NULL)
    {
      snprintf (s->target, sizeof s->target, "%s", target);
      s->port = port;
      s->family = family;
      if (family == 4 && hint != NULL)
        memcpy (s->addr, hint, 4);
    }
  if (s->nalpn < 4 && alpn_len < 8)
    {
      memcpy (s->alpn[s->nalpn], alpn, alpn_len);
      s->alpn[s->nalpn][alpn_len] = 0;
      s->nalpn++;
    }
  s->n++;
}

static void
test_svcb (void)
{
  static const uint8_t msg[] = {
    0x00, 0x03, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
    0x04, '_', 'd', 'n', 's', 0x08, 'r', 'e', 's', 'o', 'l', 'v', 'e', 'r',
    0x04, 'a', 'r', 'p', 'a', 0x00, 0x00, 0x40, 0x00, 0x01,
    0xc0, 0x0c, 0x00, 0x40, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x28,
    0x00, 0x01,
    0x03, 'd', 'n', 's', 0x06, 'g', 'o', 'o', 'g', 'l', 'e', 0x00,
    0x00, 0x01, 0x00, 0x08, 0x03, 'd', 'o', 'q', 0x03, 'd', 'o', 't',
    0x00, 0x03, 0x00, 0x02, 0x03, 0x55,
    0x00, 0x04, 0x00, 0x04, 8, 8, 8, 8
  };
  static const uint8_t alias[] = {
    0x00, 0x03, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
    0x04, '_', 'd', 'n', 's', 0x08, 'r', 'e', 's', 'o', 'l', 'v', 'e', 'r',
    0x04, 'a', 'r', 'p', 'a', 0x00, 0x00, 0x40, 0x00, 0x01,
    0xc0, 0x0c, 0x00, 0x40, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03,
    0x00, 0x00, 0x00
  };
  uint8_t framed[sizeof msg + 2];
  uint8_t window[sizeof msg + 2];
  struct svcb_saw saw;
  struct twist_dns_events ev;
  struct twist_easy *easy;
  uint8_t raw[12];
  uint8_t *out = NULL;
  size_t outlen = 0;
  size_t step;

  memset (raw, 0, sizeof raw);
  raw[0] = 0x12;
  raw[1] = 0x34;
  check (twist_dns_frame_stream (raw, sizeof raw, 1, &out, &outlen) == TWIST_OK
         && outlen == 14 && out[0] == 0 && out[1] == 12 && out[2] == 0
         && out[3] == 0, "doq id");
  free (out);
  memset (&saw, 0, sizeof saw);
  memset (&ev, 0, sizeof ev);
  ev.user = &saw;
  ev.svcb = saw_svcb;
  check (twist_dns_datagram_receive (msg, sizeof msg, &ev) == sizeof msg,
         "svcb dgram");
  check (saw.n == 2 && strcmp (saw.target, "dns.google") == 0
         && strcmp (saw.alpn[0], "doq") == 0 && strcmp (saw.alpn[1], "dot") == 0
         && saw.port == 853 && saw.family == 4 && saw.addr[0] == 8
         && saw.addr[3] == 8, "svcb fields");
  framed[0] = 0;
  framed[1] = (uint8_t) sizeof msg;
  memcpy (framed + 2, msg, sizeof msg);
  for (step = 1; step <= sizeof framed; step++)
    {
      size_t have = 0;
      size_t off = 0;

      memset (&saw, 0, sizeof saw);
      while (off < sizeof framed)
        {
          size_t chunk = step;
          size_t i;
          if (chunk > sizeof framed - off)
            chunk = sizeof framed - off;
          for (i = 0; i < chunk; i++)
            window[have++] = framed[off++];
          for (;;)
            {
              size_t c = twist_dns_stream_receive (window, have, &ev);
              if (c == 0)
                break;
              memmove (window, window + c, have - c);
              have -= c;
            }
        }
      check (saw.n == 2 && strcmp (saw.alpn[0], "doq") == 0
             && strcmp (saw.alpn[1], "dot") == 0, "svcb split");
    }
  memset (&saw, 0, sizeof saw);
  check (twist_dns_datagram_receive (alias, sizeof alias, &ev) == sizeof alias
         && saw.n == 0, "svcb alias");
  easy = twist_easy_init ();
  check (easy != NULL, "resolver easy");
  check (twist_easy_setopt (easy, TWISTOPT_DOQ_URL, "quic://dns.example:8853")
         == TWIST_OK && easy->doq_url != NULL
         && strcmp (easy->doq_url, "quic://dns.example:8853") == 0, "doq url");
  check (twist_easy_setopt (easy, TWISTOPT_DOT_URL, "dns.example") == TWIST_OK
         && strcmp (easy->dot_url, "dns.example") == 0, "dot url");
  check (twist_easy_setopt (easy, TWISTOPT_DOQ_URL, "") == TWIST_OK
         && easy->doq_url == NULL, "doq clear");
  check (twist_easy_setopt (easy, TWISTOPT_DOT_URL, "") == TWIST_OK
         && easy->dot_url == NULL, "dot clear");
  twist_easy_cleanup (easy);
}

static int dns_wait_n;
static int dns_wait_err;
static char dns_wait_text[64];

static void
on_dns_wait (void *user, int err, const struct twist_dns_addr *addr)
{
  (void) user;
  dns_wait_n++;
  dns_wait_err = err;
  dns_wait_text[0] = 0;
  if (addr != NULL)
    snprintf (dns_wait_text, sizeof dns_wait_text, "%s", addr->text);
}

static int
dns_a_msg (const char *name, uint32_t ttl, uint8_t *out, size_t cap,
           size_t *len)
{
  uint8_t *q = NULL;
  size_t qlen = 0;
  size_t n;

  if (twist_dns_encode_query (name, 1, 1, &q, &qlen) != TWIST_OK)
    return -1;
  if (qlen + 16 > cap)
    {
      free (q);
      return -1;
    }
  memcpy (out, q, qlen);
  free (q);
  out[6] = 0;
  out[7] = 1;
  n = qlen;
  out[n++] = 0xc0;
  out[n++] = 0x0c;
  out[n++] = 0x00;
  out[n++] = 0x01;
  out[n++] = 0x00;
  out[n++] = 0x01;
  out[n++] = (uint8_t) (ttl >> 24);
  out[n++] = (uint8_t) (ttl >> 16);
  out[n++] = (uint8_t) (ttl >> 8);
  out[n++] = (uint8_t) ttl;
  out[n++] = 0x00;
  out[n++] = 0x04;
  out[n++] = 192;
  out[n++] = 0;
  out[n++] = 2;
  out[n++] = 1;
  *len = n;
  return 0;
}

static void
test_dns_cache (void)
{
  struct twist_dns_cache *cache = twist_dns_cache_new ();
  uint8_t msg[128];
  size_t len = 0;
  struct twist_dns_addr hit;
  struct twist_dns_addr again;
  int st;
  int i;

  check (cache != NULL, "dns cache");
  check (dns_a_msg ("example.com", 60, msg, sizeof msg, &len) == 0, "dns msg");
  check (twist_dns_cache_put_msg (cache, "example.com", 1, msg, len, 1000)
         == TWIST_OK, "dns store");
  memset (&hit, 0, sizeof hit);
  check (twist_dns_cache_get (cache, "example.com", 1, &hit, 1000) == 1
         && strcmp (hit.text, "192.0.2.1") == 0, "dns hit");
  check (twist_dns_cache_get (cache, "example.com", 1, &hit, 1000 + 60000)
         == 0, "dns expired");
  check (dns_a_msg ("example.com", 30, msg, sizeof msg, &len) == 0, "dns msg 2");
  check (twist_dns_cache_put_msg (cache, "Example.COM", 1, msg, len, 5000)
         == TWIST_OK, "dns store fold");
  dns_wait_n = 0;
  st = twist_dns_cache_begin (cache, NULL, "other.test", 1, on_dns_wait, NULL,
                              5000, &again);
  check (st == 0, "dns lead");
  st = twist_dns_cache_begin (cache, NULL, "other.test", 1, on_dns_wait, NULL,
                              5000, &again);
  check (st == 1 && dns_wait_n == 0, "dns singleflight");
  memset (&hit, 0, sizeof hit);
  hit.family = 4;
  hit.addr[0] = 192;
  hit.addr[3] = 9;
  snprintf (hit.text, sizeof hit.text, "192.0.0.9");
  twist_dns_cache_end (cache, NULL, "other.test", 1, TWIST_OK, &hit, 10, 8000);
  check (dns_wait_n == 1 && dns_wait_err == TWIST_OK
         && strcmp (dns_wait_text, "192.0.0.9") == 0, "dns waiter");
  check (twist_dns_cache_get (cache, "other.test", 1, &again, 8000) == 1,
         "dns after end");
  for (i = 0; i < 257; i++)
    {
      char name[32];
      uint8_t one[128];
      size_t n = 0;

      snprintf (name, sizeof name, "n%d.example", i);
      check (dns_a_msg (name, (uint32_t) (i + 1), one, sizeof one, &n) == 0
             && twist_dns_cache_put_msg (cache, name, 1, one, n, 0) == TWIST_OK,
             "dns fill");
    }
  check (twist_dns_cache_get (cache, "n0.example", 1, &hit, 0) == 0,
         "dns evict soonest");
  check (twist_dns_cache_get (cache, "n256.example", 1, &hit, 0) == 1,
         "dns keep newest");
  twist_dns_cache_free (cache);
}

int
main (void)
{
  test_dns ();
  test_doh ();
  test_svcb ();
  test_dns_cache ();
  return tests_finish ();
}
