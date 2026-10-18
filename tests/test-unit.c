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

#include "reactor/cmdq.h"
#include "twist-int.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int failed;

static void
check (int cond, const char *what)
{
  if (!cond)
    {
      fprintf (stderr, "FAIL %s\n", what);
      failed = 1;
    }
}

static uint64_t clock_ms;

static uint64_t
fake_now (void *user)
{
  (void) user;
  return clock_ms;
}

static int timer_hits;

static void
timer_cb (void *user)
{
  int *flag = user;
  (*flag)++;
  timer_hits++;
}

static uint64_t
aux_deadline (void *user, uint64_t now_us)
{
  (void) user;
  (void) now_us;
  return 2500ull * 1000ull;
}

static int aux_fired;

static void
aux_fire (void *user, uint64_t now_us)
{
  (void) user;
  (void) now_us;
  aux_fired++;
}

static void
test_timer (void)
{
  struct twist_loop *loop = twist_loop_new (1);
  struct twist_timer *timer = NULL;
  int hits = 0;

  check (loop != NULL, "loop");
  twist_loop_set_now (loop, fake_now, NULL);
  clock_ms = 1000;
  check (twist_loop_schedule (loop, 5000, timer_cb, &hits, &timer) == TWIST_OK,
         "schedule");
  check (twist_loop_next_timeout (loop, clock_ms) == 4000, "heap timeout");
  twist_loop_set_aux_timeout (loop, aux_deadline, NULL);
  check (twist_loop_next_timeout (loop, clock_ms) == 1500, "aux earlier");
  clock_ms = 2500;
  twist_loop_set_aux_fire (loop, aux_fire);
  twist_loop_on_timer (loop, clock_ms);
  check (aux_fired == 1, "aux fire");
  check (hits == 0, "timer not yet");
  clock_ms = 5000;
  twist_loop_on_timer (loop, clock_ms);
  check (hits == 1, "timer fired");
  hits = 0;
  check (twist_loop_schedule (loop, 9000, timer_cb, &hits, &timer) == TWIST_OK,
         "schedule 2");
  twist_timer_cancel (timer);
  clock_ms = 9000;
  twist_loop_on_timer (loop, clock_ms);
  check (hits == 0, "cancelled");
  twist_loop_free (loop);
}

static int cmd_order[4];
static int cmd_n;

static void
cmd_a (void *user)
{
  (void) user;
  cmd_order[cmd_n++] = 1;
}

static void
cmd_b (void *user)
{
  (void) user;
  cmd_order[cmd_n++] = 2;
}

static void
test_cmdq (void)
{
  struct twist_cmdq *q = twist_cmdq_new ();

  cmd_n = 0;
  check (q != NULL, "cmdq");
  check (twist_cmdq_push (q, cmd_a, NULL) == TWIST_OK, "push a");
  check (twist_cmdq_push (q, cmd_b, NULL) == TWIST_OK, "push b");
  twist_cmdq_drain (q);
  check (cmd_n == 2 && cmd_order[0] == 1 && cmd_order[1] == 2, "order");
  twist_cmdq_free (q);
}

static int saw_status;
static int saw_done;
static char body[64];
static size_t body_len;
static char hdr_name[64];
static char hdr_value[64];

static void
ev_status (void *user, int code, const char *reason, size_t n)
{
  (void) user;
  (void) reason;
  (void) n;
  saw_status = code;
}

static void
ev_header (void *user, const char *name, size_t name_len, const char *value,
           size_t value_len)
{
  (void) user;
  if (name_len >= sizeof hdr_name)
    name_len = sizeof hdr_name - 1;
  if (value_len >= sizeof hdr_value)
    value_len = sizeof hdr_value - 1;
  memcpy (hdr_name, name, name_len);
  hdr_name[name_len] = 0;
  memcpy (hdr_value, value, value_len);
  hdr_value[value_len] = 0;
}

static void
ev_body (void *user, const uint8_t *data, size_t len)
{
  (void) user;
  if (body_len + len < sizeof body)
    {
      memcpy (body + body_len, data, len);
      body_len += len;
      body[body_len] = 0;
    }
}

static void
ev_done (void *user)
{
  (void) user;
  saw_done++;
}

static void
reset_ev (void)
{
  saw_status = 0;
  saw_done = 0;
  body_len = 0;
  body[0] = 0;
  hdr_name[0] = 0;
  hdr_value[0] = 0;
}

static struct twist_h1_events
test_events (void)
{
  struct twist_h1_events ev;

  memset (&ev, 0, sizeof ev);
  ev.status_line = ev_status;
  ev.header = ev_header;
  ev.body = ev_body;
  ev.message_done = ev_done;
  return ev;
}

static void
feed_all (size_t (*recv) (void *, const uint8_t *, size_t), void *obj,
          const uint8_t *data, size_t len, size_t chunk)
{
  size_t off = 0;

  while (off < len)
    {
      size_t n = chunk;
      size_t got;
      if (n > len - off)
        n = len - off;
      got = recv (obj, data + off, n);
      if (got == 0)
        {
          failed = 1;
          fprintf (stderr, "FAIL parser stalled at %zu\n", off);
          return;
        }
      off += got;
    }
}

static size_t
h1_recv (void *obj, const uint8_t *data, size_t len)
{
  return twist_h1_receive (obj, data, len);
}

static size_t
h2_recv (void *obj, const uint8_t *data, size_t len)
{
  return twist_h2_receive (obj, data, len);
}

static size_t
h3_recv (void *obj, const uint8_t *data, size_t len)
{
  return twist_h3_receive (obj, data, len);
}

static void
test_h1 (void)
{
  static const char msg[] =
    "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello";
  struct twist_h1_events ev = test_events ();
  struct twist_h1 *h = twist_h1_new (&ev);

  reset_ev ();
  feed_all (h1_recv, h, (const uint8_t *) msg, sizeof msg - 1, sizeof msg);
  check (saw_status == 200, "h1 status");
  check (body_len == 5 && memcmp (body, "hello", 5) == 0, "h1 body");
  check (saw_done == 1, "h1 done");
  twist_h1_free (h);

  h = twist_h1_new (&ev);
  reset_ev ();
  feed_all (h1_recv, h, (const uint8_t *) msg, sizeof msg - 1, 1);
  check (saw_status == 200 && body_len == 5 && saw_done == 1, "h1 bytes");
  twist_h1_free (h);
}

static void
test_h2 (void)
{
  struct twist_h1_events ev = test_events ();
  struct twist_h2 *h;
  uint8_t *preface = NULL;
  size_t plen = 0;
  static const uint8_t frames[] = {
    0, 0, 0, 4, 0, 0, 0, 0, 0,
    0, 0, 1, 1, 0x4, 0, 0, 0, 1, 0x88,
    0, 0, 5, 0, 0x1, 0, 0, 0, 1, 'h', 'e', 'l', 'l', 'o'
  };

  check (twist_h2_client_preface (&preface, &plen) == TWIST_OK, "preface");
  check (plen > 24 && memcmp (preface, "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n", 24) == 0,
         "pri");
  free (preface);
  h = twist_h2_new (&ev);
  reset_ev ();
  feed_all (h2_recv, h, frames, sizeof frames, 1);
  check (strcmp (hdr_name, ":status") == 0 && strcmp (hdr_value, "200") == 0,
         "h2 status");
  check (body_len == 5 && memcmp (body, "hello", 5) == 0, "h2 body");
  check (saw_done == 1, "h2 done");
  twist_h2_free (h);
}

static void
test_h3 (void)
{
  struct twist_h1_events ev = test_events ();
  struct twist_h3 *h = twist_h3_new (&ev);
  static const uint8_t msg[] = {
    0x01, 0x03, 0x00, 0x00, 0xd9,
    0x04, 0x00
  };

  reset_ev ();
  feed_all (h3_recv, h, msg, sizeof msg, 1);
  check (strcmp (hdr_name, ":status") == 0 && strcmp (hdr_value, "200") == 0,
         "h3 status");
  check (saw_done == 1, "h3 done");
  twist_h3_free (h);
}

static void
test_url (void)
{
  struct twist_url *url = NULL;
  struct twist_url *rel = NULL;

  check (twist_url_parse_int ("http://user:secret@example.com:8080/a/b?x=1#f",
                              &url) == TWIST_OK, "parse");
  check (url != NULL && strcmp (url->scheme, "http") == 0, "scheme");
  check (strcmp (url->host, "example.com") == 0, "host");
  check (url->port == 8080, "port");
  check (strcmp (url->path, "/a/b") == 0, "path");
  check (strcmp (url->query, "x=1") == 0, "query");
  check (strcmp (url->user, "user") == 0, "user");
  check (twist_url_resolve_int (url, "/z", &rel) == TWIST_OK, "resolve");
  check (rel != NULL && strcmp (rel->path, "/z") == 0, "rel path");
  check (strcmp (rel->host, "example.com") == 0, "rel host");
  twist_url_free_int (rel);
  twist_url_free_int (url);
}

static void
test_auth (void)
{
  uint8_t dig[16];
  char *hdr = NULL;
  static const char chal[] =
    "Digest realm=\"testrealm@host.com\", qop=\"auth\", "
    "nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\"";
  int use_get = 0;

  check (twist_md5 ("", 0, dig) == TWIST_OK, "md5");
  check (dig[0] == 0xd4 && dig[1] == 0x1d && dig[15] == 0x7e, "md5 empty");
  check (twist_auth_digest (chal, "GET", "/dir/index.html", "Mufasa",
                            "Circle Of Life", 1, "0a4f113b", &hdr) == TWIST_OK,
         "digest");
  check (hdr != NULL && strstr (hdr, "6629fae49393a05397450978507c4ef1") != NULL,
         "rfc2617");
  free (hdr);
  check (twist_auth_basic ("a", "b", &hdr) == TWIST_OK, "basic");
  check (hdr != NULL && strstr (hdr, "Basic YTpi") != NULL, "basic b64");
  free (hdr);
  check (twist_http_should_redirect (301, "POST", 1, 0, 5, &use_get) == 1
         && use_get == 1, "301");
  check (twist_http_should_redirect (307, "POST", 1, 0, 5, &use_get) == 1
         && use_get == 0, "307");
  check (twist_http_should_redirect (302, "GET", 1, 5, 5, &use_get) == 0,
         "max");
}

static void
test_cookie (void)
{
  struct twist_jar *jar = twist_jar_new ();
  char *hdr = NULL;

  check (jar != NULL, "jar");
  check (twist_jar_store (jar, "a=b; Path=/", "example.com", "/", 0) == TWIST_OK,
         "store");
  check (twist_jar_header (jar, "example.com", "/", 0, &hdr) == TWIST_OK, "hdr");
  check (hdr != NULL && strstr (hdr, "a=b") != NULL, "cookie");
  free (hdr);
  hdr = NULL;
  check (twist_jar_header (jar, "other.test", "/", 0, &hdr) == TWIST_OK, "miss");
  check (hdr == NULL, "no cookie");
  twist_jar_free (jar);
}

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

static void
test_scheme (void)
{
  const struct twist_scheme *http = twist_scheme_by_name ("http");
  const struct twist_scheme *ftp = twist_scheme_by_name ("ftp");
  const struct twist_scheme *ftps = twist_scheme_by_name ("ftps");
  const struct twist_scheme *smtp = twist_scheme_by_name ("smtp");

  check (http != NULL && (http->flags & TWIST_SCHEME_READY) != 0, "http");
  check (ftp != NULL && (ftp->flags & TWIST_SCHEME_READY) != 0, "ftp");
  check (ftps != NULL && (ftps->flags & TWIST_SCHEME_READY) != 0, "ftps");
  check (smtp != NULL && (smtp->flags & TWIST_SCHEME_READY) == 0, "smtp");
  check (twist_scheme_by_name ("no-such") == NULL, "missing");
  check (twist_scheme_by_name ("file") != NULL, "file");
  check (twist_scheme_by_name ("wss") != NULL, "wss");
}

static int echo_n;
static char echo[32];
static char written[32];
static size_t written_len;
static int watched;

static size_t
echo_receive (struct twist_endpoint *ep, const uint8_t *data, size_t len)
{
  size_t n = len > 0 ? 1 : 0;

  if (n == 0)
    return 0;
  if (echo_n + 1 < (int) sizeof echo)
    echo[echo_n++] = (char) data[0];
  twist_endpoint_send (ep, data, n);
  if (echo_n >= 2)
    return n;
  return n;
}

static ssize_t
capture_write (void *user, const uint8_t *buf, size_t len)
{
  (void) user;
  if (written_len + len < sizeof written)
    {
      memcpy (written + written_len, buf, len);
      written_len += len;
    }
  return (ssize_t) len;
}

static ssize_t
capture_read (void *user, uint8_t *buf, size_t len)
{
  (void) user;
  (void) buf;
  (void) len;
  return 0;
}

static void
on_watch (void *user, int fd, int interest)
{
  (void) user;
  (void) fd;
  watched = interest;
}

static const struct twist_protocol_handler echo_handler = {
  NULL,
  echo_receive,
  NULL,
  NULL,
  NULL,
  NULL,
  NULL
};

static void
test_connection (void)
{
  struct twist_loop *loop = twist_loop_new (1);
  struct twist_connection *c;
  struct twist_endpoint *ep;
  int fds[2];

  echo_n = 0;
  written_len = 0;
  watched = -1;
  check (pipe (fds) == 0, "pipe");
  c = twist_connection_new (loop);
  check (c != NULL, "conn");
  twist_loop_set_watch (loop, on_watch, NULL);
  twist_connection_set_fd (c, fds[0]);
  check ((watched & TWIST_INTEREST_READ) != 0, "read interest");
  twist_connection_set_io (c, capture_read, capture_write, NULL);
  twist_connection_set_handler (c, &echo_handler);
  ep = twist_connection_endpoint (c);
  ep->user_data = NULL;
  twist_connection_ingest (c, (const uint8_t *) "hi", 2);
  twist_connection_on_writable (c);
  check (echo_n == 2 && echo[0] == 'h' && echo[1] == 'i', "echo");
  check (written_len == 2 && written[0] == 'h' && written[1] == 'i', "wrote");
  twist_endpoint_pause_read (ep);
  check ((watched & TWIST_INTEREST_READ) == 0, "paused");
  twist_endpoint_resume_read (ep);
  check ((watched & TWIST_INTEREST_READ) != 0, "resumed");
  twist_connection_free (c);
  close (fds[1]);
  twist_loop_free (loop);
}

static void
test_proxy (void)
{
  struct twist_proxy *p;
  uint8_t *out = NULL;
  size_t len = 0;
  int ready = 0;
  static const uint8_t http[] =
    "HTTP/1.1 200 Connection Established\r\n\r\n";
  static const uint8_t greet[] = { 5, 0 };
  static const uint8_t reply[] = { 5, 0, 0, 1, 0, 0, 0, 0, 0, 0 };

  p = twist_proxy_new (TWIST_PROXY_HTTP, "127.0.0.1", 8080, NULL);
  twist_proxy_set_target (p, "example.com", 443);
  check (twist_proxy_opening (p, &out, &len) == TWIST_OK, "connect open");
  check (out != NULL && memcmp (out, "CONNECT example.com:443", 23) == 0,
         "connect line");
  free (out);
  check (twist_proxy_feed (p, http, sizeof http - 1, &ready) == TWIST_OK
         && ready == 1, "connect ready");
  twist_proxy_free (p);

  p = twist_proxy_new (TWIST_PROXY_SOCKS5, "127.0.0.1", 1080, NULL);
  twist_proxy_set_target (p, "example.com", 80);
  out = NULL;
  check (twist_proxy_opening (p, &out, &len) == TWIST_OK && len == 3
         && out[0] == 5 && out[2] == 0, "socks greet");
  free (out);
  ready = 0;
  check (twist_proxy_feed (p, greet, sizeof greet, &ready) == TWIST_OK, "socks");
  out = NULL;
  check (twist_proxy_opening (p, &out, &len) == TWIST_OK && out[0] == 5
         && out[3] == 3, "socks req");
  free (out);
  check (twist_proxy_feed (p, reply, sizeof reply, &ready) == TWIST_OK
         && ready == 1, "socks ready");
  twist_proxy_free (p);
}

static int ftp_seen_n;
static int ftp_seen_code[8];
static int ftp_seen_final[8];
static char ftp_seen_text[8][32];
static char ftp_body[16];
static size_t ftp_body_len;

static void
ftp_on_line (void *user, int code, int final, const char *text, size_t len)
{
  (void) user;
  if (ftp_seen_n >= 8)
    return;
  ftp_seen_code[ftp_seen_n] = code;
  ftp_seen_final[ftp_seen_n] = final;
  if (len >= sizeof ftp_seen_text[0])
    len = sizeof ftp_seen_text[0] - 1;
  memcpy (ftp_seen_text[ftp_seen_n], text, len);
  ftp_seen_text[ftp_seen_n][len] = 0;
  ftp_seen_n++;
}

static void
feed_parser (struct twist_ftp_parser *p, const char *s, size_t split)
{
  const uint8_t *data = (const uint8_t *) s;
  size_t n = strlen (s);
  uint8_t window[8192];
  size_t held = 0;
  size_t off = 0;

  while (off < n)
    {
      size_t take = split;
      size_t got;
      size_t used;

      if (take > n - off)
        take = n - off;
      check (held + take <= sizeof window, "ftp window");
      memcpy (window + held, data + off, take);
      off += take;
      got = held + take;
      used = twist_ftp_parser_receive (p, window, got);
      if (used > got)
        used = got;
      held = got - used;
      if (held > 0)
        memmove (window, window + used, held);
    }
}

static void
test_ftp_parser (void)
{
  static const char banner[] = "220-hello\r\nwelcome\r\n220 ready\r\n";
  struct twist_ftp_events ev;
  size_t n = sizeof banner - 1;
  size_t split;
  uint8_t partial[16];
  size_t used;

  memset (&ev, 0, sizeof ev);
  ev.reply = ftp_on_line;
  for (split = 1; split <= n; split++)
    {
      struct twist_ftp_parser *p = twist_ftp_parser_new (&ev);

      ftp_seen_n = 0;
      feed_parser (p, banner, split);
      check (ftp_seen_n == 3, "ftp lines");
      check (ftp_seen_code[0] == 220 && ftp_seen_final[0] == 0, "ftp cont");
      check (strcmp (ftp_seen_text[0], "hello") == 0, "ftp hello");
      check (ftp_seen_final[1] == 0 && strcmp (ftp_seen_text[1], "welcome") == 0,
             "ftp mid");
      check (ftp_seen_code[2] == 220 && ftp_seen_final[2] == 1, "ftp final");
      check (strcmp (ftp_seen_text[2], "ready") == 0, "ftp ready");
      twist_ftp_parser_free (p);
    }
  {
    struct twist_ftp_parser *p = twist_ftp_parser_new (&ev);

    ftp_seen_n = 0;
    memcpy (partial, "220 hel", 7);
    used = twist_ftp_parser_receive (p, partial, 7);
    check (used == 0 && ftp_seen_n == 0, "ftp underflow");
    memcpy (partial + 7, "lo\r\n", 4);
    used = twist_ftp_parser_receive (p, partial, 11);
    check (used == 11 && ftp_seen_n == 1 && ftp_seen_final[0] == 1, "ftp resume");
    check (strcmp (ftp_seen_text[0], "hello") == 0, "ftp resumed text");
    twist_ftp_parser_free (p);
  }
  {
    char host[32];
    int port = 0;

    check (twist_ftp_pasv ("227 Entering Passive Mode (192,0,2,10,7,138).",
                           48, host, sizeof host, &port) == TWIST_OK, "pasv");
    check (strcmp (host, "192.0.2.10") == 0 && port == 1930, "pasv addr");
    check (twist_ftp_epsv ("229 Entering Extended Passive Mode (|||40000|)",
                           46, &port) == TWIST_OK && port == 40000, "epsv");
  }
}

static size_t
ftp_write (char *ptr, size_t size, size_t nmemb, void *user)
{
  size_t n = size * nmemb;

  (void) user;
  if (ftp_body_len + n < sizeof ftp_body)
    {
      memcpy (ftp_body + ftp_body_len, ptr, n);
      ftp_body_len += n;
    }
  return n;
}

static void
feed_session (struct twist_ftp *f, const char *s, size_t split)
{
  const uint8_t *data = (const uint8_t *) s;
  size_t n = strlen (s);
  uint8_t window[8192];
  size_t held = 0;
  size_t off = 0;

  while (off < n)
    {
      size_t take = split;
      size_t got;
      size_t used;

      if (take > n - off)
        take = n - off;
      check (held + take <= sizeof window, "session window");
      memcpy (window + held, data + off, take);
      off += take;
      got = held + take;
      used = twist_ftp_receive (f, window, got);
      if (used > got)
        used = got;
      held = got - used;
      if (held > 0)
        memmove (window, window + used, held);
    }
}

static void
test_ftp_session (void)
{
  static const char talk[] =
    "220-vsFTPd\r\n220 ready\r\n"
    "331 Password required.\r\n"
    "230 Logged in.\r\n"
    "200 Type set.\r\n"
    "229 Entering Extended Passive Mode (|||40000|)\r\n"
    "150 Opening data connection.\r\n";
  size_t n = sizeof talk - 1;
  size_t split;

  for (split = 1; split <= n; split++)
    {
      twist_easy *easy = twist_easy_init ();
      struct twist_ftp *f;
      size_t i;

      ftp_body_len = 0;
      check (easy != NULL, "easy");
      check (twist_url_parse_int ("ftp://127.0.0.1/pub/file.txt", &easy->url)
             == TWIST_OK, "ftp url");
      easy->write_cb = ftp_write;
      f = twist_ftp_new (easy, 0);
      check (f != NULL, "ftp");
      feed_session (f, talk, split);
      check (strcmp (twist_ftp_command (f), "RETR pub/file.txt\r\n") == 0,
             "retr");
      check (twist_ftp_data_port (f) == 40000, "data port");
      for (i = 0; i < 5; i++)
        twist_ftp_data (f, (const uint8_t *) "hello" + i, 1);
      check (!easy->done, "waiting for 226");
      feed_session (f, "226 Transfer complete.\r\n", split > 24 ? 24 : split);
      check (!easy->done, "waiting for data eof");
      twist_ftp_data_eof (f);
      check (easy->done && easy->result == TWIST_OK, "ftp done");
      check (easy->http_code == 226, "ftp code");
      check (easy->size_download == 5 && ftp_body_len == 5, "ftp body");
      check (memcmp (ftp_body, "hello", 5) == 0, "ftp bytes");
      twist_easy_cleanup (easy);
    }
  {
    twist_easy *easy = twist_easy_init ();
    struct twist_ftp *f;

    check (twist_url_parse_int ("ftp://alice:secret@127.0.0.1/pub/", &easy->url)
           == TWIST_OK, "auth url");
    f = twist_ftp_new (easy, 0);
    feed_session (f, "220 ready\r\n", 1);
    check (strcmp (twist_ftp_command (f), "USER alice\r\n") == 0, "user");
    feed_session (f, "331 need pass\r\n", 1);
    check (strcmp (twist_ftp_command (f), "PASS secret\r\n") == 0, "pass");
    feed_session (f, "230 ok\r\n200 Type set.\r\n500 no epsv\r\n", 1);
    check (strcmp (twist_ftp_command (f), "PASV\r\n") == 0, "pasv fallback");
    feed_session (f, "227 Entering Passive Mode (192,0,2,10,7,138).\r\n", 1);
    check (strcmp (twist_ftp_command (f), "LIST pub\r\n") == 0, "list");
    check (strcmp (twist_ftp_data_host (f), "192.0.2.10") == 0, "pasv host");
    check (twist_ftp_data_port (f) == 1930, "pasv port");
    twist_easy_cleanup (easy);
  }
}

static int cap_err;
static size_t cap_got;

static size_t
cap_hold (struct twist_endpoint *ep, const uint8_t *data, size_t len)
{
  (void) ep;
  (void) data;
  (void) len;
  return 0;
}

static void
cap_error (struct twist_endpoint *ep, int err)
{
  (void) ep;
  cap_err = err;
}

static size_t
cap_take (struct twist_endpoint *ep, const uint8_t *data, size_t len)
{
  (void) ep;
  (void) data;
  cap_got += len;
  return len;
}

static const struct twist_protocol_handler cap_hold_handler = {
  NULL,
  cap_hold,
  NULL,
  NULL,
  cap_error,
  NULL,
  NULL
};

static const struct twist_protocol_handler cap_take_handler = {
  NULL,
  cap_take,
  NULL,
  NULL,
  cap_error,
  NULL,
  NULL
};

static void
test_inbound_ceiling (void)
{
  struct twist_loop *loop = twist_loop_new (1);
  struct twist_connection *c;
  uint8_t *blob;
  size_t i;

  blob = calloc (1, TWIST_IN_CEILING);
  check (blob != NULL && loop != NULL, "ceiling buf");
  c = twist_connection_new (loop);
  cap_err = 0;
  twist_connection_set_handler (c, &cap_hold_handler);
  twist_connection_ingest (c, blob, TWIST_IN_CEILING);
  check (cap_err == TWIST_ERR_PROTOCOL, "ceiling fails");
  twist_connection_free (c);

  c = twist_connection_new (loop);
  cap_err = 0;
  cap_got = 0;
  twist_connection_set_handler (c, &cap_take_handler);
  for (i = 0; i < 4; i++)
    twist_connection_ingest (c, blob, TWIST_IN_CEILING / 2);
  check (cap_err == 0, "stream no error");
  check (cap_got == TWIST_IN_CEILING * 2, "stream consumed");
  twist_connection_free (c);
  free (blob);
  twist_loop_free (loop);
}

static void
test_sasl (void)
{
  struct twist_sasl_client *c;
  uint8_t *out = NULL;
  size_t n = 0;
  int done = 0;
  static const uint8_t plain[] = { 0, 'a', 0, 'b' };
  static const char xo[] = "user=alice\001auth=Bearer tok\001\001";

  check (twist_sasl_from_name ("plain") == TWIST_SASL_PLAIN, "plain name");
  check (twist_sasl_from_name ("GSSAPI") == 0, "no gssapi");
  c = twist_sasl_client_new (TWIST_SASL_PLAIN, "a", "b", NULL);
  check (c != NULL && twist_sasl_has_initial (c), "plain initial");
  check (twist_sasl_step (c, NULL, 0, &out, &n, &done) == TWIST_OK, "plain step");
  check (done && n == sizeof plain && memcmp (out, plain, n) == 0, "plain wire");
  free (out);
  check (twist_sasl_step (c, NULL, 0, &out, &n, &done) == TWIST_ERR_AUTH,
         "plain done");
  twist_sasl_client_free (c);

  c = twist_sasl_client_new (TWIST_SASL_LOGIN, "alice", "secret", NULL);
  check (c != NULL && !twist_sasl_has_initial (c), "login no initial");
  check (twist_sasl_step (c, NULL, 0, &out, &n, &done) == TWIST_OK && !done, "user");
  check (n == 5 && memcmp (out, "alice", 5) == 0, "login user");
  free (out);
  check (twist_sasl_step (c, NULL, 0, &out, &n, &done) == TWIST_OK && done, "pass");
  check (n == 6 && memcmp (out, "secret", 6) == 0, "login pass");
  free (out);
  twist_sasl_client_free (c);

  c = twist_sasl_client_new (TWIST_SASL_XOAUTH2, "alice", NULL, "tok");
  check (twist_sasl_step (c, NULL, 0, &out, &n, &done) == TWIST_OK && done, "xoauth2");
  check (n == sizeof xo - 1 && memcmp (out, xo, n) == 0, "xoauth2 wire");
  free (out);
  twist_sasl_client_free (c);
}

static void
test_errors (void)
{
  struct twist_easy *easy;

  check (strcmp (twist_strerror (TWIST_ERR_FILE),
                 twist_strerror (TWIST_ERR_URL)) != 0, "file distinct");
  check (strcmp (twist_strerror (TWIST_ERR_HTTP),
                 twist_strerror (TWIST_ERR_PROTOCOL)) != 0, "http distinct");
  check (twist_file_check_url (NULL, "/etc/hostname", 1) == TWIST_OK, "file path");
  check (twist_file_check_url ("localhost", "/a", 1) == TWIST_OK, "localhost");
  check (twist_file_check_url ("127.0.0.1", "/a", 1) == TWIST_OK, "loopback");
  check (twist_file_check_url ("example.com", "/a", 1) == TWIST_ERR_URL,
         "remote file");
  check (twist_file_check_url ("localhost", "/", 0) == TWIST_ERR_URL,
         "no path");
  check (twist_file_check_url (NULL, NULL, 0) == TWIST_ERR_URL, "empty path");
  check (twist_file_check_url (NULL, "relative", 1) == TWIST_ERR_URL, "relative");
  {
    struct twist_url *url = NULL;

    check (twist_url_parse_int ("file://localhost", &url) == TWIST_OK,
           "parse host");
    check (url != NULL && !url->path_set, "host has no path");
    twist_url_free_int (url);
    url = NULL;
    check (twist_url_parse_int ("file:///etc/hostname", &url) == TWIST_OK,
           "parse path");
    check (url != NULL && url->path_set
           && strcmp (url->path, "/etc/hostname") == 0, "path set");
    twist_url_free_int (url);
  }
  check (twist_http_status_result (0, 404) == TWIST_OK, "404 ok");
  check (twist_http_status_result (1, 404) == TWIST_ERR_HTTP, "404 fail");
  check (twist_http_status_result (1, 200) == TWIST_OK, "200 ok");
  check (twist_http_status_result (1, 399) == TWIST_OK, "399 ok");
  check (twist_http_status_result (1, 400) == TWIST_ERR_HTTP, "400 fail");
  easy = twist_easy_init ();
  check (easy != NULL && twist_easy_error (easy) == NULL, "no detail");
  twist_easy_set_error (easy, twist_strdup ("could not open file /no/such"));
  check (twist_easy_error (easy) != NULL
         && strcmp (twist_easy_error (easy),
                    "could not open file /no/such") == 0, "detail");
  twist_easy_cleanup (easy);
}

int
main (void)
{
  test_timer ();
  test_cmdq ();
  test_h1 ();
  test_h2 ();
  test_h3 ();
  test_url ();
  test_auth ();
  test_sasl ();
  test_cookie ();
  test_dns ();
  test_scheme ();
  test_connection ();
  test_proxy ();
  test_ftp_parser ();
  test_ftp_session ();
  test_inbound_ceiling ();
  test_errors ();
  if (failed)
    {
      fprintf (stderr, "unit tests failed\n");
      return 1;
    }
  return 0;
}
