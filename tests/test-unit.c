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

#include <quickstep/tls.h>

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
  clock_ms = 1000;
  twist_loop_set_aux_timeout (loop, NULL, NULL);
  check (twist_loop_schedule (loop, 4000, timer_cb, &hits, &timer) == TWIST_OK,
         "schedule early");
  check (twist_loop_schedule (loop, 7000, timer_cb, &hits, NULL) == TWIST_OK,
         "schedule late");
  twist_timer_cancel (timer);
  check (twist_loop_next_timeout (loop, clock_ms) == 6000, "skip cancelled");
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

static uint8_t h2_emitted[64];
static size_t h2_emitted_n;

static int
h2_capture (void *user, const uint8_t *data, size_t len)
{
  (void) user;
  if (h2_emitted_n + len <= sizeof h2_emitted)
    memcpy (h2_emitted + h2_emitted_n, data, len);
  h2_emitted_n += len;
  return 0;
}

static int saw_status;
static int saw_done;
static char body[64];
static size_t body_len;
static size_t body_total;
static int slice_ok;
static const uint8_t *slice_lo;
static const uint8_t *slice_hi;
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
  body_total += len;
  if (slice_lo != NULL
      && (data < slice_lo || data + len > slice_hi))
    slice_ok = 0;
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
  body_total = 0;
  slice_ok = 1;
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

/* Connection-buffer contract: a parser may leave an incomplete frame
   unconsumed.  The next push is that tail plus the following bytes.  */
static void
feed_remain (size_t (*recv) (void *, const uint8_t *, size_t), void *obj,
             const uint8_t *data, size_t len, size_t chunk)
{
  uint8_t *buf;
  size_t have = 0;
  size_t off = 0;

  buf = malloc (len + 1);
  if (buf == NULL)
    {
      failed = 1;
      fprintf (stderr, "FAIL feed buffer\n");
      return;
    }
  while (off < len || have > 0)
    {
      size_t n = chunk;
      size_t got;

      if (off < len)
        {
          if (n > len - off)
            n = len - off;
          memcpy (buf + have, data + off, n);
          have += n;
          off += n;
        }
      slice_lo = buf;
      slice_hi = buf + have;
      got = recv (obj, buf, have);
      if (got == 0)
        {
          if (off < len)
            continue;
          if (have > 0)
            {
              failed = 1;
              fprintf (stderr, "FAIL parser left %zu bytes\n", have);
            }
          break;
        }
      if (got > have)
        got = have;
      memmove (buf, buf + got, have - got);
      have -= got;
    }
  free (buf);
  slice_lo = NULL;
  slice_hi = NULL;
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
  feed_remain (h2_recv, h, frames, sizeof frames, 1);
  check (strcmp (hdr_name, ":status") == 0 && strcmp (hdr_value, "200") == 0,
         "h2 status");
  check (body_len == 5 && memcmp (body, "hello", 5) == 0, "h2 body");
  check (slice_ok, "h2 body is a slice");
  check (saw_done == 1, "h2 done");
  twist_h2_free (h);
  {
    uint8_t *out = NULL;
    size_t n = 0;
    uint8_t big[20000];
    size_t data_frames = 0;
    size_t i = 0;

    memset (big, 'a', sizeof big);
    h = twist_h2_new (&ev);
    check (twist_h2_request (h, "POST", "https", "example", "/", NULL, big,
                             sizeof big, 0, &out, &n) == TWIST_OK,
           "h2 request");
    while (i + 9 <= n)
      {
        uint32_t flen = ((uint32_t) out[i] << 16) | ((uint32_t) out[i + 1] << 8)
          | out[i + 2];
        if (out[i + 3] == 0)
          {
            data_frames++;
            check (flen <= 16384, "h2 data frame size");
          }
        i += 9 + flen;
      }
    check (data_frames >= 2, "h2 data is framed");
    free (out);
    twist_h2_free (h);
  }
  {
    enum { N = 32 };
    uint8_t *frames_b;
    size_t flen = (size_t) N * (9 + 16384);
    size_t i;

    frames_b = malloc (flen);
    check (frames_b != NULL, "h2 window buf");
    if (frames_b != NULL)
      {
        for (i = 0; i < N; i++)
          {
            uint8_t *p = frames_b + i * (9 + 16384);
            p[0] = 0;
            p[1] = 0x40;
            p[2] = 0;
            p[3] = 0;
            p[4] = (i + 1 == N) ? 0x1 : 0;
            p[5] = 0;
            p[6] = 0;
            p[7] = 0;
            p[8] = 1;
            memset (p + 9, 'b', 16384);
          }
        h = twist_h2_new (&ev);
        h2_emitted_n = 0;
        twist_h2_set_emit (h, h2_capture, NULL);
        reset_ev ();
        feed_remain (h2_recv, h, frames_b, flen, 1000);
        check (body_total == (size_t) N * 16384, "h2 past 64KiB");
        check (slice_ok, "h2 large slice");
        check (h2_emitted_n >= 13 && h2_emitted[3] == 8, "h2 window update");
        twist_h2_free (h);
        free (frames_b);
      }
  }
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
  feed_remain (h3_recv, h, msg, sizeof msg, 1);
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
  check (smtp != NULL && (smtp->flags & TWIST_SCHEME_READY) != 0, "smtp");
  check (twist_scheme_by_name ("imap") != NULL
         && (twist_scheme_by_name ("imap")->flags & TWIST_SCHEME_READY) != 0,
         "imap");
  check (twist_scheme_by_name ("pop3s") != NULL
         && (twist_scheme_by_name ("pop3s")->flags & TWIST_SCHEME_READY) != 0,
         "pop3s");
  check (twist_scheme_by_name ("mqtt") != NULL
         && (twist_scheme_by_name ("mqtt")->flags & TWIST_SCHEME_READY) != 0,
         "mqtt");
  check (twist_scheme_by_name ("mqtts") != NULL
         && (twist_scheme_by_name ("mqtts")->flags & TWIST_SCHEME_TLS) != 0,
         "mqtts");
  check (twist_scheme_by_name ("ldaps") != NULL
         && (twist_scheme_by_name ("ldaps")->flags & TWIST_SCHEME_READY) != 0,
         "ldaps");
  check (twist_scheme_by_name ("no-such") == NULL, "missing");
  check (twist_scheme_by_name ("file") != NULL, "file");
  check (twist_scheme_by_name ("ws") != NULL
         && (twist_scheme_by_name ("ws")->flags & TWIST_SCHEME_READY) != 0,
         "ws");
  check (twist_scheme_by_name ("wss") != NULL
         && (twist_scheme_by_name ("wss")->flags & TWIST_SCHEME_TLS) != 0
         && (twist_scheme_by_name ("wss")->flags & TWIST_SCHEME_READY) != 0,
         "wss");
  check (twist_scheme_by_name ("gopher") != NULL
         && (twist_scheme_by_name ("gopher")->flags & TWIST_SCHEME_READY) != 0,
         "gopher");
  check (twist_scheme_by_name ("gophers") != NULL
         && (twist_scheme_by_name ("gophers")->flags & TWIST_SCHEME_TLS) != 0
         && (twist_scheme_by_name ("gophers")->flags & TWIST_SCHEME_READY) != 0,
         "gophers");
  check (twist_scheme_by_name ("dict") != NULL
         && (twist_scheme_by_name ("dict")->flags & TWIST_SCHEME_READY) != 0
         && twist_scheme_by_name ("dict")->default_port == 2628,
         "dict");
  check (twist_scheme_by_name ("tftp") != NULL
         && (twist_scheme_by_name ("tftp")->flags & TWIST_SCHEME_READY) != 0
         && (twist_scheme_by_name ("tftp")->flags & TWIST_SCHEME_DATAGRAM) != 0
         && twist_scheme_by_name ("tftp")->default_port == 69,
         "tftp");
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

struct mail_cap
{
  uint8_t b[512];
  size_t n;
};

static int
mail_sink (void *user, const uint8_t *data, size_t len)
{
  struct mail_cap *c = user;

  if (c->n + len > sizeof c->b)
    return 1;
  memcpy (c->b + c->n, data, len);
  c->n += len;
  return 0;
}

static char mail_body[128];
static size_t mail_body_len;

static size_t
mail_write (char *ptr, size_t size, size_t nmemb, void *user)
{
  size_t n = size * nmemb;

  (void) user;
  if (mail_body_len + n < sizeof mail_body)
    {
      memcpy (mail_body + mail_body_len, ptr, n);
      mail_body_len += n;
    }
  return n;
}

static void
feed_n (size_t (*recv) (void *, const uint8_t *, size_t), void *obj,
        const char *text, size_t split)
{
  const uint8_t *data = (const uint8_t *) text;
  size_t n = strlen (text);
  uint8_t window[1024];
  size_t held = 0;
  size_t off = 0;

  while (off < n)
    {
      size_t take = split;
      size_t got;
      size_t used;

      if (take > n - off)
        take = n - off;
      memcpy (window + held, data + off, take);
      off += take;
      got = held + take;
      used = recv (obj, window, got);
      if (used > got)
        used = got;
      held = got - used;
      if (held > 0)
        memmove (window, window + used, held);
    }
}

static void
feed_bin (size_t (*recv) (void *, const uint8_t *, size_t), void *obj,
          const uint8_t *data, size_t n, size_t split)
{
  uint8_t window[1024];
  size_t held = 0;
  size_t off = 0;

  while (off < n)
    {
      size_t take = split;
      size_t got;
      size_t used;

      if (take > n - off)
        take = n - off;
      memcpy (window + held, data + off, take);
      off += take;
      got = held + take;
      used = recv (obj, window, got);
      if (used > got)
        used = got;
      held = got - used;
      if (held > 0)
        memmove (window, window + used, held);
    }
}

static int
has_bytes (const uint8_t *hay, size_t n, const void *needle, size_t m)
{
  size_t i;

  if (needle == NULL || m == 0 || m > n)
    return 0;
  for (i = 0; i + m <= n; i++)
    if (memcmp (hay + i, needle, m) == 0)
      return 1;
  return 0;
}

static size_t
smtp_recv (void *obj, const uint8_t *data, size_t len)
{
  return twist_smtp_receive (obj, data, len);
}

static size_t
pop3_recv (void *obj, const uint8_t *data, size_t len)
{
  return twist_pop3_receive (obj, data, len);
}

static size_t
imap_recv (void *obj, const uint8_t *data, size_t len)
{
  return twist_imap_receive (obj, data, len);
}

static void
test_mail (void)
{
  static const char plain[] = "Hi\r\n.x\r\n";
  static const char stuffed[] = "Hi\r\n..x\r\n.\r\n";
  struct mail_cap cap;
  struct twist_dotout out;
  struct twist_dotin in;
  size_t i;
  int done = 0;
  int err = 0;
  struct twist_mime *mime;
  static const char expect_mime[] =
    "--twist-mime-1\r\n"
    "Content-Type: text/plain\r\n"
    "\r\n"
    "ab\r\n"
    "--twist-mime-1\r\n"
    "Content-Transfer-Encoding: base64\r\n"
    "\r\n"
    "aGk=\r\n"
    "--twist-mime-1--\r\n";

  memset (&cap, 0, sizeof cap);
  twist_dotout_init (&out);
  for (i = 0; i < sizeof plain - 1; i++)
    check (twist_dotout_write (&out, (const uint8_t *) plain + i, 1,
                               mail_sink, &cap) == TWIST_OK, "dotout");
  check (twist_dotout_finish (&out, mail_sink, &cap) == TWIST_OK, "dotend");
  check (cap.n == sizeof stuffed - 1
         && memcmp (cap.b, stuffed, cap.n) == 0, "stuffed");
  memset (&cap, 0, sizeof cap);
  twist_dotin_init (&in);
  for (i = 0; i < sizeof stuffed - 1; i++)
    {
      size_t used = twist_dotin_pull (&in, (const uint8_t *) stuffed + i, 1,
                                      mail_sink, &cap, &done, &err);

      check (used == 1 && err == TWIST_OK, "dotin byte");
    }
  check (done && cap.n == sizeof plain - 1
         && memcmp (cap.b, plain, cap.n) == 0, "unstuffed");

  memset (&cap, 0, sizeof cap);
  mime = twist_mime_new (mail_sink, &cap);
  check (mime != NULL && twist_mime_begin (mime, "mixed") == TWIST_OK, "mime");
  check (twist_mime_part (mime) == TWIST_OK, "part1");
  check (twist_mime_header (mime, "Content-Type", "text/plain") == TWIST_OK,
         "hdr");
  check (twist_mime_body (mime, (const uint8_t *) "a", 1) == TWIST_OK, "a");
  check (twist_mime_body (mime, (const uint8_t *) "b", 1) == TWIST_OK, "b");
  check (twist_mime_part (mime) == TWIST_OK, "part2");
  check (twist_mime_header (mime, "Content-Transfer-Encoding", "base64")
         == TWIST_OK, "cte");
  check (twist_mime_body_b64 (mime, (const uint8_t *) "hi", 2) == TWIST_OK,
         "b64");
  check (twist_mime_finish (mime) == TWIST_OK, "mime end");
  check (cap.n == sizeof expect_mime - 1
         && memcmp (cap.b, expect_mime, cap.n) == 0, "mime bytes");
  twist_mime_free (mime);

  {
    uint8_t raw[13] = { 0, 'a', 'l', 'i', 'c', 'e', 0,
                        's', 'e', 'c', 'r', 'e', 't' };
    char *b64 = NULL;
    char authcmd[128];
    twist_easy *easy = twist_easy_init ();
    struct twist_slist *rcpt = twist_slist_append (NULL, "c@d");
    struct twist_smtp *smtp;
    size_t split;

    check (twist_b64_encode (raw, sizeof raw, &b64) == TWIST_OK, "plain b64");
    snprintf (authcmd, sizeof authcmd, "AUTH PLAIN %s\r\n", b64);
    free (b64);
    for (split = 1; split <= 12; split++)
      {
        check (twist_url_parse_int ("smtp://alice:secret@127.0.0.1",
                                    &easy->url) == TWIST_OK, "smtp url");
        easy->mail_from = twist_strdup ("a@b");
        easy->mail_rcpt = rcpt;
        easy->postfields = (char[]) { 'H', 'i', '\r', '\n', '.', 'x', '\r', '\n', 0 };
        smtp = twist_smtp_new (easy, 0);
        feed_n (smtp_recv, smtp, "220 ready\r\n", split);
        check (strcmp (twist_smtp_command (smtp), "EHLO twist\r\n") == 0,
               "ehlo");
        feed_n (smtp_recv, smtp, "250-AUTH PLAIN\r\n250 hello\r\n", split);
        check (strcmp (twist_smtp_command (smtp), authcmd) == 0, "auth plain");
        feed_n (smtp_recv, smtp, "235 ok\r\n", split);
        check (strcmp (twist_smtp_command (smtp), "MAIL FROM:<a@b>\r\n") == 0,
               "mail from");
        feed_n (smtp_recv, smtp, "250 sender\r\n", split);
        check (strcmp (twist_smtp_command (smtp), "RCPT TO:<c@d>\r\n") == 0,
               "rcpt");
        feed_n (smtp_recv, smtp, "250 rcpt\r\n", split);
        check (strcmp (twist_smtp_command (smtp), "DATA\r\n") == 0, "data");
        feed_n (smtp_recv, smtp, "354 go\r\n", split);
        check (strcmp (twist_smtp_command (smtp), stuffed) == 0, "smtp body");
        feed_n (smtp_recv, smtp, "250 queued\r\n", split);
        check (easy->done && easy->result == TWIST_OK, "smtp done");
        check (strcmp (twist_smtp_command (smtp), "QUIT\r\n") == 0, "quit");
        twist_easy_cleanup (easy);
        easy = twist_easy_init ();
      }
    twist_slist_free_all (rcpt);
    twist_easy_cleanup (easy);
  }
  {
    twist_easy *easy = twist_easy_init ();
    struct twist_pop3 *pop;

    mail_body_len = 0;
    check (twist_url_parse_int ("pop3://alice:secret@127.0.0.1/1", &easy->url)
           == TWIST_OK, "pop url");
    easy->write_cb = mail_write;
    pop = twist_pop3_new (easy, 0);
    feed_n (pop3_recv, pop, "+OK pop\r\n", 1);
    check (strcmp (twist_pop3_command (pop), "CAPA\r\n") == 0, "capa");
    feed_n (pop3_recv, pop, "+OK\r\nUSER\r\n.\r\n", 1);
    check (strcmp (twist_pop3_command (pop), "USER alice\r\n") == 0, "user");
    feed_n (pop3_recv, pop, "+OK\r\n", 1);
    check (strcmp (twist_pop3_command (pop), "PASS secret\r\n") == 0, "pass");
    feed_n (pop3_recv, pop, "+OK\r\n+OK 5\r\nhello\r\n.\r\n+OK bye\r\n", 1);
    check (easy->done && easy->result == TWIST_OK, "pop done");
    check (mail_body_len == 7 && memcmp (mail_body, "hello\r\n", 7) == 0,
           "pop body");
    twist_easy_cleanup (easy);
  }
  {
    uint8_t raw[13] = { 0, 'a', 'l', 'i', 'c', 'e', 0,
                        's', 'e', 'c', 'r', 'e', 't' };
    char *b64 = NULL;
    char authcmd[160];
    twist_easy *easy = twist_easy_init ();
    struct twist_imap *imap;

    check (twist_b64_encode (raw, sizeof raw, &b64) == TWIST_OK, "imap b64");
    snprintf (authcmd, sizeof authcmd, "A2 AUTHENTICATE PLAIN %s\r\n", b64);
    free (b64);
    mail_body_len = 0;
    check (twist_url_parse_int ("imap://alice:secret@127.0.0.1/INBOX;UID=1",
                                &easy->url) == TWIST_OK, "imap url");
    easy->write_cb = mail_write;
    imap = twist_imap_new (easy, 0);
    feed_n (imap_recv, imap, "* OK ready\r\n", 1);
    check (strcmp (twist_imap_command (imap), "A1 CAPABILITY\r\n") == 0,
           "capability");
    feed_n (imap_recv, imap, "* CAPABILITY IMAP4rev1 AUTH=PLAIN\r\nA1 OK\r\n",
            1);
    check (strcmp (twist_imap_command (imap), authcmd) == 0, "authenticate");
    feed_n (imap_recv, imap, "A2 OK\r\n", 1);
    check (strcmp (twist_imap_command (imap), "A3 SELECT INBOX\r\n") == 0,
           "select");
    feed_n (imap_recv, imap, "* 1 EXISTS\r\nA3 OK [READ-WRITE]\r\n", 1);
    check (strcmp (twist_imap_command (imap), "A4 UID FETCH 1 BODY[]\r\n") == 0,
           "fetch");
    feed_n (imap_recv, imap, "* 1 FETCH (BODY[] {5}\r\nhello)\r\nA4 OK\r\n", 1);
    check (easy->done && easy->result == TWIST_OK, "imap done");
    check (mail_body_len == 5 && memcmp (mail_body, "hello", 5) == 0,
           "imap body");
    twist_easy_cleanup (easy);
  }
}

static size_t
mqtt_recv (void *obj, const uint8_t *data, size_t len)
{
  return twist_mqtt_receive (obj, data, len);
}

static size_t
ldap_recv (void *obj, const uint8_t *data, size_t len)
{
  return twist_ldap_receive (obj, data, len);
}

static void
test_mqtt_ldap (void)
{
  static const uint8_t connect[] = {
    0x10, 0x11, 0x00, 0x04, 'M', 'Q', 'T', 'T', 0x04, 0x02, 0x00, 0x3c,
    0x00, 0x05, 't', 'w', 'i', 's', 't'
  };
  static const uint8_t connack[] = { 0x20, 0x02, 0x00, 0x00 };
  static const uint8_t refused[] = { 0x20, 0x02, 0x00, 0x05 };
  static const uint8_t suback[] = { 0x90, 0x03, 0x00, 0x01, 0x00 };
  static const uint8_t publish[] = {
    0x30, 19, 0x00, 12, 's', 'e', 'n', 's', 'o', 'r', 's', '/', 't', 'e',
    'm', 'p', 'h', 'e', 'l', 'l', 'o'
  };
  static const uint8_t disc[] = { 0xe0, 0x00 };
  static const uint8_t bind_ok[] = {
    0x30, 0x0c, 0x02, 0x01, 0x01, 0x61, 0x07, 0x0a, 0x01, 0x00, 0x04, 0x00,
    0x04, 0x00
  };
  static const uint8_t bind_no[] = {
    0x30, 0x0c, 0x02, 0x01, 0x01, 0x61, 0x07, 0x0a, 0x01, 0x31, 0x04, 0x00,
    0x04, 0x00
  };
  static const uint8_t entry[] = {
    0x30, 0x27, 0x02, 0x01, 0x02, 0x64, 0x22, 0x04, 0x11, 'd', 'c', '=',
    'e', 'x', 'a', 'm', 'p', 'l', 'e', ',', 'd', 'c', '=', 'c', 'o', 'm',
    0x30, 0x0d, 0x30, 0x0b, 0x04, 0x02, 'c', 'n', 0x31, 0x05, 0x04, 0x03,
    'b', 'o', 'b'
  };
  static const uint8_t search_done[] = {
    0x30, 0x0c, 0x02, 0x01, 0x02, 0x65, 0x07, 0x0a, 0x01, 0x00, 0x04, 0x00,
    0x04, 0x00
  };
  static const char ldif[] = "dn: dc=example,dc=com\ncn: bob\n\n";
  twist_easy *easy = twist_easy_init ();
  struct twist_mqtt *mqtt;
  struct twist_ldap *ldap;
  const uint8_t *cmd;
  size_t n = 0;
  char ping[] = "ping";

  check (twist_url_parse_int ("mqtt://127.0.0.1/sensors/temp", &easy->url)
         == TWIST_OK, "mqtt url");
  mqtt = twist_mqtt_new (easy, 0);
  cmd = twist_mqtt_command (mqtt, &n);
  check (n == sizeof connect && memcmp (cmd, connect, n) == 0, "connect");
  feed_bin (mqtt_recv, mqtt, connack, sizeof connack, 1);
  cmd = twist_mqtt_command (mqtt, &n);
  check (has_bytes (cmd, n, "sensors/temp", 12), "subscribe");
  feed_bin (mqtt_recv, mqtt, suback, sizeof suback, 1);
  mail_body_len = 0;
  easy->write_cb = mail_write;
  feed_bin (mqtt_recv, mqtt, publish, sizeof publish, 1);
  check (mail_body_len == 5 && memcmp (mail_body, "hello", 5) == 0,
         "mqtt payload");
  feed_bin (mqtt_recv, mqtt, disc, sizeof disc, 1);
  check (easy->done && easy->result == TWIST_OK, "mqtt done");
  twist_easy_cleanup (easy);

  easy = twist_easy_init ();
  check (twist_url_parse_int ("mqtt://127.0.0.1/a", &easy->url) == TWIST_OK,
         "pub url");
  easy->postfields = ping;
  mqtt = twist_mqtt_new (easy, 0);
  feed_bin (mqtt_recv, mqtt, connack, sizeof connack, 1);
  cmd = twist_mqtt_command (mqtt, &n);
  check (easy->done && easy->result == TWIST_OK, "published");
  check (has_bytes (cmd, n, "ping", 4)
         && n >= 2 && cmd[n - 2] == 0xe0 && cmd[n - 1] == 0x00, "pub bytes");
  twist_easy_cleanup (easy);

  easy = twist_easy_init ();
  check (twist_url_parse_int ("mqtt://127.0.0.1/a", &easy->url) == TWIST_OK,
         "refuse url");
  mqtt = twist_mqtt_new (easy, 0);
  feed_bin (mqtt_recv, mqtt, refused, sizeof refused, 1);
  check (easy->done && easy->result == TWIST_ERR_AUTH, "connack auth");
  twist_easy_cleanup (easy);

  easy = twist_easy_init ();
  check (twist_url_parse_int ("mqtt://alice:secret@127.0.0.1/a", &easy->url)
         == TWIST_OK, "mqtt user");
  mqtt = twist_mqtt_new (easy, 0);
  cmd = twist_mqtt_command (mqtt, &n);
  check (has_bytes (cmd, n, "alice", 5) && has_bytes (cmd, n, "secret", 6),
         "mqtt credentials");
  twist_easy_cleanup (easy);

  easy = twist_easy_init ();
  check (twist_url_parse_int
         ("ldap://cn=alice:secret@127.0.0.1/dc=example,dc=com?cn?sub?(uid=alice)",
          &easy->url) == TWIST_OK, "ldap url");
  ldap = twist_ldap_new (easy, 0);
  cmd = twist_ldap_command (ldap, &n);
  check (has_bytes (cmd, n, "cn=alice", 8) && has_bytes (cmd, n, "secret", 6),
         "simple bind");
  feed_bin (ldap_recv, ldap, bind_ok, sizeof bind_ok, 1);
  cmd = twist_ldap_command (ldap, &n);
  check (has_bytes (cmd, n, "dc=example,dc=com", 17)
         && has_bytes (cmd, n, "uid", 3) && has_bytes (cmd, n, "alice", 5)
         && has_bytes (cmd, n, "cn", 2), "search");
  mail_body_len = 0;
  easy->write_cb = mail_write;
  feed_bin (ldap_recv, ldap, entry, sizeof entry, 1);
  feed_bin (ldap_recv, ldap, search_done, sizeof search_done, 1);
  check (easy->done && easy->result == TWIST_OK, "ldap done");
  check (mail_body_len == sizeof ldif - 1
         && memcmp (mail_body, ldif, mail_body_len) == 0, "ldif");
  cmd = twist_ldap_command (ldap, &n);
  check (has_bytes (cmd, n, "\x42", 1), "unbind");
  twist_easy_cleanup (easy);

  easy = twist_easy_init ();
  check (twist_url_parse_int ("ldap://cn=alice:no@127.0.0.1/dc=x", &easy->url)
         == TWIST_OK, "ldap bad url");
  ldap = twist_ldap_new (easy, 0);
  feed_bin (ldap_recv, ldap, bind_no, sizeof bind_no, 1);
  check (easy->done && easy->result == TWIST_ERR_AUTH, "bind refused");
  twist_easy_cleanup (easy);

  {
    static const uint8_t bind_long[] = {
      0x30, 0x82, 0x00, 0x0e, 0x02, 0x01, 0x01, 0x61, 0x82, 0x00, 0x07,
      0x0a, 0x01, 0x00, 0x04, 0x00, 0x04, 0x00
    };

    easy = twist_easy_init ();
    check (twist_url_parse_int ("ldap://127.0.0.1/dc=example,dc=com",
                                &easy->url) == TWIST_OK, "long url");
    ldap = twist_ldap_new (easy, 0);
    feed_bin (ldap_recv, ldap, bind_long, sizeof bind_long, 1);
    cmd = twist_ldap_command (ldap, &n);
    check (has_bytes (cmd, n, "dc=example,dc=com", 17)
           && has_bytes (cmd, n, "objectClass", 11), "long bind");
    twist_easy_cleanup (easy);
  }

  easy = twist_easy_init ();
  check (twist_url_parse_int ("ldap://alice:x@127.0.0.1/dc=example,dc=com",
                              &easy->url) == TWIST_OK, "sasl url");
  easy->bearer = twist_strdup ("tok");
  ldap = twist_ldap_new (easy, 0);
  cmd = twist_ldap_command (ldap, &n);
  check (has_bytes (cmd, n, "XOAUTH2", 7)
         && has_bytes (cmd, n, "auth=Bearer tok", 15), "sasl bind");
  twist_easy_cleanup (easy);
  easy = NULL;
}

static uint8_t ws_out[64];
static size_t ws_out_n;
static int ws_done_err;
static int ws_done_n;

static int
ws_sink (void *user, const uint8_t *data, size_t len)
{
  (void) user;
  if (ws_out_n + len > sizeof ws_out)
    return 1;
  memcpy (ws_out + ws_out_n, data, len);
  ws_out_n += len;
  return 0;
}

static void
ws_finished (void *user, int err)
{
  (void) user;
  ws_done_err = err;
  ws_done_n++;
}

static size_t
ws_recv (void *obj, const uint8_t *data, size_t len)
{
  return twist_ws_receive (obj, data, len);
}

static int opened_switch (void *user);

static void
test_ws (void)
{
  char *accept = NULL;
  struct twist_ws *ws;
  struct twist_easy *easy;
  static const uint8_t hello[] = {
    0x81, 0x05, 'H', 'e', 'l', 'l', 'o'
  };
  static const uint8_t ping[] = { 0x89, 0x01, 'z' };
  static const uint8_t close_frame[] = { 0x88, 0x00 };

  check (twist_ws_accept ("dGhlIHNhbXBsZSBub25jZQ==", &accept) == TWIST_OK,
         "ws accept rc");
  check (accept != NULL
         && strcmp (accept, "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=") == 0,
         "ws accept");
  free (accept);
  check (twist_ws_validate ("dGhlIHNhbXBsZSBub25jZQ==", "websocket",
                            "Upgrade", "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=")
         == TWIST_OK, "ws validate");
  check (twist_ws_validate ("dGhlIHNhbXBsZSBub25jZQ==", "websocket",
                            "Upgrade", "nope") == TWIST_ERR_PROTOCOL,
         "ws bad accept");
  easy = twist_easy_init ();
  easy->write_cb = mail_write;
  mail_body_len = 0;
  ws_out_n = 0;
  ws_done_n = 0;
  ws = twist_ws_new (easy, ws_sink, NULL, ws_finished, NULL);
  feed_bin (ws_recv, ws, hello, sizeof hello, 1);
  check (mail_body_len == 5 && memcmp (mail_body, "Hello", 5) == 0,
         "ws text");
  feed_bin (ws_recv, ws, ping, sizeof ping, 1);
  check (ws_out_n == 7 && (ws_out[0] & 0x0f) == 0x0a
         && (ws_out[1] & 0x80) != 0
         && (ws_out[6] ^ ws_out[2]) == 'z', "ws pong");
  check (ws_done_n == 0, "ws ping open");
  ws_out_n = 0;
  feed_bin (ws_recv, ws, close_frame, sizeof close_frame, 1);
  check (ws_done_n == 1 && ws_done_err == TWIST_OK, "ws close");
  check (ws_out_n == 6 && (ws_out[0] & 0x0f) == 0x08
         && (ws_out[1] & 0x80) != 0, "ws close frame");
  twist_ws_free (ws);
  twist_easy_cleanup (easy);
  {
    struct twist_slist *extra = NULL;
    struct twist_h1_events ev;
    struct twist_h3 *h3;
    uint8_t *out = NULL;
    size_t n = 0;
    static const uint8_t resp[] = {
      0x01, 0x03, 0x00, 0x00, 0xd9,
      0x00, 0x07, 0x81, 0x05, 'H', 'e', 'l', 'l', 'o',
      0x04, 0x00
    };
    static int opened;

    extra = twist_slist_append (NULL, ":protocol: websocket");
    check (twist_h3_request (NULL, "CONNECT", "https", "example", "/chat",
                             extra, NULL, 0, &out, &n) == TWIST_OK,
           "h3 connect rc");
    check (out != NULL && out[0] == 0x01, "h3 headers");
    check (has_bytes (out, n, "CONNECT", 7)
           && has_bytes (out, n, ":protocol", 9)
           && has_bytes (out, n, "websocket", 9)
           && has_bytes (out, n, "https", 5), "h3 connect fields");
    free (out);
    twist_slist_free_all (extra);
    ev = test_events ();
    opened = 0;
    ev.switching = opened_switch;
    ev.user = &opened;
    h3 = twist_h3_new (&ev);
    reset_ev ();
    feed_remain (h3_recv, h3, resp, sizeof resp, 1);
    check (opened == 1, "h3 opened");
    check (body_len == 7 && memcmp (body, "\x81\x05Hello", 7) == 0,
           "h3 ws data");
    check (saw_done == 1, "h3 ws done");
    twist_h3_free (h3);
  }
}

static int
opened_switch (void *user)
{
  int *opened = user;

  (*opened)++;
  return 1;
}

static size_t
gopher_recv (void *obj, const uint8_t *data, size_t len)
{
  return twist_gopher_receive (obj, data, len);
}

static void
test_gopher_one (const char *url, const void *expect, size_t expect_n,
                 const char *what)
{
  struct twist_easy *easy = twist_easy_init ();
  struct twist_gopher *g;
  const uint8_t *req;
  size_t n = 0;

  check (twist_url_parse_int (url, &easy->url) == TWIST_OK, what);
  g = twist_gopher_new (easy, 0);
  req = twist_gopher_request (g, &n);
  check (g != NULL && !easy->done && n == expect_n
         && memcmp (req, expect, expect_n) == 0, what);
  twist_easy_cleanup (easy);
}

static void
test_gopher (void)
{
  struct twist_easy *easy;
  struct twist_gopher *g;
  static const uint8_t menu[] = {
    '1', 'H', 'e', 'l', 'l', 'o', '\t', 's', '\t', 'h', '\t', '7', '0',
    '\r', '\n', '.', '\r', '\n'
  };
  static const uint8_t tabbed[] = { '/', 'a', '\t', 'b', '\r', '\n' };

  test_gopher_one ("gopher://127.0.0.1/1/foo", "/foo\r\n", 6, "gopher sel");
  test_gopher_one ("gopher://127.0.0.1/", "\r\n", 2, "gopher root");
  test_gopher_one ("gopher://127.0.0.1/1", "\r\n", 2, "gopher type");
  test_gopher_one ("gopher://127.0.0.1/0file%20name", "file name\r\n", 11,
                   "gopher decode");
  test_gopher_one ("gopher://127.0.0.1/1/a%09b", tabbed, sizeof tabbed,
                   "gopher tab");
  test_gopher_one ("gopher://127.0.0.1/7/q?find", "/q?find\r\n", 9,
                   "gopher search");
  easy = twist_easy_init ();
  check (twist_url_parse_int ("gopher://127.0.0.1/1/%00", &easy->url)
         == TWIST_OK, "gopher nul url");
  g = twist_gopher_new (easy, 0);
  check (g != NULL && easy->done && easy->result == TWIST_ERR_URL,
         "gopher nul");
  twist_easy_cleanup (easy);
  easy = twist_easy_init ();
  check (twist_url_parse_int ("gopher://127.0.0.1/1/hello", &easy->url)
         == TWIST_OK, "gopher body url");
  easy->write_cb = mail_write;
  mail_body_len = 0;
  g = twist_gopher_new (easy, 0);
  feed_bin (gopher_recv, g, menu, sizeof menu, 1);
  check (mail_body_len == sizeof menu
         && memcmp (mail_body, menu, sizeof menu) == 0, "gopher body");
  check (!easy->done, "gopher still open");
  twist_gopher_closed (g, TWIST_ERR_CLOSED);
  check (easy->done && easy->result == TWIST_OK, "gopher close");
  twist_easy_cleanup (easy);
}

static size_t
dict_recv (void *obj, const uint8_t *data, size_t len)
{
  return twist_dict_receive (obj, data, len);
}

static void
test_dict_one (const char *url, const char *expect, const char *what)
{
  struct twist_easy *easy = twist_easy_init ();
  struct twist_dict *d;
  const uint8_t *req;
  size_t n = 0;
  size_t en = strlen (expect);

  check (twist_url_parse_int (url, &easy->url) == TWIST_OK, what);
  check (easy->url->port == 2628, what);
  d = twist_dict_new (easy, 0);
  req = twist_dict_request (d, &n);
  check (d != NULL && !easy->done && n == en
         && memcmp (req, expect, en) == 0, what);
  twist_easy_cleanup (easy);
}

static void
test_dict (void)
{
  struct twist_easy *easy;
  struct twist_dict *d;
  static const uint8_t reply[] =
    "150 1 definitions retrieved\r\nhello\r\n250 ok\r\n";

  test_dict_one ("dict://127.0.0.1/d:hello:wn",
                 "CLIENT twist 0.1\r\nDEFINE wn hello\r\nQUIT\r\n",
                 "dict define");
  test_dict_one ("dict://127.0.0.1/m:hello",
                 "CLIENT twist 0.1\r\nMATCH ! . hello\r\nQUIT\r\n",
                 "dict match");
  test_dict_one ("dict://127.0.0.1/MATCH:foo:foldoc:exact:9",
                 "CLIENT twist 0.1\r\nMATCH foldoc exact foo\r\nQUIT\r\n",
                 "dict nth");
  test_dict_one ("dict://127.0.0.1/SHOW:DB",
                 "CLIENT twist 0.1\r\nSHOW DB\r\nQUIT\r\n",
                 "dict show");
  test_dict_one ("dict://127.0.0.1/d:hello%20world",
                 "CLIENT twist 0.1\r\nDEFINE ! hello\\ world\r\nQUIT\r\n",
                 "dict space");
  test_dict_one ("dict://127.0.0.1/d:a%22b%5Cc",
                 "CLIENT twist 0.1\r\nDEFINE ! a\\\"b\\\\c\r\nQUIT\r\n",
                 "dict escape");
  test_dict_one ("dict://127.0.0.1/d:word:db?x=1",
                 "CLIENT twist 0.1\r\nDEFINE db word\r\nQUIT\r\n",
                 "dict query");
  test_dict_one ("dict://127.0.0.1/",
                 "CLIENT twist 0.1\r\n\r\nQUIT\r\n",
                 "dict root");
  test_dict_one ("dict://127.0.0.1/d:",
                 "CLIENT twist 0.1\r\nDEFINE ! default\r\nQUIT\r\n",
                 "dict default");
  test_dict_one ("dict://127.0.0.1/FIND:bar:!:prefix",
                 "CLIENT twist 0.1\r\nMATCH ! prefix bar\r\nQUIT\r\n",
                 "dict find");
  test_dict_one ("dict://127.0.0.1/LOOKUP:Bar",
                 "CLIENT twist 0.1\r\nDEFINE ! Bar\r\nQUIT\r\n",
                 "dict lookup");
  test_dict_one ("dict://127.0.0.1/DeFiNe:Foo:*",
                 "CLIENT twist 0.1\r\nDEFINE * Foo\r\nQUIT\r\n",
                 "dict case");
  easy = twist_easy_init ();
  check (twist_url_parse_int ("dict://127.0.0.1/d:a%00", &easy->url)
         == TWIST_OK, "dict nul url");
  d = twist_dict_new (easy, 0);
  check (d != NULL && easy->done && easy->result == TWIST_ERR_URL,
         "dict nul");
  twist_easy_cleanup (easy);
  easy = twist_easy_init ();
  check (twist_url_parse_int ("dict://127.0.0.1/d:a%0a", &easy->url)
         == TWIST_OK, "dict lf url");
  d = twist_dict_new (easy, 0);
  check (d != NULL && easy->done && easy->result == TWIST_ERR_URL,
         "dict lf");
  twist_easy_cleanup (easy);
  easy = twist_easy_init ();
  check (twist_url_parse_int ("dict:///d:word", &easy->url) == TWIST_OK,
         "dict host url");
  d = twist_dict_new (easy, 0);
  check (d != NULL && easy->done && easy->result == TWIST_ERR_URL,
         "dict host");
  twist_easy_cleanup (easy);
  easy = twist_easy_init ();
  check (twist_url_parse_int ("dict://127.0.0.1/d:hello", &easy->url)
         == TWIST_OK, "dict body url");
  easy->write_cb = mail_write;
  mail_body_len = 0;
  d = twist_dict_new (easy, 0);
  feed_bin (dict_recv, d, reply, sizeof reply - 1, 1);
  check (mail_body_len == sizeof reply - 1
         && memcmp (mail_body, reply, mail_body_len) == 0, "dict body");
  check (!easy->done, "dict still open");
  twist_dict_closed (d, TWIST_ERR_CLOSED);
  check (easy->done && easy->result == TWIST_OK, "dict close");
  twist_easy_cleanup (easy);
  easy = twist_easy_init ();
  check (twist_url_parse_int ("dict://127.0.0.1/d:hello", &easy->url)
         == TWIST_OK, "dict early url");
  d = twist_dict_new (easy, 0);
  twist_dict_closed (d, TWIST_ERR_CLOSED);
  check (easy->done && easy->result == TWIST_ERR_CLOSED, "dict early close");
  twist_easy_cleanup (easy);
}

static size_t
tftp_read (char *ptr, size_t size, size_t nmemb, void *user)
{
  static const char chunk[] = "xy";
  static size_t off;
  size_t want = size * nmemb;
  size_t left;

  (void) user;
  if (ptr == NULL)
    {
      off = 0;
      return 0;
    }
  left = sizeof chunk - 1 - off;
  if (left > want)
    left = want;
  if (left == 0)
    return 0;
  memcpy (ptr, chunk + off, left);
  off += left;
  return left;
}

static void
test_tftp_is (struct twist_tftp *t, const uint8_t *expect, size_t n,
              const char *what)
{
  const uint8_t *pkt;
  size_t got = 0;

  pkt = twist_tftp_packet (t, &got);
  check (pkt != NULL && got == n && memcmp (pkt, expect, n) == 0, what);
}

static void
test_tftp (void)
{
  struct twist_easy *easy;
  struct twist_tftp *t;
  uint8_t block[4 + 512];
  static const uint8_t rrq[] = {
    0, 1,
    'h', 'e', 'l', 'l', 'o', 0,
    'o', 'c', 't', 'e', 't', 0,
    't', 's', 'i', 'z', 'e', 0,
    '0', 0,
    'b', 'l', 'k', 's', 'i', 'z', 'e', 0,
    '5', '1', '2', 0,
    't', 'i', 'm', 'e', 'o', 'u', 't', 0,
    '5', 0
  };
  static const uint8_t wrq[] = {
    0, 2,
    'u', 'p', 0,
    'o', 'c', 't', 'e', 't', 0,
    't', 's', 'i', 'z', 'e', 0,
    '3', 0,
    'b', 'l', 'k', 's', 'i', 'z', 'e', 0,
    '5', '1', '2', 0,
    't', 'i', 'm', 'e', 'o', 'u', 't', 0,
    '5', 0
  };
  static const uint8_t wrq_cb[] = {
    0, 2,
    'c', 'b', 0,
    'o', 'c', 't', 'e', 't', 0,
    't', 's', 'i', 'z', 'e', 0,
    '0', 0,
    'b', 'l', 'k', 's', 'i', 'z', 'e', 0,
    '5', '1', '2', 0,
    't', 'i', 'm', 'e', 'o', 'u', 't', 0,
    '5', 0
  };
  static const uint8_t data_abc[] = { 0, 3, 0, 1, 'a', 'b', 'c' };
  static const uint8_t data_xy[] = { 0, 3, 0, 1, 'x', 'y' };
  static const uint8_t ack0[] = { 0, 4, 0, 0 };
  static const uint8_t ack1[] = { 0, 4, 0, 1 };
  static const uint8_t ack2[] = { 0, 4, 0, 2 };
  static const uint8_t oack[] = {
    0, 6,
    'B', 'L', 'K', 'S', 'I', 'Z', 'E', 0,
    '5', '1', '2', 0
  };
  static const uint8_t oack_big[] = {
    0, 6,
    'b', 'l', 'k', 's', 'i', 'z', 'e', 0,
    '4', '0', '9', '6', 0
  };
  static const uint8_t oack_bad[] = { 0, 6, 'b', 'l', 'k' };
  static const uint8_t err_pkt[] = { 0, 5, 0, 1, 'n', 'o', 0 };
  static const uint8_t data_hi[] = { 0, 3, 0, 1, 'h', 'i' };
  int i;

  easy = twist_easy_init ();
  check (twist_url_parse_int ("tftp://127.0.0.1/hello", &easy->url) == TWIST_OK,
         "tftp url");
  check (easy->url->port == 69, "tftp port");
  t = twist_tftp_new (easy, 0);
  test_tftp_is (t, rrq, sizeof rrq, "tftp rrq");
  check (!easy->done, "tftp rrq open");
  twist_easy_cleanup (easy);

  easy = twist_easy_init ();
  check (twist_url_parse_int ("tftp://127.0.0.1/hello?x=1", &easy->url)
         == TWIST_OK, "tftp query url");
  t = twist_tftp_new (easy, 0);
  test_tftp_is (t, rrq, sizeof rrq, "tftp query");
  twist_easy_cleanup (easy);

  easy = twist_easy_init ();
  check (twist_url_parse_int ("tftp://127.0.0.1/", &easy->url) == TWIST_OK,
         "tftp empty url");
  t = twist_tftp_new (easy, 0);
  check (t != NULL && easy->done && easy->result == TWIST_ERR_URL,
         "tftp empty");
  twist_easy_cleanup (easy);

  easy = twist_easy_init ();
  check (twist_url_parse_int ("tftp://127.0.0.1/a%00", &easy->url) == TWIST_OK,
         "tftp nul url");
  t = twist_tftp_new (easy, 0);
  check (t != NULL && easy->done && easy->result == TWIST_ERR_URL, "tftp nul");
  twist_easy_cleanup (easy);

  static char upload[] = "abc";

  easy = twist_easy_init ();
  check (twist_url_parse_int ("tftp://127.0.0.1/up", &easy->url) == TWIST_OK,
         "tftp put url");
  easy->postfields = upload;
  easy->postfieldsize = 3;
  easy->postfieldsize_set = 1;
  t = twist_tftp_new (easy, 0);
  test_tftp_is (t, wrq, sizeof wrq, "tftp wrq");
  twist_tftp_receive (t, ack0, sizeof ack0);
  test_tftp_is (t, data_abc, sizeof data_abc, "tftp data");
  check (!easy->done, "tftp put open");
  twist_tftp_receive (t, ack1, sizeof ack1);
  check (easy->done && easy->result == TWIST_OK, "tftp put done");
  easy->postfields = NULL;
  twist_easy_cleanup (easy);

  easy = twist_easy_init ();
  check (twist_url_parse_int ("tftp://127.0.0.1/cb", &easy->url) == TWIST_OK,
         "tftp read url");
  tftp_read (NULL, 0, 0, NULL);
  easy->read_cb = tftp_read;
  t = twist_tftp_new (easy, 0);
  test_tftp_is (t, wrq_cb, sizeof wrq_cb, "tftp wrq cb");
  twist_tftp_receive (t, ack0, sizeof ack0);
  test_tftp_is (t, data_xy, sizeof data_xy, "tftp data cb");
  twist_tftp_receive (t, ack1, sizeof ack1);
  check (easy->done && easy->result == TWIST_OK, "tftp read done");
  twist_easy_cleanup (easy);

  easy = twist_easy_init ();
  check (twist_url_parse_int ("tftp://127.0.0.1/hello", &easy->url) == TWIST_OK,
         "tftp get url");
  easy->write_cb = mail_write;
  mail_body_len = 0;
  t = twist_tftp_new (easy, 0);
  twist_tftp_receive (t, oack, sizeof oack);
  test_tftp_is (t, ack0, sizeof ack0, "tftp oack");
  check (!easy->done, "tftp oack open");
  twist_tftp_receive (t, data_hi, sizeof data_hi);
  test_tftp_is (t, ack1, sizeof ack1, "tftp ack hi");
  check (mail_body_len == 2 && memcmp (mail_body, "hi", 2) == 0, "tftp body");
  check (easy->done && easy->result == TWIST_OK, "tftp get done");
  twist_easy_cleanup (easy);

  easy = twist_easy_init ();
  check (twist_url_parse_int ("tftp://127.0.0.1/hello", &easy->url) == TWIST_OK,
         "tftp blocks url");
  t = twist_tftp_new (easy, 0);
  memset (block, 'a', sizeof block);
  block[0] = 0;
  block[1] = 3;
  block[2] = 0;
  block[3] = 1;
  twist_tftp_receive (t, block, sizeof block);
  check (!easy->done && easy->size_download == 512, "tftp full");
  test_tftp_is (t, ack1, sizeof ack1, "tftp ack full");
  twist_tftp_receive (t, block, sizeof block);
  check (!easy->done && easy->size_download == 512, "tftp dup");
  block[3] = 3;
  twist_tftp_receive (t, block, 4 + 8);
  check (!easy->done && easy->size_download == 512, "tftp skip");
  test_tftp_is (t, ack1, sizeof ack1, "tftp ack held");
  block[3] = 2;
  twist_tftp_receive (t, block, 4);
  test_tftp_is (t, ack2, sizeof ack2, "tftp ack end");
  check (easy->done && easy->result == TWIST_OK
         && easy->size_download == 512, "tftp end");
  twist_easy_cleanup (easy);

  easy = twist_easy_init ();
  check (twist_url_parse_int ("tftp://127.0.0.1/hello", &easy->url) == TWIST_OK,
         "tftp err url");
  t = twist_tftp_new (easy, 0);
  twist_tftp_receive (t, err_pkt, sizeof err_pkt);
  check (easy->done && easy->result == TWIST_ERR_FILE, "tftp missing");
  twist_easy_cleanup (easy);

  easy = twist_easy_init ();
  check (twist_url_parse_int ("tftp://127.0.0.1/hello", &easy->url) == TWIST_OK,
         "tftp big url");
  t = twist_tftp_new (easy, 0);
  twist_tftp_receive (t, oack_big, sizeof oack_big);
  check (easy->done && easy->result == TWIST_ERR_PROTOCOL, "tftp big blk");
  check (t != NULL && twist_tftp_packet (t, NULL)[1] == 5, "tftp error op");
  twist_easy_cleanup (easy);

  easy = twist_easy_init ();
  check (twist_url_parse_int ("tftp://127.0.0.1/hello", &easy->url) == TWIST_OK,
         "tftp bad url");
  t = twist_tftp_new (easy, 0);
  twist_tftp_receive (t, oack_bad, sizeof oack_bad);
  check (easy->done && easy->result == TWIST_ERR_PROTOCOL, "tftp bad oack");
  twist_easy_cleanup (easy);

  easy = twist_easy_init ();
  check (twist_url_parse_int ("tftp://127.0.0.1/hello", &easy->url) == TWIST_OK,
         "tftp time url");
  t = twist_tftp_new (easy, 0);
  for (i = 0; i < 8 && !easy->done; i++)
    twist_tftp_timeout (t);
  check (easy->done && easy->result == TWIST_ERR_CONNECT && i == 6,
         "tftp timeout");
  twist_easy_cleanup (easy);

  easy = twist_easy_init ();
  check (twist_url_parse_int ("tftp://127.0.0.1/hello", &easy->url) == TWIST_OK,
         "tftp proxy url");
  check (twist_easy_setopt (easy, TWISTOPT_PROXY, "http://127.0.0.1:9")
         == TWIST_OK, "tftp proxy set");
  t = twist_tftp_new (easy, 0);
  check (t != NULL && easy->done && easy->result == TWIST_ERR_UNSUPPORTED,
         "tftp proxy");
  twist_easy_cleanup (easy);
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

static void
test_client_auth (void)
{
  static const char pem[] =
    "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n"
    "-----BEGIN CERTIFICATE-----\nAQIDBA==\n-----END CERTIFICATE-----\n"
    "-----BEGIN CERTIFICATE-----\nBQYH\n-----END CERTIFICATE-----\n";
  gq_slice chain[4];
  size_t n = 0;
  uint8_t *storage = NULL;
  struct twist_client_auth *auth = NULL;
  struct gq_tls_info info;

  check (twist_pem_certificates (pem, sizeof pem - 1, chain, 4, &n, &storage)
         == TWIST_OK && n == 2, "pem certs");
  check (storage != NULL && chain[0].len == 4 && chain[0].data[0] == 1
         && chain[0].data[1] == 2 && chain[0].data[2] == 3
         && chain[0].data[3] == 4 && chain[1].len == 3
         && chain[1].data[0] == 5 && chain[1].data[1] == 6
         && chain[1].data[2] == 7, "pem der");
  free (storage);
  storage = NULL;
  check (twist_pem_certificates ("nope", 4, chain, 4, &n, &storage)
         == TWIST_ERR_TLS && storage == NULL, "pem none");
  check (twist_client_auth_load (&auth, NULL, NULL) == TWIST_OK
         && auth == NULL, "client auth absent");
  check (twist_client_auth_load (&auth, "cert.pem", NULL) == TWIST_ERR_INVAL,
         "client auth half");
  memset (&info, 0, sizeof info);
  check (!twist_client_auth_missing (&info), "mtls quiet");
  info.client_auth_requested = 1;
  check (twist_client_auth_missing (&info), "mtls required");
  info.client_auth_sent = 1;
  check (!twist_client_auth_missing (&info), "mtls sent");
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

static int file_body_calls;
static int file_hopped;

static size_t
file_body (char *ptr, size_t size, size_t nmemb, void *userdata)
{
  (void) ptr;
  (void) size;
  (void) nmemb;
  (void) userdata;
  file_body_calls++;
  return nmemb;
}

static void
file_hop_done (void *user)
{
  int *flag = user;

  *flag = 1;
}

static void
file_hop_work (void *arg)
{
  struct twist_loop *loop = arg;

  twist_loop_post (loop, file_hop_done, &file_hopped);
}

static void
test_file_pool (void)
{
  struct twist_easy *easy;
  struct twist_multi *multi;

  easy = twist_easy_init ();
  check (easy != NULL, "file easy");
  check (twist_easy_setopt (easy, TWISTOPT_URL, "file://example.com/a")
         == TWIST_OK, "file url");
  easy->write_cb = file_body;
  multi = twist_multi_init ();
  check (multi != NULL && multi->storage != NULL, "file pool");
  check (twist_multi_add_handle (multi, easy) == TWIST_ERR_URL, "file remote");
  check (easy->done && easy->result == TWIST_ERR_URL && file_body_calls == 0,
         "file remote done");
  twist_multi_cleanup (multi);
  twist_easy_cleanup (easy);

  file_hopped = 0;
  multi = twist_multi_init ();
  check (multi != NULL, "file hop multi");
  check (twist_storage_submit (multi->storage, file_hop_work, multi->loop,
                               NULL, NULL, NULL) == TWIST_OK, "file hop submit");
  check (twist_loop_run_once (multi->loop) == TWIST_OK && file_hopped == 1,
         "file hop");
  twist_multi_cleanup (multi);
}

static void
test_conn_pool (void)
{
  struct twist_loop *loop = twist_loop_new (1);
  struct twist_pool *pool = twist_pool_new ();
  struct twist_connection *got = NULL;
  int i;
  int n = 0;
  char key[16];

  check (loop != NULL && pool != NULL, "pool alloc");
  for (i = 0; i < 9; i++)
    {
      struct twist_connection *c = twist_connection_new (loop);

      check (c != NULL
             && twist_pool_put_idle (pool, "h", c, 1000) == TWIST_OK,
             "pool put");
    }
  while (twist_pool_take (pool, "h", &got) == TWIST_OK)
    {
      n++;
      twist_connection_free (got);
    }
  check (n == 8, "pool per-host cap");
  for (i = 0; i < 33; i++)
    {
      struct twist_connection *c = twist_connection_new (loop);

      snprintf (key, sizeof key, "k%d", i);
      check (c != NULL
             && twist_pool_put_idle (pool, key, c, 5000) == TWIST_OK,
             "pool many");
    }
  n = 0;
  for (i = 0; i < 33; i++)
    {
      snprintf (key, sizeof key, "k%d", i);
      if (twist_pool_take (pool, key, &got) == TWIST_OK)
        {
          n++;
          twist_connection_free (got);
        }
    }
  check (n == 32, "pool total cap");
  {
    struct twist_connection *c = twist_connection_new (loop);

    check (twist_pool_put_idle (pool, "old", c, 0) == TWIST_OK, "pool age put");
    twist_pool_expire (pool, 117999);
    check (twist_pool_take (pool, "old", &got) == TWIST_OK, "pool not expired");
    twist_connection_free (got);
    c = twist_connection_new (loop);
    check (twist_pool_put_idle (pool, "old", c, 0) == TWIST_OK, "pool age put 2");
    twist_pool_expire (pool, 118000);
    check (twist_pool_take (pool, "old", &got) == TWIST_ERR_AGAIN, "pool expired");
  }
  twist_pool_free (pool);
  twist_loop_free (loop);
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

static int
on_multi_socket (twist_easy *easy, int fd, int what, void *user, void *socketp)
{
  int *saw = user;

  (void) easy;
  (void) fd;
  (void) what;
  (void) socketp;
  if (saw != NULL)
    *saw = 1;
  return 0;
}

static void
test_multi_perform (void)
{
  struct twist_multi *multi = twist_multi_init ();
  int running = -1;
  int saw = 0;

  check (multi != NULL, "multi");
  check (twist_multi_perform (multi, &running) == TWIST_OK && running == 0,
         "multi perform");
  twist_multi_setopt (multi, TWISTMOPT_SOCKETDATA, &saw);
  twist_multi_setopt (multi, TWISTMOPT_SOCKETFUNCTION, on_multi_socket);
  check (saw == 1, "multi waker");
  twist_multi_cleanup (multi);
}

static void
test_h2_share (void)
{
  struct twist_h1_events ev;
  struct twist_h2 *h2;
  struct twist_multi *multi;
  struct twist_session *sess;
  uint8_t *a = NULL;
  uint8_t *b = NULL;
  size_t an = 0;
  size_t bn = 0;
  uint8_t settings[] = {
    0, 0, 6, 4, 0, 0, 0, 0, 0,
    0, 3, 0, 0, 0, 1
  };
  uint8_t end[] = { 0, 0, 0, 0, 1, 0, 0, 0, 1 };

  memset (&ev, 0, sizeof ev);
  h2 = twist_h2_new (&ev);
  multi = twist_multi_init ();
  check (h2 != NULL && multi != NULL && twist_h2_can_open (h2), "h2 room");
  sess = twist_session_add (multi, "k", multi->loop, NULL, h2);
  check (sess != NULL && twist_session_find (multi, "k", multi->loop) == sess,
         "h2 find");
  check (twist_h2_request (h2, "GET", "https", "ex", "/", NULL, NULL, 0, 1,
                           &a, &an) == TWIST_OK
         && an >= 9 && a[8] == 1, "h2 stream 1");
  check (twist_h2_receive (h2, settings, sizeof settings) == sizeof settings,
         "h2 limit");
  check (!twist_h2_can_open (h2), "h2 full");
  check (twist_h2_request (h2, "GET", "https", "ex", "/", NULL, NULL, 0, 0,
                           &b, &bn) != TWIST_OK, "h2 blocked");
  check (twist_h2_receive (h2, end, sizeof end) == sizeof end, "h2 end");
  check (twist_h2_can_open (h2), "h2 room again");
  free (b);
  b = NULL;
  check (twist_h2_request (h2, "GET", "https", "ex", "/", NULL, NULL, 0, 1,
                           &b, &bn) == TWIST_OK
         && bn >= 9 && b[8] == 3, "h2 stream 3");
  check (twist_session_find (multi, "k", multi->loop) == NULL, "h2 no room");
  free (a);
  free (b);
  twist_multi_cleanup (multi);
}

int
main (void)
{
  test_timer ();
  test_conn_pool ();
  test_dns_cache ();
  test_h2_share ();
  test_multi_perform ();
  test_cmdq ();
  test_h1 ();
  test_h2 ();
  test_h3 ();
  test_url ();
  test_auth ();
  test_sasl ();
  test_cookie ();
  test_dns ();
  test_doh ();
  test_svcb ();
  test_client_auth ();
  test_file_pool ();
  test_scheme ();
  test_connection ();
  test_proxy ();
  test_ftp_parser ();
  test_ftp_session ();
  test_inbound_ceiling ();
  test_errors ();
  test_mail ();
  test_mqtt_ldap ();
  test_ws ();
  test_gopher ();
  test_dict ();
  test_tftp ();
  if (failed)
    {
      fprintf (stderr, "unit tests failed\n");
      return 1;
    }
  return 0;
}
