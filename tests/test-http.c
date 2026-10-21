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
#include "http-ev.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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

/* A server's SETTINGS and WINDOW_UPDATE decide how much may be sent, in
   numbers of 31 bits.  What does not fit is the server's error, a flow control
   error, and not a number that wraps.  (Found by fuzzing.)  */
struct h2_seen
{
  int failures;
  int err;
};

static void
h2_seen_failure (void *user, int err)
{
  struct h2_seen *seen = user;

  seen->failures++;
  seen->err = err;
}

static int
h2_emit_none (void *user, const uint8_t *data, size_t len)
{
  (void) user;
  (void) data;
  (void) len;
  return 0;
}

static struct twist_h2 *
h2_with_stream (struct h2_seen *seen, const uint8_t *payload, size_t payload_len)
{
  struct twist_h1_events ev;
  struct twist_h2 *h;
  uint8_t *out = NULL;
  size_t n = 0;

  memset (&ev, 0, sizeof ev);
  ev.user = seen;
  ev.failure = h2_seen_failure;
  memset (seen, 0, sizeof *seen);
  h = twist_h2_new (&ev);
  twist_h2_set_emit (h, h2_emit_none, NULL);
  if (twist_h2_request (h, "POST", "https", "ex", "/", NULL, payload,
                        payload_len, 1, &out, &n) == TWIST_OK)
    free (out);
  return h;
}

static void
h2_settings_window (struct twist_h2 *h, uint32_t value)
{
  uint8_t f[15] = { 0, 0, 6, 4, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0 };

  f[11] = (uint8_t) (value >> 24);
  f[12] = (uint8_t) (value >> 16);
  f[13] = (uint8_t) (value >> 8);
  f[14] = (uint8_t) value;
  twist_h2_receive (h, f, sizeof f);
}

static void
h2_window_update (struct twist_h2 *h, uint32_t stream, uint32_t inc)
{
  uint8_t f[13] = { 0, 0, 4, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0 };

  f[5] = (uint8_t) (stream >> 24);
  f[6] = (uint8_t) (stream >> 16);
  f[7] = (uint8_t) (stream >> 8);
  f[8] = (uint8_t) stream;
  f[9] = (uint8_t) (inc >> 24);
  f[10] = (uint8_t) (inc >> 16);
  f[11] = (uint8_t) (inc >> 8);
  f[12] = (uint8_t) inc;
  twist_h2_receive (h, f, sizeof f);
}

static void
test_h2_windows (void)
{
  struct h2_seen seen;
  struct twist_h2 *h;
  static uint8_t data[40000];

  /* An initial window of more than 2^31-1 is not a number.  */
  h = h2_with_stream (&seen, NULL, 0);
  h2_settings_window (h, 0x80000000u);
  check (seen.failures == 1 && seen.err == TWIST_ERR_PROTOCOL,
         "an initial window of 2^31 is refused");
  twist_h2_free (h);
  h = h2_with_stream (&seen, NULL, 0);
  h2_settings_window (h, 0xffffffffu);
  check (seen.failures == 1, "and one of 2^32-1");
  twist_h2_free (h);
  h = h2_with_stream (&seen, NULL, 0);
  h2_settings_window (h, 0x7fffffffu);
  check (seen.failures == 0, "the largest there can be is not");
  twist_h2_free (h);

  /* A setting that takes a stream's window past 2^31-1.  */
  h = h2_with_stream (&seen, NULL, 0);
  h2_window_update (h, 1, 100000);
  h2_settings_window (h, 0x7fffffffu);
  check (seen.failures == 1 && seen.err == TWIST_ERR_PROTOCOL,
         "a setting that makes a window too big is refused");
  twist_h2_free (h);

  /* A window can go below zero when the setting is lowered; it is then
     made up by updates, and the limit is still the limit.  */
  memset (data, 'x', sizeof data);
  h = h2_with_stream (&seen, data, sizeof data);
  h2_settings_window (h, 0);
  check (seen.failures == 0, "a window made negative is allowed");
  h2_window_update (h, 1, 0x7fffffffu);
  check (seen.failures == 0, "and made up with the largest update");
  h2_window_update (h, 1, 40001);
  check (seen.failures == 1 && seen.err == TWIST_ERR_PROTOCOL,
         "one more than 2^31-1 is refused");
  twist_h2_free (h);
}

/* The HPACK dynamic table is a number of bytes (RFC 7541, 4.1): an entry is
   its name and value and 32, and the table is 4096 unless it is changed with
   a size update (6.3), which may not be more than we allow.  A server may
   rely on all of it.  */
static unsigned long hp_headers;
static char hp_last_name[64], hp_last_value[64];

static void
hp_header (void *user, const char *name, size_t nn, const char *value, size_t vn)
{
  (void) user;
  hp_headers++;
  snprintf (hp_last_name, sizeof hp_last_name, "%.*s", (int) nn, name);
  snprintf (hp_last_value, sizeof hp_last_value, "%.*s", (int) vn, value);
}

/* A literal with indexing: name NAME, value of VLEN copies of V, all of it.  */
static size_t
hp_literal (uint8_t *out, const char *name, char v, size_t vlen)
{
  size_t n = 0, nl = strlen (name), rest;

  out[n++] = 0x40;
  out[n++] = (uint8_t) nl;
  memcpy (out + n, name, nl);
  n += nl;
  if (vlen < 127)
    out[n++] = (uint8_t) vlen;
  else
    {
      out[n++] = 127;
      rest = vlen - 127;
      while (rest >= 128)
        {
          out[n++] = (uint8_t) (rest & 127) | 0x80;
          rest >>= 7;
        }
      out[n++] = (uint8_t) rest;
    }
  memset (out + n, v, vlen);
  return n + vlen;
}

static int
hp_decode (struct twist_hpack *hp, const uint8_t *data, size_t n)
{
  struct twist_h1_events ev;

  memset (&ev, 0, sizeof ev);
  ev.header = hp_header;
  hp_headers = 0;
  return twist_hpack_decode (hp, data, n, &ev);
}

static void
test_hpack_table (void)
{
  struct twist_hpack *hp = twist_hpack_new ();
  uint8_t blk[8000];
  size_t n, i;
  static const uint8_t size_4096[] = { 0x3f, 0xe1, 0x1f, 0x82 };
  static const uint8_t size_4097[] = { 0x3f, 0xe2, 0x1f, 0x82 };
  static const uint8_t size_0_then_literal[] = { 0x20, 0x40, 0x01, 'a', 0x01, 'b' };
  static const uint8_t first_entry[] = { 0xbe };
  static const uint8_t second_entry[] = { 0xbf };

  /* A size update is not a literal header.  */
  check (hp_decode (hp, size_4096, sizeof size_4096) == TWIST_OK
         && hp_headers == 1 && strcmp (hp_last_name, ":method") == 0,
         "a size update to 4096, then an indexed header");
  check (hp_decode (hp, size_4097, sizeof size_4097) == TWIST_ERR_PROTOCOL,
         "a size above what we allow is refused");
  twist_hpack_free (hp);

  /* A table of size 0 keeps nothing.  */
  hp = twist_hpack_new ();
  check (hp_decode (hp, size_0_then_literal, sizeof size_0_then_literal)
         == TWIST_OK && hp_headers == 1 && strcmp (hp_last_name, "a") == 0,
         "a literal after a size update to 0 is still a header");
  check (hp_decode (hp, first_entry, sizeof first_entry) == TWIST_ERR_PROTOCOL,
         "and is not in the table");
  twist_hpack_free (hp);

  /* A hundred small entries all fit in 4096 bytes: 34 each, 3400.  The
     oldest is index 61 + 100.  */
  hp = twist_hpack_new ();
  for (i = 0; i < 100; i++)
    {
      char name[8];

      snprintf (name, sizeof name, "n%03zu", i);
      n = hp_literal (blk, name, 'v', 1);
      check (hp_decode (hp, blk, n) == TWIST_OK, "a small entry");
    }
  {
    static const uint8_t oldest[] = { 0xff, 0x22 };	/* 127 + 34 = 161 */

    check (hp_decode (hp, oldest, sizeof oldest) == TWIST_OK
           && strcmp (hp_last_name, "n000") == 0,
           "the hundredth entry back is there");
  }
  twist_hpack_free (hp);

  /* By size, not by number: two entries of 3000 do not both fit.  */
  hp = twist_hpack_new ();
  n = hp_literal (blk, "big1", 'x', 3000);
  check (hp_decode (hp, blk, n) == TWIST_OK, "a big entry");
  n = hp_literal (blk, "big2", 'y', 3000);
  check (hp_decode (hp, blk, n) == TWIST_OK, "another");
  check (hp_decode (hp, first_entry, sizeof first_entry) == TWIST_OK
         && strcmp (hp_last_name, "big2") == 0, "the newer is kept");
  check (hp_decode (hp, second_entry, sizeof second_entry)
         == TWIST_ERR_PROTOCOL, "and the older was made room of");
  twist_hpack_free (hp);

  /* One bigger than the table empties it and is not kept.  */
  hp = twist_hpack_new ();
  n = hp_literal (blk, "small", 's', 1);
  check (hp_decode (hp, blk, n) == TWIST_OK, "a small entry first");
  n = hp_literal (blk, "huge", 'h', 5000);
  check (hp_decode (hp, blk, n) == TWIST_OK && hp_headers == 1,
         "an entry of 5000 is a header");
  check (hp_decode (hp, first_entry, sizeof first_entry) == TWIST_ERR_PROTOCOL,
         "and the table is empty");
  twist_hpack_free (hp);
}

static void
test_qpack_static_index (void)
{
  /* Prefix 0 0; a literal field with a name from the static table (T set),
     index 142, which the table has not got; then an empty value.  */
  static const uint8_t bad[] = { 0x00, 0x00, 0x5f, 0x7f, 0x00 };
  /* The last entry that it has (98) is fine.  */
  static const uint8_t last[] = { 0x00, 0x00, 0x5f, 0x53, 0x00 };
  struct twist_h1_events ev = test_events ();

  check (twist_qpack_decode (bad, sizeof bad, &ev) == TWIST_ERR_PROTOCOL,
         "a name from past the end of the static table");
  check (twist_qpack_decode (last, sizeof last, &ev) == TWIST_OK,
         "and from its last entry");
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
  check (twist_jar_store (jar, "a=b; Domain=bank.example", "evil.example", "/",
                          1) == TWIST_ERR_PROTOCOL, "foreign domain");
  check (twist_jar_store (jar, "a=b\r\nX: y; Path=/", "example.com", "/", 1)
         == TWIST_ERR_PROTOCOL, "cookie ctl");
  check (twist_jar_store (jar, "id=1; Domain=example.com", "www.example.com",
                          "/", 1) == TWIST_OK, "parent domain");
  check (twist_jar_header (jar, "www.example.com", "/", 1, &hdr) == TWIST_OK
         && hdr != NULL && strstr (hdr, "id=1") != NULL, "parent send");
  free (hdr);
  hdr = NULL;
  check (twist_jar_header (jar, "other.test", "/", 1, &hdr) == TWIST_OK
         && (hdr == NULL || strstr (hdr, "id=1") == NULL), "parent miss");
  free (hdr);
  twist_jar_free (jar);
}

static void
test_hpack_long (void)
{
  struct twist_hpack *hp = twist_hpack_new ();
  char path[301];
  uint8_t *out = NULL;
  size_t n = 0;

  memset (path, 'a', 300);
  path[300] = 0;
  check (hp != NULL, "hpack");
  check (twist_hpack_encode_request (hp, "GET", "https", "h", path, NULL,
                                     &out, &n) == TWIST_OK, "hpack enc");
  check (out != NULL && n > 306 && out[0] == 0x82 && out[1] == 0x87
         && out[2] == 0x44 && out[3] == 0x7f && out[4] == (173 | 128)
         && out[5] == 1 && memcmp (out + 6, path, 300) == 0, "hpack len");
  free (out);
  twist_hpack_free (hp);
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

static void
test_http_status (void)
{
  check (twist_http_status_result (0, 404) == TWIST_OK, "404 ok");
  check (twist_http_status_result (1, 404) == TWIST_ERR_HTTP, "404 fail");
  check (twist_http_status_result (1, 200) == TWIST_OK, "200 ok");
  check (twist_http_status_result (1, 399) == TWIST_OK, "399 ok");
  check (twist_http_status_result (1, 400) == TWIST_ERR_HTTP, "400 fail");
}

int
main (void)
{
  test_h1 ();
  test_h2 ();
  test_h3 ();
  test_h2_windows ();
  test_hpack_table ();
  test_qpack_static_index ();
  test_cookie ();
  test_hpack_long ();
  test_h2_share ();
  test_http_status ();
  return tests_finish ();
}
