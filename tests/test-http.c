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

/* A response that has no body, though it may say it has one: to a HEAD
   request, or a 204 or a 304 (RFC 9112, 6.3).  The parser must not wait for
   what is never sent, or for the connection to close.  */
static void
test_h1_no_body (void)
{
  static const char head[] =
    "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n";
  static const char chunked[] =
    "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n";
  static const char not_modified[] =
    "HTTP/1.1 304 Not Modified\r\nContent-Length: 5\r\n\r\n";
  static const char no_content[] =
    "HTTP/1.1 204 No Content\r\nContent-Length: 5\r\n\r\n";
  struct twist_h1_events ev = test_events ();
  struct twist_h1 *h;
  size_t split;

  for (split = 1; split <= 4; split *= 4)
    {
      h = twist_h1_new (&ev);
      reset_ev ();
      twist_h1_set_head (h, 1);
      feed_all (h1_recv, h, (const uint8_t *) head, sizeof head - 1, split);
      check (saw_status == 200 && saw_done == 1 && body_len == 0,
             "a response to HEAD is done at the headers");
      twist_h1_free (h);

      h = twist_h1_new (&ev);
      reset_ev ();
      twist_h1_set_head (h, 1);
      feed_all (h1_recv, h, (const uint8_t *) chunked, sizeof chunked - 1,
                split);
      check (saw_done == 1 && body_len == 0,
             "and one that says it is chunked");
      twist_h1_free (h);

      h = twist_h1_new (&ev);
      reset_ev ();
      feed_all (h1_recv, h, (const uint8_t *) head, sizeof head - 1, split);
      check (saw_status == 200 && saw_done == 0,
             "to anything else the same headers promise a body");
      twist_h1_free (h);

      h = twist_h1_new (&ev);
      reset_ev ();
      feed_all (h1_recv, h, (const uint8_t *) not_modified,
                sizeof not_modified - 1, split);
      check (saw_status == 304 && saw_done == 1 && body_len == 0,
             "a 304 has no body");
      twist_h1_free (h);

      h = twist_h1_new (&ev);
      reset_ev ();
      feed_all (h1_recv, h, (const uint8_t *) no_content,
                sizeof no_content - 1, split);
      check (saw_status == 204 && saw_done == 1 && body_len == 0,
             "nor a 204");
      twist_h1_free (h);
    }
}

/* Open stream 1 by sending a request: a response only follows one, and a
   frame on a stream that was not opened is a connection error.  */
static void
h2_open_stream (struct twist_h2 *h)
{
  uint8_t *out = NULL;
  size_t n = 0;

  if (twist_h2_request (h, "GET", "https", "h", "/", NULL, NULL, 0, 0, &out,
                        &n) != TWIST_OK)
    abort ();
  free (out);
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
  h2_open_stream (h);
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
        h2_open_stream (h);
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

/* A CONNECT tunnel on a stream of HTTP/2 (RFC 9113, 8.5): the request has the
   method and the authority and nothing else of the pseudo-headers, and the
   data on the stream goes out in frames that keep to the windows and to the
   frame size, waiting for the peer's updates when they are used up.  */
static uint8_t tun_out[300000];
static size_t tun_out_n;
static int tun_writable;

static int
tun_emit (void *user, const uint8_t *data, size_t len)
{
  (void) user;
  if (tun_out_n + len > sizeof tun_out)
    return TWIST_ERR_NOMEM;
  memcpy (tun_out + tun_out_n, data, len);
  tun_out_n += len;
  return 0;
}

static void
tun_ready (void *user)
{
  (void) user;
  tun_writable++;
}

static char tun_names[8][32];
static char tun_values[8][64];
static size_t tun_seen;

static void
tun_header (void *user, const char *name, size_t nn, const char *value,
            size_t vn)
{
  (void) user;
  if (tun_seen < 8)
    {
      snprintf (tun_names[tun_seen], sizeof tun_names[0], "%.*s", (int) nn,
                name);
      snprintf (tun_values[tun_seen], sizeof tun_values[0], "%.*s", (int) vn,
                value);
      tun_seen++;
    }
}

/* The DATA frames in OUT from OFFSET: how many bytes they carry, and a check
   that each is on stream ID and no longer than the frame size.  Returns the
   total, or -1 if a frame is wrong.  *ENDS is the number with END_STREAM.  */
static long
tun_frames (size_t offset, uint32_t id, int *ends)
{
  long total = 0;

  *ends = 0;
  while (offset + 9 <= tun_out_n)
    {
      size_t len = ((size_t) tun_out[offset] << 16)
                   | ((size_t) tun_out[offset + 1] << 8) | tun_out[offset + 2];
      uint32_t sid = ((uint32_t) tun_out[offset + 5] << 24)
                     | ((uint32_t) tun_out[offset + 6] << 16)
                     | ((uint32_t) tun_out[offset + 7] << 8)
                     | tun_out[offset + 8];

      if (tun_out[offset + 3] != 0 || sid != id || len > 16384
          || offset + 9 + len > tun_out_n)
        return -1;
      if (tun_out[offset + 4] & 1)
        (*ends)++;
      total += (long) len;
      offset += 9 + len;
    }
  return total;
}

static void
test_h2_tunnel (void)
{
  struct twist_h2 *h;
  struct twist_hpack *hp;
  struct twist_h1_events ev;
  struct twist_slist *extra = twist_slist_append (NULL,
                                                  "proxy-authorization: Basic eDp5");
  uint8_t *out = NULL;
  size_t n = 0;
  static uint8_t data[100000];
  size_t sent;
  size_t mark;
  int ends;

  memset (data, 'x', sizeof data);
  memset (&ev, 0, sizeof ev);
  h = twist_h2_new (&ev);
  twist_h2_set_emit (h, tun_emit, NULL);
  twist_h2_set_writable (h, tun_ready, NULL);
  check (twist_h2_request (h, "CONNECT", NULL, "example.org:443", NULL, extra,
                           NULL, 0, 1, &out, &n) == TWIST_OK, "a CONNECT request");
  /* The block after the 9 bytes of the frame header.  */
  check (n > 9 && out[3] == 1 && (out[4] & 4) != 0 && (out[4] & 1) == 0,
         "HEADERS with END_HEADERS, and the stream is left open");
  memset (&ev, 0, sizeof ev);
  ev.header = tun_header;
  hp = twist_hpack_new ();
  tun_seen = 0;
  check (twist_hpack_decode (hp, out + 9, n - 9, &ev) == TWIST_OK
         && tun_seen == 3
         && strcmp (tun_names[0], ":method") == 0
         && strcmp (tun_values[0], "CONNECT") == 0
         && strcmp (tun_names[1], ":authority") == 0
         && strcmp (tun_values[1], "example.org:443") == 0
         && strcmp (tun_names[2], "proxy-authorization") == 0,
         "CONNECT has :method and :authority, no :scheme and no :path");
  twist_hpack_free (hp);
  free (out);
  check (twist_h2_last_stream (h) == 1, "the stream is 1");

  /* The first window is 65535 for the connection and for the stream.  */
  tun_out_n = 0;
  sent = twist_h2_send_data (h, 1, data, sizeof data, 0);
  check (sent == 65535, "a send stops at the window");
  check (tun_frames (0, 1, &ends) == 65535 && ends == 0,
         "frames of at most 16384, on the stream");
  check (twist_h2_send_data (h, 1, data + sent, sizeof data - sent, 0) == 0,
         "and nothing more until the window is opened");
  check (twist_h2_send_data (h, 3, data, 10, 0) == 0, "no such stream: none");

  /* An update on the connection alone is not enough, and the caller is told
     when it might be: after each.  */
  mark = tun_out_n;
  tun_writable = 0;
  h2_window_update (h, 0, 100000);
  check (tun_writable == 1, "told of a window update");
  check (twist_h2_send_data (h, 1, data + sent, sizeof data - sent, 0) == 0,
         "the stream's window is shut as well");
  h2_window_update (h, 1, 100000);
  check (tun_writable == 2, "and of the next");
  n = twist_h2_send_data (h, 1, data + sent, sizeof data - sent, 0);
  check (n == sizeof data - sent && tun_frames (mark, 1, &ends) == (long) n,
         "the rest goes");

  /* The end of the stream, in a frame of no data, which needs no window.  */
  mark = tun_out_n;
  check (twist_h2_send_data (h, 1, NULL, 0, 1) == 0 && tun_frames (mark, 1, &ends) == 0
         && ends == 1, "END_STREAM in an empty DATA frame");
  twist_h2_free (h);
  twist_slist_free_all (extra);
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

/* QPACK as RFC 9204 has it: a request is written with the static table and
   literals, and a section is read with names and values as literals, with
   Huffman coding, and with indices; the dynamic table is refused.  */
static char qp_names[12][40];
static char qp_values[12][512];
static int qp_seen;

static void
qp_collect (void *user, const char *name, size_t nn, const char *value,
            size_t vn)
{
  (void) user;
  if (qp_seen < 12)
    {
      snprintf (qp_names[qp_seen], sizeof qp_names[0], "%.*s", (int) nn, name);
      snprintf (qp_values[qp_seen], sizeof qp_values[0], "%.*s", (int) vn,
                value);
      qp_seen++;
    }
}

static int
qp_has (const char *name, const char *value)
{
  int i;

  for (i = 0; i < qp_seen; i++)
    if (strcmp (qp_names[i], name) == 0 && strcmp (qp_values[i], value) == 0)
      return 1;
  return 0;
}

static int
qp_decode (const uint8_t *data, size_t n)
{
  struct twist_h1_events ev;

  memset (&ev, 0, sizeof ev);
  ev.header = qp_collect;
  qp_seen = 0;
  return twist_qpack_decode (data, n, &ev);
}

static void
test_qpack (void)
{
  uint8_t *out = NULL;
  size_t n = 0;
  /* GET https://example.com/ : prefix, :method GET (static 17), :scheme https
     (23), :authority from static 0 with a literal value, :path / (1).  */
  static const uint8_t get[] = {
    0x00, 0x00, 0xd1, 0xd7, 0x50, 0x0b, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
    '.', 'c', 'o', 'm', 0xc1
  };
  /* A literal name and value: x-test: abc.  */
  static const uint8_t lit[] = {
    0x00, 0x00, 0x26, 'x', '-', 't', 'e', 's', 't', 0x03, 'a', 'b', 'c'
  };
  /* custom-key: custom-value, both Huffman coded (RFC 7541, C.4.3).  The
     name is 8 bytes: more than the 3-bit prefix holds, so the length goes on
     into the next byte.  */
  static const uint8_t huff[] = {
    0x00, 0x00, 0x2f, 0x01, 0x25, 0xa8, 0x49, 0xe9, 0x5b, 0xa9, 0x7d, 0x7f,
    0x89, 0x25, 0xa8, 0x49, 0xe9, 0x5b, 0xb8, 0xe8, 0xb4, 0xbf
  };
  /* :status 200 (static 25), content-length from static 4 with the value 5,
     and a name from the static table past the 15 a 4-bit index holds.  */
  static const uint8_t resp[] = {
    0x00, 0x00, 0xd9, 0x54, 0x01, '5', 0x5f, 0x00, 0x03, 'G', 'E', 'T'
  };
  static const uint8_t dynamic_ric[] = { 0x01, 0x00, 0xd9 };
  static const uint8_t dynamic_ref[] = { 0x00, 0x00, 0x80 };
  static const uint8_t post_base[] = { 0x00, 0x00, 0x10 };
  static const uint8_t cut[] = { 0x00, 0x00, 0x26, 'x', '-' };
  struct twist_slist *extra = twist_slist_append (NULL, "X-Mixed-Case: v");
  struct twist_slist *auth;
  char *big = malloc (400);

  check (twist_qpack_encode_request ("GET", "https", "example.com", "/", NULL,
                                     &out, &n) == TWIST_OK
         && n == sizeof get && memcmp (out, get, n) == 0,
         "a GET is the static table and one literal");
  free (out);
  check (twist_qpack_encode_request ("CONNECT", NULL, "h:443", NULL, NULL,
                                     &out, &n) == TWIST_OK
         && qp_decode (out, n) == TWIST_OK && qp_seen == 2
         && qp_has (":method", "CONNECT") && qp_has (":authority", "h:443"),
         "a CONNECT has no scheme and no path");
  free (out);
  twist_slist_append (extra, "x-long: 0");
  check (twist_qpack_encode_request ("POST", "http", "h", "/p?q=1", extra,
                                     &out, &n) == TWIST_OK
         && qp_decode (out, n) == TWIST_OK && qp_has (":method", "POST")
         && qp_has (":scheme", "http") && qp_has (":path", "/p?q=1")
         && qp_has ("x-mixed-case", "v"), "literals, and names in lower case");
  free (out);
  twist_slist_free_all (extra);
  /* A value too long for the 7 bits of its length.  */
  memset (big, 'v', 399);
  big[399] = 0;
  auth = twist_slist_append (NULL, "x-big: ");
  free (auth->data);
  auth->data = malloc (420);
  snprintf (auth->data, 420, "x-big: %s", big);
  check (twist_qpack_encode_request ("GET", "https", "h", "/", auth, &out, &n)
         == TWIST_OK && qp_decode (out, n) == TWIST_OK && qp_has ("x-big", big),
         "a value of 399 bytes");
  free (out);
  twist_slist_free_all (auth);
  free (big);
  auth = twist_slist_append (NULL, "Authorization: Basic eDp5");
  check (twist_qpack_encode_request ("GET", "https", "h", "/", auth, &out, &n)
         == TWIST_OK && qp_decode (out, n) == TWIST_OK
         && qp_has ("authorization", "Basic eDp5")
         && memchr (out, 0x7f, n) != NULL,
         "a credential is never indexed (the N bit)");
  free (out);
  twist_slist_free_all (auth);

  check (qp_decode (get, sizeof get) == TWIST_OK && qp_seen == 4
         && qp_has (":authority", "example.com") && qp_has (":path", "/"),
         "reads what it writes");
  check (qp_decode (lit, sizeof lit) == TWIST_OK && qp_has ("x-test", "abc"),
         "a literal name");
  check (qp_decode (huff, sizeof huff) == TWIST_OK
         && qp_has ("custom-key", "custom-value"), "Huffman coded literals");
  check (qp_decode (resp, sizeof resp) == TWIST_OK && qp_has (":status", "200")
         && qp_has ("content-length", "5") && qp_has (":method", "GET"),
         "indices, with a value, and past 15");
  check (qp_decode (dynamic_ric, sizeof dynamic_ric) == TWIST_ERR_PROTOCOL,
         "a section that needs the dynamic table is refused");
  check (qp_decode (dynamic_ref, sizeof dynamic_ref) == TWIST_ERR_PROTOCOL,
         "and a reference to it");
  check (qp_decode (post_base, sizeof post_base) == TWIST_ERR_PROTOCOL,
         "and a post-base one");
  check (qp_decode (cut, sizeof cut) == TWIST_ERR_PROTOCOL,
         "a section cut short");
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

static size_t big_seen;

static void
big_body (void *user, const uint8_t *data, size_t len)
{
  (void) user;
  (void) data;
  big_seen += len;
}

/* A DATA frame is as long as the server likes (quic-go's are the size of its
   writes), and a frame of a type that is not known is passed over, whatever
   its size; neither is held whole.  */
static void
test_h3_long_frames (void)
{
  struct twist_h1_events ev;
  struct twist_h3 *h;
  static uint8_t msg[200100];
  size_t n = 0;
  size_t off;

  memset (&ev, 0, sizeof ev);
  ev.body = big_body;
  h = twist_h3_new (&ev);
  /* DATA, length 100000 (a 4-byte varint), then a reserved frame (0x21,
     length 50000) and a DATA frame of 5.  */
  msg[n++] = 0x00;
  msg[n++] = 0x80; msg[n++] = 0x01; msg[n++] = 0x86; msg[n++] = 0xa0;
  memset (msg + n, 'd', 100000);
  n += 100000;
  msg[n++] = 0x21;
  msg[n++] = 0x80; msg[n++] = 0x00; msg[n++] = 0xc3; msg[n++] = 0x50;
  memset (msg + n, 'x', 50000);
  n += 50000;
  msg[n++] = 0x00; msg[n++] = 0x05;
  memset (msg + n, 'e', 5);
  n += 5;
  big_seen = 0;
  /* In pieces of 1000 bytes, as the stream gives them.  */
  for (off = 0; off < n;)
    {
      size_t piece = n - off > 1000 ? 1000 : n - off;
      size_t used = twist_h3_receive (h, msg + off, piece);

      check (used <= piece, "no more than was given");
      off += used;
      if (used == 0)
        break;
    }
  check (off == n && big_seen == 100005,
         "a long DATA frame is delivered as it comes, and a reserved one skipped");
  twist_h3_free (h);
}

/* What the jar takes, and from whom.  A cookie is a claim by a server to be
   sent to others, so the jar decides which claims it believes.  It believes
   none that reach past the host that set it: a Domain attribute is read only
   to refuse a cookie that names a domain the host is not under, and every
   other cookie is for that host alone, however wide it asked to be.  A
   server at attacker.com that sets Domain=com therefore gets a cookie for
   attacker.com, and not the fixation of a session on every site under a
   registry suffix, which a list of suffixes would always be behind on.  A
   response over plain http that sets a Secure cookie is no more to be
   believed than whoever rewrote it on the way; a repeated cookie replaces
   the old one and does not pile up beside it; and a server cannot make the
   jar grow without bound.  */
static int
cookie_sent_to (struct twist_jar *jar, const char *host, const char *path,
                int https, const char *want)
{
  char *hdr = NULL;
  int found;

  if (twist_jar_header (jar, host, path, https, &hdr) != TWIST_OK)
    return 0;
  found = hdr != NULL && strstr (hdr, want) != NULL;
  free (hdr);
  return found;
}

static void
test_cookie_domains (void)
{
  struct twist_jar *jar = twist_jar_new ();

  /* A wide Domain is kept for the host that set it, and for no one else.  */
  check (twist_jar_store (jar, "evil=1; Domain=com", "attacker.com", "/", 1)
         == TWIST_OK, "Domain=com is kept for its host");
  check (cookie_sent_to (jar, "attacker.com", "/", 1, "evil=1"),
         "and sent there");
  check (!cookie_sent_to (jar, "victim.com", "/", 1, "evil=1"),
         "and not to another .com host");
  check (!cookie_sent_to (jar, "www.attacker.com", "/", 1, "evil=1"),
         "nor to a host under it");
  check (twist_jar_store (jar, "s=1; Domain=.co.uk", "a.co.uk", "/", 1)
         == TWIST_OK, "a leading dot changes nothing");
  check (!cookie_sent_to (jar, "b.co.uk", "/", 1, "s=1"),
         "Domain=co.uk is not sent on");
  check (twist_jar_store (jar, "g=1; Domain=github.io", "me.github.io", "/",
                          1) == TWIST_OK, "a suffix no list is needed for");
  check (cookie_sent_to (jar, "me.github.io", "/", 1, "g=1"),
         "is sent to its host");
  check (!cookie_sent_to (jar, "you.github.io", "/", 1, "g=1"),
         "and not to its neighbours");
  check (twist_jar_store (jar, "s=1; Domain=example.co.uk", "www.example.co.uk",
                          "/", 1) == TWIST_OK, "a domain under co.uk is kept");
  check (cookie_sent_to (jar, "www.example.co.uk", "/", 1, "s=1"),
         "for its host");
  check (!cookie_sent_to (jar, "shop.example.co.uk", "/", 1, "s=1"),
         "and not for the hosts under the domain");
  check (!cookie_sent_to (jar, "example.co.uk", "/", 1, "s=1"),
         "nor for the domain itself");
  check (twist_jar_store (jar, "t=1; Domain=example.com", "www.example.com",
                          "/", 1) == TWIST_OK, "an ordinary domain is kept");
  check (!cookie_sent_to (jar, "api.example.com", "/", 1, "t=1"),
         "for its host only");
  check (twist_jar_store (jar, "h=1; Domain=localhost", "localhost", "/", 1)
         == TWIST_OK, "localhost for localhost");
  check (cookie_sent_to (jar, "localhost", "/", 1, "h=1"), "is sent there");
  check (!cookie_sent_to (jar, "x.localhost", "/", 1, "h=1"),
         "and only there");
  check (twist_jar_store (jar, "i=1; Domain=intranet", "app.intranet", "/", 1)
         == TWIST_OK, "a single label above the host is kept");
  check (!cookie_sent_to (jar, "other.intranet", "/", 1, "i=1"),
         "for the host only");
  check (twist_jar_store (jar, "x=1; Domain=bank.example", "evil.example", "/",
                          1) == TWIST_ERR_PROTOCOL,
         "a domain the host is not under is refused");
  check (twist_jar_store (jar, "x=1; Domain=ample.com", "example.com", "/", 1)
         == TWIST_ERR_PROTOCOL, "and a suffix that is not a whole label");

  /* An address matches only itself, never as a suffix.  */
  check (twist_jar_store (jar, "ip=1; Domain=0.0.1", "127.0.0.1", "/", 1)
         == TWIST_ERR_PROTOCOL, "a suffix of an IPv4 address is refused");
  check (twist_jar_store (jar, "ip=1; Domain=127.0.0.1", "127.0.0.1", "/", 1)
         == TWIST_OK, "its own address is fine");
  check (!cookie_sent_to (jar, "8.0.0.1", "/", 1, "ip=1"),
         "and is sent to no other");
  twist_jar_free (jar);
}

static void
test_cookie_secure (void)
{
  struct twist_jar *jar = twist_jar_new ();

  check (twist_jar_store (jar, "s=plain; Secure", "example.com", "/", 0)
         == TWIST_ERR_PROTOCOL, "a Secure cookie over http is refused");
  check (!cookie_sent_to (jar, "example.com", "/", 1, "s=plain"),
         "and is not kept");
  check (twist_jar_store (jar, "s=safe; Secure", "example.com", "/", 1)
         == TWIST_OK, "over https it is kept");
  check (!cookie_sent_to (jar, "example.com", "/", 0, "s=safe"),
         "and sent over https only");
  check (cookie_sent_to (jar, "example.com", "/", 1, "s=safe"), "there");
  /* Nor can http overwrite it, with or without the attribute.  */
  check (twist_jar_store (jar, "s=fixed", "example.com", "/", 0)
         == TWIST_ERR_PROTOCOL, "http does not overwrite a Secure cookie");
  check (cookie_sent_to (jar, "example.com", "/", 1, "s=safe")
         && !cookie_sent_to (jar, "example.com", "/", 1, "s=fixed"),
         "which keeps its value");
  twist_jar_free (jar);
}

static void
test_cookie_replace (void)
{
  struct twist_jar *jar = twist_jar_new ();
  char *hdr = NULL;

  check (twist_jar_store (jar, "a=1", "example.com", "/", 1) == TWIST_OK, "a=1");
  check (twist_jar_store (jar, "a=2", "example.com", "/", 1) == TWIST_OK, "a=2");
  check (twist_jar_count (jar) == 1, "the same cookie is replaced");
  check (twist_jar_header (jar, "example.com", "/", 1, &hdr) == TWIST_OK
         && hdr != NULL && strstr (hdr, "a=2") != NULL
         && strstr (hdr, "a=1") == NULL, "and the new value is the one sent");
  free (hdr);
  check (twist_jar_store (jar, "a=3; Path=/x", "example.com", "/", 1)
         == TWIST_OK, "another path");
  check (twist_jar_count (jar) == 2, "is another cookie");
  check (twist_jar_store (jar, "A=4", "example.com", "/", 1) == TWIST_OK,
         "a name is case sensitive");
  check (twist_jar_count (jar) == 3, "so it is another");
  twist_jar_free (jar);
}

static void
test_cookie_limits (void)
{
  struct twist_jar *jar = twist_jar_new ();
  char name[32];
  char *big;
  char host[64];
  char *hdr = NULL;
  int i;
  int n = 0;
  char *p;

  /* One cookie is no more than 4096 bytes of name and value.  */
  big = malloc (5000);
  check (big != NULL, "buffer");
  memset (big, 'v', 4999);
  big[4999] = 0;
  memcpy (big, "k=", 2);
  check (twist_jar_store (jar, big, "example.com", "/", 1) == TWIST_ERR_PROTOCOL,
         "a cookie of 5 KB is refused");
  big[4096] = 0;
  check (twist_jar_store (jar, big, "example.com", "/", 1) == TWIST_OK,
         "one of 4 KB is kept");
  free (big);

  /* A host keeps no more than 50.  */
  for (i = 0; i < 200; i++)
    {
      snprintf (name, sizeof name, "c%d=v", i);
      twist_jar_store (jar, name, "many.example", "/", 1);
    }
  check (twist_jar_header (jar, "many.example", "/", 1, &hdr) == TWIST_OK
         && hdr != NULL, "many");
  for (p = hdr; p != NULL && (p = strstr (p, "=v")) != NULL; p += 2)
    n++;
  free (hdr);
  check (n == 50, "a host keeps its 50 newest");
  hdr = NULL;
  check (twist_jar_header (jar, "many.example", "/", 1, &hdr) == TWIST_OK
         && hdr != NULL && strstr (hdr, "c199=v") != NULL
         && strstr (hdr, "c0=v") == NULL, "and the oldest are the ones dropped");
  free (hdr);
  twist_jar_free (jar);

  /* And the jar as a whole no more than 3000, however many hosts.  */
  jar = twist_jar_new ();
  for (i = 0; i < 5000; i++)
    {
      snprintf (host, sizeof host, "h%d.example", i);
      twist_jar_store (jar, "k=v", host, "/", 1);
    }
  check (twist_jar_count (jar) == 3000, "the jar holds 3000 at most");
  twist_jar_free (jar);
}

/* How long a cookie lives (RFC 6265, 5.2.1 and 5.2.2): to the Expires date or
   for Max-Age seconds, Max-Age winning if both are there; one with neither
   lasts as long as the jar; and one that has already expired, or has
   Max-Age=0, is the server's way to delete what it set.  The jar's clock is
   set, to 14 November 2023, 22:13:20 UTC.  */
static void
test_cookie_expiry (void)
{
  static const int64_t T0 = 1700000000;
  struct twist_jar *jar = twist_jar_new ();

  twist_jar_set_time (jar, T0);
  check (twist_jar_store (jar, "m=1; Max-Age=100", "e.example", "/", 1)
         == TWIST_OK && cookie_sent_to (jar, "e.example", "/", 1, "m=1"),
         "Max-Age: sent");
  twist_jar_set_time (jar, T0 + 99);
  check (cookie_sent_to (jar, "e.example", "/", 1, "m=1"),
         "Max-Age: still sent just before");
  twist_jar_set_time (jar, T0 + 101);
  check (!cookie_sent_to (jar, "e.example", "/", 1, "m=1"),
         "Max-Age: not sent after");
  check (twist_jar_count (jar) == 0, "and an expired cookie is not kept");

  twist_jar_set_time (jar, T0);
  check (twist_jar_store (jar, "x=1; Expires=Wed, 15 Nov 2023 00:00:00 GMT",
                          "e.example", "/", 1) == TWIST_OK
         && cookie_sent_to (jar, "e.example", "/", 1, "x=1"),
         "Expires: sent");
  twist_jar_set_time (jar, T0 + 6401);
  check (!cookie_sent_to (jar, "e.example", "/", 1, "x=1"),
         "Expires: not sent after");

  /* A cookie with no lifetime lasts as long as the jar.  */
  twist_jar_set_time (jar, T0);
  twist_jar_store (jar, "s=1", "e.example", "/", 1);
  twist_jar_set_time (jar, T0 + 400 * 86400LL);
  check (cookie_sent_to (jar, "e.example", "/", 1, "s=1"),
         "a session cookie stays");

  /* Deleting.  */
  twist_jar_set_time (jar, T0);
  twist_jar_store (jar, "d=1", "e.example", "/", 1);
  check (cookie_sent_to (jar, "e.example", "/", 1, "d=1"), "d is set");
  check (twist_jar_store (jar, "d=; Max-Age=0", "e.example", "/", 1)
         == TWIST_OK && !cookie_sent_to (jar, "e.example", "/", 1, "d="),
         "Max-Age=0 deletes");
  twist_jar_store (jar, "d=1", "e.example", "/", 1);
  twist_jar_store (jar, "d=; Max-Age=-5", "e.example", "/", 1);
  check (!cookie_sent_to (jar, "e.example", "/", 1, "d="),
         "a negative Max-Age deletes");
  twist_jar_store (jar, "d=1", "e.example", "/", 1);
  twist_jar_store (jar, "d=; Expires=Tue, 14 Nov 2023 00:00:00 GMT",
                   "e.example", "/", 1);
  check (!cookie_sent_to (jar, "e.example", "/", 1, "d="),
         "an Expires in the past deletes");
  twist_jar_store (jar, "d=1; Path=/a", "e.example", "/", 1);
  twist_jar_store (jar, "d=; Max-Age=0", "e.example", "/", 1);
  check (cookie_sent_to (jar, "e.example", "/a", 1, "d=1"),
         "and only the cookie of that path");
  twist_jar_store (jar, "d=; Max-Age=0; Path=/a", "e.example", "/", 1);
  check (!cookie_sent_to (jar, "e.example", "/a", 1, "d="), "whose path it is");

  /* Max-Age wins.  */
  twist_jar_store (jar, "w=1; Max-Age=100; Expires=Tue, 14 Nov 2023 00:00:00 GMT",
                   "e.example", "/", 1);
  check (cookie_sent_to (jar, "e.example", "/", 1, "w=1"),
         "Max-Age over a past Expires");
  twist_jar_store (jar, "w=2; Expires=Wed, 15 Nov 2023 00:00:00 GMT; Max-Age=0",
                   "e.example", "/", 1);
  check (!cookie_sent_to (jar, "e.example", "/", 1, "w="),
         "Max-Age=0 over a future Expires");

  /* The forms of date servers use (RFC 6265, 5.1.1 reads them all).  */
  twist_jar_store (jar, "r=1; Expires=Tuesday, 14-Nov-23 22:13:30 GMT",
                   "e.example", "/", 1);
  check (cookie_sent_to (jar, "e.example", "/", 1, "r=1"), "an RFC 850 date");
  twist_jar_store (jar, "a=1; Expires=Tue Nov 14 22:14:00 2023",
                   "e.example", "/", 1);
  check (cookie_sent_to (jar, "e.example", "/", 1, "a=1"), "an asctime date");
  twist_jar_store (jar, "g=1; Expires=not a date at all", "e.example", "/", 1);
  twist_jar_set_time (jar, T0 + 400 * 86400LL);
  check (cookie_sent_to (jar, "e.example", "/", 1, "g=1"),
         "a date that is not one is no expiry");
  twist_jar_set_time (jar, T0);

  /* A server cannot ask for more than 400 days.  */
  twist_jar_store (jar, "l=1; Max-Age=99999999999", "e.example", "/", 1);
  twist_jar_set_time (jar, T0 + 399 * 86400LL);
  check (cookie_sent_to (jar, "e.example", "/", 1, "l=1"), "a long life");
  twist_jar_set_time (jar, T0 + 401 * 86400LL);
  check (!cookie_sent_to (jar, "e.example", "/", 1, "l=1"),
         "is cut at 400 days");

  /* An origin that is not secure cannot delete a Secure cookie.  */
  twist_jar_set_time (jar, T0);
  twist_jar_store (jar, "z=1; Secure", "e.example", "/", 1);
  check (twist_jar_store (jar, "z=; Max-Age=0", "e.example", "/", 0)
         == TWIST_ERR_PROTOCOL
         && cookie_sent_to (jar, "e.example", "/", 1, "z=1"),
         "http cannot delete a Secure cookie");
  twist_jar_free (jar);
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
  check (twist_jar_header (jar, "api.example.com", "/", 1, &hdr) == TWIST_OK
         && (hdr == NULL || strstr (hdr, "id=1") == NULL),
         "a Domain is not for the hosts under it");
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

/* HTTP/2 header field names are lower case (RFC 9113, section 8.2.1) and a
   request with a capital in one is malformed: the server must refuse it.
   Most do not, and GitHub's answers a GOAWAY with PROTOCOL_ERROR ("found an
   upper-case letter in header name"), so every request to raw.githubusercontent.com
   and docs.github.com failed with "connection closed".  HTTP/3's encoder
   lowered names; HTTP/2's sent them as given ("User-Agent").  */
static char hn_names[1024];
static char hn_values[1024];

static void
hn_header (void *user, const char *name, size_t name_len, const char *value,
           size_t value_len)
{
  (void) user;
  if (strlen (hn_names) + name_len + 2 < sizeof hn_names)
    {
      strncat (hn_names, name, name_len);
      strcat (hn_names, " ");
    }
  if (strlen (hn_values) + value_len + 2 < sizeof hn_values)
    {
      strncat (hn_values, value, value_len);
      strcat (hn_values, " ");
    }
}

static void
test_hpack_lowercase_names (void)
{
  struct twist_hpack *enc = twist_hpack_new ();
  struct twist_hpack *dec = twist_hpack_new ();
  struct twist_h1_events ev;
  struct twist_slist *extra = NULL;
  uint8_t *out = NULL;
  size_t n = 0;
  size_t i;
  int upper = 0;

  extra = twist_slist_append (extra, "User-Agent: twist/0.1");
  extra = twist_slist_append (extra, "X-Custom-Header: KeepMyCase");
  extra = twist_slist_append (extra, "ACCEPT-ENCODING: gzip");
  extra = twist_slist_append (extra, "Authorization: Bearer AbC");
  extra = twist_slist_append (extra, ":protocol: websocket");
  check (enc != NULL && dec != NULL, "hpack handles");
  check (twist_hpack_encode_request (enc, "GET", "https", "h.example", "/p?Q=1",
                                     extra, &out, &n) == TWIST_OK, "encode");
  memset (&ev, 0, sizeof ev);
  ev.header = hn_header;
  hn_names[0] = 0;
  hn_values[0] = 0;
  check (twist_hpack_decode (dec, out, n, &ev) == TWIST_OK, "decode");
  for (i = 0; hn_names[i] != 0; i++)
    if (hn_names[i] >= 'A' && hn_names[i] <= 'Z')
      upper = 1;
  check (!upper, "no header name has a capital letter");
  check (strstr (hn_names, " user-agent ") != NULL
         && strstr (hn_names, " x-custom-header ") != NULL
         && strstr (hn_names, " accept-encoding ") != NULL
         && strstr (hn_names, " authorization ") != NULL
         && strstr (hn_names, " :protocol ") != NULL,
         "they are the lower case of what was given");
  check (strstr (hn_values, "KeepMyCase") != NULL
         && strstr (hn_values, "Bearer AbC") != NULL
         && strstr (hn_values, "/p?Q=1") != NULL,
         "and the values are as given");
  free (out);
  twist_slist_free_all (extra);
  twist_hpack_free (enc);
  twist_hpack_free (dec);
}

/* Connection-specific header fields are not sent in HTTP/2 or HTTP/3 (RFC
   9113 and 9114, section 8.2.2 and 4.2): Connection, Keep-Alive,
   Proxy-Connection, Transfer-Encoding and Upgrade, and TE except "trailers".
   A message that has one is malformed, and GitHub's server ends the
   connection on it, so "-H 'Connection: close'" made every request fail.
   curl leaves them out.  Anything else is sent.  */
static void
test_connection_specific_headers (void)
{
  struct twist_hpack *enc = twist_hpack_new ();
  struct twist_hpack *dec = twist_hpack_new ();
  struct twist_h1_events ev;
  struct twist_slist *extra = NULL;
  uint8_t *out = NULL;
  size_t n = 0;

  extra = twist_slist_append (extra, "Connection: close");
  extra = twist_slist_append (extra, "Keep-Alive: timeout=5");
  extra = twist_slist_append (extra, "Proxy-Connection: keep-alive");
  extra = twist_slist_append (extra, "Transfer-Encoding: chunked");
  extra = twist_slist_append (extra, "Upgrade: websocket");
  extra = twist_slist_append (extra, "TE: gzip");
  extra = twist_slist_append (extra, "Accept: */*");
  extra = twist_slist_append (extra, "Te: trailers");
  extra = twist_slist_append (extra, "X-Connection: stays");

  check (twist_hpack_encode_request (enc, "GET", "https", "h.example", "/",
                                     extra, &out, &n) == TWIST_OK, "encode");
  memset (&ev, 0, sizeof ev);
  ev.header = hn_header;
  hn_names[0] = 0;
  hn_values[0] = 0;
  check (twist_hpack_decode (dec, out, n, &ev) == TWIST_OK, "decode");
  check (strstr (hn_names, " connection ") == NULL
         && strstr (hn_names, " keep-alive ") == NULL
         && strstr (hn_names, " proxy-connection ") == NULL
         && strstr (hn_names, " transfer-encoding ") == NULL
         && strstr (hn_names, " upgrade ") == NULL,
         "HTTP/2 leaves out the connection-specific fields");
  check (strstr (hn_names, " accept ") != NULL
         && strstr (hn_names, " x-connection ") != NULL,
         "and sends the others, even one named like one");
  check (strstr (hn_names, " te ") != NULL
         && strstr (hn_values, " trailers ") != NULL
         && strstr (hn_values, "gzip") == NULL,
         "TE only with trailers");
  free (out);
  out = NULL;

  /* The same for HTTP/3.  */
  check (twist_qpack_encode_request ("GET", "https", "h.example", "/", extra,
                                     &out, &n) == TWIST_OK
         && qp_decode (out, n) == TWIST_OK, "qpack encode");
  check (!qp_has ("connection", "close") && !qp_has ("keep-alive", "timeout=5")
         && !qp_has ("proxy-connection", "keep-alive")
         && !qp_has ("transfer-encoding", "chunked")
         && !qp_has ("upgrade", "websocket"),
         "HTTP/3 leaves out the connection-specific fields");
  check (qp_has ("accept", "*/*") && qp_has ("x-connection", "stays")
         && qp_has ("te", "trailers") && !qp_has ("te", "gzip"),
         "and sends the others, TE only with trailers");
  free (out);
  twist_slist_free_all (extra);
  twist_hpack_free (enc);
  twist_hpack_free (dec);
}

/* A client has frames only on streams it opened: odd, and below the next it
   will open.  A server (a proxy, for a tunnel) that sends DATA or HEADERS on
   any other stream was having them taken for a stream of their own, and the
   data went to the same place as the tunnel's.  It is a connection error
   (RFC 9113, section 5.1), as is data on a stream that has already ended.  */
static int h2f_failed;
static size_t h2f_body;
static int h2f_done;

static void
h2f_fail_cb (void *user, int err)
{
  (void) user;
  h2f_failed = err;
}

static void
h2f_body_cb (void *user, const uint8_t *data, size_t len)
{
  (void) user;
  (void) data;
  h2f_body += len;
}

static void
h2f_done_cb (void *user)
{
  (void) user;
  h2f_done++;
}

/* A session with stream 1 open, and the server's SETTINGS in.  */
static struct twist_h2 *
h2f_open (void)
{
  static const uint8_t settings[] = { 0, 0, 0, 4, 0, 0, 0, 0, 0 };
  struct twist_h1_events ev;
  struct twist_h2 *h;
  uint8_t *out = NULL;
  size_t n = 0;

  memset (&ev, 0, sizeof ev);
  ev.user = &h2f_failed;
  ev.failure = h2f_fail_cb;
  ev.body = h2f_body_cb;
  ev.message_done = h2f_done_cb;
  h2f_failed = 0;
  h2f_body = 0;
  h2f_done = 0;
  h = twist_h2_new (&ev);
  twist_h2_set_emit (h, tun_emit, NULL);
  if (twist_h2_request (h, "GET", "https", "h", "/", NULL, NULL, 0, 0, &out,
                        &n) != TWIST_OK)
    abort ();
  free (out);
  twist_h2_receive (h, settings, sizeof settings);
  return h;
}

static void
test_h2_foreign_streams (void)
{
  /* DATA on stream 2, which is the server's to open, and never is.  */
  static const uint8_t data_even[] = { 0, 0, 1, 0, 0, 0, 0, 0, 2, 'x' };
  /* HEADERS, :status 200, on stream 3, which the client has not opened.  */
  static const uint8_t head_idle[] = { 0, 0, 1, 1, 4, 0, 0, 0, 3, 0x88 };
  /* DATA on stream 5, further on.  */
  static const uint8_t data_idle[] = { 0, 0, 1, 0, 0, 0, 0, 0, 5, 'x' };
  /* A response on stream 1: HEADERS 200, then DATA "hi" with END_STREAM.  */
  static const uint8_t head_ok[] = { 0, 0, 1, 1, 4, 0, 0, 0, 1, 0x88 };
  static const uint8_t data_end[] = { 0, 0, 2, 0, 1, 0, 0, 0, 1, 'h', 'i' };
  static const uint8_t data_after[] = { 0, 0, 1, 0, 0, 0, 0, 0, 1, 'x' };
  struct twist_h2 *h;

  h = h2f_open ();
  twist_h2_receive (h, data_even, sizeof data_even);
  check (h2f_failed == TWIST_ERR_PROTOCOL && h2f_body == 0,
         "DATA on a stream the server would open is a connection error");
  twist_h2_free (h);

  h = h2f_open ();
  twist_h2_receive (h, head_idle, sizeof head_idle);
  check (h2f_failed == TWIST_ERR_PROTOCOL, "HEADERS on an idle stream is one");
  twist_h2_free (h);

  h = h2f_open ();
  twist_h2_receive (h, data_idle, sizeof data_idle);
  check (h2f_failed == TWIST_ERR_PROTOCOL && h2f_body == 0,
         "and DATA on one");
  twist_h2_free (h);

  h = h2f_open ();
  twist_h2_receive (h, head_ok, sizeof head_ok);
  twist_h2_receive (h, data_end, sizeof data_end);
  check (h2f_failed == 0 && h2f_body == 2 && h2f_done == 1,
         "a response on the stream that was opened is as it was");
  twist_h2_receive (h, data_after, sizeof data_after);
  check (h2f_failed == TWIST_ERR_PROTOCOL && h2f_body == 2,
         "data after the stream has ended is refused, and not delivered");
  twist_h2_free (h);
}

static void
test_h2_share (void)
{
  struct twist_h1_events ev;
  struct twist_h2 *h2;
  struct twist_runtime *runtime;
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
  runtime = twist_runtime_new ();
  check (h2 != NULL && runtime != NULL && twist_h2_can_open (h2), "h2 room");
  sess = twist_session_add (runtime, "k", runtime->loop, NULL, h2);
  check (sess != NULL
         && twist_session_find (runtime, "k", runtime->loop) == sess,
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
  check (twist_session_find (runtime, "k", runtime->loop) == NULL,
         "h2 no room");
  free (a);
  free (b);
  twist_runtime_free (runtime);
}

/* The request writer sized its buffer from the extra headers alone, so a
   request line longer than that wrote past the allocation.  Every length
   from well under the old capacity to well over it must give the request,
   byte for byte.  */
static void
test_h1_write_request (void)
{
  static const size_t lens[] = { 1, 100, 440, 480, 500, 505, 510, 511, 512,
                                 513, 520, 560, 700, 1500, 2047 };
  struct twist_slist *extra = NULL;
  size_t i;
  int ok = 1;

  extra = twist_slist_append (extra, "User-Agent: twist/0.1");
  extra = twist_slist_append (extra, "Accept-Encoding: gzip, deflate");
  for (i = 0; i < sizeof lens / sizeof lens[0]; i++)
    {
      char *target = malloc (lens[i] + 1);
      char *expect = malloc (lens[i] + 256);
      uint8_t *out = NULL;
      size_t out_len = 0;
      int n;
      int rc;

      if (target == NULL || expect == NULL)
        abort ();
      memset (target, 'a', lens[i]);
      target[0] = '/';
      target[lens[i]] = 0;
      n = snprintf (expect, lens[i] + 256,
                    "GET %s HTTP/1.1\r\nHost: example.com\r\n"
                    "User-Agent: twist/0.1\r\n"
                    "Accept-Encoding: gzip, deflate\r\n\r\n", target);
      rc = twist_h1_write_request ("GET", target, "example.com", 0, extra,
                                   NULL, 0, &out, &out_len);
      if (rc != TWIST_OK || out == NULL || out_len != (size_t) n
          || memcmp (out, expect, out_len) != 0)
        ok = 0;
      free (out);
      free (target);
      free (expect);
    }
  check (ok, "h1 request is written whole for any target length");
  twist_slist_free_all (extra);
}

/* A long host and a body length go through the same buffer.  */
static void
test_h1_write_request_host (void)
{
  char host[512];
  uint8_t payload[1] = { 'x' };
  struct twist_slist *extra = NULL;
  uint8_t *out = NULL;
  size_t out_len = 0;
  int rc;

  memset (host, 'h', sizeof host - 1);
  host[sizeof host - 1] = 0;
  extra = twist_slist_append (extra, "User-Agent: twist/0.1");
  rc = twist_h1_write_request ("POST", "/p", host, 0, extra, payload, 1, &out,
                               &out_len);
  check (rc == TWIST_OK && out != NULL && out_len > sizeof host
         && memmem (out, out_len, "Content-Length: 1\r\n\r\n", 21) != NULL,
         "h1 request with a long host and a body length");
  free (out);
  twist_slist_free_all (extra);
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
  test_h1_no_body ();
  test_h2 ();
  test_h3 ();
  test_h3_long_frames ();
  test_h2_windows ();
  test_h2_tunnel ();
  test_hpack_table ();
  test_qpack_static_index ();
  test_qpack ();
  test_cookie ();
  test_cookie_domains ();
  test_cookie_secure ();
  test_cookie_replace ();
  test_cookie_limits ();
  test_cookie_expiry ();
  test_hpack_long ();
  test_hpack_lowercase_names ();
  test_connection_specific_headers ();
  test_h2_foreign_streams ();
  test_h2_share ();
  test_http_status ();
  test_h1_write_request ();
  test_h1_write_request_host ();
  return tests_finish ();
}
