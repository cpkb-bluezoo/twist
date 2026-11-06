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
#include <string.h>

/* The BER and DER codec: the writer's bytes, and the reader's events fed
   whole and in one-byte pieces.  */

struct log
{
  char text[512];
  int err;			/* From failure, or 0.  */
  int fails;
  int stop_on;			/* Return TWIST_DER_STOP at this primitive tag.  */
};

#define ADD(g, ...) \
  do \
    { \
      size_t n_ = strlen ((g)->text); \
      snprintf ((g)->text + n_, sizeof (g)->text - n_, __VA_ARGS__); \
    } \
  while (0)

static int
ev_start (void *user, uint8_t tag, size_t len)
{
  ADD ((struct log *) user, "[%02x/%u ", tag, (unsigned) len);
  return TWIST_OK;
}

static int
ev_end (void *user, uint8_t tag)
{
  ADD ((struct log *) user, "%02x] ", tag);
  return TWIST_OK;
}

static int
ev_prim (void *user, uint8_t tag, const uint8_t *val, size_t len)
{
  struct log *g = user;
  size_t i;
  unsigned sum = 0;

  for (i = 0; i < len; i++)
    sum += val[i];
  ADD (g, "%02x:%u ", tag, sum);
  return g->stop_on == tag ? TWIST_DER_STOP : TWIST_OK;
}

static void
ev_failure (void *user, int err)
{
  struct log *g = user;

  g->err = err;
  g->fails++;
}

static struct twist_der_events events;
static uint8_t scratch[64];

static size_t
run (struct log *g, const uint8_t *in, size_t n, size_t piece, int strict,
     struct twist_der_reader *r)
{
  size_t off = 0, took = 0;

  memset (g, 0, sizeof *g);
  events.user = g;
  events.start = ev_start;
  events.end = ev_end;
  events.prim = ev_prim;
  events.failure = ev_failure;
  twist_der_reader_init (r, &events, scratch, sizeof scratch, strict);
  while (off < n)
    {
      size_t c = n - off < piece ? n - off : piece;
      size_t used = twist_der_receive (r, in + off, c);

      took += used;
      if (used < c)
        break;
      off += c;
    }
  return took;
}

/* SEQUENCE { INTEGER 5, OCTET STRING "ab", SEQUENCE { NULL } }  */
static const uint8_t good[] = {
  0x30, 0x0b, 0x02, 0x01, 0x05, 0x04, 0x02, 'a', 'b', 0x30, 0x02, 0x05, 0x00
};

static void
test_reader_events (void)
{
  struct log g;
  struct twist_der_reader r;
  char whole[512];
  size_t n;

  n = run (&g, good, sizeof good, sizeof good, 1, &r);
  check (n == sizeof good && g.fails == 0 && twist_der_idle (&r),
         "reader: a message is taken whole");
  check (strcmp (g.text, "[30/11 02:5 04:195 [30/2 05:0 30] 30] ") == 0,
         "reader: the events are start, primitives and end, in order");
  strcpy (whole, g.text);
  n = run (&g, good, sizeof good, 1, 1, &r);
  check (n == sizeof good && strcmp (g.text, whole) == 0 && twist_der_idle (&r),
         "reader: the same events in pieces of one byte");
  n = run (&g, good, sizeof good, 3, 0, &r);
  check (n == sizeof good && strcmp (g.text, whole) == 0,
         "reader: and in pieces of three, in BER mode");
  /* Two messages in a row, the second cut short.  */
  {
    uint8_t two[sizeof good * 2 - 3];

    memcpy (two, good, sizeof good);
    memcpy (two + sizeof good, good, sizeof good - 3);
    n = run (&g, two, sizeof two, 5, 1, &r);
    check (n == sizeof two && !twist_der_idle (&r) && g.fails == 0,
           "reader: a partial second message leaves the reader mid-element");
  }
  /* A callback that stops the reader leaves what follows unconsumed.  */
  memset (&g, 0, sizeof g);
  events.user = &g;
  twist_der_reader_init (&r, &events, scratch, sizeof scratch, 1);
  g.stop_on = 0x04;
  n = twist_der_receive (&r, good, sizeof good);
  check (n == 9 && g.fails == 0, "reader: a stop leaves the tail unconsumed");
  check (twist_der_receive (&r, good, sizeof good) == 0,
         "reader: and takes nothing more");
}

static void
refused (const char *what, const uint8_t *in, size_t n, int strict)
{
  struct log g;
  struct twist_der_reader r;
  size_t piece;
  char msg[160];

  for (piece = n; piece >= 1; piece = piece > 1 ? 1 : 0)
    {
      size_t took = run (&g, in, n, piece, strict, &r);

      snprintf (msg, sizeof msg, "reader: %s (%s)", what,
                piece == 1 ? "1-byte pieces" : "whole");
      check (g.fails == 1 && g.err == TWIST_ERR_PROTOCOL && took >= n,
             msg);
    }
}

static void
test_reader_refusals (void)
{
  static const uint8_t indef[] = { 0x30, 0x80, 0x02, 0x01, 0x05, 0, 0 };
  static const uint8_t nonmin1[] = { 0x04, 0x81, 0x02, 'a', 'b' };
  static const uint8_t nonmin2[] = { 0x04, 0x82, 0x00, 0x81 };
  static const uint8_t longlen[] = { 0x04, 0x84, 0, 0, 0, 1, 'a' };
  static const uint8_t overrun[] = { 0x30, 0x03, 0x04, 0x05, 'a', 'b', 'c' };
  static const uint8_t toobig[] = { 0x04, 0x81, 0x80 };
  static const uint8_t hightag[] = { 0x1f, 0x01, 0x00 };
  uint8_t deep[40];
  size_t i;
  struct log g;
  struct twist_der_reader r;

  refused ("an indefinite length", indef, sizeof indef, 1);
  refused ("an indefinite length in BER mode", indef, sizeof indef, 0);
  refused ("a length in long form under 128", nonmin1, sizeof nonmin1, 1);
  refused ("a length with a leading zero byte", nonmin2, sizeof nonmin2, 1);
  refused ("a length of four bytes", longlen, sizeof longlen, 1);
  refused ("a child longer than its parent", overrun, sizeof overrun, 1);
  refused ("a primitive longer than the scratch buffer", toobig,
           sizeof toobig, 1);
  refused ("a tag that continues in more bytes", hightag, sizeof hightag, 1);
  /* Too deep: a SEQUENCE inside a SEQUENCE, thirteen times.  */
  for (i = 0; i < 13; i++)
    {
      deep[i * 2] = 0x30;
      deep[i * 2 + 1] = (uint8_t) (2 * (12 - i));
    }
  refused ("nesting too deep", deep, 26, 1);
  /* What DER refuses, BER takes.  */
  run (&g, nonmin1, sizeof nonmin1, 1, 0, &r);
  check (g.fails == 0 && strcmp (g.text, "04:195 ") == 0,
         "reader: BER mode takes a non-minimal length");
  run (&g, hightag, sizeof hightag, sizeof hightag, 0, &r);
  check (g.fails == 0, "reader: BER mode takes the tag byte as it is");
  /* Twelve deep is the limit and is allowed.  */
  for (i = 0; i < 12; i++)
    {
      deep[i * 2] = 0x30;
      deep[i * 2 + 1] = (uint8_t) (2 * (11 - i));
    }
  run (&g, deep, 24, 1, 1, &r);
  check (g.fails == 0 && twist_der_idle (&r), "reader: twelve levels is allowed");
  /* max_len bounds a constructed element too.  */
  memset (&g, 0, sizeof g);
  events.user = &g;
  twist_der_reader_init (&r, &events, scratch, sizeof scratch, 1);
  r.max_len = 10;
  twist_der_receive (&r, (const uint8_t *) "\x30\x0b", 2);
  check (g.fails == 1 && g.err == TWIST_ERR_PROTOCOL,
         "reader: a length above max_len is refused");
  check (twist_der_receive (&r, good, sizeof good) == sizeof good
         && g.fails == 1, "reader: after a failure all input is taken, once");
}

static void
test_writer (void)
{
  uint8_t buf[600], big[300];
  struct twist_der_writer w;
  size_t m1, m2;

  memset (big, 'x', sizeof big);
  /* BER: a constructed element always has three length bytes.  */
  twist_der_writer_init (&w, buf, sizeof buf, 0);
  m1 = twist_der_begin (&w, 0x30);
  twist_der_put_int (&w, 0x02, 5);
  twist_der_end (&w, m1);
  check (!w.err && w.n == 3 + 1 + 3 && memcmp (buf, "\x30\x82\x00\x03\x02\x01\x05", 7) == 0,
         "writer: BER lengths of a constructed element take three bytes");
  /* DER: the shortest form, nested, with the content moved back.  */
  twist_der_writer_init (&w, buf, sizeof buf, 1);
  m1 = twist_der_begin (&w, 0x30);
  twist_der_put_int (&w, 0x02, 5);
  m2 = twist_der_begin (&w, 0xa0);
  twist_der_put (&w, 0x04, "ab", 2);
  twist_der_end (&w, m2);
  twist_der_end (&w, m1);
  check (!w.err && w.n == 11
         && memcmp (buf, "\x30\x09\x02\x01\x05\xa0\x04\x04\x02" "ab", 11) == 0,
         "writer: DER uses the shortest length, nested");
  twist_der_writer_init (&w, buf, sizeof buf, 1);
  m1 = twist_der_begin (&w, 0x30);
  twist_der_put (&w, 0x04, big, 200);
  twist_der_end (&w, m1);
  /* 0x30 0x81 0xcb | 0x04 0x81 0xc8 ... : 200 byte value, 203 in the sequence. */
  check (!w.err && w.n == 3 + 203 && buf[1] == 0x81 && buf[2] == 203
         && buf[3] == 0x04 && buf[4] == 0x81 && buf[5] == 200,
         "writer: a length of 128 or more takes the long form");
  twist_der_writer_init (&w, buf, sizeof buf, 1);
  m1 = twist_der_begin (&w, 0x30);
  twist_der_put (&w, 0x04, big, 300);
  twist_der_end (&w, m1);
  check (!w.err && buf[1] == 0x82 && ((buf[2] << 8) | buf[3]) == 304,
         "writer: and 256 or more takes two bytes of length");
  /* Integers: minimal, with a sign byte where the high bit is set.  */
  twist_der_writer_init (&w, buf, sizeof buf, 1);
  twist_der_put_int (&w, 0x02, 128);
  twist_der_put_int (&w, 0x02, 0);
  twist_der_put_int (&w, 0x02, -1);
  twist_der_put_int (&w, 0x02, -129);
  check (!w.err && w.n == 4 + 3 + 3 + 4
         && memcmp (buf, "\x02\x02\x00\x80\x02\x01\x00\x02\x01\xff\x02\x02\xff\x7f", 14) == 0,
         "writer: integers take the fewest bytes");
  /* A buffer that is too small sets err and writes nothing past the end.  */
  twist_der_writer_init (&w, buf, 4, 1);
  twist_der_put (&w, 0x04, "abcdef", 6);
  check (w.err && w.n <= 4, "writer: overflow sets err");
  twist_der_writer_init (&w, buf, sizeof buf, 1);
  twist_der_end (&w, 7);
  check (w.err, "writer: a mark that was never begun sets err");
}

int
main (void)
{
  test_reader_events ();
  test_reader_refusals ();
  test_writer ();
  return tests_finish ();
}
