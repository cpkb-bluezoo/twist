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

#include <string.h>

/* HTTP Datagrams of a CONNECT-UDP stream (RFC 9298 section 5): the stream's
   ID divided by four, as a QUIC variable-length integer; context ID 0; the UDP
   payload.  */

static void
test_wrap (void)
{
  const uint8_t p[] = { 0xaa, 0xbb, 0xcc };
  uint8_t out[16];

  check (twist_masque_wrap (0, p, 3, out, sizeof out) == 5
         && memcmp (out, "\x00\x00\xaa\xbb\xcc", 5) == 0,
         "stream 0: quarter id 0, context 0, payload");
  check (twist_masque_wrap (7, p, 3, out, sizeof out) == 5 && out[0] == 7
         && out[1] == 0, "the quarter stream id is in front of the context id");
  check (twist_masque_wrap (100, p, 3, out, sizeof out) == 6
         && memcmp (out, "\x40\x64\x00\xaa\xbb\xcc", 6) == 0,
         "an id of 64 or more takes two bytes");
  check (twist_masque_wrap (20000, p, 3, out, sizeof out) == 8
         && out[0] == 0x80 && out[1] == 0 && out[2] == 0x4e && out[3] == 0x20
         && out[4] == 0, "an id of 16384 or more takes four bytes");
  check (twist_masque_wrap (0, p, 3, out, 4) == 0, "too little room");
  check (twist_masque_wrap (0, p, 3, out, 5) == 5, "exactly enough room");
  check (twist_masque_wrap (0, p, 0, out, sizeof out) == 2,
         "an empty payload is a datagram");
}

static void
test_unwrap (void)
{
  const uint8_t good[] = { 0x00, 0x00, 0xaa, 0xbb };
  const uint8_t other[] = { 0x01, 0x00, 0xaa, 0xbb };
  const uint8_t ext[] = { 0x00, 0x04, 0xaa, 0xbb };
  const uint8_t two[] = { 0x40, 0x64, 0x00, 0xaa };
  const uint8_t *pl = NULL;
  size_t n = 99;

  check (twist_masque_unwrap (0, good, sizeof good, &pl, &n) == 1 && n == 2
         && pl == good + 2, "the payload of our stream's datagram");
  check (twist_masque_unwrap (0, other, sizeof other, &pl, &n) == 0,
         "another stream's datagram is not ours");
  check (twist_masque_unwrap (1, other, sizeof other, &pl, &n) == 1 && n == 2,
         "the same datagram on that stream");
  check (twist_masque_unwrap (0, ext, sizeof ext, &pl, &n) == 0,
         "a context that is not 0 is dropped");
  check (twist_masque_unwrap (100, two, sizeof two, &pl, &n) == 1 && n == 1
         && pl == two + 3, "a two-byte quarter stream id");
  check (twist_masque_unwrap (0, good, 0, &pl, &n) == 0, "nothing");
  check (twist_masque_unwrap (0, good, 1, &pl, &n) == 0, "no context id");
  check (twist_masque_unwrap (0, good, 2, &pl, &n) == 1 && n == 0,
         "no payload is an empty one");
  check (twist_masque_unwrap (100, two, 1, &pl, &n) == 0,
         "a cut-off varint");
}

static void
test_round_trip (void)
{
  uint8_t pay[1300], out[1400];
  const uint8_t *pl;
  size_t i, n, wl;

  for (i = 0; i < sizeof pay; i++)
    pay[i] = (uint8_t) i;
  wl = twist_masque_wrap (12, pay, sizeof pay, out, sizeof out);
  check (wl == sizeof pay + 2, "a full-size packet wraps");
  check (twist_masque_unwrap (12, out, wl, &pl, &n) == 1 && n == sizeof pay
         && memcmp (pl, pay, n) == 0, "and comes out the same");
}

int
main (void)
{
  test_wrap ();
  test_unwrap ();
  test_round_trip ();
  return tests_finish ();
}
