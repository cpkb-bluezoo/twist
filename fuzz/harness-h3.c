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

#include "fuzz.h"

/* HTTP/3 frames and QPACK field sections.  */

static unsigned long events;

static void header (void *u, const char *a, size_t an, const char *b, size_t bn)
{
  (void) u;
  if (an > 0)
    events += (unsigned char) a[an - 1];
  if (bn > 0)
    events += (unsigned char) b[bn - 1];
}
static void status_line (void *u, int c, const char *r, size_t n) { (void) u; (void) c; (void) r; (void) n; events++; }
static void body (void *u, const uint8_t *d, size_t n) { (void) u; if (n > 0) events += d[n - 1]; }
static void done (void *u) { (void) u; events++; }
static void failure (void *u, int e) { (void) u; (void) e; events++; }

void
fuzz_seeds (void (*add) (const void *, size_t))
{
  static const uint8_t s1[] = { 0x00, 0x01, 0x03, 0x00, 0x00, 0xd9, 0x04, 0x00 };
  static const uint8_t s2[] = { 0x01, 0x00, 0x05, 'h', 'e', 'l', 'l', 'o',
                                0x01, 0x03, 0x00, 0x00, 0xd9 };

  add (s1, sizeof s1);
  add (s2, sizeof s2);
}

int
LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
  struct twist_h1_events ev;
  struct twist_h3 *h3;

  if (size == 0)
    return 0;
  memset (&ev, 0, sizeof ev);
  ev.status_line = status_line;
  ev.header = header;
  ev.body = body;
  ev.message_done = done;
  ev.failure = failure;
  twist_qpack_decode (data, size, &ev);
  h3 = twist_h3_new (&ev);
  if (h3 == NULL)
    abort ();
  fuzz_feed ((fuzz_recv) twist_h3_receive, h3, data + 1, size - 1,
             fuzz_piece (data[0], size));
  twist_h3_free (h3);
  return 0;
}
