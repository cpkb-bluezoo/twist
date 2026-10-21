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

/* HTTP/2 frames from a server, with two requests open to take them.  */

static unsigned long events;

static void status_line (void *u, int c, const char *r, size_t n) { (void) u; (void) c; (void) r; (void) n; events++; }
static void header (void *u, const char *a, size_t an, const char *b, size_t bn)
{
  (void) u;
  if (an > 0)
    events += (unsigned char) a[an - 1];
  if (bn > 0)
    events += (unsigned char) b[bn - 1];
}
static void body (void *u, const uint8_t *d, size_t n) { (void) u; if (n > 0) events += d[n - 1]; }
static void done (void *u) { (void) u; events++; }
static void failure (void *u, int e) { (void) u; (void) e; events++; }
static int emit (void *u, const uint8_t *d, size_t n) { (void) u; (void) d; (void) n; return 0; }

void
fuzz_seeds (void (*add) (const void *, size_t))
{
  /* Settings, a headers frame (":status: 200"), data, end of stream.  */
  static const uint8_t s1[] = {
    0x00,
    0, 0, 0, 4, 0, 0, 0, 0, 0,
    0, 0, 1, 1, 0x4, 0, 0, 0, 1, 0x88,
    0, 0, 5, 0, 0x1, 0, 0, 0, 1, 'h', 'e', 'l', 'l', 'o'
  };
  static const uint8_t s2[] = {
    0x01,
    0, 0, 6, 4, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 1,
    0, 0, 8, 6, 0, 0, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8,
    0, 0, 4, 8, 0, 0, 0, 0, 1, 0, 0, 0, 100
  };

  add (s1, sizeof s1);
  add (s2, sizeof s2);
}

int
LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
  struct twist_h1_events ev;
  struct twist_h2 *h2;
  uint8_t *out;
  size_t n, i;

  if (size == 0)
    return 0;
  memset (&ev, 0, sizeof ev);
  ev.status_line = status_line;
  ev.header = header;
  ev.body = body;
  ev.message_done = done;
  ev.failure = failure;
  h2 = twist_h2_new (&ev);
  if (h2 == NULL)
    abort ();
  twist_h2_set_emit (h2, emit, NULL);
  for (i = 0; i < 2; i++)
    {
      out = NULL;
      n = 0;
      if (twist_h2_request (h2, "GET", "https", "ex", "/", NULL, NULL, 0, 1,
                            &out, &n) == TWIST_OK)
        free (out);
    }
  fuzz_feed ((fuzz_recv) twist_h2_receive, h2, data + 1, size - 1,
             fuzz_piece (data[0], size));
  twist_h2_can_open (h2);
  twist_h2_free (h2);
  return 0;
}
