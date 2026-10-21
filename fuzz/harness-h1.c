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

/* The HTTP/1 response parser: status line, headers, the body in each of its
   framings, in pieces of any size.  */

static unsigned long events;

static void status_line (void *u, int c, const char *r, size_t n) { (void) u; (void) c; (void) r; (void) n; events++; }
static void header (void *u, const char *a, size_t an, const char *b, size_t bn)
{
  (void) u;
  /* The text must be readable as long as it says.  */
  if (an > 0)
    events += (unsigned char) a[an - 1];
  if (bn > 0)
    events += (unsigned char) b[bn - 1];
}
static void body (void *u, const uint8_t *d, size_t n) { (void) u; if (n > 0) events += d[n - 1]; }
static void done (void *u) { (void) u; events++; }
static void failure (void *u, int e) { (void) u; (void) e; events++; }
static void version (void *u, int a, int b) { (void) u; (void) a; (void) b; events++; }
static int switching (void *u) { (void) u; return 0; }

const char *const fuzz_tokens[] = {
  "HTTP/1.1 ", "HTTP/1.0 ", "200 OK", "\r\n", "\r\n\r\n", "Content-Length: ",
  "Transfer-Encoding: chunked", "Connection: close", "0\r\n\r\n", "\r\n0\r\n",
  "Content-Encoding: gzip", "100 Continue", "101 Switching Protocols",
  "Trailer: ", NULL
};

void
fuzz_seeds (void (*add) (const void *, size_t))
{
  static const char *seeds[] = {
    "\x00HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello",
    "\x00HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n",
    "\x00HTTP/1.0 200 OK\r\nConnection: close\r\n\r\nbody until close",
    "\x00HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 204 No Content\r\n\r\n",
    "\x00HTTP/1.1 301 Moved\r\nLocation: /x\r\nContent-Length: 0\r\n\r\n",
    "\x01HTTP/1.1 200 OK\r\nContent-Length: 3\r\nX: y\r\n z\r\n\r\nabc"
  };
  size_t i;

  for (i = 0; i < sizeof seeds / sizeof seeds[0]; i++)
    add (seeds[i], strlen (seeds[i] + 1) + 1);
}

int
LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
  struct twist_h1_events ev;
  struct twist_h1 *h;

  if (size == 0)
    return 0;
  memset (&ev, 0, sizeof ev);
  ev.status_line = status_line;
  ev.header = header;
  ev.body = body;
  ev.message_done = done;
  ev.failure = failure;
  ev.version = version;
  ev.switching = switching;
  h = twist_h1_new (&ev);
  if (h == NULL)
    abort ();
  fuzz_feed ((fuzz_recv) twist_h1_receive, h, data + 1, size - 1,
             fuzz_piece (data[0], size));
  twist_h1_keep (h);
  twist_h1_free (h);
  return 0;
}
