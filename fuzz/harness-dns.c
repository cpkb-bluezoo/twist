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

/* DNS messages as they come over UDP, over TCP and TLS with a length in front,
   or in a DoH body; and what is taken from them.  */

static unsigned long events;

static void address (void *u, const struct twist_dns_addr *a)
{
  (void) u;
  events += strlen (a->text) + (unsigned) a->family;
}
static void https_alpn (void *u, const char *id, size_t n) { (void) u; if (n > 0) events += (unsigned char) id[n - 1]; }
static void https_port (void *u, int p) { (void) u; events += (unsigned) p; }
static void https_rr (void *u) { (void) u; events++; }
static void svcb (void *u, const char *t, const char *a, size_t an, int p,
                  int hf, const uint8_t *h)
{
  (void) u; (void) p; (void) hf;
  events += strlen (t);
  if (an > 0)
    events += (unsigned char) a[an - 1];
  if (h != NULL)
    events += h[0];
}
static void truncated (void *u) { (void) u; events++; }
static void failure (void *u, int e) { (void) u; (void) e; events++; }
static void ttl (void *u, uint32_t t) { (void) u; events += t; }

const char *const fuzz_tokens[] = {
  "\xc0\x0c", "\x00\x01\x00\x01", "\x00\x1c\x00\x01", "\x00\x41\x00\x01",
  "\x00\x05\x00\x01", "\x81\x80", "\x00\x00\x00\x3c", "\x03www\x07" "example\x03" "com\x00", NULL
};

void
fuzz_seeds (void (*add) (const void *, size_t))
{
  static const uint8_t a[] = {
    0x12, 0x34, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0,
    7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, 0, 1, 0, 1,
    0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 93, 184, 216, 34
  };
  static const uint8_t cname[] = {
    0x12, 0x34, 0x81, 0x80, 0, 1, 0, 2, 0, 0, 0, 0,
    3, 'w', 'w', 'w', 0, 0, 1, 0, 1,
    0xc0, 0x0c, 0, 5, 0, 1, 0, 0, 0, 60, 0, 2, 0xc0, 0x10,
    0xc0, 0x10, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 1, 2, 3, 4
  };

  add (a, sizeof a);
  add (cname, sizeof cname);
}

int
LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
  struct twist_dns_events ev;
  struct twist_dns_addr *addrs = NULL;
  size_t n = 0;
  uint8_t *window = malloc (size + 1);
  size_t have = 0;

  memset (&ev, 0, sizeof ev);
  ev.address = address;
  ev.https_alpn = https_alpn;
  ev.https_port = https_port;
  ev.https_rr = https_rr;
  ev.svcb = svcb;
  ev.truncated = truncated;
  ev.failure = failure;
  ev.ttl = ttl;
  twist_dns_datagram_receive (data, size, &ev);
  /* The same bytes as a stream, as far as it goes.  */
  if (window != NULL)
    {
      memcpy (window, data, size);
      have = size;
      while (have > 0)
        {
          size_t used = twist_dns_stream_receive (window, have, &ev);

          if (used == 0 || used > have)
            break;
          memmove (window, window + used, have - used);
          have -= used;
        }
      free (window);
    }
  if (twist_dns_decode (data, size, 1, &addrs, &n) == TWIST_OK)
    free (addrs);
  addrs = NULL;
  if (twist_dns_decode (data, size, 28, &addrs, &n) == TWIST_OK)
    free (addrs);
  twist_dns_response_ok (data, size, 0x1234, "example.com");
  return 0;
}
