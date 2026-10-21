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

/* HPACK: header blocks decoded one after another, so that what the first
   put in the dynamic table is there for the next; and Huffman strings.  */

static unsigned long events;

static void header (void *u, const char *a, size_t an, const char *b, size_t bn)
{
  (void) u;
  if (an > 0)
    events += (unsigned char) a[an - 1];
  if (bn > 0)
    events += (unsigned char) b[bn - 1];
}

void
fuzz_seeds (void (*add) (const void *, size_t))
{
  static const uint8_t seeds[][12] = {
    { 0x88 }, { 0x82, 0x86, 0x84 }, { 0x40, 0x01, 'a', 0x01, 'b' },
    { 0x3f, 0xe1, 0x1f }, { 0x41, 0x8c, 0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a,
                            0x6b, 0xa0, 0xab, 0x90 }
  };
  size_t i;

  for (i = 0; i < sizeof seeds / sizeof seeds[0]; i++)
    add (seeds[i], 12);
}

int
LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
  struct twist_h1_events ev;
  struct twist_hpack *hp = twist_hpack_new ();
  uint8_t *out = NULL;
  size_t n = 0, half = size / 2;

  memset (&ev, 0, sizeof ev);
  ev.header = header;
  twist_hpack_decode (hp, data, half, &ev);
  twist_hpack_decode (hp, data + half, size - half, &ev);
  twist_hpack_decode (hp, data, size, &ev);
  twist_hpack_free (hp);
  if (twist_huff_decode (data, size, &out, &n) == TWIST_OK)
    free (out);
  return 0;
}
