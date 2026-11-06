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

/* The SPNEGO token reader.  The first byte picks the size of the pieces the
   input is fed in and which of the server's two tokens it is; the rest is
   the token.  A first token that is taken goes on, and the same bytes are
   offered again as the last.  */

const char *const fuzz_tokens[] = {
  "\xa1", "\x30", "\xa0\x03\x0a\x01\x01", "\xa0\x03\x0a\x01\x00",
  "\xa1\x0c\x06\x0a\x2b\x06\x01\x04\x01\x82\x37\x02\x02\x0a", "\xa2", "\xa3",
  "\x04\x10", "NTLMSSP\0", NULL
};

static const char seed1[] =
    "a1818e30818ba0030a0101a10c060a2b06010401823702020aa27604744e544c4d53535000020000000c000c003800000015028a620123456789abcdef000000000000000030003000440000000a00614a0000000f53004500520056004500520002000c0044004f004d00410049004e0001000c0053004500520056004500520007000800001122334455667700000000";
static const char seed2[] =
    "a11b3019a0030a0100a3120410010000007dd6da05648a73ae00000000";

static void
add_hex (void (*add) (const void *, size_t), const char *hex, int which)
{
  uint8_t buf[1 + 1200];
  size_t n = strlen (hex) / 2, i;

  if (n + 1 > sizeof buf)
    return;
  buf[0] = (uint8_t) which;
  for (i = 0; i < n; i++)
    {
      unsigned v;

      sscanf (hex + 2 * i, "%2x", &v);
      buf[1 + i] = (uint8_t) v;
    }
  add (buf, n + 1);
}

void
fuzz_seeds (void (*add) (const void *, size_t))
{
  add_hex (add, seed1, 0);
  add_hex (add, seed2, 0x80);
}

static int
fill (void *user, void *buf, size_t len)
{
  (void) user;
  memset (buf, 0x5a, len);
  return 0;
}

static int
offer (struct twist_spnego *s, const uint8_t *data, size_t size, size_t piece,
       uint8_t *out, size_t cap, int *done)
{
  size_t off, got, n;

  for (off = 0; off < size; off += got)
    {
      got = size - off < piece ? size - off : piece;
      if (twist_spnego_feed (s, data + off, got) != TWIST_OK)
        return -1;
    }
  if (size == 0)
    return -1;
  return twist_spnego_finish (s, out, cap, &n, done) == TWIST_OK ? 0 : -1;
}

int
LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
  struct twist_ntlm_rand rnd = { fill, NULL };
  struct twist_spnego *s;
  uint8_t out[8192];
  size_t len;
  int done = 0;

  if (size == 0)
    return 0;
  s = twist_spnego_new ("DOMAIN", "user", "secret", "host", &rnd);
  if (s == NULL)
    abort ();
  twist_spnego_start (s, out, sizeof out, &len);
  if (offer (s, data + 1, size - 1, (size_t) (data[0] & 0x3f) + 1, out,
             sizeof out, &done) == 0)
    offer (s, data + 1, size - 1, (size_t) (data[0] & 0x3f) + 1, out,
           sizeof out, &done);
  twist_spnego_free (s);
  return 0;
}
