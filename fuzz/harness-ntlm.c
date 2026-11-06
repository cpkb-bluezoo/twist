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

/* The NTLM CHALLENGE parser.  The first byte picks how the input is cut into
   pieces; the rest is the CHALLENGE.  An input that is taken goes on to
   AUTHENTICATE and the signature calls.  */

const char *const fuzz_tokens[] = {
  "NTLMSSP\0", "\x02\x00\x00\x00", "\x07\x00\x08\x00", "\x06\x00\x04\x00",
  "\x02\x00\x0c\x00", "\x00\x00\x00\x00", "\x15\x02\x8a\x62", NULL
};

static const char seed_hex[] =
    "4e544c4d53535000020000000c000c003800000015028a620123456789abcdef000000000000000030003000440000000a00614a0000000f53004500520056004500520002000c0044004f004d00410049004e0001000c0053004500520056004500520007000800001122334455667700000000";

void
fuzz_seeds (void (*add) (const void *, size_t))
{
  uint8_t buf[512 + 1];
  size_t n = strlen (seed_hex) / 2, i;

  if (n + 1 > sizeof buf)
    return;
  buf[0] = 0;
  for (i = 0; i < n; i++)
    {
      unsigned v;

      sscanf (seed_hex + 2 * i, "%2x", &v);
      buf[1 + i] = (uint8_t) v;
    }
  add (buf, n + 1);
}

static int
fill (void *user, void *buf, size_t len)
{
  (void) user;
  memset (buf, 0x5a, len);
  return 0;
}

int
LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
  struct twist_ntlm_rand rnd = { fill, NULL };
  struct twist_ntlm *n;
  uint8_t out[8192], sig[16];
  size_t len, piece, off, got;

  if (size == 0)
    return 0;
  n = twist_ntlm_new ("DOMAIN", "user", "secret", "host", &rnd);
  if (n == NULL)
    abort ();
  twist_ntlm_negotiate (n, out, sizeof out, &len);
  piece = (size_t) data[0] % 64 + 1;
  data++;
  size--;
  for (off = 0; off < size; off += got)
    {
      got = size - off < piece ? size - off : piece;
      if (twist_ntlm_feed (n, data + off, got) != TWIST_OK)
        break;
    }
  if (off >= size && twist_ntlm_challenge_end (n) == TWIST_OK
      && twist_ntlm_authenticate (n, out, sizeof out, &len) == TWIST_OK)
    {
      twist_ntlm_sign (n, out, len, sig);
      twist_ntlm_verify (n, out, len, sig);
    }
  twist_ntlm_free (n);
  return 0;
}
