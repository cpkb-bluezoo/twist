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

#include "twist-int.h"

#include <quickstep/crypto.h>

#include <stdint.h>
#include <string.h>

/* MD4 (RFC 1320).  NTLM makes the NT hash of a password with it and nothing
   else does: it is not offered outside src/auth/ntlm.c.  */

static uint32_t
rotl (uint32_t x, int n)
{
  return (x << n) | (x >> (32 - n));
}

#define F(x, y, z) (((x) & (y)) | (~(x) & (z)))
#define G(x, y, z) (((x) & (y)) | ((x) & (z)) | ((y) & (z)))
#define H(x, y, z) ((x) ^ (y) ^ (z))

static void
md4_block (uint32_t st[4], const uint8_t block[64])
{
  uint32_t X[16];
  uint32_t a = st[0], b = st[1], c = st[2], d = st[3];
  int i;

  for (i = 0; i < 16; i++)
    X[i] = (uint32_t) block[i * 4] | ((uint32_t) block[i * 4 + 1] << 8)
      | ((uint32_t) block[i * 4 + 2] << 16) | ((uint32_t) block[i * 4 + 3] << 24);
  /* Round 1: X in order, shifts 3, 7, 11, 19.  */
  for (i = 0; i < 16; i += 4)
    {
      a = rotl (a + F (b, c, d) + X[i], 3);
      d = rotl (d + F (a, b, c) + X[i + 1], 7);
      c = rotl (c + F (d, a, b) + X[i + 2], 11);
      b = rotl (b + F (c, d, a) + X[i + 3], 19);
    }
  /* Round 2: X by columns, shifts 3, 5, 9, 13.  */
  for (i = 0; i < 4; i++)
    {
      int k = i;

      a = rotl (a + G (b, c, d) + X[k] + 0x5a827999, 3);
      d = rotl (d + G (a, b, c) + X[k + 4] + 0x5a827999, 5);
      c = rotl (c + G (d, a, b) + X[k + 8] + 0x5a827999, 9);
      b = rotl (b + G (c, d, a) + X[k + 12] + 0x5a827999, 13);
    }
  /* Round 3: X in bit-reversed order, shifts 3, 9, 11, 15.  */
  {
    static const int o[4] = { 0, 2, 1, 3 };

    for (i = 0; i < 4; i++)
      {
        int k = o[i];

        a = rotl (a + H (b, c, d) + X[k] + 0x6ed9eba1, 3);
        d = rotl (d + H (a, b, c) + X[k + 8] + 0x6ed9eba1, 9);
        c = rotl (c + H (d, a, b) + X[k + 4] + 0x6ed9eba1, 11);
        b = rotl (b + H (c, d, a) + X[k + 12] + 0x6ed9eba1, 15);
      }
  }
  st[0] += a;
  st[1] += b;
  st[2] += c;
  st[3] += d;
  gq_wipe (X, sizeof X);
}

int
twist_md4 (const void *data, size_t len, uint8_t out[16])
{
  uint32_t st[4] = { 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476 };
  const uint8_t *p = data;
  uint8_t block[64];
  size_t off = 0;
  uint64_t bits = (uint64_t) len * 8u;
  size_t i;

  if (out == NULL || (data == NULL && len > 0))
    return TWIST_ERR_INVAL;
  while (len - off >= 64)
    {
      md4_block (st, p + off);
      off += 64;
    }
  memset (block, 0, sizeof block);
  if (len > off)
    memcpy (block, p + off, len - off);
  block[len - off] = 0x80;
  if (len - off >= 56)
    {
      md4_block (st, block);
      memset (block, 0, sizeof block);
    }
  for (i = 0; i < 8; i++)
    block[56 + i] = (uint8_t) (bits >> (8 * i));
  md4_block (st, block);
  for (i = 0; i < 4; i++)
    {
      out[i * 4] = (uint8_t) st[i];
      out[i * 4 + 1] = (uint8_t) (st[i] >> 8);
      out[i * 4 + 2] = (uint8_t) (st[i] >> 16);
      out[i * 4 + 3] = (uint8_t) (st[i] >> 24);
    }
  gq_wipe (block, sizeof block);
  gq_wipe (st, sizeof st);
  return TWIST_OK;
}
