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

#include <stdint.h>
#include <string.h>

static uint32_t
rotl (uint32_t x, int n)
{
  return (x << n) | (x >> (32 - n));
}

static void
md5_block (uint32_t st[4], const uint8_t block[64])
{
  static const uint32_t K[64] = {
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a,
    0xa8304613, 0xfd469501, 0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
    0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821, 0xf61e2562, 0xc040b340,
    0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8,
    0x676f02d9, 0x8d2a4c8a, 0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
    0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70, 0x289b7ec6, 0xeaa127fa,
    0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92,
    0xffeff47d, 0x85845dd1, 0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
    0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
  };
  static const int S[64] = {
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
    5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
    4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
    6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21
  };
  uint32_t M[16];
  uint32_t A = st[0], B = st[1], C = st[2], D = st[3];
  int i;

  for (i = 0; i < 16; i++)
    M[i] = (uint32_t) block[i * 4] | ((uint32_t) block[i * 4 + 1] << 8)
      | ((uint32_t) block[i * 4 + 2] << 16) | ((uint32_t) block[i * 4 + 3] << 24);
  for (i = 0; i < 64; i++)
    {
      uint32_t F;
      int g;
      if (i < 16)
        {
          F = (B & C) | (~B & D);
          g = i;
        }
      else if (i < 32)
        {
          F = (D & B) | (~D & C);
          g = (5 * i + 1) % 16;
        }
      else if (i < 48)
        {
          F = B ^ C ^ D;
          g = (3 * i + 5) % 16;
        }
      else
        {
          F = C ^ (B | ~D);
          g = (7 * i) % 16;
        }
      F = F + A + K[i] + M[g];
      A = D;
      D = C;
      C = B;
      B = B + rotl (F, S[i]);
    }
  st[0] += A;
  st[1] += B;
  st[2] += C;
  st[3] += D;
}

int
twist_md5 (const void *data, size_t len, uint8_t out[16])
{
  uint32_t st[4] = { 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476 };
  const uint8_t *p = data;
  uint8_t block[64];
  size_t off = 0;
  uint64_t bits = (uint64_t) len * 8u;
  size_t i;

  while (len - off >= 64)
    {
      md5_block (st, p + off);
      off += 64;
    }
  memset (block, 0, sizeof block);
  memcpy (block, p + off, len - off);
  block[len - off] = 0x80;
  if (len - off >= 56)
    {
      md5_block (st, block);
      memset (block, 0, sizeof block);
    }
  for (i = 0; i < 8; i++)
    block[56 + i] = (uint8_t) (bits >> (8 * i));
  md5_block (st, block);
  for (i = 0; i < 4; i++)
    {
      out[i * 4] = (uint8_t) st[i];
      out[i * 4 + 1] = (uint8_t) (st[i] >> 8);
      out[i * 4 + 2] = (uint8_t) (st[i] >> 16);
      out[i * 4 + 3] = (uint8_t) (st[i] >> 24);
    }
  return TWIST_OK;
}

