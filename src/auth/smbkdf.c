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
#include <quickstep/status.h>

#include <string.h>

/* The key derivation of MS-SMB2 3.1.4.2: SP800-108 in counter mode with
   HMAC-SHA256 as the PRF and a counter of 32 bits.  Each block is

     HMAC (key, [i]4 || label || 0x00 || context || [L]4)

   with i and L, the length wanted in bits, in big-endian.  The caller gives
   the label and the context as SMB 3.1.1 defines them, which is with their
   terminating NUL where there is one (the label "SMBSigningKey\0"), and the
   context is the pre-authentication hash.  Only 128 and 256 bits are made:
   the first is the first block cut short, the second is two blocks.  */

#define KDF_MAX_INPUT 256

int
twist_smb_kdf (const uint8_t *key, size_t keylen,
               const void *label, size_t labellen,
               const void *context, size_t contextlen,
               unsigned bits, uint8_t *out)
{
  uint8_t in[4 + KDF_MAX_INPUT + 1 + 4];
  uint8_t block[32];
  size_t n, blocks, i, len;

  if (key == NULL || out == NULL || (bits != 128 && bits != 256)
      || (label == NULL && labellen > 0)
      || (context == NULL && contextlen > 0))
    return TWIST_ERR_INVAL;
  if (labellen + contextlen > KDF_MAX_INPUT)
    return TWIST_ERR_INVAL;
  if (gq_crypto_init () != GQ_OK)
    return TWIST_ERR_AUTH;
  n = 4;
  memcpy (in + n, label, labellen);
  n += labellen;
  in[n++] = 0;
  memcpy (in + n, context, contextlen);
  n += contextlen;
  in[n++] = 0;
  in[n++] = 0;
  in[n++] = (uint8_t) (bits >> 8);
  in[n++] = (uint8_t) bits;
  blocks = bits / 256 + 1;
  for (i = 1; i <= blocks; i++)
    {
      in[0] = in[1] = in[2] = 0;
      in[3] = (uint8_t) i;
      if (gq_hmac (GQ_HASH_SHA256, key, keylen, in, n, block, sizeof block)
          != GQ_OK)
        {
          gq_wipe (block, sizeof block);
          return TWIST_ERR_AUTH;
        }
      len = bits / 8 - (i - 1) * 32;
      if (len > 32)
        len = 32;
      memcpy (out + (i - 1) * 32, block, len);
    }
  gq_wipe (block, sizeof block);
  return TWIST_OK;
}
