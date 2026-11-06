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

#include <stdlib.h>
#include <string.h>

/* HMAC-MD5 (RFC 2104) on twist_md5.  NTLMv2 and NTLM's message signature use
   it.  The key is hashed first if it is longer than the block of 64 bytes.  */

int
twist_hmac_md5 (const void *key, size_t keylen, const void *data, size_t len,
                uint8_t out[16])
{
  uint8_t k[64], inner[16];
  uint8_t *buf;
  size_t i;
  int rc;

  if (out == NULL || (key == NULL && keylen > 0) || (data == NULL && len > 0))
    return TWIST_ERR_INVAL;
  if (len > (size_t) -1 - 64)
    return TWIST_ERR_INVAL;
  buf = malloc (64 + (len > 16 ? len : 16));
  if (buf == NULL)
    return TWIST_ERR_NOMEM;
  memset (k, 0, sizeof k);
  if (keylen > 64)
    twist_md5 (key, keylen, k);
  else if (keylen > 0)
    memcpy (k, key, keylen);
  for (i = 0; i < 64; i++)
    buf[i] = k[i] ^ 0x36;
  if (len > 0)
    memcpy (buf + 64, data, len);
  rc = twist_md5 (buf, 64 + len, inner);
  if (rc == TWIST_OK)
    {
      for (i = 0; i < 64; i++)
        buf[i] = k[i] ^ 0x5c;
      memcpy (buf + 64, inner, 16);
      rc = twist_md5 (buf, 64 + 16, out);
    }
  gq_wipe (buf, 64 + (len > 16 ? len : 16));
  gq_wipe (k, sizeof k);
  gq_wipe (inner, sizeof inner);
  free (buf);
  return rc;
}
