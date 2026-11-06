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

/* SHA-512 and AES-128-CMAC, as SMB 3.1.1 uses them: the first for the
   pre-authentication hash, the second for message signatures.  Thin wrappers
   over quickstep, in the style of twist_sha256.  */

int
twist_sha512 (const void *data, size_t len, uint8_t out[64])
{
  if (out == NULL || (data == NULL && len > 0))
    return TWIST_ERR_INVAL;
  if (gq_crypto_init () != GQ_OK)
    return TWIST_ERR_AUTH;
  if (gq_sha512 (data, len, out) != GQ_OK)
    return TWIST_ERR_AUTH;
  return TWIST_OK;
}

int
twist_cmac_aes128 (const uint8_t key[16], const void *data, size_t len,
                   uint8_t out[16])
{
  if (key == NULL || out == NULL || (data == NULL && len > 0))
    return TWIST_ERR_INVAL;
  if (gq_crypto_init () != GQ_OK)
    return TWIST_ERR_AUTH;
  if (gq_cmac_aes128 (key, data, len, out) != GQ_OK)
    return TWIST_ERR_AUTH;
  return TWIST_OK;
}
