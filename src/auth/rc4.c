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

#include <string.h>

/* RC4.  NTLM uses it for the exported session key under KEY_EXCH and to seal
   the checksum of its message signature, and for nothing else.  It is not
   offered outside src/auth/ntlm.c.  */

int
twist_rc4_init (struct twist_rc4 *c, const uint8_t *key, size_t keylen)
{
  unsigned i, j = 0;

  if (c == NULL || key == NULL || keylen == 0 || keylen > 256)
    return TWIST_ERR_INVAL;
  for (i = 0; i < 256; i++)
    c->s[i] = (uint8_t) i;
  for (i = 0; i < 256; i++)
    {
      uint8_t t = c->s[i];

      j = (j + t + key[i % keylen]) & 0xff;
      c->s[i] = c->s[j];
      c->s[j] = t;
    }
  c->i = c->j = 0;
  return TWIST_OK;
}

void
twist_rc4_crypt (struct twist_rc4 *c, const uint8_t *in, uint8_t *out,
                 size_t len)
{
  size_t n;

  for (n = 0; n < len; n++)
    {
      uint8_t t;

      c->i = (uint8_t) (c->i + 1);
      t = c->s[c->i];
      c->j = (uint8_t) (c->j + t);
      c->s[c->i] = c->s[c->j];
      c->s[c->j] = t;
      out[n] = in[n] ^ c->s[(uint8_t) (c->s[c->i] + c->s[c->j])];
    }
}

void
twist_rc4_wipe (struct twist_rc4 *c)
{
  gq_wipe (c, sizeof *c);
}
