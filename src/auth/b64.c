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

#include <stdlib.h>
#include <string.h>

int
twist_b64_encode (const uint8_t *in, size_t len, char **out)
{
  static const char tab[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  size_t n = 4 * ((len + 2) / 3);
  char *buf = twist_xmalloc (n + 1);
  size_t i;
  size_t o = 0;

  if (buf == NULL)
    return TWIST_ERR_NOMEM;
  for (i = 0; i < len; i += 3)
    {
      unsigned v = (unsigned) in[i] << 16;
      if (i + 1 < len)
        v |= (unsigned) in[i + 1] << 8;
      if (i + 2 < len)
        v |= in[i + 2];
      buf[o++] = tab[(v >> 18) & 63];
      buf[o++] = tab[(v >> 12) & 63];
      buf[o++] = i + 1 < len ? tab[(v >> 6) & 63] : '=';
      buf[o++] = i + 2 < len ? tab[v & 63] : '=';
    }
  buf[o] = 0;
  *out = buf;
  return TWIST_OK;
}

