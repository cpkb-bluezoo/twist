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

#include "feed.h"

#include <string.h>

void
feed_n (size_t (*recv) (void *, const uint8_t *, size_t), void *obj,
        const char *text, size_t split)
{
  const uint8_t *data = (const uint8_t *) text;
  size_t n = strlen (text);
  uint8_t window[1024];
  size_t held = 0;
  size_t off = 0;

  while (off < n)
    {
      size_t take = split;
      size_t got;
      size_t used;

      if (take > n - off)
        take = n - off;
      memcpy (window + held, data + off, take);
      off += take;
      got = held + take;
      used = recv (obj, window, got);
      if (used > got)
        used = got;
      held = got - used;
      if (held > 0)
        memmove (window, window + used, held);
    }
}

void
feed_bin (size_t (*recv) (void *, const uint8_t *, size_t), void *obj,
          const uint8_t *data, size_t n, size_t split)
{
  uint8_t window[1024];
  size_t held = 0;
  size_t off = 0;

  while (off < n)
    {
      size_t take = split;
      size_t got;
      size_t used;

      if (take > n - off)
        take = n - off;
      memcpy (window + held, data + off, take);
      off += take;
      got = held + take;
      used = recv (obj, window, got);
      if (used > got)
        used = got;
      held = got - used;
      if (held > 0)
        memmove (window, window + used, held);
    }
}

int
has_bytes (const uint8_t *hay, size_t n, const void *needle, size_t m)
{
  size_t i;

  if (needle == NULL || m == 0 || m > n)
    return 0;
  for (i = 0; i + m <= n; i++)
    if (memcmp (hay + i, needle, m) == 0)
      return 1;
  return 0;
}
