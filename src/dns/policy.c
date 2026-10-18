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

#include <string.h>

/* Secure first, then plaintext.  UDP's TCP retry on the truncation
   bit is part of the plaintext transport, not a separate preference.  */

static const int twist_dns_default_order[] = {
  TWIST_DNS_DOQ,
  TWIST_DNS_DOT,
  TWIST_DNS_DOH,
  TWIST_DNS_UDP
};

static int
known (int type)
{
  return type == TWIST_DNS_DOQ || type == TWIST_DNS_DOT
         || type == TWIST_DNS_DOH || type == TWIST_DNS_UDP;
}

static int
tok_eq (const char *s, size_t n, const char *lit)
{
  size_t i;

  for (i = 0; lit[i] != 0; i++)
    {
      char c;
      if (i >= n)
        return 0;
      c = s[i];
      if (c >= 'A' && c <= 'Z')
        c = (char) (c - 'A' + 'a');
      if (c != lit[i])
        return 0;
    }
  return i == n;
}

int
twist_dns_parse_order (const char *text, int *out, size_t cap, size_t *n)
{
  const char *p;

  if (text == NULL || out == NULL || n == NULL)
    return TWIST_ERR_INVAL;
  *n = 0;
  p = text;
  while (*p != 0)
    {
      const char *start;
      size_t len;
      int type = 0;
      while (*p == ' ' || *p == ',')
        p++;
      if (*p == 0)
        break;
      start = p;
      while (*p != 0 && *p != ',' && *p != ' ')
        p++;
      len = (size_t) (p - start);
      if (tok_eq (start, len, "doq"))
        type = TWIST_DNS_DOQ;
      else if (tok_eq (start, len, "dot"))
        type = TWIST_DNS_DOT;
      else if (tok_eq (start, len, "doh"))
        type = TWIST_DNS_DOH;
      else if (tok_eq (start, len, "udp"))
        type = TWIST_DNS_UDP;
      else
        return TWIST_ERR_INVAL;
      if (*n >= cap)
        return TWIST_ERR_INVAL;
      out[(*n)++] = type;
    }
  return *n > 0 ? TWIST_OK : TWIST_ERR_INVAL;
}

int
twist_dns_transport_plan (const int *user, size_t nuser, int *out,
                          size_t cap, size_t *n)
{
  const int *src;
  size_t nsrc;
  size_t i;

  if (out == NULL || n == NULL || cap == 0)
    return TWIST_ERR_INVAL;
  if (user != NULL && nuser > 0)
    {
      src = user;
      nsrc = nuser;
    }
  else
    {
      src = twist_dns_default_order;
      nsrc = sizeof twist_dns_default_order / sizeof twist_dns_default_order[0];
    }
  *n = 0;
  for (i = 0; i < nsrc && *n < cap; i++)
    {
      if (!known (src[i]))
        continue;
      out[(*n)++] = src[i];
    }
  return *n > 0 ? TWIST_OK : TWIST_ERR_INVAL;
}
