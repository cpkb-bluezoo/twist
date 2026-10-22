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

#include "qpack_tab.h"
#include "twist-int.h"

#include <stdlib.h>
#include <string.h>
#include <strings.h>

struct twist_qpack
{
  int unused;
};

static int
qpack_int (const uint8_t *p, size_t len, size_t *off, unsigned prefix,
           uint64_t *out)
{
  unsigned max;
  uint64_t v;
  unsigned shift = 0;

  if (*off >= len)
    return 0;
  max = (1u << prefix) - 1u;
  v = p[(*off)++] & max;
  if (v < max)
    {
      *out = v;
      return 1;
    }
  for (;;)
    {
      uint8_t b;
      if (*off >= len)
        return 0;
      b = p[(*off)++];
      v += (uint64_t) (b & 127u) << shift;
      shift += 7;
      if (shift > 56)
        return -1;
      if ((b & 128u) == 0)
        break;
    }
  *out = v;
  return 1;
}

/* A string whose length is an integer with PREFIX bits in the byte at *OFF,
   whose bit HBIT says it is Huffman coded (RFC 9204, 4.1.2).  */
static int
qpack_string (const uint8_t *p, size_t len, size_t *off, unsigned prefix,
              unsigned hbit, char **out)
{
  int huff;
  uint64_t slen;
  int rc;

  if (*off >= len)
    return 0;
  huff = (p[*off] & hbit) != 0;
  rc = qpack_int (p, len, off, prefix, &slen);
  if (rc <= 0)
    return rc;
  if (slen > len || *off + (size_t) slen > len)
    return 0;
  if (huff)
    {
      uint8_t *dec = NULL;
      size_t dn = 0;
      rc = twist_huff_decode (p + *off, (size_t) slen, &dec, &dn);
      *off += (size_t) slen;
      if (rc != TWIST_OK)
        return -1;
      *out = (char *) dec;
      return 1;
    }
  *out = twist_xmalloc ((size_t) slen + 1);
  if (*out == NULL)
    return -1;
  memcpy (*out, p + *off, (size_t) slen);
  (*out)[slen] = 0;
  *off += (size_t) slen;
  return 1;
}

#define STATIC_N (sizeof twist_qpack_static_tab / sizeof twist_qpack_static_tab[0])

/* A field section (RFC 9204, 4.5).  The dynamic table is not used: we say so
   in SETTINGS (a capacity of 0), so a section needs nothing from it, and one
   that does is an error.  */
int
twist_qpack_decode (const uint8_t *data, size_t len, struct twist_h1_events *ev)
{
  size_t off = 0;
  uint64_t ric;
  uint64_t base;

  if (qpack_int (data, len, &off, 8, &ric) <= 0)
    return TWIST_ERR_PROTOCOL;
  if (qpack_int (data, len, &off, 7, &base) <= 0)
    return TWIST_ERR_PROTOCOL;
  if (ric != 0)
    return TWIST_ERR_PROTOCOL;
  while (off < len)
    {
      uint8_t b = data[off];
      char *name = NULL;
      char *value = NULL;
      const char *nptr;
      const char *vptr;

      if (b & 0x80)
        {
          /* Indexed field line: 1 T index(6).  */
          uint64_t idx;

          if (qpack_int (data, len, &off, 6, &idx) <= 0)
            return TWIST_ERR_PROTOCOL;
          if ((b & 0x40) == 0 || idx >= STATIC_N)
            return TWIST_ERR_PROTOCOL;
          nptr = twist_qpack_static_tab[idx].name;
          vptr = twist_qpack_static_tab[idx].value;
        }
      else if ((b & 0xc0) == 0x40)
        {
          /* Literal with name reference: 01 N T index(4), then the value.  */
          uint64_t idx = 0;

          if (qpack_int (data, len, &off, 4, &idx) <= 0)
            return TWIST_ERR_PROTOCOL;
          if ((b & 0x10) == 0 || idx >= STATIC_N)
            return TWIST_ERR_PROTOCOL;
          name = twist_strdup (twist_qpack_static_tab[idx].name);
          if (name == NULL)
            return TWIST_ERR_NOMEM;
          if (qpack_string (data, len, &off, 7, 0x80, &value) <= 0)
            {
              free (name);
              return TWIST_ERR_PROTOCOL;
            }
          nptr = name;
          vptr = value;
        }
      else if ((b & 0xe0) == 0x20)
        {
          /* Literal with literal name: 001 N H length(3), the name, then the
             value.  */
          if (qpack_string (data, len, &off, 3, 0x08, &name) <= 0)
            return TWIST_ERR_PROTOCOL;
          if (qpack_string (data, len, &off, 7, 0x80, &value) <= 0)
            {
              free (name);
              return TWIST_ERR_PROTOCOL;
            }
          nptr = name;
          vptr = value;
        }
      else
        /* Post-base: it needs the dynamic table.  */
        return TWIST_ERR_PROTOCOL;
      if (ev != NULL && ev->header != NULL)
        ev->header (ev->user, nptr, strlen (nptr), vptr, strlen (vptr));
      free (name);
      free (value);
    }
  return TWIST_OK;
}

/* ---- the encoder: the static table and literals, nothing else ---- */

static int
put_int (uint8_t *buf, size_t cap, size_t *n, uint8_t pattern, unsigned prefix,
         uint64_t v)
{
  unsigned max = (1u << prefix) - 1u;

  if (*n >= cap)
    return TWIST_ERR_NOMEM;
  if (v < max)
    {
      buf[(*n)++] = (uint8_t) (pattern | v);
      return TWIST_OK;
    }
  buf[(*n)++] = (uint8_t) (pattern | max);
  v -= max;
  while (v >= 128)
    {
      if (*n >= cap)
        return TWIST_ERR_NOMEM;
      buf[(*n)++] = (uint8_t) (v | 128);
      v >>= 7;
    }
  if (*n >= cap)
    return TWIST_ERR_NOMEM;
  buf[(*n)++] = (uint8_t) v;
  return TWIST_OK;
}

static int
put_bytes (uint8_t *buf, size_t cap, size_t *n, const char *s, size_t len)
{
  if (*n + len > cap)
    return TWIST_ERR_NOMEM;
  memcpy (buf + *n, s, len);
  *n += len;
  return TWIST_OK;
}

/* A field a credential or cookie travels in is never put in a table by an
   intermediary (the N bit).  */
static int
sensitive (const char *name)
{
  return strcasecmp (name, "authorization") == 0
         || strcasecmp (name, "proxy-authorization") == 0
         || strcasecmp (name, "cookie") == 0
         || strcasecmp (name, "set-cookie") == 0;
}

static int
put_field (uint8_t *buf, size_t cap, size_t *n, const char *given,
           const char *value)
{
  size_t i;
  long name_idx = -1;
  size_t nl = strlen (given);
  char lower[160];
  const char *name = lower;
  size_t vl = strlen (value);
  int never;
  int rc;

  /* Names are lower case in HTTP/3.  */
  if (nl >= sizeof lower)
    return TWIST_ERR_NOMEM;
  for (i = 0; i < nl; i++)
    lower[i] = given[i] >= 'A' && given[i] <= 'Z' ? given[i] + 32 : given[i];
  lower[nl] = 0;
  never = sensitive (name);

  for (i = 0; i < STATIC_N; i++)
    {
      if (strcmp (twist_qpack_static_tab[i].name, name) != 0)
        continue;
      if (!never && strcmp (twist_qpack_static_tab[i].value, value) == 0
          && value[0] != 0)
        return put_int (buf, cap, n, 0xc0, 6, i);
      if (name_idx < 0)
        name_idx = (long) i;
    }
  if (name_idx >= 0)
    rc = put_int (buf, cap, n, (uint8_t) (0x50 | (never ? 0x20 : 0)), 4,
                  (uint64_t) name_idx);
  else
    {
      rc = put_int (buf, cap, n, (uint8_t) (0x20 | (never ? 0x10 : 0)), 3, nl);
      if (rc == TWIST_OK)
        {
          rc = put_bytes (buf, cap, n, name, nl);
        }
    }
  if (rc != TWIST_OK)
    return rc;
  rc = put_int (buf, cap, n, 0x00, 7, vl);
  if (rc != TWIST_OK)
    return rc;
  return put_bytes (buf, cap, n, value, vl);
}

/* The request's fields.  SCHEME and PATH are NULL for a CONNECT that has
   none.  EXTRA is "name: value" lines, and may have ":protocol".  */
int
twist_qpack_encode_request (const char *method, const char *scheme,
                            const char *authority, const char *path,
                            const struct twist_slist *extra, uint8_t **out,
                            size_t *out_len)
{
  size_t cap = 1024;
  uint8_t *buf;
  size_t n = 0;
  const struct twist_slist *h;
  int rc;

  for (h = extra; h != NULL; h = h->next)
    cap += strlen (h->data) + 16;
  cap += strlen (method) + (scheme != NULL ? strlen (scheme) : 0)
         + strlen (authority) + (path != NULL ? strlen (path) : 0);
  buf = twist_xmalloc (cap);
  if (buf == NULL)
    return TWIST_ERR_NOMEM;
  /* Required insert count 0, base 0.  */
  buf[n++] = 0;
  buf[n++] = 0;
  rc = put_field (buf, cap, &n, ":method", method);
  if (rc == TWIST_OK && scheme != NULL)
    rc = put_field (buf, cap, &n, ":scheme", scheme);
  if (rc == TWIST_OK)
    rc = put_field (buf, cap, &n, ":authority", authority);
  if (rc == TWIST_OK && path != NULL)
    rc = put_field (buf, cap, &n, ":path", path);
  for (h = extra; rc == TWIST_OK && h != NULL; h = h->next)
    {
      const char *colon = h->data[0] == ':' ? strchr (h->data + 1, ':')
                                            : strchr (h->data, ':');
      char name[128];
      const char *val;
      size_t nl;

      if (colon == NULL)
        continue;
      nl = (size_t) (colon - h->data);
      if (nl >= sizeof name)
        continue;
      memcpy (name, h->data, nl);
      name[nl] = 0;
      val = colon + 1;
      while (*val == ' ')
        val++;
      rc = put_field (buf, cap, &n, name, val);
    }
  if (rc != TWIST_OK)
    {
      free (buf);
      return rc;
    }
  *out = buf;
  *out_len = n;
  return TWIST_OK;
}
