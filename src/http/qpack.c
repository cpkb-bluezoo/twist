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

static int
qpack_string (const uint8_t *p, size_t len, size_t *off, char **out)
{
  int huff;
  uint64_t slen;
  int rc;

  if (*off >= len)
    return 0;
  huff = (p[*off] & 0x80) != 0;
  rc = qpack_int (p, len, off, 7, &slen);
  if (rc <= 0)
    return rc;
  if (*off + (size_t) slen > len)
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
  (void) ric;
  (void) base;
  while (off < len)
    {
      uint8_t b = data[off];
      char *name = NULL;
      char *value = NULL;
      const char *nptr;
      const char *vptr;

      if (b & 0x80)
        {
          uint64_t idx;
          int stat;
          if (qpack_int (data, len, &off, 6, &idx) <= 0)
            return TWIST_ERR_PROTOCOL;
          stat = (b & 0x40) != 0;
          if (!stat || idx >= (sizeof twist_qpack_static_tab
                               / sizeof twist_qpack_static_tab[0]))
            return TWIST_ERR_PROTOCOL;
          nptr = twist_qpack_static_tab[idx].name;
          vptr = twist_qpack_static_tab[idx].value;
        }
      else if ((b & 0xc0) == 0x40)
        {
          uint64_t idx = 0;
          if ((b & 0x0f) != 0)
            {
              int stat = (b & 0x10) != 0;
              if (qpack_int (data, len, &off, 4, &idx) <= 0)
                return TWIST_ERR_PROTOCOL;
              if (!stat)
                return TWIST_ERR_PROTOCOL;
              name = twist_strdup (twist_qpack_static_tab[idx].name);
            }
          else
            {
              off++;
              if (qpack_string (data, len, &off, &name) <= 0)
                return TWIST_ERR_PROTOCOL;
            }
          if (qpack_string (data, len, &off, &value) <= 0)
            return TWIST_ERR_PROTOCOL;
          nptr = name;
          vptr = value;
        }
      else
        {
          off++;
          if (qpack_string (data, len, &off, &name) <= 0)
            return TWIST_ERR_PROTOCOL;
          if (qpack_string (data, len, &off, &value) <= 0)
            return TWIST_ERR_PROTOCOL;
          nptr = name;
          vptr = value;
        }
      if (ev != NULL && ev->header != NULL)
        ev->header (ev->user, nptr, strlen (nptr), vptr, strlen (vptr));
      free (name);
      free (value);
    }
  return TWIST_OK;
}

static int
put_str (uint8_t *buf, size_t cap, size_t *n, const char *s)
{
  size_t len = strlen (s);
  if (*n + 1 + len > cap)
    return TWIST_ERR_NOMEM;
  buf[(*n)++] = (uint8_t) len;
  memcpy (buf + *n, s, len);
  *n += len;
  return TWIST_OK;
}

int
twist_qpack_encode_request (const char *method, const char *scheme,
                            const char *authority, const char *path,
                            const struct twist_slist *extra, uint8_t **out,
                            size_t *out_len)
{
  uint8_t *buf = twist_xmalloc (1024);
  size_t n = 0;
  const struct twist_slist *h;
  (void) method;
  (void) scheme;
  (void) path;

  if (buf == NULL)
    return TWIST_ERR_NOMEM;
  buf[n++] = 0;
  buf[n++] = 0;
  /* :status is not a request field.  Literal :method, :scheme, :authority,
     :path with the static name references where the index fits in 4 bits.
     Static index 0 is :authority in the generated table.  */
  buf[n++] = 0x50;
  if (put_str (buf, 1024, &n, authority) != TWIST_OK)
    {
      free (buf);
      return TWIST_ERR_NOMEM;
    }
  buf[n++] = 0x20;
  if (put_str (buf, 1024, &n, ":method") != TWIST_OK
      || put_str (buf, 1024, &n, method) != TWIST_OK
      || put_str (buf, 1024, &n, ":scheme") != TWIST_OK
      || put_str (buf, 1024, &n, scheme) != TWIST_OK
      || put_str (buf, 1024, &n, ":path") != TWIST_OK
      || put_str (buf, 1024, &n, path) != TWIST_OK)
    {
      free (buf);
      return TWIST_ERR_NOMEM;
    }
  for (h = extra; h != NULL; h = h->next)
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
      buf[n++] = 0x20;
      if (put_str (buf, 1024, &n, name) != TWIST_OK
          || put_str (buf, 1024, &n, val) != TWIST_OK)
        {
          free (buf);
          return TWIST_ERR_NOMEM;
        }
    }
  *out = buf;
  *out_len = n;
  return TWIST_OK;
}
