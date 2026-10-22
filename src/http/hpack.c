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

#include "hpack_tab.h"
#include "twist-int.h"

#include <stdlib.h>
#include <string.h>

#define HPACK_STATIC 61
/* The dynamic table is counted in bytes (RFC 7541, 4.1): an entry is its name,
   its value and 32.  4096 is what we allow, and it holds at most 128.  */
#define HPACK_TABLE_MAX 4096u
#define HPACK_DYN (HPACK_TABLE_MAX / 32)

struct twist_hfield
{
  char *name;
  char *value;
};

struct twist_hpack
{
  struct twist_hfield dyn[HPACK_DYN];
  size_t n_dyn;
  size_t dyn_size;		/* Bytes the entries take, as counted above.  */
  size_t dyn_max;		/* The table's size now: a size update sets it.  */
};

struct twist_hpack *
twist_hpack_new (void)
{
  struct twist_hpack *hp = calloc (1, sizeof (struct twist_hpack));

  if (hp != NULL)
    hp->dyn_max = HPACK_TABLE_MAX;
  return hp;
}

void
twist_hpack_free (struct twist_hpack *hp)
{
  size_t i;

  if (hp == NULL)
    return;
  for (i = 0; i < hp->n_dyn; i++)
    {
      free (hp->dyn[i].name);
      free (hp->dyn[i].value);
    }
  free (hp);
}

static int
read_int (const uint8_t *p, size_t len, size_t *off, unsigned prefix,
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
      if (shift > 56)
        return -1;
      v += (uint64_t) (b & 127u) << shift;
      shift += 7;
      if ((b & 128u) == 0)
        break;
    }
  *out = v;
  return 1;
}

int
twist_huff_decode (const uint8_t *in, size_t in_len, uint8_t **out,
                   size_t *out_len)
{
  uint64_t acc = 0;
  int nbits = 0;
  size_t i = 0;
  uint8_t *buf;
  size_t n = 0;
  size_t cap = in_len * 2 + 1;

  buf = twist_xmalloc (cap);
  if (buf == NULL)
    return TWIST_ERR_NOMEM;
  while (i < in_len || nbits >= 5)
    {
      int matched = 0;
      int bits;

      while (nbits < 30 && i < in_len)
        {
          acc = (acc << 8) | in[i++];
          nbits += 8;
        }
      for (bits = 5; bits <= 30 && bits <= nbits; bits++)
        {
          uint32_t mask = bits == 32 ? 0xffffffffu : (1u << bits) - 1u;
          uint32_t code = (uint32_t) ((acc >> (nbits - bits)) & mask);
          int s;

          for (s = 0; s < 257; s++)
            if (twist_huff_bits[s] == bits && twist_huff_code[s] == code)
              {
                if (s == 256)
                  {
                    nbits = 0;
                    matched = 1;
                    i = in_len;
                    break;
                  }
                if (n + 1 >= cap)
                  {
                    free (buf);
                    return TWIST_ERR_PROTOCOL;
                  }
                buf[n++] = (uint8_t) s;
                nbits -= bits;
                if (nbits == 0)
                  acc = 0;
                else
                  acc &= (1ull << nbits) - 1ull;
                matched = 1;
                break;
              }
          if (matched)
            break;
        }
      if (!matched)
        {
          if (i >= in_len && nbits < 8)
            break;
          free (buf);
          return TWIST_ERR_PROTOCOL;
        }
    }
  buf[n] = 0;
  *out = buf;
  *out_len = n;
  return TWIST_OK;
}

static int
read_string (const uint8_t *p, size_t len, size_t *off, char **out)
{
  int huff;
  uint64_t slen;
  int rc;

  if (*off >= len)
    return 0;
  huff = (p[*off] & 0x80) != 0;
  rc = read_int (p, len, off, 7, &slen);
  if (rc <= 0)
    return rc;
  if (*off + slen > len)
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

static int
lookup (struct twist_hpack *hp, uint64_t idx, const char **name,
        const char **value)
{
  if (idx == 0)
    return TWIST_ERR_PROTOCOL;
  if (idx <= HPACK_STATIC)
    {
      *name = twist_hpack_static_tab[idx - 1].name;
      *value = twist_hpack_static_tab[idx - 1].value;
      return TWIST_OK;
    }
  idx -= HPACK_STATIC + 1;
  if (idx >= hp->n_dyn)
    return TWIST_ERR_PROTOCOL;
  *name = hp->dyn[idx].name;
  *value = hp->dyn[idx].value;
  return TWIST_OK;
}

static size_t
entry_size (const char *name, const char *value)
{
  return strlen (name) + strlen (value) + 32;
}

/* Drop the oldest entries until the table is no bigger than LIMIT.  */
static void
evict (struct twist_hpack *hp, size_t limit)
{
  while (hp->n_dyn > 0 && hp->dyn_size > limit)
    {
      struct twist_hfield *old = &hp->dyn[hp->n_dyn - 1];

      hp->dyn_size -= entry_size (old->name, old->value);
      free (old->name);
      free (old->value);
      hp->n_dyn--;
    }
}

/* Add an entry, which the table owns.  Room is made first; an entry that is
   bigger than the whole table empties it and is not kept (RFC 7541, 4.4).  */
static void
dyn_insert (struct twist_hpack *hp, char *name, char *value)
{
  size_t sz, i;

  if (name == NULL || value == NULL)
    {
      free (name);
      free (value);
      return;
    }
  sz = entry_size (name, value);
  evict (hp, sz > hp->dyn_max ? 0 : hp->dyn_max - sz);
  if (sz > hp->dyn_max)
    {
      free (name);
      free (value);
      return;
    }
  for (i = hp->n_dyn; i > 0; i--)
    hp->dyn[i] = hp->dyn[i - 1];
  hp->dyn[0].name = name;
  hp->dyn[0].value = value;
  hp->n_dyn++;
  hp->dyn_size += sz;
}

int
twist_hpack_decode (struct twist_hpack *hp, const uint8_t *data, size_t len,
                    struct twist_h1_events *ev)
{
  size_t off = 0;

  while (off < len)
    {
      uint8_t b = data[off];
      const char *name = NULL;
      const char *value = NULL;
      char *nbuf = NULL;
      char *vbuf = NULL;
      int add = 0, rc = TWIST_ERR_PROTOCOL;
      uint64_t idx = 0;

      if (b & 0x80)
        {
          /* An entry of either table.  */
          if (read_int (data, len, &off, 7, &idx) <= 0)
            return TWIST_ERR_PROTOCOL;
          if (lookup (hp, idx, &name, &value) != TWIST_OK)
            return TWIST_ERR_PROTOCOL;
        }
      else if ((b & 0xe0) == 0x20)
        {
          /* The table is to be this big (6.3); not more than we allow.  */
          uint64_t size;

          if (read_int (data, len, &off, 5, &size) <= 0)
            return TWIST_ERR_PROTOCOL;
          if (size > HPACK_TABLE_MAX)
            return TWIST_ERR_PROTOCOL;
          hp->dyn_max = (size_t) size;
          evict (hp, hp->dyn_max);
          continue;
        }
      else
        {
          /* A literal: with indexing (01, 6 bit prefix), or without or never
             (0000 and 0001, 4 bit).  The name is an entry's, or a string.  */
          unsigned prefix = (b & 0x40) ? 6 : 4;
          unsigned mask = (b & 0x40) ? 0x3f : 0x0f;

          add = (b & 0x40) != 0;
          if ((b & mask) != 0)
            {
              if (read_int (data, len, &off, prefix, &idx) <= 0)
                return TWIST_ERR_PROTOCOL;
              if (lookup (hp, idx, &name, &value) != TWIST_OK)
                return TWIST_ERR_PROTOCOL;
              nbuf = twist_strdup (name);
              if (nbuf == NULL)
                return TWIST_ERR_NOMEM;
            }
          else
            {
              off++;
              if (read_string (data, len, &off, &nbuf) <= 0)
                return TWIST_ERR_PROTOCOL;
            }
          if (read_string (data, len, &off, &vbuf) <= 0)
            goto fail;
          name = nbuf;
          value = vbuf;
        }
      if (ev != NULL && ev->header != NULL)
        ev->header (ev->user, name, strlen (name), value, strlen (value));
      if (add)
        {
          /* The table keeps copies, so that the event has had the originals
             whatever the table does.  */
          dyn_insert (hp, twist_strdup (nbuf), twist_strdup (vbuf));
        }
      free (nbuf);
      free (vbuf);
      continue;
    fail:
      /* The name that was read is not leaked.  */
      free (nbuf);
      free (vbuf);
      return rc;
    }
  return TWIST_OK;
}

static int
emit_str (uint8_t **buf, size_t *n, size_t *cap, const char *s)
{
  size_t len = strlen (s);
  size_t extra = 1;
  size_t rest;

  if (len >= 127)
    {
      rest = len - 127;
      do
        {
          extra++;
          if (rest < 128)
            break;
          rest >>= 7;
        }
      while (rest > 0);
    }
  if (*n + extra + len > *cap)
    return TWIST_ERR_NOMEM;
  if (len < 127)
    (*buf)[(*n)++] = (uint8_t) len;
  else
    {
      (*buf)[(*n)++] = 127;
      rest = len - 127;
      while (rest >= 128)
        {
          (*buf)[(*n)++] = (uint8_t) ((rest & 127u) | 128u);
          rest >>= 7;
        }
      (*buf)[(*n)++] = (uint8_t) rest;
    }
  if (len > 0)
    memcpy (*buf + *n, s, len);
  *n += len;
  return TWIST_OK;
}

int
twist_hpack_encode_request (struct twist_hpack *hp, const char *method,
                            const char *scheme, const char *authority,
                            const char *path, const struct twist_slist *extra,
                            uint8_t **out, size_t *out_len)
{
  uint8_t *buf;
  size_t n = 0;
  size_t cap = 512;
  size_t i;
  const struct twist_slist *h;
  (void) hp;

  buf = twist_xmalloc (cap);
  if (buf == NULL)
    return TWIST_ERR_NOMEM;
  if (strcmp (method, "GET") == 0)
    buf[n++] = 0x82;
  else if (strcmp (method, "POST") == 0)
    buf[n++] = 0x83;
  else
    {
      buf[n++] = 0x40 | 2;
      if (emit_str (&buf, &n, &cap, method) != TWIST_OK)
        {
          free (buf);
          return TWIST_ERR_NOMEM;
        }
    }
  /* CONNECT (RFC 9113, 8.5) has neither a scheme nor a path.  */
  if (scheme != NULL)
    buf[n++] = strcmp (scheme, "https") == 0 ? 0x87 : 0x86;
  if (path != NULL)
    {
      buf[n++] = strcmp (path, "/") == 0 ? 0x84 : 0;
      if (strcmp (path, "/") != 0)
        {
          buf[n - 1] = 0x40 | 4;
          if (emit_str (&buf, &n, &cap, path) != TWIST_OK)
            {
              free (buf);
              return TWIST_ERR_NOMEM;
            }
        }
    }
  buf[n++] = 0x41;
  if (emit_str (&buf, &n, &cap, authority) != TWIST_OK)
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
      /* Field names are lower case in HTTP/2 (RFC 9113, section 8.2.1), and a
         request with a capital in one is malformed: some servers refuse it,
         and a GOAWAY ends the whole connection.  Values are as given.  */
      for (i = 0; i < nl; i++)
        name[i] = h->data[i] >= 'A' && h->data[i] <= 'Z'
                  ? (char) (h->data[i] + 32) : h->data[i];
      name[nl] = 0;
      val = colon + 1;
      while (*val == ' ')
        val++;
      /* Connection-specific fields are not sent in HTTP/2 (section 8.2.2).  */
      if (twist_header_connection_specific (name, nl, val))
        continue;
      if (n + nl + strlen (val) + 4 > cap)
        {
          free (buf);
          return TWIST_ERR_NOMEM;
        }
      buf[n++] = 0x40;
      if (emit_str (&buf, &n, &cap, name) != TWIST_OK
          || emit_str (&buf, &n, &cap, val) != TWIST_OK)
        {
          free (buf);
          return TWIST_ERR_NOMEM;
        }
    }
  *out = buf;
  *out_len = n;
  return TWIST_OK;
}
