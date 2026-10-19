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
#include <strings.h>
#include <zlib.h>

/* gzip and deflate only.  A later coding, such as Brotli, is another
   name in coding_kind and does not change the HTTP caller.  */

struct twist_coding
{
  z_stream strm;
  int inited;
  int kind;
  int raw;
  int started;
  int ended;
};

static int
coding_kind (const char *name)
{
  if (name == NULL)
    return 0;
  if (strcasecmp (name, "gzip") == 0 || strcasecmp (name, "x-gzip") == 0)
    return 1;
  if (strcasecmp (name, "deflate") == 0)
    return 2;
  return 0;
}

int
twist_coding_known (const char *name)
{
  return coding_kind (name) != 0;
}

static int
grow (uint8_t **buf, size_t *cap, size_t need)
{
  size_t ncap = *cap == 0 ? 256 : *cap;
  uint8_t *p;

  if (need <= *cap)
    return TWIST_OK;
  while (ncap < need)
    {
      if (ncap > (size_t) -1 / 2)
        return TWIST_ERR_NOMEM;
      ncap *= 2;
    }
  p = realloc (*buf, ncap);
  if (p == NULL)
    return TWIST_ERR_NOMEM;
  *buf = p;
  *cap = ncap;
  return TWIST_OK;
}

static int
decoder_init (struct twist_coding *c, int window)
{
  int z;

  memset (&c->strm, 0, sizeof c->strm);
  z = inflateInit2 (&c->strm, window);
  if (z != Z_OK)
    return z == Z_MEM_ERROR ? TWIST_ERR_NOMEM : TWIST_ERR_ENCODING;
  c->inited = 1;
  return TWIST_OK;
}

int
twist_coding_open (struct twist_coding **out, const char *name)
{
  struct twist_coding *c;
  int kind;
  int window;
  int rc;

  if (out == NULL)
    return TWIST_ERR_INVAL;
  *out = NULL;
  kind = coding_kind (name);
  if (kind == 0)
    return TWIST_ERR_ENCODING;
  c = calloc (1, sizeof *c);
  if (c == NULL)
    return TWIST_ERR_NOMEM;
  c->kind = kind;
  window = kind == 1 ? 16 + MAX_WBITS : MAX_WBITS;
  rc = decoder_init (c, window);
  if (rc != TWIST_OK)
    {
      free (c);
      return rc;
    }
  *out = c;
  return TWIST_OK;
}

static int
inflate_chunk (struct twist_coding *c, uint8_t *in, size_t n,
               uint8_t **out, size_t *out_n)
{
  size_t cap = 0;
  size_t have = 0;
  uint8_t *buf = NULL;

  *out = NULL;
  *out_n = 0;
  c->strm.next_in = in;
  c->strm.avail_in = (uInt) n;
  c->strm.next_out = NULL;
  c->strm.avail_out = 0;
  for (;;)
    {
      int z;

      if (c->strm.avail_out == 0)
        {
          if (grow (&buf, &cap, have + 256) != TWIST_OK)
            {
              free (buf);
              return TWIST_ERR_NOMEM;
            }
          c->strm.next_out = buf + have;
          c->strm.avail_out = (uInt) (cap - have);
        }
      z = inflate (&c->strm, Z_NO_FLUSH);
      have = cap - c->strm.avail_out;
      if (z == Z_STREAM_END)
        {
          c->ended = 1;
          break;
        }
      if (z == Z_OK || (z == Z_BUF_ERROR && c->strm.avail_in == 0))
        {
          if (c->strm.avail_in == 0)
            break;
          continue;
        }
      if (z == Z_DATA_ERROR && c->kind == 2 && !c->raw && !c->started
          && have == 0)
        {
          int window = -MAX_WBITS;

          inflateEnd (&c->strm);
          c->inited = 0;
          free (buf);
          buf = NULL;
          cap = 0;
          have = 0;
          if (decoder_init (c, window) != TWIST_OK)
            return TWIST_ERR_ENCODING;
          c->raw = 1;
          c->strm.next_in = in;
          c->strm.avail_in = (uInt) n;
          continue;
        }
      free (buf);
      return z == Z_MEM_ERROR ? TWIST_ERR_NOMEM : TWIST_ERR_ENCODING;
    }
  c->started = 1;
  if (have == 0)
    {
      free (buf);
      buf = NULL;
    }
  *out = buf;
  *out_n = have;
  return TWIST_OK;
}

int
twist_coding_feed (struct twist_coding *c, const uint8_t *data, size_t len,
                   uint8_t **out, size_t *out_n)
{
  uint8_t *copy;
  int rc;

  if (c == NULL || out == NULL || out_n == NULL)
    return TWIST_ERR_INVAL;
  *out = NULL;
  *out_n = 0;
  if (!c->inited)
    return TWIST_ERR_ENCODING;
  if (c->ended)
    return len == 0 ? TWIST_OK : TWIST_ERR_ENCODING;
  if (len > (size_t) ~0u)
    return TWIST_ERR_ENCODING;
  if (len == 0)
    return TWIST_OK;
  copy = twist_xmalloc (len);
  if (copy == NULL)
    return TWIST_ERR_NOMEM;
  memcpy (copy, data, len);
  rc = inflate_chunk (c, copy, len, out, out_n);
  free (copy);
  return rc;
}

int
twist_coding_finish (struct twist_coding *c, uint8_t **out, size_t *out_n)
{
  uint8_t *buf = NULL;
  size_t cap = 0;
  size_t have = 0;
  uint8_t empty;

  if (c == NULL || out == NULL || out_n == NULL)
    return TWIST_ERR_INVAL;
  *out = NULL;
  *out_n = 0;
  if (!c->inited)
    return TWIST_ERR_ENCODING;
  if (c->ended)
    return TWIST_OK;
  c->strm.next_out = NULL;
  c->strm.avail_out = 0;
  c->strm.next_in = &empty;
  c->strm.avail_in = 0;
  for (;;)
    {
      int z;

      if (c->strm.avail_out == 0)
        {
          if (grow (&buf, &cap, have + 64) != TWIST_OK)
            {
              free (buf);
              return TWIST_ERR_NOMEM;
            }
          c->strm.next_out = buf + have;
          c->strm.avail_out = (uInt) (cap - have);
        }
      z = inflate (&c->strm, Z_FINISH);
      have = cap - c->strm.avail_out;
      if (z == Z_STREAM_END)
        {
          c->ended = 1;
          *out = buf;
          *out_n = have;
          return TWIST_OK;
        }
      if (z == Z_OK || (z == Z_BUF_ERROR && c->strm.avail_out == 0))
        continue;
      free (buf);
      return z == Z_MEM_ERROR ? TWIST_ERR_NOMEM : TWIST_ERR_ENCODING;
    }
}

void
twist_coding_free (struct twist_coding *c)
{
  if (c == NULL)
    return;
  if (c->inited)
    inflateEnd (&c->strm);
  free (c);
}

int
twist_coding_encode (const char *name, const uint8_t *data, size_t len,
                     uint8_t **out, size_t *out_n)
{
  z_stream strm;
  int kind;
  int window;
  int z;
  uLong bound;
  uint8_t *buf;
  uint8_t *copy = NULL;
  uint8_t empty_in = 0;

  if (out == NULL || out_n == NULL)
    return TWIST_ERR_INVAL;
  *out = NULL;
  *out_n = 0;
  kind = coding_kind (name);
  if (kind == 0)
    return TWIST_ERR_UNSUPPORTED;
  if (len > (size_t) ~0u)
    return TWIST_ERR_ENCODING;
  window = kind == 1 ? 16 + MAX_WBITS : MAX_WBITS;
  memset (&strm, 0, sizeof strm);
  z = deflateInit2 (&strm, Z_DEFAULT_COMPRESSION, Z_DEFLATED, window, 8,
                    Z_DEFAULT_STRATEGY);
  if (z != Z_OK)
    return z == Z_MEM_ERROR ? TWIST_ERR_NOMEM : TWIST_ERR_ENCODING;
  bound = deflateBound (&strm, (uLong) len);
  if (bound > (uLong) ~0u)
    {
      deflateEnd (&strm);
      return TWIST_ERR_ENCODING;
    }
  buf = twist_xmalloc (bound > 0 ? (size_t) bound : 1);
  if (buf == NULL)
    {
      deflateEnd (&strm);
      return TWIST_ERR_NOMEM;
    }
  if (len > 0)
    {
      copy = twist_xmalloc (len);
      if (copy == NULL)
        {
          free (buf);
          deflateEnd (&strm);
          return TWIST_ERR_NOMEM;
        }
      memcpy (copy, data, len);
    }
  strm.next_in = copy != NULL ? copy : &empty_in;
  strm.avail_in = (uInt) len;
  strm.next_out = buf;
  strm.avail_out = (uInt) bound;
  z = deflate (&strm, Z_FINISH);
  *out_n = (size_t) strm.total_out;
  deflateEnd (&strm);
  free (copy);
  if (z != Z_STREAM_END)
    {
      free (buf);
      return z == Z_MEM_ERROR ? TWIST_ERR_NOMEM : TWIST_ERR_ENCODING;
    }
  *out = buf;
  return TWIST_OK;
}
