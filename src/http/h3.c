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

#define H3_DATA 0x00
#define H3_HEADERS 0x01
#define H3_SETTINGS 0x04
#define H3_GOAWAY 0x07
#define H3_FRAME 16384u
#define H3_MAX_LEN 65536u
#define H3_MAX_STREAMS 100u

struct twist_h3_stream
{
  int live;
  struct twist_h3_stream *next;
};

struct twist_h3
{
  struct twist_h1_events ev;
  int failed;
  uint64_t data_left;		/* Of the DATA frame being read.  */
  uint64_t skip_left;		/* Of a frame being passed over.  */
  struct twist_h3_stream *active;
  struct twist_h3_stream *free_list;
  size_t n_alloc;
};

static int
peek_varint (const uint8_t *p, size_t len, size_t *used, uint64_t *out)
{
  unsigned prefix;
  uint64_t v;
  size_t i;

  if (len == 0)
    return 0;
  prefix = 1u << (p[0] >> 6);
  if (len < prefix)
    return 0;
  v = p[0] & 0x3fu;
  for (i = 1; i < prefix; i++)
    v = (v << 8) | p[i];
  *used = prefix;
  *out = v;
  return 1;
}

static struct twist_h3_stream *
take_stream (struct twist_h3 *h)
{
  struct twist_h3_stream *s;

  if (h->active != NULL)
    return h->active;
  if (h->free_list != NULL)
    {
      s = h->free_list;
      h->free_list = s->next;
    }
  else
    {
      if (h->n_alloc >= H3_MAX_STREAMS)
        return NULL;
      s = calloc (1, sizeof *s);
      if (s == NULL)
        return NULL;
      h->n_alloc++;
    }
  s->live = 1;
  s->next = NULL;
  h->active = s;
  return s;
}

static void
release_stream (struct twist_h3 *h)
{
  struct twist_h3_stream *s = h->active;

  if (s == NULL)
    return;
  h->active = NULL;
  s->live = 0;
  s->next = h->free_list;
  h->free_list = s;
}

struct twist_h3 *
twist_h3_new (const struct twist_h1_events *ev)
{
  struct twist_h3 *h = calloc (1, sizeof *h);

  if (h == NULL)
    return NULL;
  if (ev != NULL)
    h->ev = *ev;
  return h;
}

void
twist_h3_free (struct twist_h3 *h)
{
  struct twist_h3_stream *s;

  if (h == NULL)
    return;
  s = h->active;
  if (s == NULL)
    s = h->free_list;
  else
    s->next = h->free_list;
  while (s != NULL)
    {
      struct twist_h3_stream *next = s->next;

      free (s);
      s = next;
    }
  free (h);
}

static void
h3_fail (struct twist_h3 *h, int err)
{
  h->failed = 1;
  if (h->ev.failure != NULL)
    h->ev.failure (h->ev.user, err);
}

static void
on_frame (struct twist_h3 *h, uint64_t type, const uint8_t *p, size_t len)
{
  if (type == H3_HEADERS)
    {
      if (take_stream (h) == NULL)
        {
          h3_fail (h, TWIST_ERR_NOMEM);
          return;
        }
      if (twist_qpack_decode (p, len, &h->ev) != TWIST_OK)
        h3_fail (h, TWIST_ERR_PROTOCOL);
      else if (h->ev.switching != NULL)
        h->ev.switching (h->ev.user);
      return;
    }
  if (type == H3_DATA)
    {
      if (take_stream (h) == NULL)
        {
          h3_fail (h, TWIST_ERR_NOMEM);
          return;
        }
      if (h->ev.body != NULL && len > 0)
        h->ev.body (h->ev.user, p, len);
      return;
    }
  if (type == H3_SETTINGS)
    {
      if (h->ev.message_done != NULL)
        h->ev.message_done (h->ev.user);
      release_stream (h);
      return;
    }
  if (type == H3_GOAWAY)
    {
      release_stream (h);
      h3_fail (h, TWIST_ERR_PROTOCOL);
    }
}

size_t
twist_h3_receive (struct twist_h3 *h, const uint8_t *data, size_t len)
{
  size_t off = 0;

  if (h == NULL || h->failed)
    return 0;
  while (off < len && !h->failed)
    {
      size_t tn = 0;
      size_t ln = 0;
      uint64_t type = 0;
      uint64_t length = 0;

      /* A DATA frame can be of any size, and its bytes go on as they come; so
         can the payload of a frame that is passed over.  */
      if (h->data_left > 0 || h->skip_left > 0)
        {
          uint64_t *left = h->data_left > 0 ? &h->data_left : &h->skip_left;
          size_t n = len - off;

          if ((uint64_t) n > *left)
            n = (size_t) *left;
          if (left == &h->data_left && h->ev.body != NULL)
            h->ev.body (h->ev.user, data + off, n);
          *left -= n;
          off += n;
          continue;
        }
      if (!peek_varint (data + off, len - off, &tn, &type))
        break;
      if (!peek_varint (data + off + tn, len - off - tn, &ln, &length))
        break;
      if (type == H3_DATA)
        {
          if (take_stream (h) == NULL)
            {
              h3_fail (h, TWIST_ERR_NOMEM);
              break;
            }
          off += tn + ln;
          h->data_left = length;
          continue;
        }
      if (type != H3_HEADERS && type != H3_SETTINGS && type != H3_GOAWAY)
        {
          off += tn + ln;
          h->skip_left = length;
          continue;
        }
      if (length > H3_MAX_LEN)
        {
          h3_fail (h, TWIST_ERR_PROTOCOL);
          break;
        }
      if (len - off - tn - ln < length)
        break;
      on_frame (h, type, data + off + tn + ln, (size_t) length);
      off += tn + ln + (size_t) length;
    }
  return off;
}

static size_t
put_varint (uint8_t *buf, uint64_t v)
{
  if (v < 64)
    {
      buf[0] = (uint8_t) v;
      return 1;
    }
  if (v < 16384)
    {
      buf[0] = (uint8_t) (0x40 | (v >> 8));
      buf[1] = (uint8_t) v;
      return 2;
    }
  buf[0] = (uint8_t) (0x80 | (v >> 24));
  buf[1] = (uint8_t) (v >> 16);
  buf[2] = (uint8_t) (v >> 8);
  buf[3] = (uint8_t) v;
  return 4;
}

int
twist_h3_request (struct twist_h3 *h, const char *method, const char *scheme,
                  const char *authority, const char *path,
                  const struct twist_slist *extra, const uint8_t *body,
                  size_t body_len, uint8_t **out, size_t *out_len)
{
  uint8_t *block = NULL;
  size_t blen = 0;
  uint8_t *buf;
  size_t n = 0;
  size_t cap;
  size_t frames;
  int rc;

  (void) h;
  rc = twist_qpack_encode_request (method, scheme, authority, path, extra,
                                   &block, &blen);
  if (rc != TWIST_OK)
    return rc;
  if (blen > 0x3fffffff)
    {
      free (block);
      return TWIST_ERR_PROTOCOL;
    }
  frames = body_len == 0 ? 0 : (body_len / H3_FRAME) + 1;
  cap = 16 + blen + frames * 16 + body_len;
  buf = twist_xmalloc (cap);
  if (buf == NULL)
    {
      free (block);
      return TWIST_ERR_NOMEM;
    }
  buf[n++] = H3_HEADERS;
  n += put_varint (buf + n, blen);
  memcpy (buf + n, block, blen);
  n += blen;
  if (body != NULL && body_len > 0)
    {
      size_t off = 0;

      while (off < body_len)
        {
          size_t chunk = body_len - off;

          if (chunk > H3_FRAME)
            chunk = H3_FRAME;
          buf[n++] = H3_DATA;
          n += put_varint (buf + n, chunk);
          memcpy (buf + n, body + off, chunk);
          n += chunk;
          off += chunk;
        }
    }
  free (block);
  *out = buf;
  *out_len = n;
  return TWIST_OK;
}
