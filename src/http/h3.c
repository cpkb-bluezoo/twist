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

int twist_qpack_decode (const uint8_t *data, size_t len,
                        struct twist_h1_events *ev);
int twist_qpack_encode_request (const char *method, const char *scheme,
                                const char *authority, const char *path,
                                const struct twist_slist *extra,
                                uint8_t **out, size_t *out_len);

struct twist_h3
{
  struct twist_h1_events ev;
  int phase;
  uint64_t type;
  uint64_t length;
  uint64_t got;
  int type_shift;
  int len_shift;
  int saw_type;
  uint8_t *payload;
  size_t payload_len;
  int failed;
};

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
  if (h == NULL)
    return;
  free (h->payload);
  free (h);
}

static int
take_varint (struct twist_h3 *h, const uint8_t *data, size_t len, size_t *off,
             uint64_t *acc, int *shift, int *done)
{
  while (*off < len && !*done)
    {
      uint8_t b = data[(*off)++];
      if (*shift == 0)
        {
          unsigned prefix = 1u << (b >> 6);
          *acc = b & 0x3fu;
          if (prefix == 1)
            {
              *done = 1;
              return 1;
            }
          *shift = 6;
          h->got = 1;
          h->length = prefix;
          continue;
        }
      *acc = (*acc << 8) | b;
      h->got++;
      if (h->got == h->length)
        {
          *done = 1;
          *shift = 0;
          return 1;
        }
    }
  return 0;
}

size_t
twist_h3_receive (struct twist_h3 *h, const uint8_t *data, size_t len)
{
  size_t off = 0;

  if (h->failed)
    return 0;
  while (off < len && !h->failed)
    {
      if (h->phase == 0)
        {
          int done = 0;
          if (!take_varint (h, data, len, &off, &h->type, &h->type_shift, &done))
            break;
          h->phase = 1;
          h->len_shift = 0;
          h->got = 0;
        }
      if (h->phase == 1)
        {
          int done = 0;
          if (!take_varint (h, data, len, &off, &h->length, &h->len_shift,
                            &done))
            break;
          if (h->length > 65536)
            {
              h->failed = 1;
              if (h->ev.failure != NULL)
                h->ev.failure (h->ev.user, TWIST_ERR_PROTOCOL);
              break;
            }
          free (h->payload);
          h->payload = h->length ? twist_xmalloc ((size_t) h->length) : NULL;
          h->payload_len = 0;
          h->phase = 2;
          if (h->length > 0 && h->payload == NULL)
            {
              h->failed = 1;
              break;
            }
        }
      if (h->phase == 2)
        {
          size_t n = (size_t) h->length - h->payload_len;
          if (n > len - off)
            n = len - off;
          if (n > 0)
            memcpy (h->payload + h->payload_len, data + off, n);
          h->payload_len += n;
          off += n;
          if (h->payload_len < h->length)
            break;
          if (h->type == 0x1)
            {
              if (twist_qpack_decode (h->payload, h->payload_len, &h->ev)
                  != TWIST_OK && h->ev.failure != NULL)
                h->ev.failure (h->ev.user, TWIST_ERR_PROTOCOL);
            }
          else if (h->type == 0x0 && h->ev.body != NULL)
            h->ev.body (h->ev.user, h->payload, h->payload_len);
          else if (h->type == 0x4 && h->ev.message_done != NULL)
            h->ev.message_done (h->ev.user);
          if (h->type == 0x0)
            {
              /* A DATA frame does not by itself end the message.  */
            }
          h->phase = 0;
          h->type_shift = 0;
          h->got = 0;
        }
    }
  return off;
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
  int rc;
  (void) h;

  rc = twist_qpack_encode_request (method, scheme, authority, path, extra,
                                   &block, &blen);
  if (rc != TWIST_OK)
    return rc;
  buf = twist_xmalloc (8 + blen + 8 + body_len);
  if (buf == NULL)
    {
      free (block);
      return TWIST_ERR_NOMEM;
    }
  buf[n++] = 0x01;
  buf[n++] = (uint8_t) blen;
  memcpy (buf + n, block, blen);
  n += blen;
  if (body != NULL && body_len > 0)
    {
      buf[n++] = 0x00;
      buf[n++] = (uint8_t) body_len;
      memcpy (buf + n, body, body_len);
      n += body_len;
    }
  free (block);
  *out = buf;
  *out_len = n;
  return TWIST_OK;
}
