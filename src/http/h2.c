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

#define H2_DATA 0
#define H2_HEADERS 1
#define H2_RST 3
#define H2_SETTINGS 4
#define H2_PING 6
#define H2_GOAWAY 7
#define H2_WINDOW 8
#define H2_CONTINUATION 9
#define H2_END_STREAM 0x1
#define H2_END_HEADERS 0x4
#define H2_ACK 0x1

struct twist_h2
{
  struct twist_h1_events ev;
  struct twist_hpack *hp;
  int phase;                    /* 0 header, 1 payload */
  uint8_t hdr[9];
  size_t hdr_got;
  uint32_t length;
  uint8_t type;
  uint8_t flags;
  uint32_t stream;
  uint8_t *payload;
  size_t payload_got;
  uint8_t *block;
  size_t block_len;
  size_t block_cap;
  int32_t conn_window;
  int failed;
};

static const char preface[] = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

struct twist_h2 *
twist_h2_new (const struct twist_h1_events *ev)
{
  struct twist_h2 *h = calloc (1, sizeof *h);
  if (h == NULL)
    return NULL;
  if (ev != NULL)
    h->ev = *ev;
  h->hp = twist_hpack_new ();
  h->conn_window = 65535;
  if (h->hp == NULL)
    {
      free (h);
      return NULL;
    }
  return h;
}

void
twist_h2_free (struct twist_h2 *h)
{
  if (h == NULL)
    return;
  twist_hpack_free (h->hp);
  free (h->payload);
  free (h->block);
  free (h);
}

int
twist_h2_client_preface (uint8_t **out, size_t *len)
{
  uint8_t *buf = twist_xmalloc (sizeof preface - 1 + 9);
  if (buf == NULL)
    return TWIST_ERR_NOMEM;
  memcpy (buf, preface, sizeof preface - 1);
  memset (buf + sizeof preface - 1, 0, 9);
  buf[sizeof preface - 1 + 3] = H2_SETTINGS;
  *out = buf;
  *len = sizeof preface - 1 + 9;
  return TWIST_OK;
}

static void
h2_fail (struct twist_h2 *h, int err)
{
  h->failed = 1;
  if (h->ev.failure != NULL)
    h->ev.failure (h->ev.user, err);
}

static void
on_frame (struct twist_h2 *h)
{
  if (h->type == H2_SETTINGS && (h->flags & H2_ACK) == 0)
    return;
  if (h->type == H2_PING)
    return;
  if (h->type == H2_WINDOW && h->length == 4)
    {
      uint32_t inc = ((uint32_t) h->payload[0] << 24)
        | ((uint32_t) h->payload[1] << 16)
        | ((uint32_t) h->payload[2] << 8)
        | h->payload[3];
      inc &= 0x7fffffffu;
      if (h->stream == 0)
        h->conn_window += (int32_t) inc;
      return;
    }
  if (h->type == H2_DATA)
    {
      if (h->ev.body != NULL && h->length > 0)
        h->ev.body (h->ev.user, h->payload, h->length);
      if ((h->flags & H2_END_STREAM) && h->ev.message_done != NULL)
        h->ev.message_done (h->ev.user);
      return;
    }
  if (h->type == H2_HEADERS || h->type == H2_CONTINUATION)
    {
      if (h->block_len + h->length > h->block_cap)
        {
          size_t cap = h->block_cap == 0 ? 256 : h->block_cap;
          uint8_t *p;
          while (cap < h->block_len + h->length)
            cap *= 2;
          p = realloc (h->block, cap);
          if (p == NULL)
            {
              h2_fail (h, TWIST_ERR_NOMEM);
              return;
            }
          h->block = p;
          h->block_cap = cap;
        }
      if (h->length > 0)
        memcpy (h->block + h->block_len, h->payload, h->length);
      h->block_len += h->length;
      if (h->flags & H2_END_HEADERS)
        {
          if (twist_hpack_decode (h->hp, h->block, h->block_len, &h->ev)
              != TWIST_OK)
            {
              h2_fail (h, TWIST_ERR_PROTOCOL);
              return;
            }
          h->block_len = 0;
          if ((h->flags & H2_END_STREAM) && h->ev.message_done != NULL)
            h->ev.message_done (h->ev.user);
        }
      return;
    }
  if (h->type == H2_GOAWAY || h->type == H2_RST)
    h2_fail (h, TWIST_ERR_PROTOCOL);
}

size_t
twist_h2_receive (struct twist_h2 *h, const uint8_t *data, size_t len)
{
  size_t off = 0;

  if (h->failed)
    return 0;
  while (off < len && !h->failed)
    {
      if (h->phase == 0)
        {
          size_t n = 9 - h->hdr_got;
          if (n > len - off)
            n = len - off;
          memcpy (h->hdr + h->hdr_got, data + off, n);
          h->hdr_got += n;
          off += n;
          if (h->hdr_got < 9)
            break;
          h->length = ((uint32_t) h->hdr[0] << 16) | ((uint32_t) h->hdr[1] << 8)
            | h->hdr[2];
          h->type = h->hdr[3];
          h->flags = h->hdr[4];
          h->stream = ((uint32_t) h->hdr[5] << 24) | ((uint32_t) h->hdr[6] << 16)
            | ((uint32_t) h->hdr[7] << 8) | h->hdr[8];
          h->stream &= 0x7fffffffu;
          if (h->length > 16384)
            {
              h2_fail (h, TWIST_ERR_PROTOCOL);
              break;
            }
          free (h->payload);
          h->payload = NULL;
          h->payload_got = 0;
          if (h->length > 0)
            {
              h->payload = twist_xmalloc (h->length);
              if (h->payload == NULL)
                {
                  h2_fail (h, TWIST_ERR_NOMEM);
                  break;
                }
            }
          h->phase = 1;
          h->hdr_got = 0;
        }
      if (h->phase == 1)
        {
          size_t n = h->length - h->payload_got;
          if (n > len - off)
            n = len - off;
          if (n > 0 && h->payload != NULL)
            memcpy (h->payload + h->payload_got, data + off, n);
          h->payload_got += n;
          off += n;
          if (h->payload_got < h->length)
            break;
          on_frame (h);
          h->phase = 0;
        }
    }
  return off;
}

static void
put24 (uint8_t *p, uint32_t v)
{
  p[0] = (uint8_t) (v >> 16);
  p[1] = (uint8_t) (v >> 8);
  p[2] = (uint8_t) v;
}

static void
frame_hdr (uint8_t *p, uint32_t len, uint8_t type, uint8_t flags,
           uint32_t stream)
{
  put24 (p, len);
  p[3] = type;
  p[4] = flags;
  p[5] = (uint8_t) (stream >> 24);
  p[6] = (uint8_t) (stream >> 16);
  p[7] = (uint8_t) (stream >> 8);
  p[8] = (uint8_t) stream;
}

int
twist_h2_request (struct twist_h2 *h, const char *method, const char *scheme,
                  const char *authority, const char *path,
                  const struct twist_slist *extra, const uint8_t *body,
                  size_t body_len, uint8_t **out, size_t *out_len)
{
  uint8_t *block = NULL;
  size_t blen = 0;
  uint8_t *buf;
  size_t n;
  int rc;

  rc = twist_hpack_encode_request (h->hp, method, scheme, authority, path,
                                   extra, &block, &blen);
  if (rc != TWIST_OK)
    return rc;
  n = 9 + blen + (body != NULL ? 9 + body_len : 0);
  buf = twist_xmalloc (n);
  if (buf == NULL)
    {
      free (block);
      return TWIST_ERR_NOMEM;
    }
  frame_hdr (buf, (uint32_t) blen, H2_HEADERS,
             (uint8_t) (H2_END_HEADERS | (body == NULL ? H2_END_STREAM : 0)),
             1);
  memcpy (buf + 9, block, blen);
  if (body != NULL)
    {
      frame_hdr (buf + 9 + blen, (uint32_t) body_len, H2_DATA, H2_END_STREAM, 1);
      memcpy (buf + 18 + blen, body, body_len);
    }
  free (block);
  *out = buf;
  *out_len = n;
  return TWIST_OK;
}
