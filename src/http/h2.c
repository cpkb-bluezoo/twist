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
#define H2_PRIORITY 2
#define H2_RST 3
#define H2_SETTINGS 4
#define H2_PUSH 5
#define H2_PING 6
#define H2_GOAWAY 7
#define H2_WINDOW 8
#define H2_CONTINUATION 9
#define H2_END_STREAM 0x1
#define H2_END_HEADERS 0x4
#define H2_PADDED 0x8
#define H2_PRIORITY_FLAG 0x20
#define H2_ACK 0x1
#define H2_FRAME 16384u
#define H2_HEADER_CAP 8192u
#define H2_MAX_STREAMS 100u
#define H2_CONN_TARGET (1 << 20)
#define H2_STREAM_TARGET (256 << 10)

static const char preface[] = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

struct twist_h2_stream
{
  uint32_t id;
  int live;
  uint8_t *block;
  size_t block_len;
  size_t block_cap;
  int32_t recv_left;
  int32_t send_left;
  struct twist_h1_events ev;
  int have_ev;
  struct twist_h2_stream *next;
};

struct twist_h2
{
  struct twist_h1_events ev;
  struct twist_hpack *hp;
  int (*emit) (void *, const uint8_t *, size_t);
  void *emit_user;
  int32_t conn_recv;
  int32_t conn_send;
  int32_t peer_init;
  uint32_t max_frame;
  uint32_t cont_stream;
  uint32_t next_id;
  uint32_t peer_max;
  /* Streams the client has opened and ended its side of, and that the server
     has not yet ended: a response is to come on each.  The only streams, with
     the live ones, that frames may arrive on.  */
  struct
  {
    uint32_t id;
    /* Who the response is for, when it is not the connection's one user.  */
    int have_ev;
    struct twist_h1_events ev;
  } waiting[H2_MAX_STREAMS];
  size_t n_waiting;
  int failed;
  struct twist_h2_stream *active;
  struct twist_h2_stream *free_list;
  size_t n_alloc;
  const uint8_t *pending;
  size_t pending_len;
  uint32_t pending_id;
  int pending_end;
  int hold;			/* A body is being sent: nothing else begins.  */
  struct twist_h1_events next_ev;
  int have_next;
  void (*writable) (void *);
  void *writable_user;
};

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

static int
waiting_has (const struct twist_h2 *h, uint32_t id)
{
  size_t i;

  for (i = 0; i < h->n_waiting; i++)
    if (h->waiting[i].id == id)
      return 1;
  return 0;
}

/* Wait for the response to ID, which is for the owner S had, if it had one:
   the stream's record is let go when its request is sent, and made again
   when the response comes, and must then be given the owner again.  */
static void
waiting_add (struct twist_h2 *h, uint32_t id, const struct twist_h2_stream *s)
{
  if (h->n_waiting < H2_MAX_STREAMS && !waiting_has (h, id))
    {
      h->waiting[h->n_waiting].id = id;
      h->waiting[h->n_waiting].have_ev = s != NULL && s->have_ev;
      if (h->waiting[h->n_waiting].have_ev)
        h->waiting[h->n_waiting].ev = s->ev;
      h->n_waiting++;
    }
}

/* Stop waiting for ID.  If there was an owner for it, *HAVE is true and *EV
   is it.  */
static void
waiting_take (struct twist_h2 *h, uint32_t id, int *have,
              struct twist_h1_events *ev)
{
  size_t i;

  if (have != NULL)
    *have = 0;
  for (i = 0; i < h->n_waiting; i++)
    if (h->waiting[i].id == id)
      {
        if (have != NULL && h->waiting[i].have_ev)
          {
            *have = 1;
            *ev = h->waiting[i].ev;
          }
        h->waiting[i] = h->waiting[--h->n_waiting];
        return;
      }
}

static void
waiting_drop (struct twist_h2 *h, uint32_t id)
{
  waiting_take (h, id, NULL, NULL);
}

static void
h2_fail (struct twist_h2 *h, int err)
{
  struct twist_h2_stream *s;
  size_t i;

  h->failed = 1;
  if (h->ev.failure != NULL && h->ev.user != NULL)
    h->ev.failure (h->ev.user, err);
  for (s = h->active; s != NULL; s = s->next)
    if (s->have_ev && s->ev.failure != NULL && s->ev.user != NULL
        && s->ev.user != h->ev.user)
      s->ev.failure (s->ev.user, err);
  for (i = 0; i < h->n_waiting; i++)
    if (h->waiting[i].have_ev && h->waiting[i].ev.failure != NULL
        && h->waiting[i].ev.user != NULL
        && h->waiting[i].ev.user != h->ev.user)
      h->waiting[i].ev.failure (h->waiting[i].ev.user, err);
}

static int
emit_bytes (struct twist_h2 *h, const uint8_t *p, size_t n)
{
  if (h->emit == NULL || n == 0)
    return TWIST_OK;
  return h->emit (h->emit_user, p, n);
}

static void
emit_window (struct twist_h2 *h, uint32_t stream, uint32_t inc)
{
  uint8_t buf[13];

  if (inc == 0 || h->failed)
    return;
  frame_hdr (buf, 4, H2_WINDOW, 0, stream);
  buf[9] = (uint8_t) (inc >> 24);
  buf[10] = (uint8_t) (inc >> 16);
  buf[11] = (uint8_t) (inc >> 8);
  buf[12] = (uint8_t) inc;
  if (emit_bytes (h, buf, sizeof buf) != TWIST_OK)
    h2_fail (h, TWIST_ERR_CONNECT);
}

static void
emit_settings_ack (struct twist_h2 *h)
{
  uint8_t buf[9];

  frame_hdr (buf, 0, H2_SETTINGS, H2_ACK, 0);
  if (emit_bytes (h, buf, sizeof buf) != TWIST_OK)
    h2_fail (h, TWIST_ERR_CONNECT);
}

static void
emit_ping_ack (struct twist_h2 *h, const uint8_t *payload)
{
  uint8_t buf[17];

  frame_hdr (buf, 8, H2_PING, H2_ACK, 0);
  memcpy (buf + 9, payload, 8);
  if (emit_bytes (h, buf, sizeof buf) != TWIST_OK)
    h2_fail (h, TWIST_ERR_CONNECT);
}

static struct twist_h1_events *
stream_ev (struct twist_h2 *h, struct twist_h2_stream *s)
{
  if (s != NULL && s->have_ev)
    return &s->ev;
  return &h->ev;
}

static struct twist_h2_stream *
find_stream (struct twist_h2 *h, uint32_t id)
{
  struct twist_h2_stream *s;

  for (s = h->active; s != NULL; s = s->next)
    if (s->id == id && s->live)
      return s;
  return NULL;
}

static struct twist_h2_stream *
take_stream (struct twist_h2 *h, uint32_t id)
{
  struct twist_h2_stream *s;
  size_t live = 0;

  s = find_stream (h, id);
  if (s != NULL)
    return s;
  for (s = h->active; s != NULL; s = s->next)
    if (s->live)
      live++;
  /* The streams that are waiting for a response are streams in use, to the
     server's limit and to ours.  */
  live += h->n_waiting;
  if (h->peer_max != 0 && live >= h->peer_max)
    return NULL;
  if (live >= H2_MAX_STREAMS)
    return NULL;
  if (h->free_list != NULL)
    {
      s = h->free_list;
      h->free_list = s->next;
      s->block_len = 0;
    }
  else
    {
      if (h->n_alloc >= H2_MAX_STREAMS)
        return NULL;
      s = calloc (1, sizeof *s);
      if (s == NULL)
        return NULL;
      h->n_alloc++;
    }
  s->id = id;
  s->live = 1;
  s->recv_left = H2_STREAM_TARGET;
  s->send_left = h->peer_init;
  if (h->have_next)
    {
      s->ev = h->next_ev;
      s->have_ev = 1;
      h->have_next = 0;
    }
  else
    s->have_ev = 0;
  s->next = h->active;
  h->active = s;
  return s;
}

static void
release_stream (struct twist_h2 *h, struct twist_h2_stream *s)
{
  struct twist_h2_stream **pp;

  if (s == NULL || !s->live)
    return;
  for (pp = &h->active; *pp != NULL; pp = &(*pp)->next)
    if (*pp == s)
      {
        *pp = s->next;
        break;
      }
  s->live = 0;
  s->id = 0;
  s->block_len = 0;
  s->next = h->free_list;
  h->free_list = s;
}

static void
free_stream_list (struct twist_h2_stream *s)
{
  while (s != NULL)
    {
      struct twist_h2_stream *next = s->next;

      free (s->block);
      free (s);
      s = next;
    }
}

struct twist_h2 *
twist_h2_new (const struct twist_h1_events *ev)
{
  struct twist_h2 *h = calloc (1, sizeof *h);

  if (h == NULL)
    return NULL;
  if (ev != NULL)
    h->ev = *ev;
  h->hp = twist_hpack_new ();
  h->conn_recv = H2_CONN_TARGET;
  h->conn_send = 65535;
  h->peer_init = 65535;
  h->max_frame = H2_FRAME;
  h->next_id = 1;
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
  free_stream_list (h->active);
  free_stream_list (h->free_list);
  free (h);
}

void
twist_h2_set_emit (struct twist_h2 *h,
                   int (*emit) (void *, const uint8_t *, size_t), void *user)
{
  if (h == NULL)
    return;
  h->emit = emit;
  h->emit_user = user;
}

int
twist_h2_can_open (const struct twist_h2 *h)
{
  const struct twist_h2_stream *s;
  size_t live = 0;

  if (h == NULL || h->failed || h->pending != NULL || h->hold)
    return 0;
  for (s = h->active; s != NULL; s = s->next)
    if (s->live)
      live++;
  live += h->n_waiting;
  if (h->peer_max != 0 && live >= h->peer_max)
    return 0;
  if (live >= H2_MAX_STREAMS)
    return 0;
  if (h->free_list == NULL && h->n_alloc >= H2_MAX_STREAMS)
    return 0;
  return 1;
}

void
twist_h2_set_next_owner (struct twist_h2 *h, const struct twist_h1_events *ev)
{
  if (h == NULL)
    return;
  if (ev == NULL)
    {
      h->have_next = 0;
      return;
    }
  h->next_ev = *ev;
  h->have_next = 1;
}

void
twist_h2_drop_user (struct twist_h2 *h, void *user)
{
  struct twist_h2_stream *s;
  size_t i;

  if (h == NULL || user == NULL)
    return;
  if (h->ev.user == user)
    {
      h->ev.user = NULL;
      h->ev.failure = NULL;
      h->ev.body = NULL;
      h->ev.header = NULL;
      h->ev.message_done = NULL;
      h->ev.switching = NULL;
    }
  for (s = h->active; s != NULL; s = s->next)
    if (s->have_ev && s->ev.user == user)
      s->have_ev = 0;
  for (i = 0; i < h->n_waiting; i++)
    if (h->waiting[i].have_ev && h->waiting[i].ev.user == user)
      h->waiting[i].have_ev = 0;
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

int
twist_h2_preface (uint8_t **out, size_t *out_len)
{
  static const uint8_t settings[] = {
    0x00, 0x02, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x04, 0x00, 0x04, 0x00, 0x00
  };
  uint32_t inc = H2_CONN_TARGET - 65535u;
  uint8_t *buf = twist_xmalloc (24 + 9 + sizeof settings + 13);

  if (buf == NULL)
    return TWIST_ERR_NOMEM;
  memcpy (buf, preface, 24);
  frame_hdr (buf + 24, (uint32_t) sizeof settings, H2_SETTINGS, 0, 0);
  memcpy (buf + 33, settings, sizeof settings);
  frame_hdr (buf + 33 + sizeof settings, 4, H2_WINDOW, 0, 0);
  buf[33 + sizeof settings + 9] = (uint8_t) (inc >> 24);
  buf[33 + sizeof settings + 10] = (uint8_t) (inc >> 16);
  buf[33 + sizeof settings + 11] = (uint8_t) (inc >> 8);
  buf[33 + sizeof settings + 12] = (uint8_t) inc;
  *out = buf;
  *out_len = 24 + 9 + sizeof settings + 13;
  return TWIST_OK;
}

static int
append_block (struct twist_h2_stream *s, const uint8_t *p, size_t n)
{
  if (n == 0)
    return TWIST_OK;
  if (s->block_len + n > H2_HEADER_CAP)
    return TWIST_ERR_PROTOCOL;
  if (s->block_len + n > s->block_cap)
    {
      size_t cap = s->block_cap == 0 ? 256 : s->block_cap;
      uint8_t *grown;

      while (cap < s->block_len + n)
        cap *= 2;
      if (cap > H2_HEADER_CAP)
        cap = H2_HEADER_CAP;
      grown = realloc (s->block, cap);
      if (grown == NULL)
        return TWIST_ERR_NOMEM;
      s->block = grown;
      s->block_cap = cap;
    }
  memcpy (s->block + s->block_len, p, n);
  s->block_len += n;
  return TWIST_OK;
}

static const uint8_t *
frame_body (uint8_t type, uint8_t flags, const uint8_t *p, size_t len,
            size_t *out)
{
  size_t off = 0;
  size_t pad = 0;

  if ((flags & H2_PADDED) != 0
      && (type == H2_DATA || type == H2_HEADERS || type == H2_PUSH
          || type == H2_CONTINUATION))
    {
      if (len < 1)
        return NULL;
      pad = p[0];
      off = 1;
    }
  if (type == H2_HEADERS && (flags & H2_PRIORITY_FLAG) != 0)
    {
      if (len < off + 5)
        return NULL;
      off += 5;
    }
  if (off + pad > len)
    return NULL;
  *out = len - off - pad;
  return p + off;
}

static void
note_recv (struct twist_h2 *h, struct twist_h2_stream *s, size_t n)
{
  int32_t half_c = H2_CONN_TARGET / 2;
  int32_t half_s = H2_STREAM_TARGET / 2;

  if (n == 0)
    return;
  if ((int32_t) n > h->conn_recv || (s != NULL && (int32_t) n > s->recv_left))
    {
      h2_fail (h, TWIST_ERR_PROTOCOL);
      return;
    }
  h->conn_recv -= (int32_t) n;
  if (h->conn_recv <= half_c)
    {
      uint32_t inc = (uint32_t) (H2_CONN_TARGET - h->conn_recv);

      h->conn_recv = H2_CONN_TARGET;
      emit_window (h, 0, inc);
    }
  if (s == NULL)
    return;
  s->recv_left -= (int32_t) n;
  if (s->recv_left <= half_s)
    {
      uint32_t inc = (uint32_t) (H2_STREAM_TARGET - s->recv_left);

      s->recv_left = H2_STREAM_TARGET;
      emit_window (h, s->id, inc);
    }
}

static void
flush_pending (struct twist_h2 *h)
{
  struct twist_h2_stream *s;

  if (h->pending == NULL || h->failed)
    return;
  s = find_stream (h, h->pending_id);
  if (s == NULL)
    return;
  while (h->pending_len > 0 && h->conn_send > 0 && s->send_left > 0)
    {
      size_t n = h->pending_len;
      uint8_t hdr[9];
      int end;

      if (n > h->max_frame)
        n = h->max_frame;
      if (n > (size_t) h->conn_send)
        n = (size_t) h->conn_send;
      if (n > (size_t) s->send_left)
        n = (size_t) s->send_left;
      end = h->pending_end && n == h->pending_len;
      frame_hdr (hdr, (uint32_t) n, H2_DATA, end ? H2_END_STREAM : 0,
                 h->pending_id);
      if (emit_bytes (h, hdr, sizeof hdr) != TWIST_OK
          || emit_bytes (h, h->pending, n) != TWIST_OK)
        {
          h2_fail (h, TWIST_ERR_CONNECT);
          return;
        }
      h->conn_send -= (int32_t) n;
      s->send_left -= (int32_t) n;
      h->pending += n;
      h->pending_len -= n;
    }
  if (h->pending_len == 0)
    h->pending = NULL;
}

static void
on_settings (struct twist_h2 *h, const uint8_t *p, size_t len)
{
  size_t off = 0;

  if ((len % 6) != 0)
    {
      h2_fail (h, TWIST_ERR_PROTOCOL);
      return;
    }
  while (off + 6 <= len)
    {
      uint16_t id = (uint16_t) ((p[off] << 8) | p[off + 1]);
      uint32_t val = ((uint32_t) p[off + 2] << 24)
        | ((uint32_t) p[off + 3] << 16)
        | ((uint32_t) p[off + 4] << 8) | p[off + 5];

      off += 6;
      if (id == 3)
        h->peer_max = val;
      else if (id == 4)
        {
          int64_t delta;
          struct twist_h2_stream *s;

          /* A window is a number of 31 bits (RFC 7540, 6.5.2); more is a flow
             control error, and a number that wraps.  */
          if (val > 0x7fffffffu)
            {
              h2_fail (h, TWIST_ERR_PROTOCOL);
              return;
            }
          delta = (int64_t) val - h->peer_init;
          for (s = h->active; s != NULL; s = s->next)
            if (s->live)
              {
                /* A window may be below zero after this, and it may not be
                   above the largest there is.  */
                int64_t now = (int64_t) s->send_left + delta;

                if (now > 0x7fffffff || now < -(int64_t) 0x7fffffff - 1)
                  {
                    h2_fail (h, TWIST_ERR_PROTOCOL);
                    return;
                  }
                s->send_left = (int32_t) now;
              }
          h->peer_init = (int32_t) val;
          if (h->writable != NULL && delta > 0)
            h->writable (h->writable_user);
        }
      else if (id == 5)
        {
          if (val < 16384 || val > 16777215)
            {
              h2_fail (h, TWIST_ERR_PROTOCOL);
              return;
            }
          h->max_frame = val;
        }
    }
  emit_settings_ack (h);
}

/* The stream a HEADERS or DATA frame is for.  Only a stream the client opened
   and the server has not ended: one that is live, or that was opened and ended
   on our side and is waiting for its response, which is then given a record.
   A stream is not made for any number the peer names: a proxy that sent
   frames on a stream of its own would have them taken for part of the
   tunnel, and data after a stream has ended would be delivered again.
   Anything else is a connection error (RFC 9113, section 5.1), and NULL.  */
static struct twist_h2_stream *
incoming_stream (struct twist_h2 *h, uint32_t id)
{
  struct twist_h2_stream *s = find_stream (h, id);
  struct twist_h1_events ev;
  int have;

  if (s != NULL)
    return s;
  if ((id & 1) == 0 || id >= h->next_id || !waiting_has (h, id))
    {
      h2_fail (h, TWIST_ERR_PROTOCOL);
      return NULL;
    }
  waiting_take (h, id, &have, &ev);
  s = take_stream (h, id);
  if (s == NULL)
    h2_fail (h, TWIST_ERR_NOMEM);
  else if (have)
    {
      s->ev = ev;
      s->have_ev = 1;
    }
  return s;
}

static void
on_headers (struct twist_h2 *h, uint32_t stream, uint8_t flags,
            const uint8_t *p, size_t len)
{
  struct twist_h2_stream *s;
  size_t n = 0;
  const uint8_t *body;
  int rc;

  if (h->cont_stream != 0 && h->cont_stream != stream)
    {
      h2_fail (h, TWIST_ERR_PROTOCOL);
      return;
    }
  s = incoming_stream (h, stream);
  if (s == NULL)
    return;
  body = frame_body (H2_HEADERS, flags, p, len, &n);
  if (body == NULL)
    {
      h2_fail (h, TWIST_ERR_PROTOCOL);
      return;
    }
  rc = append_block (s, body, n);
  if (rc != TWIST_OK)
    {
      h2_fail (h, rc);
      return;
    }
  if ((flags & H2_END_HEADERS) == 0)
    {
      h->cont_stream = stream;
      return;
    }
  h->cont_stream = 0;
  {
    struct twist_h1_events *ev = stream_ev (h, s);

    if (twist_hpack_decode (h->hp, s->block, s->block_len, ev) != TWIST_OK)
      {
        h2_fail (h, TWIST_ERR_PROTOCOL);
        return;
      }
    s->block_len = 0;
    if ((flags & H2_END_STREAM) != 0)
      {
        if (ev->message_done != NULL)
          ev->message_done (ev->user);
        release_stream (h, s);
      }
    else if (ev->switching != NULL)
      ev->switching (ev->user);
  }
}

static void
dispatch_frame (struct twist_h2 *h, uint8_t type, uint8_t flags,
                uint32_t stream, const uint8_t *p, size_t len)
{
  if (h->cont_stream != 0
      && !(type == H2_CONTINUATION && stream == h->cont_stream))
    {
      h2_fail (h, TWIST_ERR_PROTOCOL);
      return;
    }
  if (type == H2_SETTINGS)
    {
      if (stream != 0)
        {
          h2_fail (h, TWIST_ERR_PROTOCOL);
          return;
        }
      if ((flags & H2_ACK) == 0)
        on_settings (h, p, len);
      else if (len != 0)
        h2_fail (h, TWIST_ERR_PROTOCOL);
      return;
    }
  if (type == H2_PING)
    {
      if (len != 8 || stream != 0)
        {
          h2_fail (h, TWIST_ERR_PROTOCOL);
          return;
        }
      if ((flags & H2_ACK) == 0)
        emit_ping_ack (h, p);
      return;
    }
  if (type == H2_WINDOW && len == 4)
    {
      uint32_t inc = ((uint32_t) p[0] << 24) | ((uint32_t) p[1] << 16)
        | ((uint32_t) p[2] << 8) | p[3];
      struct twist_h2_stream *s;

      inc &= 0x7fffffffu;
      if (stream == 0)
        {
          /* In 64 bits: a window below zero would overflow the difference.  */
          if ((int64_t) h->conn_send + (int64_t) inc > 0x7fffffff)
            {
              h2_fail (h, TWIST_ERR_PROTOCOL);
              return;
            }
          h->conn_send += (int32_t) inc;
        }
      else
        {
          s = find_stream (h, stream);
          if (s != NULL)
            {
              if ((int64_t) s->send_left + (int64_t) inc > 0x7fffffff)
                {
                  h2_fail (h, TWIST_ERR_PROTOCOL);
                  return;
                }
              s->send_left += (int32_t) inc;
            }
        }
      flush_pending (h);
      if (h->writable != NULL && !h->failed)
        h->writable (h->writable_user);
      return;
    }
  if (type == H2_DATA)
    {
      struct twist_h2_stream *s = incoming_stream (h, stream);
      size_t n = 0;
      const uint8_t *body;

      if (s == NULL)
        return;
      body = frame_body (H2_DATA, flags, p, len, &n);
      if (body == NULL)
        {
          h2_fail (h, TWIST_ERR_PROTOCOL);
          return;
        }
      note_recv (h, s, n);
      if (h->failed)
        return;
      {
        struct twist_h1_events *ev = stream_ev (h, s);

        if (ev->body != NULL && n > 0)
          ev->body (ev->user, body, n);
        if ((flags & H2_END_STREAM) != 0)
          {
            if (ev->message_done != NULL)
              ev->message_done (ev->user);
            release_stream (h, s);
          }
      }
      return;
    }
  if (type == H2_HEADERS || type == H2_CONTINUATION)
    {
      on_headers (h, stream, flags, p, len);
      return;
    }
  if (type == H2_GOAWAY || type == H2_RST)
    {
      if (type == H2_RST)
        {
          release_stream (h, find_stream (h, stream));
          waiting_drop (h, stream);
        }
      h2_fail (h, TWIST_ERR_PROTOCOL);
      return;
    }
}

size_t
twist_h2_receive (struct twist_h2 *h, const uint8_t *data, size_t len)
{
  size_t off = 0;

  if (h == NULL || h->failed)
    return 0;
  while (off + 9 <= len && !h->failed)
    {
      uint32_t flen = ((uint32_t) data[off] << 16)
        | ((uint32_t) data[off + 1] << 8) | data[off + 2];
      uint8_t type = data[off + 3];
      uint8_t flags = data[off + 4];
      uint32_t stream = ((uint32_t) data[off + 5] << 24)
        | ((uint32_t) data[off + 6] << 16)
        | ((uint32_t) data[off + 7] << 8) | data[off + 8];

      stream &= 0x7fffffffu;
      if (flen > h->max_frame)
        {
          h2_fail (h, TWIST_ERR_PROTOCOL);
          break;
        }
      if (off + 9 + flen > len)
        break;
      dispatch_frame (h, type, flags, stream, data + off + 9, flen);
      off += 9 + flen;
    }
  return off;
}

static int
queue_data (uint8_t **buf, size_t *n, size_t *cap, const uint8_t *p, size_t len)
{
  if (*n + len > *cap)
    return TWIST_ERR_NOMEM;
  if (len > 0)
    memcpy (*buf + *n, p, len);
  *n += len;
  return TWIST_OK;
}

void
twist_h2_set_writable (struct twist_h2 *h, void (*cb) (void *), void *user)
{
  h->writable = cb;
  h->writable_user = user;
}

uint32_t
twist_h2_last_stream (const struct twist_h2 *h)
{
  return h != NULL && h->next_id > 1 ? h->next_id - 2 : 0;
}

size_t
twist_h2_send_data (struct twist_h2 *h, uint32_t id, const uint8_t *data,
                    size_t len, int end)
{
  struct twist_h2_stream *s;
  size_t sent = 0;
  uint8_t hdr[9];

  if (h == NULL || h->failed)
    return 0;
  s = find_stream (h, id);
  if (s == NULL)
    return 0;
  while (sent < len && h->conn_send > 0 && s->send_left > 0)
    {
      size_t n = len - sent;

      if (n > h->max_frame)
        n = h->max_frame;
      if (n > (size_t) h->conn_send)
        n = (size_t) h->conn_send;
      if (n > (size_t) s->send_left)
        n = (size_t) s->send_left;
      frame_hdr (hdr, (uint32_t) n, H2_DATA, 0, id);
      if (emit_bytes (h, hdr, sizeof hdr) != TWIST_OK
          || emit_bytes (h, data + sent, n) != TWIST_OK)
        {
          h2_fail (h, TWIST_ERR_CONNECT);
          return sent;
        }
      h->conn_send -= (int32_t) n;
      s->send_left -= (int32_t) n;
      sent += n;
    }
  /* The end of the stream takes no window.  */
  if (end && sent == len)
    {
      frame_hdr (hdr, 0, H2_DATA, H2_END_STREAM, id);
      if (emit_bytes (h, hdr, sizeof hdr) != TWIST_OK)
        h2_fail (h, TWIST_ERR_CONNECT);
    }
  return sent;
}

size_t
twist_h2_send_body (struct twist_h2 *h, uint32_t id, const uint8_t *data,
                    size_t len, int end)
{
  struct twist_h2_stream *s;
  size_t sent;

  if (h == NULL || h->failed)
    return (size_t) -1;
  s = find_stream (h, id);
  if (s == NULL)
    return (size_t) -1;
  sent = twist_h2_send_data (h, id, data, len, 0);
  if (h->failed)
    return (size_t) -1;
  if (end && sent == len)
    {
      uint8_t hdr[9];

      /* The request is whole; the response is what is waited for.  */
      frame_hdr (hdr, 0, H2_DATA, H2_END_STREAM, id);
      if (emit_bytes (h, hdr, sizeof hdr) != TWIST_OK)
        {
          h2_fail (h, TWIST_ERR_CONNECT);
          return (size_t) -1;
        }
      waiting_add (h, id, s);
      release_stream (h, s);
    }
  return sent;
}

void
twist_h2_hold (struct twist_h2 *h, int hold)
{
  if (h != NULL)
    h->hold = hold;
}

void
twist_h2_cancel (struct twist_h2 *h, uint32_t id)
{
  struct twist_h2_stream *s;
  uint8_t buf[13];

  if (h == NULL || h->failed)
    return;
  s = find_stream (h, id);
  if (s == NULL && !waiting_has (h, id))
    return;
  /* CANCEL (8): the body is not going to be sent.  */
  frame_hdr (buf, 4, H2_RST, 0, id);
  buf[9] = buf[10] = buf[11] = 0;
  buf[12] = 8;
  if (emit_bytes (h, buf, sizeof buf) != TWIST_OK)
    h2_fail (h, TWIST_ERR_CONNECT);
  waiting_drop (h, id);
  release_stream (h, s);
}

int
twist_h2_request (struct twist_h2 *h, const char *method, const char *scheme,
                  const char *authority, const char *path,
                  const struct twist_slist *extra, const uint8_t *body,
                  size_t body_len, int keep_open, uint8_t **out,
                  size_t *out_len)
{
  uint8_t *block = NULL;
  size_t blen = 0;
  uint8_t *buf;
  size_t n = 0;
  size_t cap;
  size_t sent = 0;
  uint32_t id;
  struct twist_h2_stream *s;
  int rc;
  int headers_end;

  if (h == NULL)
    return TWIST_ERR_INVAL;
  if (h->pending != NULL || h->hold)
    return TWIST_ERR_AGAIN;
  rc = twist_hpack_encode_request (h->hp, method, scheme, authority, path,
                                   extra, &block, &blen);
  if (rc != TWIST_OK)
    return rc;
  id = h->next_id;
  s = take_stream (h, id);
  if (s == NULL)
    {
      free (block);
      return TWIST_ERR_NOMEM;
    }
  h->next_id += 2;
  headers_end = (body == NULL || body_len == 0) && !keep_open;
  cap = 9 + blen;
  if (body != NULL)
    {
      size_t room = body_len;
      size_t win = 0;

      if (h->conn_send > 0)
        win = (size_t) h->conn_send;
      if ((size_t) s->send_left < win)
        win = (size_t) s->send_left;
      if (room > win)
        room = win;
      cap += ((room / h->max_frame) + 1) * (9 + h->max_frame);
    }
  buf = twist_xmalloc (cap > 0 ? cap : 1);
  if (buf == NULL)
    {
      free (block);
      release_stream (h, s);
      return TWIST_ERR_NOMEM;
    }
  {
    uint8_t hdr[9];

    frame_hdr (hdr, (uint32_t) blen, H2_HEADERS,
               (uint8_t) (H2_END_HEADERS | (headers_end ? H2_END_STREAM : 0)),
               id);
    rc = queue_data (&buf, &n, &cap, hdr, 9);
    if (rc == TWIST_OK)
      rc = queue_data (&buf, &n, &cap, block, blen);
  }
  free (block);
  if (rc != TWIST_OK)
    {
      free (buf);
      return rc;
    }
  if (headers_end)
    {
      waiting_add (h, id, s);
      release_stream (h, s);
    }
  while (body != NULL && sent < body_len && h->conn_send > 0 && s->send_left > 0
         && s->live)
    {
      size_t chunk = body_len - sent;
      uint8_t hdr[9];
      int end;

      if (chunk > h->max_frame)
        chunk = h->max_frame;
      if (chunk > (size_t) h->conn_send)
        chunk = (size_t) h->conn_send;
      if (chunk > (size_t) s->send_left)
        chunk = (size_t) s->send_left;
      end = !keep_open && sent + chunk == body_len;
      frame_hdr (hdr, (uint32_t) chunk, H2_DATA, end ? H2_END_STREAM : 0, id);
      if (queue_data (&buf, &n, &cap, hdr, 9) != TWIST_OK
          || queue_data (&buf, &n, &cap, body + sent, chunk) != TWIST_OK)
        {
          free (buf);
          return TWIST_ERR_NOMEM;
        }
      h->conn_send -= (int32_t) chunk;
      s->send_left -= (int32_t) chunk;
      sent += chunk;
      if (end)
        {
          waiting_add (h, id, s);
          release_stream (h, s);
        }
    }
  if (body != NULL && sent < body_len)
    {
      h->pending = body + sent;
      h->pending_len = body_len - sent;
      h->pending_id = id;
      h->pending_end = !keep_open;
    }
  *out = buf;
  *out_len = n;
  return TWIST_OK;
}
