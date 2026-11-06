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

/* A BER/DER writer and a push reader for the tag-length-value encoding that
   LDAP and SPNEGO share.  Tags are one byte.  Lengths are definite and take
   at most three bytes.

   The writer encodes into a buffer the caller owns.  The reader is a state
   machine over a byte at a time, holding nothing but a fixed stack of open
   constructed elements and a scratch buffer the caller gives it for one
   primitive value, which is the most it will take.  */

/* ---- Writer ---- */

void
twist_der_writer_init (struct twist_der_writer *w, uint8_t *buf, size_t cap,
                       int der)
{
  w->buf = buf;
  w->cap = cap;
  w->n = 0;
  w->err = 0;
  w->der = der != 0;
}

static void
put (struct twist_der_writer *w, unsigned c)
{
  if (w->err || w->n >= w->cap)
    {
      w->err = 1;
      return;
    }
  w->buf[w->n++] = (uint8_t) c;
}

/* The shortest form of a length: one byte below 128, then 0x81, 0x82, 0x83
   with the length after.  A length of 16 MiB or more is not made.  */
static size_t
len_bytes (size_t len)
{
  if (len < 128)
    return 1;
  if (len < 256)
    return 2;
  if (len < 65536)
    return 3;
  return 4;
}

static void
len_encode (size_t len, uint8_t *out)
{
  switch (len_bytes (len))
    {
    case 1:
      out[0] = (uint8_t) len;
      break;
    case 2:
      out[0] = 0x81;
      out[1] = (uint8_t) len;
      break;
    case 3:
      out[0] = 0x82;
      out[1] = (uint8_t) (len >> 8);
      out[2] = (uint8_t) len;
      break;
    default:
      out[0] = 0x83;
      out[1] = (uint8_t) (len >> 16);
      out[2] = (uint8_t) (len >> 8);
      out[3] = (uint8_t) len;
      break;
    }
}

static void
put_len (struct twist_der_writer *w, size_t len)
{
  uint8_t b[4];
  size_t i, n;

  if (len >= (size_t) 1 << 24)
    {
      w->err = 1;
      return;
    }
  n = len_bytes (len);
  len_encode (len, b);
  for (i = 0; i < n; i++)
    put (w, b[i]);
}

void
twist_der_put (struct twist_der_writer *w, uint8_t tag, const void *data,
               size_t n)
{
  const uint8_t *p = data;
  size_t i;

  put (w, tag);
  put_len (w, n);
  if (w->err || n > w->cap - w->n)
    {
      w->err = 1;
      return;
    }
  for (i = 0; i < n; i++)
    w->buf[w->n++] = p[i];
}

void
twist_der_put_int (struct twist_der_writer *w, uint8_t tag, int v)
{
  unsigned u = (unsigned) v;
  uint8_t tmp[4];
  int start = 0;

  tmp[0] = (uint8_t) (u >> 24);
  tmp[1] = (uint8_t) (u >> 16);
  tmp[2] = (uint8_t) (u >> 8);
  tmp[3] = (uint8_t) u;
  while (start < 3
         && ((tmp[start] == 0 && (tmp[start + 1] & 0x80) == 0)
             || (tmp[start] == 0xff && (tmp[start + 1] & 0x80) != 0)))
    start++;
  twist_der_put (w, tag, tmp + start, (size_t) (4 - start));
}

/* A constructed element does not know its length until it is closed.  It
   reserves three length bytes (0x82 and two more).  Closing writes them in
   BER; in DER it writes the shortest form and moves the content back over
   what is saved, which only touches bytes after the mark.  */
size_t
twist_der_begin (struct twist_der_writer *w, uint8_t tag)
{
  size_t mark;

  put (w, tag);
  mark = w->n;
  put (w, 0x82);
  put (w, 0);
  put (w, 0);
  return mark;
}

void
twist_der_end (struct twist_der_writer *w, size_t mark)
{
  size_t len, n;
  uint8_t b[4];

  if (w->err || mark + 3 > w->n)
    {
      w->err = 1;
      return;
    }
  len = w->n - (mark + 3);
  if (len >= 65536)
    {
      w->err = 1;
      return;
    }
  if (!w->der)
    {
      w->buf[mark + 1] = (uint8_t) (len >> 8);
      w->buf[mark + 2] = (uint8_t) len;
      return;
    }
  n = len_bytes (len);
  len_encode (len, b);
  memmove (w->buf + mark + n, w->buf + mark + 3, len);
  memcpy (w->buf + mark, b, n);
  w->n = mark + n + len;
}

/* ---- Reader ---- */

enum
{
  ST_TAG,
  ST_LEN,
  ST_LLEN,
  ST_VAL
};

void
twist_der_reader_init (struct twist_der_reader *r,
                       const struct twist_der_events *ev, uint8_t *val,
                       size_t cap, int strict)
{
  memset (r, 0, sizeof *r);
  r->ev = ev;
  r->val = val;
  r->cap = cap;
  r->max_len = (size_t) 1 << 20;
  r->strict = strict != 0;
}

int
twist_der_idle (const struct twist_der_reader *r)
{
  return r->depth == 0 && r->st == ST_TAG && !r->failed;
}

/* Count N bytes against every open element.  A byte an element does not have
   room for is a protocol error.  */
static int
consume (struct twist_der_reader *r, size_t n)
{
  int i;

  for (i = 0; i < r->depth; i++)
    if (r->stk[i].left < n)
      return TWIST_ERR_PROTOCOL;
  for (i = 0; i < r->depth; i++)
    r->stk[i].left -= n;
  return TWIST_OK;
}

static int
open_value (struct twist_der_reader *r)
{
  int constructed = (r->tag & 0x20) != 0;

  if (r->len > r->max_len)
    return TWIST_ERR_PROTOCOL;
  if (r->depth > 0 && r->len > r->stk[r->depth - 1].left)
    return TWIST_ERR_PROTOCOL;
  if (constructed)
    {
      if (r->depth >= TWIST_DER_DEPTH)
        return TWIST_ERR_PROTOCOL;
      r->stk[r->depth].tag = r->tag;
      r->stk[r->depth].left = r->len;
      r->depth++;
      r->st = ST_TAG;
      return r->ev->start != NULL ? r->ev->start (r->ev->user, r->tag, r->len)
                                  : TWIST_OK;
    }
  if (r->len > r->cap)
    return TWIST_ERR_PROTOCOL;
  r->got = 0;
  if (r->len == 0)
    {
      r->st = ST_TAG;
      return r->ev->prim != NULL
        ? r->ev->prim (r->ev->user, r->tag, r->val, 0) : TWIST_OK;
    }
  r->st = ST_VAL;
  return TWIST_OK;
}

static int
pop_done (struct twist_der_reader *r)
{
  while (r->depth > 0 && r->stk[r->depth - 1].left == 0)
    {
      uint8_t tag;
      int rc;

      if (r->st != ST_TAG)
        return TWIST_ERR_PROTOCOL;
      tag = r->stk[r->depth - 1].tag;
      r->depth--;
      rc = r->ev->end != NULL ? r->ev->end (r->ev->user, tag) : TWIST_OK;
      if (rc != TWIST_OK)
        return rc;
    }
  return TWIST_OK;
}

static int
header_byte (struct twist_der_reader *r, uint8_t c)
{
  switch (r->st)
    {
    case ST_TAG:
      /* A tag number of 31 or more continues in further bytes; none of the
         protocols here uses one.  */
      if (r->strict && (c & 0x1f) == 0x1f)
        return TWIST_ERR_PROTOCOL;
      r->tag = c;
      r->st = ST_LEN;
      return TWIST_OK;
    case ST_LEN:
      if ((c & 0x80) != 0)
        {
          /* 0x80 is the indefinite form, which is refused in both modes.  */
          r->len_left = c & 0x7f;
          if (r->len_left == 0 || r->len_left > 3)
            return TWIST_ERR_PROTOCOL;
          r->len = 0;
          r->len_first = 1;
          r->st = ST_LLEN;
          return TWIST_OK;
        }
      r->len = c;
      return open_value (r);
    default:			/* ST_LLEN */
      if (r->strict && r->len_first && c == 0)
        return TWIST_ERR_PROTOCOL;
      r->len_first = 0;
      r->len = (r->len << 8) | c;
      r->len_left--;
      if (r->len_left > 0)
        return TWIST_OK;
      if (r->strict && r->len < 128)
        return TWIST_ERR_PROTOCOL;
      return open_value (r);
    }
}

size_t
twist_der_receive (struct twist_der_reader *r, const uint8_t *data, size_t len)
{
  size_t off = 0;
  int rc = TWIST_OK;

  if (r->failed)
    return len;
  if (r->stopped)
    return 0;
  while (off < len)
    {
      if (r->st == ST_VAL)
        {
          size_t n = r->len - r->got;

          if (n > len - off)
            n = len - off;
          rc = consume (r, n);
          if (rc != TWIST_OK)
            break;
          memcpy (r->val + r->got, data + off, n);
          r->got += n;
          off += n;
          if (r->got == r->len)
            {
              r->st = ST_TAG;
              rc = r->ev->prim != NULL
                ? r->ev->prim (r->ev->user, r->tag, r->val, r->got)
                : TWIST_OK;
              if (rc == TWIST_OK)
                rc = pop_done (r);
            }
        }
      else
        {
          rc = consume (r, 1);
          if (rc != TWIST_OK)
            break;
          rc = header_byte (r, data[off]);
          off++;
          if (rc == TWIST_OK)
            rc = pop_done (r);
        }
      if (rc != TWIST_OK)
        break;
    }
  if (rc == TWIST_DER_STOP)
    {
      r->stopped = 1;
      return off;
    }
  if (rc != TWIST_OK)
    {
      r->failed = 1;
      if (r->ev->failure != NULL)
        r->ev->failure (r->ev->user, rc);
      return len;
    }
  return off;
}
