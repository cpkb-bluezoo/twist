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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Events become bytes in a fixed buffer and are handed to the sink as
   soon as the buffer fills.  A body chunk is not kept after the call
   returns.  Base64 keeps at most two leftover octets.  */

#define MIME_CAP 4096
#define MIME_MARK (MIME_CAP * 3 / 4)

struct twist_mime
{
  int (*sink) (void *user, const uint8_t *data, size_t len);
  void *user;
  uint8_t buf[MIME_CAP];
  size_t len;
  char boundary[24];
  int parts;
  int bol;
  int header;
  int b64;
  unsigned b64_acc;
  int b64_n;
  int b64_col;
  int err;
};

static int
flush (struct twist_mime *m, int force)
{
  if (m->err != TWIST_OK)
    return m->err;
  if (m->len == 0 || (m->len < MIME_MARK && !force))
    return TWIST_OK;
  if (m->sink (m->user, m->buf, m->len) != 0)
    {
      m->err = TWIST_ERR_ABORTED;
      return m->err;
    }
  m->len = 0;
  return TWIST_OK;
}

static int
emit (struct twist_mime *m, const void *data, size_t n)
{
  const uint8_t *p = data;
  size_t i;

  if (m->err != TWIST_OK)
    return m->err;
  for (i = 0; i < n; i++)
    {
      m->buf[m->len++] = p[i];
      m->bol = p[i] == '\n';
      if (m->len == MIME_CAP && flush (m, 1) != TWIST_OK)
        return m->err;
    }
  return flush (m, 0);
}

static int
emit_str (struct twist_mime *m, const char *s)
{
  return emit (m, s, strlen (s));
}

static int
bad_header (const char *s)
{
  return s == NULL || strchr (s, '\r') != NULL || strchr (s, '\n') != NULL;
}

struct twist_mime *
twist_mime_new (int (*sink) (void *, const uint8_t *, size_t), void *user)
{
  struct twist_mime *m;

  if (sink == NULL)
    return NULL;
  m = calloc (1, sizeof *m);
  if (m == NULL)
    return NULL;
  m->sink = sink;
  m->user = user;
  m->bol = 1;
  return m;
}

void
twist_mime_free (struct twist_mime *mime)
{
  free (mime);
}

int
twist_mime_begin (struct twist_mime *mime, const char *subtype)
{
  if (mime == NULL || subtype == NULL || bad_header (subtype))
    return TWIST_ERR_INVAL;
  memcpy (mime->boundary, "twist-mime-1", 13);
  (void) subtype;
  return TWIST_OK;
}

static int
b64_end (struct twist_mime *m)
{
  static const char tab[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  char out[4];
  unsigned v;
  int n;

  if (!m->b64)
    return TWIST_OK;
  n = m->b64_n;
  v = m->b64_acc;
  m->b64 = 0;
  m->b64_n = 0;
  m->b64_acc = 0;
  if (n == 0)
    return TWIST_OK;
  if (n == 1)
    v <<= 16;
  else
    v <<= 8;
  out[0] = tab[(v >> 18) & 63];
  out[1] = tab[(v >> 12) & 63];
  out[2] = n == 2 ? tab[(v >> 6) & 63] : '=';
  out[3] = '=';
  return emit (m, out, 4);
}

static int
close_headers (struct twist_mime *m)
{
  if (!m->header)
    return TWIST_OK;
  m->header = 0;
  return emit_str (m, "\r\n");
}

int
twist_mime_part (struct twist_mime *mime)
{
  char line[48];
  int n;

  if (mime == NULL || mime->boundary[0] == 0)
    return TWIST_ERR_INVAL;
  if (b64_end (mime) != TWIST_OK)
    return mime->err;
  if (mime->parts > 0 && !mime->bol)
    n = snprintf (line, sizeof line, "\r\n--%s\r\n", mime->boundary);
  else
    n = snprintf (line, sizeof line, "--%s\r\n", mime->boundary);
  if (n < 0 || emit (mime, line, (size_t) n) != TWIST_OK)
    return mime->err != TWIST_OK ? mime->err : TWIST_ERR_PROTOCOL;
  mime->parts++;
  mime->header = 1;
  return TWIST_OK;
}

int
twist_mime_header (struct twist_mime *mime, const char *name, const char *value)
{
  char line[256];
  int n;

  if (mime == NULL || !mime->header || bad_header (name) || bad_header (value))
    return TWIST_ERR_INVAL;
  n = snprintf (line, sizeof line, "%s: %s\r\n", name, value);
  if (n < 0 || (size_t) n >= sizeof line)
    return TWIST_ERR_PROTOCOL;
  return emit (mime, line, (size_t) n);
}

int
twist_mime_body (struct twist_mime *mime, const uint8_t *data, size_t len)
{
  if (mime == NULL)
    return TWIST_ERR_INVAL;
  if (b64_end (mime) != TWIST_OK)
    return mime->err;
  if (close_headers (mime) != TWIST_OK)
    return mime->err;
  if (data == NULL || len == 0)
    return TWIST_OK;
  return emit (mime, data, len);
}

int
twist_mime_body_b64 (struct twist_mime *mime, const uint8_t *data, size_t len)
{
  static const char tab[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  size_t i;

  if (mime == NULL)
    return TWIST_ERR_INVAL;
  if (close_headers (mime) != TWIST_OK)
    return mime->err;
  mime->b64 = 1;
  if (data == NULL)
    return TWIST_OK;
  for (i = 0; i < len; i++)
    {
      mime->b64_acc = (mime->b64_acc << 8) | data[i];
      mime->b64_n++;
      if (mime->b64_n == 3)
        {
          unsigned v = mime->b64_acc;
          char out[6];
          int n = 4;

          out[0] = tab[(v >> 18) & 63];
          out[1] = tab[(v >> 12) & 63];
          out[2] = tab[(v >> 6) & 63];
          out[3] = tab[v & 63];
          mime->b64_col += 4;
          mime->b64_n = 0;
          mime->b64_acc = 0;
          if (mime->b64_col >= 76)
            {
              out[4] = '\r';
              out[5] = '\n';
              n = 6;
              mime->b64_col = 0;
            }
          if (emit (mime, out, (size_t) n) != TWIST_OK)
            return mime->err;
        }
    }
  return TWIST_OK;
}

int
twist_mime_finish (struct twist_mime *mime)
{
  char line[48];
  int n;

  if (mime == NULL || mime->boundary[0] == 0)
    return TWIST_ERR_INVAL;
  if (b64_end (mime) != TWIST_OK)
    return mime->err;
  if (!mime->bol && emit_str (mime, "\r\n") != TWIST_OK)
    return mime->err;
  n = snprintf (line, sizeof line, "--%s--\r\n", mime->boundary);
  if (n < 0 || emit (mime, line, (size_t) n) != TWIST_OK)
    return mime->err != TWIST_OK ? mime->err : TWIST_ERR_PROTOCOL;
  if (flush (mime, 1) != TWIST_OK)
    return mime->err;
  return TWIST_OK;
}
