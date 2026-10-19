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

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

enum
{
  H1_STATUS,
  H1_HEADER,
  H1_BODY,
  H1_CHUNK_SIZE,
  H1_CHUNK_DATA,
  H1_CHUNK_CRLF,
  H1_TRAILER,
  H1_DONE,
  H1_ERROR
};

struct twist_h1
{
  struct twist_h1_events ev;
  int state;
  int code;
  int chunked;
  int keep;
  uint64_t need;
  char line[8192];
  size_t line_len;
};

struct twist_h1 *
twist_h1_new (const struct twist_h1_events *ev)
{
  struct twist_h1 *p = calloc (1, sizeof *p);
  if (p == NULL)
    return NULL;
  if (ev != NULL)
    p->ev = *ev;
  p->state = H1_STATUS;
  return p;
}

void
twist_h1_free (struct twist_h1 *p)
{
  free (p);
}

static void
fail (struct twist_h1 *p, int err)
{
  p->state = H1_ERROR;
  if (p->ev.failure != NULL)
    p->ev.failure (p->ev.user, err);
}

static int
take_line (struct twist_h1 *p, const uint8_t *data, size_t len, size_t *used)
{
  size_t i;

  for (i = 0; i < len; i++)
    {
      char c = (char) data[i];
      if (p->line_len + 1 >= sizeof p->line)
        {
          fail (p, TWIST_ERR_PROTOCOL);
          return -1;
        }
      p->line[p->line_len++] = c;
      if (c == '\n')
        {
          *used = i + 1;
          p->line[p->line_len] = 0;
          if (p->line_len >= 2 && p->line[p->line_len - 2] == '\r')
            p->line[p->line_len - 2] = 0;
          else
            p->line[p->line_len - 1] = 0;
          return 1;
        }
    }
  *used = len;
  return 0;
}

static void
parse_status (struct twist_h1 *p)
{
  const char *sp;
  char *end = NULL;
  long code;

  sp = strchr (p->line, ' ');
  if (sp == NULL)
    {
      fail (p, TWIST_ERR_PROTOCOL);
      return;
    }
  code = strtol (sp + 1, &end, 10);
  if (end == sp + 1 || code < 100 || code > 599)
    {
      fail (p, TWIST_ERR_PROTOCOL);
      return;
    }
  p->code = (int) code;
  while (*end == ' ')
    end++;
  if (strncmp (p->line, "HTTP/", 5) == 0 && p->line[5] >= '0'
      && p->line[5] <= '9' && p->line[6] == '.' && p->line[7] >= '0'
      && p->line[7] <= '9' && p->ev.version != NULL)
    p->ev.version (p->ev.user, p->line[5] - '0', p->line[7] - '0');
  if (p->ev.status_line != NULL)
    p->ev.status_line (p->ev.user, p->code, end, strlen (end));
  p->state = H1_HEADER;
  p->chunked = 0;
  p->need = 0;
  if (strncmp (p->line, "HTTP/", 5) == 0 && p->line[6] == '.')
    p->keep = (p->line[5] == '1' && p->line[7] == '1');
  if (code == 204 || code == 304 || (code >= 100 && code < 200))
    p->need = 0;
}

static void
header_done (struct twist_h1 *p)
{
  if (p->code == 101 && p->ev.switching != NULL && p->ev.switching (p->ev.user))
    {
      p->state = H1_DONE;
      return;
    }
  if (p->code >= 100 && p->code < 200)
    {
      p->state = H1_STATUS;
      return;
    }
  if (p->chunked)
    p->state = H1_CHUNK_SIZE;
  else if (p->need == 0)
    {
      p->state = H1_DONE;
      if (p->ev.message_done != NULL)
        p->ev.message_done (p->ev.user);
    }
  else
    p->state = H1_BODY;
}

static void
parse_header (struct twist_h1 *p)
{
  char *colon;
  char *value;
  size_t nl;
  size_t vl;

  if (p->line[0] == 0)
    {
      header_done (p);
      return;
    }
  colon = strchr (p->line, ':');
  if (colon == NULL)
    {
      fail (p, TWIST_ERR_PROTOCOL);
      return;
    }
  *colon = 0;
  value = colon + 1;
  while (*value == ' ' || *value == '\t')
    value++;
  nl = strlen (p->line);
  vl = strlen (value);
  if (p->ev.header != NULL)
    p->ev.header (p->ev.user, p->line, nl, value, vl);
  if (strcasecmp (p->line, "content-length") == 0 && !p->chunked)
    p->need = (uint64_t) strtoull (value, NULL, 10);
  else if (strcasecmp (p->line, "transfer-encoding") == 0
           && strstr (value, "chunked") != NULL)
    {
      p->chunked = 1;
      p->need = 0;
    }
  else if (strcasecmp (p->line, "connection") == 0)
    {
      if (strstr (value, "close") != NULL)
        p->keep = 0;
      else if (strstr (value, "keep-alive") != NULL)
        p->keep = 1;
    }
}

int
twist_h1_keep (const struct twist_h1 *p)
{
  return p != NULL && p->keep;
}

static void
parse_chunk_size (struct twist_h1 *p)
{
  char *end = NULL;
  unsigned long sz = strtoul (p->line, &end, 16);

  if (end == p->line)
    {
      fail (p, TWIST_ERR_PROTOCOL);
      return;
    }
  if (sz == 0)
    p->state = H1_TRAILER;
  else
    {
      p->need = sz;
      p->state = H1_CHUNK_DATA;
    }
}

size_t
twist_h1_receive (struct twist_h1 *p, const uint8_t *data, size_t len)
{
  size_t off = 0;

  if (p->state == H1_ERROR || p->state == H1_DONE)
    return 0;
  while (off < len && p->state != H1_ERROR && p->state != H1_DONE)
    {
      if (p->state == H1_BODY || p->state == H1_CHUNK_DATA)
        {
          size_t n = len - off;
          if ((uint64_t) n > p->need)
            n = (size_t) p->need;
          if (n == 0)
            break;
          if (p->ev.body != NULL)
            p->ev.body (p->ev.user, data + off, n);
          off += n;
          p->need -= n;
          if (p->need == 0)
            {
              if (p->state == H1_BODY)
                {
                  p->state = H1_DONE;
                  if (p->ev.message_done != NULL)
                    p->ev.message_done (p->ev.user);
                }
              else
                p->state = H1_CHUNK_CRLF;
            }
          continue;
        }
      if (p->state == H1_CHUNK_CRLF)
        {
          if (off >= len)
            break;
          if (data[off] == '\r')
            {
              off++;
              continue;
            }
          if (data[off] == '\n')
            {
              off++;
              p->state = H1_CHUNK_SIZE;
              continue;
            }
          fail (p, TWIST_ERR_PROTOCOL);
          break;
        }
      {
        size_t used = 0;
        int got = take_line (p, data + off, len - off, &used);
        off += used;
        if (got <= 0)
          {
            if (got < 0)
              break;
            /* Incomplete line stays in p->line.  Consumed the bytes
               that were copied into it.  */
            break;
          }
        if (p->state == H1_STATUS)
          parse_status (p);
        else if (p->state == H1_HEADER || p->state == H1_TRAILER)
          {
            int trailer = p->state == H1_TRAILER;
            parse_header (p);
            if (trailer && p->state == H1_HEADER)
              {
                /* header_done moved a trailer-empty line to body states.
                   An empty trailer line should finish the message.  */
              }
            if (trailer && p->line[0] == 0 && p->state != H1_ERROR)
              {
                p->state = H1_DONE;
                if (p->ev.message_done != NULL)
                  p->ev.message_done (p->ev.user);
              }
          }
        else if (p->state == H1_CHUNK_SIZE)
          parse_chunk_size (p);
        p->line_len = 0;
      }
    }
  return off;
}

int
twist_h1_write_request (const char *method, const char *target,
                        const char *host, int http10,
                        const struct twist_slist *extra,
                        const uint8_t *body, size_t body_len, uint8_t **out,
                        size_t *out_len)
{
  size_t cap = 512;
  const struct twist_slist *h;
  uint8_t *buf;
  size_t n = 0;
  int wr;

  if (twist_has_ctl (method) || twist_has_ctl (target) || twist_has_ctl (host))
    return TWIST_ERR_PROTOCOL;
  for (h = extra; h != NULL; h = h->next)
    {
      if (twist_has_ctl (h->data))
        return TWIST_ERR_PROTOCOL;
      cap += strlen (h->data) + 2;
    }
  buf = twist_xmalloc (cap + 64);
  if (buf == NULL)
    return TWIST_ERR_NOMEM;
  wr = snprintf ((char *) buf, cap,
                 "%s %s HTTP/1.%d\r\nHost: %s\r\n",
                 method, target, http10 ? 0 : 1, host);
  if (wr < 0)
    {
      free (buf);
      return TWIST_ERR_NOMEM;
    }
  n = (size_t) wr;
  for (h = extra; h != NULL; h = h->next)
    {
      wr = snprintf ((char *) buf + n, cap - n, "%s\r\n", h->data);
      if (wr < 0 || n + (size_t) wr >= cap)
        {
          free (buf);
          return TWIST_ERR_NOMEM;
        }
      n += (size_t) wr;
    }
  if (body != NULL && body_len > 0)
    {
      wr = snprintf ((char *) buf + n, cap - n, "Content-Length: %zu\r\n",
                     body_len);
      if (wr < 0 || n + (size_t) wr >= cap)
        {
          free (buf);
          return TWIST_ERR_NOMEM;
        }
      n += (size_t) wr;
    }
  if (n + 2 > cap)
    {
      free (buf);
      return TWIST_ERR_NOMEM;
    }
  buf[n++] = '\r';
  buf[n++] = '\n';
  (void) body;
  *out = buf;
  *out_len = n;
  return TWIST_OK;
}
