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

/* A line stays in the caller's buffer.  receive-style callers keep the
   tail when this returns 0.  Dot stuffing is a one-byte state machine:
   the body is never copied aside from a fixed scratch on the stack.  */

enum
{
  DIN_BOL = 0,
  DIN_TEXT,
  DIN_CR,
  DIN_DOT,
  DIN_DOTCR,
  DIN_END
};

size_t
twist_mail_line (const uint8_t *data, size_t len, const uint8_t **line,
                 size_t *line_len, int *err)
{
  size_t i;

  if (err != NULL)
    *err = TWIST_OK;
  if (data == NULL || line == NULL || line_len == NULL)
    return 0;
  for (i = 0; i < len; i++)
    {
      if (data[i] == '\n')
        {
          size_t end = i;

          if (end > 0 && data[end - 1] == '\r')
            end--;
          *line = data;
          *line_len = end;
          return i + 1;
        }
      if (i >= TWIST_MAIL_LINE_MAX)
        {
          if (err != NULL)
            *err = TWIST_ERR_PROTOCOL;
          return len;
        }
    }
  if (len > TWIST_MAIL_LINE_MAX)
    {
      if (err != NULL)
        *err = TWIST_ERR_PROTOCOL;
      return len;
    }
  return 0;
}

void
twist_dotout_init (struct twist_dotout *dot)
{
  if (dot != NULL)
    dot->bol = 1;
}

static int
dot_flush (uint8_t *tmp, size_t *o,
           int (*sink) (void *, const uint8_t *, size_t), void *user, int force)
{
  if (*o == 0 || (*o < 128 && !force))
    return TWIST_OK;
  if (sink (user, tmp, *o) != 0)
    return TWIST_ERR_ABORTED;
  *o = 0;
  return TWIST_OK;
}

static int
dot_put (uint8_t *tmp, size_t *o, unsigned char c,
         int (*sink) (void *, const uint8_t *, size_t), void *user)
{
  if (*o == 128 && dot_flush (tmp, o, sink, user, 1) != TWIST_OK)
    return TWIST_ERR_ABORTED;
  tmp[(*o)++] = c;
  return TWIST_OK;
}

int
twist_dotout_write (struct twist_dotout *dot, const uint8_t *data, size_t len,
                    int (*sink) (void *user, const uint8_t *data, size_t len),
                    void *user)
{
  uint8_t tmp[128];
  size_t o = 0;
  size_t i;

  if (dot == NULL || sink == NULL)
    return TWIST_ERR_INVAL;
  for (i = 0; i < len; i++)
    {
      unsigned char c = data[i];

      if (dot->bol && c == '.'
          && dot_put (tmp, &o, '.', sink, user) != TWIST_OK)
        return TWIST_ERR_ABORTED;
      if (dot_put (tmp, &o, c, sink, user) != TWIST_OK)
        return TWIST_ERR_ABORTED;
      dot->bol = c == '\n';
    }
  return dot_flush (tmp, &o, sink, user, 1);
}

int
twist_dotout_finish (struct twist_dotout *dot,
                     int (*sink) (void *user, const uint8_t *data, size_t len),
                     void *user)
{
  static const uint8_t crlf_dot[] = { '\r', '\n', '.', '\r', '\n' };
  static const uint8_t marker[] = { '.', '\r', '\n' };
  const uint8_t *p;
  size_t n;

  if (dot == NULL || sink == NULL)
    return TWIST_ERR_INVAL;
  if (dot->bol)
    {
      p = marker;
      n = sizeof marker;
    }
  else
    {
      p = crlf_dot;
      n = sizeof crlf_dot;
    }
  dot->bol = 1;
  return sink (user, p, n) != 0 ? TWIST_ERR_ABORTED : TWIST_OK;
}

void
twist_dotin_init (struct twist_dotin *dot)
{
  if (dot != NULL)
    dot->state = DIN_BOL;
}

size_t
twist_dotin_pull (struct twist_dotin *dot, const uint8_t *data, size_t len,
                  int (*sink) (void *user, const uint8_t *data, size_t len),
                  void *user, int *done, int *err)
{
  uint8_t tmp[128];
  size_t o = 0;
  size_t i = 0;

  if (done != NULL)
    *done = 0;
  if (err != NULL)
    *err = TWIST_OK;
  if (dot == NULL || data == NULL || sink == NULL)
    return 0;
  if (dot->state == DIN_END)
    {
      if (done != NULL)
        *done = 1;
      return 0;
    }
  while (i < len && dot->state != DIN_END)
    {
      unsigned char c = data[i];
      int redo = 0;

      switch (dot->state)
        {
        case DIN_BOL:
          if (c == '.')
            dot->state = DIN_DOT;
          else if (c == '\r')
            dot->state = DIN_CR;
          else
            {
              tmp[o++] = c;
              if (c != '\n')
                dot->state = DIN_TEXT;
            }
          break;
        case DIN_TEXT:
          if (c == '\r')
            dot->state = DIN_CR;
          else if (c == '\n')
            {
              tmp[o++] = c;
              dot->state = DIN_BOL;
            }
          else
            tmp[o++] = c;
          break;
        case DIN_CR:
          if (c == '\n')
            {
              tmp[o++] = '\r';
              tmp[o++] = '\n';
              dot->state = DIN_BOL;
            }
          else
            {
              tmp[o++] = '\r';
              dot->state = DIN_TEXT;
              redo = 1;
            }
          break;
        case DIN_DOT:
          if (c == '.')
            {
              tmp[o++] = '.';
              dot->state = DIN_TEXT;
            }
          else if (c == '\r')
            dot->state = DIN_DOTCR;
          else if (c == '\n')
            dot->state = DIN_END;
          else
            {
              tmp[o++] = '.';
              dot->state = DIN_TEXT;
              redo = 1;
            }
          break;
        case DIN_DOTCR:
          if (c == '\n')
            dot->state = DIN_END;
          else
            {
              tmp[o++] = '.';
              tmp[o++] = '\r';
              dot->state = DIN_TEXT;
              redo = 1;
            }
          break;
        default:
          break;
        }
      if (!redo)
        i++;
      if (o >= sizeof tmp - 2)
        {
          if (sink (user, tmp, o) != 0)
            {
              if (err != NULL)
                *err = TWIST_ERR_ABORTED;
              return i;
            }
          o = 0;
        }
    }
  if (o > 0 && sink (user, tmp, o) != 0)
    {
      if (err != NULL)
        *err = TWIST_ERR_ABORTED;
      return i;
    }
  if (done != NULL)
    *done = dot->state == DIN_END;
  return i;
}
