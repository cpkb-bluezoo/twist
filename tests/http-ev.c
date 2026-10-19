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

#include "check.h"
#include "http-ev.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int saw_status;
int saw_done;
char body[64];
size_t body_len;
size_t body_total;
int slice_ok;
static const uint8_t *slice_lo;
static const uint8_t *slice_hi;
char hdr_name[64];
char hdr_value[64];

static void
ev_status (void *user, int code, const char *reason, size_t n)
{
  (void) user;
  (void) reason;
  (void) n;
  saw_status = code;
}

static void
ev_header (void *user, const char *name, size_t name_len, const char *value,
           size_t value_len)
{
  (void) user;
  if (name_len >= sizeof hdr_name)
    name_len = sizeof hdr_name - 1;
  if (value_len >= sizeof hdr_value)
    value_len = sizeof hdr_value - 1;
  memcpy (hdr_name, name, name_len);
  hdr_name[name_len] = 0;
  memcpy (hdr_value, value, value_len);
  hdr_value[value_len] = 0;
}

static void
ev_body (void *user, const uint8_t *data, size_t len)
{
  (void) user;
  body_total += len;
  if (slice_lo != NULL
      && (data < slice_lo || data + len > slice_hi))
    slice_ok = 0;
  if (body_len + len < sizeof body)
    {
      memcpy (body + body_len, data, len);
      body_len += len;
      body[body_len] = 0;
    }
}

static void
ev_done (void *user)
{
  (void) user;
  saw_done++;
}

void
reset_ev (void)
{
  saw_status = 0;
  saw_done = 0;
  body_len = 0;
  body_total = 0;
  slice_ok = 1;
  body[0] = 0;
  hdr_name[0] = 0;
  hdr_value[0] = 0;
}

struct twist_h1_events
test_events (void)
{
  struct twist_h1_events ev;

  memset (&ev, 0, sizeof ev);
  ev.status_line = ev_status;
  ev.header = ev_header;
  ev.body = ev_body;
  ev.message_done = ev_done;
  return ev;
}

void
feed_all (size_t (*recv) (void *, const uint8_t *, size_t), void *obj,
          const uint8_t *data, size_t len, size_t chunk)
{
  size_t off = 0;

  while (off < len)
    {
      size_t n = chunk;
      size_t got;
      if (n > len - off)
        n = len - off;
      got = recv (obj, data + off, n);
      if (got == 0)
        {
          failed = 1;
          fprintf (stderr, "FAIL parser stalled at %zu\n", off);
          return;
        }
      off += got;
    }
}

/* Connection-buffer contract: a parser may leave an incomplete frame
   unconsumed.  The next push is that tail plus the following bytes.  */
void
feed_remain (size_t (*recv) (void *, const uint8_t *, size_t), void *obj,
             const uint8_t *data, size_t len, size_t chunk)
{
  uint8_t *buf;
  size_t have = 0;
  size_t off = 0;

  buf = malloc (len + 1);
  if (buf == NULL)
    {
      failed = 1;
      fprintf (stderr, "FAIL feed buffer\n");
      return;
    }
  while (off < len || have > 0)
    {
      size_t n = chunk;
      size_t got;

      if (off < len)
        {
          if (n > len - off)
            n = len - off;
          memcpy (buf + have, data + off, n);
          have += n;
          off += n;
        }
      slice_lo = buf;
      slice_hi = buf + have;
      got = recv (obj, buf, have);
      if (got == 0)
        {
          if (off < len)
            continue;
          if (have > 0)
            {
              failed = 1;
              fprintf (stderr, "FAIL parser left %zu bytes\n", have);
            }
          break;
        }
      if (got > have)
        got = have;
      memmove (buf, buf + got, have - got);
      have -= got;
    }
  free (buf);
  slice_lo = NULL;
  slice_hi = NULL;
}

size_t
h1_recv (void *obj, const uint8_t *data, size_t len)
{
  return twist_h1_receive (obj, data, len);
}

size_t
h2_recv (void *obj, const uint8_t *data, size_t len)
{
  return twist_h2_receive (obj, data, len);
}

size_t
h3_recv (void *obj, const uint8_t *data, size_t len)
{
  return twist_h3_receive (obj, data, len);
}
