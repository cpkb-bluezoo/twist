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

#include <stdint.h>

/* The limit is on the average over the whole transfer.  A
   chunk may go when the bytes before it have been earned: LIMIT bytes a
   second since the first question.  So the transfer is ahead of its rate by
   at most one chunk, and with chunks of half a second's worth that is half a
   second.  */

void
twist_rate_init (struct twist_rate *r, uint64_t limit)
{
  r->limit = limit;
  r->start_ms = 0;
  r->bytes = 0;
  r->started = 0;
}

/* N is the chunk that is about to go; it counts when it is noted, not now.  */
uint64_t
twist_rate_wait (struct twist_rate *r, uint64_t now_ms, size_t n)
{
  uint64_t whole, rest, due, elapsed;

  (void) n;
  /* A limit this high is not one, and the arithmetic below needs room.  */
  if (r->limit == 0 || r->limit > UINT64_MAX / 1000)
    return 0;
  if (!r->started)
    {
      r->started = 1;
      r->start_ms = now_ms;
    }
  whole = r->bytes / r->limit;
  rest = r->bytes % r->limit;
  if (whole > (UINT64_MAX - 1000) / 1000)
    return UINT64_MAX;
  /* Rounded up, so that the rate is never exceeded.  */
  due = whole * 1000 + (rest * 1000 + r->limit - 1) / r->limit;
  elapsed = now_ms > r->start_ms ? now_ms - r->start_ms : 0;
  return due > elapsed ? due - elapsed : 0;
}

void
twist_rate_note (struct twist_rate *r, uint64_t n)
{
  if (UINT64_MAX - r->bytes < n)
    r->bytes = UINT64_MAX;
  else
    r->bytes += n;
}

size_t
twist_rate_chunk (const struct twist_rate *r, size_t max)
{
  uint64_t half;

  if (r->limit == 0)
    return max;
  half = r->limit / 2;
  if (half < 1)
    half = 1;
  return half < max ? (size_t) half : max;
}
