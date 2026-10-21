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
#include "twist-int.h"

#include <stdint.h>

/* The pacer that keeps a transfer to a rate on average.  Times are
   milliseconds on any clock; the first question starts the transfer's
   clock.  */

static void
test_pacing (void)
{
  struct twist_rate r;

  /* No limit: never a wait.  */
  twist_rate_init (&r, 0);
  check (twist_rate_wait (&r, 1000, 1 << 20) == 0, "no limit, no wait");
  twist_rate_note (&r, 1u << 30);
  check (twist_rate_wait (&r, 1001, 1 << 20) == 0, "still none");

  /* 100000 bytes a second.  The first chunk goes at once; the next when the
     bytes sent so far have been earned.  */
  twist_rate_init (&r, 100000);
  check (twist_rate_wait (&r, 5000, 32768) == 0, "the first chunk is free");
  twist_rate_note (&r, 32768);
  check (twist_rate_wait (&r, 5000, 32768) == 328,
         "the second waits until the first has been earned");
  check (twist_rate_wait (&r, 5200, 32768) == 128, "less, later");
  check (twist_rate_wait (&r, 5328, 32768) == 0, "none when it is due");
  check (twist_rate_wait (&r, 9000, 32768) == 0, "nor when it is long due");
  twist_rate_note (&r, 32768);
  twist_rate_note (&r, 34464);
  /* 100000 bytes in all: 1000 ms after the start.  */
  check (twist_rate_wait (&r, 5000, 1) == 1000, "100000 bytes take a second");
  check (twist_rate_wait (&r, 5999, 1) == 1, "to the millisecond");
  check (twist_rate_wait (&r, 6000, 1) == 0, "and not past it");

  /* Rounding goes up, so the rate is never exceeded.  */
  twist_rate_init (&r, 3);
  twist_rate_wait (&r, 0, 1);
  twist_rate_note (&r, 1);
  check (twist_rate_wait (&r, 0, 1) == 334, "a third of a second, rounded up");

  /* A count that would overflow when multiplied by 1000.  */
  twist_rate_init (&r, 1);
  twist_rate_wait (&r, 0, 1);
  twist_rate_note (&r, UINT64_MAX / 2);
  check (twist_rate_wait (&r, 0, 1) > 1000000000000ull,
         "a huge count is a long wait, not a wrapped one");
}

static void
test_chunks (void)
{
  struct twist_rate r;

  twist_rate_init (&r, 0);
  check (twist_rate_chunk (&r, 32768) == 32768, "no limit: the full size");
  twist_rate_init (&r, 10000000);
  check (twist_rate_chunk (&r, 32768) == 32768, "a fast limit: the full size");
  twist_rate_init (&r, 20000);
  check (twist_rate_chunk (&r, 32768) == 10000,
         "a slow one: half a second's worth");
  twist_rate_init (&r, 1000);
  check (twist_rate_chunk (&r, 32768) == 500, "slower");
  twist_rate_init (&r, 1);
  check (twist_rate_chunk (&r, 32768) == 1, "never nothing");
}

int
main (void)
{
  test_pacing ();
  test_chunks ();
  return tests_finish ();
}
