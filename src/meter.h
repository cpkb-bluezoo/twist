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

#ifndef TWIST_METER_H
#define TWIST_METER_H

#include <stdint.h>
#include <stdio.h>

/* The progress meter of transfers that run together (-Z): one line for the
   whole run, in the layout curl uses for its parallel transfers, drawn by the
   tool from the library's progress callback.  The header is printed once.
   Each line begins with a carriage return and gives the share of the
   download and of the upload that is done (blank dashes unless every
   transfer under way has a size), the bytes moved, how many transfers have
   been started and how many are under way, the time the whole should take,
   the time spent, the time left and the speed.  */

#define TWIST_METER_SPEEDS 10

/* What the meter keeps for one transfer.  The progress callback fills it.  */
struct twist_meter_xfer
{
  struct twist_meter_xfer *next;
  long long dltotal;
  long long dlnow;
  long long ultotal;
  long long ulnow;
  int dltotal_added;
  int ultotal_added;
};

struct twist_meter
{
  FILE *out;
  uint64_t start_ms;
  uint64_t stamp_ms;            /* The last line.  */
  int drawn;                    /* There has been one.  */
  int header;                   /* The header has been printed.  */
  struct twist_meter_xfer *xfers;       /* Under way.  */
  long long started;            /* How many have been added.  */
  long long running;            /* How many are in XFERS.  */
  /* The sizes and the bytes of the transfers that are over.  */
  long long dltotal;
  long long ultotal;
  long long dlalready;
  long long ulalready;
  unsigned int index;
  int wrapped;
  struct
  {
    long long dl;
    long long ul;
    uint64_t stamp_ms;
  } speeds[TWIST_METER_SPEEDS];
};

/* A meter that writes to OUT, for a run that begins at START_MS (a monotonic
   clock in milliseconds).  */
void twist_meter_init (struct twist_meter *meter, FILE *out,
                       uint64_t start_ms);

/* A transfer starts: count it, and keep XFER up to date.  */
void twist_meter_add (struct twist_meter *meter,
                      struct twist_meter_xfer *xfer);

/* The progress callback itself, with a struct twist_meter_xfer as CLIENTP.
   Always returns 0: the library's own meter is not wanted as well.  */
int twist_meter_callback (void *clientp, long long dltotal, long long dlnow,
                          long long ultotal, long long ulnow);

/* A transfer is over: what it moved and its sizes are added to the totals,
   and it is no longer under way.  */
void twist_meter_done (struct twist_meter *meter,
                       struct twist_meter_xfer *xfer);

/* The header, on the first call, and a line, if FINAL or more than half a
   second has passed since the last.  The last line ends with a newline.
   Returns 1 if a line was written.  */
int twist_meter_draw (struct twist_meter *meter, uint64_t now_ms, int final);

#endif /* TWIST_METER_H */
