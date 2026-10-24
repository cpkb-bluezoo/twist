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

#include "meter.h"
#include "twist-int.h"

#include <stdio.h>
#include <string.h>

void
twist_meter_init (struct twist_meter *meter, FILE *out, uint64_t start_ms)
{
  memset (meter, 0, sizeof *meter);
  meter->out = out;
  meter->start_ms = start_ms;
}

void
twist_meter_add (struct twist_meter *meter, struct twist_meter_xfer *xfer)
{
  memset (xfer, 0, sizeof *xfer);
  xfer->next = meter->xfers;
  meter->xfers = xfer;
  meter->started++;
  meter->running++;
}

int
twist_meter_callback (void *clientp, long long dltotal, long long dlnow,
                      long long ultotal, long long ulnow)
{
  struct twist_meter_xfer *xfer = clientp;

  /* This runs on the thread of the transfer's loop, and the run reads the
     counts from another.  Each is a word of its own.  */
  __atomic_store_n (&xfer->dltotal, dltotal, __ATOMIC_RELAXED);
  __atomic_store_n (&xfer->dlnow, dlnow, __ATOMIC_RELAXED);
  __atomic_store_n (&xfer->ultotal, ultotal, __ATOMIC_RELAXED);
  __atomic_store_n (&xfer->ulnow, ulnow, __ATOMIC_RELAXED);
  return 0;
}

void
twist_meter_done (struct twist_meter *meter, struct twist_meter_xfer *xfer)
{
  struct twist_meter_xfer **link;

  meter->dlalready += __atomic_load_n (&xfer->dlnow, __ATOMIC_RELAXED);
  meter->ulalready += __atomic_load_n (&xfer->ulnow, __ATOMIC_RELAXED);
  /* A size that was not yet counted into the whole counts now.  */
  if (!xfer->dltotal_added)
    {
      meter->dltotal += __atomic_load_n (&xfer->dltotal, __ATOMIC_RELAXED);
      xfer->dltotal_added = 1;
    }
  if (!xfer->ultotal_added)
    {
      meter->ultotal += __atomic_load_n (&xfer->ultotal, __ATOMIC_RELAXED);
      xfer->ultotal_added = 1;
    }
  for (link = &meter->xfers; *link != NULL; link = &(*link)->next)
    if (*link == xfer)
      {
        *link = xfer->next;
        xfer->next = NULL;
        meter->running--;
        break;
      }
}

/* The share of a whole that is done, as the text of the column: dashes
   unless every transfer has a size.  */
static void
share_text (char *buf, size_t cap, int all_known, long long now,
            long long whole)
{
  if (all_known && whole != 0)
    snprintf (buf, cap, "%3lld", now * 100 / whole);
  else
    snprintf (buf, cap, "--");
}

int
twist_meter_draw (struct twist_meter *meter, uint64_t now_ms, int final)
{
  struct twist_meter_xfer *x;
  long long dlnow = meter->dlalready;
  long long ulnow = meter->ulalready;
  int dl_known = 1;
  int ul_known = 1;
  unsigned oldest;
  uint64_t since;
  long long dl_moved;
  long long ul_moved;
  long long dl_rate;
  long long ul_rate;
  long long speed;
  long long total_time = 0;
  long long left_time = 0;
  char dl_pct[16], ul_pct[16];
  char dl_bytes[16], ul_bytes[16], speed_text[16];
  char total_text[16], spent_text[16], left_text[16];

  if (!meter->header)
    {
      fputs ("DL% UL%  Dled  Uled  Xfers  Live Total     Current  Left    Speed\n",
             meter->out);
      meter->header = 1;
    }
  if (!final && meter->drawn && now_ms <= meter->stamp_ms + 500)
    return 0;

  for (x = meter->xfers; x != NULL; x = x->next)
    {
      long long xdl = __atomic_load_n (&x->dltotal, __ATOMIC_RELAXED);
      long long xul = __atomic_load_n (&x->ultotal, __ATOMIC_RELAXED);

      dlnow += __atomic_load_n (&x->dlnow, __ATOMIC_RELAXED);
      ulnow += __atomic_load_n (&x->ulnow, __ATOMIC_RELAXED);
      if (xdl == 0)
        dl_known = 0;
      else if (!x->dltotal_added)
        {
          meter->dltotal += xdl;
          x->dltotal_added = 1;
        }
      if (xul == 0)
        ul_known = 0;
      else if (!x->ultotal_added)
        {
          meter->ultotal += xul;
          x->ultotal_added = 1;
        }
    }
  share_text (dl_pct, sizeof dl_pct, dl_known, dlnow, meter->dltotal);
  share_text (ul_pct, sizeof ul_pct, ul_known, ulnow, meter->ultotal);

  /* The speed is measured over the last ten lines once there have been that
     many, and over the whole run before.  */
  meter->speeds[meter->index].dl = dlnow;
  meter->speeds[meter->index].ul = ulnow;
  meter->speeds[meter->index].stamp_ms = now_ms;
  meter->index = (meter->index + 1) % TWIST_METER_SPEEDS;
  if (meter->index == 0)
    meter->wrapped = 1;
  if (meter->wrapped)
    {
      oldest = meter->index;
      since = meter->speeds[oldest].stamp_ms;
      dl_moved = dlnow - meter->speeds[oldest].dl;
      ul_moved = ulnow - meter->speeds[oldest].ul;
    }
  else
    {
      since = meter->start_ms;
      dl_moved = dlnow;
      ul_moved = ulnow;
    }
  {
    uint64_t span = now_ms > since ? now_ms - since : 0;
    double span_s = (double) (span < 1 ? 1 : span) / 1000.0;

    dl_rate = (long long) ((double) dl_moved / span_s);
    ul_rate = (long long) ((double) ul_moved / span_s);
  }
  speed = dl_rate > ul_rate ? dl_rate : ul_rate;

  if (dl_known && meter->dltotal != 0 && speed > 0)
    {
      total_time = meter->dltotal / speed;
      left_time = (meter->dltotal - dlnow) / speed;
    }

  fprintf (meter->out, "\r%-3s %-3s %s %s %5lld %5lld  %s %s %s %s %5s",
           dl_pct, ul_pct,
           twist_progress_max5 (dlnow, dl_bytes),
           twist_progress_max5 (ulnow, ul_bytes),
           meter->started, meter->running,
           twist_progress_time2str (total_time, total_text),
           twist_progress_time2str ((long long) ((now_ms - meter->start_ms)
                                                 / 1000u), spent_text),
           twist_progress_time2str (left_time, left_text),
           twist_progress_max5 (speed, speed_text),
           final ? "\n" : "");
  fflush (meter->out);
  meter->stamp_ms = now_ms;
  meter->drawn = 1;
  return 1;
}
