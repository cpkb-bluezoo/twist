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

  xfer->dltotal = dltotal;
  xfer->dlnow = dlnow;
  xfer->ultotal = ultotal;
  xfer->ulnow = ulnow;
  return 0;
}

void
twist_meter_done (struct twist_meter *meter, struct twist_meter_xfer *xfer)
{
  struct twist_meter_xfer **link;

  meter->dlalready += xfer->dlnow;
  meter->ulalready += xfer->ulnow;
  if (!xfer->dltotal_added)
    {
      meter->dltotal += xfer->dltotal;
      xfer->dltotal_added = 1;
    }
  if (!xfer->ultotal_added)
    {
      meter->ultotal += xfer->ultotal;
      xfer->ultotal_added = 1;
    }
  for (link = &meter->xfers; *link != NULL; link = &(*link)->next)
    if (*link == xfer)
      {
        *link = xfer->next;
        meter->running--;
        break;
      }
}

int
twist_meter_draw (struct twist_meter *meter, uint64_t now_ms, int final)
{
  struct twist_meter_xfer *x;
  char dlpercen[4] = "--";
  char ulpercen[4] = "--";
  char time_left[10];
  char time_total[10];
  char time_spent[10];
  char buffer[3][10];
  long long dlnow = meter->dlalready;
  long long ulnow = meter->ulalready;
  long long speed;
  long long spent;
  int dlknown = 1;
  int ulknown = 1;
  unsigned int i;
  uint64_t delta;
  long long dl;
  long long ul;

  if (!meter->header)
    {
      meter->header = 1;
      fputs ("DL% UL%  Dled  Uled  Xfers  Live "
             "Total     Current  Left    Speed\n", meter->out);
    }
  if (!final && meter->drawn && now_ms - meter->stamp_ms <= 500)
    return 0;
  meter->drawn = 1;
  meter->stamp_ms = now_ms;
  spent = (long long) (now_ms - meter->start_ms) / 1000;

  /* What the transfers that are over moved, and what the others have.  */
  for (x = meter->xfers; x != NULL; x = x->next)
    {
      dlnow += x->dlnow;
      ulnow += x->ulnow;
      if (!x->dltotal)
        dlknown = 0;
      else if (!x->dltotal_added)
        {
          /* Only add the size once.  */
          meter->dltotal += x->dltotal;
          x->dltotal_added = 1;
        }
      if (!x->ultotal)
        ulknown = 0;
      else if (!x->ultotal_added)
        {
          meter->ultotal += x->ultotal;
          x->ultotal_added = 1;
        }
    }
  if (dlknown && meter->dltotal)
    snprintf (dlpercen, sizeof dlpercen, "%3lld",
              dlnow * 100 / meter->dltotal);
  if (ulknown && meter->ultotal)
    snprintf (ulpercen, sizeof ulpercen, "%3lld",
              ulnow * 100 / meter->ultotal);

  /* The speed is the higher of the two, over the last ten lines drawn, or
     since the start until there have been so many.  */
  i = meter->index;
  meter->speeds[i].dl = dlnow;
  meter->speeds[i].ul = ulnow;
  meter->speeds[i].stamp_ms = now_ms;
  if (++meter->index >= TWIST_METER_SPEEDS)
    {
      meter->wrapped = 1;
      meter->index = 0;
    }
  if (meter->wrapped)
    {
      /* The index is now at the oldest.  */
      delta = now_ms - meter->speeds[meter->index].stamp_ms;
      dl = dlnow - meter->speeds[meter->index].dl;
      ul = ulnow - meter->speeds[meter->index].ul;
    }
  else
    {
      delta = now_ms - meter->start_ms;
      dl = dlnow;
      ul = ulnow;
    }
  if (delta == 0)
    delta++;
  {
    long long dls = (long long) ((double) dl / ((double) delta / 1000.0));
    long long uls = (long long) ((double) ul / ((double) delta / 1000.0));

    speed = dls > uls ? dls : uls;
  }

  if (dlknown && speed)
    {
      long long est = meter->dltotal / speed;
      long long left = (meter->dltotal - dlnow) / speed;

      twist_progress_time2str (left, time_left);
      twist_progress_time2str (est, time_total);
    }
  else
    {
      twist_progress_time2str (0, time_left);
      twist_progress_time2str (0, time_total);
    }
  twist_progress_time2str (spent, time_spent);

  fprintf (meter->out,
           "\r"
           "%-3s "              /* Percent downloaded.  */
           "%-3s "              /* Percent uploaded.  */
           "%s "                /* Dled.  */
           "%s "                /* Uled.  */
           "%5lld "             /* Xfers.  */
           "%5lld "             /* Live.  */
           " %s "               /* Total time.  */
           "%s "                /* Current time.  */
           "%s "                /* Time left.  */
           "%s "                /* Speed.  */
           "%5s",               /* The final newline.  */
           dlpercen, ulpercen,
           twist_progress_max5 (dlnow, buffer[0]),
           twist_progress_max5 (ulnow, buffer[1]),
           meter->started, meter->running,
           time_total, time_spent, time_left,
           twist_progress_max5 (speed, buffer[2]),
           final ? "\n" : "");
  return 1;
}
