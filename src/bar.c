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

#include "bar.h"

#include <limits.h>
#include <math.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/ioctl.h>
#include <unistd.h>

/* The turn of the escort is 200 steps.  */
#define ESCORT_STEPS 200

/* Where the escort's STEP-th position falls on a line of WIDTH columns: the
   sine is scaled to a million and that to the width less the two columns
   at the edge.  The turn is measured with 3.1415, as the positions are.  */
static int
escort_column (int step, int width)
{
  long scaled = (long) (sin ((step % ESCORT_STEPS + 1) / (double) ESCORT_STEPS
                              * 2.0 * 3.1415) * 500000.0 + 500000.0);
  int col = (int) (scaled / (1000000 / (width - 2)));

  return col < width ? col : width - 1;
}

/* One frame of the spaceship, for a total that is not known: the ship
   (-=O=-) moves along the line when data has come, and four hash signs fly
   about it, whether or not it did.  */
static void
fly (struct twist_bar *bar, int moved)
{
  char line[TWIST_BAR_MAX + 2];
  int i;

  memset (line, ' ', bar->width);
  line[bar->width] = '\r';
  line[bar->width + 1] = 0;
  memcpy (line + bar->bar, "-=O=-", 5);
  for (i = 0; i < 4; i++)
    line[escort_column (bar->tick + 5 * i, bar->width)] = '#';
  fputs (line, bar->out);

  bar->tick += 2;
  if (bar->tick >= ESCORT_STEPS)
    bar->tick -= ESCORT_STEPS;
  if (moved)
    bar->bar += bar->barmove;
  if (bar->bar >= bar->width - 6)
    {
      bar->barmove = -1;
      bar->bar = bar->width - 6;
    }
  else if (bar->bar < 0)
    {
      bar->barmove = 1;
      bar->bar = 0;
    }
}

static long long
sum_up (long long a, long long b)
{
  return a > LLONG_MAX - b ? LLONG_MAX : a + b;
}

void
twist_bar_step (struct twist_bar *bar, long long dltotal, long long dlnow,
                long long ultotal, long long ulnow, uint64_t now_ms)
{
  long long total;
  long long point;
  int idle = bar->calls > 0 && now_ms < bar->prevtime_ms + 100;

  if (bar->initial_size < 0)
    {
      /* Learn the size from the remote, if it has told.  */
      total = (dltotal != 0 || ultotal != 0)
        ? sum_up (dltotal, ultotal) : LLONG_MAX;
      point = (dltotal != 0 || ultotal != 0)
        ? sum_up (dlnow, ulnow) : LLONG_MAX;
    }
  else
    {
      total = sum_up (sum_up (dltotal, ultotal), bar->initial_size);
      point = sum_up (sum_up (dlnow, ulnow), bar->initial_size);
    }

  if (bar->calls > 0)
    {
      if (total != 0)
        {
          if (point == bar->prev || (idle && point < total))
            return;
        }
      else
        {
          if (idle)
            return;
          fly (bar, point != bar->prev);
        }
    }
  bar->calls++;

  if (total > 0 && point != bar->prev)
    {
      char hashes[TWIST_BAR_MAX + 1];
      double fraction;
      int room = bar->width - 7;
      int num;

      if (point > total)
        total = point;
      fraction = (double) point / (double) total;
      num = (int) (room * fraction);
      if (num > TWIST_BAR_MAX)
        num = TWIST_BAR_MAX;
      memset (hashes, '#', num);
      hashes[num] = 0;
      fprintf (bar->out, "\r%-*s %5.1f%%", room, hashes, fraction * 100.0);
    }
  fflush (bar->out);
  bar->prev = point;
  bar->prevtime_ms = now_ms;
}

int
twist_bar_columns (const char *columns_env, int terminal_cols)
{
  int width = 0;

  if (columns_env != NULL)
    {
      char *end;
      long num = strtol (columns_env, &end, 10);

      if (end != columns_env && *end == 0 && num > 20 && num < 10000)
        width = (int) num;
    }
  if (width == 0 && terminal_cols > 20)
    width = terminal_cols;
  if (width == 0)
    width = 79;
  else if (width > TWIST_BAR_MAX)
    width = TWIST_BAR_MAX;
  return width;
}

int
twist_bar_terminal_cols (void)
{
  struct winsize ws;

  if (ioctl (STDIN_FILENO, TIOCGWINSZ, &ws) == 0)
    return ws.ws_col;
  return 0;
}

void
twist_bar_init (struct twist_bar *bar, FILE *out, long long initial_size)
{
  memset (bar, 0, sizeof *bar);
  bar->out = out;
  bar->initial_size = initial_size;
  bar->width = twist_bar_columns (getenv ("COLUMNS"),
                                  twist_bar_terminal_cols ());
  bar->tick = 150;
  bar->barmove = 1;
}

int
twist_bar_callback (void *clientp, long long dltotal, long long dlnow,
                    long long ultotal, long long ulnow)
{
  struct timespec ts;

  clock_gettime (CLOCK_MONOTONIC, &ts);
  twist_bar_step (clientp, dltotal, dlnow, ultotal, ulnow,
                  (uint64_t) ts.tv_sec * 1000u + (uint64_t) ts.tv_nsec / 1000000u);
  return 0;
}

void
twist_bar_finish (struct twist_bar *bar)
{
  if (bar->calls)
    fputs ("\n", bar->out);
}
