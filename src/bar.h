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

#ifndef TWIST_BAR_H
#define TWIST_BAR_H

#include <stdint.h>
#include <stdio.h>

/* The progress bar of -#, --progress-bar, drawn by the tool from the library's
   progress callback, as curl's is (src/tool_cb_prg.c): a line of '#' across
   the screen and the percentage when the size is known, and when it is not a
   spaceship (-=O=-) with hash signs flying above it, which moves while data
   comes.  */

#define TWIST_BAR_MAX 256

struct twist_bar
{
  FILE *out;
  int width;
  int tick;
  int bar;
  int barmove;
  int calls;
  long long prev;
  uint64_t prevtime_ms;
  /* What was already there when the transfer began (a resumed one); less
     than 0 when it is to be learned from the remote.  */
  long long initial_size;
};

/* The width to draw: COLUMNS if it is a number above 20 and below 10000, else
   the terminal's (COLS, as the caller read it, 0 if none), else 79; at most
   TWIST_BAR_MAX.  */
int twist_bar_columns (const char *columns_env, int terminal_cols);

/* Standard input's terminal width, 0 if it has none.  */
int twist_bar_terminal_cols (void);

void twist_bar_init (struct twist_bar *bar, FILE *out, long long initial_size);

/* One call of the progress callback at time NOW_MS.  */
void twist_bar_step (struct twist_bar *bar, long long dltotal,
                     long long dlnow, long long ultotal, long long ulnow,
                     uint64_t now_ms);

/* The progress callback itself, with a struct twist_bar as CLIENTP.  Always
   returns 0: the library's own meter is not wanted as well.  */
int twist_bar_callback (void *clientp, long long dltotal, long long dlnow,
                        long long ultotal, long long ulnow);

/* The end of the bar's line, if one was drawn.  */
void twist_bar_finish (struct twist_bar *bar);

#endif /* TWIST_BAR_H */
