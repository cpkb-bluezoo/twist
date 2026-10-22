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
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/ioctl.h>
#include <unistd.h>

/* 200 values of the position of the spaceship's escort across the screen,
   in millionths: sin (i / 200 * 2 * pi) * 500000 + 500000 for i = 1 to 200,
   with pi as 3.1415.  */
static const unsigned int sinus[] = {
  515704, 531394, 547052, 562664, 578214, 593687, 609068, 624341, 639491,
  654504, 669364, 684057, 698568, 712883, 726989, 740870, 754513, 767906,
  781034, 793885, 806445, 818704, 830647, 842265, 853545, 864476, 875047,
  885248, 895069, 904500, 913532, 922156, 930363, 938145, 945495, 952406,
  958870, 964881, 970434, 975522, 980141, 984286, 987954, 991139, 993840,
  996054, 997778, 999011, 999752, 999999, 999754, 999014, 997783, 996060,
  993848, 991148, 987964, 984298, 980154, 975536, 970449, 964898, 958888,
  952426, 945516, 938168, 930386, 922180, 913558, 904527, 895097, 885277,
  875077, 864507, 853577, 842299, 830682, 818739, 806482, 793922, 781072,
  767945, 754553, 740910, 727030, 712925, 698610, 684100, 669407, 654548,
  639536, 624386, 609113, 593733, 578260, 562710, 547098, 531440, 515751,
  500046, 484341, 468651, 452993, 437381, 421830, 406357, 390976, 375703,
  360552, 345539, 330679, 315985, 301474, 287158, 273052, 259170, 245525,
  232132, 219003, 206152, 193590, 181331, 169386, 157768, 146487, 135555,
  124983, 114781, 104959, 95526, 86493, 77868, 69660, 61876, 54525, 47613,
  41147, 35135, 29581, 24491, 19871, 15724, 12056, 8868, 6166, 3951, 2225,
  990, 248, 0, 244, 982, 2212, 3933, 6144, 8842, 12025, 15690, 19832, 24448,
  29534, 35084, 41092, 47554, 54462, 61809, 69589, 77794, 86415, 95445,
  104873, 114692, 124891, 135460, 146389, 157667, 169282, 181224, 193480,
  206039, 218888, 232015, 245406, 259048, 272928, 287032, 301346, 315856,
  330548, 345407, 360419, 375568, 390841, 406221, 421693, 437243, 452854,
  468513, 484202, 499907
};

static void
fly (struct twist_bar *bar, int moved)
{
  char buf[TWIST_BAR_MAX + 2];
  int pos;
  int check = bar->width - 2;

  memset (buf, ' ', (size_t) bar->width);
  buf[bar->width] = '\r';
  buf[bar->width + 1] = 0;
  memcpy (&buf[bar->bar], "-=O=-", 5);
  pos = (int) (sinus[bar->tick % 200] / (1000000 / check));
  buf[pos] = '#';
  pos = (int) (sinus[(bar->tick + 5) % 200] / (1000000 / check));
  buf[pos] = '#';
  pos = (int) (sinus[(bar->tick + 10) % 200] / (1000000 / check));
  buf[pos] = '#';
  pos = (int) (sinus[(bar->tick + 15) % 200] / (1000000 / check));
  buf[pos] = '#';
  fputs (buf, bar->out);
  bar->tick += 2;
  if (bar->tick >= 200)
    bar->tick -= 200;
  bar->bar += moved ? bar->barmove : 0;
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

void
twist_bar_step (struct twist_bar *bar, long long dltotal, long long dlnow,
                long long ultotal, long long ulnow, uint64_t now_ms)
{
  long long total;
  long long point;

  /* The size to expect.  An initial size below 0 says it is to come from
     the remote.  */
  if (bar->initial_size < 0)
    {
      if (dltotal != 0 || ultotal != 0)
        total = dltotal + ultotal;
      else
        total = LLONG_MAX;
    }
  else if (LLONG_MAX - bar->initial_size < dltotal + ultotal)
    total = LLONG_MAX;
  else
    total = dltotal + ultotal + bar->initial_size;
  if (bar->initial_size < 0)
    {
      if (dltotal != 0 || ultotal != 0)
        point = dlnow + ulnow;
      else
        point = LLONG_MAX;
    }
  else if (LLONG_MAX - bar->initial_size < dlnow + ulnow)
    point = LLONG_MAX;
  else
    point = dlnow + ulnow + bar->initial_size;

  if (bar->calls)
    {
      if (total != 0)
        {
          if (bar->prev == point)
            return;
          /* At most ten times a second, except at the end.  */
          if (now_ms - bar->prevtime_ms < 100 && point < total)
            return;
        }
      else
        {
          if (now_ms - bar->prevtime_ms < 100)
            return;
          fly (bar, point != bar->prev);
        }
    }
  bar->calls++;
  if (total > 0 && point != bar->prev)
    {
      char line[TWIST_BAR_MAX + 1];
      double frac;
      double percent;
      int barwidth;
      int num;

      /* More than was expected.  */
      if (point > total)
        total = point;
      frac = (double) point / (double) total;
      percent = frac * 100.0;
      barwidth = bar->width - 7;
      num = (int) ((double) barwidth * frac);
      if (num > TWIST_BAR_MAX)
        num = TWIST_BAR_MAX;
      memset (line, '#', (size_t) num);
      line[num] = 0;
      fprintf (bar->out, "\r%-*s %5.1f%%", barwidth, line, percent);
    }
  fflush (bar->out);
  bar->prev = point;
  bar->prevtime_ms = now_ms;
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
