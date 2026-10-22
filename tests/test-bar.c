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
#include "bar.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* The progress bar (-#), on a clock the test passes in.  What it is
   compared with was written by curl 8.5.0 for the same sequence.  */

struct rig
{
  struct twist_bar bar;
  FILE *out;
  char *buf;
  size_t len;
};

static void
rig_open (struct rig *r, int width, long long initial)
{
  memset (r, 0, sizeof *r);
  r->out = open_memstream (&r->buf, &r->len);
  twist_bar_init (&r->bar, r->out, initial);
  r->bar.width = width;
}

static const char *
rig_text (struct rig *r)
{
  fflush (r->out);
  return r->buf != NULL ? r->buf : "";
}

static void
rig_close (struct rig *r)
{
  fclose (r->out);
  free (r->buf);
}

static void
test_columns (void)
{
  check (twist_bar_columns (NULL, 0) == 79, "79 when nothing says");
  check (twist_bar_columns ("60", 0) == 60, "COLUMNS");
  check (twist_bar_columns ("60", 100) == 60, "COLUMNS before the terminal");
  check (twist_bar_columns (NULL, 100) == 100, "the terminal");
  check (twist_bar_columns ("20", 0) == 79, "COLUMNS must be above 20");
  check (twist_bar_columns ("21", 0) == 21, "21 will do");
  check (twist_bar_columns ("10000", 0) == 79, "and below 10000");
  check (twist_bar_columns ("9999", 0) == TWIST_BAR_MAX, "and is cut to 256");
  check (twist_bar_columns ("60x", 0) == 79, "all of it a number");
  check (twist_bar_columns ("abc", 50) == 50, "not a number: the terminal");
  check (twist_bar_columns ("", 0) == 79, "empty");
  check (twist_bar_columns (NULL, 20) == 79, "a terminal this narrow is not");
}

static void
test_known (void)
{
  struct rig r;
  char want[128];
  size_t len;

  /* 60 columns: 53 for the bar, a space and 5 for the percentage.  */
  rig_open (&r, 60, 0);
  twist_bar_step (&r.bar, 5000, 0, 0, 0, 1000);
  check (strcmp (rig_text (&r), "") == 0, "nothing at 0");
  twist_bar_step (&r.bar, 5000, 5000, 0, 0, 1010);
  memset (want, '#', 53);
  strcpy (want + 53, " 100.0%");
  check (rig_text (&r)[0] == '\r' && strcmp (rig_text (&r) + 1, want) == 0,
         "the whole bar, at once, at the end");
  twist_bar_finish (&r.bar);
  check (strchr (rig_text (&r), '\n') != NULL, "the line is ended");
  rig_close (&r);

  /* A download of 80000 bytes, seen at 50% and 75%: 26 and 39 of 53.  */
  rig_open (&r, 60, 0);
  twist_bar_step (&r.bar, 80000, 0, 0, 0, 0);
  twist_bar_step (&r.bar, 80000, 40000, 0, 0, 900);
  twist_bar_step (&r.bar, 80000, 60000, 0, 0, 1800);
  twist_bar_step (&r.bar, 80000, 80000, 0, 0, 2700);
  snprintf (want, sizeof want, "\r%-53s %5.1f%%", "##########################",
            50.0);
  check (strncmp (rig_text (&r), want, 61) == 0, "50% is 26 hashes");
  rig_close (&r);

  /* Updates are at most ten a second, and only when the count changes.  */
  rig_open (&r, 60, 0);
  twist_bar_step (&r.bar, 1000, 0, 0, 0, 5000);
  twist_bar_step (&r.bar, 1000, 100, 0, 0, 5010);
  check (strcmp (rig_text (&r), "") == 0, "not within 100 ms");
  twist_bar_step (&r.bar, 1000, 100, 0, 0, 5200);
  check (strstr (rig_text (&r), " 10.0%") != NULL, "after them");
  len = strlen (rig_text (&r));
  twist_bar_step (&r.bar, 1000, 100, 0, 0, 5400);
  check (strlen (rig_text (&r)) == len, "not when nothing changed");
  twist_bar_step (&r.bar, 1000, 200, 0, 0, 5250);
  check (strlen (rig_text (&r)) == len, "not within 100 ms of the last");
  twist_bar_step (&r.bar, 1000, 200, 0, 0, 5300);
  check (strstr (rig_text (&r) + len, " 20.0%") != NULL, "when it did");
  rig_close (&r);

  /* Uploads count too, and what is already there when it was resumed.  */
  rig_open (&r, 60, 1000);
  twist_bar_step (&r.bar, 1000, 0, 0, 0, 0);
  twist_bar_step (&r.bar, 1000, 500, 0, 0, 500);
  check (strstr (rig_text (&r), " 75.0%") != NULL,
         "1500 of 2000 with 1000 from before");
  rig_close (&r);
}

static void
test_fly (void)
{
  struct rig r;
  /* As curl wrote them at 40 columns, a spaceship that moves one step each
     time data comes.  */
  const char *want =
    "###=-                                   \r"
    "###O=-                                  \r"
    "# ##O=-                                 \r"
    "###-#O=-                                \r";

  rig_open (&r, 40, 0);
  twist_bar_step (&r.bar, 0, 20000, 0, 0, 1000);
  check (strcmp (rig_text (&r), "") == 0, "the first call draws nothing");
  twist_bar_step (&r.bar, 0, 40000, 0, 0, 1200);
  twist_bar_step (&r.bar, 0, 60000, 0, 0, 1400);
  twist_bar_step (&r.bar, 0, 80000, 0, 0, 1600);
  twist_bar_step (&r.bar, 0, 100000, 0, 0, 1800);
  check (strcmp (rig_text (&r), want) == 0, "the spaceship and its escort");
  twist_bar_finish (&r.bar);
  check (rig_text (&r)[strlen (rig_text (&r)) - 1] == '\n', "ended");
  rig_close (&r);

  rig_open (&r, 40, 0);
  twist_bar_step (&r.bar, 0, 1, 0, 0, 1000);
  twist_bar_step (&r.bar, 0, 1, 0, 0, 1050);
  check (strcmp (rig_text (&r), "") == 0, "ten a second at most");
  twist_bar_step (&r.bar, 0, 1, 0, 0, 1100);
  check (strncmp (rig_text (&r), "###=-", 5) == 0
         && strlen (rig_text (&r)) == 41, "drawn when the time has come");
  /* Nothing has come since, and the spaceship is drawn again, in the same
     place.  */
  twist_bar_step (&r.bar, 0, 1, 0, 0, 1300);
  check (strlen (rig_text (&r)) == 82
         && strstr (rig_text (&r) + 41, "=-") != NULL, "and drawn again");
  rig_close (&r);
}

static void
test_finish (void)
{
  struct rig r;

  /* No newline for a bar that was never drawn (an error before anything).  */
  rig_open (&r, 60, 0);
  twist_bar_finish (&r.bar);
  check (strcmp (rig_text (&r), "") == 0, "nothing to end");
  rig_close (&r);
}

int
main (void)
{
  test_columns ();
  test_known ();
  test_fly ();
  test_finish ();
  return tests_finish ();
}
