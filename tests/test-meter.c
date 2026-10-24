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
#include "meter.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* The meter of -Z, on a clock the test passes in.  What it is compared with
   was written by curl 8.5.0 (tool_progress.c) for the same sequence.  */

#define BASE 1000000u
#define HEADER "DL% UL%  Dled  Uled  Xfers  Live Total     Current  Left    Speed\n"

struct rig
{
  struct twist_meter meter;
  FILE *out;
  char *buf;
  size_t len;
  size_t seen;
  struct twist_meter_xfer x[2];
};

static void
rig_open (struct rig *r)
{
  memset (r, 0, sizeof *r);
  r->out = open_memstream (&r->buf, &r->len);
  twist_meter_init (&r->meter, r->out, BASE);
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

/* Draw at MS after the start, and compare what that wrote, after the header
   if it is the first, with WANT.  */
static void
step (struct rig *r, unsigned ms, int final, const char *want, const char *what)
{
  const char *text;
  char msg[96];

  twist_meter_draw (&r->meter, BASE + ms, final);
  text = rig_text (r) + r->seen;
  if (r->seen == 0 && strncmp (text, HEADER, strlen (HEADER)) == 0)
    text += strlen (HEADER);
  snprintf (msg, sizeof msg, "%s", what);
  check (strcmp (text, want) == 0, msg);
  if (strcmp (text, want) != 0)
    fprintf (stderr, "  got  %s\n  want %s\n", text, want);
  r->seen = strlen (rig_text (r));
}

static void
set (struct twist_meter_xfer *x, long long dltotal, long long dlnow,
     long long ultotal, long long ulnow)
{
  check (twist_meter_callback (x, dltotal, dlnow, ultotal, ulnow) == 0,
         "the callback returns 0");
}

/* Two transfers with sizes; a line at most every 500 ms; one finishes and its
   bytes stay in the totals.  */
static void
test_two (void)
{
  struct rig r;
  const char *text;
  const char *p;
  int headers = 0;

  rig_open (&r);
  twist_meter_add (&r.meter, &r.x[0]);
  twist_meter_add (&r.meter, &r.x[1]);
  set (&r.x[0], 1000, 0, 0, 0);
  set (&r.x[1], 3000, 0, 0, 0);
  step (&r, 0, 0, "\r  0 --      0     0     2     2  --:--:-- --:--:-- --:--:--     0      ", "A0");
  set (&r.x[0], 1000, 500, 0, 0);
  set (&r.x[1], 3000, 100, 0, 0);
  step (&r, 300, 0, "", "A1");
  step (&r, 501, 0, "\r 15 --    600     0     2     2   0:00:03 --:--:--  0:00:02  1197      ", "A1b");
  set (&r.x[0], 1000, 1000, 0, 0);
  set (&r.x[1], 3000, 1500, 0, 0);
  step (&r, 1000, 0, "", "A2");
  twist_meter_done (&r.meter, &r.x[0]);
  set (&r.x[1], 3000, 3000, 0, 0);
  step (&r, 1600, 0, "\r100 --   4000     0     2     1   0:00:01  0:00:01 --:--:--  2500      ", "A3");
  twist_meter_done (&r.meter, &r.x[1]);
  step (&r, 2200, 1, "\r100 --   4000     0     2     0   0:00:02  0:00:02 --:--:--  1818     \n", "A4");
  text = rig_text (&r);
  for (p = text; (p = strstr (p, "DL% UL%")) != NULL; p++)
    headers++;
  check (headers == 1, "the header is there once");
  check (strncmp (text, HEADER, strlen (HEADER)) == 0, "and first");
  check (text[strlen (text) - 1] == '\n', "the last line is ended");
  check (strchr (text + strlen (HEADER), '\n') == text + strlen (text) - 1,
         "and no other is");
  rig_close (&r);
}

/* A transfer with no size, so no percentage, and an upload that is faster
   than the download, so the speed is the upload's.  */
static void
test_unknown (void)
{
  struct rig r;

  rig_open (&r);
  twist_meter_add (&r.meter, &r.x[0]);
  twist_meter_add (&r.meter, &r.x[1]);
  set (&r.x[0], 1000, 0, 0, 0);
  set (&r.x[1], 0, 0, 5000, 0);
  step (&r, 0, 0, "\r--  --      0     0     2     2  --:--:-- --:--:-- --:--:--     0      ", "B0");
  set (&r.x[0], 1000, 1000, 0, 0);
  set (&r.x[1], 0, 200, 5000, 2500);
  step (&r, 600, 0, "\r--  --   1200  2500     2     2  --:--:-- --:--:-- --:--:--  4166      ", "B1");
  set (&r.x[1], 0, 200, 5000, 5000);
  step (&r, 1300, 0, "\r--  --   1200  5000     2     2  --:--:--  0:00:01 --:--:--  3846      ", "B2");
  rig_close (&r);
}

/* Both directions have sizes, and the speed is the higher.  */
static void
test_both (void)
{
  struct rig r;

  rig_open (&r);
  twist_meter_add (&r.meter, &r.x[0]);
  set (&r.x[0], 100, 0, 100, 0);
  step (&r, 0, 0, "\r  0   0     0     0     1     1  --:--:-- --:--:-- --:--:--     0      ", "D0");
  set (&r.x[0], 100, 10, 100, 100);
  step (&r, 2000, 0, "\r 10 100    10   100     1     1   0:00:02  0:00:02  0:00:01    50      ", "D1");
  set (&r.x[0], 100, 100, 100, 100);
  step (&r, 4000, 0, "\r100 100   100   100     1     1   0:00:04  0:00:04 --:--:--    25      ", "D2");
  rig_close (&r);
}

/* A transfer that has reported nothing, then ends.  */
static void
test_nothing (void)
{
  struct rig r;

  rig_open (&r);
  twist_meter_add (&r.meter, &r.x[0]);
  step (&r, 0, 0, "\r--  --      0     0     1     1  --:--:-- --:--:-- --:--:--     0      ", "E0");
  step (&r, 700, 0, "\r--  --      0     0     1     1  --:--:-- --:--:-- --:--:--     0      ", "E1");
  twist_meter_done (&r.meter, &r.x[0]);
  step (&r, 700, 1, "\r--  --      0     0     1     0  --:--:-- --:--:-- --:--:--     0     \n", "E2");
  rig_close (&r);
}

/* Large numbers, and the speed over the last ten lines once there have been
   so many.  */
static void
test_wrap (void)
{
  struct rig r;
  char tag[16];
  int i;
  static const char *want[13] = {
    "\r  0 --      0     0     1     1  --:--:-- --:--:-- --:--:--     0      ",
    "\r  0 --  19.0M  1000     1     1   0:01:30 --:--:--  0:01:29 31.7M      ",
    "\r  2 --  76.2M  2000     1     1   0:00:45  0:00:01  0:00:43 63.5M      ",
    "\r  6 --   171M  3000     1     1   0:00:30  0:00:01  0:00:28 95.3M      ",
    "\r 10 --   305M  4000     1     1   0:00:22  0:00:02  0:00:20  127M      ",
    "\r 16 --   476M  5000     1     1   0:00:18  0:00:03  0:00:15  158M      ",
    "\r 24 --   686M  6000     1     1   0:00:15  0:00:03  0:00:11  190M      ",
    "\r 32 --   934M  7000     1     1   0:00:12  0:00:04  0:00:08  222M      ",
    "\r 42 --  1220M  8000     1     1   0:00:11  0:00:04  0:00:06  254M      ",
    "\r 54 --  1544M  9000     1     1   0:00:10  0:00:05  0:00:04  286M      ",
    "\r 66 --  1907M 10000     1     1   0:00:08  0:00:06  0:00:02  349M      ",
    "\r 80 --  2307M 11000     1     1   0:00:06  0:00:06  0:00:01  413M      ",
    "\r 96 --  2746M 12000     1     1   0:00:06  0:00:07 --:--:--  476M      ",
  };

  rig_open (&r);
  twist_meter_add (&r.meter, &r.x[0]);
  for (i = 0; i < 13; i++)
    {
      snprintf (tag, sizeof tag, "line %d", i);
      set (&r.x[0], 3000000000LL, (long long) i * i * 20000000LL, 0,
           (long long) i * 1000);
      step (&r, (unsigned) i * 600, 0, want[i], tag);
    }
  twist_meter_done (&r.meter, &r.x[0]);
  step (&r, 8000, 1, "\r 96 --  2746M 12000     1     0   0:00:06  0:00:08 --:--:--  435M     \n", "Cend");
  rig_close (&r);
}

static void
test_quiet (void)
{
  struct rig r;

  rig_open (&r);
  check (strcmp (rig_text (&r), "") == 0, "nothing until it is asked");
  twist_meter_add (&r.meter, &r.x[0]);
  check (strcmp (rig_text (&r), "") == 0, "and not for a start");
  check (r.meter.started == 1 && r.meter.running == 1, "one started");
  twist_meter_done (&r.meter, &r.x[0]);
  check (r.meter.started == 1 && r.meter.running == 0, "and over");
  rig_close (&r);
}

int
main (void)
{
  test_two ();
  test_unknown ();
  test_both ();
  test_nothing ();
  test_wrap ();
  test_quiet ();
  return tests_finish ();
}
