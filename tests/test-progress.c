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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* The progress meter and the callback, on a clock the test sets.  The
   expected lines are those of curl 8.5 for the same numbers: the layout was
   compared with its output for a slow download of 80000 bytes.  */

static uint64_t clock_ms;

static uint64_t
fake_now (void *user)
{
  (void) user;
  return clock_ms;
}

struct rig
{
  struct twist_loop *loop;
  struct twist_easy *easy;
  FILE *out;
  char *buf;
  size_t len;
};

static int
rig_open (struct rig *r, long noprogress)
{
  memset (r, 0, sizeof *r);
  r->loop = twist_loop_new (1);
  r->easy = twist_easy_init ();
  if (r->loop == NULL || r->easy == NULL)
    return -1;
  twist_loop_set_now (r->loop, fake_now, NULL);
  r->easy->loop = r->loop;
  r->out = open_memstream (&r->buf, &r->len);
  if (r->out == NULL)
    return -1;
  twist_easy_setopt (r->easy, TWISTOPT_STDERR, r->out);
  twist_easy_setopt (r->easy, TWISTOPT_NOPROGRESS, noprogress);
  return 0;
}

/* What has been written so far.  */
static const char *
rig_text (struct rig *r)
{
  fflush (r->out);
  return r->buf != NULL ? r->buf : "";
}

static void
rig_close (struct rig *r)
{
  twist_progress_release (r->easy);
  r->easy->loop = NULL;
  twist_easy_cleanup (r->easy);
  fclose (r->out);
  free (r->buf);
  twist_loop_free (r->loop);
}

static void
test_max5 (void)
{
  char b[16];

  check (strcmp (twist_progress_max5 (0, b), "    0") == 0, "zero");
  check (strcmp (twist_progress_max5 (99999, b), "99999") == 0, "5 digits");
  check (strcmp (twist_progress_max5 (100000, b), "  97k") == 0, "100000");
  check (strcmp (twist_progress_max5 (300000, b), " 292k") == 0,
         "300000 is 292k, as curl shows it");
  check (strcmp (twist_progress_max5 (10239999, b), "9999k") == 0, "9999k");
  check (strcmp (twist_progress_max5 (10240000, b), " 9.7M") == 0, "9.7M");
  /* Curl's tenths can come to 10, and its buffer cuts the text to five
     columns.  */
  check (strcmp (twist_progress_max5 (104857599, b), "99.10") == 0,
         "the cut tenth");
  check (strcmp (twist_progress_max5 (104857600, b), " 100M") == 0, "100M");
  check (strcmp (twist_progress_max5 (10485759999LL, b), "9999M") == 0,
         "9999M");
  check (strcmp (twist_progress_max5 (10485760000LL, b), " 9.7G") == 0,
         "9.7G");
  check (strcmp (twist_progress_max5 (107374182400LL, b), " 100G") == 0,
         "100G");
  check (strcmp (twist_progress_max5 (10737418240000LL, b), "   9T") == 0,
         "9T");
  check (strcmp (twist_progress_max5 (10995116277760000LL, b), "   9P") == 0,
         "9P");
  check (strcmp (twist_progress_max5 (9223372036854775807LL, b), "8191P") == 0,
         "the most");
}

static void
test_time2str (void)
{
  char b[16];

  check (strcmp (twist_progress_time2str (0, b), "--:--:--") == 0, "none");
  check (strcmp (twist_progress_time2str (-5, b), "--:--:--") == 0, "less");
  check (strcmp (twist_progress_time2str (1, b), " 0:00:01") == 0, "a second");
  check (strcmp (twist_progress_time2str (3661, b), " 1:01:01") == 0,
         "an hour and more");
  check (strcmp (twist_progress_time2str (359999, b), "99:59:59") == 0,
         "99 hours");
  check (strcmp (twist_progress_time2str (360000, b), "  4d 04h") == 0,
         "days");
  check (strcmp (twist_progress_time2str (86400LL * 999 + 3600, b),
                 "999d 01h") == 0, "999 days");
  check (strcmp (twist_progress_time2str (86400LL * 1000, b), "   1000d") == 0,
         "more days");
}

/* A download of 80000 bytes at 40000 a second.  */
static void
test_download (void)
{
  struct rig r;
  const char *head =
    "  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current\n"
    "                                 Dload  Upload   Total   Spent    Left  Speed\n";
  char want[1024];

  check (rig_open (&r, 0) == 0, "rig");
  clock_ms = 10500;
  twist_progress_begin (r.easy);
  /* Begin draws the heading and a line of zeros, as curl does at once.  */
  snprintf (want, sizeof want,
            "%s\r  0     0    0     0    0     0      0      0 "
            "--:--:-- --:--:-- --:--:--     0", head);
  check (strcmp (rig_text (&r), want) == 0, "the first line");

  twist_progress_dl_size (r.easy, 80000);
  clock_ms = 10900;
  twist_progress_downloaded (r.easy, 20000);
  check (strcmp (rig_text (&r), want) == 0,
         "nothing more within the same second");

  clock_ms = 11401;
  twist_progress_downloaded (r.easy, 20000);
  /* 40000 bytes in 901 ms is 44395 a second, 80000 in all will take 1 s.  */
  strcat (want, "\r 50 80000   50 40000    0     0  44395      0  "
                "0:00:01 --:--:--  0:00:01 44395");
  check (strcmp (rig_text (&r), want) == 0, "half way");

  clock_ms = 12500;
  twist_progress_downloaded (r.easy, 40000);
  strcat (want, "\r100 80000  100 80000    0     0  40000      0  "
                "0:00:02  0:00:02 --:--:-- 40000");
  check (strcmp (rig_text (&r), want) == 0, "done");

  /* The end forces a line and closes it, even in the same second.  */
  twist_progress_end (r.easy, TWIST_OK);
  strcat (want, "\r100 80000  100 80000    0     0  40000      0  "
                "0:00:02  0:00:02 --:--:-- 40000\n");
  check (strcmp (rig_text (&r), want) == 0, "the last line and the newline");
  rig_close (&r);
}

/* A download of a size that is not known: the total is what has come.  */
static void
test_unknown_size (void)
{
  struct rig r;

  check (rig_open (&r, 0) == 0, "rig");
  clock_ms = 20000;
  twist_progress_begin (r.easy);
  clock_ms = 21000;
  twist_progress_downloaded (r.easy, 60000);
  check (strstr (rig_text (&r),
                 "\r100 60000    0 60000    0     0  60000      0 "
                 "--:--:--  0:00:01 --:--:-- 60000") != NULL,
         "100% of what there is, none of what is expected");
  rig_close (&r);
}

static void
test_upload (void)
{
  struct rig r;

  check (rig_open (&r, 0) == 0, "rig");
  clock_ms = 30000;
  twist_progress_begin (r.easy);
  twist_progress_ul_size (r.easy, 1000);
  clock_ms = 31000;
  twist_progress_uploaded (r.easy, 500);
  /* 500 of 1000 up and nothing down: half of the whole, and the upload's
     percentage in the third column.  */
  check (strstr (rig_text (&r),
                 "\r 50  1000    0     0   50   500      0    500  "
                 "0:00:02  0:00:01  0:00:01   500") != NULL,
         "half way up");
  rig_close (&r);
}

/* The percentages are of whole numbers, as curl's: a size above 10000 is
   divided by 100 first.  The two ways come to different numbers for 100 bytes
   of 10001.  */
static void
test_percent (void)
{
  struct rig r;

  check (rig_open (&r, 0) == 0, "rig");
  clock_ms = 160000;
  twist_progress_begin (r.easy);
  twist_progress_dl_size (r.easy, 10001);
  clock_ms = 161000;
  twist_progress_downloaded (r.easy, 100);
  check (strstr (rig_text (&r), "\r  1 10001    1   100    0     0 ") != NULL,
         "1% of 10001 as curl rounds it");
  rig_close (&r);
  check (rig_open (&r, 0) == 0, "rig");
  clock_ms = 165000;
  twist_progress_begin (r.easy);
  twist_progress_ul_size (r.easy, 10001);
  clock_ms = 166000;
  twist_progress_uploaded (r.easy, 100);
  check (strstr (rig_text (&r), "\r  1 10001    0     0    1   100 ") != NULL,
         "the same for an upload");
  rig_close (&r);
}

/* The speed over the last five seconds is that of the entry five seconds
   back once there are that many.  */
static void
test_current_speed (void)
{
  struct rig r;
  static const long long added[] = { 0, 100, 100, 100, 100, 100, 1000, 1000 };
  size_t i;

  check (rig_open (&r, 0) == 0, "rig");
  clock_ms = 170000;
  twist_progress_begin (r.easy);
  for (i = 1; i < sizeof added / sizeof added[0]; i++)
    {
      clock_ms = 170000 + 1000 * i;
      twist_progress_downloaded (r.easy, (size_t) added[i]);
    }
  /* 2500 bytes in 7 seconds on average; from the second second to the
     seventh, 2300 in 5.  */
  check (strstr (rig_text (&r),
                 "\r100  2500    0  2500    0     0    357      0 "
                 "--:--:--  0:00:07 --:--:--   460") != NULL,
         "the last five seconds");
  rig_close (&r);
}

static void
test_first_line_speed (void)
{
  struct rig r;

  /* The first line to be drawn has no second before it to measure: the
     average is the speed.  A file draws nothing when it begins.  */
  check (rig_open (&r, 0) == 0, "rig");
  twist_url_parse_int ("file:///x", &r.easy->url);
  clock_ms = 180000;
  twist_progress_begin (r.easy);
  clock_ms = 181000;
  /* Known already, so that the first thing drawn has the count.  */
  r.easy->progress.size_dl = 10000;
  r.easy->progress.dl_known = 1;
  twist_progress_downloaded (r.easy, 5000);
  check (strstr (rig_text (&r),
                 "\r 50 10000   50  5000    0     0   5000      0  "
                 "0:00:02  0:00:01  0:00:01  5000") != NULL,
         "the average is the current speed at first");
  rig_close (&r);
}

static void
test_hidden (void)
{
  struct rig r;

  /* The default: nothing is drawn, whatever happens.  */
  check (rig_open (&r, 1) == 0, "rig");
  clock_ms = 40000;
  twist_progress_begin (r.easy);
  twist_progress_dl_size (r.easy, 10);
  clock_ms = 41000;
  twist_progress_downloaded (r.easy, 10);
  twist_progress_end (r.easy, TWIST_OK);
  check (strcmp (rig_text (&r), "") == 0, "no meter with NOPROGRESS");
  rig_close (&r);
}

static int calls;
static long long last_dltotal, last_dlnow, last_ultotal, last_ulnow;
static int answer;

static int
xfer (void *user, long long dltotal, long long dlnow, long long ultotal,
      long long ulnow)
{
  (void) user;
  calls++;
  last_dltotal = dltotal;
  last_dlnow = dlnow;
  last_ultotal = ultotal;
  last_ulnow = ulnow;
  return answer;
}

static void
test_callback (void)
{
  struct rig r;

  /* Called each time, even within the second; zero leaves the drawing to it.
     */
  check (rig_open (&r, 0) == 0, "rig");
  twist_easy_setopt (r.easy, TWISTOPT_XFERINFOFUNCTION, xfer);
  twist_easy_setopt (r.easy, TWISTOPT_XFERINFODATA, NULL);
  answer = 0;
  calls = 0;
  clock_ms = 50000;
  twist_progress_begin (r.easy);
  check (calls == 1, "called at the start");
  twist_progress_dl_size (r.easy, 100);
  twist_progress_downloaded (r.easy, 40);
  twist_progress_ul_size (r.easy, 7);
  twist_progress_uploaded (r.easy, 3);
  check (calls == 5, "called for each thing");
  check (last_dltotal == 100 && last_dlnow == 40 && last_ultotal == 7
         && last_ulnow == 3, "with the totals and the counts");
  twist_progress_end (r.easy, TWIST_OK);
  check (strcmp (rig_text (&r), "") == 0,
         "nothing drawn, and no newline, when the callback answers 0");
  rig_close (&r);

  /* TWIST_PROGRESSFUNC_CONTINUE: the callback and the meter.  */
  check (rig_open (&r, 0) == 0, "rig");
  twist_easy_setopt (r.easy, TWISTOPT_XFERINFOFUNCTION, xfer);
  answer = TWIST_PROGRESSFUNC_CONTINUE;
  clock_ms = 60000;
  twist_progress_begin (r.easy);
  check (strstr (rig_text (&r), "% Total") != NULL
         && strstr (rig_text (&r), "\r  0     0") != NULL,
         "the meter as well");
  twist_progress_end (r.easy, TWIST_OK);
  rig_close (&r);

  /* Unknown sizes are 0 to the callback, not -1.  */
  check (rig_open (&r, 0) == 0, "rig");
  twist_easy_setopt (r.easy, TWISTOPT_XFERINFOFUNCTION, xfer);
  answer = 0;
  clock_ms = 70000;
  twist_progress_begin (r.easy);
  twist_progress_downloaded (r.easy, 5);
  check (last_dltotal == 0 && last_dlnow == 5, "unknown is 0");
  rig_close (&r);

  /* Anything else stops the transfer.  */
  check (rig_open (&r, 0) == 0, "rig");
  twist_easy_setopt (r.easy, TWISTOPT_XFERINFOFUNCTION, xfer);
  answer = 1;
  clock_ms = 80000;
  r.easy->done = 0;
  twist_progress_begin (r.easy);
  check (r.easy->done && r.easy->result == TWIST_ERR_ABORTED,
         "a non-zero answer ends the transfer as aborted");
  rig_close (&r);

  /* With the meter hidden the callback is not called either.  */
  check (rig_open (&r, 1) == 0, "rig");
  twist_easy_setopt (r.easy, TWISTOPT_XFERINFOFUNCTION, xfer);
  answer = 0;
  calls = 0;
  clock_ms = 90000;
  twist_progress_begin (r.easy);
  twist_progress_downloaded (r.easy, 5);
  check (calls == 0, "NOPROGRESS silences the callback too");
  rig_close (&r);
}

static void
test_hop (void)
{
  struct rig r;

  /* A redirect finishes the line and starts the counters again, without a
     second heading.  */
  check (rig_open (&r, 0) == 0, "rig");
  clock_ms = 100000;
  twist_progress_begin (r.easy);
  twist_progress_dl_size (r.easy, 10);
  clock_ms = 100200;
  twist_progress_hop (r.easy);
  {
    const char *t = rig_text (&r);
    size_t lines = 0;

    for (; *t != 0; t++)
      lines += *t == '\n';
    /* The two lines of the heading and the end of the first response's.  */
    check (lines == 3 && t[-1] == '\n', "the first response's line is closed");
  }
  twist_progress_downloaded (r.easy, 4);
  twist_progress_end (r.easy, TWIST_OK);
  {
    const char *t = rig_text (&r);
    const char *h = strstr (t, "% Total");

    check (h != NULL && strstr (h + 1, "% Total") == NULL, "one heading");
    check (strstr (t, "\r100     4    0     4") != NULL,
           "the sizes and counts are those of the second response");
  }
  rig_close (&r);
}

static void
test_resume_line (void)
{
  struct rig r;

  check (rig_open (&r, 0) == 0, "rig");
  r.easy->resume_from = 1234;
  clock_ms = 110000;
  twist_progress_begin (r.easy);
  check (strncmp (rig_text (&r), "** Resuming transfer from byte position "
                  "1234\n  % Total", 54) == 0,
         "the resume line comes before the heading");
  rig_close (&r);
}

static void
test_file_failure (void)
{
  struct rig r;

  /* A file that cannot be opened has drawn nothing, and shows nothing.  */
  check (rig_open (&r, 0) == 0, "rig");
  twist_url_parse_int ("file:///nonexistent", &r.easy->url);
  clock_ms = 120000;
  twist_progress_begin (r.easy);
  twist_progress_end (r.easy, TWIST_ERR_FILE);
  check (strcmp (rig_text (&r), "") == 0, "nothing for a file that is not there");
  rig_close (&r);
}

static void
test_tick (void)
{
  struct rig r;
  size_t before;

  /* A transfer that is waiting is still drawn once a second: the timer.  */
  check (rig_open (&r, 0) == 0, "rig");
  clock_ms = 130000;
  twist_progress_begin (r.easy);
  before = strlen (rig_text (&r));
  clock_ms = 130999;
  twist_loop_on_timer (r.loop, clock_ms);
  check (strlen (rig_text (&r)) == before, "not before the second is up");
  clock_ms = 131000;
  twist_loop_on_timer (r.loop, clock_ms);
  check (strlen (rig_text (&r)) > before, "a line after a second");
  before = strlen (rig_text (&r));
  clock_ms = 132000;
  twist_loop_on_timer (r.loop, clock_ms);
  check (strlen (rig_text (&r)) > before, "and another");
  twist_progress_end (r.easy, TWIST_OK);
  before = strlen (rig_text (&r));
  clock_ms = 140000;
  twist_loop_on_timer (r.loop, clock_ms);
  check (strlen (rig_text (&r)) == before, "the timer stops with the transfer");
  rig_close (&r);

  /* Anything that happens puts the timer off by a second, as the poll of
     curl is: a transfer whose data comes more often than that is drawn
     when the data comes, and by nothing else.  */
  check (rig_open (&r, 0) == 0, "rig");
  clock_ms = 150000;
  twist_progress_begin (r.easy);
  clock_ms = 150500;
  twist_progress_downloaded (r.easy, 1);
  before = strlen (rig_text (&r));
  clock_ms = 151000;
  twist_loop_on_timer (r.loop, clock_ms);
  check (strlen (rig_text (&r)) == before, "no tick a second after the start");
  clock_ms = 151499;
  twist_loop_on_timer (r.loop, clock_ms);
  check (strlen (rig_text (&r)) == before, "nor before a second after the data");
  clock_ms = 151500;
  twist_loop_on_timer (r.loop, clock_ms);
  check (strlen (rig_text (&r)) > before, "but a second after it");
  rig_close (&r);
}

int
main (void)
{
  test_max5 ();
  test_time2str ();
  test_download ();
  test_unknown_size ();
  test_upload ();
  test_percent ();
  test_current_speed ();
  test_first_line_speed ();
  test_hidden ();
  test_callback ();
  test_hop ();
  test_resume_line ();
  test_file_failure ();
  test_tick ();
  return tests_finish ();
}
