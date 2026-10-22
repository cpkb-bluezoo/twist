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

#include "twist-int.h"
#include "gettext.h"

#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

/* The progress meter, as curl draws it (lib/progress.c): the counters, the
   once-a-second arithmetic of the current speed, and the line

     % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                    Dload  Upload   Total   Spent    Left  Speed
   100  5000  100  5000    0     0  7443k      0 --:--:-- --:--:-- --:--:-- 4882k

   The line is rewritten in place with a carriage return, and is drawn when
   the second has changed, and once more when the transfer is done.  The
   tool's bar is a callback (src/bar.c) and is not drawn here.

   The clock is the loop's, so that a test can set it.  A timer asks for an
   update when a second has passed with none, so that a transfer that is
   waiting is still drawn; curl does that by waking its poll after a second
   with no event.  Every update puts the timer off by a second again, which
   is done by moving the due time, not the timer.  */

#define TICK_MS 1000u

#define KILO 1024LL
#define MEGA (1024LL * KILO)
#define GIGA (1024LL * MEGA)
#define TERA (1024LL * GIGA)
#define PETA (1024LL * TERA)

/* Curl writes into a buffer that holds what the column does, and cuts the
   rest.  So a number that is too wide for its column loses its end.  */
static char *
fit (char *buf, size_t cap, const char *text)
{
  size_t n = strlen (text);

  if (n > cap - 1)
    n = cap - 1;
  memcpy (buf, text, n);
  buf[n] = 0;
  return buf;
}

/* A size in at most five columns: 12345, 1234k, 12.3M, 1234M, 12.3G...  */
char *
twist_progress_max5 (long long bytes, char *buf)
{
  char t[48];

  if (bytes < 100000LL)
    snprintf (t, sizeof t, "%5lld", bytes);
  else if (bytes < 10000LL * KILO)
    snprintf (t, sizeof t, "%4lldk", bytes / KILO);
  else if (bytes < 100LL * MEGA)
    snprintf (t, sizeof t, "%2lld.%0lldM", bytes / MEGA,
              (bytes % MEGA) / (MEGA / 10));
  else if (bytes < 10000LL * MEGA)
    snprintf (t, sizeof t, "%4lldM", bytes / MEGA);
  else if (bytes < 100LL * GIGA)
    snprintf (t, sizeof t, "%2lld.%0lldG", bytes / GIGA,
              (bytes % GIGA) / (GIGA / 10));
  else if (bytes < 10000LL * GIGA)
    snprintf (t, sizeof t, "%4lldG", bytes / GIGA);
  else if (bytes < 10000LL * TERA)
    snprintf (t, sizeof t, "%4lldT", bytes / TERA);
  else
    snprintf (t, sizeof t, "%4lldP", bytes / PETA);
  return fit (buf, 6, t);
}

/* Eight columns: hours, minutes and seconds, or days and hours.  */
char *
twist_progress_time2str (long long seconds, char *buf)
{
  char t[48];
  long long h;

  if (seconds <= 0)
    return fit (buf, 10, "--:--:--");
  h = seconds / 3600;
  if (h <= 99)
    {
      long long m = (seconds - h * 3600) / 60;
      long long s = (seconds - h * 3600) - m * 60;

      snprintf (t, sizeof t, "%2lld:%02lld:%02lld", h, m, s);
    }
  else
    {
      long long d = seconds / 86400;

      h = (seconds - d * 86400) / 3600;
      if (d <= 999)
        snprintf (t, sizeof t, "%3lldd %02lldh", d, h);
      else
        snprintf (t, sizeof t, "%7lldd", d);
    }
  return fit (buf, 9, t);
}

/* Bytes a second over US microseconds.  */
static long long
speed (long long size, long long us)
{
  if (us < 1)
    return size < LLONG_MAX / 1000000 ? size * 1000000 : LLONG_MAX;
  if (size < LLONG_MAX / 1000000)
    return (size * 1000000) / us;
  if (us >= 1000000)
    return size / (us / 1000000);
  return LLONG_MAX;
}

/* The averages, and once a second the speed over the last few seconds.
   Returns 1 if the second has changed, which is when the meter draws.  */
static int
calculate (struct twist_progress *p, uint64_t now_ms)
{
  int show = 0;

  p->timespent_us = (long long) (now_ms - p->start_ms) * 1000;
  p->dlspeed = speed (p->downloaded, p->timespent_us);
  p->ulspeed = speed (p->uploaded, p->timespent_us);
  if (p->lastshow != (long long) (now_ms / 1000))
    {
      unsigned nowindex = p->speeder_n % TWIST_PROGRESS_HISTORY;
      unsigned count;

      p->lastshow = (long long) (now_ms / 1000);
      show = 1;
      p->speeder[nowindex] = p->downloaded + p->uploaded;
      p->speeder_ms[nowindex] = now_ms;
      p->speeder_n++;
      count = (p->speeder_n >= TWIST_PROGRESS_HISTORY
               ? TWIST_PROGRESS_HISTORY : p->speeder_n) - 1;
      if (count > 0)
        {
          unsigned check = p->speeder_n >= TWIST_PROGRESS_HISTORY
            ? p->speeder_n % TWIST_PROGRESS_HISTORY : 0;
          long long span = (long long) (now_ms - p->speeder_ms[check]);
          long long amount = p->speeder[nowindex] - p->speeder[check];

          if (span == 0)
            span = 1;
          if (amount > 4294967LL)
            p->current_speed = (long long) ((double) amount
                                            / ((double) span / 1000.0));
          else
            p->current_speed = amount * 1000 / span;
        }
      else
        p->current_speed = p->ulspeed + p->dlspeed;
    }
  return show;
}

static void
meter (struct twist_easy *easy)
{
  struct twist_progress *p = &easy->progress;
  FILE *out = p->err != NULL ? p->err : stderr;
  char max5[6][10];
  char time_left[10];
  char time_total[10];
  char time_spent[10];
  long long dlpercen = 0;
  long long ulpercen = 0;
  long long total_percen = 0;
  long long ulestimate = 0;
  long long dlestimate = 0;
  long long total_estimate;
  long long total_expected;
  long long total_transfer;
  long long timespent = p->timespent_us / 1000000;

  if (!p->headers_out)
    {
      if (easy->resume_from > 0)
        fprintf (out, "** Resuming transfer from byte position %lld\n",
                 easy->resume_from);
      fputs ("  % Total    % Received % Xferd  Average Speed   "
             "Time    Time     Time  Current\n"
             "                                 Dload  Upload   "
             "Total   Spent    Left  Speed\n", out);
      p->headers_out = 1;
    }
  if (p->ul_known && p->ulspeed > 0)
    {
      ulestimate = p->size_ul / p->ulspeed;
      if (p->size_ul > 10000)
        ulpercen = p->uploaded / (p->size_ul / 100);
      else if (p->size_ul > 0)
        ulpercen = (p->uploaded * 100) / p->size_ul;
    }
  if (p->dl_known && p->dlspeed > 0)
    {
      dlestimate = p->size_dl / p->dlspeed;
      if (p->size_dl > 10000)
        dlpercen = p->downloaded / (p->size_dl / 100);
      else if (p->size_dl > 0)
        dlpercen = (p->downloaded * 100) / p->size_dl;
    }
  /* The slower of the two is when it will be done.  */
  total_estimate = ulestimate > dlestimate ? ulestimate : dlestimate;
  twist_progress_time2str (total_estimate > 0 ? total_estimate - timespent : 0,
                           time_left);
  twist_progress_time2str (total_estimate, time_total);
  twist_progress_time2str (timespent, time_spent);
  total_expected = (p->ul_known ? p->size_ul : p->uploaded)
    + (p->dl_known ? p->size_dl : p->downloaded);
  total_transfer = p->downloaded + p->uploaded;
  if (total_expected > 10000)
    total_percen = total_transfer / (total_expected / 100);
  else if (total_expected > 0)
    total_percen = (total_transfer * 100) / total_expected;
  fprintf (out, "\r%3lld %s  %3lld %s  %3lld %s  %s  %s %s %s %s %s",
           total_percen, twist_progress_max5 (total_expected, max5[2]),
           dlpercen, twist_progress_max5 (p->downloaded, max5[0]),
           ulpercen, twist_progress_max5 (p->uploaded, max5[1]),
           twist_progress_max5 (p->dlspeed, max5[3]),
           twist_progress_max5 (p->ulspeed, max5[4]),
           time_total, time_spent, time_left,
           twist_progress_max5 (p->current_speed, max5[5]));
  fflush (out);
  p->shown = 1;
}

static void
arm (struct twist_easy *easy);

static void
tick (void *user)
{
  struct twist_easy *easy = user;

  easy->progress.tick = NULL;
  if (!easy->progress.begun)
    return;
  /* Something has happened since the timer was set: not yet.  */
  if (easy->loop != NULL && twist_loop_now (easy->loop) < easy->progress.tick_due)
    {
      arm (easy);
      return;
    }
  twist_progress_update (easy);
  /* The update may have ended the transfer.  */
  if (easy->progress.begun)
    arm (easy);
}

static void
arm (struct twist_easy *easy)
{
  struct twist_progress *p = &easy->progress;

  if (easy->loop == NULL || p->tick != NULL)
    return;
  twist_loop_schedule (easy->loop, p->tick_due, tick, easy, &p->tick);
}

void
twist_progress_release (struct twist_easy *easy)
{
  struct twist_progress *p = &easy->progress;

  if (p->tick != NULL)
    {
      twist_timer_cancel (p->tick);
      p->tick = NULL;
    }
  p->begun = 0;
}

/* What the transfer has learned changes what is drawn, if the second has
   changed.  Returns what the callback returned: not 0 means stop.  */
int
twist_progress_update (struct twist_easy *easy)
{
  struct twist_progress *p = &easy->progress;
  int show;

  if (!p->begun || p->hide || easy->loop == NULL)
    return 0;
  show = calculate (p, twist_loop_now (easy->loop));
  p->tick_due = twist_loop_now (easy->loop) + TICK_MS;
  if (p->xferinfo != NULL)
    {
      int r = p->xferinfo (p->xferinfo_data, p->dl_known ? p->size_dl : 0,
                           p->downloaded, p->ul_known ? p->size_ul : 0,
                           p->uploaded);

      /* Zero leaves the drawing to the callback.  */
      if (r != TWIST_PROGRESSFUNC_CONTINUE)
        {
          if (r != 0 && !p->aborted)
            {
              p->aborted = 1;
              if (!easy->done)
                {
                  twist_easy_set_error (easy, twist_strdup (_("callback aborted")));
                  twist_easy_finish (easy, TWIST_ERR_ABORTED);
                }
            }
          return r;
        }
    }
  if (show)
    meter (easy);
  return 0;
}

/* The forced last update of a transfer or of one hop of it, and the end of
   its line.  A callback is left to end its own.  */
static void
finish_line (struct twist_easy *easy)
{
  struct twist_progress *p = &easy->progress;

  p->lastshow = -1;
  if (twist_progress_update (easy) != 0)
    return;
  if (!p->hide && p->xferinfo == NULL)
    fputc ('\n', p->err != NULL ? p->err : stderr);
  p->speeder_n = 0;
}

static void
reset_counters (struct twist_progress *p)
{
  p->downloaded = 0;
  p->uploaded = 0;
  p->size_dl = 0;
  p->size_ul = 0;
  p->dl_known = 0;
  p->ul_known = 0;
  p->current_speed = 0;
  p->dlspeed = 0;
  p->ulspeed = 0;
}

/* A file that is not there draws nothing, as curl's does: the heading would
   be all there was.  */
static int
quiet_scheme (const struct twist_easy *easy)
{
  return easy->url != NULL && easy->url->scheme != NULL
    && strcmp (easy->url->scheme, "file") == 0;
}

void
twist_progress_begin (struct twist_easy *easy)
{
  struct twist_progress *p = &easy->progress;

  twist_progress_release (easy);
  reset_counters (p);
  p->aborted = 0;
  p->shown = 0;
  p->headers_out = 0;
  p->lastshow = -1;
  p->speeder_n = 0;
  p->begun = 1;
  if (easy->loop != NULL)
    p->start_ms = twist_loop_now (easy->loop);
  if (p->hide)
    return;
  p->tick_due = (easy->loop != NULL ? twist_loop_now (easy->loop) : 0) + TICK_MS;
  arm (easy);
  if (!quiet_scheme (easy))
    twist_progress_update (easy);
}

void
twist_progress_end (struct twist_easy *easy, int result)
{
  struct twist_progress *p = &easy->progress;

  if (!p->begun)
    return;
  if (!(result != TWIST_OK && !p->shown && quiet_scheme (easy)))
    finish_line (easy);
  twist_progress_release (easy);
}

/* A redirect: this response is done and the next request is another.  */
void
twist_progress_hop (struct twist_easy *easy)
{
  struct twist_progress *p = &easy->progress;

  if (!p->begun)
    return;
  finish_line (easy);
  reset_counters (p);
}

void
twist_progress_dl_size (struct twist_easy *easy, long long size)
{
  struct twist_progress *p = &easy->progress;

  if (size >= 0)
    {
      p->size_dl = size;
      p->dl_known = 1;
    }
  else
    {
      p->size_dl = 0;
      p->dl_known = 0;
    }
  twist_progress_update (easy);
}

void
twist_progress_ul_size (struct twist_easy *easy, long long size)
{
  struct twist_progress *p = &easy->progress;

  if (size >= 0)
    {
      p->size_ul = size;
      p->ul_known = 1;
    }
  else
    {
      p->size_ul = 0;
      p->ul_known = 0;
    }
  twist_progress_update (easy);
}

void
twist_progress_downloaded (struct twist_easy *easy, size_t n)
{
  easy->progress.downloaded += (long long) n;
  twist_progress_update (easy);
}

void
twist_easy_downloaded (struct twist_easy *easy, size_t n)
{
  easy->size_download += n;
  twist_progress_downloaded (easy, n);
}

long long
twist_easy_upload_size (const struct twist_easy *easy)
{
  if (easy->postfields != NULL)
    return easy->postfieldsize_set && easy->postfieldsize >= 0
      ? (long long) easy->postfieldsize : (long long) strlen (easy->postfields);
  return easy->infilesize >= 0 ? easy->infilesize : -1;
}

void
twist_progress_uploaded (struct twist_easy *easy, size_t n)
{
  easy->progress.uploaded += (long long) n;
  twist_progress_update (easy);
}
