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

/* The progress meter: the counters, the
   once-a-second arithmetic of the current speed, and the line

     % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                    Dload  Upload   Total   Spent    Left  Speed
   100  5000  100  5000    0     0  7443k      0 --:--:-- --:--:-- --:--:-- 4882k

   The line is rewritten in place with a carriage return, and is drawn when
   the second has changed, and once more when the transfer is done.  The
   tool's bar is a callback (src/bar.c) and is not drawn here.

   The clock is the loop's, so that a test can set it.  A timer asks for an
   update when a second has passed with none, so that a transfer that is
   waiting is still drawn.  Every update puts the timer off by a second again, which
   is done by moving the due time, not the timer.  */

#define TICK_MS 1000u

#define KILO 1024LL
#define MEGA (1024LL * KILO)
#define GIGA (1024LL * MEGA)
#define TERA (1024LL * GIGA)
#define PETA (1024LL * TERA)

/* A number is written into a buffer that holds what its column does, and the
   rest is cut: a number that is too wide for its column loses its end.  */
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

/* Adds two counts that are not negative, and stops at the largest number
   where the sum would be past it.  */
static long long
sum_up (long long a, long long b)
{
  if (a > LLONG_MAX - b)
    return LLONG_MAX;
  return a + b;
}

/* A count of bytes over a span of microseconds, as bytes a second.  A span
   that is not there yet makes it the count of a whole second's worth, and a
   count too large to be scaled to microseconds is divided over whole seconds
   instead.  */
static long long
per_second (long long bytes, long long span_us)
{
  if (bytes <= 0)
    return 0;
  if (span_us < 1)
    return bytes > LLONG_MAX / 1000000LL ? LLONG_MAX : bytes * 1000000LL;
  if (bytes <= LLONG_MAX / 1000000LL)
    return bytes * 1000000LL / span_us;
  if (span_us >= 1000000LL)
    return bytes / (span_us / 1000000LL);
  return LLONG_MAX;
}

/* How much of WHOLE is PART, in percent.  A large whole is divided first,
   so that the product cannot overflow.  */
static long long
percent_of (long long part, long long whole)
{
  if (whole > 10000)
    return part / (whole / 100);
  if (whole > 0)
    return part * 100 / whole;
  return 0;
}

char *
twist_progress_max5 (long long bytes, char *buf)
{
  char text[32];

  if (bytes < 100000LL)
    snprintf (text, sizeof text, "%5lld", bytes);
  else if (bytes < 10000 * KILO)
    snprintf (text, sizeof text, "%4lldk", bytes / KILO);
  else if (bytes < 100 * MEGA)
    snprintf (text, sizeof text, "%2lld.%lldM", bytes / MEGA,
              (bytes % MEGA) / (MEGA / 10));
  else if (bytes < 10000 * MEGA)
    snprintf (text, sizeof text, "%4lldM", bytes / MEGA);
  else if (bytes < 100 * GIGA)
    snprintf (text, sizeof text, "%2lld.%lldG", bytes / GIGA,
              (bytes % GIGA) / (GIGA / 10));
  else if (bytes < 10000 * GIGA)
    snprintf (text, sizeof text, "%4lldG", bytes / GIGA);
  else if (bytes < 10000 * TERA)
    snprintf (text, sizeof text, "%4lldT", bytes / TERA);
  else
    snprintf (text, sizeof text, "%4lldP", bytes / PETA);
  return fit (buf, 6, text);
}

char *
twist_progress_time2str (long long seconds, char *buf)
{
  char text[32];
  long long hours = seconds / 3600;

  if (seconds <= 0)
    return fit (buf, 9, "--:--:--");
  if (hours <= 99)
    snprintf (text, sizeof text, "%2lld:%02lld:%02lld", hours,
              (seconds % 3600) / 60, seconds % 60);
  else if (seconds / 86400 <= 999)
    snprintf (text, sizeof text, "%3lldd %02lldh", seconds / 86400,
              hours % 24);
  else
    snprintf (text, sizeof text, "%7lldd", seconds / 86400);
  return fit (buf, 9, text);
}

/* Takes the averages up to NOW_MS, and, if the line is to be drawn, the
   speed of the last few draws.  Returns 1 if the second has changed since the
   last draw.  */
static int
refresh (struct twist_progress *p, uint64_t now_ms)
{
  long long second = (long long) (now_ms / 1000u);
  long long total;
  unsigned draws;

  p->timespent_us = (long long) (now_ms - p->start_ms) * 1000LL;
  p->dlspeed = per_second (p->downloaded, p->timespent_us);
  p->ulspeed = per_second (p->uploaded, p->timespent_us);
  if (second == p->lastshow)
    return 0;
  p->lastshow = second;

  total = sum_up (p->downloaded, p->uploaded);
  p->hist_bytes[p->draws % TWIST_PROGRESS_HISTORY] = total;
  p->hist_ms[p->draws % TWIST_PROGRESS_HISTORY] = now_ms;
  p->draws++;
  draws = p->draws;
  if (draws < 2)
    p->current_speed = sum_up (p->dlspeed, p->ulspeed);
  else
    {
      /* The oldest entry still kept: the next to be overwritten once the
         history is full.  */
      unsigned oldest = draws >= TWIST_PROGRESS_HISTORY
        ? draws % TWIST_PROGRESS_HISTORY : 0;
      long long span = (long long) (now_ms - p->hist_ms[oldest]);
      long long amount = total - p->hist_bytes[oldest];

      if (span < 1)
        span = 1;
      if (amount > 4294967LL)
        p->current_speed = (long long) ((double) amount * 1000.0
                                        / (double) span);
      else
        p->current_speed = amount * 1000LL / span;
    }
  return 1;
}

/* The line, with the heading above the first.  */
static void
draw_line (struct twist_transfer *transfer)
{
  struct twist_progress *p = &transfer->progress;
  FILE *out = p->err != NULL ? p->err : stderr;
  long long dl_est = 0;
  long long ul_est = 0;
  long long dl_pct = 0;
  long long ul_pct = 0;
  long long est;
  long long spent;
  long long left;
  long long expected;
  long long moved;
  char total_size[16], dl_count[16], ul_count[16];
  char dl_avg[16], ul_avg[16], speed[16];
  char est_time[16], spent_time[16], left_time[16];

  if (!p->headers_out)
    {
      if (transfer->resume_from > 0)
        fprintf (out, "** Resuming transfer from byte position %lld\n",
                 transfer->resume_from);
      fputs ("  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current\n"
             "                                 Dload  Upload   Total   Spent    Left  Speed\n",
             out);
      p->headers_out = 1;
    }
  p->shown = 1;

  if (p->ul_known && p->ulspeed > 0)
    {
      ul_est = p->size_ul / p->ulspeed;
      ul_pct = percent_of (p->uploaded, p->size_ul);
    }
  if (p->dl_known && p->dlspeed > 0)
    {
      dl_est = p->size_dl / p->dlspeed;
      dl_pct = percent_of (p->downloaded, p->size_dl);
    }
  est = ul_est > dl_est ? ul_est : dl_est;
  spent = p->timespent_us / 1000000LL;
  left = est > 0 ? est - spent : 0;
  expected = sum_up (p->ul_known ? p->size_ul : p->uploaded,
                     p->dl_known ? p->size_dl : p->downloaded);
  moved = sum_up (p->downloaded, p->uploaded);

  fprintf (out, "\r%3lld %s  %3lld %s  %3lld %s  %s  %s %s %s %s %s",
           percent_of (moved, expected),
           twist_progress_max5 (expected, total_size),
           dl_pct, twist_progress_max5 (p->downloaded, dl_count),
           ul_pct, twist_progress_max5 (p->uploaded, ul_count),
           twist_progress_max5 (p->dlspeed, dl_avg),
           twist_progress_max5 (p->ulspeed, ul_avg),
           twist_progress_time2str (est, est_time),
           twist_progress_time2str (spent, spent_time),
           twist_progress_time2str (left, left_time),
           twist_progress_max5 (p->current_speed, speed));
  fflush (out);
}

static void
arm (struct twist_transfer *transfer);

static void
tick (void *user)
{
  struct twist_transfer *transfer = user;

  transfer->progress.tick = NULL;
  if (!transfer->progress.begun)
    return;
  /* Something has happened since the timer was set: not yet.  */
  if (transfer->loop != NULL && twist_loop_now (transfer->loop) < transfer->progress.tick_due)
    {
      arm (transfer);
      return;
    }
  twist_progress_update (transfer);
  /* The update may have ended the transfer.  */
  if (transfer->progress.begun)
    arm (transfer);
}

static void
arm (struct twist_transfer *transfer)
{
  struct twist_progress *p = &transfer->progress;

  if (transfer->loop == NULL || p->tick != NULL)
    return;
  twist_loop_schedule (transfer->loop, p->tick_due, tick, transfer, &p->tick);
}

void
twist_progress_release (struct twist_transfer *transfer)
{
  struct twist_progress *p = &transfer->progress;

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
twist_progress_update (struct twist_transfer *transfer)
{
  struct twist_progress *p = &transfer->progress;
  int show;

  if (!p->begun || p->hide || transfer->loop == NULL)
    return 0;
  show = refresh (p, twist_loop_now (transfer->loop));
  p->tick_due = twist_loop_now (transfer->loop) + TICK_MS;
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
              if (!transfer->done)
                {
                  twist_transfer_set_error (transfer, twist_strdup (_("callback aborted")));
                  twist_transfer_finish (transfer, TWIST_ERR_ABORTED);
                }
            }
          return r;
        }
    }
  if (show)
    draw_line (transfer);
  return 0;
}

/* The forced last update of a transfer or of one hop of it, and the end of
   its line.  A callback is left to end its own.  */
static void
finish_line (struct twist_transfer *transfer)
{
  struct twist_progress *p = &transfer->progress;

  p->lastshow = -1;
  if (twist_progress_update (transfer) != 0)
    return;
  if (!p->hide && p->xferinfo == NULL)
    fputc ('\n', p->err != NULL ? p->err : stderr);
  p->draws = 0;
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

/* A file that is not there draws nothing: the heading would
   be all there was.  */
static int
quiet_scheme (const struct twist_transfer *transfer)
{
  return transfer->url != NULL && transfer->url->scheme != NULL
    && strcmp (transfer->url->scheme, "file") == 0;
}

void
twist_progress_begin (struct twist_transfer *transfer)
{
  struct twist_progress *p = &transfer->progress;

  twist_progress_release (transfer);
  reset_counters (p);
  p->aborted = 0;
  p->shown = 0;
  p->headers_out = 0;
  p->lastshow = -1;
  p->draws = 0;
  p->begun = 1;
  if (transfer->loop != NULL)
    p->start_ms = twist_loop_now (transfer->loop);
  if (p->hide)
    return;
  p->tick_due = (transfer->loop != NULL ? twist_loop_now (transfer->loop) : 0) + TICK_MS;
  arm (transfer);
  if (!quiet_scheme (transfer))
    twist_progress_update (transfer);
}

void
twist_progress_end (struct twist_transfer *transfer, int result)
{
  struct twist_progress *p = &transfer->progress;

  if (!p->begun)
    return;
  if (!(result != TWIST_OK && !p->shown && quiet_scheme (transfer)))
    finish_line (transfer);
  twist_progress_release (transfer);
}

/* A redirect: this response is done and the next request is another.  */
void
twist_progress_hop (struct twist_transfer *transfer)
{
  struct twist_progress *p = &transfer->progress;

  if (!p->begun)
    return;
  finish_line (transfer);
  reset_counters (p);
}

void
twist_progress_dl_size (struct twist_transfer *transfer, long long size)
{
  struct twist_progress *p = &transfer->progress;

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
  twist_progress_update (transfer);
}

void
twist_progress_ul_size (struct twist_transfer *transfer, long long size)
{
  struct twist_progress *p = &transfer->progress;

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
  twist_progress_update (transfer);
}

void
twist_progress_downloaded (struct twist_transfer *transfer, size_t n)
{
  transfer->progress.downloaded += (long long) n;
  twist_progress_update (transfer);
}

void
twist_transfer_downloaded (struct twist_transfer *transfer, size_t n)
{
  transfer->size_download += n;
  twist_progress_downloaded (transfer, n);
}

long long
twist_transfer_upload_size (const struct twist_transfer *transfer)
{
  if (transfer->postfields != NULL)
    return transfer->postfieldsize_set && transfer->postfieldsize >= 0
      ? (long long) transfer->postfieldsize : (long long) strlen (transfer->postfields);
  return transfer->infilesize >= 0 ? transfer->infilesize : -1;
}

void
twist_progress_uploaded (struct twist_transfer *transfer, size_t n)
{
  transfer->progress.uploaded += (long long) n;
  twist_progress_update (transfer);
}
