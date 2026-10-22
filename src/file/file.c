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

#include "gettext.h"
#include "twist-int.h"

#include <ctype.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

/* Four chunks may be in flight.  The worker waits only when that
   pipeline is full, and it stops when the easy aborts.  The worker
   owns the file until the last ack, so the loop cannot free it early.

   The loop's thread acknowledges the chunks the worker posts.  When the
   transfer is let go of before it is done, that same thread is the one that
   waits for the worker to retire, so it has to acknowledge the chunks itself
   while it waits: the worker can be waiting for room to post another.  A
   transfer that has been let go of delivers nothing to the application and
   tells the multi handle nothing.  */

#define FILE_CHUNK 16384
#define FILE_PIPELINE 4

struct file_chunk
{
  struct twist_file *file;
  char *data;
  size_t len;
  int err;
  char *errmsg;
  int final_note;
  int busy;
};

struct twist_file
{
  struct twist_easy *easy;
  pthread_mutex_t mu;
  pthread_cond_t cv;
  int live;
  int stop;
  int abandoned;
  int inflight;
  size_t total;
  long long size;		/* From the worker, under MU.  */
  int size_known;
  int size_noted;
  int err;
  /* The path, percent-decoded, and the range asked for: both made on the
     loop's thread, for the worker.  RANGE_MODE is 0 for none, 1 for A-B or A-
     (RANGE_END -1: to the end), 2 for the last RANGE_END bytes.  */
  char *path;
  int range_mode;
  long long range_start;
  long long range_end;
  struct file_chunk slot[FILE_PIPELINE];
};

static void
file_free (void *p)
{
  struct twist_file *f = p;
  struct twist_loop *loop;

  if (f == NULL)
    return;
  loop = f->easy != NULL ? f->easy->loop : NULL;
  pthread_mutex_lock (&f->mu);
  f->abandoned = 1;
  f->stop = 1;
  pthread_cond_broadcast (&f->cv);
  while (f->live)
    {
      struct timespec until;

      /* Acknowledge what the worker has posted: it may be waiting for room.  */
      pthread_mutex_unlock (&f->mu);
      if (loop != NULL)
        twist_loop_drain (loop);
      pthread_mutex_lock (&f->mu);
      if (!f->live)
        break;
      clock_gettime (CLOCK_REALTIME, &until);
      until.tv_nsec += 1000000;
      if (until.tv_nsec >= 1000000000)
        {
          until.tv_sec++;
          until.tv_nsec -= 1000000000;
        }
      pthread_cond_timedwait (&f->cv, &f->mu, &until);
    }
  pthread_mutex_unlock (&f->mu);
  pthread_cond_destroy (&f->cv);
  pthread_mutex_destroy (&f->mu);
  free (f->path);
  free (f);
}

int
twist_file_check_url (const char *host, const char *path, int path_set)
{
  if (!path_set || path == NULL || path[0] != '/')
    return TWIST_ERR_URL;
  if (host == NULL || host[0] == 0)
    return TWIST_OK;
  if (strcasecmp (host, "localhost") == 0 || strcmp (host, "127.0.0.1") == 0)
    return TWIST_OK;
  return TWIST_ERR_URL;
}

static char *
file_errmsg (const char *path, int reading)
{
  const char *fmt = reading ? _("could not read file %s")
                            : _("could not open file %s");
  size_t n = strlen (fmt) + strlen (path) + 1;
  char *msg = twist_xmalloc (n);

  if (msg == NULL)
    return NULL;
  if (reading)
    snprintf (msg, n, _("could not read file %s"), path);
  else
    snprintf (msg, n, _("could not open file %s"), path);
  return msg;
}

static void
file_on_loop (void *user)
{
  struct file_chunk *c = user;
  struct twist_file *f = c->file;
  struct twist_easy *easy = f->easy;
  int err = c->err;

  if (f->abandoned)
    {
      /* Let go of: nothing is for the application or the multi handle now.  */
      free (c->data);
      free (c->errmsg);
      c->data = NULL;
      c->errmsg = NULL;
      pthread_mutex_lock (&f->mu);
      c->busy = 0;
      if (f->inflight > 0)
        f->inflight--;
      pthread_cond_broadcast (&f->cv);
      pthread_mutex_unlock (&f->mu);
      return;
    }
  if (!f->size_noted)
    {
      long long size = -1;

      pthread_mutex_lock (&f->mu);
      if (f->size_known)
        size = f->size;
      pthread_mutex_unlock (&f->mu);
      if (size >= 0)
        {
          f->size_noted = 1;
          twist_progress_dl_size (easy, size);
        }
    }
  if (c->data != NULL && c->len > 0 && f->err == TWIST_OK && err == TWIST_OK
      && easy->write_cb != NULL)
    {
      size_t got = easy->write_cb (c->data, 1, c->len, easy->write_data);

      if (got < c->len)
        err = TWIST_ERR_ABORTED;
      else
        {
          f->total += c->len;
          twist_progress_downloaded (easy, c->len);
        }
    }
  free (c->data);
  c->data = NULL;
  if (err != TWIST_OK && f->err == TWIST_OK)
    f->err = err;
  if (c->errmsg != NULL)
    {
      if (f->err != TWIST_OK)
        twist_easy_set_error (easy, c->errmsg);
      else
        free (c->errmsg);
      c->errmsg = NULL;
    }
  if (c->final_note)
    {
      if (f->err == TWIST_OK)
        easy->size_download = f->total;
      twist_easy_finish (easy, f->err);
    }
  pthread_mutex_lock (&f->mu);
  c->busy = 0;
  if (f->inflight > 0)
    f->inflight--;
  if (f->err != TWIST_OK)
    f->stop = 1;
  pthread_cond_broadcast (&f->cv);
  pthread_mutex_unlock (&f->mu);
}

static int
hand_off (struct twist_file *f, char *data, size_t len, int err, char *msg,
          int final_note)
{
  struct file_chunk *c = NULL;
  int i;
  int rc;

  pthread_mutex_lock (&f->mu);
  for (;;)
    {
      /* A stop is looked for before waiting for room, not only after: the
         one that wants it may be waiting for this thread.  */
      if (f->stop && !final_note)
        {
          int why = f->err != TWIST_OK ? f->err : TWIST_ERR_ABORTED;

          pthread_mutex_unlock (&f->mu);
          free (data);
          free (msg);
          return why;
        }
      if (f->inflight < FILE_PIPELINE)
        break;
      pthread_cond_wait (&f->cv, &f->mu);
    }
  for (i = 0; i < FILE_PIPELINE; i++)
    if (!f->slot[i].busy)
      {
        c = &f->slot[i];
        c->busy = 1;
        break;
      }
  if (c == NULL)
    {
      pthread_mutex_unlock (&f->mu);
      free (data);
      free (msg);
      return TWIST_ERR_NOMEM;
    }
  f->inflight++;
  pthread_mutex_unlock (&f->mu);
  c->file = f;
  c->data = data;
  c->len = len;
  c->err = err;
  c->errmsg = msg;
  c->final_note = final_note;
  rc = twist_loop_post (f->easy->loop, file_on_loop, c);
  if (rc != TWIST_OK)
    {
      free (data);
      free (msg);
      c->data = NULL;
      c->errmsg = NULL;
      pthread_mutex_lock (&f->mu);
      c->busy = 0;
      if (f->inflight > 0)
        f->inflight--;
      pthread_cond_broadcast (&f->cv);
      pthread_mutex_unlock (&f->mu);
      return rc;
    }
  return TWIST_OK;
}

static void
file_drain (struct twist_file *f)
{
  pthread_mutex_lock (&f->mu);
  while (f->inflight > 0)
    pthread_cond_wait (&f->cv, &f->mu);
  pthread_mutex_unlock (&f->mu);
}

static void
file_retire (struct twist_file *f)
{
  pthread_mutex_lock (&f->mu);
  f->live = 0;
  pthread_cond_broadcast (&f->cv);
  pthread_mutex_unlock (&f->mu);
}

/* The percent-decoded path, in memory of its own; NULL if it holds a NUL,
   which is no part of a name, or there is no memory.  An escape that is not
   two hex digits is left as it is.  */
static char *
decode_path (const char *in, int *nul)
{
  size_t n = strlen (in);
  char *out = twist_xmalloc (n + 1);
  size_t i;
  size_t o = 0;

  *nul = 0;
  if (out == NULL)
    return NULL;
  for (i = 0; i < n; i++)
    {
      unsigned char c = (unsigned char) in[i];

      if (c == '%' && i + 2 < n && isxdigit ((unsigned char) in[i + 1])
          && isxdigit ((unsigned char) in[i + 2]))
        {
          int hi = (unsigned char) in[i + 1];
          int lo = (unsigned char) in[i + 2];

          hi = isdigit (hi) ? hi - '0' : tolower (hi) - 'a' + 10;
          lo = isdigit (lo) ? lo - '0' : tolower (lo) - 'a' + 10;
          c = (unsigned char) ((hi << 4) | lo);
          i += 2;
        }
      if (c == 0)
        {
          *nul = 1;
          free (out);
          return NULL;
        }
      out[o++] = (char) c;
    }
  out[o] = 0;
  return out;
}

/* A number of only digits, not past what a file can be.  */
static int
range_number (const char *s, size_t n, long long *out)
{
  long long v = 0;
  size_t i;

  if (n == 0 || n > 18)
    return -1;
  for (i = 0; i < n; i++)
    {
      if (s[i] < '0' || s[i] > '9')
        return -1;
      v = v * 10 + (s[i] - '0');
    }
  *out = v;
  return 0;
}

/* "A-B", "A-" or "-N", one range, as -r gives it.  */
static int
parse_range (const char *r, struct twist_file *f)
{
  const char *dash = strchr (r, '-');
  size_t len = strlen (r);

  if (dash == NULL || strchr (r, ',') != NULL)
    return TWIST_ERR_RANGE;
  if (dash == r)
    {
      if (range_number (r + 1, len - 1, &f->range_end) != 0
          || f->range_end == 0)
        return TWIST_ERR_RANGE;
      f->range_mode = 2;
      return TWIST_OK;
    }
  if (range_number (r, (size_t) (dash - r), &f->range_start) != 0)
    return TWIST_ERR_RANGE;
  f->range_end = -1;
  if (dash[1] != 0
      && (range_number (dash + 1, len - (size_t) (dash - r) - 1,
                        &f->range_end) != 0 || f->range_end < f->range_start))
    return TWIST_ERR_RANGE;
  f->range_mode = 1;
  return TWIST_OK;
}

static void
file_work (void *arg)
{
  struct twist_file *f = arg;
  const char *path = f->path;
  FILE *fp = NULL;
  int fd;
  struct stat st;
  int err = TWIST_OK;
  char *msg = NULL;
  long long start = 0;
  long long left;

  /* Not blocking, so that a FIFO with nobody at the other end, or the like,
     is looked at and refused and not waited on: the loop waits for this
     thread when the transfer is let go of, and --max-time could not end it.
     A regular file does not mind.  */
  fd = open (path, O_RDONLY | O_NONBLOCK | O_CLOEXEC);
  if (fd < 0)
    {
      err = TWIST_ERR_FILE;
      msg = file_errmsg (path, 0);
      goto done;
    }
  if (fstat (fd, &st) != 0 || !S_ISREG (st.st_mode))
    {
      close (fd);
      err = TWIST_ERR_FILE;
      msg = file_errmsg (path, 0);
      goto done;
    }
  fp = fdopen (fd, "rb");
  if (fp == NULL)
    {
      close (fd);
      err = TWIST_ERR_FILE;
      msg = file_errmsg (path, 0);
      goto done;
    }
  left = (long long) st.st_size;
  if (f->range_mode == 1)
    {
      start = f->range_start;
      if (start >= left)
        {
          err = TWIST_ERR_RANGE;
          goto done;
        }
      if (f->range_end >= 0 && f->range_end < left - 1)
        left = f->range_end + 1;
      left -= start;
    }
  else if (f->range_mode == 2)
    {
      start = f->range_end < left ? left - f->range_end : 0;
      left -= start;
    }
  if (start > 0 && fseeko (fp, (off_t) start, SEEK_SET) != 0)
    {
      err = TWIST_ERR_FILE;
      msg = file_errmsg (path, 1);
      goto done;
    }
  pthread_mutex_lock (&f->mu);
  f->size = left;
  f->size_known = 1;
  pthread_mutex_unlock (&f->mu);
  while (left > 0)
    {
      char buf[FILE_CHUNK];
      size_t want = left < (long long) sizeof buf ? (size_t) left : sizeof buf;
      size_t n = fread (buf, 1, want, fp);
      char *copy;

      left -= (long long) n;

      pthread_mutex_lock (&f->mu);
      if (f->stop)
        {
          pthread_mutex_unlock (&f->mu);
          break;
        }
      pthread_mutex_unlock (&f->mu);
      if (n > 0)
        {
          copy = twist_xmalloc (n);
          if (copy == NULL)
            {
              err = TWIST_ERR_NOMEM;
              break;
            }
          memcpy (copy, buf, n);
          if (hand_off (f, copy, n, TWIST_OK, NULL, 0) != TWIST_OK)
            {
              err = f->err != TWIST_OK ? f->err : TWIST_ERR_ABORTED;
              break;
            }
        }
      if (n < want)
        {
          if (ferror (fp))
            {
              err = TWIST_ERR_FILE;
              msg = file_errmsg (path, 1);
            }
          break;
        }
    }
done:
  if (fp != NULL)
    fclose (fp);
  if (hand_off (f, NULL, 0, err, msg, 1) != TWIST_OK && f->err == TWIST_OK)
    twist_easy_finish (f->easy, err != TWIST_OK ? err : TWIST_ERR_NOMEM);
  file_drain (f);
  file_retire (f);
}

int
twist_file_attach (struct twist_easy *easy)
{
  struct twist_file *f;
  const char *host;
  const char *path;
  int rc;

  if (easy == NULL || easy->url == NULL || easy->loop == NULL
      || easy->multi == NULL || easy->multi->storage == NULL)
    return TWIST_ERR_INVAL;
  host = easy->url->host;
  path = easy->url->path;
  rc = twist_file_check_url (host, path, easy->url->path_set);
  if (rc != TWIST_OK)
    return rc;
  f = calloc (1, sizeof *f);
  if (f == NULL)
    return TWIST_ERR_NOMEM;
  if (pthread_mutex_init (&f->mu, NULL) != 0)
    {
      free (f);
      return TWIST_ERR_NOMEM;
    }
  if (pthread_cond_init (&f->cv, NULL) != 0)
    {
      pthread_mutex_destroy (&f->mu);
      free (f);
      return TWIST_ERR_NOMEM;
    }
  f->easy = easy;
  f->live = 1;
  {
    int nul = 0;

    f->path = decode_path (path, &nul);
    if (f->path == NULL)
      {
        pthread_cond_destroy (&f->cv);
        pthread_mutex_destroy (&f->mu);
        free (f);
        return nul ? TWIST_ERR_URL : TWIST_ERR_NOMEM;
      }
  }
  if (easy->range != NULL && easy->range[0] != 0)
    {
      rc = parse_range (easy->range, f);
      if (rc != TWIST_OK)
        {
          pthread_cond_destroy (&f->cv);
          pthread_mutex_destroy (&f->mu);
          free (f->path);
          free (f);
          return rc;
        }
    }
  easy->xfer = f;
  easy->xfer_free = file_free;
  rc = twist_storage_submit (easy->multi->storage, file_work, f, NULL, NULL,
                             NULL);
  if (rc != TWIST_OK)
    {
      easy->xfer = NULL;
      easy->xfer_free = NULL;
      f->live = 0;
      file_free (f);
      return rc;
    }
  return TWIST_OK;
}
