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

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>

/* One chunk is in flight.  The worker blocks until the loop has written
   it, so a slow body callback holds the worker rather than the reactor
   and rather than the rest of the file.  */

#define FILE_CHUNK 16384

struct twist_file
{
  struct twist_easy *easy;
  pthread_mutex_t mu;
  pthread_cond_t cv;
  int live;
  int acked;
  int stop;
  int final_note;
  int note_err;
  char *data;
  size_t len;
  char *errmsg;
  size_t total;
  int err;
};

static void
file_free (void *p)
{
  struct twist_file *f = p;

  if (f == NULL)
    return;
  pthread_mutex_lock (&f->mu);
  while (f->live)
    pthread_cond_wait (&f->cv, &f->mu);
  pthread_mutex_unlock (&f->mu);
  pthread_cond_destroy (&f->cv);
  pthread_mutex_destroy (&f->mu);
  free (f->data);
  free (f->errmsg);
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
  struct twist_file *f = user;
  struct twist_easy *easy = f->easy;
  int err = f->note_err;

  if (f->data != NULL && f->len > 0 && f->err == TWIST_OK && err == TWIST_OK
      && easy->write_cb != NULL)
    {
      size_t got = easy->write_cb (f->data, 1, f->len, easy->write_data);

      if (got < f->len)
        err = TWIST_ERR_ABORTED;
      else
        f->total += f->len;
    }
  free (f->data);
  f->data = NULL;
  if (err != TWIST_OK && f->err == TWIST_OK)
    f->err = err;
  if (f->errmsg != NULL)
    {
      if (f->err != TWIST_OK)
        twist_easy_set_error (easy, f->errmsg);
      else
        free (f->errmsg);
      f->errmsg = NULL;
    }
  if (f->final_note)
    {
      if (f->err == TWIST_OK)
        easy->size_download = f->total;
      twist_easy_finish (easy, f->err);
    }
  pthread_mutex_lock (&f->mu);
  f->acked = 1;
  if (f->err != TWIST_OK)
    f->stop = 1;
  pthread_cond_signal (&f->cv);
  pthread_mutex_unlock (&f->mu);
}

static int
hand_off (struct twist_file *f, char *data, size_t len, int err, char *msg,
          int final_note)
{
  int rc;

  f->data = data;
  f->len = len;
  f->note_err = err;
  f->errmsg = msg;
  f->final_note = final_note;
  f->acked = 0;
  rc = twist_loop_post (f->easy->loop, file_on_loop, f);
  if (rc != TWIST_OK)
    {
      free (data);
      free (msg);
      f->data = NULL;
      f->errmsg = NULL;
      return rc;
    }
  pthread_mutex_lock (&f->mu);
  while (!f->acked)
    pthread_cond_wait (&f->cv, &f->mu);
  pthread_mutex_unlock (&f->mu);
  return f->stop ? f->err : TWIST_OK;
}

static void
file_retire (struct twist_file *f)
{
  pthread_mutex_lock (&f->mu);
  f->live = 0;
  pthread_cond_signal (&f->cv);
  pthread_mutex_unlock (&f->mu);
}

static void
file_work (void *arg)
{
  struct twist_file *f = arg;
  const char *path = f->easy->url->path;
  FILE *fp;
  struct stat st;
  int err = TWIST_OK;
  char *msg = NULL;

  fp = fopen (path, "rb");
  if (fp == NULL)
    {
      err = TWIST_ERR_FILE;
      msg = file_errmsg (path, 0);
      goto done;
    }
  if (fstat (fileno (fp), &st) != 0 || !S_ISREG (st.st_mode))
    {
      err = TWIST_ERR_FILE;
      msg = file_errmsg (path, 0);
      goto done;
    }
  for (;;)
    {
      char buf[FILE_CHUNK];
      size_t n = fread (buf, 1, sizeof buf, fp);
      char *copy;

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
      if (n < sizeof buf)
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
