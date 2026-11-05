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

#include <stdlib.h>
#include <string.h>

/* The upload of a transfer as a push source (see twist-int.h), and the
   adapter that makes one of the application's read callback.  */

struct twist_upload
{
  struct twist_upload_producer prod;
  void *prod_user;
  struct twist_upload_consumer cons;
  void *cons_user;
  int attached;
  int paused;
  int finished;
  size_t max;
};

struct twist_upload *
twist_upload_new (const struct twist_upload_producer *p, void *user)
{
  struct twist_upload *up = calloc (1, sizeof *up);

  if (up == NULL)
    return NULL;
  up->prod = *p;
  up->prod_user = user;
  return up;
}

void
twist_upload_free (struct twist_upload *up)
{
  if (up == NULL)
    return;
  if (up->prod.release != NULL)
    up->prod.release (up->prod_user);
  free (up);
}

int
twist_upload_attach (struct twist_upload *up,
                     const struct twist_upload_consumer *c, void *user,
                     size_t max)
{
  if (up == NULL || c == NULL || up->attached)
    return TWIST_ERR_INVAL;
  up->cons = *c;
  up->cons_user = user;
  up->attached = 1;
  up->paused = 0;
  up->finished = 0;
  up->max = max > 0 ? max : 16384;
  return TWIST_OK;
}

void
twist_upload_detach (struct twist_upload *up)
{
  if (up == NULL)
    return;
  up->attached = 0;
  up->paused = 1;
}

int
twist_upload_active (const struct twist_upload *up)
{
  return up != NULL && up->attached && !up->paused && !up->finished;
}

size_t
twist_upload_max (const struct twist_upload *up)
{
  return up != NULL ? up->max : 0;
}

void
twist_upload_pause (struct twist_upload *up)
{
  if (up == NULL || !up->attached || up->paused)
    return;
  up->paused = 1;
  if (up->prod.pause != NULL)
    up->prod.pause (up->prod_user);
}

void
twist_upload_resume (struct twist_upload *up)
{
  if (up == NULL || !up->attached || up->finished)
    return;
  up->paused = 0;
  if (up->prod.resume != NULL)
    up->prod.resume (up->prod_user);
}

int
twist_upload_push (struct twist_upload *up, const uint8_t *data, size_t len)
{
  int rc;

  if (up == NULL || !up->attached || up->finished)
    return TWIST_ERR_INVAL;
  rc = up->cons.chunk (up->cons_user, data, len);
  if (rc != TWIST_OK)
    twist_upload_finish (up, rc);
  return rc;
}

void
twist_upload_finish (struct twist_upload *up, int err)
{
  if (up == NULL || !up->attached || up->finished)
    return;
  up->finished = 1;
  up->cons.end (up->cons_user, err);
}

int
twist_upload_restart (struct twist_upload *up)
{
  if (up == NULL || up->prod.restart == NULL)
    return TWIST_ERR_REWIND;
  if (up->prod.restart (up->prod_user) != 0)
    return TWIST_ERR_REWIND;
  up->finished = 0;
  return TWIST_OK;
}

/* ---- the adapter over the read callback ---- */

struct read_adapter
{
  struct twist_transfer *transfer;
  struct twist_upload *up;
  int running;
  uint8_t buf[16384];
};

/* Call the application's callback, on the loop's thread, while the consumer
   has not paused the source: a callback that returns at once is read as fast
   as the consumer takes it.  A resume from inside a push does not begin
   another loop; the one that is running goes on.  */
static void
adapter_resume (void *user)
{
  struct read_adapter *a = user;
  struct twist_transfer *t = a->transfer;

  if (a->running)
    return;
  if (t->read_cb == NULL)
    {
      twist_upload_finish (a->up, TWIST_ERR_ABORTED);
      return;
    }
  a->running = 1;
  while (twist_upload_active (a->up))
    {
      size_t want = twist_upload_max (a->up);
      size_t n;

      if (want > sizeof a->buf)
        want = sizeof a->buf;
      n = t->read_cb ((char *) a->buf, 1, want, t->read_data);
      if (n == TWIST_READFUNC_ABORT || n > want)
        {
          twist_upload_finish (a->up, TWIST_ERR_ABORTED);
          break;
        }
      if (n == 0)
        {
          twist_upload_finish (a->up, TWIST_OK);
          break;
        }
      if (twist_upload_push (a->up, a->buf, n) != TWIST_OK)
        break;
    }
  a->running = 0;
}

static void
adapter_pause (void *user)
{
  (void) user;
}

static int
adapter_restart (void *user)
{
  struct read_adapter *a = user;
  struct twist_transfer *t = a->transfer;

  if (t->seek_cb == NULL || t->seek_cb (t->seek_data, 0, 0) != 0)
    return -1;
  return 0;
}

static void
adapter_release (void *user)
{
  free (user);
}

static const struct twist_upload_producer adapter_ops = {
  adapter_resume, adapter_pause, adapter_restart, adapter_release
};

struct twist_upload *
twist_transfer_upload (struct twist_transfer *t)
{
  struct read_adapter *a;

  if (t == NULL)
    return NULL;
  if (t->upload != NULL)
    return t->upload;
  if (t->read_cb == NULL)
    return NULL;
  a = calloc (1, sizeof *a);
  if (a == NULL)
    return NULL;
  a->transfer = t;
  a->up = twist_upload_new (&adapter_ops, a);
  if (a->up == NULL)
    {
      free (a);
      return NULL;
    }
  t->upload = a->up;
  return a->up;
}
