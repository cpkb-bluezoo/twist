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

#include <pthread.h>
#include <stdlib.h>

struct twist_storage
{
  pthread_mutex_t mu;
  pthread_cond_t cv;
  struct twist_job *head;
  struct twist_job *tail;
  size_t len;
  size_t bound;
  int inline_mode;
  int stop;
  pthread_t *threads;
  size_t nthreads;
};

struct twist_job
{
  void (*work) (void *);
  void *arg;
  void (*done) (void *user, int err);
  void *user;
  struct twist_loop *loop;
  struct twist_job *next;
};

struct twist_done
{
  void (*done) (void *, int);
  void *user;
  int err;
};

static void
done_on_loop (void *user)
{
  struct twist_done *d = user;
  d->done (d->user, d->err);
  free (d);
}

static void
finish_job (struct twist_job *job, int err)
{
  struct twist_done *d;

  if (job->done == NULL)
    return;
  if (job->loop == NULL)
    {
      job->done (job->user, err);
      return;
    }
  d = calloc (1, sizeof *d);
  if (d == NULL)
    return;
  d->done = job->done;
  d->user = job->user;
  d->err = err;
  twist_loop_post (job->loop, done_on_loop, d);
}

static void *
worker (void *arg)
{
  struct twist_storage *st = arg;

  for (;;)
    {
      struct twist_job *job;

      pthread_mutex_lock (&st->mu);
      while (st->head == NULL && !st->stop)
        pthread_cond_wait (&st->cv, &st->mu);
      if (st->stop && st->head == NULL)
        {
          pthread_mutex_unlock (&st->mu);
          break;
        }
      job = st->head;
      st->head = job->next;
      if (st->head == NULL)
        st->tail = NULL;
      st->len--;
      pthread_mutex_unlock (&st->mu);
      job->work (job->arg);
      finish_job (job, TWIST_OK);
      free (job);
    }
  return NULL;
}

struct twist_storage *
twist_storage_new (size_t threads, size_t bound)
{
  struct twist_storage *st;
  size_t i;

  st = calloc (1, sizeof *st);
  if (st == NULL)
    return NULL;
  st->bound = bound == 0 ? 32 : bound;
  pthread_mutex_init (&st->mu, NULL);
  pthread_cond_init (&st->cv, NULL);
  if (threads > 0)
    {
      st->threads = calloc (threads, sizeof *st->threads);
      if (st->threads == NULL)
        {
          free (st);
          return NULL;
        }
      st->nthreads = threads;
      for (i = 0; i < threads; i++)
        pthread_create (&st->threads[i], NULL, worker, st);
    }
  return st;
}

void
twist_storage_free (struct twist_storage *st)
{
  size_t i;

  if (st == NULL)
    return;
  pthread_mutex_lock (&st->mu);
  st->stop = 1;
  pthread_cond_broadcast (&st->cv);
  pthread_mutex_unlock (&st->mu);
  for (i = 0; i < st->nthreads; i++)
    pthread_join (st->threads[i], NULL);
  while (st->head != NULL)
    {
      struct twist_job *job = st->head;
      st->head = job->next;
      free (job);
    }
  free (st->threads);
  pthread_mutex_destroy (&st->mu);
  pthread_cond_destroy (&st->cv);
  free (st);
}

void
twist_storage_set_inline (struct twist_storage *st, int inline_mode)
{
  st->inline_mode = inline_mode;
}

int
twist_storage_submit (struct twist_storage *st, void (*work) (void *),
                      void *arg, void (*done) (void *user, int err),
                      void *user, struct twist_loop *loop)
{
  struct twist_job *job;

  if (st->inline_mode || st->nthreads == 0)
    {
      work (arg);
      if (done != NULL)
        done (user, TWIST_OK);
      return TWIST_OK;
    }
  job = calloc (1, sizeof *job);
  if (job == NULL)
    return TWIST_ERR_NOMEM;
  job->work = work;
  job->arg = arg;
  job->done = done;
  job->user = user;
  job->loop = loop;
  pthread_mutex_lock (&st->mu);
  if (st->len >= st->bound)
    {
      pthread_mutex_unlock (&st->mu);
      free (job);
      return TWIST_ERR_AGAIN;
    }
  if (st->tail != NULL)
    st->tail->next = job;
  else
    st->head = job;
  st->tail = job;
  st->len++;
  pthread_cond_signal (&st->cv);
  pthread_mutex_unlock (&st->mu);
  return TWIST_OK;
}
