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

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

/* Reads and writes of regular files, on the worker threads of a storage pool
   (see twist-int.h).  The worker is a thread of the pool and the transfer
   belongs to the loop's thread, and they share this record.  Letting go of a
   transfer (twist_fio_free) is not to wait for the worker, whose read may be
   slow or stuck, or which may not have started because the pool is busy: it
   marks the record released and returns, and the record is freed by whichever
   of the loop (the last chunk it has to acknowledge) and the worker (when it
   ends) is the last to be done with it.  A released transfer calls nothing
   back; the worker, which sees that, stops.

   The worker tells the loop what it has by posting commands, and it must not
   change what belongs to the loop.  The last of them, that it is done, is made
   when the transfer is begun, so that posting it cannot fail for want of
   memory.  A chunk that cannot be posted ends the worker with that error,
   which the last command carries.  */

enum { FIO_READ, FIO_WRITE };

struct fio_chunk
{
  struct twist_fio *f;
  uint8_t *data;		/* Read: owned, until delivered.  Write: the slot's.  */
  size_t len;
  int err;
  char *msg;
  int final_note;
  int busy;
  struct fio_chunk *next;	/* In the held queue, or the worker's.  */
};

struct twist_fio
{
  int dir;
  /* The loop's, for the worker: it must not reach it through anything that a
     released transfer may have left behind.  */
  struct twist_loop *loop;
  void *user;
  void (*user_free) (void *);
  struct twist_fio_read_ops rops;
  struct twist_fio_write_ops wops;
  pthread_mutex_t mu;
  pthread_cond_t cv;
  int live;
  int stop;
  int released;
  int inflight;
  int err;			/* Under MU.  */
  /* The note that the worker is done: its command, made at the start, and the
     chunk it carries.  Counted in INFLIGHT once posted.  */
  struct fio_chunk final;
  struct twist_cmd *final_cmd;
  int final_posted;
  struct fio_chunk slot[TWIST_FIO_PIPELINE];
  /* The loop's: chunks that have come and are not delivered.  */
  int paused;
  int delivering;
  struct fio_chunk *hq_head;
  struct fio_chunk *hq_tail;
  long long size;		/* From the worker, under MU.  */
  int size_known;
  int size_noted;
  /* Writing: the file, and the chunks that the loop has given the worker.  */
  char *path;
  int append;
  int wfd;			/* An open descriptor to write at WOFF, in place of PATH.  */
  long long woff;
  int wplain;			/* Write at the descriptor's own position.  */
  struct twist_storage *wst;	/* The pool the writer runs on.  */
  int wcur;			/* The file being written, once open; -1.  */
  struct fio_chunk *wq_head;
  struct fio_chunk *wq_tail;
  int end_req;
};

static void on_loop (void *user);

static void
fio_destroy (struct twist_fio *f)
{
  size_t i;

  if (!f->final_posted && f->final_cmd != NULL)
    twist_loop_cmd_free (f->final_cmd);
  for (i = 0; i < TWIST_FIO_PIPELINE; i++)
    if (f->dir == FIO_WRITE)
      free (f->slot[i].data);
  pthread_cond_destroy (&f->cv);
  pthread_mutex_destroy (&f->mu);
  free (f->path);
  if (f->user_free != NULL)
    f->user_free (f->user);
  free (f);
}

/* Let go of MU, which the caller holds, and free the record if nobody is left
   to use it: the transfer is released, the worker has ended and every chunk it
   posted has been acknowledged.  Whoever makes that so is the one that sees it
   so, and the others do not touch the record again after they have let go of
   the lock.  */
static void
fio_unlock (struct twist_fio *f)
{
  int last = f->released && !f->live && f->inflight == 0;

  pthread_mutex_unlock (&f->mu);
  if (last)
    fio_destroy (f);
}

/* A chunk, or the note that the worker is done, has been acknowledged: its
   slot is free.  The record may be freed here.  C is not used after.  */
static void
chunk_done (struct twist_fio *f, struct fio_chunk *c, int stop)
{
  pthread_mutex_lock (&f->mu);
  c->busy = 0;
  if (f->inflight > 0)
    f->inflight--;
  if (stop)
    f->stop = 1;
  pthread_cond_broadcast (&f->cv);
  fio_unlock (f);
}

int
twist_fio_inflight (struct twist_fio *f)
{
  int n;

  if (twist_uio_is (f))
    return twist_uio_inflight (f);
  pthread_mutex_lock (&f->mu);
  n = f->inflight;
  pthread_mutex_unlock (&f->mu);
  return n;
}

/* The transfer is let go of: by the application, which no longer wants it, or
   the runtime going away.  It returns at once, and nothing is called back
   after it.  */
void
twist_fio_free (struct twist_fio *f)
{
  if (f == NULL)
    return;
  if (twist_uio_is (f))
    {
      twist_uio_free (f);
      return;
    }
  pthread_mutex_lock (&f->mu);
  f->released = 1;
  f->stop = 1;
  /* What came and was held back is acknowledged here.  */
  while (f->hq_head != NULL)
    {
      struct fio_chunk *c = f->hq_head;

      f->hq_head = c->next;
      free (c->data);
      free (c->msg);
      c->data = NULL;
      c->msg = NULL;
      c->busy = 0;
      if (f->inflight > 0)
        f->inflight--;
    }
  f->hq_tail = NULL;
  pthread_cond_broadcast (&f->cv);
  fio_unlock (f);
}

static struct twist_fio *
fio_new (struct twist_loop *loop, int dir)
{
  struct twist_fio *f = calloc (1, sizeof *f);

  if (f == NULL)
    return NULL;
  if (pthread_mutex_init (&f->mu, NULL) != 0)
    {
      free (f);
      return NULL;
    }
  if (pthread_cond_init (&f->cv, NULL) != 0)
    {
      pthread_mutex_destroy (&f->mu);
      free (f);
      return NULL;
    }
  f->dir = dir;
  f->loop = loop;
  f->live = 1;
  f->final.f = f;
  f->final_cmd = twist_loop_cmd_new (on_loop, &f->final);
  if (f->final_cmd == NULL)
    {
      fio_destroy (f);
      return NULL;
    }
  return f;
}

/* Give the loop a chunk of data (DATA, LEN, owned from here) to deliver.  It
   waits for room, and gives up with the reason if the transfer has been
   stopped.  A failure to post is the error NOMEM, and nothing is delivered.  */
static int
hand_off (struct twist_fio *f, uint8_t *data, size_t len)
{
  struct fio_chunk *c = NULL;
  int i;
  int rc;

  pthread_mutex_lock (&f->mu);
  for (;;)
    {
      /* A stop is looked for before waiting for room, not only after: the one
         that wants it may be waiting for this thread.  */
      if (f->stop)
        {
          int why = f->err != TWIST_OK ? f->err : TWIST_ERR_ABORTED;

          pthread_mutex_unlock (&f->mu);
          free (data);
          return why;
        }
      if (f->inflight < TWIST_FIO_PIPELINE)
        break;
      pthread_cond_wait (&f->cv, &f->mu);
    }
  for (i = 0; i < TWIST_FIO_PIPELINE; i++)
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
      return TWIST_ERR_NOMEM;
    }
  f->inflight++;
  pthread_mutex_unlock (&f->mu);
  c->f = f;
  c->data = data;
  c->len = len;
  c->err = TWIST_OK;
  c->msg = NULL;
  c->final_note = 0;
  c->next = NULL;
  rc = twist_loop_post (f->loop, on_loop, c);
  if (rc != TWIST_OK)
    {
      free (data);
      c->data = NULL;
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

/* Tell the loop that the worker is done, with ERR and MSG (owned from here) if
   it failed.  Its command was made when the transfer was begun, and it is not
   a slot of the pipeline, so there is no waiting for room and nothing to fail:
   it comes after the chunks posted before it.  */
static void
hand_off_final (struct twist_fio *f, int err, char *msg)
{
  struct fio_chunk *c = &f->final;

  pthread_mutex_lock (&f->mu);
  f->inflight++;
  f->final_posted = 1;
  pthread_mutex_unlock (&f->mu);
  c->f = f;
  c->data = NULL;
  c->len = 0;
  c->err = err;
  c->msg = msg;
  c->final_note = 1;
  twist_loop_cmd_post (f->loop, f->final_cmd);
}

/* The worker is done.  If the transfer was let go of, nobody is told.  */
static void
worker_end (struct twist_fio *f, int err, char *msg)
{
  int released;

  pthread_mutex_lock (&f->mu);
  released = f->released;
  pthread_mutex_unlock (&f->mu);
  if (released)
    free (msg);
  else
    hand_off_final (f, err, msg);
  pthread_mutex_lock (&f->mu);
  f->live = 0;
  pthread_cond_broadcast (&f->cv);
  fio_unlock (f);
}

static int
started_released (struct twist_fio *f)
{
  int released;

  pthread_mutex_lock (&f->mu);
  released = f->released;
  pthread_mutex_unlock (&f->mu);
  return released;
}

static char *
errmsg_open (const char *path)
{
  const char *fmt = _("could not open file %s");
  char *msg = twist_xmalloc (strlen (fmt) + strlen (path) + 1);

  if (msg != NULL)
    snprintf (msg, strlen (fmt) + strlen (path) + 1, _("could not open file %s"),
              path);
  return msg;
}

static char *
errmsg_write (const char *path)
{
  const char *fmt = _("could not write file %s");
  char *msg = twist_xmalloc (strlen (fmt) + strlen (path) + 1);

  if (msg != NULL)
    snprintf (msg, strlen (fmt) + strlen (path) + 1,
              _("could not write file %s"), path);
  return msg;
}

/* ---- reading ---- */

/* One chunk, or the note that the worker is done, is for the application.
   Returns 1 if the record is let go of and may be gone: nothing of it is used
   after.  */
static int
deliver_one (struct twist_fio *f, struct fio_chunk *c)
{
  int err = c->err;
  int gone;

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
          if (f->rops.size != NULL)
            f->rops.size (f->user, size);
        }
    }
  if (!f->released && c->data != NULL && c->len > 0 && err == TWIST_OK)
    {
      int stopped;

      pthread_mutex_lock (&f->mu);
      stopped = f->err != TWIST_OK;
      pthread_mutex_unlock (&f->mu);
      if (!stopped)
        err = f->rops.chunk (f->user, c->data, c->len);
    }
  free (c->data);
  c->data = NULL;
  if (f->released)
    {
      free (c->msg);
      c->msg = NULL;
      gone = 1;
      chunk_done (f, c, 0);
      return gone;
    }
  if (err != TWIST_OK)
    {
      pthread_mutex_lock (&f->mu);
      if (f->err == TWIST_OK)
        f->err = err;
      pthread_mutex_unlock (&f->mu);
    }
  if (c->final_note)
    {
      char *msg = c->msg;
      int why;

      c->msg = NULL;
      pthread_mutex_lock (&f->mu);
      why = f->err;
      pthread_mutex_unlock (&f->mu);
      f->rops.end (f->user, why, msg);
    }
  else
    {
      /* A message that comes with a chunk is for a failure only.  */
      free (c->msg);
      c->msg = NULL;
    }
  gone = f->released;
  pthread_mutex_lock (&f->mu);
  err = f->err;
  pthread_mutex_unlock (&f->mu);
  chunk_done (f, c, err != TWIST_OK);
  return gone;
}

static void
deliver (struct twist_fio *f)
{
  if (f->delivering)
    return;
  f->delivering = 1;
  while (f->hq_head != NULL && !f->paused)
    {
      struct fio_chunk *c = f->hq_head;

      f->hq_head = c->next;
      if (f->hq_head == NULL)
        f->hq_tail = NULL;
      c->next = NULL;
      if (deliver_one (f, c))
        return;			/* Gone; F is not touched.  */
    }
  f->delivering = 0;
}

void
twist_fio_pause (struct twist_fio *f)
{
  if (twist_uio_is (f))
    {
      twist_uio_pause (f);
      return;
    }
  if (f != NULL)
    f->paused = 1;
}

void
twist_fio_resume (struct twist_fio *f)
{
  if (twist_uio_is (f))
    {
      twist_uio_resume (f);
      return;
    }
  if (f == NULL || !f->paused)
    return;
  f->paused = 0;
  deliver (f);
}

/* A write has been acknowledged by the worker, or it has ended.  */
static void
write_ack (struct twist_fio *f, struct fio_chunk *c)
{
  if (c->final_note)
    {
      char *msg = c->msg;

      c->msg = NULL;
      f->wops.end (f->user, c->err, msg);
      chunk_done (f, c, 0);
      return;
    }
  chunk_done (f, c, 0);
  if (f->wops.credit != NULL)
    f->wops.credit (f->user);
}

static void
on_loop (void *user)
{
  struct fio_chunk *c = user;
  struct twist_fio *f = c->f;

  if (f->released)
    {
      /* Let go of: nothing is for the application now.  Only the loop's thread
         sets RELEASED, and this is it.  */
      free (c->data);
      free (c->msg);
      c->data = NULL;
      c->msg = NULL;
      chunk_done (f, c, 0);
      return;
    }
  if (f->dir == FIO_WRITE)
    {
      write_ack (f, c);
      return;
    }
  c->next = NULL;
  if (f->hq_tail != NULL)
    f->hq_tail->next = c;
  else
    f->hq_head = c;
  f->hq_tail = c;
  deliver (f);
}

static void
read_work (void *arg)
{
  struct twist_fio *f = arg;
  int fd = -1;
  int own = 0;
  long long start = 0;
  long long left = -1;
  long long off;
  int err = TWIST_OK;
  char *msg = NULL;

  if (started_released (f))
    {
      worker_end (f, TWIST_OK, NULL);
      return;
    }
  err = f->rops.open (f->user, &fd, &own, &start, &left, &msg);
  if (err != TWIST_OK)
    goto done;
  off = start;
  if (left >= 0)
    {
      pthread_mutex_lock (&f->mu);
      f->size = left;
      f->size_known = 1;
      pthread_mutex_unlock (&f->mu);
    }
  while (left != 0)
    {
      size_t want = TWIST_FIO_CHUNK;
      uint8_t *buf;
      ssize_t n;
      int stopped;
      int rc;

      if (left > 0 && left < (long long) want)
        want = (size_t) left;
      pthread_mutex_lock (&f->mu);
      stopped = f->stop;
      pthread_mutex_unlock (&f->mu);
      if (stopped)
        break;
      buf = twist_xmalloc (want);
      if (buf == NULL)
        {
          err = TWIST_ERR_NOMEM;
          break;
        }
      do
        n = pread (fd, buf, want, (off_t) off);
      while (n < 0 && errno == EINTR);
      if (n <= 0)
        {
          free (buf);
          if (n < 0)
            err = TWIST_ERR_FILE;
          break;
        }
      off += n;
      if (left > 0)
        left -= n;
      rc = hand_off (f, buf, (size_t) n);
      if (rc != TWIST_OK)
        {
          err = rc;
          break;
        }
    }
done:
  if (own && fd >= 0)
    close (fd);
  worker_end (f, err, msg);
}

int
twist_fio_read_new (struct twist_loop *loop, struct twist_storage *st,
                    const struct twist_fio_read_ops *ops, void *user,
                    struct twist_fio **out)
{
  struct twist_fio *f;
  int rc;

  *out = NULL;
  if (loop == NULL || st == NULL || ops == NULL || ops->open == NULL
      || ops->chunk == NULL || ops->end == NULL)
    return TWIST_ERR_INVAL;
  if (twist_uio_usable (loop, st))
    return twist_uio_read_new (loop, st, ops, user, out);
  /* The worker waits on the loop for room to hand over what it reads, so it
     cannot be the loop's own thread.  */
  if (twist_storage_threads (st) == 0)
    return TWIST_ERR_UNSUPPORTED;
  f = fio_new (loop, FIO_READ);
  if (f == NULL)
    return TWIST_ERR_NOMEM;
  f->rops = *ops;
  f->user = user;
  rc = twist_storage_submit_worker (st, read_work, f);
  if (rc != TWIST_OK)
    {
      f->live = 0;
      twist_fio_free (f);
      return rc;
    }
  f->user_free = ops->release;
  *out = f;
  return TWIST_OK;
}

/* ---- writing ---- */

/* Take everything the worker has not written off its queue, counting it
   as acknowledged, for a worker that is stopping.  */
static void
write_drop_queue (struct twist_fio *f)
{
  pthread_mutex_lock (&f->mu);
  while (f->wq_head != NULL)
    {
      struct fio_chunk *c = f->wq_head;

      f->wq_head = c->next;
      c->busy = 0;
      if (f->inflight > 0)
        f->inflight--;
    }
  f->wq_tail = NULL;
  pthread_cond_broadcast (&f->cv);
  pthread_mutex_unlock (&f->mu);
}

static void
write_fail (struct twist_fio *f, int err)
{
  pthread_mutex_lock (&f->mu);
  if (f->err == TWIST_OK)
    f->err = err;
  f->stop = 1;
  pthread_mutex_unlock (&f->mu);
}

/* A writer holds a thread of its pool only while it has something to write:
   when it has nothing and another job is waiting for a thread, it puts itself
   at the back of the queue and gives its thread up.  Otherwise a pool full
   of writers waiting for data would keep out the jobs that make it.  */
static void
write_work (void *arg)
{
  struct twist_fio *f = arg;
  int fd;
  int err = TWIST_OK;
  char *msg = NULL;

  if (f->wcur < 0)
    {
      if (started_released (f))
        {
          worker_end (f, TWIST_OK, NULL);
          return;
        }
      if (f->wfd >= 0)
        fd = f->wfd;
      else
        fd = open (f->path,
                   O_WRONLY | O_CREAT | O_CLOEXEC
                   | (f->append ? O_APPEND : O_TRUNC), 0666);
      if (fd < 0)
        {
          err = TWIST_ERR_FILE;
          msg = errmsg_open (f->path);
          write_fail (f, err);
          write_drop_queue (f);
          worker_end (f, err, msg);
          return;
        }
      f->wcur = fd;
    }
  fd = f->wcur;
  for (;;)
    {
      struct fio_chunk *c;
      size_t done = 0;
      int rc;

      pthread_mutex_lock (&f->mu);
      while (f->wq_head == NULL && !f->end_req && !f->stop)
        {
          struct timespec until;

          if (f->wst != NULL && twist_storage_queued (f->wst) > 0)
            {
              pthread_mutex_unlock (&f->mu);
              if (twist_storage_submit_worker (f->wst, write_work, f)
                  == TWIST_OK)
                return;
              pthread_mutex_lock (&f->mu);
            }
          /* Look again soon: a job may be queued behind this one.  */
          clock_gettime (CLOCK_REALTIME, &until);
          until.tv_nsec += 5 * 1000 * 1000;
          if (until.tv_nsec >= 1000000000L)
            {
              until.tv_sec++;
              until.tv_nsec -= 1000000000L;
            }
          pthread_cond_timedwait (&f->cv, &f->mu, &until);
        }
      if (f->stop)
        {
          pthread_mutex_unlock (&f->mu);
          break;
        }
      c = f->wq_head;
      if (c == NULL)
        {
          pthread_mutex_unlock (&f->mu);
          break;		/* All written, and no more to come.  */
        }
      f->wq_head = c->next;
      if (f->wq_head == NULL)
        f->wq_tail = NULL;
      c->next = NULL;
      pthread_mutex_unlock (&f->mu);
      while (done < c->len)
        {
          ssize_t n = f->wfd >= 0 && !f->wplain
                      ? pwrite (fd, c->data + done, c->len - done,
                                (off_t) (f->woff + (long long) done))
                      : write (fd, c->data + done, c->len - done);

          if (n < 0 && errno == EINTR)
            continue;
          if (n <= 0)
            break;
          done += (size_t) n;
        }
      if (done < c->len)
        {
          err = TWIST_ERR_FILE;
          msg = errmsg_write (f->path);
          write_fail (f, err);
          pthread_mutex_lock (&f->mu);
          c->busy = 0;
          if (f->inflight > 0)
            f->inflight--;
          pthread_mutex_unlock (&f->mu);
          break;
        }
      f->woff += (long long) c->len;
      rc = twist_loop_post (f->loop, on_loop, c);
      if (rc != TWIST_OK)
        {
          err = rc;
          write_fail (f, err);
          pthread_mutex_lock (&f->mu);
          c->busy = 0;
          if (f->inflight > 0)
            f->inflight--;
          pthread_mutex_unlock (&f->mu);
          break;
        }
    }
  write_drop_queue (f);
  if (close (fd) != 0 && err == TWIST_OK)
    {
      err = TWIST_ERR_FILE;
      msg = errmsg_write (f->path);
      write_fail (f, err);
    }
  worker_end (f, err, msg);
}

int
twist_fio_write_new (struct twist_loop *loop, struct twist_storage *st,
                     const char *path, int append,
                     const struct twist_fio_write_ops *ops, void *user,
                     struct twist_fio **out)
{
  struct twist_fio *f;
  int rc;

  *out = NULL;
  if (loop == NULL || st == NULL || path == NULL || ops == NULL
      || ops->end == NULL)
    return TWIST_ERR_INVAL;
  if (twist_storage_threads (st) == 0)
    return TWIST_ERR_UNSUPPORTED;
  f = fio_new (loop, FIO_WRITE);
  if (f == NULL)
    return TWIST_ERR_NOMEM;
  f->wops = *ops;
  f->user = user;
  f->append = append;
  f->wfd = -1;
  f->wcur = -1;
  f->wst = st;
  f->path = twist_xmalloc (strlen (path) + 1);
  if (f->path == NULL)
    {
      f->live = 0;
      twist_fio_free (f);
      return TWIST_ERR_NOMEM;
    }
  strcpy (f->path, path);
  rc = twist_storage_submit_worker (st, write_work, f);
  if (rc != TWIST_OK)
    {
      f->live = 0;
      twist_fio_free (f);
      return rc;
    }
  f->user_free = ops->release;
  *out = f;
  return TWIST_OK;
}

static int
fio_write (struct twist_fio *f, const uint8_t *data, size_t len,
           uint8_t **swap)
{
  struct fio_chunk *c = NULL;
  int i;

  if (twist_uio_is (f))
    return twist_uio_write (f, data, len, swap);
  if (f == NULL || f->dir != FIO_WRITE || len > TWIST_FIO_WCHUNK)
    return TWIST_ERR_INVAL;
  pthread_mutex_lock (&f->mu);
  if (f->end_req)
    {
      pthread_mutex_unlock (&f->mu);
      return TWIST_ERR_INVAL;
    }
  if (f->err != TWIST_OK || f->stop)
    {
      int why = f->err != TWIST_OK ? f->err : TWIST_ERR_ABORTED;

      pthread_mutex_unlock (&f->mu);
      return why;
    }
  if (f->inflight >= TWIST_FIO_PIPELINE)
    {
      pthread_mutex_unlock (&f->mu);
      return 1;
    }
  for (i = 0; i < TWIST_FIO_PIPELINE; i++)
    if (!f->slot[i].busy)
      {
        c = &f->slot[i];
        break;
      }
  if (c == NULL)
    {
      pthread_mutex_unlock (&f->mu);
      return 1;
    }
  if (c->data == NULL || swap != NULL)
    {
      /* A buffer to fill, and, if the caller's goes, the one it gets.  */
      uint8_t *fresh = c->data;

      if (fresh == NULL)
        {
          fresh = twist_xmalloc (TWIST_FIO_WCHUNK);
          if (fresh == NULL)
            {
              pthread_mutex_unlock (&f->mu);
              return TWIST_ERR_NOMEM;
            }
        }
      if (swap != NULL)
        {
          c->data = *swap;
          *swap = fresh;
          data = c->data;
        }
      else
        c->data = fresh;
    }
  c->busy = 1;
  c->f = f;
  c->len = len;
  c->err = TWIST_OK;
  c->msg = NULL;
  c->final_note = 0;
  c->next = NULL;
  if (len > 0 && data != c->data)
    memcpy (c->data, data, len);
  f->inflight++;
  if (f->wq_tail != NULL)
    f->wq_tail->next = c;
  else
    f->wq_head = c;
  f->wq_tail = c;
  pthread_cond_broadcast (&f->cv);
  pthread_mutex_unlock (&f->mu);
  return TWIST_OK;
}

int
twist_fio_write (struct twist_fio *f, const uint8_t *data, size_t len)
{
  return fio_write (f, data, len, NULL);
}

int
twist_fio_write_swap (struct twist_fio *f, uint8_t **buf, size_t len)
{
  return fio_write (f, *buf, len, buf);
}

void
twist_fio_write_end (struct twist_fio *f)
{
  if (twist_uio_is (f))
    {
      twist_uio_write_end (f);
      return;
    }
  if (f == NULL || f->dir != FIO_WRITE)
    return;
  pthread_mutex_lock (&f->mu);
  f->end_req = 1;
  pthread_cond_broadcast (&f->cv);
  pthread_mutex_unlock (&f->mu);
}

/* As twist_fio_write_new, to an open descriptor, from the offset AT (the
   caller's position is not moved; a negative AT writes at the descriptor's own
   position, for one that cannot be written to at an offset).  FD is the
   writer's from here, and is closed when it ends.  */
int
twist_fio_write_fd_new (struct twist_loop *loop, struct twist_storage *st,
                        int fd, long long at,
                        const struct twist_fio_write_ops *ops, void *user,
                        struct twist_fio **out)
{
  struct twist_fio *f;
  int rc;

  *out = NULL;
  if (loop == NULL || st == NULL || fd < 0 || ops == NULL || ops->end == NULL)
    return TWIST_ERR_INVAL;
  if (twist_uio_usable (loop, st))
    return twist_uio_write_fd_new (loop, st, fd, at, ops, user, out);
  if (twist_storage_threads (st) == 0)
    return TWIST_ERR_UNSUPPORTED;
  f = fio_new (loop, FIO_WRITE);
  if (f == NULL)
    return TWIST_ERR_NOMEM;
  f->wops = *ops;
  f->user = user;
  f->wcur = -1;
  f->wst = st;
  f->wfd = fd;
  f->woff = at < 0 ? 0 : at;
  f->wplain = at < 0;
  f->path = twist_xmalloc (1);
  if (f->path == NULL)
    {
      f->live = 0;
      f->wfd = -1;
      twist_fio_free (f);
      return TWIST_ERR_NOMEM;
    }
  f->path[0] = 0;
  rc = twist_storage_submit_worker (st, write_work, f);
  if (rc != TWIST_OK)
    {
      f->live = 0;
      f->wfd = -1;
      twist_fio_free (f);
      return rc;
    }
  f->user_free = ops->release;
  *out = f;
  return TWIST_OK;
}
