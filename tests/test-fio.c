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

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

/* Regular files are read and written by workers of a pool, with a bounded
   number of chunks in flight, and the loop is told what happened.  */

#define FILE_SIZE (1024 * 1024 + 123)

static char path[64];
static uint8_t *content;

static double
now_ms (void)
{
  struct timespec t;

  clock_gettime (CLOCK_MONOTONIC, &t);
  return (double) t.tv_sec * 1000.0 + (double) t.tv_nsec / 1e6;
}

static void
run_for (struct twist_loop *loop, double ms)
{
  double end = now_ms () + ms;

  while (now_ms () < end)
    twist_loop_run_once_ms (loop, 1);
}

static int
make_file (void)
{
  int fd;
  size_t i;

  content = malloc (FILE_SIZE);
  if (content == NULL)
    return -1;
  for (i = 0; i < FILE_SIZE; i++)
    content[i] = (uint8_t) (i * 31 + i / 257);
  snprintf (path, sizeof path, "/tmp/twist-test-fio-XXXXXX");
  fd = mkstemp (path);
  if (fd < 0)
    return -1;
  if (write (fd, content, FILE_SIZE) != FILE_SIZE)
    {
      close (fd);
      return -1;
    }
  close (fd);
  return 0;
}

struct rd
{
  uint8_t *got;
  size_t n;
  int chunks;
  long long size;
  int sizes;
  int ends;
  int end_err;
  char *msg;
  int chunk_err;
  long long start;
  long long length;
  const char *file;
};

static int
rd_open (void *user, int *fd, int *own, long long *start, long long *length,
         char **msg)
{
  struct rd *r = user;

  (void) msg;
  *fd = open (r->file, O_RDONLY | O_CLOEXEC);
  if (*fd < 0)
    return TWIST_ERR_FILE;
  *own = 1;
  *start = r->start;
  *length = r->length;
  return TWIST_OK;
}

static void
rd_size (void *user, long long size)
{
  struct rd *r = user;

  r->sizes++;
  r->size = size;
}

static int
rd_chunk (void *user, uint8_t *data, size_t len)
{
  struct rd *r = user;

  if (r->chunk_err != TWIST_OK)
    return r->chunk_err;
  if (r->n + len <= FILE_SIZE)
    memcpy (r->got + r->n, data, len);
  r->n += len;
  r->chunks++;
  return TWIST_OK;
}

static void
rd_end (void *user, int err, char *msg)
{
  struct rd *r = user;

  r->ends++;
  r->end_err = err;
  free (r->msg);
  r->msg = msg;
}

static const struct twist_fio_read_ops rd_ops = { rd_open, rd_size, rd_chunk,
                                                  rd_end, NULL };

static void
rd_init (struct rd *r)
{
  memset (r, 0, sizeof *r);
  r->got = malloc (FILE_SIZE);
  r->file = path;
  r->length = -1;
}

static void
test_read (struct twist_loop *loop, struct twist_storage *st)
{
  struct rd r;
  struct twist_fio *f;

  rd_init (&r);
  check (twist_fio_read_new (loop, st, &rd_ops, &r, &f) == TWIST_OK,
         "a read is begun");
  run_for (loop, 500);
  check (r.ends == 1 && r.end_err == TWIST_OK, "it ends once, with no error");
  check (r.n == FILE_SIZE && memcmp (r.got, content, FILE_SIZE) == 0,
         "and delivered the file, in order");
  check (r.sizes == 0, "a read to the end has no size to tell");
  twist_fio_free (f);
  free (r.got);
  free (r.msg);
}

static void
test_read_range (struct twist_loop *loop, struct twist_storage *st)
{
  struct rd r;
  struct twist_fio *f;

  rd_init (&r);
  r.start = 1000;
  r.length = 70000;
  twist_fio_read_new (loop, st, &rd_ops, &r, &f);
  run_for (loop, 300);
  check (r.ends == 1 && r.n == 70000
         && memcmp (r.got, content + 1000, 70000) == 0,
         "a range is the bytes asked for");
  check (r.sizes == 1 && r.size == 70000, "and its size is its length");
  twist_fio_free (f);
  free (r.got);
  free (r.msg);
}

static void
test_read_missing (struct twist_loop *loop, struct twist_storage *st)
{
  struct rd r;
  struct twist_fio *f;

  rd_init (&r);
  r.file = "/nonexistent/twist-fio";
  twist_fio_read_new (loop, st, &rd_ops, &r, &f);
  run_for (loop, 200);
  check (r.ends == 1 && r.end_err == TWIST_ERR_FILE && r.n == 0,
         "a file that cannot be opened ends the read with the error");
  twist_fio_free (f);
  free (r.got);
  free (r.msg);
}

static void
test_read_chunk_error (struct twist_loop *loop, struct twist_storage *st)
{
  struct rd r;
  struct twist_fio *f;

  rd_init (&r);
  r.chunk_err = TWIST_ERR_ABORTED;
  twist_fio_read_new (loop, st, &rd_ops, &r, &f);
  run_for (loop, 300);
  check (r.ends == 1 && r.end_err == TWIST_ERR_ABORTED,
         "a chunk that is refused ends the read with that error");
  twist_fio_free (f);
  free (r.got);
  free (r.msg);
}

/* A worker with four unacknowledged chunks submits nothing more.  */
static void
test_credit (struct twist_loop *loop, struct twist_storage *st)
{
  struct rd r;
  struct twist_fio *f;

  rd_init (&r);
  check (twist_fio_read_new (loop, st, &rd_ops, &r, &f) == TWIST_OK,
         "a read to hold");
  twist_fio_pause (f);
  run_for (loop, 200);
  check (twist_fio_inflight (f) == TWIST_FIO_PIPELINE,
         "a worker stops when four chunks are unacknowledged");
  check (r.chunks == 0, "and none is delivered while it is paused");
  twist_fio_resume (f);
  run_for (loop, 500);
  check (r.ends == 1 && r.n == FILE_SIZE
         && memcmp (r.got, content, FILE_SIZE) == 0,
         "resuming delivers all of it, in order");
  twist_fio_free (f);
  free (r.got);
  free (r.msg);
}

/* Let go of, a transfer delivers nothing more and is not waited for.  */
static void
test_release (struct twist_loop *loop, struct twist_storage *st)
{
  struct rd r;
  struct twist_fio *f;
  double t0;

  rd_init (&r);
  twist_fio_read_new (loop, st, &rd_ops, &r, &f);
  twist_fio_pause (f);
  run_for (loop, 100);
  t0 = now_ms ();
  twist_fio_free (f);
  check (now_ms () - t0 < 100, "letting go does not wait for the worker");
  run_for (loop, 200);
  check (r.chunks == 0 && r.ends == 0, "and nothing is delivered after it");
  free (r.got);
  free (r.msg);
}

struct wr
{
  struct twist_fio *f;
  size_t off;			/* How much of CONTENT is queued.  */
  int ends;
  int end_err;
  int ended_sent;
  char *msg;
};

static void
wr_pump (struct wr *w)
{
  while (w->off < FILE_SIZE)
    {
      size_t n = FILE_SIZE - w->off;
      int rc;

      if (n > TWIST_FIO_CHUNK)
        n = TWIST_FIO_CHUNK;
      rc = twist_fio_write (w->f, content + w->off, n);
      if (rc != TWIST_OK)
        return;
      w->off += n;
    }
  if (!w->ended_sent)
    {
      w->ended_sent = 1;
      twist_fio_write_end (w->f);
    }
}

static void
wr_credit (void *user)
{
  wr_pump (user);
}

static void
wr_end (void *user, int err, char *msg)
{
  struct wr *w = user;

  w->ends++;
  w->end_err = err;
  free (w->msg);
  w->msg = msg;
}

static const struct twist_fio_write_ops wr_ops = { wr_credit, wr_end, NULL };

static uint8_t *
slurp (const char *p, size_t *n)
{
  FILE *fp = fopen (p, "rb");
  uint8_t *b = malloc (2 * FILE_SIZE + 10);

  *n = fp != NULL ? fread (b, 1, 2 * FILE_SIZE + 10, fp) : 0;
  if (fp != NULL)
    fclose (fp);
  return b;
}

static void
test_write (struct twist_loop *loop, struct twist_storage *st)
{
  char out[64];
  struct wr w;
  uint8_t *b;
  size_t n;
  int fd;

  snprintf (out, sizeof out, "/tmp/twist-test-fio-out-XXXXXX");
  fd = mkstemp (out);
  close (fd);
  memset (&w, 0, sizeof w);
  check (twist_fio_write_new (loop, st, out, 0, &wr_ops, &w, &w.f)
         == TWIST_OK, "a write is begun");
  wr_pump (&w);
  run_for (loop, 800);
  check (w.ends == 1 && w.end_err == TWIST_OK, "it ends once, with no error");
  b = slurp (out, &n);
  check (n == FILE_SIZE && memcmp (b, content, FILE_SIZE) == 0,
         "and the file is what was written");
  free (b);
  twist_fio_free (w.f);
  free (w.msg);

  /* Appending adds to the end.  */
  memset (&w, 0, sizeof w);
  twist_fio_write_new (loop, st, out, 1, &wr_ops, &w, &w.f);
  wr_pump (&w);
  run_for (loop, 800);
  b = slurp (out, &n);
  check (w.ends == 1 && n == 2 * FILE_SIZE
         && memcmp (b + FILE_SIZE, content, FILE_SIZE) == 0,
         "an append adds to the end of the file");
  free (b);
  twist_fio_free (w.f);
  free (w.msg);
  unlink (out);
}

static void
test_write_credit (struct twist_loop *loop, struct twist_storage *st)
{
  char out[64];
  struct wr w;
  int fd, rc, taken = 0;
  uint8_t chunk[TWIST_FIO_CHUNK];

  snprintf (out, sizeof out, "/tmp/twist-test-fio-out-XXXXXX");
  fd = mkstemp (out);
  close (fd);
  memset (&w, 0, sizeof w);
  memset (chunk, 'w', sizeof chunk);
  twist_fio_write_new (loop, st, out, 0, &wr_ops, &w, &w.f);
  /* Without the loop running, no chunk is acknowledged.  */
  while ((rc = twist_fio_write (w.f, chunk, sizeof chunk)) == TWIST_OK)
    taken++;
  check (taken == TWIST_FIO_PIPELINE && rc == 1,
         "no more than four chunks are taken before one is acknowledged");
  w.ended_sent = 1;
  twist_fio_write_end (w.f);
  run_for (loop, 300);
  check (w.ends == 1 && w.end_err == TWIST_OK, "and it ends");
  twist_fio_free (w.f);
  free (w.msg);
  unlink (out);
}

static void
test_write_fail (struct twist_loop *loop, struct twist_storage *st)
{
  struct wr w;

  memset (&w, 0, sizeof w);
  twist_fio_write_new (loop, st, "/nonexistent/twist-fio", 0, &wr_ops, &w,
                       &w.f);
  run_for (loop, 200);
  check (w.ends == 1 && w.end_err == TWIST_ERR_FILE,
         "a file that cannot be created ends the write with the error");
  check (twist_fio_write (w.f, content, 10) != TWIST_OK
         && twist_fio_write (w.f, content, 10) != 1,
         "and a write after that fails");
  twist_fio_free (w.f);
  free (w.msg);
}

static void
test_write_release (struct twist_loop *loop, struct twist_storage *st)
{
  char out[64];
  struct wr w;
  int fd;
  double t0;

  snprintf (out, sizeof out, "/tmp/twist-test-fio-out-XXXXXX");
  fd = mkstemp (out);
  close (fd);
  memset (&w, 0, sizeof w);
  twist_fio_write_new (loop, st, out, 0, &wr_ops, &w, &w.f);
  twist_fio_write (w.f, content, 100);
  t0 = now_ms ();
  twist_fio_free (w.f);
  check (now_ms () - t0 < 100, "letting go of a write does not wait");
  run_for (loop, 200);
  check (w.ends == 0, "and nothing is delivered after it");
  free (w.msg);
  unlink (out);
}

static void
ran_work (void *arg)
{
  __atomic_store_n ((int *) arg, 1, __ATOMIC_RELEASE);
}

/* Writers that are waiting for data do not hold their threads: with every
   thread of the pool taken by one, a job that makes the data they wait for
   (a read) still runs.  */
static void
test_writers_yield (struct twist_loop *loop, struct twist_storage *st)
{
  char out[2][64];
  struct wr w[2];
  int ran = 0;
  int i;
  double t0;

  for (i = 0; i < 2; i++)
    {
      int fd;

      snprintf (out[i], sizeof out[i], "/tmp/twist-test-fio-out-XXXXXX");
      fd = mkstemp (out[i]);
      close (fd);
      memset (&w[i], 0, sizeof w[i]);
      twist_fio_write_new (loop, st, out[i], 0, &wr_ops, &w[i], &w[i].f);
    }
  run_for (loop, 100);
  twist_storage_submit (st, ran_work, &ran, NULL, NULL, NULL);
  t0 = now_ms ();
  while (!__atomic_load_n (&ran, __ATOMIC_ACQUIRE) && now_ms () - t0 < 2000)
    run_for (loop, 20);
  check (__atomic_load_n (&ran, __ATOMIC_ACQUIRE),
         "a job runs although every thread was taken by a writer with no data");
  for (i = 0; i < 2; i++)
    {
      w[i].ended_sent = 1;
      twist_fio_write_end (w[i].f);
    }
  run_for (loop, 200);
  check (w[0].ends == 1 && w[1].ends == 1,
         "and the writers, put back in the queue, end when they are told to");
  for (i = 0; i < 2; i++)
    {
      twist_fio_free (w[i].f);
      free (w[i].msg);
      unlink (out[i]);
    }
}

static size_t hopped;

static void
hop_done (void *user)
{
  (void) user;
  hopped++;
}

static void
hop_work (void *arg)
{
  twist_loop_post (arg, hop_done, NULL);
}

/* The runtime's two pools are apart: transfers that fill every transfer
   worker do not hold up a key load.  */
static void
test_pools_apart (void)
{
  struct twist_runtime *runtime = twist_runtime_new ();
  struct rd r[2];
  struct twist_fio *f[2];
  int i;
  double end;

  check (runtime != NULL && runtime->xfer != NULL
         && runtime->xfer != runtime->storage,
         "the runtime has a pool for transfers of its own");
  if (runtime == NULL || runtime->xfer == NULL)
    return;
  for (i = 0; i < 2; i++)
    {
      rd_init (&r[i]);
      twist_fio_read_new (runtime->loop, runtime->xfer, &rd_ops, &r[i], &f[i]);
      twist_fio_pause (f[i]);
    }
  run_for (runtime->loop, 100);
  hopped = 0;
  twist_storage_submit (runtime->storage, hop_work, runtime->loop, NULL, NULL,
                        NULL);
  end = now_ms () + 1000;
  while (hopped == 0 && now_ms () < end)
    twist_loop_run_once_ms (runtime->loop, 1);
  check (hopped == 1,
         "a key-load job runs while every transfer worker is busy");
  for (i = 0; i < 2; i++)
    {
      twist_fio_free (f[i]);
      free (r[i].got);
    }
  twist_runtime_free (runtime);
}

int
main (void)
{
  struct twist_loop *loop = twist_loop_new (0);
  struct twist_storage *st;

  if (loop == NULL || make_file () != 0)
    return 77;
  st = twist_storage_new (2, 32);
  test_read (loop, st);
  test_read_range (loop, st);
  test_read_missing (loop, st);
  test_read_chunk_error (loop, st);
  test_credit (loop, st);
  test_release (loop, st);
  test_write (loop, st);
  test_write_credit (loop, st);
  test_write_fail (loop, st);
  test_write_release (loop, st);
  test_writers_yield (loop, st);
  test_pools_apart ();
  twist_storage_free (st);
  twist_loop_free (loop);
  unlink (path);
  free (content);
  return tests_finish ();
}
