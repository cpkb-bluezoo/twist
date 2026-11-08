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
  size_t maxchunk;
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
  if (len > r->maxchunk)
    r->maxchunk = len;
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
  check (r.maxchunk == twist_fio_chunk (),
         "in chunks of the size the environment gave");
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

/* A buffer handed over, not copied: what is written is what was in it, the
   caller gets another to fill, and when the writer has no room the buffer is
   the caller's still.  */
static void
swap_credit (void *user)
{
  (void) user;
}

static const struct twist_fio_write_ops swap_ops = { swap_credit, wr_end,
                                                     NULL };

static void
test_write_swap (struct twist_loop *loop, struct twist_storage *st)
{
  enum { PIECES = 12 };
  const size_t PIECE = twist_fio_wchunk ();
  char out[64];
  struct wr w;
  uint8_t *buf = twist_xmalloc (twist_fio_wchunk ());
  uint8_t *b;
  size_t n;
  int fd;
  int sent = 0;
  int full = 0;
  int ok = 1;

  snprintf (out, sizeof out, "/tmp/twist-test-fio-out-XXXXXX");
  fd = mkstemp (out);
  close (fd);
  memset (&w, 0, sizeof w);
  check (twist_fio_write_new (loop, st, out, 0, &swap_ops, &w, &w.f)
         == TWIST_OK, "a write is begun");
  while (sent < PIECES)
    {
      uint8_t *mine = buf;
      int rc;

      memset (buf, 'a' + sent, PIECE);
      rc = twist_fio_write_swap (w.f, &buf, PIECE);
      if (rc == 1)
        {
          full++;
          if (buf != mine)
            ok = 0;		/* Not taken: it must still be ours.  */
          run_for (loop, 20);
          continue;
        }
      if (rc != TWIST_OK || buf == mine || buf == NULL)
        ok = 0;
      sent++;
    }
  check (ok, "a buffer is swapped for another, or kept when there is no room");
  check (full > 0, "and the writer did fill up");
  twist_fio_write_end (w.f);
  run_for (loop, 800);
  check (w.ends == 1 && w.end_err == TWIST_OK, "it ends once, with no error");
  b = malloc ((size_t) PIECES * PIECE);
  {
    FILE *fp = fopen (out, "rb");

    n = fp != NULL ? fread (b, 1, (size_t) PIECES * PIECE, fp) : 0;
    if (fp != NULL)
      fclose (fp);
  }
  ok = n == (size_t) PIECES * PIECE;
  for (fd = 0; ok && fd < PIECES; fd++)
    ok = b[(size_t) fd * PIECE] == 'a' + fd
         && b[(size_t) fd * PIECE + PIECE - 1] == 'a' + fd;
  check (ok, "and the file has the pieces, in order");
  free (b);
  twist_fio_free (w.f);
  free (w.msg);
  free (buf);
  unlink (out);
}

/* A descriptor written to, from an offset, through whichever backend there is:
   what was there before the offset stays, and the position is not moved.  */
static void
test_write_fd (struct twist_loop *loop, struct twist_storage *st)
{
  char out[64];
  struct wr w;
  int fd;
  int dfd;
  FILE *fp;
  uint8_t *got = malloc (FILE_SIZE + 10);
  size_t n = 0;

  snprintf (out, sizeof out, "/tmp/twist-test-fio-out-XXXXXX");
  fd = mkstemp (out);
  (void) !write (fd, "0123456789", 10);
  dfd = dup (fd);
  memset (&w, 0, sizeof w);
  check (twist_fio_write_fd_new (loop, st, dfd, 10, &wr_ops, &w, &w.f)
         == TWIST_OK, "a writer on a descriptor");
  wr_pump (&w);
  run_for (loop, 800);
  check (w.ends == 1 && w.end_err == TWIST_OK, "ends well");
  fp = fopen (out, "rb");
  if (fp != NULL)
    {
      n = fread (got, 1, FILE_SIZE + 10, fp);
      fclose (fp);
    }
  check (n == FILE_SIZE + 10 && memcmp (got, "0123456789", 10) == 0
         && memcmp (got + 10, content, FILE_SIZE) == 0,
         "the file is what was there, then the content from the offset");
  twist_fio_free (w.f);
  free (w.msg);
  close (fd);
  unlink (out);
  free (got);
}

/* A writer or a reader is a job for the life of its transfer, so as many may
   be started as there are transfers: more than the pool queues.  A hundred
   downloads to files at once all begin.  */
static void
test_many_workers (struct twist_loop *loop, struct twist_storage *st)
{
  enum { N = 100 };
  static struct wr w[N];
  int started = 0;
  int ended = 0;
  int i;

  for (i = 0; i < N; i++)
    {
      int fd = open ("/dev/null", O_WRONLY);

      memset (&w[i], 0, sizeof w[i]);
      if (fd >= 0
          && twist_fio_write_fd_new (loop, st, fd, -1, &wr_ops, &w[i],
                                     &w[i].f) == TWIST_OK)
        started++;
      else if (fd >= 0)
        close (fd);
    }
  check (started == N, "every one of a hundred writers starts");
  for (i = 0; i < N; i++)
    if (w[i].f != NULL)
      wr_pump (&w[i]);
  run_for (loop, 1500);
  for (i = 0; i < N; i++)
    {
      if (w[i].ends == 1 && w[i].end_err == TWIST_OK)
        ended++;
      if (w[i].f != NULL)
        twist_fio_free (w[i].f);
      free (w[i].msg);
    }
  check (ended == started, "and every one of them ends well");
}

/* Which backend there is: the reads and writes of a loop that can have a ring
   use it, unless the environment says not to.  */
static void
test_backend (struct twist_loop *loop, struct twist_storage *st, int uring)
{
  struct rd r;
  struct twist_fio *f;

  rd_init (&r);
  r.start = 0;
  r.length = 100;
  twist_fio_read_new (loop, st, &rd_ops, &r, &f);
  if (uring)
    {
      check (twist_uio_is (f) == twist_uio_usable (loop, st),
             "a loop that can have a ring uses it");
      fprintf (stderr, "test-fio: %s\n", twist_uio_is (f)
               ? "io_uring in use" : "no io_uring here; the pool");
    }
  else
    check (!twist_uio_is (f), "TWIST_NO_URING keeps the pool");
  run_for (loop, 200);
  twist_fio_free (f);
  free (r.got);
  free (r.msg);
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

/* Every test through the pool (TWIST_NO_URING), and through io_uring where the
   loop can have it (and, where it cannot, through the pool again).  */
static void
run_all (int uring)
{
  struct twist_loop *loop;
  struct twist_storage *st;

  if (uring)
    unsetenv ("TWIST_NO_URING");
  else
    setenv ("TWIST_NO_URING", "1", 1);
  loop = twist_loop_new (0);
  st = twist_storage_new (2, 32);
  test_backend (loop, st, uring);
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
  test_write_fd (loop, st);
  test_write_swap (loop, st);
  test_writers_yield (loop, st);
  test_many_workers (loop, st);
  twist_storage_free (st);
  twist_loop_free (loop);
}

/* The size of a piece for the writer is the environment's, within bounds.  */
static void
test_wchunk (void)
{
  check (twist_fio_wchunk_parse (NULL) == TWIST_FIO_WCHUNK_DEFAULT,
         "no setting is the default");
  check (twist_fio_wchunk_parse ("") == TWIST_FIO_WCHUNK_DEFAULT
         && twist_fio_wchunk_parse ("x") == TWIST_FIO_WCHUNK_DEFAULT
         && twist_fio_wchunk_parse ("-5") == TWIST_FIO_WCHUNK_DEFAULT
         && twist_fio_wchunk_parse ("64kb") == TWIST_FIO_WCHUNK_DEFAULT,
         "what is not a size is the default");
  check (twist_fio_wchunk_parse ("131072") == 131072,
         "a number of bytes");
  check (twist_fio_wchunk_parse ("128k") == 131072
         && twist_fio_wchunk_parse ("128K") == 131072
         && twist_fio_wchunk_parse ("1m") == 1048576,
         "with k or m for KiB and MiB");
  check (twist_fio_wchunk_parse ("1") == TWIST_FIO_WCHUNK_MIN
         && twist_fio_wchunk_parse ("100m") == TWIST_FIO_WCHUNK_MAX
         && twist_fio_wchunk_parse ("99999999999999999999")
            == TWIST_FIO_WCHUNK_MAX,
         "and kept within the least and the most");
  check (TWIST_FIO_WCHUNK_MIN >= TWIST_SINK_PIECE,
         "the least takes a whole piece from the sink");
  check (twist_fio_wchunk () == 32768,
         "the size in use is the one the environment gave at the start");
  check (twist_fio_chunk_parse (NULL) == TWIST_FIO_RCHUNK_DEFAULT
         && twist_fio_chunk_parse ("x") == TWIST_FIO_RCHUNK_DEFAULT,
         "a read chunk with no size is the default");
  check (twist_fio_chunk_parse ("256k") == 262144
         && twist_fio_chunk_parse ("1") == TWIST_FIO_RCHUNK_MIN
         && twist_fio_chunk_parse ("100m") == TWIST_FIO_RCHUNK_MAX,
         "a read chunk is kept within the least and the most");
  check (twist_fio_chunk () == 65536,
         "and the one in use is the environment's");
}

int
main (void)
{
  /* Before anything asks, so the tests run with other than the default.  */
  setenv ("TWIST_WRITE_CHUNK", "32k", 1);
  setenv ("TWIST_READ_CHUNK", "64k", 1);
  if (make_file () != 0)
    return 77;
  test_wchunk ();
  run_all (0);
  run_all (1);
  test_pools_apart ();
  unlink (path);
  free (content);
  return tests_finish ();
}
