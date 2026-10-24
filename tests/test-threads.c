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

/* The storage pool's worker threads and the loop's thread: what runs where,
   when things go wrong.  Three things are made to go wrong, by replacing
   functions of the C library and of twist in this program only:

   - calloc fails on a worker thread when asked to, so that a worker cannot
     post to the loop.  What a worker was to do on the loop must not be done
     on the worker.
   - fread is slow on a worker thread when asked to, as a disk that is slow or
     does not answer is.  The loop's thread must not wait for it.
   - twist_transfer_finish notes the thread it is called on.  It changes the
     state of a transfer, which belongs to the loop's thread.  */

#define _GNU_SOURCE

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include "check.h"
#include "twist-int.h"

#include <dlfcn.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

extern void *__libc_calloc (size_t, size_t);

/* A function the next definition has, from dlsym, which gives an object
   pointer.  */
static void *
next_symbol (const char *name)
{
  return dlsym (RTLD_NEXT, name);
}

static pthread_t main_tid;
static volatile int fail_alloc;
static volatile int slow_read_ms;
static volatile int off_thread_finish;

void *
calloc (size_t n, size_t m)
{
  if (fail_alloc && !pthread_equal (pthread_self (), main_tid))
    return NULL;
  return __libc_calloc (n, m);
}

size_t
fread (void *p, size_t s, size_t n, FILE *f)
{
  static union { void *p; size_t (*f) (void *, size_t, size_t, FILE *); } real;

  if (real.p == NULL)
    real.p = next_symbol ("fread");
  if (slow_read_ms > 0 && !pthread_equal (pthread_self (), main_tid))
    usleep ((useconds_t) slow_read_ms * 1000);
  return real.f (p, s, n, f);
}

int
twist_transfer_finish (struct twist_transfer *transfer, int result)
{
  static union { void *p; int (*f) (struct twist_transfer *, int); } real;

  if (real.p == NULL)
    real.p = next_symbol ("twist_transfer_finish");
  if (!pthread_equal (pthread_self (), main_tid))
    off_thread_finish++;
  return real.f (transfer, result);
}

static double
now (void)
{
  struct timespec t;

  clock_gettime (CLOCK_MONOTONIC, &t);
  return (double) t.tv_sec + (double) t.tv_nsec / 1e9;
}

static void
nap_ms (long ms)
{
  struct timespec t = { ms / 1000, (ms % 1000) * 1000000L };

  nanosleep (&t, NULL);
}

/* A file of N bytes, its path in PATH.  */
static int
make_file (char *path, size_t cap, size_t n)
{
  int fd;
  char *buf = malloc (n);
  size_t i;

  snprintf (path, cap, "/tmp/twist-test-threads-XXXXXX");
  fd = mkstemp (path);
  if (fd < 0 || buf == NULL)
    return -1;
  for (i = 0; i < n; i++)
    buf[i] = (char) ('a' + i % 26);
  if (write (fd, buf, n) != (ssize_t) n)
    {
      close (fd);
      free (buf);
      return -1;
    }
  close (fd);
  free (buf);
  return 0;
}

static int body_calls;

static size_t
body (char *ptr, size_t size, size_t nmemb, void *user)
{
  (void) ptr;
  (void) user;
  body_calls++;
  return size * nmemb;
}

/* ---- a job's completion is delivered on the loop ---- */

static volatile int job_ran;
static pthread_t job_tid;
static int job_err = -1;

static void
job_work (void *arg)
{
  (void) arg;
  /* The worker can allocate nothing from here on.  */
  fail_alloc = 1;
}

static void
job_done (void *user, int err)
{
  (void) user;
  job_tid = pthread_self ();
  job_err = err;
  job_ran = 1;
}

/* A worker that has finished a job posts the completion to the loop.  When
   that post could not be made (no memory) the worker ran the completion
   itself, on its own thread, where it was written to run on the loop's: it
   touches the transfer.  The command is made when the job is submitted,
   where the caller can be told, and posting it cannot fail.  */
static void
test_completion_on_the_loop (void)
{
  struct twist_runtime *runtime = twist_runtime_new ();
  int i;

  check (runtime != NULL, "a runtime");
  check (twist_storage_submit (runtime->storage, job_work, NULL, job_done,
                               NULL,
                               runtime->loop) == TWIST_OK, "submit");
  for (i = 0; i < 400 && !job_ran; i++)
    {
      twist_runtime_run_once (runtime, 0);
      nap_ms (5);
    }
  fail_alloc = 0;
  check (job_ran, "the job's completion was delivered");
  check (pthread_equal (job_tid, main_tid),
         "on the loop's thread, not a worker's");
  check (job_err == TWIST_OK, "as a success");
  twist_runtime_free (runtime);
}

/* ---- a transfer is finished on the loop ---- */

/* The file handler's worker tells the loop that it is done by posting a last
   note.  When that could not be posted, the worker called
   twist_transfer_finish itself.  The note's command is made when the
   transfer attaches.  The chunks it posts before can fail, and the transfer
   then ends with that error, on the loop.  */
static void
test_finish_on_the_loop (const char *path)
{
  struct twist_runtime *runtime = twist_runtime_new ();
  struct twist_transfer *transfer = twist_transfer_new ();
  char url[128];
  struct check_job job = { 0, 0, 0 };
  int i;

  snprintf (url, sizeof url, "file://%s", path);
  twist_transfer_setopt (transfer, TWISTOPT_URL, url);
  transfer->write_cb = body;
  /* Before the start: the worker may run as soon as it has the job, and what
     it allocates before the flag is set is what the test is not about.  */
  off_thread_finish = 0;
  fail_alloc = 1;
  check (twist_runtime_start (runtime, transfer, check_job_done,
                              &job) == TWIST_OK,
         "start");
  for (i = 0; i < 400 && !job.done; i++)
    {
      twist_runtime_run_once (runtime, 0);
      nap_ms (5);
    }
  fail_alloc = 0;
  check (job.done && job.calls == 1,
         "the transfer ended, though nothing posted");
  check (job.result == TWIST_ERR_NOMEM, "with the error that stopped it");
  check (off_thread_finish == 0,
         "and was finished on the loop's thread, not a worker's");
  twist_transfer_free (transfer);
  twist_runtime_free (runtime);
}

/* ---- letting go of a transfer does not wait ---- */

#define LET_GO_LIMIT 0.5

/* Cancelling a handle whose worker is in a read that does not come back: the
   loop's thread waited for it, and so did every other transfer on that loop.
   Letting go of a transfer is to return at once, and the worker, when it is
   done, to clean up after itself.  */
static void
test_let_go_of_a_stuck_read (const char *path)
{
  struct twist_runtime *runtime = twist_runtime_new ();
  struct twist_transfer *transfer = twist_transfer_new ();
  char url[128];
  double t0;
  double took;

  snprintf (url, sizeof url, "file://%s", path);
  twist_transfer_setopt (transfer, TWISTOPT_URL, url);
  transfer->write_cb = body;
  slow_read_ms = 1500;
  check (twist_runtime_start (runtime, transfer, NULL, NULL) == TWIST_OK,
         "start");
  twist_runtime_run_once (runtime, 0);
  nap_ms (200);
  body_calls = 0;
  t0 = now ();
  check (twist_runtime_cancel (runtime, transfer) == TWIST_OK, "cancel");
  took = now () - t0;
  check (took < LET_GO_LIMIT,
         "cancelling a transfer whose read is stuck does not wait for the read");
  twist_transfer_free (transfer);
  /* The worker comes back by itself and finds nobody; what it read is not
     for the application.  */
  slow_read_ms = 0;
  twist_runtime_free (runtime);
  check (body_calls == 0, "and nothing was delivered after the transfer was let go");
}

/* The same for a transfer that has not started: the pool has two threads,
   both reading slowly, and a third transfer waits in the queue.  Letting go
   of it waited for a thread to be free to start it and finish it.  */
static void
test_let_go_of_a_queued_transfer (const char *path)
{
  struct twist_runtime *runtime = twist_runtime_new ();
  struct twist_transfer *transfer[3];
  char url[128];
  double t0;
  double took;
  int i;

  snprintf (url, sizeof url, "file://%s", path);
  slow_read_ms = 400;
  for (i = 0; i < 3; i++)
    {
      transfer[i] = twist_transfer_new ();
      twist_transfer_setopt (transfer[i], TWISTOPT_URL, url);
      transfer[i]->write_cb = body;
      check (twist_runtime_start (runtime, transfer[i], NULL,
                                  NULL) == TWIST_OK,
             "start");
    }
  twist_runtime_run_once (runtime, 0);
  nap_ms (100);
  t0 = now ();
  check (twist_runtime_cancel (runtime, transfer[2]) == TWIST_OK,
         "cancel third");
  took = now () - t0;
  check (took < LET_GO_LIMIT,
         "cancelling a transfer that has not started does not wait for the pool");
  for (i = 0; i < 3; i++)
    twist_transfer_free (transfer[i]);
  slow_read_ms = 0;
  twist_runtime_free (runtime);
}

int
main (void)
{
  char small[64];
  char big[64];

  main_tid = pthread_self ();
  twist_global_init ();
  if (make_file (small, sizeof small, 2000) != 0
      || make_file (big, sizeof big, 70000) != 0)
    {
      check (0, "files to read");
      return tests_finish ();
    }
  test_completion_on_the_loop ();
  test_finish_on_the_loop (big);
  test_let_go_of_a_stuck_read (small);
  test_let_go_of_a_queued_transfer (big);
  unlink (small);
  unlink (big);
  return tests_finish ();
}
