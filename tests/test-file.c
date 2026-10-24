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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

static int file_body_calls;
static int file_hopped;

static size_t
file_body (char *ptr, size_t size, size_t nmemb, void *userdata)
{
  (void) ptr;
  (void) size;
  (void) nmemb;
  (void) userdata;
  file_body_calls++;
  return nmemb;
}

static void
file_hop_done (void *user)
{
  int *flag = user;

  *flag = 1;
}

static void
file_hop_work (void *arg)
{
  struct twist_loop *loop = arg;

  twist_loop_post (loop, file_hop_done, &file_hopped);
}

static void
test_file_pool (void)
{
  struct twist_transfer *transfer;
  struct twist_runtime *runtime;
  struct check_job job = { 0, 0, 0 };

  transfer = twist_transfer_new ();
  check (transfer != NULL, "file transfer");
  check (twist_transfer_setopt (transfer, TWISTOPT_URL, "file://example.com/a")
         == TWIST_OK, "file url");
  transfer->write_cb = file_body;
  runtime = twist_runtime_new ();
  check (runtime != NULL && runtime->storage != NULL, "file pool");
  check (twist_runtime_start (runtime, transfer, check_job_done,
                              &job) == TWIST_OK,
         "file remote");
  check (check_pump (runtime, &job, 2000) && job.result == TWIST_ERR_URL
         && job.calls == 1 && file_body_calls == 0, "file remote done");
  twist_runtime_free (runtime);
  twist_transfer_free (transfer);

  file_hopped = 0;
  runtime = twist_runtime_new ();
  check (runtime != NULL, "file hop runtime");
  check (twist_storage_submit (runtime->storage, file_hop_work, runtime->loop,
                               NULL, NULL, NULL) == TWIST_OK, "file hop submit");
  check (twist_loop_run_once (runtime->loop) == TWIST_OK && file_hopped == 1,
         "file hop");
  twist_runtime_free (runtime);
}

static void
test_file_url (void)
{
  check (twist_file_check_url (NULL, "/etc/hostname", 1) == TWIST_OK, "file path");
  check (twist_file_check_url ("localhost", "/a", 1) == TWIST_OK, "localhost");
  check (twist_file_check_url ("127.0.0.1", "/a", 1) == TWIST_OK, "loopback");
  check (twist_file_check_url ("example.com", "/a", 1) == TWIST_ERR_URL,
         "remote file");
  check (twist_file_check_url ("localhost", "/", 0) == TWIST_ERR_URL,
         "no path");
  check (twist_file_check_url (NULL, NULL, 0) == TWIST_ERR_URL, "empty path");
  check (twist_file_check_url (NULL, "relative", 1) == TWIST_ERR_URL, "relative");
  {
    struct twist_url *url = NULL;

    check (twist_url_parse_int ("file://localhost", &url) == TWIST_OK,
           "parse host");
    check (url != NULL && !url->path_set, "host has no path");
    twist_url_free_int (url);
    url = NULL;
    check (twist_url_parse_int ("file:///etc/hostname", &url) == TWIST_OK,
           "parse path");
    check (url != NULL && url->path_set
           && strcmp (url->path, "/etc/hostname") == 0, "path set");
    twist_url_free_int (url);
  }
}


/* ---- a file of several chunks ---- */

#define BIG_FILE (3 * 1024 * 1024)

static char big_path[64];

static unsigned char
big_byte (size_t i)
{
  return (unsigned char) (i * 31 + (i >> 9));
}

static int
make_big_file (void)
{
  int fd;
  size_t i;
  unsigned char *buf = malloc (BIG_FILE);

  snprintf (big_path, sizeof big_path, "/tmp/twist-test-file-XXXXXX");
  fd = mkstemp (big_path);
  if (fd < 0 || buf == NULL)
    return -1;
  for (i = 0; i < BIG_FILE; i++)
    buf[i] = big_byte (i);
  if (write (fd, buf, BIG_FILE) != BIG_FILE)
    {
      close (fd);
      free (buf);
      return -1;
    }
  close (fd);
  free (buf);
  return 0;
}

static size_t big_seen;
static int big_wrong;
static int big_calls;
static int big_abort_after;	/* Refuse the data after this many calls.  */

static size_t
big_body (char *ptr, size_t size, size_t nmemb, void *userdata)
{
  size_t n = size * nmemb, i;

  (void) userdata;
  big_calls++;
  if (big_abort_after > 0 && big_calls > big_abort_after)
    return 0;
  for (i = 0; i < n; i++)
    if ((unsigned char) ptr[i] != big_byte (big_seen + i))
      big_wrong = 1;
  big_seen += n;
  return n;
}

static twist_transfer *
big_transfer (void)
{
  twist_transfer *transfer = twist_transfer_new ();
  char url[96];

  snprintf (url, sizeof url, "file://%s", big_path);
  twist_transfer_setopt (transfer, TWISTOPT_URL, url);
  twist_transfer_setopt (transfer, TWISTOPT_WRITEFUNCTION, big_body);
  big_seen = 0;
  big_wrong = 0;
  big_calls = 0;
  return transfer;
}

/* A file is delivered whole and in order through the pipeline of chunks.  */
static void
test_file_large (void)
{
  twist_transfer *transfer = big_transfer ();

  alarm (30);
  check (check_perform (transfer) == TWIST_OK, "a large file");
  alarm (0);
  check (big_seen == BIG_FILE && !big_wrong, "the whole file, in order");
  twist_transfer_free (transfer);
}

/* The application refuses the data part way: the transfer ends with an
   error, and ends.  */
static void
test_file_refused (void)
{
  twist_transfer *transfer = big_transfer ();

  big_abort_after = 3;
  alarm (30);
  check (check_perform (transfer) == TWIST_ERR_ABORTED, "data refused");
  alarm (0);
  check (big_calls == 4, "no data after it was refused");
  big_abort_after = 0;
  twist_transfer_free (transfer);
}

/* A transfer that is let go of while the worker is part way through the
   file, with its pipeline full and nobody acknowledging.  The worker waits
   for the loop, and the loop's thread is the one letting go, so releasing it
   has to acknowledge the chunks itself.  An alarm turns a hang into a
   failure.  NAP_NS is how long the worker is given first, and PUMPS how many
   times the loop runs before the release, so that some chunks have reached
   the application and some have not.  */
static void
file_abandon (int remove_first, long nap_ns, int pumps)
{
  twist_runtime *runtime = twist_runtime_new ();
  twist_transfer *transfer = big_transfer ();
  struct timespec nap = { 0, nap_ns };
  int calls_at_release, i;

  alarm (30);
  check (twist_runtime_start (runtime, transfer, NULL, NULL) == TWIST_OK,
         "start the file");
  if (nap_ns > 0)
    nanosleep (&nap, NULL);
  for (i = 0; i < pumps; i++)
    twist_runtime_run_once (runtime, 0);
  if (remove_first)
    check (twist_runtime_cancel (runtime, transfer) == TWIST_OK
           || transfer->runtime == NULL,
           "cancel it");
  calls_at_release = big_calls;
  twist_runtime_free (runtime);
  alarm (0);
  check (big_calls == calls_at_release,
         "nothing is delivered to the application after it is released");
  twist_transfer_free (transfer);
}

static void
test_file_abandoned (void)
{
  int i;

  /* The pipeline full and nothing acknowledged.  */
  file_abandon (1, 150000000L, 0);
  file_abandon (0, 150000000L, 0);
  /* Let go of at every stage: reading, posting, part delivered.  */
  for (i = 0; i < 30; i++)
    {
      file_abandon (i % 2, (long) i * 400000L, i % 4);
      check (big_seen <= BIG_FILE && !big_wrong,
             "what was delivered before the release was right");
    }
}

/* The file handler reads on a worker thread and waits for the loop to take
   what it reads.  A pool with no threads ran the worker on the loop's own
   thread, which then waited for itself, for any file of more than three
   chunks: it never came back from the call that added the handle.  Such a
   pool is refused.  (A signal ends the test if it does not come back.)  */
static void
test_file_without_threads (void)
{
  struct twist_runtime *runtime = twist_runtime_new ();
  struct twist_transfer *transfer = twist_transfer_new ();
  char url[128];
  struct check_job job = { 0, 0, 0 };
  int rc;

  check (runtime != NULL && transfer != NULL, "a runtime and a handle");
  twist_storage_free (runtime->storage);
  runtime->storage = twist_storage_new (0, 32);
  check (runtime->storage != NULL, "a pool with no threads");
  snprintf (url, sizeof url, "file://%s", big_path);
  twist_transfer_setopt (transfer, TWISTOPT_URL, url);
  transfer->write_cb = file_body;
  alarm (20);
  rc = twist_runtime_start (runtime, transfer, check_job_done, &job);
  check (rc == TWIST_OK && check_pump (runtime, &job, 2000), "started and ended");
  alarm (0);
  check (job.result == TWIST_ERR_UNSUPPORTED,
         "a file transfer is refused where there is no thread to read it");
  twist_runtime_free (runtime);
  twist_transfer_free (transfer);
}

int
main (void)
{
  test_file_url ();
  test_file_pool ();
  if (make_big_file () != 0)
    check (0, "a large file to read");
  else
    {
      test_file_large ();
      test_file_refused ();
      test_file_abandoned ();
      test_file_without_threads ();
      unlink (big_path);
    }
  return tests_finish ();
}
