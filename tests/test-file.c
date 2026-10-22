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
  struct twist_easy *easy;
  struct twist_multi *multi;

  easy = twist_easy_init ();
  check (easy != NULL, "file easy");
  check (twist_easy_setopt (easy, TWISTOPT_URL, "file://example.com/a")
         == TWIST_OK, "file url");
  easy->write_cb = file_body;
  multi = twist_multi_init ();
  check (multi != NULL && multi->storage != NULL, "file pool");
  check (twist_multi_add_handle (multi, easy) == TWIST_ERR_URL, "file remote");
  check (easy->done && easy->result == TWIST_ERR_URL && file_body_calls == 0,
         "file remote done");
  twist_multi_cleanup (multi);
  twist_easy_cleanup (easy);

  file_hopped = 0;
  multi = twist_multi_init ();
  check (multi != NULL, "file hop multi");
  check (twist_storage_submit (multi->storage, file_hop_work, multi->loop,
                               NULL, NULL, NULL) == TWIST_OK, "file hop submit");
  check (twist_loop_run_once (multi->loop) == TWIST_OK && file_hopped == 1,
         "file hop");
  twist_multi_cleanup (multi);
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

static twist_easy *
big_easy (void)
{
  twist_easy *easy = twist_easy_init ();
  char url[96];

  snprintf (url, sizeof url, "file://%s", big_path);
  twist_easy_setopt (easy, TWISTOPT_URL, url);
  twist_easy_setopt (easy, TWISTOPT_WRITEFUNCTION, big_body);
  big_seen = 0;
  big_wrong = 0;
  big_calls = 0;
  return easy;
}

/* A file is delivered whole and in order through the pipeline of chunks.  */
static void
test_file_large (void)
{
  twist_easy *easy = big_easy ();

  alarm (30);
  check (twist_easy_perform (easy) == TWIST_OK, "a large file");
  alarm (0);
  check (big_seen == BIG_FILE && !big_wrong, "the whole file, in order");
  twist_easy_cleanup (easy);
}

/* The application refuses the data part way: the transfer ends with an
   error, and ends.  */
static void
test_file_refused (void)
{
  twist_easy *easy = big_easy ();

  big_abort_after = 3;
  alarm (30);
  check (twist_easy_perform (easy) == TWIST_ERR_ABORTED, "data refused");
  alarm (0);
  check (big_calls == 4, "no data after it was refused");
  big_abort_after = 0;
  twist_easy_cleanup (easy);
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
  twist_multi *multi = twist_multi_init ();
  twist_easy *easy = big_easy ();
  struct timespec nap = { 0, nap_ns };
  int calls_at_release, running = 0, i;

  alarm (30);
  check (twist_multi_add_handle (multi, easy) == TWIST_OK, "add the file");
  if (nap_ns > 0)
    nanosleep (&nap, NULL);
  for (i = 0; i < pumps; i++)
    twist_multi_perform (multi, &running);
  if (remove_first)
    check (twist_multi_remove_handle (multi, easy) == TWIST_OK, "remove it");
  calls_at_release = big_calls;
  twist_multi_cleanup (multi);
  alarm (0);
  check (big_calls == calls_at_release,
         "nothing is delivered to the application after it is released");
  twist_easy_cleanup (easy);
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
  struct twist_multi *multi = twist_multi_init ();
  struct twist_easy *easy = twist_easy_init ();
  char url[128];
  int rc;

  check (multi != NULL && easy != NULL, "a multi and a handle");
  twist_storage_free (multi->storage);
  multi->storage = twist_storage_new (0, 32);
  check (multi->storage != NULL, "a pool with no threads");
  snprintf (url, sizeof url, "file://%s", big_path);
  twist_easy_setopt (easy, TWISTOPT_URL, url);
  easy->write_cb = file_body;
  alarm (20);
  rc = twist_multi_add_handle (multi, easy);
  alarm (0);
  check (rc == TWIST_ERR_UNSUPPORTED,
         "a file transfer is refused where there is no thread to read it");
  twist_multi_remove_handle (multi, easy);
  twist_multi_cleanup (multi);
  twist_easy_cleanup (easy);
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
