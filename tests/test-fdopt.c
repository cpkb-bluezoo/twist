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

/* TWISTOPT_READFD and TWISTOPT_WRITEFD: a regular file goes through the file
   pipeline and a pipe is waited for; twist does not close the descriptor,
   make it non-blocking or, for a file, move its position.  */

static double
now_ms (void)
{
  struct timespec t;

  clock_gettime (CLOCK_MONOTONIC, &t);
  return (double) t.tv_sec * 1000.0 + (double) t.tv_nsec / 1e6;
}

static void
run_for (struct twist_runtime *rt, double ms)
{
  double end = now_ms () + ms;

  while (now_ms () < end)
    twist_loop_run_once_ms (rt->loop, 1);
}

struct cons
{
  struct twist_upload *up;
  uint8_t got[100000];
  size_t n;
  int ends, end_err;
};

static int
cons_chunk (void *user, const uint8_t *data, size_t len)
{
  struct cons *c = user;

  if (c->n + len <= sizeof c->got)
    memcpy (c->got + c->n, data, len);
  c->n += len;
  return TWIST_OK;
}

static void
cons_end (void *user, int err)
{
  struct cons *c = user;

  c->ends++;
  c->end_err = err;
}

static const struct twist_upload_consumer cons_ops = { cons_chunk, cons_end };

static struct twist_transfer *
make (struct twist_runtime *rt)
{
  struct twist_transfer *t = twist_transfer_new ();

  t->runtime = rt;
  t->loop = rt->loop;
  return t;
}

static uint8_t *
pattern (size_t n)
{
  uint8_t *b = malloc (n);
  size_t i;

  for (i = 0; i < n; i++)
    b[i] = (uint8_t) (i * 13 + i / 7);
  return b;
}

static int
temp_file (char *path, const uint8_t *data, size_t n)
{
  int fd;

  snprintf (path, 64, "/tmp/twist-test-fdopt-XXXXXX");
  fd = mkstemp (path);
  if (fd >= 0 && n > 0 && write (fd, data, n) != (ssize_t) n)
    {
      close (fd);
      return -1;
    }
  return fd;
}

/* A file is the upload: read from where the descriptor is, which is not moved,
   and read again from there for a restart.  */
static void
test_read_file (struct twist_runtime *rt)
{
  char path[64];
  uint8_t *data = pattern (50000);
  int fd = temp_file (path, data, 50000);
  struct twist_transfer *t = make (rt);
  struct cons k;
  off_t pos;

  memset (&k, 0, sizeof k);
  lseek (fd, 1000, SEEK_SET);
  twist_transfer_setopt (t, TWISTOPT_READFD, (long) fd);
  k.up = twist_transfer_upload (t);
  check (k.up != NULL, "a transfer with a descriptor to read has an upload");
  check (twist_upload_skip (k.up, 500) == TWIST_OK, "which can skip");
  twist_upload_attach (k.up, &cons_ops, &k, 4096);
  twist_upload_resume (k.up);
  run_for (rt, 300);
  check (k.ends == 1 && k.end_err == TWIST_OK && k.n == 50000 - 1500
         && memcmp (k.got, data + 1500, k.n) == 0,
         "a file is read from its position and the offset");
  pos = lseek (fd, 0, SEEK_CUR);
  check (pos == 1000, "and its position is not moved");
  check (fcntl (fd, F_GETFD) != -1, "nor is it closed");
  twist_upload_detach (k.up);
  check (twist_upload_restart (k.up) == TWIST_OK, "a file can be restarted");
  memset (&k.n, 0, sizeof k.n);
  k.ends = 0;
  twist_upload_attach (k.up, &cons_ops, &k, 4096);
  twist_upload_resume (k.up);
  run_for (rt, 300);
  check (k.ends == 1 && k.n == 50000 - 1000
         && memcmp (k.got, data + 1000, k.n) == 0,
         "and is read again from where it began");
  twist_upload_detach (k.up);
  twist_transfer_free (t);
  close (fd);
  unlink (path);
  free (data);
}

/* A pipe is waited for, is not made non-blocking, and cannot be restarted.  */
static void
test_read_pipe (struct twist_runtime *rt)
{
  int p[2];
  struct twist_transfer *t = make (rt);
  struct cons k;
  int fl;

  if (pipe (p) != 0)
    return;
  memset (&k, 0, sizeof k);
  fl = fcntl (p[0], F_GETFL);
  twist_transfer_setopt (t, TWISTOPT_READFD, (long) p[0]);
  k.up = twist_transfer_upload (t);
  twist_upload_attach (k.up, &cons_ops, &k, 4096);
  twist_upload_resume (k.up);
  run_for (rt, 50);
  check (k.n == 0 && k.ends == 0, "a pipe with nothing in it is waited for");
  check (write (p[1], "hello", 5) == 5, "something is written");
  run_for (rt, 100);
  check (k.n == 5 && memcmp (k.got, "hello", 5) == 0, "and it arrives");
  close (p[1]);
  run_for (rt, 100);
  check (k.ends == 1 && k.end_err == TWIST_OK, "the end of the pipe is the end");
  check ((fcntl (p[0], F_GETFL) & O_NONBLOCK) == (fl & O_NONBLOCK),
         "the pipe is not made non-blocking");
  twist_upload_detach (k.up);
  check (twist_upload_restart (k.up) == TWIST_ERR_REWIND,
         "a pipe cannot be read again: a rewind error");
  twist_transfer_free (t);
  check (fcntl (p[0], F_GETFD) != -1, "and is not closed");
  close (p[0]);
}

struct dl
{
  size_t calls;
};

/* The body is written to a pipe: a pipe that is full pauses the transfer, and
   the transfer goes on when it is read.  */
static void
test_write_pipe (struct twist_runtime *rt)
{
  int p[2];
  struct twist_transfer *t = make (rt);
  uint8_t *data = pattern (1u << 20);
  uint8_t *in = malloc (1u << 20);
  size_t sent = 0, seen = 0;
  double end;

  if (pipe (p) != 0)
    return;
  fcntl (p[0], F_SETFL, O_NONBLOCK);	/* Our own end of it.  */
  twist_transfer_setopt (t, TWISTOPT_WRITEFD, (long) p[1]);
  check (twist_transfer_fds_setup (t) == TWIST_OK, "the descriptors are set up");
  check (t->write_cb != NULL, "and the body goes to a callback of its own");
  while (sent < (1u << 20))
    {
      size_t n = (1u << 20) - sent;

      if (n > 4096)
        n = 4096;
      if (twist_deliver (t, data + sent, n) < n)
        break;
      sent += n;
      if (t->sink_paused)
        break;
    }
  check (t->sink_paused, "a pipe that is full pauses the transfer");
  /* Deliver the rest; it is held, and the reader makes room.  */
  while (sent < (1u << 20))
    {
      size_t n = (1u << 20) - sent;

      if (n > 4096)
        n = 4096;
      if (twist_deliver (t, data + sent, n) < n)
        break;
      sent += n;
    }
  end = now_ms () + 3000;
  while (now_ms () < end && seen < (1u << 20))
    {
      ssize_t n = read (p[0], in + seen, (1u << 20) - seen);

      if (n > 0)
        seen += (size_t) n;
      twist_loop_run_once_ms (rt->loop, 1);
    }
  check (sent == (1u << 20) && seen == (1u << 20)
         && memcmp (in, data, 1u << 20) == 0,
         "and goes on when it is read: all of it arrives, in order");
  check (fcntl (p[1], F_GETFD) != -1, "the descriptor is not closed");
  twist_transfer_free (t);
  close (p[0]);
  close (p[1]);
  free (data);
  free (in);
}

/* The body is written to a file at its position, and the transfer is not over
   until it is written.  */
static void
test_write_file (struct twist_runtime *rt)
{
  char path[64];
  int fd = temp_file (path, (const uint8_t *) "0123456789", 10);
  struct twist_transfer *t = make (rt);
  uint8_t *data = pattern (300000);
  uint8_t *got = malloc (300010);
  size_t i;
  FILE *fp;
  size_t n;

  lseek (fd, 10, SEEK_SET);
  twist_transfer_setopt (t, TWISTOPT_WRITEFD, (long) fd);
  twist_transfer_fds_setup (t);
  for (i = 0; i < 300000; i += 5000)
    check (twist_deliver (t, data + i, 5000) == 5000, "delivered");
  twist_transfer_finish (t, TWIST_OK);
  check (!t->done, "the transfer is not over while the body is being written");
  run_for (rt, 500);
  check (t->done && t->result == TWIST_OK, "and is, once it is written");
  fp = fopen (path, "rb");
  n = fp != NULL ? fread (got, 1, 300010, fp) : 0;
  if (fp != NULL)
    fclose (fp);
  check (n == 300010 && memcmp (got, "0123456789", 10) == 0
         && memcmp (got + 10, data, 300000) == 0,
         "the file is what was there, then the body");
  check (lseek (fd, 0, SEEK_CUR) == 10, "the position is not moved");
  twist_transfer_free (t);
  close (fd);
  unlink (path);
  free (data);
  free (got);
}

/* A body that comes in small pieces goes to the writer in few: a call for
   each piece was a hand-over to another thread for each, which cost more than
   the writing.  What has come reaches the file without waiting for the end of
   the transfer, though: a stream that is slow is not held back.  */
static void
test_write_batches (struct twist_runtime *rt)
{
  char path[64];
  int fd = temp_file (path, NULL, 0);
  struct twist_transfer *t = make (rt);
  uint8_t *data = pattern (300000);
  uint8_t *got = malloc (300000);
  struct stat st;
  size_t i;
  FILE *fp;
  size_t n;

  twist_transfer_setopt (t, TWISTOPT_WRITEFD, (long) fd);
  twist_transfer_fds_setup (t);
  for (i = 0; i < 300000; i += 5000)
    check (twist_deliver (t, data + i, 5000) == 5000, "delivered");
  run_for (rt, 300);
  check (twist_wsink_writes (t) <= 8,
         "sixty pieces go to the writer in a few writes");
  check (fstat (fd, &st) == 0 && st.st_size == 300000,
         "and all of it is in the file before the transfer is finished");
  twist_transfer_finish (t, TWIST_OK);
  run_for (rt, 300);
  check (t->done && t->result == TWIST_OK, "which then ends well");
  fp = fopen (path, "rb");
  n = fp != NULL ? fread (got, 1, 300000, fp) : 0;
  if (fp != NULL)
    fclose (fp);
  check (n == 300000 && memcmp (got, data, 300000) == 0,
         "with the body in order");
  twist_transfer_free (t);
  close (fd);
  unlink (path);
  free (data);
  free (got);
}

/* The body has been written, and acknowledged, before the transfer finishes (a
   slow connection, or a loaded machine): nothing else is coming from the
   writer to say it is done, and the end must still close it.  */
static void
test_write_file_then_finish (struct twist_runtime *rt)
{
  char path[64];
  int fd = temp_file (path, NULL, 0);
  struct twist_transfer *t = make (rt);
  uint8_t *data = pattern (5000);

  twist_transfer_setopt (t, TWISTOPT_WRITEFD, (long) fd);
  twist_transfer_fds_setup (t);
  check (twist_deliver (t, data, 5000) == 5000, "delivered");
  run_for (rt, 300);
  check (!t->done, "the transfer is not over before it is finished");
  twist_transfer_finish (t, TWIST_OK);
  run_for (rt, 500);
  check (t->done && t->result == TWIST_OK,
         "and it is over once it is, though the write had already gone");
  twist_transfer_free (t);
  close (fd);
  unlink (path);
  free (data);
}

/* A descriptor that cannot be polled and is not a regular file (/dev/null is
   one) takes the body too: it is written to on a thread of the pool.  */
static void
test_write_unpollable (struct twist_runtime *rt)
{
  int fd = open ("/dev/null", O_WRONLY);
  struct twist_transfer *t = make (rt);
  uint8_t *data = pattern (100000);
  size_t i;

  check (fd >= 0, "/dev/null opened");
  twist_transfer_setopt (t, TWISTOPT_WRITEFD, (long) fd);
  check (twist_transfer_fds_setup (t) == TWIST_OK, "a descriptor set up");
  for (i = 0; i < 100000; i += 5000)
    check (twist_deliver (t, data + i, 5000) == 5000, "delivered");
  twist_transfer_finish (t, TWIST_OK);
  run_for (rt, 500);
  check (t->done && t->result == TWIST_OK,
         "the transfer ends well and is not failed by the descriptor");
  twist_transfer_free (t);
  close (fd);
  free (data);
}

int
main (void)
{
  struct twist_runtime *rt = twist_runtime_new ();

  if (rt == NULL)
    return 77;
  test_read_file (rt);
  test_read_pipe (rt);
  test_write_pipe (rt);
  test_write_file (rt);
  test_write_batches (rt);
  test_write_file_then_finish (rt);
  test_write_unpollable (rt);
  twist_runtime_free (rt);
  return tests_finish ();
}
