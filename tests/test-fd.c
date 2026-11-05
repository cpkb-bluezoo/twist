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
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

/* Pipes can be waited for, and are not twist's to make non-blocking.  A read
   is made only when there is something to read; a write only when there is
   room.  */

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

struct src
{
  uint8_t got[4096];
  size_t n;
  size_t take;			/* Take this many at a time; 0: all.  */
  int chunks;
  int ends;
  int end_err;
  struct twist_fd_source *s;
};

static size_t
src_chunk (void *user, const uint8_t *data, size_t len)
{
  struct src *s = user;
  size_t n = len;

  if (s->take != 0 && n > s->take)
    n = s->take;
  if (s->n + n <= sizeof s->got)
    memcpy (s->got + s->n, data, n);
  s->n += n;
  s->chunks++;
  return n;
}

static void
src_end (void *user, int err)
{
  struct src *s = user;

  s->ends++;
  s->end_err = err;
}

static const struct twist_fd_source_ops src_ops = { src_chunk, src_end };

static int ticks;

static void
tick (void *user)
{
  (void) user;
  ticks++;
}

/* A pipe with nothing in it does not hold up the loop: a timer on another
   transfer still runs.  The source is read once there is a byte.  */
static void
test_idle_pipe (struct twist_loop *loop)
{
  int p[2];
  struct src s;
  struct twist_timer *timer = NULL;

  if (pipe (p) != 0)
    return;
  memset (&s, 0, sizeof s);
  check (twist_fd_source_new (loop, p[0], &src_ops, &s, &s.s) == TWIST_OK,
         "a source is made on a pipe");
  ticks = 0;
  twist_loop_schedule (loop, twist_loop_now (loop) + 20, tick, NULL, &timer);
  run_for (loop, 100);
  check (ticks == 1, "a pipe with nothing in it does not stop the loop");
  check (s.chunks == 0, "and nothing is read from it");
  check (write (p[1], "x", 1) == 1, "a byte is written");
  run_for (loop, 100);
  check (s.chunks == 1 && s.n == 1 && s.got[0] == 'x',
         "and the source is read once there is one");
  close (p[1]);
  run_for (loop, 100);
  check (s.ends == 1 && s.end_err == TWIST_OK,
         "the end of the descriptor ends the source, once");
  twist_fd_source_free (s.s);
  close (p[0]);
}

/* A chunk that is only partly used pauses the source; resuming goes on.  */
static void
test_source_pause (struct twist_loop *loop)
{
  int p[2];
  struct src s;
  uint8_t in[100];
  size_t i;
  int ok = 1;

  if (pipe (p) != 0)
    return;
  for (i = 0; i < sizeof in; i++)
    in[i] = (uint8_t) i;
  memset (&s, 0, sizeof s);
  s.take = 10;
  twist_fd_source_new (loop, p[0], &src_ops, &s, &s.s);
  check (write (p[1], in, sizeof in) == (ssize_t) sizeof in, "bytes written");
  run_for (loop, 100);
  check (s.n == 10, "a source that takes part of a chunk stops there");
  check (write (p[1], in, 5) == 5, "more bytes are written");
  run_for (loop, 50);
  check (s.n == 10, "and is given nothing while it is paused");
  s.take = 0;
  twist_fd_source_resume (s.s);
  run_for (loop, 100);
  check (s.n == 105, "resuming delivers the tail, then what came after");
  for (i = 0; i < 100; i++)
    if (s.got[i] != (uint8_t) i)
      ok = 0;
  check (ok, "in order");
  twist_fd_source_free (s.s);
  close (p[0]);
  close (p[1]);
}

/* The descriptor is the caller's: freeing a source does not close it, and
   it is not made non-blocking.  */
static void
test_not_ours (struct twist_loop *loop)
{
  int p[2];
  struct src s;
  int flags_before, flags_after;
  char c;

  if (pipe (p) != 0)
    return;
  flags_before = fcntl (p[0], F_GETFL);
  memset (&s, 0, sizeof s);
  twist_fd_source_new (loop, p[0], &src_ops, &s, &s.s);
  run_for (loop, 20);
  flags_after = fcntl (p[0], F_GETFL);
  check ((flags_after & O_NONBLOCK) == (flags_before & O_NONBLOCK),
         "the descriptor is not made non-blocking");
  twist_fd_source_free (s.s);
  check (fcntl (p[0], F_GETFD) != -1, "freeing the source leaves it open");
  check (write (p[1], "y", 1) == 1 && read (p[0], &c, 1) == 1 && c == 'y',
         "and usable");
  close (p[0]);
  close (p[1]);
}

struct snk
{
  struct twist_fd_sink *s;
  int ready;
  int errors;
  int err;
};

static void
snk_ready (void *user)
{
  struct snk *k = user;

  k->ready++;
}

static void
snk_error (void *user, int err)
{
  struct snk *k = user;

  k->errors++;
  k->err = err;
}

static const struct twist_fd_sink_ops snk_ops = { snk_ready, snk_error };

/* A sink whose pipe is full is full, and is ready again when the reader has
   drained it.  Nothing is lost, and no write is larger than PIPE_BUF.  */
static void
test_sink_full (struct twist_loop *loop)
{
  int p[2];
  struct snk k;
  uint8_t chunk[1000];
  uint8_t in[65536];
  size_t sent = 0, seen = 0;
  double end;

  if (pipe (p) != 0)
    return;
  fcntl (p[0], F_SETFL, O_NONBLOCK);	/* Our own end, for the test.  */
  memset (&k, 0, sizeof k);
  memset (chunk, 'k', sizeof chunk);
  check (twist_fd_sink_new (loop, p[1], &snk_ops, &k, &k.s) == TWIST_OK,
         "a sink is made on a pipe");
  while (!twist_fd_sink_full (k.s) && sent < 8u * 1024u * 1024u)
    {
      if (twist_fd_sink_write (k.s, chunk, sizeof chunk) != TWIST_OK)
        break;
      sent += sizeof chunk;
    }
  check (twist_fd_sink_full (k.s), "a sink whose pipe is full says so");
  check (twist_fd_sink_pending (k.s) < 2 * TWIST_OUT_HIGH,
         "and holds about a chunk");
  k.ready = 0;
  end = now_ms () + 3000;
  while (now_ms () < end && !(k.ready > 0 && seen == sent))
    {
      ssize_t n = read (p[0], in, sizeof in);

      if (n > 0)
        seen += (size_t) n;
      twist_loop_run_once_ms (loop, 1);
    }
  check (k.ready > 0 && seen == sent,
         "when the reader drains it, it is ready, and all of it arrived");
  check (!twist_fd_sink_full (k.s), "and is no longer full");
  twist_fd_sink_free (k.s);
  check (fcntl (p[1], F_GETFD) != -1, "freeing the sink leaves its pipe open");
  close (p[0]);
  close (p[1]);
}

/* A reader that has gone is an error and not a signal.  */
static void
test_sink_gone (struct twist_loop *loop)
{
  int p[2];
  struct snk k;

  if (pipe (p) != 0)
    return;
  memset (&k, 0, sizeof k);
  close (p[0]);
  twist_fd_sink_new (loop, p[1], &snk_ops, &k, &k.s);
  twist_fd_sink_write (k.s, (const uint8_t *) "gone", 4);
  run_for (loop, 100);
  check (k.errors == 1 && k.err != TWIST_OK,
         "a reader that has gone is an error for the sink");
  twist_fd_sink_free (k.s);
  close (p[1]);
}

int
main (void)
{
  struct twist_loop *loop = twist_loop_new (0);

  if (loop == NULL)
    return 77;
  test_idle_pipe (loop);
  test_source_pause (loop);
  test_not_ours (loop);
  test_sink_full (loop);
  test_sink_gone (loop);
  twist_loop_free (loop);
  return tests_finish ();
}
