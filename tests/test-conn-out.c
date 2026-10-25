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

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

/* What a connection holds that has not been written is about a chunk: it says
   when it is full, a producer stops, and a body that is large is streamed,
   read only as the connection writes, so that a peer that does not read does
   not make anything grow.  The far end is a socket pair.  */

static double
now_ms (void)
{
  struct timespec t;

  clock_gettime (CLOCK_MONOTONIC, &t);
  return (double) t.tv_sec * 1000.0 + (double) t.tv_nsec / 1e6;
}

static int
pair (int sv[2])
{
  if (socketpair (AF_UNIX, SOCK_STREAM, 0, sv) != 0)
    return -1;
  fcntl (sv[0], F_SETFL, O_NONBLOCK);
  fcntl (sv[1], F_SETFL, O_NONBLOCK);
  return 0;
}

static struct twist_connection *
make (struct twist_loop *loop, int fd)
{
  struct twist_connection *c = twist_connection_new (loop);

  twist_connection_set_fd (c, fd);
  return c;
}

static int drained;

static void
on_drained (struct twist_endpoint *ep)
{
  (void) ep;
  drained++;
}

/* A producer is told when to stop: after a send the connection says it is full
   once it holds a chunk that the peer has not taken, and says when it has
   written it all.  Nothing else is queued.  */
static void
test_backpressure (struct twist_loop *loop)
{
  int sv[2];
  uint8_t buf[1000];
  struct twist_connection *c;
  struct twist_endpoint *ep;
  size_t sent = 0, seen = 0;
  double end;

  if (pair (sv) != 0)
    return;
  memset (buf, 'a', sizeof buf);
  c = make (loop, sv[0]);
  ep = twist_connection_endpoint (c);
  ep->on_write_ready = on_drained;
  check (!twist_endpoint_full (ep), "an idle connection is not full");
  /* The peer does not read.  The socket takes some; then it is full.  */
  while (!twist_endpoint_full (ep) && sent < 64u * 1024u * 1024u)
    {
      if (twist_endpoint_send (ep, buf, sizeof buf) != TWIST_OK)
        break;
      sent += sizeof buf;
    }
  check (twist_endpoint_full (ep), "it says when it is full");
  check (twist_endpoint_pending (ep) < 2 * TWIST_OUT_HIGH,
         "holding about a chunk, and not more");
  drained = 0;
  end = now_ms () + 3000;
  while (now_ms () < end && !(drained > 0 && seen == sent))
    {
      uint8_t in[65536];
      ssize_t n = read (sv[1], in, sizeof in);

      if (n > 0)
        seen += (size_t) n;
      twist_loop_run_once_ms (loop, 1);
    }
  check (seen == sent && drained > 0, "and when it has written it all");
  check (!twist_endpoint_full (ep), "and is not full then");
  twist_connection_free (c);
  close (sv[1]);
}

/* A connection whose write calls back into it (as a tunnel's does, when what
   it writes to drains at once and says so): what was sent is written once,
   and in order.  */
static struct twist_connection *nest_c;
static uint8_t nest_out[200000];
static size_t nest_n;
static int nest_depth, nest_max_depth;

static ssize_t
nest_write (void *user, const uint8_t *buf, size_t len)
{
  size_t take = len > 3000 ? 3000 : len;

  (void) user;
  nest_depth++;
  if (nest_depth > nest_max_depth)
    nest_max_depth = nest_depth;
  /* The consumer is ready again as soon as it has taken this.  */
  if (nest_n + take <= sizeof nest_out)
    memcpy (nest_out + nest_n, buf, take);
  nest_n += take;
  twist_connection_on_writable (nest_c);
  nest_depth--;
  return (ssize_t) take;
}

static ssize_t
nest_read (void *user, uint8_t *buf, size_t len)
{
  (void) user;
  (void) buf;
  (void) len;
  errno = EAGAIN;
  return -1;
}

static void
nest_free (void *p)
{
  (void) p;
}

static void
test_nested_write (struct twist_loop *loop)
{
  uint8_t in[60000];
  size_t i;
  int ok = 1;

  for (i = 0; i < sizeof in; i++)
    in[i] = (uint8_t) (i * 7 + i / 251);
  nest_c = twist_connection_new (loop);
  twist_connection_set_io (nest_c, nest_read, nest_write, NULL);
  twist_connection_set_owner (nest_c, NULL, nest_free, NULL);
  twist_endpoint_send (twist_connection_endpoint (nest_c), in, sizeof in);
  check (nest_n == sizeof in, "all that was sent is written, no more");
  for (i = 0; i < sizeof in && i < nest_n; i++)
    if (nest_out[i] != in[i])
      ok = 0;
  check (ok, "and in order");
  check (nest_max_depth == 1, "a write is not begun inside another");
  twist_connection_free (nest_c);
}

/* The most a connection has held is told (for tests).  */
static void
test_peak (struct twist_loop *loop)
{
  int sv[2];
  uint8_t buf[1000];
  struct twist_connection *c;
  int i;

  if (pair (sv) != 0)
    return;
  memset (buf, 'p', sizeof buf);
  c = make (loop, sv[0]);
  twist_connection_peak_reset ();
  for (i = 0; i < 40; i++)
    twist_endpoint_send (twist_connection_endpoint (c), buf, sizeof buf);
  check (twist_connection_peak_out () >= 1000, "the peak is kept");
  twist_connection_peak_reset ();
  check (twist_connection_peak_out () == 0, "and can be reset");
  twist_connection_free (c);
  close (sv[1]);
}

struct src
{
  size_t total, made;
  size_t most_pending;		/* The most queued when it was read from.  */
  struct twist_endpoint *ep;
  int ended, end_err, ends;
};

static size_t
s_read (void *user, uint8_t *buf, size_t cap)
{
  struct src *s = user;
  size_t n = s->total - s->made;
  size_t pend = twist_endpoint_pending (s->ep);

  if (pend > s->most_pending)
    s->most_pending = pend;
  if (n > cap)
    n = cap;
  memset (buf, 's', n);
  s->made += n;
  return n;
}

static void
s_end (void *user, int err)
{
  struct src *s = user;

  s->ended = 1;
  s->end_err = err;
  s->ends++;
}

static void
test_stream (struct twist_loop *loop)
{
  int sv[2];
  struct twist_connection *c;
  struct src s;
  size_t seen = 0;
  double end;

  if (pair (sv) != 0)
    return;
  memset (&s, 0, sizeof s);
  s.total = 5u * 1024u * 1024u;
  c = make (loop, sv[0]);
  s.ep = twist_connection_endpoint (c);
  check (twist_connection_stream (c, s_read, s_end, &s) == TWIST_OK,
         "a stream is begun");
  /* The peer reads nothing for a while: the connection reads ahead only a
     little.  */
  end = now_ms () + 200;
  while (now_ms () < end)
    twist_loop_run_once_ms (loop, 5);
  check (s.made < s.total / 2 && !s.ended,
         "a peer that does not read does not make it read ahead");
  check (s.most_pending <= 2 * TWIST_OUT_HIGH, "and what is queued is a chunk");
  /* Now it reads everything.  */
  end = now_ms () + 8000;
  while (!s.ended && now_ms () < end)
    {
      uint8_t in[65536];
      ssize_t n = read (sv[1], in, sizeof in);

      if (n > 0)
        seen += (size_t) n;
      twist_loop_run_once_ms (loop, 1);
    }
  check (s.ended && s.end_err == TWIST_OK && s.ends == 1,
         "the end is called once, with no error");
  check (s.made == s.total, "all of it was produced");
  /* What was queued after the last read is still to be written.  */
  end = now_ms () + 2000;
  while (seen < s.total && now_ms () < end)
    {
      uint8_t in[65536];
      ssize_t n = read (sv[1], in, sizeof in);

      if (n > 0)
        seen += (size_t) n;
      twist_loop_run_once_ms (loop, 1);
    }
  check (seen == s.total, "and the peer got all of it");
  twist_connection_free (c);
  close (sv[1]);
}

static void
test_stream_freed (struct twist_loop *loop)
{
  int sv[2];
  struct twist_connection *c;
  struct src s;
  double end;

  if (pair (sv) != 0)
    return;
  memset (&s, 0, sizeof s);
  s.total = 5u * 1024u * 1024u;
  c = make (loop, sv[0]);
  s.ep = twist_connection_endpoint (c);
  twist_connection_stream (c, s_read, s_end, &s);
  end = now_ms () + 100;
  while (now_ms () < end)
    twist_loop_run_once_ms (loop, 5);
  twist_connection_free (c);
  check (s.ended && s.end_err != TWIST_OK && s.ends == 1,
         "a stream that is cut short is told, once");
  close (sv[1]);
}

int
main (void)
{
  struct twist_loop *loop = twist_loop_new (0);

  if (loop == NULL)
    return 77;
  test_backpressure (loop);
  test_peak (loop);
  test_nested_write (loop);
  test_stream (loop);
  test_stream_freed (loop);
  twist_loop_free (loop);
  return tests_finish ();
}
