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
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

/* A source that is pushed into, and a sink that can pause.  The far end of
   the connection is a socket pair that the test reads when it chooses.  */

#define CHUNK 4096

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

/* Run the loop and read what the peer is sent, for MS.  */
static size_t
drain (struct twist_loop *loop, int fd, double ms)
{
  size_t seen = 0;
  double end = now_ms () + ms;

  while (now_ms () < end)
    {
      uint8_t in[65536];
      ssize_t n = read (fd, in, sizeof in);

      if (n > 0)
        seen += (size_t) n;
      twist_loop_run_once_ms (loop, 1);
    }
  return seen;
}

struct prod
{
  struct twist_connection *c;
  size_t total;			/* What it has to push.  */
  size_t pushed;
  int paused;			/* Told to pause, and not resumed.  */
  int pauses;
  int resumes;
  int pushed_while_paused;
  int ends;
  int end_err;
  int released;
  int restarts;
  int restart_rc;
  int has_restart;
  size_t most_pending;
  uint8_t chunk[CHUNK];
};

static void
p_release (void *user)
{
  struct prod *p = user;

  p->released++;
}

/* Push until the connection says to stop or there is no more.  */
static void
p_run (struct prod *p)
{
  while (!p->paused && p->pushed < p->total)
    {
      size_t n = p->total - p->pushed;
      size_t pend;

      if (n > CHUNK)
        n = CHUNK;
      memset (p->chunk, 'p', n);
      if (twist_connection_push (p->c, p->chunk, n, p_release, p) != TWIST_OK)
        return;
      p->pushed += n;
      pend = twist_endpoint_pending (twist_connection_endpoint (p->c));
      if (pend > p->most_pending)
        p->most_pending = pend;
    }
  if (!p->paused && p->pushed == p->total)
    {
      p->pushed = p->total + 1;	/* The end is pushed once.  */
      twist_connection_push_end (p->c, TWIST_OK);
    }
}

static void
p_pause (void *user)
{
  struct prod *p = user;

  p->paused = 1;
  p->pauses++;
}

static void
p_resume (void *user)
{
  struct prod *p = user;

  p->paused = 0;
  p->resumes++;
  p_run (p);
}

static int
p_restart (void *user)
{
  struct prod *p = user;

  p->restarts++;
  return p->restart_rc;
}

static void
p_end (void *user, int err)
{
  struct prod *p = user;

  p->ends++;
  p->end_err = err;
}

static const struct twist_source_ops ops_norestart = { p_pause, p_resume, NULL,
                                                       p_end };
static const struct twist_source_ops ops_restart = { p_pause, p_resume,
                                                     p_restart, p_end };

/* A peer that does not read stops the source once the connection holds
   TWIST_OUT_HIGH; draining resumes it, and the end is called once.  */
static void
test_pause_resume (struct twist_loop *loop)
{
  int sv[2];
  struct prod p;
  size_t seen;

  if (pair (sv) != 0)
    return;
  memset (&p, 0, sizeof p);
  p.total = 4u * 1024u * 1024u;
  p.c = make (loop, sv[0]);
  check (twist_connection_attach_source (p.c, &ops_norestart, &p) == TWIST_OK,
         "a source is attached");
  p_run (&p);
  drain (loop, -1, 150);
  check (p.paused && p.pauses == 1, "the source is paused once it is full");
  check (twist_connection_source_paused (p.c), "and the connection says so");
  check (p.pushed < p.total, "it is not left to push all of it");
  check (p.most_pending <= TWIST_OUT_HIGH + CHUNK + 1,
         "what is queued is a chunk past the high mark");
  {
    size_t held = p.pushed;

    drain (loop, -1, 100);
    check (p.pushed == held, "a stalled peer causes no further chunk");
  }
  check (p.ends == 0, "and it is not over");
  seen = drain (loop, sv[1], 6000);
  check (p.resumes > 0, "draining resumes the source");
  check (p.ends == 1 && p.end_err == TWIST_OK, "the end is called once");
  seen += drain (loop, sv[1], 300);
  check (seen == p.total, "and the peer got all of it");
  check (p.released == (int) ((p.total + CHUNK - 1) / CHUNK),
         "each chunk is released");
  check (!twist_connection_streaming (p.c), "nothing is attached after");
  twist_connection_free (p.c);
  check (p.ends == 1, "freeing it does not end it again");
  close (sv[1]);
}

/* A connection that goes before the source is over tells the source why.  */
static void
test_freed (struct twist_loop *loop)
{
  int sv[2];
  struct prod p;

  if (pair (sv) != 0)
    return;
  memset (&p, 0, sizeof p);
  p.total = 4u * 1024u * 1024u;
  p.c = make (loop, sv[0]);
  twist_connection_attach_source (p.c, &ops_norestart, &p);
  p_run (&p);
  drain (loop, -1, 50);
  twist_connection_free (p.c);
  check (p.ends == 1 && p.end_err != TWIST_OK,
         "a source cut short is told, once, with an error");
  close (sv[1]);
}

/* The producer failing is passed on as it is.  */
static void
test_producer_fails (struct twist_loop *loop)
{
  int sv[2];
  struct prod p;

  if (pair (sv) != 0)
    return;
  memset (&p, 0, sizeof p);
  p.c = make (loop, sv[0]);
  twist_connection_attach_source (p.c, &ops_norestart, &p);
  twist_connection_push_end (p.c, TWIST_ERR_ABORTED);
  twist_connection_push_end (p.c, TWIST_OK);
  check (p.ends == 1 && p.end_err == TWIST_ERR_ABORTED,
         "a failure of the producer reaches the end callback, once");
  twist_connection_free (p.c);
  close (sv[1]);
}

/* Only one source at a time.  */
static void
test_one_source (struct twist_loop *loop)
{
  int sv[2];
  struct prod p;

  if (pair (sv) != 0)
    return;
  memset (&p, 0, sizeof p);
  p.c = make (loop, sv[0]);
  check (twist_connection_attach_source (p.c, &ops_norestart, &p) == TWIST_OK,
         "the first source is attached");
  check (twist_connection_attach_source (p.c, &ops_norestart, &p)
         != TWIST_OK, "a second is refused");
  twist_connection_free (p.c);
  close (sv[1]);
}

/* A restart is a call on the source; one that cannot is a rewind error.  */
static void
test_restart (struct twist_loop *loop)
{
  int sv[2];
  struct prod p;

  if (pair (sv) != 0)
    return;
  memset (&p, 0, sizeof p);
  p.c = make (loop, sv[0]);
  twist_connection_attach_source (p.c, &ops_restart, &p);
  p.restart_rc = 0;
  check (twist_connection_source_restart (p.c) == TWIST_OK && p.restarts == 1,
         "a source that restarts is restarted");
  p.restart_rc = -1;
  check (twist_connection_source_restart (p.c) == TWIST_ERR_REWIND,
         "a source that refuses is a rewind error");
  twist_connection_free (p.c);

  memset (&p, 0, sizeof p);
  p.c = make (loop, sv[0] = -1);
  twist_connection_attach_source (p.c, &ops_norestart, &p);
  check (twist_connection_source_restart (p.c) == TWIST_ERR_REWIND,
         "a source with no restart is a rewind error");
  twist_connection_free (p.c);
  check (twist_connection_source_restart (NULL) == TWIST_ERR_REWIND,
         "and so is no source");
  close (sv[1]);
}

/* The count of body bytes the socket has accepted leaves out framing and what
   is still queued.  */
static void
test_body_written (struct twist_loop *loop)
{
  int sv[2];
  struct twist_connection *c;
  struct twist_endpoint *ep;
  uint8_t buf[1000];
  size_t body = 0, frame = 0, seen;
  int i;

  if (pair (sv) != 0)
    return;
  memset (buf, 'b', sizeof buf);
  c = make (loop, sv[0]);
  ep = twist_connection_endpoint (c);
  check (twist_connection_body_written (c) == 0, "nothing is written at first");
  /* The peer reads nothing: the socket takes some and the rest is queued.  */
  for (i = 0; i < 2000; i++)
    {
      twist_endpoint_send (ep, (const uint8_t *) "5\r\n", 3);
      frame += 3;
      twist_connection_send_body (c, buf, sizeof buf);
      body += sizeof buf;
    }
  drain (loop, -1, 50);
  check (twist_connection_body_written (c) + twist_endpoint_pending (ep)
         <= body + frame,
         "body written and still queued do not exceed what was sent");
  check (twist_connection_body_written (c) < body,
         "body still queued is not counted as written");
  check (twist_endpoint_pending (ep) > 0, "some of it is still queued");
  seen = drain (loop, sv[1], 1500);
  check (seen == body + frame, "the peer got the body and the framing");
  check (twist_connection_body_written (c) == body,
         "when it is all written, the count is the body and no framing");
  twist_connection_free (c);
  close (sv[1]);
}

/* A sink that pauses.  */
struct snk
{
  struct twist_sink sink;
  size_t got;
  size_t limit;			/* How much it takes before it pauses.  */
  int takes;
  uint8_t data[512];
};

static size_t
s_take (void *user, const uint8_t *data, size_t len)
{
  struct snk *s = user;
  size_t n = len;

  s->takes++;
  if (s->limit != (size_t) -1 && n > s->limit - s->got)
    n = s->limit - s->got;
  if (s->got + n <= sizeof s->data)
    memcpy (s->data + s->got, data, n);
  s->got += n;
  return n;
}

static size_t
s_receive (struct twist_endpoint *ep, const uint8_t *data, size_t len)
{
  struct snk *s = ep->user_data;

  return twist_sink_feed (&s->sink, ep, data, len);
}

static void
test_sink (struct twist_loop *loop)
{
  struct twist_connection *c;
  struct twist_endpoint *ep;
  struct twist_protocol_handler h;
  struct snk s;
  uint8_t in[100];
  size_t i;
  int ok = 1;

  for (i = 0; i < sizeof in; i++)
    in[i] = (uint8_t) i;
  memset (&s, 0, sizeof s);
  s.sink.take = s_take;
  s.sink.user = &s;
  s.limit = 10;
  memset (&h, 0, sizeof h);
  h.receive = s_receive;
  c = twist_connection_new (loop);
  ep = twist_connection_endpoint (c);
  ep->user_data = &s;
  twist_connection_set_handler (c, &h);
  twist_connection_ingest (c, in, sizeof in);
  check (s.got == 10, "a sink takes what it can");
  check (twist_connection_paused (c), "and the read is paused");
  s.limit = (size_t) -1;
  twist_sink_resume (&s.sink);
  check (!twist_connection_paused (c), "resume resumes the read");
  check (s.got == 100, "and delivers the tail");
  for (i = 0; i < 100; i++)
    if (s.data[i] != (uint8_t) i)
      ok = 0;
  check (ok, "in order");
  twist_connection_free (c);
}

int
main (void)
{
  struct twist_loop *loop = twist_loop_new (0);

  if (loop == NULL)
    return 77;
  test_pause_resume (loop);
  test_freed (loop);
  test_producer_fails (loop);
  test_one_source (loop);
  test_restart (loop);
  test_body_written (loop);
  test_sink (loop);
  twist_loop_free (loop);
  return tests_finish ();
}
