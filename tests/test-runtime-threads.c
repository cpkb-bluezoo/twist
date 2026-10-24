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

#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

/* A runtime that runs transfers on several loops, each in a thread of its
   own: that all of them are done, that the done callback is on the thread that
   drives the runtime, that transfers which can share a connection are on one
   loop and the rest are spread, that the limit on connections to a host holds
   across loops, that a transfer can be cancelled or freed from the driving
   thread whatever loop it is on, and that the stores that loops share stand
   the threads.  The servers are threads on the loopback.  */

#define SRV_MAX 64

struct srv
{
  int listen_fd;
  int port;
  int h2;			/* Speak HTTP/2 from the first byte.  */
  int ndummy;			/* Connections made to fill the backlog.  */
  int dummy[8];
  int silent;			/* Take connections and say nothing.  */
  int stop;
  int accepts;
  int open;
  int max_open;
  pthread_t thread;
  int conns[SRV_MAX];
  unsigned char buf[SRV_MAX][512];
  size_t have[SRV_MAX];
  int greeted[SRV_MAX];
};

static const char h1_reply[] =
  "HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\nhello\n";

static int
ld (int *p)
{
  return __atomic_load_n (p, __ATOMIC_ACQUIRE);
}

static void
srv_drop (struct srv *s, int i)
{
  close (s->conns[i]);
  s->conns[i] = -1;
  s->have[i] = 0;
  s->greeted[i] = 0;
  __atomic_sub_fetch (&s->open, 1, __ATOMIC_ACQ_REL);
}

static int
frame (unsigned char *out, int type, int flags, unsigned stream,
       const void *payload, size_t n)
{
  out[0] = (unsigned char) (n >> 16);
  out[1] = (unsigned char) (n >> 8);
  out[2] = (unsigned char) n;
  out[3] = (unsigned char) type;
  out[4] = (unsigned char) flags;
  out[5] = (unsigned char) (stream >> 24);
  out[6] = (unsigned char) (stream >> 16);
  out[7] = (unsigned char) (stream >> 8);
  out[8] = (unsigned char) stream;
  if (n > 0)
    memcpy (out + 9, payload, n);
  return (int) (9 + n);
}

static int
srv_serve (struct srv *s, int i)
{
  unsigned char out[512];
  int n = 0;

  if (s->silent)
    {
      s->have[i] = 0;
      return 0;
    }
  if (!s->h2)
    {
      s->have[i] = 0;
      return write (s->conns[i], h1_reply, sizeof h1_reply - 1) < 0 ? -1 : 0;
    }
  if (!s->greeted[i])
    {
      if (s->have[i] < 24)
        return 0;
      memmove (s->buf[i], s->buf[i] + 24, s->have[i] - 24);
      s->have[i] -= 24;
      s->greeted[i] = 1;
      n += frame (out + n, 4, 0, 0, NULL, 0);
    }
  while (s->have[i] >= 9)
    {
      size_t len = ((size_t) s->buf[i][0] << 16) | ((size_t) s->buf[i][1] << 8)
                   | s->buf[i][2];
      int type = s->buf[i][3];
      int flags = s->buf[i][4];
      unsigned stream = ((unsigned) s->buf[i][5] << 24)
                        | ((unsigned) s->buf[i][6] << 16)
                        | ((unsigned) s->buf[i][7] << 8) | s->buf[i][8];

      if (len > sizeof s->buf[i] - 9)
        return -1;
      if (s->have[i] < 9 + len)
        break;
      if (type == 4 && !(flags & 1))
        n += frame (out + n, 4, 1, 0, NULL, 0);
      else if (type == 1)
        {
          static const unsigned char status200 = 0x88;

          n += frame (out + n, 1, 4, stream, &status200, 1);
          n += frame (out + n, 0, 1, stream, "hello\n", 6);
        }
      memmove (s->buf[i], s->buf[i] + 9 + len, s->have[i] - 9 - len);
      s->have[i] -= 9 + len;
      if (n > 400)
        break;
    }
  return n > 0 && write (s->conns[i], out, (size_t) n) < 0 ? -1 : 0;
}

static void *
srv_run (void *arg)
{
  struct srv *s = arg;
  struct pollfd fds[SRV_MAX + 1];
  int i, n;

  while (!ld (&s->stop))
    {
      n = 0;
      fds[n].fd = s->listen_fd;
      fds[n++].events = POLLIN;
      for (i = 0; i < SRV_MAX; i++)
        if (s->conns[i] >= 0)
          {
            fds[n].fd = s->conns[i];
            fds[n++].events = POLLIN;
          }
      if (poll (fds, (nfds_t) n, 20) <= 0)
        continue;
      /* What was said and closed is seen to before a connection is taken,
         so that one closed before another was made is not open with it.  */
      for (i = 0; i < SRV_MAX; i++)
        {
          int j, hit = 0;
          ssize_t got;

          if (s->conns[i] < 0)
            continue;
          for (j = 1; j < n; j++)
            if (fds[j].fd == s->conns[i]
                && (fds[j].revents & (POLLIN | POLLHUP)))
              hit = 1;
          if (!hit)
            continue;
          got = read (s->conns[i], s->buf[i] + s->have[i],
                      sizeof s->buf[i] - s->have[i]);
          if (got <= 0)
            {
              srv_drop (s, i);
              continue;
            }
          s->have[i] += (size_t) got;
          if (srv_serve (s, i) < 0)
            srv_drop (s, i);
        }
      if (fds[0].revents & POLLIN)
        {
          int c = accept (s->listen_fd, NULL, NULL);

          if (c >= 0)
            {
              __atomic_add_fetch (&s->accepts, 1, __ATOMIC_ACQ_REL);
              for (i = 0; i < SRV_MAX && s->conns[i] >= 0; i++)
                ;
              if (i == SRV_MAX)
                close (c);
              else
                {
                  int open;

                  s->conns[i] = c;
                  open = __atomic_add_fetch (&s->open, 1, __ATOMIC_ACQ_REL);
                  if (open > ld (&s->max_open))
                    __atomic_store_n (&s->max_open, open, __ATOMIC_RELEASE);
                }
            }
        }
    }
  for (i = 0; i < SRV_MAX; i++)
    if (s->conns[i] >= 0)
      srv_drop (s, i);
  return NULL;
}

static int
srv_start (struct srv *s, int h2, int silent)
{
  struct sockaddr_in sin;
  socklen_t len = sizeof sin;
  int i;

  memset (s, 0, sizeof *s);
  for (i = 0; i < SRV_MAX; i++)
    s->conns[i] = -1;
  s->h2 = h2;
  s->silent = silent;
  s->listen_fd = socket (AF_INET, SOCK_STREAM, 0);
  if (s->listen_fd < 0)
    return -1;
  memset (&sin, 0, sizeof sin);
  sin.sin_family = AF_INET;
  sin.sin_addr.s_addr = htonl (INADDR_LOOPBACK);
  if (bind (s->listen_fd, (struct sockaddr *) &sin, sizeof sin) != 0
      || listen (s->listen_fd, 64) != 0
      || getsockname (s->listen_fd, (struct sockaddr *) &sin, &len) != 0)
    {
      close (s->listen_fd);
      return -1;
    }
  s->port = ntohs (sin.sin_port);
  return pthread_create (&s->thread, NULL, srv_run, s);
}

static void srv_stop (struct srv *s);

/* A server that does not take connections yet, and whose queue of them is
   full, so that a connection made to it is not made until srv_begin: the
   system holds the handshake back and tries again.  */
static int
srv_start_stalled (struct srv *s, int h2)
{
  struct sockaddr_in sin;
  socklen_t len = sizeof sin;
  int i;

  memset (s, 0, sizeof *s);
  for (i = 0; i < SRV_MAX; i++)
    s->conns[i] = -1;
  s->h2 = h2;
  s->listen_fd = socket (AF_INET, SOCK_STREAM, 0);
  if (s->listen_fd < 0)
    return -1;
  memset (&sin, 0, sizeof sin);
  sin.sin_family = AF_INET;
  sin.sin_addr.s_addr = htonl (INADDR_LOOPBACK);
  if (bind (s->listen_fd, (struct sockaddr *) &sin, sizeof sin) != 0
      || listen (s->listen_fd, 0) != 0
      || getsockname (s->listen_fd, (struct sockaddr *) &sin, &len) != 0)
    {
      close (s->listen_fd);
      return -1;
    }
  s->port = ntohs (sin.sin_port);
  for (i = 0; i < 6; i++)
    {
      int fd = socket (AF_INET, SOCK_STREAM, 0);

      if (fd < 0)
        break;
      fcntl (fd, F_SETFL, O_NONBLOCK);
      connect (fd, (struct sockaddr *) &sin, sizeof sin);
      s->dummy[s->ndummy++] = fd;
    }
  return 0;
}

/* The server begins to take connections, those that filled the queue too.  */
static int
srv_begin (struct srv *s)
{
  return pthread_create (&s->thread, NULL, srv_run, s);
}

static void
srv_stop_stalled (struct srv *s)
{
  int i;

  srv_stop (s);
  for (i = 0; i < s->ndummy; i++)
    close (s->dummy[i]);
}

static void
srv_stop (struct srv *s)
{
  __atomic_store_n (&s->stop, 1, __ATOMIC_RELEASE);
  pthread_join (s->thread, NULL);
  close (s->listen_fd);
}

/* ---- the client side ---- */

#define MANY 48

struct run
{
  struct twist_runtime *runtime;
  twist_transfer *t[MANY];
  struct check_job job[MANY];
  pthread_t write_tid[MANY];
  int wrote[MANY];
  size_t got[MANY];
  pthread_t done_tid[MANY];
};

struct cb
{
  struct run *r;
  int i;
};

static struct cb cbs[MANY];

static size_t
count_body (char *ptr, size_t size, size_t nmemb, void *user)
{
  struct cb *c = user;

  (void) ptr;
  c->r->write_tid[c->i] = pthread_self ();
  c->r->wrote[c->i] = 1;
  c->r->got[c->i] += size * nmemb;
  return size * nmemb;
}

static void
note_done (twist_transfer *transfer, int result, void *user)
{
  struct cb *c = user;

  (void) transfer;
  c->r->done_tid[c->i] = pthread_self ();
  c->r->job[c->i].result = result;
  c->r->job[c->i].done = 1;
  c->r->job[c->i].calls++;
}

static int
run_open (struct run *r, long threads)
{
  memset (r, 0, sizeof *r);
  r->runtime = twist_runtime_new ();
  if (r->runtime == NULL)
    return 0;
  if (threads > 0
      && twist_runtime_setopt (r->runtime, TWIST_RUNTIMEOPT_THREADS, threads)
         != TWIST_OK)
    {
      check (0, "THREADS is accepted");
      return 0;
    }
  return 1;
}

static void
run_make (struct run *r, int i, const struct srv *s, int h2)
{
  char url[64];

  snprintf (url, sizeof url, "http://127.0.0.1:%d/%d", s->port, i);
  cbs[i].r = r;
  cbs[i].i = i;
  r->t[i] = twist_transfer_new ();
  twist_transfer_setopt (r->t[i], TWISTOPT_URL, url);
  twist_transfer_setopt (r->t[i], TWISTOPT_WRITEFUNCTION, count_body);
  twist_transfer_setopt (r->t[i], TWISTOPT_WRITEDATA, &cbs[i]);
  twist_transfer_setopt (r->t[i], TWISTOPT_TIMEOUT_MS, 8000L);
  if (h2)
    twist_transfer_setopt (r->t[i], TWISTOPT_HTTP_VERSION,
                           (long) TWIST_HTTP_VERSION_2_PRIOR_KNOWLEDGE);
}

static void
run_go (struct run *r, int i)
{
  check (twist_runtime_start (r->runtime, r->t[i], note_done, &cbs[i])
         == TWIST_OK, "start");
}

static int
run_wait (struct run *r, int n)
{
  struct timespec t0, t1;
  int i, all;

  clock_gettime (CLOCK_MONOTONIC, &t0);
  for (;;)
    {
      all = 1;
      for (i = 0; i < n; i++)
        if (!r->job[i].done)
          all = 0;
      if (all)
        return 1;
      twist_runtime_run_once (r->runtime, 10);
      clock_gettime (CLOCK_MONOTONIC, &t1);
      if ((t1.tv_sec - t0.tv_sec) * 1000
          + (t1.tv_nsec - t0.tv_nsec) / 1000000 >= 10000)
        {
          for (i = 0; i < n; i++)
            if (!r->job[i].done)
              fprintf (stderr, "  transfer %d has not ended\n", i);
          return 0;
        }
    }
}

static void
run_close (struct run *r, int n)
{
  int i;

  twist_runtime_free (r->runtime);
  for (i = 0; i < n; i++)
    twist_transfer_free (r->t[i]);
}

/* How many different threads wrote the bodies of the first N.  */
static int
threads_seen (struct run *r, int n)
{
  pthread_t seen[MANY];
  int ns = 0, i, j;

  for (i = 0; i < n; i++)
    {
      int known = 0;

      if (!r->wrote[i])
        continue;
      for (j = 0; j < ns; j++)
        if (pthread_equal (seen[j], r->write_tid[i]))
          known = 1;
      if (!known)
        seen[ns++] = r->write_tid[i];
    }
  return ns;
}

static int
all_ok (struct run *r, int n)
{
  int i;

  for (i = 0; i < n; i++)
    if (r->job[i].result != TWIST_OK || r->got[i] != 6)
      return 0;
  return 1;
}

/* Forty transfers to four servers on four loops are all done, and each done
   callback is called on the thread that drives the runtime.  */
static void
test_all_done (void)
{
  struct srv s[4];
  struct run r;
  pthread_t me = pthread_self ();
  int i, ondrv = 1;

  for (i = 0; i < 4; i++)
    check (srv_start (&s[i], 0, 0) == 0, "server");
  check (run_open (&r, 4), "runtime with 4 threads");
  for (i = 0; i < 40; i++)
    run_make (&r, i, &s[i % 4], 0);
  for (i = 0; i < 40; i++)
    run_go (&r, i);
  check (run_wait (&r, 40), "all forty end");
  check (all_ok (&r, 40), "and are answered");
  for (i = 0; i < 40; i++)
    if (!pthread_equal (r.done_tid[i], me) || r.job[i].calls != 1)
      ondrv = 0;
  check (ondrv, "each done callback, once, on the driving thread");
  run_close (&r, 40);
  for (i = 0; i < 4; i++)
    srv_stop (&s[i]);
}

/* Cleartext HTTP/1.1 transfers to one server cannot share a connection, so
   they are spread over the loops.  */
static void
test_h1_spread (void)
{
  struct srv s;
  struct run r;
  int i;

  check (srv_start (&s, 0, 0) == 0, "server");
  check (run_open (&r, 4), "runtime");
  for (i = 0; i < 40; i++)
    run_make (&r, i, &s, 0);
  for (i = 0; i < 40; i++)
    run_go (&r, i);
  check (run_wait (&r, 40), "all end");
  check (all_ok (&r, 40), "and are answered");
  check (threads_seen (&r, 40) > 1, "HTTP/1 transfers to one host are spread");
  run_close (&r, 40);
  srv_stop (&s);
}

/* HTTP/2 from the first byte can share a connection, so transfers to one
   server are on one loop and make one connection.  */
static void
test_h2_pinned (void)
{
  struct srv s;
  struct run r;
  int i;

  check (srv_start (&s, 1, 0) == 0, "server");
  check (run_open (&r, 4), "runtime");
  for (i = 0; i < 12; i++)
    run_make (&r, i, &s, 1);
  for (i = 0; i < 12; i++)
    run_go (&r, i);
  check (run_wait (&r, 12), "all end");
  check (all_ok (&r, 12), "and are answered");
  check (threads_seen (&r, 12) == 1, "HTTP/2 transfers to one host: one loop");
  check (ld (&s.accepts) == 1, "and one connection");
  run_close (&r, 12);
  srv_stop (&s);
}

/* The limit on connections to a host is for the runtime, not for a loop.  */
static void
test_cap_global (void)
{
  struct srv s;
  struct run r;
  int i;

  check (srv_start (&s, 0, 0) == 0, "server");
  check (run_open (&r, 4), "runtime");
  check (twist_runtime_setopt (r.runtime,
                               TWIST_RUNTIMEOPT_MAX_HOST_CONNECTIONS, 1L)
         == TWIST_OK, "the limit is set");
  for (i = 0; i < 16; i++)
    run_make (&r, i, &s, 0);
  for (i = 0; i < 16; i++)
    run_go (&r, i);
  check (run_wait (&r, 16), "all end");
  check (all_ok (&r, 16), "and are answered");
  check (ld (&s.max_open) == 1, "never more than one connection open");
  check (threads_seen (&r, 16) > 1, "though on several loops");
  run_close (&r, 16);
  srv_stop (&s);
}

/* A connection kept idle by one loop holds its place under the limit, and a
   transfer on another loop that would make one asks for it to be closed, so
   that the server never has two open.  */
static void
test_cap_idle (void)
{
  struct srv s;
  struct run r;
  int i;

  check (srv_start (&s, 0, 0) == 0, "server");
  check (run_open (&r, 4), "runtime");
  check (twist_runtime_setopt (r.runtime,
                               TWIST_RUNTIMEOPT_MAX_HOST_CONNECTIONS, 1L)
         == TWIST_OK, "the limit is set");
  run_make (&r, 0, &s, 0);
  run_go (&r, 0);
  check (run_wait (&r, 1), "the first ends");
  /* Its connection is kept by its loop.  The others are on the other loops
     too, and none is waiting for a place when it is kept.  */
  for (i = 1; i < 13; i++)
    run_make (&r, i, &s, 0);
  for (i = 1; i < 13; i++)
    run_go (&r, i);
  check (run_wait (&r, 13), "the rest end");
  check (all_ok (&r, 13), "and are answered");
  check (ld (&s.max_open) == 1, "never more than one connection open");
  check (threads_seen (&r, 13) > 1, "on more than one loop");
  run_close (&r, 13);
  srv_stop (&s);
}

/* A transfer that is cancelled while it waits for the connection another is
   making.  The connection is held back by the system, so that the wait is
   long.  The two are on one loop, as those that can share a connection are.  */
static void
test_cancel_parked (void)
{
  struct srv s;
  struct run r;
  struct timespec nap = { 0, 20000000 };
  int i;

  check (srv_start_stalled (&s, 1) == 0, "server that is not taking any");
  check (run_open (&r, 4), "runtime");
  run_make (&r, 0, &s, 1);
  run_make (&r, 1, &s, 1);
  run_go (&r, 0);
  run_go (&r, 1);
  /* Let the loop begin them both.  */
  for (i = 0; i < 5; i++)
    {
      twist_runtime_run_once (r.runtime, 10);
      nanosleep (&nap, NULL);
    }
  check (twist_runtime_cancel (r.runtime, r.t[1]) == TWIST_OK, "cancel");
  for (i = 0; i < 5 && !r.job[1].done; i++)
    twist_runtime_run_once (r.runtime, 100);
  check (r.job[1].done && r.job[1].result == TWIST_ERR_ABORTED,
         "the one that waited is aborted");
  check (!r.job[0].done, "and the first is still making its connection");
  check (srv_begin (&s) == 0, "the server takes connections");
  check (run_wait (&r, 2), "the first ends");
  check (r.job[0].result == TWIST_OK && r.got[0] == 6, "and is answered");
  check (ld (&s.accepts) <= s.ndummy + 1, "no connection was made for the other");
  run_close (&r, 2);
  srv_stop_stalled (&s);
}

/* Cancelled from the driving thread, whatever loop they are on.  */
static void
test_cancel (void)
{
  struct srv s[2];
  struct run r;
  int i;

  check (srv_start (&s[0], 0, 1) == 0 && srv_start (&s[1], 0, 1) == 0,
         "servers that say nothing");
  check (run_open (&r, 4), "runtime");
  for (i = 0; i < 8; i++)
    run_make (&r, i, &s[i % 2], 0);
  for (i = 0; i < 8; i++)
    run_go (&r, i);
  for (i = 0; i < 8; i++)
    check (twist_runtime_cancel (r.runtime, r.t[i]) == TWIST_OK, "cancel");
  check (run_wait (&r, 8), "all end");
  for (i = 0; i < 8; i++)
    check (r.job[i].result == TWIST_ERR_ABORTED && r.job[i].calls == 1,
           "each is aborted, once");
  run_close (&r, 8);
  srv_stop (&s[0]);
  srv_stop (&s[1]);
}

/* Cancelled while it waits for a connection that another transfer is making
   or a session that is: the others are answered, and nothing breaks.  */
static void
test_cancel_waiting (void)
{
  struct srv s;
  struct run r;
  int i;

  check (srv_start (&s, 1, 0) == 0, "server");
  check (run_open (&r, 4), "runtime");
  for (i = 0; i < 12; i++)
    run_make (&r, i, &s, 1);
  for (i = 0; i < 12; i++)
    run_go (&r, i);
  for (i = 1; i < 12; i += 2)
    check (twist_runtime_cancel (r.runtime, r.t[i]) == TWIST_OK, "cancel");
  check (run_wait (&r, 12), "all end");
  for (i = 0; i < 12; i++)
    {
      if (i % 2 == 1)
        check (r.job[i].result == TWIST_ERR_ABORTED
               || (r.job[i].result == TWIST_OK && r.got[i] == 6),
               "a cancelled one is aborted, or had finished");
      else
        check (r.job[i].result == TWIST_OK && r.got[i] == 6, "answered");
    }
  run_close (&r, 12);
  srv_stop (&s);
}

/* The runtime is freed with transfers running on its loops, and so is a
   transfer that is running.  */
static void
test_free_running (void)
{
  struct srv s;
  struct run r;
  int i;

  check (srv_start (&s, 0, 1) == 0, "server that says nothing");
  check (run_open (&r, 4), "runtime");
  for (i = 0; i < 8; i++)
    run_make (&r, i, &s, 0);
  for (i = 0; i < 8; i++)
    run_go (&r, i);
  twist_runtime_run_once (r.runtime, 50);
  /* Freed while running: it leaves the runtime, and its callback is not
     called.  */
  twist_transfer_free (r.t[3]);
  r.t[3] = NULL;
  twist_runtime_run_once (r.runtime, 50);
  twist_runtime_free (r.runtime);
  for (i = 0; i < 8; i++)
    twist_transfer_free (r.t[i]);
  for (i = 0; i < 8; i++)
    check (i == 3 || !r.job[i].done, "no callback for a transfer dropped");
  srv_stop (&s);
}

static void
no_watch (int fd, int what, void *user)
{
  (void) fd;
  (void) what;
  (void) user;
}

static void
no_timer (long timeout_ms, void *user)
{
  (void) timeout_ms;
  (void) user;
}

static void
test_setopt (void)
{
  struct twist_runtime *rt = twist_runtime_new ();
  struct twist_runtime *emb;
  struct srv s;
  struct run r;

  check (twist_runtime_setopt (rt, TWIST_RUNTIMEOPT_THREADS, 1L) == TWIST_OK,
         "1 thread");
  check (twist_runtime_setopt (rt, TWIST_RUNTIMEOPT_THREADS, 64L) == TWIST_OK,
         "64 threads");
  check (twist_runtime_setopt (rt, TWIST_RUNTIMEOPT_THREADS, 0L)
         == TWIST_ERR_INVAL, "0 is not a number of threads");
  check (twist_runtime_setopt (rt, TWIST_RUNTIMEOPT_THREADS, 65L)
         == TWIST_ERR_INVAL, "65 is too many");
  twist_runtime_free (rt);
  emb = twist_runtime_new_embedded (no_watch, no_timer, NULL);
  if (emb != NULL)
    {
      check (twist_runtime_setopt (emb, TWIST_RUNTIMEOPT_THREADS, 2L)
             == TWIST_ERR_INVAL, "an embedded runtime refuses threads");
      twist_runtime_free (emb);
    }
  check (srv_start (&s, 0, 0) == 0, "server");
  check (run_open (&r, 0), "runtime");
  run_make (&r, 0, &s, 0);
  run_go (&r, 0);
  check (twist_runtime_setopt (r.runtime, TWIST_RUNTIMEOPT_THREADS, 2L)
         == TWIST_ERR_INVAL, "threads cannot be set once a transfer starts");
  check (run_wait (&r, 1), "the transfer ends");
  run_close (&r, 1);
  srv_stop (&s);
}

/* Where an origin's transfers go is kept while any is under way or a session
   to it is open, and then forgotten, so that the next are put afresh.  */
static void
test_place_entries (void)
{
  struct twist_origintab *tab = twist_origintab_new ();
  int lane = -1;

  check (twist_origintab_pin (tab, "https|h|443|-", &lane) == 0,
         "an origin that is not known has no lane");
  check (twist_origintab_pin_set (tab, "https|h|443|-", 2) == TWIST_OK,
         "one is chosen");
  check (twist_origintab_pin (tab, "https|h|443|-", &lane) == 1 && lane == 2,
         "and the next go there");
  twist_origintab_session (tab, "0x1|https|h|443|-", 1);
  twist_origintab_unpin (tab, "https|h|443|-");
  twist_origintab_unpin (tab, "https|h|443|-");
  check (twist_origintab_pin (tab, "https|h|443|-", &lane) == 1,
         "it is kept while a session is open");
  twist_origintab_unpin (tab, "https|h|443|-");
  twist_origintab_session (tab, "0x1|https|h|443|-", -1);
  check (twist_origintab_pin (tab, "https|h|443|-", &lane) == 0,
         "and forgotten when the last transfer and the session are gone");
  twist_origintab_free (tab);
}

/* ---- the stores that loops share ---- */

#define ROUNDS 3000
#define WORKERS 4

struct hammer
{
  struct twist_runtime *rt;
  int id;
};

static void *
hammer_run (void *arg)
{
  struct hammer *h = arg;
  char host[32], line[96], origin[32], alt[16];
  int i;

  for (i = 0; i < ROUNDS; i++)
    {
      char *hdr = NULL;

      snprintf (host, sizeof host, "h%d-%d.example", h->id, i % 16);
      snprintf (line, sizeof line, "k%d_%d=v; Max-Age=3600", h->id, i % 16);
      twist_jar_store (h->rt->jar, line, host, "/", 0);
      if (twist_jar_header (h->rt->jar, host, "/", 0, &hdr) == TWIST_OK)
        free (hdr);
      twist_hsts_note (h->rt->hsts, host, 1000000000u);
      twist_hsts_upgrade (h->rt->hsts, host, 5u);
      snprintf (origin, sizeof origin, "o%d-%d", h->id, i % 16);
      snprintf (alt, sizeof alt, "h3:%d", 443 + i % 4);
      twist_altsvc_note (h->rt->altsvc, origin, alt);
      {
        char out[32];

        if (twist_altsvc_lookup (h->rt->altsvc, origin, out, sizeof out) == 0)
          check (strncmp (out, "h3:", 3) == 0, "an Alt-Svc value is whole");
      }
    }
  return NULL;
}

static void
test_stores (void)
{
  struct twist_runtime *rt = twist_runtime_new ();
  pthread_t th[WORKERS];
  struct hammer h[WORKERS];
  int i;

  for (i = 0; i < WORKERS; i++)
    {
      h[i].rt = rt;
      h[i].id = i;
      pthread_create (&th[i], NULL, hammer_run, &h[i]);
    }
  for (i = 0; i < WORKERS; i++)
    pthread_join (th[i], NULL);
  check (twist_jar_count (rt->jar) == (size_t) WORKERS * 16,
         "every cookie of every thread is in the jar");
  twist_runtime_free (rt);
}

static void
announce (const char *name)
{
  if (getenv ("TEST_VERBOSE") != NULL)
    fprintf (stderr, "%s\n", name);
}

int
main (void)
{
  announce ("test_setopt");
  test_setopt ();
  announce ("test_all_done");
  test_all_done ();
  announce ("test_h1_spread");
  test_h1_spread ();
  announce ("test_h2_pinned");
  test_h2_pinned ();
  announce ("test_cap_global");
  test_cap_global ();
  announce ("test_cap_idle");
  test_cap_idle ();
  announce ("test_cancel_parked");
  test_cancel_parked ();
  announce ("test_cancel");
  test_cancel ();
  announce ("test_cancel_waiting");
  test_cancel_waiting ();
  announce ("test_free_running");
  test_free_running ();
  announce ("test_place_entries");
  test_place_entries ();
  announce ("test_stores");
  test_stores ();
  return tests_finish ();
}
