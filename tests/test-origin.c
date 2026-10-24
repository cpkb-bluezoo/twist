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
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

/* Transfers to one origin: that those started together to a server that may
   multiplex share the one connection it gives, that those started when a
   connection is not wanted make their own, that a runtime keeps at most as
   many connections to an origin as it is told, and that a transfer that waits
   for a connection that never comes, or is cancelled while it waits, does no
   harm.  The server is a thread on the loopback that counts what it is asked,
   and speaks HTTP/1.1 with keep-alive, or HTTP/2 from the first byte.  */

#define SRV_MAX 16

struct srv
{
  int listen_fd;
  int port;
  int h2;			/* Speak HTTP/2 (prior knowledge).  */
  int close_first;		/* Close this many connections at once.  */
  int stop;
  int accepts;
  int requests;
  int open;
  int max_open;
  pthread_t thread;
  int conns[SRV_MAX];
  unsigned char buf[SRV_MAX][512];
  size_t have[SRV_MAX];
  int greeted[SRV_MAX];
  /* HTTP/2: the windows the server keeps to, the response that is sent as the
     window allows (/b), and the one that waits for a ping to be answered
     (/p).  */
  long conn_win[SRV_MAX];
  long stream_init[SRV_MAX];
  unsigned big_stream[SRV_MAX];
  long big_left[SRV_MAX];
  long big_win[SRV_MAX];
  unsigned ping_stream[SRV_MAX];
  int ping_wait[SRV_MAX];
};

#define BIG 150000

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
  s->big_left[i] = 0;
  s->ping_wait[i] = 0;
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

/* Send as much of the large response as the windows allow.  */
static int
srv_pump (struct srv *s, int i)
{
  static unsigned char big[16384 + 9];

  while (s->big_left[i] > 0 && s->conn_win[i] > 0 && s->big_win[i] > 0)
    {
      long n = s->big_left[i];
      int end;

      if (n > 16384)
        n = 16384;
      if (n > s->conn_win[i])
        n = s->conn_win[i];
      if (n > s->big_win[i])
        n = s->big_win[i];
      end = n == s->big_left[i];
      memset (big + 9, 'x', (size_t) n);
      frame (big, 0, end ? 1 : 0, s->big_stream[i], big + 9, 0);
      big[0] = (unsigned char) (n >> 16);
      big[1] = (unsigned char) (n >> 8);
      big[2] = (unsigned char) n;
      if (write (s->conns[i], big, (size_t) n + 9) < 0)
        return -1;
      s->big_left[i] -= n;
      s->conn_win[i] -= n;
      s->big_win[i] -= n;
    }
  return 0;
}

/* What came on connection I, answered: HTTP/1.1 once per request, or for
   HTTP/2 the settings, their acknowledgement, and a response for each
   request stream.  Returns 0, or -1 to close.  */
static int
srv_serve (struct srv *s, int i)
{
  unsigned char out[256];
  int n = 0;

  if (!s->h2)
    {
      s->have[i] = 0;
      return write (s->conns[i], h1_reply, sizeof h1_reply - 1) < 0 ? -1 : 0;
    }
  if (!s->greeted[i])
    {
      /* The client's preface is 24 bytes, and then frames.  */
      if (s->have[i] < 24)
        return 0;
      memmove (s->buf[i], s->buf[i] + 24, s->have[i] - 24);
      s->have[i] -= 24;
      s->greeted[i] = 1;
      s->conn_win[i] = 65535;
      s->stream_init[i] = 65535;
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
        {
          size_t k;

          /* INITIAL_WINDOW_SIZE (4) is the window of each new stream.  */
          for (k = 0; k + 6 <= len; k += 6)
            if (s->buf[i][9 + k] == 0 && s->buf[i][9 + k + 1] == 4)
              s->stream_init[i] = ((long) s->buf[i][9 + k + 2] << 24)
                                  | ((long) s->buf[i][9 + k + 3] << 16)
                                  | ((long) s->buf[i][9 + k + 4] << 8)
                                  | s->buf[i][9 + k + 5];
          n += frame (out + n, 4, 1, 0, NULL, 0);
        }
      else if (type == 8 && len == 4)
        {
          long inc = ((long) s->buf[i][9] << 24) | ((long) s->buf[i][10] << 16)
                     | ((long) s->buf[i][11] << 8) | s->buf[i][12];

          if (stream == 0)
            s->conn_win[i] += inc;
          else if (stream == s->big_stream[i])
            s->big_win[i] += inc;
        }
      else if (type == 6 && (flags & 1) && s->ping_wait[i])
        {
          static const unsigned char status = 0x88;

          s->ping_wait[i] = 0;
          n += frame (out + n, 1, 4, s->ping_stream[i], &status, 1);
          n += frame (out + n, 0, 1, s->ping_stream[i], "hello\n", 6);
        }
      else if (type == 1)
        {
          static const unsigned char status200 = 0x88;

          __atomic_add_fetch (&s->requests, 1, __ATOMIC_ACQ_REL);
          /* :status 302 as a literal, and location: /1.  */
          static const unsigned char moved[] = {
            0x48, 0x03, '3', '0', '2', 0x0f, 0x1f, 0x02, '/', '1'
          };
          size_t k;
          int redirect = 0;
          int big = 0;
          int ping = 0;

          /* A request for /r is sent to /1, one for /b is answered at length
             as the windows allow, and one for /p waits for the client to
             answer a ping.  */
          for (k = 9; k + 1 < 9 + len; k++)
            if (s->buf[i][k] == '/')
              {
                redirect |= s->buf[i][k + 1] == 'r';
                big |= s->buf[i][k + 1] == 'b';
                ping |= s->buf[i][k + 1] == 'p';
              }
          if (redirect)
            n += frame (out + n, 1, 5, stream, moved, sizeof moved);
          else if (big)
            {
              n += frame (out + n, 1, 4, stream, &status200, 1);
              s->big_stream[i] = stream;
              s->big_left[i] = BIG;
              s->big_win[i] = s->stream_init[i];
            }
          else if (ping)
            {
              static const unsigned char payload[8] = {
                'p', 'i', 'n', 'g', 'p', 'o', 'n', 'g'
              };

              /* Let what came before be over, so that the ping is for a
                 connection whose first transfer has ended.  */
              usleep (100000);
              n += frame (out + n, 6, 0, 0, payload, sizeof payload);
              s->ping_stream[i] = stream;
              s->ping_wait[i] = 1;
            }
          else
            {
              n += frame (out + n, 1, 4, stream, &status200, 1);
              n += frame (out + n, 0, 1, stream, "hello\n", 6);
            }
        }
      memmove (s->buf[i], s->buf[i] + 9 + len, s->have[i] - 9 - len);
      s->have[i] -= 9 + len;
    }
  if (n > 0 && write (s->conns[i], out, (size_t) n) < 0)
    return -1;
  return srv_pump (s, i);
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
      if (fds[0].revents & POLLIN)
        {
          int c = accept (s->listen_fd, NULL, NULL);
          int seen;

          if (c >= 0)
            {
              seen = __atomic_add_fetch (&s->accepts, 1, __ATOMIC_ACQ_REL);
              if (seen <= s->close_first)
                close (c);
              else
                {
                  int open;

                  for (i = 0; i < SRV_MAX && s->conns[i] >= 0; i++)
                    ;
                  if (i == SRV_MAX)
                    close (c);
                  else
                    {
                      s->conns[i] = c;
                      open = __atomic_add_fetch (&s->open, 1, __ATOMIC_ACQ_REL);
                      if (open > ld (&s->max_open))
                        __atomic_store_n (&s->max_open, open,
                                          __ATOMIC_RELEASE);
                    }
                }
            }
        }
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
    }
  for (i = 0; i < SRV_MAX; i++)
    if (s->conns[i] >= 0)
      srv_drop (s, i);
  return NULL;
}

static int
srv_start (struct srv *s, int h2, int close_first)
{
  struct sockaddr_in sin;
  socklen_t len = sizeof sin;
  int i;

  memset (s, 0, sizeof *s);
  for (i = 0; i < SRV_MAX; i++)
    s->conns[i] = -1;
  s->h2 = h2;
  s->close_first = close_first;
  s->listen_fd = socket (AF_INET, SOCK_STREAM, 0);
  if (s->listen_fd < 0)
    return -1;
  memset (&sin, 0, sizeof sin);
  sin.sin_family = AF_INET;
  sin.sin_addr.s_addr = htonl (INADDR_LOOPBACK);
  if (bind (s->listen_fd, (struct sockaddr *) &sin, sizeof sin) != 0
      || listen (s->listen_fd, 16) != 0
      || getsockname (s->listen_fd, (struct sockaddr *) &sin, &len) != 0)
    {
      close (s->listen_fd);
      return -1;
    }
  s->port = ntohs (sin.sin_port);
  return pthread_create (&s->thread, NULL, srv_run, s);
}

static void
srv_stop (struct srv *s)
{
  __atomic_store_n (&s->stop, 1, __ATOMIC_RELEASE);
  pthread_join (s->thread, NULL);
  close (s->listen_fd);
}

/* ---- the client side ---- */

#define MANY 8

struct run
{
  struct twist_runtime *runtime;
  twist_transfer *t[MANY];
  struct check_job job[MANY];
  size_t got[MANY];
};

static size_t
count_body (char *ptr, size_t size, size_t nmemb, void *user)
{
  size_t *total = user;

  (void) ptr;
  *total += size * nmemb;
  return size * nmemb;
}

static int
run_open (struct run *r)
{
  memset (r, 0, sizeof *r);
  r->runtime = twist_runtime_new ();
  return r->runtime != NULL;
}

/* Make transfer I for the server: HTTP/2 from the first byte if H2.  */
static void
run_make (struct run *r, int i, const struct srv *s, int h2, long pipewait)
{
  char url[64];

  snprintf (url, sizeof url, "http://127.0.0.1:%d/%d", s->port, i);
  r->t[i] = twist_transfer_new ();
  twist_transfer_setopt (r->t[i], TWISTOPT_URL, url);
  twist_transfer_setopt (r->t[i], TWISTOPT_WRITEFUNCTION, count_body);
  twist_transfer_setopt (r->t[i], TWISTOPT_WRITEDATA, &r->got[i]);
  twist_transfer_setopt (r->t[i], TWISTOPT_TIMEOUT_MS, 5000L);
  if (h2)
    twist_transfer_setopt (r->t[i], TWISTOPT_HTTP_VERSION,
                           (long) TWIST_HTTP_VERSION_2_PRIOR_KNOWLEDGE);
  if (pipewait >= 0)
    twist_transfer_setopt (r->t[i], TWISTOPT_PIPEWAIT, pipewait);
}

static void
run_go (struct run *r, int i)
{
  twist_runtime_start (r->runtime, r->t[i], check_job_done, &r->job[i]);
}

/* Until the first N have ended, or five seconds.  */
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
          + (t1.tv_nsec - t0.tv_nsec) / 1000000 >= 5000)
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

  for (i = 0; i < n; i++)
    twist_transfer_free (r->t[i]);
  twist_runtime_free (r->runtime);
}

/* Two transfers started back to back to an origin that speaks HTTP/2 make one
   connection, and both are answered over it.  */
static void
test_h2_shared (void)
{
  struct srv s;
  struct run r;
  int i;

  check (srv_start (&s, 1, 0) == 0, "server");
  check (run_open (&r), "runtime");
  for (i = 0; i < 2; i++)
    run_make (&r, i, &s, 1, -1);
  for (i = 0; i < 2; i++)
    run_go (&r, i);
  check (run_wait (&r, 2), "both h2 transfers end");
  check (r.job[0].result == TWIST_OK && r.job[1].result == TWIST_OK,
         "both are answered");
  check (r.got[0] == 6 && r.got[1] == 6, "with the body");
  check (ld (&s.accepts) == 1, "one connection for the two");
  run_close (&r, 2);
  srv_stop (&s);
}

/* With PIPEWAIT 0 each makes a connection of its own.  */
static void
test_h2_pipewait_off (void)
{
  struct srv s;
  struct run r;
  int i;

  check (srv_start (&s, 1, 0) == 0, "server");
  check (run_open (&r), "runtime");
  for (i = 0; i < 2; i++)
    run_make (&r, i, &s, 1, 0);
  for (i = 0; i < 2; i++)
    run_go (&r, i);
  check (run_wait (&r, 2), "both transfers end");
  check (r.job[0].result == TWIST_OK && r.job[1].result == TWIST_OK,
         "both are answered");
  check (ld (&s.accepts) == 2, "PIPEWAIT 0: two connections");
  run_close (&r, 2);
  srv_stop (&s);
}

/* Eight at once make one connection, and the ninth started later, when the
   session is there, uses it too.  */
static void
test_h2_many (void)
{
  struct srv s;
  struct run r;
  int i;

  check (srv_start (&s, 1, 0) == 0, "server");
  check (run_open (&r), "runtime");
  for (i = 0; i < MANY; i++)
    run_make (&r, i, &s, 1, -1);
  for (i = 0; i < MANY; i++)
    run_go (&r, i);
  check (run_wait (&r, MANY), "all end");
  for (i = 0; i < MANY; i++)
  for (i = 0; i < MANY; i++)
    check (r.job[i].result == TWIST_OK && r.got[i] == 6, "answered");
  check (ld (&s.accepts) == 1, "one connection for eight");
  run_close (&r, MANY);
  srv_stop (&s);
}

/* Three transfers over HTTP/1.1 with at most one connection to the origin:
   they take turns on it.  */
static void
test_cap_h1 (void)
{
  struct srv s;
  struct run r;
  int i;

  check (srv_start (&s, 0, 0) == 0, "server");
  check (run_open (&r), "runtime");
  check (twist_runtime_setopt (r.runtime,
                               TWIST_RUNTIMEOPT_MAX_HOST_CONNECTIONS, 1L)
         == TWIST_OK, "the cap is set");
  for (i = 0; i < 3; i++)
    run_make (&r, i, &s, 0, -1);
  for (i = 0; i < 3; i++)
    run_go (&r, i);
  check (run_wait (&r, 3), "all three end");
  for (i = 0; i < 3; i++)
    check (r.job[i].result == TWIST_OK && r.got[i] == 6, "answered");
  check (ld (&s.max_open) == 1, "never more than one connection open");
  check (ld (&s.accepts) == 1, "and the one is used again");
  run_close (&r, 3);
  srv_stop (&s);
}

/* A cap of two with six transfers.  */
static void
test_cap_two (void)
{
  struct srv s;
  struct run r;
  int i;

  check (srv_start (&s, 0, 0) == 0, "server");
  check (run_open (&r), "runtime");
  check (twist_runtime_setopt (r.runtime,
                               TWIST_RUNTIMEOPT_MAX_HOST_CONNECTIONS, 2L)
         == TWIST_OK, "the cap is set to two");
  for (i = 0; i < 6; i++)
    run_make (&r, i, &s, 0, -1);
  for (i = 0; i < 6; i++)
    run_go (&r, i);
  check (run_wait (&r, 6), "all six end");
  for (i = 0; i < 6; i++)
    check (r.job[i].result == TWIST_OK && r.got[i] == 6, "answered");
  check (ld (&s.max_open) <= 2, "never more than two open");
  check (ld (&s.max_open) == 2, "and two are used");
  run_close (&r, 6);
  srv_stop (&s);
}

/* The cap and a session: the transfers share the connection that is the one
   allowed, and none waits for a second.  */
static void
test_cap_h2 (void)
{
  struct srv s;
  struct run r;
  int i;

  check (srv_start (&s, 1, 0) == 0, "server");
  check (run_open (&r), "runtime");
  check (twist_runtime_setopt (r.runtime,
                               TWIST_RUNTIMEOPT_MAX_HOST_CONNECTIONS, 1L)
         == TWIST_OK, "the cap is set");
  for (i = 0; i < 4; i++)
    run_make (&r, i, &s, 1, 0);
  for (i = 0; i < 4; i++)
    run_go (&r, i);
  check (run_wait (&r, 4), "all four end");
  for (i = 0; i < 4; i++)
    check (r.job[i].result == TWIST_OK && r.got[i] == 6, "answered");
  check (ld (&s.max_open) == 1, "one connection open under a cap of one");
  run_close (&r, 4);
  srv_stop (&s);
}

/* A redirect on a connection that is shared: the transfer that was sent on
   goes where it is told, over the same connection, and the connection is
   there for the rest.  */
static void
test_h2_redirect (void)
{
  struct srv s;
  struct run r;
  char url[64];

  check (srv_start (&s, 1, 0) == 0, "server");
  check (run_open (&r), "runtime");
  run_make (&r, 0, &s, 1, -1);
  snprintf (url, sizeof url, "http://127.0.0.1:%d/r", s.port);
  twist_transfer_setopt (r.t[0], TWISTOPT_URL, url);
  twist_transfer_setopt (r.t[0], TWISTOPT_FOLLOWLOCATION, 1L);
  run_go (&r, 0);
  check (run_wait (&r, 1), "the transfer ends");
  check (r.job[0].result == TWIST_OK && r.got[0] == 6,
         "and is answered at the new place");
  run_make (&r, 1, &s, 1, -1);
  run_go (&r, 1);
  check (run_wait (&r, 2), "another ends");
  check (r.job[1].result == TWIST_OK && r.got[1] == 6, "and is answered");
  run_close (&r, 2);
  srv_stop (&s);
}

/* Give transfer I another path on the server.  */
static void
run_path (struct run *r, int i, const struct srv *s, const char *path)
{
  char url[64];

  snprintf (url, sizeof url, "http://127.0.0.1:%d%s", s->port, path);
  twist_transfer_setopt (r->t[i], TWISTOPT_URL, url);
}

/* The second transfer is answered with more than the connection's window, so
   the server must wait for the window to be opened again, and the first has
   ended, and been let go, before most of it comes: the connection is the
   session's, and answers for itself.  */
static void
test_h2_window (void)
{
  struct srv s;
  struct run r;

  check (srv_start (&s, 1, 0) == 0, "server");
  check (run_open (&r), "runtime");
  run_make (&r, 0, &s, 1, -1);
  run_make (&r, 1, &s, 1, -1);
  run_path (&r, 1, &s, "/b");
  run_go (&r, 0);
  run_go (&r, 1);
  check (run_wait (&r, 2), "both end");
  check (r.job[0].result == TWIST_OK && r.got[0] == 6, "the first is answered");
  check (r.job[1].result == TWIST_OK, "the second is answered");
  check (r.got[1] == BIG, "with all of it");
  check (ld (&s.accepts) == 1, "over one connection");
  run_close (&r, 2);
  srv_stop (&s);
}

/* The server pings after the first transfer has ended, while the second is
   waiting for its answer, which is not sent until the ping is.  */
static void
test_h2_ping (void)
{
  struct srv s;
  struct run r;

  check (srv_start (&s, 1, 0) == 0, "server");
  check (run_open (&r), "runtime");
  run_make (&r, 0, &s, 1, -1);
  run_make (&r, 1, &s, 1, -1);
  run_path (&r, 1, &s, "/p");
  run_go (&r, 0);
  run_go (&r, 1);
  check (run_wait (&r, 2), "both end");
  check (r.job[0].result == TWIST_OK && r.got[0] == 6, "the first is answered");
  check (r.job[1].result == TWIST_OK && r.got[1] == 6,
         "the second is answered once the ping is");
  check (ld (&s.accepts) == 1, "over one connection");
  run_close (&r, 2);
  srv_stop (&s);
}

/* The connection the first was to make is closed before a byte is said.  The
   first fails; the second, which was waiting for it, makes its own, and is
   answered.  */
static void
test_leader_fails (void)
{
  struct srv s;
  struct run r;

  check (srv_start (&s, 1, 1) == 0, "server");
  check (run_open (&r), "runtime");
  run_make (&r, 0, &s, 1, -1);
  run_make (&r, 1, &s, 1, -1);
  run_go (&r, 0);
  run_go (&r, 1);
  check (run_wait (&r, 2), "both end");
  check (r.job[0].result != TWIST_OK, "the first fails");
  check (r.job[1].result == TWIST_OK && r.got[1] == 6,
         "the second is answered on a connection of its own");
  check (ld (&s.accepts) == 2, "two connections were made");
  run_close (&r, 2);
  srv_stop (&s);
}

/* A transfer cancelled while it waits is told so, makes no connection, and
   the one it waited for goes on.  */
static void
test_waiter_cancelled (void)
{
  struct srv s;
  struct run r;

  check (srv_start (&s, 1, 0) == 0, "server");
  check (run_open (&r), "runtime");
  run_make (&r, 0, &s, 1, -1);
  run_make (&r, 1, &s, 1, -1);
  run_go (&r, 0);
  run_go (&r, 1);
  check (twist_runtime_cancel (r.runtime, r.t[1]) == TWIST_OK, "cancel");
  check (run_wait (&r, 2), "both end");
  check (r.job[1].result == TWIST_ERR_ABORTED, "the waiter is aborted");
  check (r.job[0].result == TWIST_OK && r.got[0] == 6, "the first is answered");
  check (ld (&s.accepts) == 1, "one connection");
  run_close (&r, 2);
  srv_stop (&s);
}

/* The transfer that was making the connection is cancelled: the one that
   waited for it goes on by itself, and is answered.  */
static void
test_leader_cancelled (void)
{
  struct srv s;
  struct run r;

  check (srv_start (&s, 1, 0) == 0, "server");
  check (run_open (&r), "runtime");
  run_make (&r, 0, &s, 1, -1);
  run_make (&r, 1, &s, 1, -1);
  run_go (&r, 0);
  run_go (&r, 1);
  check (twist_runtime_cancel (r.runtime, r.t[0]) == TWIST_OK, "cancel");
  check (run_wait (&r, 2), "both end");
  check (r.job[0].result == TWIST_ERR_ABORTED, "the first is aborted");
  check (r.job[1].result == TWIST_OK && r.got[1] == 6,
         "the second is answered");
  run_close (&r, 2);
  srv_stop (&s);
}

/* A transfer that waits under a cap, and is cancelled there.  */
static void
test_queued_cancelled (void)
{
  struct srv s;
  struct run r;
  int i;

  check (srv_start (&s, 0, 0) == 0, "server");
  check (run_open (&r), "runtime");
  twist_runtime_setopt (r.runtime, TWIST_RUNTIMEOPT_MAX_HOST_CONNECTIONS, 1L);
  for (i = 0; i < 3; i++)
    {
      run_make (&r, i, &s, 0, -1);
      run_go (&r, i);
    }
  check (twist_runtime_cancel (r.runtime, r.t[1]) == TWIST_OK, "cancel");
  check (run_wait (&r, 3), "all end");
  check (r.job[1].result == TWIST_ERR_ABORTED, "the queued one is aborted");
  check (r.job[0].result == TWIST_OK && r.job[2].result == TWIST_OK,
         "the others are answered");
  check (ld (&s.max_open) == 1, "under the cap");
  run_close (&r, 3);
  srv_stop (&s);
}

static void
test_setopt (void)
{
  struct srv s;
  struct run r;

  check (srv_start (&s, 0, 0) == 0, "server");
  check (run_open (&r), "runtime");
  check (twist_runtime_setopt (r.runtime,
                               TWIST_RUNTIMEOPT_MAX_HOST_CONNECTIONS, 3L)
         == TWIST_OK, "an option is taken before a start");
  check (twist_runtime_setopt (r.runtime,
                               TWIST_RUNTIMEOPT_MAX_HOST_CONNECTIONS, 0L)
         == TWIST_OK, "and 0 is no limit");
  check (twist_runtime_setopt (r.runtime,
                               TWIST_RUNTIMEOPT_MAX_HOST_CONNECTIONS, -1L)
         == TWIST_ERR_INVAL, "a negative number is not");
  check (twist_runtime_setopt (r.runtime, 9999, 1L) == TWIST_ERR_INVAL,
         "an option that is not known is not");
  check (twist_runtime_setopt (NULL, TWIST_RUNTIMEOPT_MAX_HOST_CONNECTIONS, 1L)
         == TWIST_ERR_INVAL, "no runtime");
  run_make (&r, 0, &s, 0, -1);
  run_go (&r, 0);
  check (twist_runtime_setopt (r.runtime,
                               TWIST_RUNTIMEOPT_MAX_HOST_CONNECTIONS, 1L)
         == TWIST_ERR_INVAL, "it is refused once a transfer has started");
  check (run_wait (&r, 1), "the transfer ends");
  check (twist_runtime_setopt (r.runtime,
                               TWIST_RUNTIMEOPT_MAX_HOST_CONNECTIONS, 1L)
         == TWIST_ERR_INVAL, "and after it has ended");
  run_close (&r, 1);
  srv_stop (&s);
}

/* PIPEWAIT is a number, 1 by default.  */
static void
test_pipewait_option (void)
{
  twist_transfer *t = twist_transfer_new ();

  check (twist_transfer_setopt (t, TWISTOPT_PIPEWAIT, 0L) == TWIST_OK,
         "PIPEWAIT 0");
  check (twist_transfer_setopt (t, TWISTOPT_PIPEWAIT, 1L) == TWIST_OK,
         "PIPEWAIT 1");
  twist_transfer_free (t);
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
  announce ("test_pipewait_option");
  test_pipewait_option ();
  announce ("test_setopt");
  test_setopt ();
  announce ("test_h2_shared");
  test_h2_shared ();
  announce ("test_h2_pipewait_off");
  test_h2_pipewait_off ();
  announce ("test_h2_many");
  test_h2_many ();
  announce ("test_cap_h1");
  test_cap_h1 ();
  announce ("test_cap_two");
  test_cap_two ();
  announce ("test_cap_h2");
  test_cap_h2 ();
  announce ("test_h2_redirect");
  test_h2_redirect ();
  announce ("test_h2_window");
  test_h2_window ();
  announce ("test_h2_ping");
  test_h2_ping ();
  announce ("test_leader_fails");
  test_leader_fails ();
  announce ("test_leader_cancelled");
  test_leader_cancelled ();
  announce ("test_waiter_cancelled");
  test_waiter_cancelled ();
  announce ("test_queued_cancelled");
  test_queued_cancelled ();
  return tests_finish ();
}
