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
  unsigned char buf[SRV_MAX][16400];
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
  /* An upload to /U is taken in and counted, never answered, and its window
     is never given back.  */
  unsigned up_stream[SRV_MAX];
  int grant[SRV_MAX];		/* An upload to /W is answered, and given room.  */
  long up_got[SRV_MAX];
  int ping_wait[SRV_MAX];
};

#define BIG 150000
/* A response on /Z is larger than a stream's window, so a stream that is not
   given its window back stalls the server.  */
#define HUGE_BODY (2 * 1024 * 1024)
/* A response on /Y is larger than all that a transfer will hold for a sink that
   is full.  */
#define ENORMOUS_BODY (16 * 1024 * 1024)

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
  s->up_stream[i] = 0;
  s->up_got[i] = 0;
  s->grant[i] = 0;
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
      __atomic_sub_fetch (&s->big_left[i], n, __ATOMIC_ACQ_REL);
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
  unsigned char out[4096];
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
      else if (type == 0 && stream != 0 && s->grant[i])
        {
          static const unsigned char status200 = 0x88;
          unsigned char inc[4];

          __atomic_add_fetch (&s->up_got[i], (long) len, __ATOMIC_ACQ_REL);
          /* Small frames can be many in one read: send what is made.  */
          if (n > (int) sizeof out - 128)
            {
              if (write (s->conns[i], out, (size_t) n) < 0)
                return -1;
              n = 0;
            }
          inc[0] = (unsigned char) (len >> 24);
          inc[1] = (unsigned char) (len >> 16);
          inc[2] = (unsigned char) (len >> 8);
          inc[3] = (unsigned char) len;
          if (len > 0 && !(flags & 1))
            {
              n += frame (out + n, 8, 0, 0, inc, 4);
              n += frame (out + n, 8, 0, stream, inc, 4);
            }
          if (flags & 1)
            {
              n += frame (out + n, 1, 4, stream, &status200, 1);
              n += frame (out + n, 0, 1, stream, "hello\n", 6);
            }
        }
      else if (type == 0 && stream != 0 && stream == s->up_stream[i])
        __atomic_add_fetch (&s->up_got[i], (long) len, __ATOMIC_ACQ_REL);
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
          int huge = 0;
          int ping = 0;
          int upload = 0;
          int granting = 0;
          int enormous = 0;

          /* A request for /r is sent to /1, one for /b is answered at length
             as the windows allow, and one for /p waits for the client to
             answer a ping.  */
          for (k = 9; k + 1 < 9 + len; k++)
            if (s->buf[i][k] == '/')
              {
                redirect |= s->buf[i][k + 1] == 'r';
                big |= s->buf[i][k + 1] == 'b';
                huge |= s->buf[i][k + 1] == 'Z';
                ping |= s->buf[i][k + 1] == 'p';
                upload |= s->buf[i][k + 1] == 'U';
                granting |= s->buf[i][k + 1] == 'W';
                enormous |= s->buf[i][k + 1] == 'Y';
              }
          if (granting)
            s->grant[i] = 1;
          else if (upload)
            s->up_stream[i] = stream;
          else if (redirect)
            n += frame (out + n, 1, 5, stream, moved, sizeof moved);
          else if (big || huge || enormous)
            {
              n += frame (out + n, 1, 4, stream, &status200, 1);
              s->big_stream[i] = stream;
              __atomic_store_n (&s->big_left[i],
                                enormous ? (long) ENORMOUS_BODY
                                : huge ? (long) HUGE_BODY : (long) BIG,
                                __ATOMIC_RELEASE);
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

struct pausing
{
  twist_transfer *transfer;
  size_t got;
  int pause_at;			/* Pause once this many bytes have come.  */
  int paused;
};

static size_t
pausing_body (char *ptr, size_t size, size_t nmemb, void *user)
{
  struct pausing *p = user;

  (void) ptr;
  /* Full: it takes none of this, and is given it again on resume.  */
  if (!p->paused && p->got >= (size_t) p->pause_at)
    {
      p->paused = 1;
      return TWIST_WRITEFUNC_PAUSE;
    }
  p->got += size * nmemb;
  return size * nmemb;
}

/* A write callback that is full (TWIST_WRITEFUNC_PAUSE) pauses its stream only: its window is not
   given back, so the server stops sending on it, and another stream on the
   same connection is still answered.  Resumed, it goes on and ends.  */
static void
test_h2_pause_stream (void)
{
  struct srv s;
  struct run r;
  struct pausing p;
  size_t at_pause;
  struct timespec t0, t1;

  check (srv_start (&s, 1, 0) == 0, "server");
  check (run_open (&r), "runtime");
  memset (&p, 0, sizeof p);
  p.pause_at = 1000;
  run_make (&r, 0, &s, 1, -1);
  run_path (&r, 0, &s, "/Z");
  p.transfer = r.t[0];
  twist_transfer_setopt (r.t[0], TWISTOPT_WRITEFUNCTION, pausing_body);
  twist_transfer_setopt (r.t[0], TWISTOPT_WRITEDATA, &p);
  run_go (&r, 0);
  clock_gettime (CLOCK_MONOTONIC, &t0);
  do
    {
      twist_runtime_run_once (r.runtime, 10);
      clock_gettime (CLOCK_MONOTONIC, &t1);
    }
  while (!p.paused && t1.tv_sec - t0.tv_sec < 3);
  check (p.paused, "the first stream is paused");
  /* Give the rest of what was in flight time to arrive.  */
  for (int k = 0; k < 20; k++)
    twist_runtime_run_once (r.runtime, 10);
  at_pause = p.got;
  check (!r.job[0].done, "and is not over");
  /* Another stream on the same connection.  */
  run_make (&r, 1, &s, 1, -1);
  run_go (&r, 1);
  {
    int k;

    for (k = 0; k < 200 && !r.job[1].done; k++)
      twist_runtime_run_once (r.runtime, 10);
  }
  check (r.job[1].done && r.job[1].result == TWIST_OK && r.got[1] == 6,
         "another stream on the connection is still answered");
  check (ld (&s.accepts) == 1, "over the one connection");
  check (!r.job[0].done && p.got <= at_pause + 4096
         && p.got < (size_t) HUGE_BODY,
         "the paused stream receives nothing more");
  check (__atomic_load_n (&s.big_left[0], __ATOMIC_ACQUIRE) > 0,
         "because the server has not been given its window back");
  twist_transfer_resume (r.t[0]);
  check (run_wait (&r, 2), "resumed, it ends");
  check (r.job[0].result == TWIST_OK && p.got == (size_t) HUGE_BODY,
         "with all of the body");
  run_close (&r, 2);
  srv_stop (&s);
}


struct upl
{
  size_t total;
  size_t sent;			/* What the source has given.  */
};

static size_t
up_read (char *buf, size_t size, size_t nmemb, void *user)
{
  struct upl *u = user;
  size_t n = size * nmemb;

  if (n > u->total - u->sent)
    n = u->total - u->sent;
  memset (buf, 'u', n);
  u->sent += n;
  return n;
}

/* An upload whose stream window the server never opens again takes no more
   from its source than the window and a chunk, and is not waiting on the
   connection: another transfer to the same origin is answered over it while
   the upload is stuck.  */
static void
test_h2_upload_stalled (void)
{
  struct srv s;
  struct run r;
  struct upl u;
  size_t at_stall;
  int k;

  check (srv_start (&s, 1, 0) == 0, "server");
  check (run_open (&r), "runtime");
  memset (&u, 0, sizeof u);
  u.total = 4 * 1024 * 1024;
  /* The connection is made, and idle.  */
  run_make (&r, 0, &s, 1, -1);
  run_go (&r, 0);
  check (run_wait (&r, 1) && r.job[0].result == TWIST_OK, "the first is answered");
  run_make (&r, 1, &s, 1, -1);
  run_path (&r, 1, &s, "/U");
  twist_transfer_setopt (r.t[1], TWISTOPT_CUSTOMREQUEST, "PUT");
  twist_transfer_setopt (r.t[1], TWISTOPT_READFUNCTION, up_read);
  twist_transfer_setopt (r.t[1], TWISTOPT_READDATA, &u);
  twist_transfer_setopt (r.t[1], TWISTOPT_INFILESIZE, (long) u.total);
  run_go (&r, 1);
  for (k = 0; k < 60; k++)
    twist_runtime_run_once (r.runtime, 10);
  at_stall = u.sent;
  for (k = 0; k < 30; k++)
    twist_runtime_run_once (r.runtime, 10);
  check (u.sent > 0 && u.sent < u.total, "the upload has begun, and is not over");
  check (u.sent == at_stall, "and takes no more from its source while stuck");
  check (u.sent <= 65535 + 2 * 16384,
         "no more than the window and a chunk or two");
  check (ld (&s.accepts) == 1, "over the one connection");
  /* Another stream on the connection.  */
  run_make (&r, 2, &s, 1, -1);
  run_go (&r, 2);
  for (k = 0; k < 200 && !r.job[2].done; k++)
    twist_runtime_run_once (r.runtime, 10);
  check (r.job[2].done && r.job[2].result == TWIST_OK && r.got[2] == 6,
         "another transfer is answered while the upload is stuck");
  check (ld (&s.accepts) == 1, "over the same connection");
  check (!r.job[1].done, "and the upload is still waiting");
  twist_runtime_cancel (r.runtime, r.t[1]);
  check (run_wait (&r, 3), "cancelled, it ends");
  run_close (&r, 3);
  srv_stop (&s);
}
/* Two uploads under way on one connection, each larger than the windows, and a
   third transfer beside them: all end, over the one connection, and the server
   has every byte of both.  */
static void
test_h2_uploads_together (void)
{
  struct srv s;
  struct run r;
  struct upl u[2];
  int i;

  check (srv_start (&s, 1, 0) == 0, "server");
  check (run_open (&r), "runtime");
  for (i = 0; i < 2; i++)
    {
      memset (&u[i], 0, sizeof u[i]);
      u[i].total = 400000 + (size_t) i * 1000;
      run_make (&r, i, &s, 1, -1);
      run_path (&r, i, &s, "/W");
      twist_transfer_setopt (r.t[i], TWISTOPT_CUSTOMREQUEST, "PUT");
      twist_transfer_setopt (r.t[i], TWISTOPT_READFUNCTION, up_read);
      twist_transfer_setopt (r.t[i], TWISTOPT_READDATA, &u[i]);
      twist_transfer_setopt (r.t[i], TWISTOPT_INFILESIZE, (long) u[i].total);
    }
  run_make (&r, 2, &s, 1, -1);
  run_go (&r, 0);
  run_go (&r, 1);
  run_go (&r, 2);
  check (run_wait (&r, 3), "all three end");
  check (r.job[0].result == TWIST_OK && r.job[1].result == TWIST_OK
         && r.job[2].result == TWIST_OK, "all three are answered");
  check (u[0].sent == u[0].total && u[1].sent == u[1].total,
         "both uploads are read to the end");
  check (ld (&s.accepts) == 1, "over one connection");
  {
    long got = 0;

    for (i = 0; i < SRV_MAX; i++)
      got += __atomic_load_n (&s.up_got[i], __ATOMIC_ACQUIRE);
    check (got == (long) (u[0].total + u[1].total),
           "and the server has every byte of both");
  }
  run_close (&r, 3);
  srv_stop (&s);
}

/* A write callback that takes a little each time it is resumed and is full
   again at once: the peer must not be let go for what is only held, or what is
   held grows by a window at each resume, with no bound, and the transfer is
   ended when it passes what a transfer will hold.  */
struct cycler
{
  size_t got;
  size_t budget;		/* What it will take before it is full.  */
};

static size_t
cycler_body (char *ptr, size_t size, size_t nmemb, void *user)
{
  struct cycler *c = user;
  size_t n = size * nmemb;

  (void) ptr;
  if (c->budget < n)
    return TWIST_WRITEFUNC_PAUSE;
  c->budget -= n;
  c->got += n;
  return n;
}

static void
test_h2_slow_sink_cycles (void)
{
  struct srv s;
  struct run r;
  struct cycler c;
  size_t most_held = 0;
  int k;

  check (srv_start (&s, 1, 0) == 0, "server");
  check (run_open (&r), "runtime");
  memset (&c, 0, sizeof c);
  c.budget = 200000;
  run_make (&r, 0, &s, 1, -1);
  run_path (&r, 0, &s, "/Y");
  twist_transfer_setopt (r.t[0], TWISTOPT_WRITEFUNCTION, cycler_body);
  twist_transfer_setopt (r.t[0], TWISTOPT_WRITEDATA, &c);
  twist_transfer_setopt (r.t[0], TWISTOPT_TIMEOUT_MS, 30000L);
  run_go (&r, 0);
  for (k = 0; k < 20000 && !r.job[0].done; k++)
    {
      twist_runtime_run_once (r.runtime, 1);
      if (r.t[0]->held_len > most_held)
        most_held = r.t[0]->held_len;
      /* Every so often the consumer has room for a little.  */
      if (k % 5 == 0 && r.t[0]->sink_paused && !r.job[0].done)
        {
          c.budget = 200000;
          twist_transfer_resume (r.t[0]);
        }
    }
  check (r.job[0].done && r.job[0].result == TWIST_OK,
         "a body larger than all that is held ends, for a consumer that takes "
         "a little each time");
  check (c.got == (size_t) ENORMOUS_BODY, "with all of it");
  check (most_held < 2 * 1024 * 1024, "and no more was held than a few windows");
  run_close (&r, 1);
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

/* A connection is made under the TLS settings of the transfer that made it,
   and another transfer may use it only if its own are the same: one that
   checks the server must not be handed a connection made without checking,
   nor one that sends no client certificate a connection that sent another's.
   The settings are part of the origin's key, when they matter, and the key of
   a transfer that has only defaults is what it always was.  */
static char key_buf[3][512];

static const char *
tls_key (int slot, const char *url, const char *proxy, long verify,
         const char *cainfo, const char *capath, const char *cert,
         const char *key, long proxy_verify, const char *proxy_cainfo,
         const char *proxy_userpwd)
{
  twist_transfer *t = twist_transfer_new ();

  twist_url_parse_int (url, &t->url);
  if (proxy != NULL)
    twist_transfer_setopt (t, TWISTOPT_PROXY, proxy);
  twist_transfer_setopt (t, TWISTOPT_SSL_VERIFYPEER, verify);
  twist_transfer_setopt (t, TWISTOPT_CAINFO, cainfo);
  twist_transfer_setopt (t, TWISTOPT_CAPATH, capath);
  twist_transfer_setopt (t, TWISTOPT_SSLCERT, cert);
  twist_transfer_setopt (t, TWISTOPT_SSLKEY, key);
  twist_transfer_setopt (t, TWISTOPT_PROXY_SSL_VERIFYPEER, proxy_verify);
  twist_transfer_setopt (t, TWISTOPT_PROXY_CAINFO, proxy_cainfo);
  twist_transfer_setopt (t, TWISTOPT_PROXYUSERPWD, proxy_userpwd);
  key_buf[slot][0] = 0;
  twist_transfer_origin_okey (t, key_buf[slot], sizeof key_buf[slot]);
  twist_transfer_free (t);
  return key_buf[slot];
}

#define H "https://example.test/"
#define SAME(a, b) (strcmp ((a), (b)) == 0)

static void
test_tls_identity (void)
{
  const char *plain = tls_key (0, H, NULL, 1, NULL, NULL, NULL, NULL, 1, NULL,
                               NULL);
  char def[512];

  snprintf (def, sizeof def, "%s", plain);
  check (SAME (def, "https|example.test|443|-"),
         "the key of a transfer with defaults is unchanged");
  check (!SAME (tls_key (1, H, NULL, 0, NULL, NULL, NULL, NULL, 1, NULL, NULL),
                def), "verifying and not verifying do not share a connection");
  check (!SAME (tls_key (1, H, NULL, 1, "/a.pem", NULL, NULL, NULL, 1, NULL,
                         NULL), def), "nor does a CA file");
  check (!SAME (tls_key (1, H, NULL, 1, "/a.pem", NULL, NULL, NULL, 1, NULL,
                         NULL),
                tls_key (2, H, NULL, 1, "/b.pem", NULL, NULL, NULL, 1, NULL,
                         NULL)), "or two");
  check (SAME (tls_key (1, H, NULL, 1, "/a.pem", NULL, NULL, NULL, 1, NULL,
                        NULL),
               tls_key (2, H, NULL, 1, "/a.pem", NULL, NULL, NULL, 1, NULL,
                        NULL)), "but the same CA file does");
  check (!SAME (tls_key (1, H, NULL, 1, NULL, "/ca.d", NULL, NULL, 1, NULL,
                         NULL), def), "a CA directory");
  check (!SAME (tls_key (1, H, NULL, 1, NULL, NULL, "/c.pem", NULL, 1, NULL,
                         NULL), def), "a client certificate");
  check (!SAME (tls_key (1, H, NULL, 1, NULL, NULL, NULL, "/k.pem", 1, NULL,
                         NULL), def), "a client key");
  check (!SAME (tls_key (1, H, NULL, 1, NULL, NULL, "ab", "", 1, NULL, NULL),
                tls_key (2, H, NULL, 1, NULL, NULL, "a", "b", 1, NULL, NULL)),
         "and where one setting ends and the next begins is not lost");

  /* Over plain http nothing of this is used, and nothing splits.  */
  check (SAME (tls_key (1, "http://example.test/", NULL, 0, "/a.pem", "/d",
                        "/c.pem", "/k.pem", 1, NULL, NULL),
               tls_key (2, "http://example.test/", NULL, 1, NULL, NULL, NULL,
                        NULL, 1, NULL, NULL)),
         "plain http has no TLS settings");

  /* A proxy that is spoken to in TLS has its own.  */
  check (!SAME (tls_key (1, H, "https://proxy.test:8443", 1, NULL, NULL, NULL,
                         NULL, 0, NULL, NULL),
                tls_key (2, H, "https://proxy.test:8443", 1, NULL, NULL, NULL,
                         NULL, 1, NULL, NULL)),
         "an https proxy that is verified and one that is not");
  check (!SAME (tls_key (1, "http://example.test/", "https://proxy.test:8443",
                         1, NULL, NULL, NULL, NULL, 1, "/p.pem", NULL),
                tls_key (2, "http://example.test/", "https://proxy.test:8443",
                         1, NULL, NULL, NULL, NULL, 1, NULL, NULL)),
         "an https proxy's CA, even to a plain http target");
  check (SAME (tls_key (1, "http://example.test/", "http://proxy.test:3128",
                        1, NULL, NULL, NULL, NULL, 0, "/p.pem", NULL),
               tls_key (2, "http://example.test/", "http://proxy.test:3128",
                        1, NULL, NULL, NULL, NULL, 1, NULL, NULL)),
         "an http proxy has none");
  check (!SAME (tls_key (1, H, "http://proxy.test:3128", 1, NULL, NULL, NULL,
                         NULL, 1, NULL, "u:p"),
                tls_key (2, H, "http://proxy.test:3128", 1, NULL, NULL, NULL,
                         NULL, 1, NULL, "v:q")),
         "a tunnel is not shared by those with other proxy credentials");
}

int
main (void)
{
  announce ("test_tls_identity");
  test_tls_identity ();
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
  announce ("test_h2_pause_stream");
  test_h2_pause_stream ();
  announce ("test_h2_upload_stalled");
  test_h2_upload_stalled ();
  announce ("test_h2_uploads_together");
  test_h2_uploads_together ();
  announce ("test_h2_slow_sink_cycles");
  test_h2_slow_sink_cycles ();
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
