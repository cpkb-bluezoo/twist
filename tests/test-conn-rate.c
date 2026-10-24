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

/* A limit belongs to the connection (twist_connection_set_rate), and is kept
   whatever the protocol on it: what is read from it, and what is written to
   it, go no faster than the limit, on average.  The far end is a socket pair
   that is not limited.  With 10000 bytes a second and 20000 bytes, chunks of
   half a second's worth go at 0, 0.5, 1 and 1.5 seconds.  */

#define TOTAL 20000
#define LIMIT 10000

static double
now_ms (void)
{
  struct timespec t;

  clock_gettime (CLOCK_MONOTONIC, &t);
  return (double) t.tv_sec * 1000.0 + (double) t.tv_nsec / 1e6;
}

static size_t got;

static size_t
h_receive (struct twist_endpoint *ep, const uint8_t *data, size_t len)
{
  (void) ep;
  (void) data;
  got += len;
  return len;
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
make (struct twist_loop *loop, int fd, uint64_t recv_limit, uint64_t send_limit)
{
  struct twist_protocol_handler h;
  struct twist_connection *c = twist_connection_new (loop);

  memset (&h, 0, sizeof h);
  h.receive = h_receive;
  twist_connection_set_handler (c, &h);
  twist_connection_set_rate (c, recv_limit, send_limit);
  twist_connection_set_fd (c, fd);
  return c;
}

static void
test_download (struct twist_loop *loop)
{
  int sv[2];
  uint8_t buf[TOTAL];
  size_t sent = 0;
  struct twist_connection *c;
  double start, end;

  if (pair (sv) != 0)
    return;
  memset (buf, 'x', sizeof buf);
  got = 0;
  c = make (loop, sv[0], LIMIT, 0);
  start = now_ms ();
  end = start + 6000;
  while (got < TOTAL && now_ms () < end)
    {
      if (sent < TOTAL)
        {
          ssize_t n = write (sv[1], buf + sent, TOTAL - sent);

          if (n > 0)
            sent += (size_t) n;
        }
      twist_loop_run_once_ms (loop, 5);
    }
  end = now_ms () - start;
  check (got == TOTAL, "all of it came");
  check (end >= 1400, "a download keeps to the limit");
  check (end < 4000, "and is not held longer than that");
  twist_connection_free (c);
  close (sv[1]);
}

static void
test_upload (struct twist_loop *loop)
{
  int sv[2];
  uint8_t buf[TOTAL];
  size_t seen = 0;
  struct twist_connection *c;
  double start, end;

  if (pair (sv) != 0)
    return;
  memset (buf, 'y', sizeof buf);
  c = make (loop, sv[0], 0, LIMIT);
  start = now_ms ();
  twist_endpoint_send (twist_connection_endpoint (c), buf, sizeof buf);
  end = start + 6000;
  while (seen < TOTAL && now_ms () < end)
    {
      uint8_t in[4096];
      ssize_t n = read (sv[1], in, sizeof in);

      if (n > 0)
        seen += (size_t) n;
      twist_loop_run_once_ms (loop, 5);
    }
  end = now_ms () - start;
  check (seen == TOTAL, "all of it went");
  check (end >= 1400, "an upload keeps to the limit");
  check (end < 4000, "and is not held longer than that");
  twist_connection_free (c);
  close (sv[1]);
}

static void
test_unlimited (struct twist_loop *loop)
{
  int sv[2];
  uint8_t buf[TOTAL];
  size_t sent = 0;
  struct twist_connection *c;
  double start, end;

  if (pair (sv) != 0)
    return;
  memset (buf, 'z', sizeof buf);
  got = 0;
  c = make (loop, sv[0], 0, 0);
  start = now_ms ();
  end = start + 3000;
  while (got < TOTAL && now_ms () < end)
    {
      if (sent < TOTAL)
        {
          ssize_t n = write (sv[1], buf + sent, TOTAL - sent);

          if (n > 0)
            sent += (size_t) n;
        }
      twist_loop_run_once_ms (loop, 5);
    }
  check (got == TOTAL && now_ms () - start < 500, "no limit is no delay");
  twist_connection_free (c);
  close (sv[1]);
}

int
main (void)
{
  struct twist_loop *loop = twist_loop_new (0);

  if (loop == NULL)
    return 77;
  test_unlimited (loop);
  test_download (loop);
  test_upload (loop);
  twist_loop_free (loop);
  return tests_finish ();
}
