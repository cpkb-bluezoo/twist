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
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

/* The addresses of a name are raced (RFC 8305, section 5): the first is tried
   at once, the next after the connection attempt delay or when the attempt
   before it fails, and the first to connect is the connection.  Listeners on
   the loopback are the servers.  An address that hangs cannot be had there, so
   a test says which should: an attempt to it is made and never completes.  */

static double
now_ms (void)
{
  struct timespec t;

  clock_gettime (CLOCK_MONOTONIC, &t);
  return (double) t.tv_sec * 1000.0 + (double) t.tv_nsec / 1e6;
}

/* A listener on the loopback: family 4 or 6, PORT 0 for any.  Returns the
   descriptor, and the port in *PORT.  -1 if it cannot be had.  */
static int
listen_on (int family, int *port)
{
  struct sockaddr_in6 a6;
  struct sockaddr_in a4;
  struct sockaddr *sa;
  socklen_t salen, len;
  int one = 1;
  int fd = socket (family == 6 ? AF_INET6 : AF_INET, SOCK_STREAM, 0);

  if (fd < 0)
    return -1;
  if (family == 6)
    {
      memset (&a6, 0, sizeof a6);
      a6.sin6_family = AF_INET6;
      a6.sin6_addr = in6addr_loopback;
      a6.sin6_port = htons ((uint16_t) *port);
      setsockopt (fd, IPPROTO_IPV6, IPV6_V6ONLY, &one, sizeof one);
      sa = (struct sockaddr *) &a6;
      salen = sizeof a6;
    }
  else
    {
      memset (&a4, 0, sizeof a4);
      a4.sin_family = AF_INET;
      a4.sin_addr.s_addr = htonl (INADDR_LOOPBACK);
      a4.sin_port = htons ((uint16_t) *port);
      sa = (struct sockaddr *) &a4;
      salen = sizeof a4;
    }
  setsockopt (fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
  if (bind (fd, sa, salen) != 0 || listen (fd, 8) != 0)
    {
      close (fd);
      return -1;
    }
  len = salen;
  getsockname (fd, sa, &len);
  *port = ntohs (family == 6 ? a6.sin6_port : a4.sin_port);
  fcntl (fd, F_SETFL, O_NONBLOCK);
  return fd;
}

static struct twist_dns_addr
addr_of (const char *text)
{
  struct twist_dns_addr a;

  memset (&a, 0, sizeof a);
  a.family = strchr (text, ':') != NULL ? 6 : 4;
  inet_pton (a.family == 6 ? AF_INET6 : AF_INET, text, a.addr);
  snprintf (a.text, sizeof a.text, "%s", text);
  return a;
}

/* What the target connection was told.  */
struct tgt
{
  struct twist_connection *conn;
  int connected;
  int failed;
  int err;
  double at;
  double start;
};

static void
t_connected (struct twist_endpoint *ep)
{
  struct tgt *t = ep->user_data;

  t->connected = 1;
  t->at = now_ms () - t->start;
}

static void
t_failed (struct twist_endpoint *ep, int err)
{
  struct tgt *t = ep->user_data;

  if (!t->failed)
    t->at = now_ms () - t->start;
  t->failed = 1;
  t->err = err;
}

static void
t_disconnected (struct twist_endpoint *ep, int err)
{
  t_failed (ep, err);
}

static size_t
t_receive (struct twist_endpoint *ep, const uint8_t *data, size_t len)
{
  (void) ep;
  (void) data;
  return len;
}

static const struct twist_protocol_handler tgt_handler = {
  t_connected, t_receive, t_disconnected, NULL, t_failed, NULL, NULL
};

static int
stall_v6 (const struct twist_dns_addr *a)
{
  return a->family == 6;
}

static int
stall_all (const struct twist_dns_addr *a)
{
  (void) a;
  return 1;
}

static void
setup (struct twist_loop *loop, struct twist_transfer **transfer, struct tgt *t,
       long connect_timeout_ms)
{
  struct twist_endpoint *ep;

  *transfer = twist_transfer_new ();
  (*transfer)->loop = loop;
  twist_transfer_setopt (*transfer, TWISTOPT_CONNECTTIMEOUT_MS,
                         connect_timeout_ms);
  memset (t, 0, sizeof *t);
  t->conn = twist_connection_new (loop);
  ep = twist_connection_endpoint (t->conn);
  ep->user_data = t;
  twist_connection_set_handler (t->conn, &tgt_handler);
  t->start = now_ms ();
}

static void
run_until (struct twist_loop *loop, const struct tgt *t, int ms)
{
  double end = now_ms () + ms;

  while (!t->connected && !t->failed && now_ms () < end)
    twist_loop_run_once_ms (loop, 5);
}

/* Whether a byte sent over the target arrives at the listener LFD.  */
static int
byte_arrives (struct tgt *t, int lfd)
{
  char b = 0;
  int peer = -1, i;

  if (twist_endpoint_send (twist_connection_endpoint (t->conn),
                           (const uint8_t *) "x", 1) != TWIST_OK)
    return 0;
  for (i = 0; i < 100 && peer < 0; i++)
    {
      peer = accept (lfd, NULL, NULL);
      if (peer < 0)
        usleep (2000);
    }
  if (peer < 0)
    return 0;
  for (i = 0; i < 100; i++)
    {
      if (recv (peer, &b, 1, 0) == 1)
        break;
      usleep (2000);
    }
  close (peer);
  return b == 'x';
}

static void
finish (struct twist_race *r, struct tgt *t, struct twist_transfer *transfer,
        struct twist_loop *loop)
{
  int i;

  twist_race_free (r);
  twist_connection_free (t->conn);
  twist_transfer_free (transfer);
  for (i = 0; i < 5; i++)
    twist_loop_run_once_ms (loop, 2);
}

static void
test_plain (struct twist_loop *loop)
{
  struct twist_transfer *transfer;
  struct tgt t;
  struct twist_race *r;
  struct twist_dns_addr a = addr_of ("127.0.0.1");
  int port = 0;
  int lfd = listen_on (4, &port);

  check (lfd >= 0, "a listener");
  setup (loop, &transfer, &t, 5000);
  r = twist_race_new (transfer, t.conn, port);
  check (r != NULL && twist_race_add (r, &a) == TWIST_OK, "a race of one");
  twist_race_end (r);
  run_until (loop, &t, 3000);
  check (t.connected && !t.failed, "it connects");
  check (t.connected && byte_arrives (&t, lfd), "and the socket is the connection's");
  finish (r, &t, transfer, loop);
  close (lfd);
}

static void
test_refused_first (struct twist_loop *loop)
{
  struct twist_transfer *transfer;
  struct tgt t;
  struct twist_race *r;
  struct twist_dns_addr v6 = addr_of ("::1");
  struct twist_dns_addr v4 = addr_of ("127.0.0.1");
  int port = 0;
  int lfd = listen_on (4, &port);

  /* Nothing is listening on ::1 at that port: refused, and the next address
     is tried at once, and not after the delay.  */
  setup (loop, &transfer, &t, 5000);
  r = twist_race_new (transfer, t.conn, port);
  twist_race_add (r, &v6);
  twist_race_add (r, &v4);
  twist_race_end (r);
  run_until (loop, &t, 3000);
  check (t.connected && byte_arrives (&t, lfd), "IPv6 refused: IPv4 connects");
  check (t.at < 150, "and at once, not after the delay");
  finish (r, &t, transfer, loop);
  close (lfd);
}

static void
test_hang_first (struct twist_loop *loop)
{
  struct twist_transfer *transfer;
  struct tgt t;
  struct twist_race *r;
  struct twist_dns_addr v6 = addr_of ("::1");
  struct twist_dns_addr v4 = addr_of ("127.0.0.1");
  int port = 0;
  int lfd = listen_on (4, &port);

  /* The first hangs: the second is tried when the delay has passed, and the
     first is not given up on.  */
  twist_race_set_stall (stall_v6);
  setup (loop, &transfer, &t, 5000);
  r = twist_race_new (transfer, t.conn, port);
  twist_race_add (r, &v6);
  twist_race_add (r, &v4);
  twist_race_end (r);
  run_until (loop, &t, 3000);
  check (t.connected && byte_arrives (&t, lfd), "IPv6 hangs: IPv4 connects");
  check (t.at >= 230 && t.at < 700, "after about the connection attempt delay");
  finish (r, &t, transfer, loop);

  /* The same, when the delay is changed.  */
  twist_race_set_delay (80);
  setup (loop, &transfer, &t, 5000);
  r = twist_race_new (transfer, t.conn, port);
  twist_race_add (r, &v6);
  twist_race_add (r, &v4);
  twist_race_end (r);
  run_until (loop, &t, 3000);
  check (t.connected && t.at >= 60 && t.at < 200, "and after the delay that is set");
  finish (r, &t, transfer, loop);
  twist_race_set_delay (0);
  twist_race_set_stall (NULL);
  close (lfd);
}

static void
test_late (struct twist_loop *loop)
{
  struct twist_transfer *transfer;
  struct tgt t;
  struct twist_race *r;
  struct twist_dns_addr v6 = addr_of ("::1");
  struct twist_dns_addr v4 = addr_of ("127.0.0.1");
  int port = 0;
  int lfd = listen_on (4, &port);
  double end;

  /* The IPv4 address is found after the first has been tried for 100 ms: it
     is tried when the delay since the first is over, 250 ms from the start.  */
  twist_race_set_stall (stall_v6);
  setup (loop, &transfer, &t, 5000);
  r = twist_race_new (transfer, t.conn, port);
  twist_race_add (r, &v6);
  end = now_ms () + 100;
  while (now_ms () < end)
    twist_loop_run_once_ms (loop, 5);
  check (!t.connected && !t.failed, "nothing yet, with one that hangs");
  twist_race_add (r, &v4);
  twist_race_end (r);
  run_until (loop, &t, 3000);
  check (t.connected && byte_arrives (&t, lfd), "an address that comes late is used");
  check (t.at >= 230 && t.at < 700, "when the delay since the first is over");
  finish (r, &t, transfer, loop);
  twist_race_set_stall (NULL);
  close (lfd);
}

static void
test_all_fail (struct twist_loop *loop)
{
  struct twist_transfer *transfer;
  struct tgt t;
  struct twist_race *r;
  struct twist_dns_addr v6 = addr_of ("::1");
  struct twist_dns_addr v4 = addr_of ("127.0.0.1");
  int port = 0;
  int lfd = listen_on (4, &port);

  /* A port that has nobody: close the listener.  */
  close (lfd);
  setup (loop, &transfer, &t, 5000);
  r = twist_race_new (transfer, t.conn, port);
  twist_race_add (r, &v6);
  twist_race_add (r, &v4);
  run_until (loop, &t, 300);
  check (!t.failed, "not failed while more may come");
  twist_race_end (r);
  run_until (loop, &t, 3000);
  check (t.failed && !t.connected && t.err == TWIST_ERR_CONNECT,
         "all refused, and no more to come: the connection could not be made");
  finish (r, &t, transfer, loop);
}

static void
test_timeout (struct twist_loop *loop)
{
  struct twist_transfer *transfer;
  struct tgt t;
  struct twist_race *r;
  struct twist_dns_addr v6 = addr_of ("::1");

  twist_race_set_stall (stall_all);
  setup (loop, &transfer, &t, 300);
  r = twist_race_new (transfer, t.conn, 80);
  twist_race_add (r, &v6);
  twist_race_end (r);
  run_until (loop, &t, 3000);
  check (t.failed && t.err == TWIST_ERR_TIMEOUT && t.at >= 250 && t.at < 900,
         "all hang: the connect timeout");
  finish (r, &t, transfer, loop);
  twist_race_set_stall (NULL);
}

static void
test_preference (struct twist_loop *loop)
{
  struct twist_transfer *transfer;
  struct tgt t;
  struct twist_race *r;
  struct twist_dns_addr v6 = addr_of ("::1");
  struct twist_dns_addr v4 = addr_of ("127.0.0.1");
  int port = 0;
  int l6 = listen_on (6, &port);
  int l4;

  l4 = l6 >= 0 ? listen_on (4, &port) : -1;
  if (l6 < 0 || l4 < 0)
    {
      fputs ("test-race: no IPv6 loopback; skipping the order test\n", stderr);
      if (l6 >= 0)
        close (l6);
      return;
    }
  /* Both are there: the first in the order is the one that is used.  */
  setup (loop, &transfer, &t, 5000);
  r = twist_race_new (transfer, t.conn, port);
  twist_race_add (r, &v6);
  twist_race_add (r, &v4);
  twist_race_end (r);
  run_until (loop, &t, 3000);
  check (t.connected && byte_arrives (&t, l6), "IPv6 first: the IPv6 listener has it");
  finish (r, &t, transfer, loop);
  close (l6);
  close (l4);
}

static void
test_dial (struct twist_loop *loop)
{
  struct twist_transfer *transfer;
  struct tgt t;
  struct twist_race *r;
  int port = 0;
  int lfd = listen_on (4, &port);

  /* A name, and the race of what it gives (here an address).  */
  setup (loop, &transfer, &t, 5000);
  r = NULL;
  check (twist_race_dial (transfer, t.conn, "127.0.0.1", port, NULL, NULL, &r)
         == TWIST_OK && r != NULL, "dial");
  run_until (loop, &t, 3000);
  check (t.connected && byte_arrives (&t, lfd), "a name is resolved and connected");
  finish (r, &t, transfer, loop);
  close (lfd);
}

int
main (void)
{
  struct twist_loop *loop = twist_loop_new (0);

  if (loop == NULL)
    return 77;
  twist_dns_set_hosts_file ("/nonexistent/twist-hosts");
  test_plain (loop);
  test_refused_first (loop);
  test_hang_first (loop);
  test_late (loop);
  test_all_fail (loop);
  test_timeout (loop);
  test_preference (loop);
  test_dial (loop);
  twist_dns_set_hosts_file (NULL);
  twist_loop_free (loop);
  return tests_finish ();
}
