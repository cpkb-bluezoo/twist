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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

static void
test_url (void)
{
  struct twist_url *url = NULL;
  struct twist_url *rel = NULL;

  check (twist_url_parse_int ("http://user:secret@example.com:8080/a/b?x=1#f",
                              &url) == TWIST_OK, "parse");
  check (url != NULL && strcmp (url->scheme, "http") == 0, "scheme");
  check (strcmp (url->host, "example.com") == 0, "host");
  check (url->port == 8080, "port");
  check (strcmp (url->path, "/a/b") == 0, "path");
  check (strcmp (url->query, "x=1") == 0, "query");
  check (strcmp (url->user, "user") == 0, "user");
  check (twist_url_resolve_int (url, "/z", &rel) == TWIST_OK, "resolve");
  check (rel != NULL && strcmp (rel->path, "/z") == 0, "rel path");
  check (strcmp (rel->host, "example.com") == 0, "rel host");
  twist_url_free_int (rel);
  {
    char target[128];

    check (twist_url_proxy_target (url, target, sizeof target) == TWIST_OK,
           "proxy target");
    check (strcmp (target, "http://example.com:8080/a/b?x=1") == 0,
           "proxy no user");
  }
  twist_url_free_int (url);
  check (twist_url_parse_int ("http://example.com/a\r\nb", &url)
         == TWIST_ERR_URL, "crlf path");
  check (twist_url_parse_int ("http://ex\r\n.com/", &url) == TWIST_ERR_URL,
         "crlf host");
  check (twist_url_parse_int ("http://example.com/%0d%0a", &url) == TWIST_OK,
         "encoded crlf");
  twist_url_free_int (url);
}

static void
test_scheme (void)
{
  const struct twist_scheme *http = twist_scheme_by_name ("http");
  const struct twist_scheme *ftp = twist_scheme_by_name ("ftp");
  const struct twist_scheme *ftps = twist_scheme_by_name ("ftps");
  const struct twist_scheme *smtp = twist_scheme_by_name ("smtp");

  check (http != NULL && (http->flags & TWIST_SCHEME_READY) != 0, "http");
  check (ftp != NULL && (ftp->flags & TWIST_SCHEME_READY) != 0, "ftp");
  check (ftps != NULL && (ftps->flags & TWIST_SCHEME_READY) != 0, "ftps");
  check (smtp != NULL && (smtp->flags & TWIST_SCHEME_READY) != 0, "smtp");
  check (twist_scheme_by_name ("imap") != NULL
         && (twist_scheme_by_name ("imap")->flags & TWIST_SCHEME_READY) != 0,
         "imap");
  check (twist_scheme_by_name ("pop3s") != NULL
         && (twist_scheme_by_name ("pop3s")->flags & TWIST_SCHEME_READY) != 0,
         "pop3s");
  check (twist_scheme_by_name ("mqtt") != NULL
         && (twist_scheme_by_name ("mqtt")->flags & TWIST_SCHEME_READY) != 0,
         "mqtt");
  check (twist_scheme_by_name ("mqtts") != NULL
         && (twist_scheme_by_name ("mqtts")->flags & TWIST_SCHEME_TLS) != 0,
         "mqtts");
  check (twist_scheme_by_name ("ldaps") != NULL
         && (twist_scheme_by_name ("ldaps")->flags & TWIST_SCHEME_READY) != 0,
         "ldaps");
  check (twist_scheme_by_name ("no-such") == NULL, "missing");
  check (twist_scheme_by_name ("file") != NULL, "file");
  check (twist_scheme_by_name ("ws") != NULL
         && (twist_scheme_by_name ("ws")->flags & TWIST_SCHEME_READY) != 0,
         "ws");
  check (twist_scheme_by_name ("wss") != NULL
         && (twist_scheme_by_name ("wss")->flags & TWIST_SCHEME_TLS) != 0
         && (twist_scheme_by_name ("wss")->flags & TWIST_SCHEME_READY) != 0,
         "wss");
  check (twist_scheme_by_name ("gopher") != NULL
         && (twist_scheme_by_name ("gopher")->flags & TWIST_SCHEME_READY) != 0,
         "gopher");
  check (twist_scheme_by_name ("gophers") != NULL
         && (twist_scheme_by_name ("gophers")->flags & TWIST_SCHEME_TLS) != 0
         && (twist_scheme_by_name ("gophers")->flags & TWIST_SCHEME_READY) != 0,
         "gophers");
  check (twist_scheme_by_name ("dict") != NULL
         && (twist_scheme_by_name ("dict")->flags & TWIST_SCHEME_READY) != 0
         && twist_scheme_by_name ("dict")->default_port == 2628,
         "dict");
  check (twist_scheme_by_name ("tftp") != NULL
         && (twist_scheme_by_name ("tftp")->flags & TWIST_SCHEME_READY) != 0
         && (twist_scheme_by_name ("tftp")->flags & TWIST_SCHEME_DATAGRAM) != 0
         && twist_scheme_by_name ("tftp")->default_port == 69,
         "tftp");
}

static void
test_proxy (void)
{
  struct twist_proxy *p;
  uint8_t *out = NULL;
  size_t len = 0;
  int ready = 0;
  static const uint8_t http[] =
    "HTTP/1.1 200 Connection Established\r\n\r\n";
  static const uint8_t greet[] = { 5, 0 };
  static const uint8_t reply[] = { 5, 0, 0, 1, 0, 0, 0, 0, 0, 0 };

  p = twist_proxy_new (TWIST_PROXY_HTTP, "127.0.0.1", 8080, NULL);
  twist_proxy_set_target (p, "example.com", 443);
  check (twist_proxy_opening (p, &out, &len) == TWIST_OK, "connect open");
  check (out != NULL && memcmp (out, "CONNECT example.com:443", 23) == 0,
         "connect line");
  free (out);
  check (twist_proxy_feed (p, http, sizeof http - 1, &ready) == TWIST_OK
         && ready == 1, "connect ready");
  twist_proxy_free (p);

  p = twist_proxy_new (TWIST_PROXY_SOCKS5, "127.0.0.1", 1080, NULL);
  twist_proxy_set_target (p, "example.com", 80);
  out = NULL;
  check (twist_proxy_opening (p, &out, &len) == TWIST_OK && len == 3
         && out[0] == 5 && out[2] == 0, "socks greet");
  free (out);
  ready = 0;
  check (twist_proxy_feed (p, greet, sizeof greet, &ready) == TWIST_OK, "socks");
  out = NULL;
  check (twist_proxy_opening (p, &out, &len) == TWIST_OK && out[0] == 5
         && out[3] == 3, "socks req");
  free (out);
  check (twist_proxy_feed (p, reply, sizeof reply, &ready) == TWIST_OK
         && ready == 1, "socks ready");
  twist_proxy_free (p);
}

static void
test_conn_pool (void)
{
  struct twist_loop *loop = twist_loop_new (1);
  struct twist_pool *pool = twist_pool_new ();
  struct twist_connection *got = NULL;
  int i;
  int n = 0;
  char key[16];

  check (loop != NULL && pool != NULL, "pool alloc");
  for (i = 0; i < 9; i++)
    {
      struct twist_connection *c = twist_connection_new (loop);

      check (c != NULL
             && twist_pool_put_idle (pool, "h", c, 1000) == TWIST_OK,
             "pool put");
    }
  while (twist_pool_take (pool, "h", &got) == TWIST_OK)
    {
      n++;
      twist_connection_free (got);
    }
  check (n == 8, "pool per-host cap");
  for (i = 0; i < 33; i++)
    {
      struct twist_connection *c = twist_connection_new (loop);

      snprintf (key, sizeof key, "k%d", i);
      check (c != NULL
             && twist_pool_put_idle (pool, key, c, 5000) == TWIST_OK,
             "pool many");
    }
  n = 0;
  for (i = 0; i < 33; i++)
    {
      snprintf (key, sizeof key, "k%d", i);
      if (twist_pool_take (pool, key, &got) == TWIST_OK)
        {
          n++;
          twist_connection_free (got);
        }
    }
  check (n == 32, "pool total cap");
  {
    struct twist_connection *c = twist_connection_new (loop);

    check (twist_pool_put_idle (pool, "old", c, 0) == TWIST_OK, "pool age put");
    twist_pool_expire (pool, 117999);
    check (twist_pool_take (pool, "old", &got) == TWIST_OK, "pool not expired");
    twist_connection_free (got);
    c = twist_connection_new (loop);
    check (twist_pool_put_idle (pool, "old", c, 0) == TWIST_OK, "pool age put 2");
    twist_pool_expire (pool, 118000);
    check (twist_pool_take (pool, "old", &got) == TWIST_ERR_AGAIN, "pool expired");
  }
  twist_pool_free (pool);
  twist_loop_free (loop);
}

static int
on_multi_socket (twist_easy *easy, int fd, int what, void *user, void *socketp)
{
  int *saw = user;

  (void) easy;
  (void) fd;
  (void) what;
  (void) socketp;
  if (saw != NULL)
    *saw = 1;
  return 0;
}

static void
test_multi_perform (void)
{
  struct twist_multi *multi = twist_multi_init ();
  int running = -1;
  int saw = 0;

  check (multi != NULL, "multi");
  check (twist_multi_perform (multi, &running) == TWIST_OK && running == 0,
         "multi perform");
  twist_multi_setopt (multi, TWISTMOPT_SOCKETDATA, &saw);
  twist_multi_setopt (multi, TWISTMOPT_SOCKETFUNCTION, on_multi_socket);
  check (saw == 1, "multi waker");
  twist_multi_cleanup (multi);
}

/* A TCP listener on the loopback that never answers.  A transfer to it
   ends by its own timeout with the connection still open.  */
static int
listen_loopback (int *port)
{
  struct sockaddr_in sin;
  socklen_t len = sizeof sin;
  int fd = socket (AF_INET, SOCK_STREAM, 0);

  if (fd < 0)
    return -1;
  memset (&sin, 0, sizeof sin);
  sin.sin_family = AF_INET;
  sin.sin_addr.s_addr = htonl (INADDR_LOOPBACK);
  if (bind (fd, (struct sockaddr *) &sin, sizeof sin) != 0
      || listen (fd, 4) != 0
      || getsockname (fd, (struct sockaddr *) &sin, &len) != 0)
    {
      close (fd);
      return -1;
    }
  fcntl (fd, F_SETFL, O_NONBLOCK);
  *port = ntohs (sin.sin_port);
  return fd;
}

static twist_easy *
timeout_easy (int port)
{
  twist_easy *easy = twist_easy_init ();
  char url[64];

  snprintf (url, sizeof url, "mqtt://127.0.0.1:%d/x", port);
  twist_easy_setopt (easy, TWISTOPT_URL, url);
  twist_easy_setopt (easy, TWISTOPT_TIMEOUT_MS, 200L);
  return easy;
}

/* The state of a transfer owns its connection, and the connection is
   released against the loop.  So the state must be released when the easy
   handle leaves the loop, not later with the handle: by then the loop is
   gone and the release reads freed memory.  */
static void
test_release_transfer (void)
{
  int port = 0;
  int fd = listen_loopback (&port);
  int peer;
  twist_easy *easy;
  twist_multi *multi;
  struct timespec nap = { 0, 5000000 };
  int running = 1;
  int i;

  check (fd >= 0, "loopback listener");
  if (fd < 0)
    return;

  /* twist_easy_perform ends the transfer with the connection open.  */
  easy = timeout_easy (port);
  check (twist_easy_perform (easy) != TWIST_OK, "perform times out");
  peer = accept (fd, NULL, NULL);
  check (peer >= 0, "the connection was open");
  if (peer >= 0)
    close (peer);
  check (easy->xfer == NULL, "perform releases the transfer state");
  twist_easy_cleanup (easy);

  /* The same through a multi handle that is removed.  */
  multi = twist_multi_init ();
  easy = timeout_easy (port);
  check (twist_multi_add_handle (multi, easy) == TWIST_OK, "add handle");
  for (i = 0; i < 400 && running > 0; i++)
    {
      twist_multi_perform (multi, &running);
      nanosleep (&nap, NULL);
    }
  check (running == 0 && easy->done, "multi transfer ended");
  check (twist_multi_remove_handle (multi, easy) == TWIST_OK, "remove handle");
  check (easy->xfer == NULL, "remove releases the transfer state");
  twist_multi_cleanup (multi);
  twist_easy_cleanup (easy);

  /* Handles still in the multi when it is cleaned up.  */
  multi = twist_multi_init ();
  easy = timeout_easy (port);
  check (twist_multi_add_handle (multi, easy) == TWIST_OK, "add handle 2");
  for (i = 0; i < 400 && running > 0; i++)
    {
      twist_multi_perform (multi, &running);
      nanosleep (&nap, NULL);
    }
  twist_multi_cleanup (multi);
  check (easy->xfer == NULL, "multi cleanup releases the transfer state");
  twist_easy_cleanup (easy);
  close (fd);
}

static void
pool_work (void *arg)
{
  (void) arg;
}

static void
pool_done (void *user, int err)
{
  (void) err;
  ++*(int *) user;
}

/* A job on the multi's storage pool whose completion is posted to its loop.
   If the multi is cleaned up before the loop has run, the completion must
   still be delivered: it owns the job and whatever the job carries, and
   dropping it with the loop leaks both.  The pool's threads are joined
   first, so every job has run and posted by then.  */
static void
test_pool_completion_at_cleanup (void)
{
  struct twist_multi *multi = twist_multi_init ();
  int done = 0, i;

  check (multi != NULL, "multi");
  for (i = 0; i < 5; i++)
    check (twist_storage_submit (multi->storage, pool_work, NULL, pool_done,
                                 &done, multi->loop) == TWIST_OK, "submit");
  twist_multi_cleanup (multi);
  check (done == 5, "completions posted before cleanup are delivered");
}

int
main (void)
{
  test_url ();
  test_scheme ();
  test_proxy ();
  test_conn_pool ();
  test_multi_perform ();
  test_release_transfer ();
  test_pool_completion_at_cleanup ();
  return tests_finish ();
}
