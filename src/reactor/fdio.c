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

#include "twist-int.h"

#include <errno.h>
#include <limits.h>
#include <poll.h>
#include <stdlib.h>
#include <unistd.h>

/* Descriptors that can be waited for (see twist-int.h).  Each is a connection
   on a duplicate of the descriptor, whose reads and writes are made only after
   a poll with no timeout has said they will not wait.  */

static int
poll_now (int fd, short events, short *revents)
{
  struct pollfd p;
  int r;

  p.fd = fd;
  p.events = events;
  p.revents = 0;
  do
    r = poll (&p, 1, 0);
  while (r < 0 && errno == EINTR);
  *revents = p.revents;
  return r;
}

ssize_t
twist_fd_read_nowait (int fd, uint8_t *buf, size_t len)
{
  short rev;
  int r = poll_now (fd, POLLIN, &rev);
  ssize_t n;

  if (r < 0)
    return -1;
  if (r == 0)
    {
      errno = EAGAIN;
      return -1;
    }
  do
    n = read (fd, buf, len);
  while (n < 0 && errno == EINTR);
  return n;
}

ssize_t
twist_fd_write_nowait (int fd, const uint8_t *data, size_t len)
{
  short rev;
  int r = poll_now (fd, POLLOUT, &rev);
  ssize_t n;

  if (r < 0)
    return -1;
  if (r == 0)
    {
      errno = EAGAIN;
      return -1;
    }
  /* The reader has gone: a write would raise SIGPIPE.  */
  if ((rev & (POLLERR | POLLHUP | POLLNVAL)) != 0 && (rev & POLLOUT) == 0)
    {
      errno = EPIPE;
      return -1;
    }
  if ((rev & (POLLERR | POLLNVAL)) != 0)
    {
      errno = EPIPE;
      return -1;
    }
  if (len > PIPE_BUF)
    len = PIPE_BUF;
  do
    n = write (fd, data, len);
  while (n < 0 && errno == EINTR);
  return n;
}

/* ---- source ---- */

struct twist_fd_source
{
  struct twist_connection *conn;
  struct twist_fd_source_ops ops;
  void *user;
  int fd;
  int setup;
  int failed;
  int ended;
};

static ssize_t
source_read (void *user, uint8_t *buf, size_t len)
{
  struct twist_fd_source *s = user;

  return twist_fd_read_nowait (s->fd, buf, len);
}

static size_t
source_receive (struct twist_endpoint *ep, const uint8_t *data, size_t len)
{
  struct twist_fd_source *s = ep->user_data;
  size_t n = s->ops.chunk (s->user, data, len);

  if (n > len)
    n = len;
  if (n < len)
    twist_endpoint_pause_read (ep);
  return n;
}

static void
source_error (struct twist_endpoint *ep, int err)
{
  struct twist_fd_source *s = ep->user_data;

  if (s->setup)
    {
      s->failed = 1;
      return;
    }
  if (s->ended)
    return;
  s->ended = 1;
  s->ops.end (s->user, err == TWIST_ERR_CLOSED ? TWIST_OK : err);
}

static const struct twist_protocol_handler source_handler = {
  NULL, source_receive, NULL, NULL, source_error, NULL, NULL
};

int
twist_fd_source_new (struct twist_loop *loop, int fd,
                     const struct twist_fd_source_ops *ops, void *user,
                     struct twist_fd_source **out)
{
  struct twist_fd_source *s;
  int dfd;

  *out = NULL;
  if (loop == NULL || fd < 0 || ops == NULL || ops->chunk == NULL
      || ops->end == NULL)
    return TWIST_ERR_INVAL;
  dfd = dup (fd);
  if (dfd < 0)
    return TWIST_ERR_INVAL;
  s = calloc (1, sizeof *s);
  if (s == NULL)
    {
      close (dfd);
      return TWIST_ERR_NOMEM;
    }
  s->conn = twist_connection_new (loop);
  if (s->conn == NULL)
    {
      close (dfd);
      free (s);
      return TWIST_ERR_NOMEM;
    }
  s->ops = *ops;
  s->user = user;
  s->fd = dfd;
  twist_connection_endpoint (s->conn)->user_data = s;
  twist_connection_set_handler (s->conn, &source_handler);
  twist_connection_set_io (s->conn, source_read, NULL, s);
  /* A descriptor that cannot be watched, such as a regular file, is refused
     here, and the caller reads it another way.  */
  s->setup = 1;
  twist_connection_set_fd (s->conn, dfd);
  s->setup = 0;
  if (s->failed)
    {
      twist_connection_free (s->conn);
      free (s);
      return TWIST_ERR_CONNECT;
    }
  *out = s;
  return TWIST_OK;
}

void
twist_fd_source_pause (struct twist_fd_source *s)
{
  if (s != NULL)
    twist_endpoint_pause_read (twist_connection_endpoint (s->conn));
}

void
twist_fd_source_resume (struct twist_fd_source *s)
{
  if (s != NULL)
    twist_endpoint_resume_read (twist_connection_endpoint (s->conn));
}

void
twist_fd_source_free (struct twist_fd_source *s)
{
  if (s == NULL)
    return;
  twist_connection_free (s->conn);
  free (s);
}

/* ---- sink ---- */

struct twist_fd_sink
{
  struct twist_connection *conn;
  struct twist_endpoint *ep;
  struct twist_fd_sink_ops ops;
  void *user;
  int fd;
  int setup;
  int failed;
  int errored;
};

static ssize_t
sink_read (void *user, uint8_t *buf, size_t len)
{
  (void) user;
  (void) buf;
  (void) len;
  errno = EAGAIN;
  return -1;
}

static ssize_t
sink_write (void *user, const uint8_t *buf, size_t len)
{
  struct twist_fd_sink *s = user;

  return twist_fd_write_nowait (s->fd, buf, len);
}

static void
sink_error (struct twist_endpoint *ep, int err)
{
  struct twist_fd_sink *s = ep->user_data;

  if (s->setup)
    {
      s->failed = 1;
      return;
    }
  if (s->errored)
    return;
  s->errored = 1;
  if (s->ops.error != NULL)
    s->ops.error (s->user, err);
}

static void
sink_ready (struct twist_endpoint *ep)
{
  struct twist_fd_sink *s = ep->user_data;

  if (s->ops.ready != NULL)
    s->ops.ready (s->user);
}

static const struct twist_protocol_handler sink_handler = {
  NULL, NULL, NULL, NULL, sink_error, NULL, NULL
};

int
twist_fd_sink_new (struct twist_loop *loop, int fd,
                   const struct twist_fd_sink_ops *ops, void *user,
                   struct twist_fd_sink **out)
{
  struct twist_fd_sink *s;
  int dfd;

  *out = NULL;
  if (loop == NULL || fd < 0 || ops == NULL)
    return TWIST_ERR_INVAL;
  dfd = dup (fd);
  if (dfd < 0)
    return TWIST_ERR_INVAL;
  s = calloc (1, sizeof *s);
  if (s == NULL)
    {
      close (dfd);
      return TWIST_ERR_NOMEM;
    }
  s->conn = twist_connection_new (loop);
  if (s->conn == NULL)
    {
      close (dfd);
      free (s);
      return TWIST_ERR_NOMEM;
    }
  s->ops = *ops;
  s->user = user;
  s->fd = dfd;
  s->ep = twist_connection_endpoint (s->conn);
  s->ep->user_data = s;
  s->ep->on_write_ready = sink_ready;
  twist_connection_set_handler (s->conn, &sink_handler);
  twist_connection_set_io (s->conn, sink_read, sink_write, s);
  /* The descriptor is written to and not read: the reading end of a pipe is
     someone else's.  */
  twist_connection_hold_read (s->conn, 1);
  s->setup = 1;
  twist_connection_set_fd (s->conn, dfd);
  s->setup = 0;
  if (s->failed)
    {
      twist_connection_free (s->conn);
      free (s);
      return TWIST_ERR_CONNECT;
    }
  *out = s;
  return TWIST_OK;
}

int
twist_fd_sink_write (struct twist_fd_sink *s, const uint8_t *data, size_t len)
{
  if (s == NULL || s->errored)
    return TWIST_ERR_INVAL;
  return twist_connection_send_body (s->conn, data, len);
}

int
twist_fd_sink_full (const struct twist_fd_sink *s)
{
  return s != NULL && twist_endpoint_full (s->ep);
}

size_t
twist_fd_sink_pending (const struct twist_fd_sink *s)
{
  return s != NULL ? twist_endpoint_pending (s->ep) : 0;
}

void
twist_fd_sink_free (struct twist_fd_sink *s)
{
  if (s == NULL)
    return;
  twist_connection_free (s->conn);
  free (s);
}
