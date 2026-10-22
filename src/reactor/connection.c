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
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <sys/types.h>

struct twist_connection
{
  struct twist_endpoint ep;
  struct twist_loop *loop;
  int fd;
  int interest;
  int paused;
  int connecting;
  int closing;
  int failed;
  int hold_read;
  int force_write;
  int in_pool;
  struct twist_protocol_handler handler;
  ssize_t (*read_fn) (void *, uint8_t *, size_t);
  ssize_t (*write_fn) (void *, const uint8_t *, size_t);
  void *io_user;
  uint8_t *inbuf;
  size_t in_off;
  size_t in_len;
  size_t in_cap;
  uint8_t *outbuf;
  size_t out_off;
  size_t out_len;
  size_t out_cap;
  uint8_t *app;
  size_t app_off;
  size_t app_len;
  size_t app_cap;
  void *tls;
  void (*free_tls) (void *);
  char alpn[32];
  size_t alpn_len;
  struct twist_timer *connect_timer;
};

int (*twist_tls_start_fn) (struct twist_connection *,
                           const struct twist_tls_want *);
int (*twist_tls_receive_fn) (struct twist_connection *, const uint8_t *,
                             size_t);
int (*twist_quic_connect_fn) (struct twist_easy *, struct twist_connection **);

int twist_connection_send_plain (struct twist_connection *c,
                                const uint8_t *data, size_t len);

static ssize_t
default_read (void *user, uint8_t *buf, size_t len)
{
  struct twist_connection *c = user;
  return read (c->fd, buf, len);
}

static ssize_t
default_write (void *user, const uint8_t *buf, size_t len)
{
  struct twist_connection *c = user;
  return write (c->fd, buf, len);
}

static size_t
pending_in (const struct twist_connection *c)
{
  if (c->tls != NULL)
    return c->app_len;
  return c->in_len;
}

static void
refresh_interest (struct twist_connection *c)
{
  int want = 0;

  if (!c->paused && !c->closing && !c->hold_read
      && pending_in (c) < TWIST_IN_CEILING && c->fd >= 0)
    want |= TWIST_INTEREST_READ;
  if ((c->out_len > 0 || c->connecting || c->force_write) && c->fd >= 0)
    want |= TWIST_INTEREST_WRITE;
  if (want != c->interest)
    {
      c->interest = want;
      twist_loop_watch_fd (c->loop, c->fd, want, c);
    }
}

void
twist_connection_hold_read (struct twist_connection *c, int hold)
{
  if (c == NULL || c->hold_read == hold)
    return;
  c->hold_read = hold;
  refresh_interest (c);
}

void
twist_connection_force_write (struct twist_connection *c, int force)
{
  if (c == NULL || c->force_write == force)
    return;
  c->force_write = force;
  refresh_interest (c);
}

static void
compact_buf (uint8_t *buf, size_t *off, size_t len)
{
  if (buf != NULL && *off > 0 && len > 0)
    memmove (buf, buf + *off, len);
  *off = 0;
}

static int
ensure_buf (uint8_t **buf, size_t *off, size_t len, size_t *cap, size_t extra)
{
  if (*off > 0
      && ((*cap > 0 && *off >= *cap / 2) || *off + len + extra > *cap))
    compact_buf (*buf, off, len);
  if (*off + len + extra > *cap)
    {
      size_t ncap = *cap == 0 ? 4096 : *cap;
      uint8_t *p;

      while (ncap < *off + len + extra)
        ncap *= 2;
      p = realloc (*buf, ncap);
      if (p == NULL)
        return TWIST_ERR_NOMEM;
      *buf = p;
      *cap = ncap;
    }
  return TWIST_OK;
}

static int
append_buf (uint8_t **buf, size_t *off, size_t *len, size_t *cap,
            const uint8_t *data, size_t n)
{
  if (ensure_buf (buf, off, *len, cap, n) != TWIST_OK)
    return TWIST_ERR_NOMEM;
  if (n > 0 && data != NULL)
    memcpy (*buf + *off + *len, data, n);
  *len += n;
  return TWIST_OK;
}

static void
deliver (struct twist_connection *c, uint8_t **buf, size_t *off, size_t *len,
         size_t *cap)
{
  while (*len > 0 && c->handler.receive != NULL && !c->paused)
    {
      size_t n = c->handler.receive (&c->ep, *buf + *off, *len);

      if (n == 0)
        break;
      if (n > *len)
        n = *len;
      *off += n;
      *len -= n;
    }
  if (*len == 0)
    *off = 0;
  else if (*off > 0 && *cap > 0 && *off >= *cap / 2)
    compact_buf (*buf, off, *len);
}

/* Append and parse, never holding more than TWIST_IN_CEILING unconsumed
   bytes.  A handler that needs more input leaves a short tail and returns.
   A handler that cannot take more calls pause.  A full buffer that the
   handler did not pause on cannot make progress: fail it.  */
static void
feed_buf (struct twist_connection *c, uint8_t **buf, size_t *boff, size_t *len,
          size_t *cap, const uint8_t *data, size_t n)
{
  size_t off = 0;

  while (off < n && !c->failed && !c->paused)
    {
      size_t room;
      size_t take;
      size_t before;

      if (*len >= TWIST_IN_CEILING)
        {
          twist_connection_fail (c, TWIST_ERR_PROTOCOL);
          return;
        }
      room = TWIST_IN_CEILING - *len;
      take = n - off;
      if (take > room)
        take = room;
      before = *len;
      if (append_buf (buf, boff, len, cap, data + off, take) != TWIST_OK)
        {
          twist_connection_fail (c, TWIST_ERR_NOMEM);
          return;
        }
      off += take;
      deliver (c, buf, boff, len, cap);
      if (c->failed || c->paused)
        return;
      if (*len > before && *len >= TWIST_IN_CEILING)
        {
          twist_connection_fail (c, TWIST_ERR_PROTOCOL);
          return;
        }
    }
}

static int
tcp_send (struct twist_endpoint *ep, const uint8_t *data, size_t len)
{
  struct twist_connection *c = ep->conn;

  if (c->tls != NULL)
    return twist_connection_send_plain (c, data, len);
  if (twist_connection_queue_out (c, data, len) != TWIST_OK)
    return TWIST_ERR_NOMEM;
  refresh_interest (c);
  twist_connection_on_writable (c);
  return TWIST_OK;
}

int (*twist_tls_send_plain_fn) (struct twist_connection *, const uint8_t *,
                                size_t);

int
twist_connection_send_plain (struct twist_connection *c, const uint8_t *data,
                             size_t len)
{
  if (twist_tls_send_plain_fn == NULL)
    return TWIST_ERR_UNSUPPORTED;
  return twist_tls_send_plain_fn (c, data, len);
}

static void
tcp_close (struct twist_endpoint *ep)
{
  struct twist_connection *c = ep->conn;
  c->closing = 1;
  refresh_interest (c);
  if (c->out_len == 0)
    twist_connection_fail (c, TWIST_OK);
}

static void
tcp_pause (struct twist_endpoint *ep)
{
  ep->conn->paused = 1;
  refresh_interest (ep->conn);
}

static void
tcp_resume (struct twist_endpoint *ep)
{
  ep->conn->paused = 0;
  refresh_interest (ep->conn);
  deliver (ep->conn, &ep->conn->inbuf, &ep->conn->in_off, &ep->conn->in_len,
           &ep->conn->in_cap);
  if (ep->conn->app_len > 0)
    deliver (ep->conn, &ep->conn->app, &ep->conn->app_off, &ep->conn->app_len,
             &ep->conn->app_cap);
}

struct twist_connection *
twist_connection_new (struct twist_loop *loop)
{
  struct twist_connection *c;

  c = calloc (1, sizeof *c);
  if (c == NULL)
    return NULL;
  c->loop = loop;
  c->fd = -1;
  c->ep.conn = c;
  c->ep.send = tcp_send;
  c->ep.close_fn = tcp_close;
  c->ep.pause_read = tcp_pause;
  c->ep.resume_read = tcp_resume;
  c->read_fn = default_read;
  c->write_fn = default_write;
  c->io_user = c;
  return c;
}

void
twist_connection_free (struct twist_connection *c)
{
  if (c == NULL)
    return;
  if (c->fd >= 0)
    {
      twist_loop_unwatch_fd (c->loop, c->fd);
      close (c->fd);
    }
  if (c->connect_timer != NULL)
    twist_timer_cancel (c->connect_timer);
  if (c->free_tls != NULL && c->tls != NULL)
    c->free_tls (c->tls);
  if (c->in_pool && c->inbuf != NULL && c->in_cap == 16384)
    twist_loop_give_rbuf (c->loop, c->inbuf);
  else
    free (c->inbuf);
  free (c->outbuf);
  free (c->app);
  free (c);
}

struct twist_endpoint *
twist_connection_endpoint (struct twist_connection *c)
{
  return &c->ep;
}

void
twist_connection_set_handler (struct twist_connection *c,
                              const struct twist_protocol_handler *h)
{
  if (h != NULL)
    c->handler = *h;
  else
    memset (&c->handler, 0, sizeof c->handler);
}

void
twist_connection_set_fd (struct twist_connection *c, int fd)
{
  c->fd = fd;
  refresh_interest (c);
}

void
twist_connection_set_io (struct twist_connection *c,
                         ssize_t (*read_fn) (void *, uint8_t *, size_t),
                         ssize_t (*write_fn) (void *, const uint8_t *, size_t),
                         void *user)
{
  c->read_fn = read_fn != NULL ? read_fn : default_read;
  c->write_fn = write_fn != NULL ? write_fn : default_write;
  c->io_user = user != NULL ? user : c;
}

void
twist_connection_set_tls (struct twist_connection *c, void *tls,
                          void (*free_tls) (void *))
{
  c->tls = tls;
  c->free_tls = free_tls;
}

void *
twist_connection_tls (struct twist_connection *c)
{
  return c->tls;
}

void
twist_connection_set_alpn (struct twist_connection *c, const char *alpn,
                           size_t len)
{
  if (len >= sizeof c->alpn)
    len = sizeof c->alpn - 1;
  if (alpn != NULL && len > 0)
    memcpy (c->alpn, alpn, len);
  c->alpn[len] = 0;
  c->alpn_len = len;
  /* With no protocol too: that the handshake is done is what is told.  */
  if (c->handler.security_established != NULL)
    c->handler.security_established (&c->ep, c->alpn, c->alpn_len);
}

const char *
twist_connection_alpn (struct twist_connection *c, size_t *len)
{
  if (len != NULL)
    *len = c->alpn_len;
  return c->alpn;
}

void
twist_connection_read_finished (struct twist_connection *c)
{
  if (c != NULL && c->handler.read_finished != NULL)
    c->handler.read_finished (&c->ep);
}

int
twist_connection_send_parts (struct twist_connection *c, const uint8_t *a,
                             size_t an, const uint8_t *b, size_t bn)
{
  if (c == NULL)
    return TWIST_ERR_INVAL;
  if (c->tls != NULL)
    {
      if (an > 0 && tcp_send (&c->ep, a, an) != TWIST_OK)
        return TWIST_ERR_NOMEM;
      if (bn > 0 && tcp_send (&c->ep, b, bn) != TWIST_OK)
        return TWIST_ERR_NOMEM;
      return TWIST_OK;
    }
  if (an > 0
      && append_buf (&c->outbuf, &c->out_off, &c->out_len, &c->out_cap, a, an)
         != TWIST_OK)
    return TWIST_ERR_NOMEM;
  if (bn > 0
      && append_buf (&c->outbuf, &c->out_off, &c->out_len, &c->out_cap, b, bn)
         != TWIST_OK)
    return TWIST_ERR_NOMEM;
  refresh_interest (c);
  twist_connection_on_writable (c);
  return TWIST_OK;
}

int
twist_connection_queue_out (struct twist_connection *c, const uint8_t *data,
                            size_t len)
{
  int rc = append_buf (&c->outbuf, &c->out_off, &c->out_len, &c->out_cap,
                       data, len);
  if (rc == TWIST_OK)
    refresh_interest (c);
  return rc;
}

void
twist_connection_deliver_app (struct twist_connection *c, const uint8_t *data,
                              size_t len)
{
  feed_buf (c, &c->app, &c->app_off, &c->app_len, &c->app_cap, data, len);
  refresh_interest (c);
}

void
twist_connection_ingest (struct twist_connection *c, const uint8_t *data,
                         size_t len)
{
  if (c->tls != NULL && twist_tls_receive_fn != NULL)
    {
      if (twist_tls_receive_fn (c, data, len) != TWIST_OK)
        twist_connection_fail (c, TWIST_ERR_TLS);
      return;
    }
  feed_buf (c, &c->inbuf, &c->in_off, &c->in_len, &c->in_cap, data, len);
  refresh_interest (c);
}

void
twist_connection_fail (struct twist_connection *c, int err)
{
  if (c->failed)
    return;
  c->failed = 1;
  c->closing = 1;
  if (err != TWIST_OK && c->handler.error != NULL)
    c->handler.error (&c->ep, err);
  if (c->handler.disconnected != NULL)
    c->handler.disconnected (&c->ep, err);
}

void
twist_connection_connected (struct twist_connection *c)
{
  c->connecting = 0;
  if (c->connect_timer != NULL)
    {
      twist_timer_cancel (c->connect_timer);
      c->connect_timer = NULL;
    }
  refresh_interest (c);
  if (c->handler.connected != NULL)
    c->handler.connected (&c->ep);
}

static void
connect_timeout (void *user)
{
  struct twist_connection *c = user;
  c->connect_timer = NULL;
  twist_connection_fail (c, TWIST_ERR_TIMEOUT);
}

int
twist_connection_connect (struct twist_connection *c, const void *addr,
                          size_t addrlen, uint64_t timeout_ms)
{
  int fd;
  int rc;
  const struct sockaddr *sa = addr;

  fd = socket (sa->sa_family, SOCK_STREAM, 0);
  if (fd < 0)
    return TWIST_ERR_CONNECT;
  if (fcntl (fd, F_SETFL, O_NONBLOCK) < 0
      || fcntl (fd, F_SETFD, FD_CLOEXEC) < 0)
    {
      close (fd);
      return TWIST_ERR_CONNECT;
    }
  {
    int one = 1;

    setsockopt (fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
  }
  rc = connect (fd, sa, (socklen_t) addrlen);
  c->fd = fd;
  if (rc == 0)
    {
      twist_connection_connected (c);
      return TWIST_OK;
    }
  if (errno != EINPROGRESS)
    {
      close (fd);
      c->fd = -1;
      return TWIST_ERR_CONNECT;
    }
  c->connecting = 1;
  refresh_interest (c);
  if (timeout_ms > 0)
    twist_loop_schedule (c->loop, twist_loop_now (c->loop) + timeout_ms,
                         connect_timeout, c, &c->connect_timer);
  return TWIST_OK;
}

void
twist_connection_on_readable (struct twist_connection *c)
{
  uint8_t tlsbuf[16384];

  if (c->connecting)
    return;
  for (;;)
    {
      size_t room;
      ssize_t n;
      uint8_t *dst;

      if (c->paused || c->closing || c->failed)
        break;
      if (pending_in (c) >= TWIST_IN_CEILING)
        break;
      room = TWIST_IN_CEILING - pending_in (c);
      if (room > 16384)
        room = 16384;
      if (c->tls != NULL)
        dst = tlsbuf;
      else
        {
          if (c->inbuf == NULL)
            {
              c->inbuf = twist_loop_take_rbuf (c->loop);
              if (c->inbuf != NULL)
                {
                  c->in_cap = 16384;
                  c->in_pool = 1;
                }
            }
          if (ensure_buf (&c->inbuf, &c->in_off, c->in_len, &c->in_cap, room)
              != TWIST_OK)
            {
              twist_connection_fail (c, TWIST_ERR_NOMEM);
              break;
            }
          dst = c->inbuf + c->in_off + c->in_len;
        }
      n = c->read_fn (c->io_user, dst, room);
      if (n > 0 && c->tls == NULL)
        {
          c->in_len += (size_t) n;
          deliver (c, &c->inbuf, &c->in_off, &c->in_len, &c->in_cap);
          refresh_interest (c);
        }
      else if (n > 0)
        twist_connection_ingest (c, tlsbuf, (size_t) n);
      else if (n == 0)
        {
          twist_connection_fail (c, TWIST_ERR_CLOSED);
          break;
        }
      else if (errno == EAGAIN || errno == EWOULDBLOCK)
        break;
      else
        {
          twist_connection_fail (c, TWIST_ERR_CONNECT);
          break;
        }
      if (c->closing)
        break;
    }
}

void
twist_connection_on_writable (struct twist_connection *c)
{
  if (c->connecting)
    {
      int err = 0;
      socklen_t len = sizeof err;
      if (getsockopt (c->fd, SOL_SOCKET, SO_ERROR, &err, &len) < 0 || err != 0)
        {
          twist_connection_fail (c, TWIST_ERR_CONNECT);
          return;
        }
      twist_connection_connected (c);
    }
  while (c->out_len > 0)
    {
      ssize_t n = c->write_fn (c->io_user, c->outbuf + c->out_off, c->out_len);
      if (n > 0)
        {
          c->out_off += (size_t) n;
          c->out_len -= (size_t) n;
          if (c->out_len == 0)
            c->out_off = 0;
          else if (c->out_cap > 0 && c->out_off >= c->out_cap / 2)
            compact_buf (c->outbuf, &c->out_off, c->out_len);
        }
      else if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
        break;
      else
        {
          twist_connection_fail (c, TWIST_ERR_CONNECT);
          return;
        }
    }
  if (c->out_len == 0 && c->ep.on_write_ready != NULL)
    c->ep.on_write_ready (&c->ep);
  refresh_interest (c);
  if (c->closing && c->out_len == 0)
    twist_connection_fail (c, TWIST_OK);
}

int
twist_endpoint_send (struct twist_endpoint *ep, const uint8_t *data,
                     size_t len)
{
  if (ep == NULL || ep->send == NULL)
    return TWIST_ERR_INVAL;
  return ep->send (ep, data, len);
}

void
twist_endpoint_close (struct twist_endpoint *ep)
{
  if (ep != NULL && ep->close_fn != NULL)
    ep->close_fn (ep);
}

void
twist_endpoint_pause_read (struct twist_endpoint *ep)
{
  if (ep != NULL && ep->pause_read != NULL)
    ep->pause_read (ep);
}

void
twist_endpoint_resume_read (struct twist_endpoint *ep)
{
  if (ep != NULL && ep->resume_read != NULL)
    ep->resume_read (ep);
}

struct twist_loop *
twist_endpoint_loop (struct twist_endpoint *ep)
{
  return ep->conn->loop;
}

int
twist_connection_start_tls (struct twist_connection *c, const char *server_name,
                            int verify, const char *const *alpn, size_t n_alpn,
                            const char *cafile, const char *capath,
                            const char *certfile, const char *keyfile)
{
  struct twist_tls_want want;

  if (twist_tls_start_fn == NULL)
    return TWIST_ERR_UNSUPPORTED;
  memset (&want, 0, sizeof want);
  want.server_name = server_name;
  want.verify = verify;
  want.alpn = alpn;
  want.n_alpn = n_alpn;
  want.cafile = cafile;
  want.capath = capath;
  want.certfile = certfile;
  want.keyfile = keyfile;
  return twist_tls_start_fn (c, &want);
}
