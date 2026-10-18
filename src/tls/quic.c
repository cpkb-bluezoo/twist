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

#include <quickstep/endpoint.h>
#include <quickstep/status.h>
#include <quickstep/trust.h>

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

struct twist_quic
{
  struct twist_connection *twist;
  struct twist_loop *loop;
  gq_endpoint *ep;
  gq_conn *conn;
  gq_trust *trust;
  struct twist_client_auth *auth;
  gq_tls_config tls;
  gq_slice alpn;
  uint8_t alpn_mem[2];
  char *server_name;
  int fd;
  uint64_t stream_id;
  int have_stream;
  int hold_stream;
  gq_path path;
};

static int quic_flush (struct twist_quic *q, uint64_t now_us);

static int
ep_accept (void *user, const gq_path *from, gq_conn_events *events)
{
  (void) user;
  (void) from;
  (void) events;
  return -1;
}

static void
ep_connection (void *user, gq_conn *conn)
{
  (void) user;
  (void) conn;
}

static void
ev_connected (void *user, const gq_tls_info *info)
{
  struct twist_quic *q = user;
  uint64_t id = 0;

  if (twist_client_auth_missing (info))
    {
      gq_conn_close (q->conn, twist_loop_now (q->loop) * 1000u, 1, 1, NULL);
      twist_connection_fail (q->twist, TWIST_ERR_TLS);
      return;
    }
  if (gq_conn_stream_open (q->conn, 1, &id) == GQ_OK)
    {
      q->stream_id = id;
      q->have_stream = 1;
    }
  if (info != NULL)
    twist_connection_set_alpn (q->twist, (const char *) info->alpn,
                               info->alpn_len);
}

static void
ev_stream_opened (void *user, uint64_t id)
{
  (void) user;
  (void) id;
}

static int
ev_stream_data (void *user, uint64_t id, const uint8_t *data, size_t len,
                int fin)
{
  struct twist_quic *q = user;

  (void) id;
  if (len > 0)
    twist_connection_deliver_app (q->twist, data, len);
  if (fin)
    twist_connection_read_finished (q->twist);
  return 0;
}

static void
ev_stream_reset (void *user, uint64_t id, uint64_t error)
{
  (void) id;
  (void) error;
  twist_connection_fail (((struct twist_quic *) user)->twist, TWIST_ERR_PROTOCOL);
}

static void
ev_stream_stopped (void *user, uint64_t id, uint64_t error)
{
  (void) user;
  (void) id;
  (void) error;
}

static void
ev_stream_writable (void *user, uint64_t id)
{
  (void) user;
  (void) id;
}

static void
ev_stream_closed (void *user, uint64_t id)
{
  (void) user;
  (void) id;
}

static void
ev_closed (void *user, const gq_conn_close_info *info)
{
  struct twist_quic *q = user;
  int err = TWIST_OK;

  if (info != NULL && info->error != 0)
    err = TWIST_ERR_TLS;
  twist_connection_fail (q->twist, err);
}

static void
ev_cid_issued (void *user, const uint8_t *cid, size_t len,
               const uint8_t token[16])
{
  (void) user;
  (void) cid;
  (void) len;
  (void) token;
}

static void
ev_cid_retired (void *user, const uint8_t *cid, size_t len)
{
  (void) user;
  (void) cid;
  (void) len;
}

static void
ev_datagram (void *user, const uint8_t *data, size_t len)
{
  struct twist_endpoint *ep;

  (void) data;
  (void) len;
  ep = twist_connection_endpoint (((struct twist_quic *) user)->twist);
  if (ep != NULL)
    {
      /* Datagrams are delivered when a handler asked for them.  */
    }
  (void) ep;
}

static void
ev_datagram_id (void *user, uint64_t id)
{
  (void) user;
  (void) id;
}

static void
ev_path (void *user, const gq_path *path)
{
  (void) user;
  (void) path;
}

static void
ev_preferred (void *user, const gq_preferred_address *pa)
{
  (void) user;
  (void) pa;
}

static void
ev_early (void *user, int accepted)
{
  (void) user;
  (void) accepted;
}

static void
ev_token (void *user, const uint8_t *token, size_t len)
{
  (void) user;
  (void) token;
  (void) len;
}

static void
ev_ticket (void *user, const gq_tls_ticket *ticket, uint32_t version)
{
  (void) user;
  (void) ticket;
  (void) version;
}

static int
quic_flush (struct twist_quic *q, uint64_t now_us)
{
  for (;;)
    {
      uint8_t buf[2048];
      size_t len = 0;
      gq_path to;
      ssize_t n;

      if (gq_endpoint_send (q->ep, now_us, buf, sizeof buf, &len, &to) != GQ_OK)
        return TWIST_ERR_TLS;
      if (len == 0)
        return TWIST_OK;
      n = send (q->fd, buf, len, 0);
      if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK)
        return TWIST_ERR_CONNECT;
    }
}

static uint64_t
quic_deadline (void *user, uint64_t now_us)
{
  struct twist_quic *q = user;

  (void) now_us;
  if (q->ep == NULL)
    return 0;
  return gq_endpoint_timeout (q->ep);
}

static void
quic_fire (void *user, uint64_t now_us)
{
  struct twist_quic *q = user;

  if (q->ep == NULL)
    return;
  gq_endpoint_on_timeout (q->ep, now_us);
  quic_flush (q, now_us);
}

static ssize_t
quic_read (void *user, uint8_t *buf, size_t len)
{
  struct twist_quic *q = user;
  ssize_t n;
  uint64_t now;

  n = recv (q->fd, buf, len, 0);
  if (n < 0)
    return -1;
  now = twist_loop_now (q->loop) * 1000u;
  if (n > 0)
    gq_endpoint_recv (q->ep, now, &q->path, buf, (size_t) n);
  quic_flush (q, now);
  errno = EAGAIN;
  return -1;
}

static ssize_t
quic_write (void *user, const uint8_t *buf, size_t len)
{
  (void) user;
  (void) buf;
  (void) len;
  errno = EAGAIN;
  return -1;
}

static int
quic_app_send (struct twist_endpoint *ep, const uint8_t *data, size_t len)
{
  struct twist_quic *q = twist_connection_tls (ep->conn);
  long n;
  uint64_t now;

  if (q == NULL || !q->have_stream)
    return TWIST_ERR_AGAIN;
  n = gq_conn_stream_write (q->conn, q->stream_id, data, len);
  if (n < 0)
    return TWIST_ERR_TLS;
  /* Extended CONNECT keeps the stream open for later WebSocket
     frames.  A normal request finishes it with this write.  */
  if (q->hold_stream)
    {
      if (n != (long) len)
        return TWIST_ERR_TLS;
    }
  else if (gq_conn_stream_finish (q->conn, q->stream_id) != GQ_OK)
    return TWIST_ERR_TLS;
  now = twist_loop_now (q->loop) * 1000u;
  return quic_flush (q, now);
}

void
twist_quic_hold_stream (struct twist_connection *conn)
{
  struct twist_quic *q = twist_connection_tls (conn);

  if (q != NULL)
    q->hold_stream = 1;
}

int
twist_quic_finish_stream (struct twist_connection *conn)
{
  struct twist_quic *q = twist_connection_tls (conn);
  uint64_t now;

  if (q == NULL || !q->hold_stream)
    return TWIST_OK;
  q->hold_stream = 0;
  if (!q->have_stream || q->conn == NULL)
    return TWIST_OK;
  if (gq_conn_stream_finish (q->conn, q->stream_id) != GQ_OK)
    return TWIST_ERR_TLS;
  now = twist_loop_now (q->loop) * 1000u;
  return quic_flush (q, now);
}

static void
quic_free (void *p)
{
  struct twist_quic *q = p;

  if (q == NULL)
    return;
  gq_endpoint_free (q->ep);
  gq_trust_free (q->trust);
  twist_client_auth_free (q->auth);
  free (q->server_name);
  free (q);
}

static void
fill_events (gq_conn_events *ev, struct twist_quic *q)
{
  memset (ev, 0, sizeof *ev);
  ev->user = q;
  ev->connected = ev_connected;
  ev->stream_opened = ev_stream_opened;
  ev->stream_data = ev_stream_data;
  ev->stream_reset = ev_stream_reset;
  ev->stream_stopped = ev_stream_stopped;
  ev->stream_writable = ev_stream_writable;
  ev->stream_closed = ev_stream_closed;
  ev->closed = ev_closed;
  ev->cid_issued = ev_cid_issued;
  ev->cid_retired = ev_cid_retired;
  ev->datagram = ev_datagram;
  ev->datagram_acked = ev_datagram_id;
  ev->datagram_lost = ev_datagram_id;
  ev->path_validated = ev_path;
  ev->path_failed = ev_path;
  ev->migrated = ev_path;
  ev->preferred_address = ev_preferred;
  ev->early_data_result = ev_early;
  ev->new_token = ev_token;
  ev->ticket = ev_ticket;
}

static int
quic_connect (struct twist_easy *easy, struct twist_connection **out)
{
  struct twist_quic *q;
  gq_endpoint_config ecfg;
  gq_endpoint_events eev;
  gq_conn_events cev;
  struct sockaddr_storage ss;
  socklen_t slen = sizeof ss;
  struct twist_dns_addr addr;
  int family;
  int fd = -1;
  int rc;
  uint64_t now;

  if (easy == NULL || easy->url == NULL || easy->loop == NULL || out == NULL)
    return TWIST_ERR_INVAL;
  *out = NULL;
  q = calloc (1, sizeof *q);
  if (q == NULL)
    return TWIST_ERR_NOMEM;
  q->loop = easy->loop;
  q->fd = -1;
  q->server_name = twist_strdup (easy->url->host);
  q->alpn_mem[0] = 'h';
  q->alpn_mem[1] = '3';
  q->alpn.data = q->alpn_mem;
  q->alpn.len = 2;
  if (gq_trust_new (&q->trust) != GQ_OK)
    {
      quic_free (q);
      return TWIST_ERR_TLS;
    }
  if (easy->cainfo != NULL)
    gq_trust_add_pem_file (q->trust, easy->cainfo);
  else
    gq_trust_add_system (q->trust, NULL);
  memset (&q->tls, 0, sizeof q->tls);
  q->tls.server_name = q->server_name;
  q->tls.alpn = &q->alpn;
  q->tls.n_alpn = 1;
  q->tls.trust = q->trust;
  q->tls.quic = 1;
  rc = twist_client_auth_load (&q->auth, easy->sslcert, easy->sslkey);
  if (rc != TWIST_OK)
    {
      quic_free (q);
      return rc;
    }
  twist_client_auth_apply (q->auth, &q->tls);
  memset (&addr, 0, sizeof addr);
  if (inet_pton (AF_INET, easy->url->host, addr.addr) == 1)
    family = AF_INET;
  else if (inet_pton (AF_INET6, easy->url->host, addr.addr) == 1)
    family = AF_INET6;
  else
    {
      quic_free (q);
      return TWIST_ERR_RESOLVE;
    }
  memset (&ss, 0, sizeof ss);
  if (family == AF_INET)
    {
      struct sockaddr_in *sin = (struct sockaddr_in *) &ss;
      sin->sin_family = AF_INET;
      memcpy (&sin->sin_addr, addr.addr, 4);
      sin->sin_port = htons ((uint16_t) easy->url->port);
      slen = sizeof *sin;
    }
  else
    {
      struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *) &ss;
      sin6->sin6_family = AF_INET6;
      memcpy (&sin6->sin6_addr, addr.addr, 16);
      sin6->sin6_port = htons ((uint16_t) easy->url->port);
      slen = sizeof *sin6;
    }
  fd = socket (family, SOCK_DGRAM, 0);
  if (fd < 0 || fcntl (fd, F_SETFL, O_NONBLOCK) < 0
      || fcntl (fd, F_SETFD, FD_CLOEXEC) < 0
      || connect (fd, (struct sockaddr *) &ss, slen) < 0)
    {
      if (fd >= 0)
        close (fd);
      quic_free (q);
      return TWIST_ERR_CONNECT;
    }
  q->fd = fd;
  q->path.remote.len = slen > 31 ? 31 : (uint8_t) slen;
  memcpy (q->path.remote.data, &ss, q->path.remote.len);
  q->twist = twist_connection_new (easy->loop);
  if (q->twist == NULL)
    {
      close (fd);
      quic_free (q);
      return TWIST_ERR_NOMEM;
    }
  twist_connection_set_tls (q->twist, q, quic_free);
  twist_connection_set_io (q->twist, quic_read, quic_write, q);
  twist_connection_set_fd (q->twist, fd);
  twist_connection_endpoint (q->twist)->send = quic_app_send;
  memset (&ecfg, 0, sizeof ecfg);
  memset (&eev, 0, sizeof eev);
  eev.user = q;
  eev.accept = ep_accept;
  eev.connection = ep_connection;
  eev.done = ep_connection;
  if (gq_endpoint_new (&q->ep, &ecfg, &eev) != GQ_OK)
    {
      twist_connection_free (q->twist);
      return TWIST_ERR_TLS;
    }
  fill_events (&cev, q);
  now = twist_loop_now (q->loop) * 1000u;
  rc = gq_endpoint_connect (q->ep, now, &q->tls, NULL, &q->path, &cev, &q->conn);
  if (rc != GQ_OK)
    {
      twist_connection_free (q->twist);
      return TWIST_ERR_TLS;
    }
  quic_flush (q, now);
  twist_loop_set_aux_timeout (q->loop, quic_deadline, q);
  twist_loop_set_aux_fire (q->loop, quic_fire);
  *out = q->twist;
  return TWIST_OK;
}

int
twist_quic_register (void)
{
  twist_quic_connect_fn = quic_connect;
  return TWIST_OK;
}
