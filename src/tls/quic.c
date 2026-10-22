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

#include <quickstep/crypto.h>
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
  int verify;
  FILE *qlog;
  int qlog_tried;
  gq_slice alpn;
  uint8_t alpn_mem[16];
  char *server_name;
  int fd;
  int hold_stream;
  gq_path path;
  uint8_t *dg;
  size_t dg_len[16];
  int dg_n;
  int dg_i;
  struct quic_stream
  {
    uint64_t id;
    int live;
    size_t (*on_data) (void *, const uint8_t *, size_t, int);
    void *on_user;
    uint8_t *pend;
    size_t pend_len;
    size_t pend_off;
    int pend_finish;
  } st[16];
  int nst;
  int cur;
};

#define QUIC_STREAMS 16

#define QUIC_DG 2048
#define QUIC_BATCH 16

static int quic_flush (struct twist_quic *q, uint64_t now_us);

static struct quic_stream *
qs_cur (struct twist_quic *q)
{
  if (q == NULL || q->nst <= 0 || q->cur < 0 || q->cur >= q->nst)
    return NULL;
  return &q->st[q->cur];
}

static struct quic_stream *
qs_find (struct twist_quic *q, uint64_t id)
{
  int i;

  for (i = 0; i < q->nst; i++)
    if (q->st[i].live && q->st[i].id == id)
      return &q->st[i];
  return NULL;
}

static int
qs_add (struct twist_quic *q, uint64_t id)
{
  if (q->nst >= QUIC_STREAMS)
    return -1;
  q->st[q->nst].id = id;
  q->st[q->nst].live = 1;
  q->cur = q->nst;
  q->nst++;
  return 0;
}

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
    qs_add (q, id);
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
  struct quic_stream *s = qs_find (q, id);

  if (s != NULL && s->on_data != NULL)
    {
      s->on_data (s->on_user, data, len, fin);
      return 0;
    }
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

static int pump_stream (struct twist_quic *q, struct quic_stream *s);
static int quic_flush (struct twist_quic *q, uint64_t now_us);

static void
ev_stream_writable (void *user, uint64_t id)
{
  struct twist_quic *q = user;
  uint64_t now;

  if (pump_stream (q, qs_find (q, id)) != TWIST_OK)
    {
      twist_connection_fail (q->twist, TWIST_ERR_TLS);
      return;
    }
  now = twist_loop_now (q->loop) * 1000u;
  quic_flush (q, now);
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
ensure_dg (struct twist_quic *q)
{
  if (q->dg != NULL)
    return TWIST_OK;
  q->dg = malloc (QUIC_BATCH * QUIC_DG);
  return q->dg == NULL ? TWIST_ERR_NOMEM : TWIST_OK;
}

static int
send_queued (struct twist_quic *q)
{
  int left = q->dg_n - q->dg_i;

  if (left <= 0)
    {
      q->dg_n = 0;
      q->dg_i = 0;
      twist_connection_force_write (q->twist, 0);
      twist_connection_hold_read (q->twist, 0);
      return TWIST_OK;
    }
#if defined __linux__
  {
    struct mmsghdr msg[QUIC_BATCH];
    struct iovec iov[QUIC_BATCH];
    int i;
    int sent;

    memset (msg, 0, sizeof msg);
    for (i = 0; i < left; i++)
      {
        iov[i].iov_base = q->dg + (size_t) (q->dg_i + i) * QUIC_DG;
        iov[i].iov_len = q->dg_len[q->dg_i + i];
        msg[i].msg_hdr.msg_iov = &iov[i];
        msg[i].msg_hdr.msg_iovlen = 1;
      }
    sent = sendmmsg (q->fd, msg, (unsigned int) left, 0);
    if (sent < 0)
      {
        if (errno == EAGAIN || errno == EWOULDBLOCK)
          {
            twist_connection_force_write (q->twist, 1);
            return TWIST_OK;
          }
        return TWIST_ERR_CONNECT;
      }
    q->dg_i += sent;
  }
#else
  while (q->dg_i < q->dg_n)
    {
      ssize_t n = send (q->fd, q->dg + (size_t) q->dg_i * QUIC_DG,
                        q->dg_len[q->dg_i], 0);

      if (n < 0)
        {
          if (errno == EAGAIN || errno == EWOULDBLOCK)
            {
              twist_connection_force_write (q->twist, 1);
              return TWIST_OK;
            }
          return TWIST_ERR_CONNECT;
        }
      q->dg_i++;
    }
#endif
  if (q->dg_i >= q->dg_n)
    {
      q->dg_n = 0;
      q->dg_i = 0;
      twist_connection_force_write (q->twist, 0);
      twist_connection_hold_read (q->twist, 0);
    }
  else
    twist_connection_force_write (q->twist, 1);
  return TWIST_OK;
}

static int
quic_flush (struct twist_quic *q, uint64_t now_us)
{
  int rc;

  if (q->ep == NULL || q->fd < 0)
    return TWIST_OK;
  rc = ensure_dg (q);
  if (rc != TWIST_OK)
    return rc;
  rc = send_queued (q);
  if (rc != TWIST_OK)
    return rc;
  if (q->dg_i > 0 && q->dg_i < q->dg_n)
    {
      memmove (q->dg, q->dg + (size_t) q->dg_i * QUIC_DG,
               (size_t) (q->dg_n - q->dg_i) * QUIC_DG);
      memmove (q->dg_len, q->dg_len + q->dg_i,
               (size_t) (q->dg_n - q->dg_i) * sizeof q->dg_len[0]);
      q->dg_n -= q->dg_i;
      q->dg_i = 0;
    }
  while (q->dg_n < QUIC_BATCH)
    {
      size_t len = 0;
      gq_path to;

      if (gq_endpoint_send (q->ep, now_us, q->dg + (size_t) q->dg_n * QUIC_DG,
                            QUIC_DG, &len, &to) != GQ_OK)
        return TWIST_ERR_TLS;
      if (len == 0)
        break;
      q->dg_len[q->dg_n++] = len;
    }
  return send_queued (q);
}

static void
quic_socket_ready (struct twist_endpoint *ep)
{
  struct twist_quic *q = twist_connection_tls (ep->conn);
  uint64_t now;

  if (q == NULL)
    return;
  now = twist_loop_now (q->loop) * 1000u;
  quic_flush (q, now);
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
  uint64_t now;

  (void) buf;
  (void) len;
  now = twist_loop_now (q->loop) * 1000u;
  if (ensure_dg (q) != TWIST_OK)
    {
      errno = ENOMEM;
      return -1;
    }
  for (;;)
    {
      int room = QUIC_BATCH - q->dg_n;
      int got;
      int i;

      if (room <= 0)
        {
          quic_flush (q, now);
          if (q->dg_n >= QUIC_BATCH)
            {
              twist_connection_hold_read (q->twist, 1);
              break;
            }
          room = QUIC_BATCH - q->dg_n;
        }
#if defined __linux__
      {
        struct mmsghdr msg[QUIC_BATCH];
        struct iovec iov[QUIC_BATCH];

        memset (msg, 0, sizeof msg);
        for (i = 0; i < room; i++)
          {
            iov[i].iov_base = q->dg + (size_t) (q->dg_n + i) * QUIC_DG;
            iov[i].iov_len = QUIC_DG;
            msg[i].msg_hdr.msg_iov = &iov[i];
            msg[i].msg_hdr.msg_iovlen = 1;
          }
        got = recvmmsg (q->fd, msg, (unsigned int) room, 0, NULL);
        if (got < 0)
          {
            if (errno == EAGAIN || errno == EWOULDBLOCK)
              break;
            return -1;
          }
        for (i = 0; i < got; i++)
          gq_endpoint_recv (q->ep, now, &q->path,
                            q->dg + (size_t) (q->dg_n + i) * QUIC_DG,
                            msg[i].msg_len);
        if (got == 0)
          break;
      }
#else
      {
        ssize_t n = recv (q->fd, q->dg + (size_t) q->dg_n * QUIC_DG, QUIC_DG,
                          0);

        if (n < 0)
          {
            if (errno == EAGAIN || errno == EWOULDBLOCK)
              break;
            return -1;
          }
        if (n == 0)
          break;
        gq_endpoint_recv (q->ep, now, &q->path,
                          q->dg + (size_t) q->dg_n * QUIC_DG, (size_t) n);
      }
#endif
    }
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
pend_append (struct quic_stream *s, const uint8_t *data, size_t len)
{
  size_t have = s->pend_len - s->pend_off;
  uint8_t *p;

  if (len == 0)
    return TWIST_OK;
  if (s->pend_off > 0)
    {
      memmove (s->pend, s->pend + s->pend_off, have);
      s->pend_len = have;
      s->pend_off = 0;
    }
  p = realloc (s->pend, s->pend_len + len);
  if (p == NULL)
    return TWIST_ERR_NOMEM;
  memcpy (p + s->pend_len, data, len);
  s->pend = p;
  s->pend_len += len;
  return TWIST_OK;
}

static int
pump_stream (struct twist_quic *q, struct quic_stream *s)
{
  if (q == NULL || s == NULL || !s->live || q->conn == NULL)
    return TWIST_ERR_AGAIN;
  while (s->pend_off < s->pend_len)
    {
      long n = gq_conn_stream_write (q->conn, s->id, s->pend + s->pend_off,
                                     s->pend_len - s->pend_off);

      if (n < 0)
        return TWIST_ERR_TLS;
      if (n == 0)
        return TWIST_OK;
      s->pend_off += (size_t) n;
    }
  if (s->pend_finish)
    {
      if (gq_conn_stream_finish (q->conn, s->id) != GQ_OK)
        return TWIST_ERR_TLS;
      s->pend_finish = 0;
    }
  return TWIST_OK;
}

static int
quic_app_send (struct twist_endpoint *ep, const uint8_t *data, size_t len)
{
  struct twist_quic *q = twist_connection_tls (ep->conn);
  struct quic_stream *s;
  uint64_t now;
  int rc;

  s = q != NULL ? qs_cur (q) : NULL;
  if (s == NULL)
    return TWIST_ERR_AGAIN;
  /* Extended CONNECT keeps the stream open for later WebSocket
     frames.  A normal request finishes once every byte is accepted.  */
  if (s->pend_off < s->pend_len)
    {
      rc = pend_append (s, data, len);
      if (rc != TWIST_OK)
        return rc;
      if (!q->hold_stream)
        s->pend_finish = 1;
    }
  else if (len > 0)
    {
      long n = gq_conn_stream_write (q->conn, s->id, data, len);

      if (n < 0)
        return TWIST_ERR_TLS;
      if ((size_t) n < len)
        {
          rc = pend_append (s, data + n, len - (size_t) n);
          if (rc != TWIST_OK)
            return rc;
          if (!q->hold_stream)
            s->pend_finish = 1;
        }
      else if (!q->hold_stream
               && gq_conn_stream_finish (q->conn, s->id) != GQ_OK)
        return TWIST_ERR_TLS;
    }
  else if (!q->hold_stream
           && gq_conn_stream_finish (q->conn, s->id) != GQ_OK)
    return TWIST_ERR_TLS;
  rc = pump_stream (q, s);
  if (rc != TWIST_OK)
    return rc;
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
  struct quic_stream *s;
  uint64_t now;

  if (q == NULL || !q->hold_stream)
    return TWIST_OK;
  q->hold_stream = 0;
  s = qs_cur (q);
  if (s == NULL || q->conn == NULL)
    return TWIST_OK;
  if (s->pend_off < s->pend_len)
    {
      s->pend_finish = 1;
      return TWIST_OK;
    }
  if (gq_conn_stream_finish (q->conn, s->id) != GQ_OK)
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
  if (q->qlog != NULL)
    fclose (q->qlog);
  gq_trust_free (q->trust);
  twist_client_auth_free (q->auth);
  free (q->server_name);
  free (q->dg);
  {
    int i;

    for (i = 0; i < q->nst; i++)
      free (q->st[i].pend);
  }
  free (q);
}

/* QLOGDIR: a file for the connection in that directory, named after the
   connection ID the client chose, with a line for each event: the time in
   microseconds, the name of the event and its fields, as quickstep writes
   them (qlog.h).  A directory that is not there, or cannot be written to, is
   no log; the transfer does not mind.  */
static void
quic_qlog (void *user, const struct gq_conn *conn, uint64_t time_us,
           const char *name, const char *fields, size_t len)
{
  struct twist_quic *q = user;

  (void) len;
  if (q->qlog == NULL && !q->qlog_tried && conn != NULL)
    {
      const char *dir = getenv ("QLOGDIR");
      size_t n = 0;
      const uint8_t *id = gq_conn_original_dcid (conn, &n);

      q->qlog_tried = 1;
      if (dir != NULL && dir[0] != 0 && id != NULL && n > 0 && n <= 20)
        {
          char path[1024];
          size_t i;
          int off = snprintf (path, sizeof path, "%s/", dir);
          int fd;

          for (i = 0; i < n && off > 0 && (size_t) off + 3 < sizeof path; i++)
            off += snprintf (path + off, sizeof path - (size_t) off, "%02x",
                             id[i]);
          if (off > 0 && (size_t) off + sizeof ".qlog" < sizeof path)
            {
              memcpy (path + off, ".qlog", sizeof ".qlog");
              fd = open (path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
              if (fd >= 0)
                {
                  q->qlog = fdopen (fd, "w");
                  if (q->qlog == NULL)
                    close (fd);
                }
            }
        }
    }
  if (q->qlog != NULL)
    fprintf (q->qlog, "%llu %s %s\n", (unsigned long long) time_us, name,
             fields);
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
  /* -k: the chain is not looked at.  */
  if (!q->verify)
    ev->verify_peer = twist_verify_accept;
  ev->ticket = ev_ticket;
}

int
twist_quic_open_stream (struct twist_connection *conn)
{
  struct twist_quic *q;
  uint64_t id = 0;

  if (conn == NULL)
    return TWIST_ERR_INVAL;
  q = twist_connection_tls (conn);
  if (q == NULL || q->conn == NULL)
    return TWIST_ERR_TLS;
  if (q->nst >= QUIC_STREAMS)
    return TWIST_ERR_AGAIN;
  if (q->conn != NULL && q->nst > 0
      && gq_conn_streams_available (q->conn, 1) == 0)
    return TWIST_ERR_AGAIN;
  if (gq_conn_stream_open (q->conn, 1, &id) != GQ_OK)
    return TWIST_ERR_TLS;
  if (qs_add (q, id) != 0)
    return TWIST_ERR_AGAIN;
  return TWIST_OK;
}

void
twist_quic_bind (struct twist_connection *conn,
                 size_t (*on_data) (void *, const uint8_t *, size_t, int),
                 void *user)
{
  struct twist_quic *q;
  struct quic_stream *s;

  if (conn == NULL)
    return;
  q = twist_connection_tls (conn);
  s = q != NULL ? qs_cur (q) : NULL;
  if (s == NULL)
    return;
  s->on_data = on_data;
  s->on_user = user;
}

int
twist_quic_can_open (struct twist_connection *conn)
{
  struct twist_quic *q;

  if (conn == NULL)
    return 0;
  q = twist_connection_tls (conn);
  if (q == NULL || q->nst >= QUIC_STREAMS)
    return 0;
  if (q->conn != NULL && q->nst > 0
      && gq_conn_streams_available (q->conn, 1) == 0)
    return 0;
  return 1;
}

int
twist_quic_dial (struct twist_loop *loop, const char *server_name,
                 const char *alpn, const struct twist_dns_addr *addr,
                 int port, const char *cafile, const char *capath,
                 const char *certfile, const char *keyfile, int verify,
                 struct twist_connection **out)
{
  struct twist_quic *q;
  gq_endpoint_config ecfg;
  gq_endpoint_events eev;
  gq_conn_events cev;
  struct sockaddr_storage ss;
  socklen_t slen = sizeof ss;
  size_t alpn_len;
  int family;
  int fd = -1;
  int rc;
  uint64_t now;

  if (loop == NULL || server_name == NULL || server_name[0] == 0
      || alpn == NULL || addr == NULL       || out == NULL || port < 0 || port > 65535)
    return TWIST_ERR_INVAL;
  alpn_len = strlen (alpn);
  if (alpn_len == 0 || alpn_len > 16)
    return TWIST_ERR_INVAL;
  *out = NULL;
  if (gq_crypto_init () != GQ_OK)
    return TWIST_ERR_TLS;
  q = calloc (1, sizeof *q);
  if (q == NULL)
    return TWIST_ERR_NOMEM;
  q->loop = loop;
  q->verify = verify;
  q->fd = -1;
  q->server_name = twist_strdup (server_name);
  memcpy (q->alpn_mem, alpn, alpn_len);
  q->alpn.data = q->alpn_mem;
  q->alpn.len = alpn_len;
  if (gq_trust_new (&q->trust) != GQ_OK)
    {
      quic_free (q);
      return TWIST_ERR_TLS;
    }
  rc = twist_trust_load (q->trust, cafile, capath, 1);
  if (rc != TWIST_OK)
    {
      quic_free (q);
      return rc;
    }
  memset (&q->tls, 0, sizeof q->tls);
  q->tls.server_name = q->server_name;
  q->tls.alpn = &q->alpn;
  q->tls.n_alpn = 1;
  q->tls.trust = q->trust;
  if (twist_keylog_wanted ())
    q->tls.keylog = twist_keylog_write;
  q->tls.quic = 1;
  rc = twist_client_auth_load (&q->auth, certfile, keyfile);
  if (rc != TWIST_OK)
    {
      quic_free (q);
      return rc;
    }
  twist_client_auth_apply (q->auth, &q->tls);
  if (addr->family == 4)
    family = AF_INET;
  else if (addr->family == 6)
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
      memcpy (&sin->sin_addr, addr->addr, 4);
      sin->sin_port = htons ((uint16_t) port);
      slen = sizeof *sin;
    }
  else
    {
      struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *) &ss;
      sin6->sin6_family = AF_INET6;
      memcpy (&sin6->sin6_addr, addr->addr, 16);
      sin6->sin6_scope_id = addr->scope_id;
      sin6->sin6_port = htons ((uint16_t) port);
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
  q->twist = twist_connection_new (loop);
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
  twist_connection_endpoint (q->twist)->on_write_ready = quic_socket_ready;
  memset (&ecfg, 0, sizeof ecfg);
  memset (&eev, 0, sizeof eev);
  {
    const char *qdir = getenv ("QLOGDIR");

    if (qdir != NULL && qdir[0] != 0)
      {
        ecfg.conn.qlog = quic_qlog;
        ecfg.conn.qlog_user = q;
      }
  }
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

static int
quic_connect (struct twist_easy *easy, struct twist_connection **out)
{
  struct twist_dns_addr addr;

  if (easy == NULL || easy->url == NULL || easy->url->host == NULL)
    return TWIST_ERR_INVAL;
  memset (&addr, 0, sizeof addr);
  if (inet_pton (AF_INET, easy->url->host, addr.addr) == 1)
    addr.family = 4;
  else if (inet_pton (AF_INET6, easy->url->host, addr.addr) == 1)
    addr.family = 6;
  else
    return TWIST_ERR_RESOLVE;
  return twist_quic_dial (easy->loop, easy->url->host, "h3", &addr,
                          easy->url->port, easy->cainfo, easy->capath, easy->sslcert,
                          easy->sslkey, easy->verifypeer, out);
}

int
twist_quic_register (void)
{
  twist_quic_connect_fn = quic_connect;
  return TWIST_OK;
}
