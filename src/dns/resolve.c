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

#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

/* DoQ, DoT, and DoH are the same DNS messages over QUIC, TLS, and
   HTTPS.  Opening one needs a resolver name to authenticate.  An
   address read from resolv.conf is not that name, so those arms
   decline and the next transport in the plan is tried.  Plain UDP
   retries the same query over TCP when the answer is truncated.  */

enum
{
  PHASE_ADDR = 0,
  PHASE_HTTPS = 1
};

struct dns_query
{
  struct twist_loop *loop;
  char *host;
  void (*cb) (void *, int, const struct twist_dns_addr *);
  void (*svc_cb) (void *, int, const struct twist_dns_service *);
  void *user;
  struct twist_connection *conn;
  struct sockaddr_in sin;
  uint8_t *pkt;
  size_t pktlen;
  int done;
  int sent;
  int tcp;
  int switching;
  int phase;
  int want_https;
  int saw_tc;
  int parse_err;
  struct twist_dns_service svc;
};

static void dns_reap (void *user);
static void dns_send (struct twist_endpoint *ep);

static void
dns_finish (struct dns_query *q, int err)
{
  struct twist_loop *loop;

  if (q->done)
    return;
  q->done = 1;
  loop = q->loop;
  if (q->svc_cb != NULL)
    q->svc_cb (q->user, err, err == TWIST_OK ? &q->svc : NULL);
  else if (q->cb != NULL)
    q->cb (q->user, err, err == TWIST_OK ? &q->svc.addr : NULL);
  if (loop != NULL)
    twist_loop_post (loop, dns_reap, q);
  else
    dns_reap (q);
}

static void
dns_reap (void *user)
{
  struct dns_query *q = user;

  if (q->conn != NULL)
    {
      struct twist_connection *c = q->conn;
      q->conn = NULL;
      twist_connection_free (c);
    }
  free (q->pkt);
  free (q->host);
  free (q);
}

static int
nameserver (struct sockaddr_in *sin)
{
  FILE *fp;
  char line[256];

  memset (sin, 0, sizeof *sin);
  sin->sin_family = AF_INET;
  sin->sin_port = htons (53);
  fp = fopen ("/etc/resolv.conf", "r");
  if (fp != NULL)
    {
      while (fgets (line, sizeof line, fp) != NULL)
        {
          char ip[64];
          if (sscanf (line, "nameserver %63s", ip) == 1
              && inet_pton (AF_INET, ip, &sin->sin_addr) == 1)
            {
              fclose (fp);
              return TWIST_OK;
            }
        }
      fclose (fp);
    }
  inet_pton (AF_INET, "127.0.0.1", &sin->sin_addr);
  return TWIST_OK;
}

static int
ensure_pkt (struct dns_query *q)
{
  int qtype = q->phase == PHASE_HTTPS ? 65 : 1;
  uint16_t id = q->phase == PHASE_HTTPS ? 2 : 1;

  if (q->pkt != NULL)
    return TWIST_OK;
  return twist_dns_encode_query (q->host, qtype, id, &q->pkt, &q->pktlen);
}

static void
dns_send (struct twist_endpoint *ep)
{
  struct dns_query *q = ep->user_data;
  uint8_t *frame = NULL;
  const uint8_t *data;
  size_t len;

  if (q->sent || q->done)
    return;
  if (ensure_pkt (q) != TWIST_OK)
    {
      if (q->phase == PHASE_HTTPS && q->svc.addr.family != 0)
        dns_finish (q, TWIST_OK);
      else
        dns_finish (q, TWIST_ERR_RESOLVE);
      return;
    }
  q->sent = 1;
  if (q->tcp)
    {
      frame = twist_xmalloc (q->pktlen + 2);
      if (frame == NULL)
        {
          dns_finish (q, TWIST_ERR_NOMEM);
          return;
        }
      frame[0] = (uint8_t) (q->pktlen >> 8);
      frame[1] = (uint8_t) q->pktlen;
      memcpy (frame + 2, q->pkt, q->pktlen);
      data = frame;
      len = q->pktlen + 2;
    }
  else
    {
      data = q->pkt;
      len = q->pktlen;
    }
  if (twist_endpoint_send (ep, data, len) != TWIST_OK)
    {
      if (q->phase == PHASE_HTTPS && q->svc.addr.family != 0)
        dns_finish (q, TWIST_OK);
      else
        dns_finish (q, TWIST_ERR_RESOLVE);
    }
  free (frame);
}

static void
on_addr (void *user, const struct twist_dns_addr *addr)
{
  struct dns_query *q = user;

  if (q->phase == PHASE_ADDR && q->svc.addr.family == 0 && addr->family == 4)
    q->svc.addr = *addr;
}

static void
on_alpn (void *user, const char *id, size_t len)
{
  struct dns_query *q = user;

  if (q->phase != PHASE_HTTPS || q->svc.nalpn >= 4 || len == 0 || len >= 16)
    return;
  memcpy (q->svc.alpn[q->svc.nalpn], id, len);
  q->svc.alpn[q->svc.nalpn][len] = 0;
  q->svc.nalpn++;
}

static void
on_port (void *user, int port)
{
  struct dns_query *q = user;

  if (q->phase == PHASE_HTTPS && port > 0 && port < 65536)
    q->svc.port = port;
}

static void
on_https (void *user)
{
  struct dns_query *q = user;

  if (q->phase == PHASE_HTTPS)
    q->svc.have_https = 1;
}

static void
on_trunc (void *user)
{
  ((struct dns_query *) user)->saw_tc = 1;
}

static void
on_fail (void *user, int err)
{
  ((struct dns_query *) user)->parse_err = err;
}

static void dns_switch_tcp (void *user);

static void
advance (struct dns_query *q, struct twist_endpoint *ep)
{
  if (q->saw_tc && !q->tcp)
    {
      q->saw_tc = 0;
      if (q->phase == PHASE_HTTPS)
        {
          q->svc.nalpn = 0;
          q->svc.port = 0;
        }
      else
        memset (&q->svc.addr, 0, sizeof q->svc.addr);
      twist_loop_post (q->loop, dns_switch_tcp, q);
      return;
    }
  if (q->parse_err != TWIST_OK)
    {
      if (q->phase == PHASE_HTTPS && q->svc.addr.family != 0)
        dns_finish (q, TWIST_OK);
      else
        dns_finish (q, q->parse_err);
      return;
    }
  if (q->phase == PHASE_ADDR)
    {
      if (q->svc.addr.family == 0)
        {
          dns_finish (q, TWIST_ERR_RESOLVE);
          return;
        }
      if (q->want_https)
        {
          q->phase = PHASE_HTTPS;
          free (q->pkt);
          q->pkt = NULL;
          q->pktlen = 0;
          q->sent = 0;
          dns_send (ep);
          return;
        }
    }
  dns_finish (q, TWIST_OK);
}

static size_t
dns_receive (struct twist_endpoint *ep, const uint8_t *data, size_t len)
{
  struct dns_query *q = ep->user_data;
  struct twist_dns_events ev;
  size_t n;

  if (q->done || q->switching)
    return len;
  q->saw_tc = 0;
  q->parse_err = TWIST_OK;
  memset (&ev, 0, sizeof ev);
  ev.user = q;
  ev.address = on_addr;
  ev.https_alpn = on_alpn;
  ev.https_port = on_port;
  ev.https_rr = on_https;
  ev.truncated = on_trunc;
  ev.failure = on_fail;
  if (q->tcp)
    n = twist_dns_stream_receive (data, len, &ev);
  else
    n = twist_dns_datagram_receive (data, len, &ev);
  if (n == 0)
    return 0;
  advance (q, ep);
  return n;
}

static void
dns_disconnected (struct twist_endpoint *ep, int error)
{
  struct dns_query *q = ep->user_data;

  if (q->switching || q->done)
    return;
  if (q->phase == PHASE_HTTPS && q->svc.addr.family != 0)
    dns_finish (q, TWIST_OK);
  else
    dns_finish (q, error != TWIST_OK ? error : TWIST_ERR_RESOLVE);
}

static const struct twist_protocol_handler dns_handler = {
  dns_send,
  dns_receive,
  dns_disconnected,
  NULL,
  NULL,
  NULL,
  NULL
};

static int
open_udp (struct dns_query *q)
{
  struct twist_endpoint *ep;
  int fd;

  fd = socket (AF_INET, SOCK_DGRAM, 0);
  if (fd < 0 || fcntl (fd, F_SETFL, O_NONBLOCK) < 0
      || fcntl (fd, F_SETFD, FD_CLOEXEC) < 0
      || connect (fd, (struct sockaddr *) &q->sin, sizeof q->sin) < 0)
    {
      if (fd >= 0)
        close (fd);
      return TWIST_ERR_RESOLVE;
    }
  q->conn = twist_connection_new (q->loop);
  if (q->conn == NULL)
    {
      close (fd);
      return TWIST_ERR_NOMEM;
    }
  ep = twist_connection_endpoint (q->conn);
  ep->user_data = q;
  twist_connection_set_handler (q->conn, &dns_handler);
  twist_connection_set_fd (q->conn, fd);
  twist_connection_connected (q->conn);
  return TWIST_OK;
}

static int
open_tcp (struct dns_query *q)
{
  struct twist_endpoint *ep;
  int rc;

  q->conn = twist_connection_new (q->loop);
  if (q->conn == NULL)
    return TWIST_ERR_NOMEM;
  ep = twist_connection_endpoint (q->conn);
  ep->user_data = q;
  twist_connection_set_handler (q->conn, &dns_handler);
  q->tcp = 1;
  q->sent = 0;
  rc = twist_connection_connect (q->conn, &q->sin, sizeof q->sin, 5000);
  if (rc != TWIST_OK)
    return rc;
  return TWIST_OK;
}

static void
dns_switch_tcp (void *user)
{
  struct dns_query *q = user;
  struct twist_connection *c;

  if (q->done)
    return;
  q->switching = 1;
  c = q->conn;
  q->conn = NULL;
  if (c != NULL)
    twist_connection_free (c);
  q->switching = 0;
  if (open_tcp (q) != TWIST_OK)
    {
      if (q->phase == PHASE_HTTPS && q->svc.addr.family != 0)
        dns_finish (q, TWIST_OK);
      else
        dns_finish (q, TWIST_ERR_RESOLVE);
    }
}

static int
open_transport (int type, struct dns_query *q)
{
  switch (type)
    {
    case TWIST_DNS_DOQ:
    case TWIST_DNS_DOT:
    case TWIST_DNS_DOH:
      return TWIST_ERR_UNSUPPORTED;
    case TWIST_DNS_UDP:
      return open_udp (q);
    default:
      return TWIST_ERR_UNSUPPORTED;
    }
}

static int
literal (const char *host, struct twist_dns_service *svc)
{
  struct in_addr a4;
  struct in6_addr a6;

  memset (svc, 0, sizeof *svc);
  if (inet_pton (AF_INET, host, &a4) == 1)
    {
      svc->addr.family = 4;
      memcpy (svc->addr.addr, &a4, 4);
      snprintf (svc->addr.text, sizeof svc->addr.text, "%s", host);
      return 1;
    }
  if (inet_pton (AF_INET6, host, &a6) == 1)
    {
      svc->addr.family = 6;
      memcpy (svc->addr.addr, &a6, 16);
      snprintf (svc->addr.text, sizeof svc->addr.text, "%s", host);
      return 1;
    }
  return 0;
}

static int
resolve (struct twist_loop *loop, const char *host, const int *order,
         size_t norder, int want_https,
         void (*cb) (void *, int, const struct twist_dns_addr *),
         void (*svc_cb) (void *, int, const struct twist_dns_service *),
         void *user)
{
  struct dns_query *q;
  struct twist_dns_service lit;
  int plan[4];
  size_t np = 0;
  size_t i;
  int saw_unsup = 0;
  int rc;

  if (host == NULL || (cb == NULL && svc_cb == NULL))
    return TWIST_ERR_INVAL;
  if (literal (host, &lit))
    {
      if (svc_cb != NULL)
        svc_cb (user, TWIST_OK, &lit);
      else
        cb (user, TWIST_OK, &lit.addr);
      return TWIST_OK;
    }
  if (loop == NULL)
    return TWIST_ERR_INVAL;
  if (twist_dns_transport_plan (order, norder, plan, 4, &np) != TWIST_OK)
    return TWIST_ERR_INVAL;
  q = calloc (1, sizeof *q);
  if (q == NULL)
    return TWIST_ERR_NOMEM;
  q->loop = loop;
  q->host = twist_strdup (host);
  q->cb = cb;
  q->svc_cb = svc_cb;
  q->user = user;
  q->want_https = want_https;
  if (q->host == NULL)
    {
      free (q);
      return TWIST_ERR_NOMEM;
    }
  nameserver (&q->sin);
  rc = TWIST_ERR_RESOLVE;
  for (i = 0; i < np; i++)
    {
      rc = open_transport (plan[i], q);
      if (rc == TWIST_OK)
        return TWIST_OK;
      if (rc == TWIST_ERR_UNSUPPORTED)
        {
          saw_unsup = 1;
          continue;
        }
      break;
    }
  free (q->host);
  free (q);
  return saw_unsup && rc == TWIST_ERR_UNSUPPORTED ? TWIST_ERR_RESOLVE : rc;
}

int
twist_dns_resolve (struct twist_loop *loop, const char *host,
                   const int *order, size_t norder,
                   void (*cb) (void *, int, const struct twist_dns_addr *),
                   void *user)
{
  return resolve (loop, host, order, norder, 0, cb, NULL, user);
}

int
twist_dns_resolve_service (struct twist_loop *loop, const char *host,
                           const int *order, size_t norder,
                           void (*cb) (void *, int,
                                       const struct twist_dns_service *),
                           void *user)
{
  return resolve (loop, host, order, norder, 1, NULL, cb, user);
}
