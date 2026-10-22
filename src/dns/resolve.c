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
#include <quickstep/status.h>

#include <arpa/inet.h>
#include <fcntl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

/* Every dial comes through here.  An IPv4 or IPv6 host is the address,
   so no transport is opened.  DoQ (RFC 9250) and DoT (RFC 7858) need a
   name to authenticate.  With no resolver URL, that name comes from a
   DDR query (RFC 9462) for _dns.resolver.arpa SVCB, sent to the
   resolv.conf address over UDP.  A configured quic:// or tls:// URL is
   used instead, and its host is resolved with UDP so the lookup cannot
   recurse.  DoH runs when a HTTPS URL was configured.  The DoH server's
   own name is resolved with DoQ, DoT, or UDP, never with DoH.  Plain
   UDP retries the same query over TCP when the answer is truncated.  */

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
  int doh;
  int doh_verifypeer;
  long timeout_ms;
  char *doh_text;
  const char *cainfo;
  const char *capath;
  const char *certfile;
  const char *keyfile;
  struct twist_url *doh_parsed;
  struct twist_doh *dohp;
  struct twist_endpoint *ep;
  int user_order[4];
  int user_order_n;
  int doq;
  int dot;
  int ddr;
  int ddr_done;
  int ddr_doq;
  int ddr_dot;
  int answered;
  int doq_sent;
  int boot;
  int plan[4];
  int plan_n;
  int plan_i;
  int peer_port;
  int ddr_doq_port;
  int ddr_dot_port;
  struct twist_dns_addr peer_addr;
  struct twist_dns_addr ddr_doq_addr;
  struct twist_dns_addr ddr_dot_addr;
  char peer_name[256];
  char ddr_doq_name[256];
  char ddr_dot_name[256];
  char *doq_text;
  char *dot_text;
  struct twist_dns_cache *cache;
  int cache_lead;
  uint32_t ttl_sec;
  uint16_t expect_id;
  char expect_name[256];
  struct twist_url *doq_parsed;
  struct twist_url *dot_parsed;
  struct twist_dns_service svc;
};

static int open_doh (struct dns_query *q);
static int open_doq (struct dns_query *q);
static int open_dot (struct dns_query *q);
static int begin_plan (struct dns_query *q);
static void fallback_cb (void *user);
static void dns_release (struct dns_query *q);
static int literal (const char *host, struct twist_dns_service *svc);

static void dns_reap (void *user);
static void dns_send (struct twist_endpoint *ep);

static void
dns_finish (struct dns_query *q, int err)
{
  struct twist_loop *loop;

  if (q->done)
    return;
  q->done = 1;
  if (q->cache_lead && q->cache != NULL)
    {
      uint32_t ttl = q->ttl_sec == 0xffffffffu ? 0 : q->ttl_sec;

      q->cache_lead = 0;
      twist_dns_cache_end (q->cache, q->loop, q->host, 1,
                           err, err == TWIST_OK ? &q->svc.addr : NULL, ttl,
                           twist_loop_now (q->loop));
    }
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
  dns_release (q);
}

static void
dns_release (struct dns_query *q)
{
  twist_doh_free (q->dohp);
  twist_url_free_int (q->doh_parsed);
  twist_url_free_int (q->doq_parsed);
  twist_url_free_int (q->dot_parsed);
  free (q->doh_text);
  free (q->doq_text);
  free (q->dot_text);
  free (q->pkt);
  free (q->host);
  free (q);
}

static struct sockaddr_in ns_addr;
static time_t ns_mtime;
static int ns_ready;

static int
nameserver (struct sockaddr_in *sin)
{
  FILE *fp;
  char line[256];
  struct stat st;
  int have;

  have = stat ("/etc/resolv.conf", &st) == 0;
  if (ns_ready && (!have || st.st_mtime == ns_mtime))
    {
      *sin = ns_addr;
      return TWIST_OK;
    }
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
              ns_addr = *sin;
              if (have)
                ns_mtime = st.st_mtime;
              ns_ready = 1;
              return TWIST_OK;
            }
        }
      fclose (fp);
    }
  inet_pton (AF_INET, "127.0.0.1", &sin->sin_addr);
  ns_addr = *sin;
  if (have)
    ns_mtime = st.st_mtime;
  ns_ready = 1;
  return TWIST_OK;
}

static void copy_dns_name (char *dst, size_t cap, const char *src);

static int
random_id (uint16_t *id)
{
  uint8_t b[2];

  if (gq_random (b, sizeof b) != GQ_OK)
    return TWIST_ERR_RESOLVE;
  *id = (uint16_t) (((unsigned) b[0] << 8) | b[1]);
  return TWIST_OK;
}

static void
set_expect (struct dns_query *q, uint16_t id, const char *name)
{
  q->expect_id = id;
  copy_dns_name (q->expect_name, sizeof q->expect_name, name);
}

static int
response_matches (const struct dns_query *q, const uint8_t *msg, size_t len)
{
  if (q->expect_name[0] == 0)
    return 0;
  return twist_dns_response_ok (msg, len, q->expect_id, q->expect_name);
}

static int
ensure_pkt (struct dns_query *q)
{
  int qtype = q->phase == PHASE_HTTPS ? 65 : 1;
  uint16_t id;

  if (q->pkt != NULL)
    return TWIST_OK;
  if (random_id (&id) != TWIST_OK)
    return TWIST_ERR_RESOLVE;
  set_expect (q, id, q->host);
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
  if (q->ddr)
    {
      uint8_t *pkt = NULL;
      size_t n = 0;
      uint16_t id = 0;
      int rc;

      q->sent = 1;
      if (random_id (&id) != TWIST_OK)
        rc = TWIST_ERR_RESOLVE;
      else
        rc = twist_dns_encode_query ("_dns.resolver.arpa", 64, id, &pkt, &n);
      if (rc != TWIST_OK)
        {
          q->ddr = 0;
          q->ddr_done = 1;
          if (q->loop != NULL)
            twist_loop_post (q->loop, fallback_cb, q);
          else
            dns_finish (q, rc);
          return;
        }
      if (q->tcp)
        {
          rc = twist_dns_frame_stream (pkt, n, 0, &frame, &len);
          free (pkt);
          if (rc != TWIST_OK)
            {
              q->ddr = 0;
              q->ddr_done = 1;
              if (q->loop != NULL)
                twist_loop_post (q->loop, fallback_cb, q);
              else
                dns_finish (q, rc);
              return;
            }
          data = frame;
        }
      else
        {
          data = pkt;
          len = n;
          frame = pkt;
        }
      set_expect (q, id, "_dns.resolver.arpa");
      if (twist_endpoint_send (ep, data, len) != TWIST_OK)
        {
          q->ddr = 0;
          q->ddr_done = 1;
          if (q->loop != NULL)
            twist_loop_post (q->loop, fallback_cb, q);
          else
            dns_finish (q, TWIST_ERR_RESOLVE);
        }
      free (frame);
      return;
    }
  if (q->doq && q->doq_sent)
    {
      if (twist_quic_open_stream (q->conn) != TWIST_OK)
        {
          dns_finish (q, TWIST_ERR_TLS);
          return;
        }
    }
  if (ensure_pkt (q) != TWIST_OK)
    {
      if (q->phase == PHASE_HTTPS && q->svc.addr.family != 0)
        dns_finish (q, TWIST_OK);
      else
        dns_finish (q, TWIST_ERR_RESOLVE);
      return;
    }
  q->sent = 1;
  if (q->doq)
    q->doq_sent = 1;
  if (q->doh)
    {
      uint8_t *http = NULL;
      size_t hn = 0;
      int rc = twist_doh_encode_url (q->doh_text, q->pkt, q->pktlen, &http,
                                     &hn);

      if (rc != TWIST_OK || twist_endpoint_send (ep, http, hn) != TWIST_OK)
        {
          free (http);
          if (q->phase == PHASE_HTTPS && q->svc.addr.family != 0)
            dns_finish (q, TWIST_OK);
          else
            dns_finish (q, rc != TWIST_OK ? rc : TWIST_ERR_RESOLVE);
        }
      else
        free (http);
      return;
    }
  if (q->tcp || q->doq)
    {
      int rc = twist_dns_frame_stream (q->pkt, q->pktlen, q->doq, &frame, &len);

      if (rc != TWIST_OK)
        {
          dns_finish (q, rc);
          return;
        }
      if (q->doq)
        q->expect_id = 0;
      data = frame;
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
copy_dns_name (char *dst, size_t cap, const char *src)
{
  size_t n;

  if (dst == NULL || cap == 0)
    return;
  dst[0] = 0;
  if (src == NULL)
    return;
  n = strlen (src);
  if (n >= cap)
    n = cap - 1;
  memcpy (dst, src, n);
  dst[n] = 0;
}

static void
hint_addr (struct dns_query *q, struct twist_dns_addr *out, int family,
           const uint8_t *hint)
{
  memset (out, 0, sizeof *out);
  if (family == 4 || family == 6)
    {
      out->family = family;
      memcpy (out->addr, hint, family == 4 ? 4 : 16);
      return;
    }
  out->family = 4;
  memcpy (out->addr, &q->sin.sin_addr, 4);
}

static void
on_svcb (void *user, const char *target, const char *alpn, size_t alpn_len,
         int port, int hint_family, const uint8_t *hint)
{
  struct dns_query *q = user;
  int use_port = port > 0 ? port : 853;

  if (!q->ddr)
    return;
  if (target == NULL || target[0] == 0 || strcmp (target, ".") == 0)
    return;
  if (alpn_len == 3 && memcmp (alpn, "doq", 3) == 0 && !q->ddr_doq)
    {
      q->ddr_doq = 1;
      q->ddr_doq_port = use_port;
      copy_dns_name (q->ddr_doq_name, sizeof q->ddr_doq_name, target);
      hint_addr (q, &q->ddr_doq_addr, hint_family, hint);
    }
  else if (alpn_len == 3 && memcmp (alpn, "dot", 3) == 0 && !q->ddr_dot)
    {
      q->ddr_dot = 1;
      q->ddr_dot_port = use_port;
      copy_dns_name (q->ddr_dot_name, sizeof q->ddr_dot_name, target);
      hint_addr (q, &q->ddr_dot_addr, hint_family, hint);
    }
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

static void
on_ttl (void *user, uint32_t ttl)
{
  struct dns_query *q = user;

  if (ttl < q->ttl_sec)
    q->ttl_sec = ttl;
}

static void dns_switch_tcp (void *user);
static void after_ddr (void *user);

static void
advance (struct dns_query *q, struct twist_endpoint *ep)
{
  if (q->ddr)
    {
      if (q->saw_tc && !q->tcp)
        {
          q->saw_tc = 0;
          twist_loop_post (q->loop, dns_switch_tcp, q);
          return;
        }
      q->ddr = 0;
      q->ddr_done = 1;
      twist_loop_post (q->loop, after_ddr, q);
      return;
    }
  q->answered = 1;
  if (q->saw_tc && !q->tcp && !q->doh && !q->dot && !q->doq)
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
  ev.svcb = on_svcb;
  ev.truncated = on_trunc;
  ev.failure = on_fail;
  ev.ttl = on_ttl;
  if (q->tcp)
    {
      size_t need;

      if (len < 2)
        return 0;
      need = ((size_t) data[0] << 8) | data[1];
      if (len < 2 + need)
        return 0;
      if (!response_matches (q, data + 2, need))
        return 2 + need;
      n = twist_dns_stream_receive (data, len, &ev);
    }
  else
    {
      if (!response_matches (q, data, len))
        return len;
      n = twist_dns_datagram_receive (data, len, &ev);
    }
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
    {
      dns_finish (q, TWIST_OK);
      return;
    }
  if (q->answered)
    {
      dns_finish (q, error != TWIST_OK ? error : TWIST_ERR_RESOLVE);
      return;
    }
  if (q->loop != NULL)
    twist_loop_post (q->loop, fallback_cb, q);
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

static void
on_doh_msg (void *user, int err, const uint8_t *msg, size_t len)
{
  struct dns_query *q = user;
  struct twist_dns_events ev;

  if (q->done)
    return;
  if (err != TWIST_OK)
    {
      if (q->phase == PHASE_HTTPS && q->svc.addr.family != 0)
        dns_finish (q, TWIST_OK);
      else
        dns_finish (q, err);
      return;
    }
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
  ev.ttl = on_ttl;
  if (!response_matches (q, msg, len)
      || twist_dns_datagram_receive (msg, len, &ev) == 0)
    {
      dns_finish (q, TWIST_ERR_PROTOCOL);
      return;
    }
  advance (q, q->ep);
}

static void
doh_connected (struct twist_endpoint *ep)
{
  struct dns_query *q = ep->user_data;
  static const char *alpn[] = { "http/1.1" };
  int rc;

  q->ep = ep;
  if (q->done)
    return;
  rc = twist_connection_start_tls (q->conn, q->doh_parsed->host,
                                   q->doh_verifypeer, alpn, 1, q->cainfo, q->capath,
                                   q->certfile, q->keyfile);
  if (rc != TWIST_OK)
    dns_finish (q, rc);
}

static void
doh_secure (struct twist_endpoint *ep, const char *alpn, size_t alpn_len)
{
  (void) alpn;
  (void) alpn_len;
  dns_send (ep);
}

static size_t
doh_receive (struct twist_endpoint *ep, const uint8_t *data, size_t len)
{
  struct dns_query *q = ep->user_data;

  q->ep = ep;
  if (q->done || q->dohp == NULL)
    return len;
  return twist_doh_receive (q->dohp, data, len);
}

static const struct twist_protocol_handler doh_handler = {
  doh_connected,
  doh_receive,
  dns_disconnected,
  doh_secure,
  NULL,
  NULL,
  NULL
};

static int
connect_doh (struct dns_query *q, const struct twist_dns_addr *addr)
{
  struct sockaddr_in sin;
  struct sockaddr_in6 sin6;
  const void *sa;
  size_t salen;
  int port;
  uint64_t tmo;
  struct twist_endpoint *ep;

  port = q->doh_parsed->port > 0 ? q->doh_parsed->port : 443;
  tmo = q->timeout_ms > 0 ? (uint64_t) q->timeout_ms : 5000;
  q->conn = twist_connection_new (q->loop);
  if (q->conn == NULL)
    return TWIST_ERR_NOMEM;
  ep = twist_connection_endpoint (q->conn);
  ep->user_data = q;
  twist_connection_set_handler (q->conn, &doh_handler);
  q->doh = 1;
  q->sent = 0;
  if (addr->family == 6)
    {
      memset (&sin6, 0, sizeof sin6);
      sin6.sin6_family = AF_INET6;
      sin6.sin6_port = htons ((uint16_t) port);
      memcpy (&sin6.sin6_addr, addr->addr, 16);
      sa = &sin6;
      salen = sizeof sin6;
    }
  else
    {
      memset (&sin, 0, sizeof sin);
      sin.sin_family = AF_INET;
      sin.sin_port = htons ((uint16_t) port);
      memcpy (&sin.sin_addr, addr->addr, 4);
      sa = &sin;
      salen = sizeof sin;
    }
  return twist_connection_connect (q->conn, sa, salen, tmo);
}

static void
on_boot (void *user, int err, const struct twist_dns_addr *addr)
{
  struct dns_query *q = user;

  if (q->done)
    return;
  if (err != TWIST_OK || addr == NULL
      || connect_doh (q, addr) != TWIST_OK)
    dns_finish (q, err != TWIST_OK ? err : TWIST_ERR_RESOLVE);
}

static int
open_doh (struct dns_query *q)
{
  int boot[4];
  size_t nboot = 0;
  int rc;

  if (q->doh_text == NULL || q->doh_text[0] == 0)
    return TWIST_ERR_UNSUPPORTED;
  if (q->doh_parsed == NULL)
    {
      rc = twist_url_parse_int (q->doh_text, &q->doh_parsed);
      if (rc != TWIST_OK)
        return rc;
      if (q->doh_parsed->scheme == NULL
          || strcmp (q->doh_parsed->scheme, "https") != 0
          || q->doh_parsed->host == NULL || q->doh_parsed->host[0] == 0)
        return TWIST_ERR_URL;
    }
  if (q->dohp == NULL)
    {
      q->dohp = twist_doh_new (on_doh_msg, q);
      if (q->dohp == NULL)
        return TWIST_ERR_NOMEM;
    }
  /* The usual transports except DoH.  resolve() returns an address
     host immediately.  A name must not be looked up through DoH.  */
  if (twist_dns_bootstrap_plan (q->user_order_n > 0 ? q->user_order : NULL,
                                (size_t) q->user_order_n, boot, 4, &nboot)
      != TWIST_OK)
    return TWIST_ERR_RESOLVE;
  return twist_dns_resolve (q->loop, q->doh_parsed->host, boot, nboot,
                            on_boot, q);
}

static void
drop_conn (struct dns_query *q)
{
  struct twist_connection *c;

  q->switching = 1;
  c = q->conn;
  q->conn = NULL;
  if (c != NULL)
    twist_connection_free (c);
  q->switching = 0;
  q->tcp = 0;
  q->doq = 0;
  q->dot = 0;
  q->doh = 0;
  q->ddr = 0;
  q->sent = 0;
  q->doq_sent = 0;
}

static int
remember_peer (struct dns_query *q, const char *name,
               const struct twist_dns_addr *addr, int port)
{
  size_t n;

  if (name == NULL || name[0] == 0 || addr == NULL || addr->family == 0
      || port <= 0 || port > 65535)
    return TWIST_ERR_RESOLVE;
  n = strlen (name);
  if (n >= sizeof q->peer_name)
    return TWIST_ERR_RESOLVE;
  memcpy (q->peer_name, name, n + 1);
  q->peer_addr = *addr;
  q->peer_port = port;
  return TWIST_OK;
}

static int
dial_tcp (struct dns_query *q, const struct twist_dns_addr *addr, int port,
          const struct twist_protocol_handler *handler)
{
  struct sockaddr_in sin;
  struct sockaddr_in6 sin6;
  const void *sa;
  size_t salen;
  struct twist_endpoint *ep;
  uint64_t tmo;
  int rc;

  q->conn = twist_connection_new (q->loop);
  if (q->conn == NULL)
    return TWIST_ERR_NOMEM;
  ep = twist_connection_endpoint (q->conn);
  ep->user_data = q;
  twist_connection_set_handler (q->conn, handler);
  tmo = q->timeout_ms > 0 ? (uint64_t) q->timeout_ms : 5000;
  if (addr->family == 6)
    {
      memset (&sin6, 0, sizeof sin6);
      sin6.sin6_family = AF_INET6;
      sin6.sin6_port = htons ((uint16_t) port);
      memcpy (&sin6.sin6_addr, addr->addr, 16);
      sa = &sin6;
      salen = sizeof sin6;
    }
  else
    {
      memset (&sin, 0, sizeof sin);
      sin.sin_family = AF_INET;
      sin.sin_port = htons ((uint16_t) port);
      memcpy (&sin.sin_addr, addr->addr, 4);
      sa = &sin;
      salen = sizeof sin;
    }
  rc = twist_connection_connect (q->conn, sa, salen, tmo);
  if (rc != TWIST_OK)
    {
      twist_connection_free (q->conn);
      q->conn = NULL;
      return rc;
    }
  return TWIST_OK;
}

static void
dot_connected (struct twist_endpoint *ep)
{
  struct dns_query *q = ep->user_data;
  static const char *alpn[] = { "dot" };
  int rc;

  if (q->done)
    return;
  rc = twist_connection_start_tls (q->conn, q->peer_name, 1, alpn, 1, q->cainfo, q->capath,
                                   q->certfile, q->keyfile);
  if (rc != TWIST_OK)
    twist_connection_fail (q->conn, rc);
}

static void
dot_secure (struct twist_endpoint *ep, const char *alpn, size_t alpn_len)
{
  struct dns_query *q = ep->user_data;

  (void) alpn;
  (void) alpn_len;
  q->tcp = 1;
  q->dot = 1;
  dns_send (ep);
}

static void
doq_secure (struct twist_endpoint *ep, const char *alpn, size_t alpn_len)
{
  (void) alpn;
  (void) alpn_len;
  dns_send (ep);
}

static const struct twist_protocol_handler dot_handler = {
  dot_connected,
  dns_receive,
  dns_disconnected,
  dot_secure,
  NULL,
  NULL,
  NULL
};

static const struct twist_protocol_handler doq_handler = {
  NULL,
  dns_receive,
  dns_disconnected,
  doq_secure,
  NULL,
  NULL,
  NULL
};

static int
connect_doq (struct dns_query *q, const struct twist_dns_addr *addr, int port,
             const char *name)
{
  struct twist_connection *conn = NULL;
  struct twist_endpoint *ep;
  int rc;

  rc = remember_peer (q, name, addr, port);
  if (rc != TWIST_OK)
    return rc;
  rc = twist_quic_dial (q->loop, q->peer_name, "doq", addr, port, q->cainfo, q->capath,
                        q->certfile, q->keyfile, &conn);
  if (rc != TWIST_OK)
    return rc;
  q->conn = conn;
  ep = twist_connection_endpoint (conn);
  ep->user_data = q;
  twist_connection_set_handler (conn, &doq_handler);
  q->doq = 1;
  q->tcp = 1;
  q->sent = 0;
  return TWIST_OK;
}

static int
connect_dot (struct dns_query *q, const struct twist_dns_addr *addr, int port,
             const char *name)
{
  int rc = remember_peer (q, name, addr, port);

  if (rc != TWIST_OK)
    return rc;
  q->dot = 1;
  q->sent = 0;
  q->tcp = 0;
  return dial_tcp (q, addr, port, &dot_handler);
}

static int
parse_secure_url (const char *text, const char *expect, struct twist_url **out)
{
  char built[512];
  const char *use = text;
  struct twist_url *u = NULL;
  int rc;
  int n;

  if (text == NULL || text[0] == 0 || expect == NULL || out == NULL)
    return TWIST_ERR_URL;
  if (strstr (text, "://") == NULL)
    {
      n = snprintf (built, sizeof built, "%s://%s", expect, text);
      if (n < 0 || (size_t) n >= sizeof built)
        return TWIST_ERR_URL;
      use = built;
    }
  rc = twist_url_parse_int (use, &u);
  if (rc != TWIST_OK)
    return rc;
  if (u->scheme == NULL || strcmp (u->scheme, expect) != 0 || u->host == NULL
      || u->host[0] == 0)
    {
      twist_url_free_int (u);
      return TWIST_ERR_URL;
    }
  if (u->port <= 0)
    u->port = 853;
  *out = u;
  return TWIST_OK;
}

static void
on_resolver_addr (void *user, int err, const struct twist_dns_addr *addr)
{
  struct dns_query *q = user;
  int rc = TWIST_ERR_RESOLVE;

  if (q->done)
    return;
  if (err == TWIST_OK && addr != NULL)
    {
      if (q->boot == TWIST_DNS_DOQ && q->doq_parsed != NULL)
        rc = connect_doq (q, addr, q->doq_parsed->port, q->doq_parsed->host);
      else if (q->boot == TWIST_DNS_DOT && q->dot_parsed != NULL)
        rc = connect_dot (q, addr, q->dot_parsed->port, q->dot_parsed->host);
    }
  if (rc != TWIST_OK && q->loop != NULL)
    twist_loop_post (q->loop, fallback_cb, q);
  else if (rc != TWIST_OK)
    dns_finish (q, rc);
}

static int
start_ddr (struct dns_query *q)
{
  q->ddr = 1;
  q->sent = 0;
  q->tcp = 0;
  return open_udp (q);
}

static int
open_doq (struct dns_query *q)
{
  struct twist_dns_service lit;
  int udp = TWIST_DNS_UDP;
  int rc;

  if (q->doq_text != NULL && q->doq_text[0] != 0)
    {
      if (q->doq_parsed == NULL)
        {
          rc = parse_secure_url (q->doq_text, "quic", &q->doq_parsed);
          if (rc != TWIST_OK)
            return rc;
        }
      if (literal (q->doq_parsed->host, &lit) == 1)
        return connect_doq (q, &lit.addr, q->doq_parsed->port,
                            q->doq_parsed->host);
      q->boot = TWIST_DNS_DOQ;
      return twist_dns_resolve (q->loop, q->doq_parsed->host, &udp, 1,
                                on_resolver_addr, q);
    }
  if (!q->ddr_done)
    return start_ddr (q);
  if (!q->ddr_doq)
    return TWIST_ERR_UNSUPPORTED;
  return connect_doq (q, &q->ddr_doq_addr, q->ddr_doq_port, q->ddr_doq_name);
}

static int
open_dot (struct dns_query *q)
{
  struct twist_dns_service lit;
  int udp = TWIST_DNS_UDP;
  int rc;

  if (q->dot_text != NULL && q->dot_text[0] != 0)
    {
      if (q->dot_parsed == NULL)
        {
          rc = parse_secure_url (q->dot_text, "tls", &q->dot_parsed);
          if (rc != TWIST_OK)
            return rc;
        }
      if (literal (q->dot_parsed->host, &lit) == 1)
        return connect_dot (q, &lit.addr, q->dot_parsed->port,
                            q->dot_parsed->host);
      q->boot = TWIST_DNS_DOT;
      return twist_dns_resolve (q->loop, q->dot_parsed->host, &udp, 1,
                                on_resolver_addr, q);
    }
  if (!q->ddr_done)
    return start_ddr (q);
  if (!q->ddr_dot)
    return TWIST_ERR_UNSUPPORTED;
  return connect_dot (q, &q->ddr_dot_addr, q->ddr_dot_port, q->ddr_dot_name);
}

static void
after_ddr (void *user)
{
  struct dns_query *q = user;
  int cur;
  int rc = TWIST_ERR_UNSUPPORTED;

  if (q->done)
    return;
  drop_conn (q);
  if (q->plan_i <= 0)
    {
      dns_finish (q, TWIST_ERR_RESOLVE);
      return;
    }
  cur = q->plan[q->plan_i - 1];
  if (cur == TWIST_DNS_DOQ && q->ddr_doq)
    rc = connect_doq (q, &q->ddr_doq_addr, q->ddr_doq_port, q->ddr_doq_name);
  else if (cur == TWIST_DNS_DOT && q->ddr_dot)
    rc = connect_dot (q, &q->ddr_dot_addr, q->ddr_dot_port, q->ddr_dot_name);
  if (rc == TWIST_OK)
    return;
  if (rc == TWIST_ERR_NOMEM || rc == TWIST_ERR_INVAL || rc == TWIST_ERR_URL)
    dns_finish (q, rc);
  else
    fallback_cb (q);
}

static int
open_transport (int type, struct dns_query *q)
{
  switch (type)
    {
    case TWIST_DNS_DOQ:
      return open_doq (q);
    case TWIST_DNS_DOT:
      return open_dot (q);
    case TWIST_DNS_DOH:
      return open_doh (q);
    case TWIST_DNS_UDP:
      return open_udp (q);
    default:
      return TWIST_ERR_UNSUPPORTED;
    }
}

static int
begin_plan (struct dns_query *q)
{
  int rc = TWIST_ERR_UNSUPPORTED;
  int tried = 0;

  while (q->plan_i < q->plan_n)
    {
      rc = open_transport (q->plan[q->plan_i++], q);
      if (rc == TWIST_OK)
        return TWIST_OK;
      if (rc == TWIST_ERR_NOMEM || rc == TWIST_ERR_INVAL
          || rc == TWIST_ERR_URL)
        return rc;
      tried = 1;
    }
  return tried ? TWIST_ERR_RESOLVE : TWIST_ERR_UNSUPPORTED;
}

static void
fallback_cb (void *user)
{
  struct dns_query *q = user;
  int rc;

  if (q->done)
    return;
  drop_conn (q);
  rc = begin_plan (q);
  if (rc != TWIST_OK)
    dns_finish (q, rc == TWIST_ERR_UNSUPPORTED ? TWIST_ERR_RESOLVE : rc);
}

/* 1: HOST is an address, and SVC has it.  0: it is not one, and may be a
   name.  -1: it has a colon, so it can only be an IPv6 address, and it is not
   a good one: there is nothing to look up.  -2: a good one, with a zone that
   is not an interface of this machine, so it cannot be reached.  An IPv6 address may end in a zone,
   %eth0 or %3, the interface it is reached by; that is how a link-local
   address is told from the same one on another link.  */
static int
literal (const char *host, struct twist_dns_service *svc)
{
  struct in_addr a4;
  struct in6_addr a6;
  char addr[64];
  const char *pct;
  size_t n;
  unsigned scope = 0;

  memset (svc, 0, sizeof *svc);
  if (inet_pton (AF_INET, host, &a4) == 1)
    {
      svc->addr.family = 4;
      memcpy (svc->addr.addr, &a4, 4);
      snprintf (svc->addr.text, sizeof svc->addr.text, "%s", host);
      return 1;
    }
  if (strchr (host, ':') == NULL)
    return 0;
  pct = strchr (host, '%');
  n = pct != NULL ? (size_t) (pct - host) : strlen (host);
  if (n >= sizeof addr)
    return -1;
  memcpy (addr, host, n);
  addr[n] = 0;
  if (inet_pton (AF_INET6, addr, &a6) != 1)
    return -1;
  if (pct != NULL)
    {
      const char *zone = pct + 1;
      const char *d;

      if (*zone == 0)
        return -1;
      for (d = zone; *d >= '0' && *d <= '9'; d++)
        ;
      if (*d == 0)
        {
          unsigned long v = strtoul (zone, NULL, 10);

          if (d - zone > 9 || v == 0)
            return -1;
          scope = (unsigned) v;
        }
      else
        {
          scope = if_nametoindex (zone);
          if (scope == 0)
            return -2;
        }
    }
  svc->addr.family = 6;
  memcpy (svc->addr.addr, &a6, 16);
  svc->addr.scope_id = scope;
  snprintf (svc->addr.text, sizeof svc->addr.text, "%s", host);
  return 1;
}

static void
cache_abort (struct twist_dns_cache *cache, struct twist_loop *loop,
             const char *host, int lead, int err)
{
  if (lead && cache != NULL)
    twist_dns_cache_end (cache, loop, host, 1, err, NULL, 0,
                         twist_loop_now (loop));
}

static int
resolve (struct twist_loop *loop, const char *host, const int *order,
         size_t norder, int want_https, const char *doh_url,
         const char *doq_url, const char *dot_url, int doh_verifypeer,
         const char *cainfo, const char *capath, const char *certfile,
         const char *keyfile, long timeout_ms, struct twist_dns_cache *cache,
         void (*cb) (void *, int, const struct twist_dns_addr *),
         void (*svc_cb) (void *, int, const struct twist_dns_service *),
         void *user)
{
  struct dns_query *q;
  struct twist_dns_service lit;
  int plan[4];
  size_t np = 0;
  int have_doh;
  int have_doq;
  int have_dot;
  int rc;

  if (host == NULL || (cb == NULL && svc_cb == NULL))
    return TWIST_ERR_INVAL;
  rc = literal (host, &lit);
  if (rc == -2)
    return TWIST_ERR_CONNECT;
  if (rc < 0)
    return TWIST_ERR_RESOLVE;
  if (rc == 1)
    {
      if (svc_cb != NULL)
        svc_cb (user, TWIST_OK, &lit);
      else
        cb (user, TWIST_OK, &lit.addr);
      return TWIST_OK;
    }
  if (loop == NULL)
    return TWIST_ERR_INVAL;
  if (!want_https && cache != NULL && cb != NULL)
    {
      struct twist_dns_addr hit;
      int st = twist_dns_cache_begin (cache, loop, host, 1, cb, user,
                                      twist_loop_now (loop), &hit);

      if (st < 0)
        return st;
      if (st == 2)
        {
          cb (user, TWIST_OK, &hit);
          return TWIST_OK;
        }
      if (st == 1)
        return TWIST_OK;
    }
  have_doh = doh_url != NULL && doh_url[0] != 0;
  have_doq = doq_url != NULL && doq_url[0] != 0;
  have_dot = dot_url != NULL && dot_url[0] != 0;
  if (twist_dns_plan_for (order, norder, have_doh, plan, 4, &np) != TWIST_OK)
    {
      cache_abort (cache, loop, host, !want_https && cache != NULL,
                   TWIST_ERR_INVAL);
      return TWIST_ERR_INVAL;
    }
  q = calloc (1, sizeof *q);
  if (q == NULL)
    {
      cache_abort (cache, loop, host, !want_https && cache != NULL, 
                   TWIST_ERR_NOMEM);
      return TWIST_ERR_NOMEM;
    }
  q->loop = loop;
  q->ttl_sec = 0xffffffffu;
  q->cache = !want_https ? cache : NULL;
  q->cache_lead = q->cache != NULL;
  q->host = twist_strdup (host);
  q->cb = cb;
  q->svc_cb = svc_cb;
  q->user = user;
  q->want_https = want_https;
  q->doh_verifypeer = doh_verifypeer;
  q->cainfo = cainfo;
  q->capath = capath;
  q->certfile = certfile;
  q->keyfile = keyfile;
  q->timeout_ms = timeout_ms;
  if (order != NULL && norder > 0)
    {
      size_t n = norder > 4 ? 4 : norder;

      memcpy (q->user_order, order, n * sizeof order[0]);
      q->user_order_n = (int) n;
    }
  if (have_doh)
    q->doh_text = twist_strdup (doh_url);
  if (have_doq)
    q->doq_text = twist_strdup (doq_url);
  if (have_dot)
    q->dot_text = twist_strdup (dot_url);
  if (q->host == NULL || (have_doh && q->doh_text == NULL)
      || (have_doq && q->doq_text == NULL) || (have_dot && q->dot_text == NULL))
    {
      cache_abort (q->cache, loop, host, q->cache_lead, TWIST_ERR_NOMEM);
      q->cache_lead = 0;
      dns_release (q);
      return TWIST_ERR_NOMEM;
    }
  memcpy (q->plan, plan, np * sizeof plan[0]);
  q->plan_n = (int) np;
  nameserver (&q->sin);
  rc = begin_plan (q);
  if (rc != TWIST_OK)
    {
      if (q->conn != NULL)
        twist_connection_free (q->conn);
      q->conn = NULL;
      rc = rc == TWIST_ERR_UNSUPPORTED ? TWIST_ERR_RESOLVE : rc;
      cache_abort (q->cache, loop, host, q->cache_lead, rc);
      q->cache_lead = 0;
      dns_release (q);
      return rc;
    }
  return TWIST_OK;
}

static struct twist_dns_cache *
loop_cache (struct twist_loop *loop)
{
  struct twist_multi *multi;

  if (loop == NULL)
    return NULL;
  multi = twist_loop_multi (loop);
  return multi != NULL ? multi->dns : NULL;
}

static struct twist_dns_cache *
easy_cache (const struct twist_easy *easy)
{
  if (easy->share != NULL && easy->share->dns != NULL)
    return easy->share->dns;
  return loop_cache (easy->loop);
}

int
twist_dns_resolve (struct twist_loop *loop, const char *host,
                   const int *order, size_t norder,
                   void (*cb) (void *, int, const struct twist_dns_addr *),
                   void *user)
{
  return resolve (loop, host, order, norder, 0, NULL, NULL, NULL, 1, NULL,
                  NULL, NULL, NULL, 0, loop_cache (loop), cb, NULL, user);
}

int
twist_dns_resolve_service (struct twist_loop *loop, const char *host,
                           const int *order, size_t norder,
                           void (*cb) (void *, int,
                                       const struct twist_dns_service *),
                           void *user)
{
  return resolve (loop, host, order, norder, 1, NULL, NULL, NULL, 1, NULL,
                  NULL, NULL, NULL, 0, NULL, NULL, cb, user);
}

/* A name is looked up within the time to connect, and no longer than the
   whole transfer may take.  */
static long
easy_timeout (const struct twist_easy *easy)
{
  if (easy->connect_timeout_ms > 0
      && (easy->timeout_ms <= 0 || easy->connect_timeout_ms < easy->timeout_ms))
    return easy->connect_timeout_ms;
  return easy->timeout_ms;
}

int
twist_dns_resolve_easy (struct twist_easy *easy, const char *host,
                        void (*cb) (void *, int, const struct twist_dns_addr *),
                        void *user)
{
  const int *order;
  size_t norder;

  if (easy == NULL)
    return TWIST_ERR_INVAL;
  order = easy->dns_order_n > 0 ? easy->dns_order : NULL;
  norder = easy->dns_order_n > 0 ? (size_t) easy->dns_order_n : 0;
  return resolve (easy->loop, host, order, norder, 0, easy->doh_url,
                  easy->doq_url, easy->dot_url, easy->doh_verifypeer,
                  easy->cainfo, easy->capath, easy->sslcert, easy->sslkey,
                  easy_timeout (easy), easy_cache (easy), cb, NULL, user);
}

int
twist_dns_resolve_service_easy (struct twist_easy *easy, const char *host,
                                void (*cb) (void *, int,
                                            const struct twist_dns_service *),
                                void *user)
{
  const int *order;
  size_t norder;

  if (easy == NULL)
    return TWIST_ERR_INVAL;
  order = easy->dns_order_n > 0 ? easy->dns_order : NULL;
  norder = easy->dns_order_n > 0 ? (size_t) easy->dns_order_n : 0;
  return resolve (easy->loop, host, order, norder, 1, easy->doh_url,
                  easy->doq_url, easy->dot_url, easy->doh_verifypeer,
                  easy->cainfo, easy->capath, easy->sslcert, easy->sslkey,
                  easy_timeout (easy), NULL, NULL, cb, user);
}
