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
#include <pthread.h>
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

/* The queries of one lookup: AAAA first, then A, then HTTPS when it is wanted.
   Over UDP, TCP and DoT they are all sent at once and are answered in any
   order, told apart by their ids.  Over DoQ (where every id is 0 and a stream
   is what tells them apart) and DoH they go one after another.  Whether the
   server will take them together in one message (RFC 10029) is not tried yet:
   none of the large public resolvers does.  */
#define MAX_SUBS 3
#define MAX_GOT 8

struct dns_sub
{
  int qtype;
  uint16_t id;
  uint8_t *pkt;
  size_t pktlen;
  int sent;
  int done;
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
  int want_https;
  /* The lookup proper: its queries, the addresses that have come ([0] IPv4,
     [1] IPv6) and the message being read, how many of each have been given to
     the sink, and the timers for the waiting.  */
  struct dns_sub sub[MAX_SUBS];
  int nsub;
  int cur_type;
  struct twist_dns_addr got[2][MAX_GOT];
  int ngot[2];
  struct twist_dns_addr tmp[2][MAX_GOT];
  int ntmp[2];
  int emitted[2];
  int released;
  int hold_elapsed;
  int linger_expired;
  int https_given;
  struct twist_timer *hold;
  struct twist_timer *linger;
  int use_sink;
  int cache_lists;              /* Keep the lists when it is done.  */
  struct twist_dns_sink sink;
  struct twist_dns_service https;
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
  /* The address of the resolver a DoT or DoQ resolver was discovered from, as
     text, when this one was: its certificate must be valid for that address
     too (RFC 9462, section 4.2).  Empty for a resolver the user named.  */
  char also_name[64];
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
static int have_addr (const struct dns_query *q);
static void progress (struct dns_query *q, struct twist_endpoint *ep);
static void give_addresses (struct dns_query *q);
static struct dns_sub *sub_of (struct dns_query *q, int qtype);

/* The first address a caller that takes one is given: an IPv4 one, so that a
   path that cannot be had does not stop what always worked, or else an IPv6
   one.  */
static int
first_address (const struct dns_query *q, struct twist_dns_addr *out)
{
  if (q->ngot[0] > 0)
    *out = q->got[0][0];
  else if (q->ngot[1] > 0)
    *out = q->got[1][0];
  else
    return 0;
  return 1;
}

static void
dns_finish (struct dns_query *q, int err)
{
  struct twist_loop *loop;
  int i;

  if (q->done)
    return;
  q->done = 1;
  if (q->hold != NULL)
    {
      twist_timer_cancel (q->hold);
      q->hold = NULL;
    }
  if (q->linger != NULL)
    {
      twist_timer_cancel (q->linger);
      q->linger = NULL;
    }
  /* What was learned is an answer, though a query went wrong after it.  */
  if (have_addr (q))
    err = TWIST_OK;
  if (q->use_sink)
    {
      /* Whatever was not given, and then what was not answered, and last.  */
      if (err == TWIST_OK)
        give_addresses (q);
      /* What was answered is kept, so that the next lookup does not ask.  A
         type that was not answered is not: that is not "none".  */
      if (q->cache_lists && q->cache != NULL && q->loop != NULL)
        {
          uint32_t ttl = q->ttl_sec == 0xffffffffu ? 0 : q->ttl_sec;
          struct dns_sub *a4 = sub_of (q, 1), *a6 = sub_of (q, 28);

          if (a6 != NULL && a6->done)
            twist_dns_cache_keep (q->cache, q->host, 28, q->got[1],
                                  q->ngot[1], ttl, twist_loop_now (q->loop));
          if (a4 != NULL && a4->done)
            twist_dns_cache_keep (q->cache, q->host, 1, q->got[0],
                                  q->ngot[0], ttl, twist_loop_now (q->loop));
        }
      for (i = 0; i < q->nsub; i++)
        if (!q->sub[i].done && q->sink.type_error != NULL)
          q->sink.type_error (q->sink.user, q->sub[i].qtype,
                              err != TWIST_OK ? err : TWIST_ERR_TIMEOUT);
      if (q->sink.complete != NULL)
        q->sink.complete (q->sink.user, err);
    }
  else
    {
      if (err == TWIST_OK)
        {
          struct twist_dns_addr first;

          if (first_address (q, &first))
            q->svc.addr = first;
          q->svc.nalpn = q->https.nalpn;
          memcpy (q->svc.alpn, q->https.alpn, sizeof q->svc.alpn);
          q->svc.port = q->https.port;
          q->svc.have_https = q->https.have_https;
        }
      if (q->cache_lead && q->cache != NULL)
        {
          uint32_t ttl = q->ttl_sec == 0xffffffffu ? 0 : q->ttl_sec;

          q->cache_lead = 0;
          twist_dns_cache_end (q->cache, q->loop, q->host, 1,
                               err, err == TWIST_OK ? &q->svc.addr : NULL, ttl,
                               twist_loop_now (q->loop));
        }
      if (q->svc_cb != NULL)
        q->svc_cb (q->user, err, err == TWIST_OK ? &q->svc : NULL);
      else if (q->cb != NULL)
        q->cb (q->user, err, err == TWIST_OK ? &q->svc.addr : NULL);
    }
  loop = q->loop;
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
  int i;

  for (i = 0; i < q->nsub; i++)
    free (q->sub[i].pkt);
  if (q->hold != NULL)
    twist_timer_cancel (q->hold);
  if (q->linger != NULL)
    twist_timer_cancel (q->linger);
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

/* The nameserver is read from resolv.conf and kept, and read again when the
   file changes.  Loops on several threads ask for it; the lock covers the
   check and the read, and nothing is called with it held.  */
static pthread_mutex_t ns_lock = PTHREAD_MUTEX_INITIALIZER;
static struct sockaddr_in ns_addr;
static time_t ns_mtime;
static int ns_ready;

static int nameserver_locked (struct sockaddr_in *sin);

static int
nameserver (struct sockaddr_in *sin)
{
  int rc;

  pthread_mutex_lock (&ns_lock);
  rc = nameserver_locked (sin);
  pthread_mutex_unlock (&ns_lock);
  return rc;
}

static struct sockaddr_in ns_forced;
static int ns_forced_set;

void
twist_dns_set_nameserver (const char *ip, int port)
{
  pthread_mutex_lock (&ns_lock);
  ns_forced_set = 0;
  if (ip != NULL)
    {
      memset (&ns_forced, 0, sizeof ns_forced);
      ns_forced.sin_family = AF_INET;
      ns_forced.sin_port = htons ((uint16_t) (port > 0 ? port : 53));
      ns_forced_set = inet_pton (AF_INET, ip, &ns_forced.sin_addr) == 1;
    }
  pthread_mutex_unlock (&ns_lock);
}

static int
nameserver_locked (struct sockaddr_in *sin)
{
  FILE *fp;
  char line[256];
  struct stat st;
  int have;

  if (ns_forced_set)
    {
      *sin = ns_forced;
      return TWIST_OK;
    }
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
static struct dns_sub *
sub_of (struct dns_query *q, int qtype)
{
  int i;

  for (i = 0; i < q->nsub; i++)
    if (q->sub[i].qtype == qtype)
      return &q->sub[i];
  return NULL;
}

static int
have_addr (const struct dns_query *q)
{
  return q->ngot[0] + q->ngot[1] > 0;
}

/* The queries: AAAA, A, and HTTPS if it is wanted, each with an id of its own.  */
static int
ensure_subs (struct dns_query *q)
{
  static const int order[3] = { 28, 1, 65 };
  int i, j;

  if (q->nsub > 0)
    return TWIST_OK;
  for (i = 0; i < 3; i++)
    {
      struct dns_sub *s;

      if (order[i] == 65 && !q->want_https)
        continue;
      s = &q->sub[q->nsub];
      s->qtype = order[i];
      do
        {
          if (random_id (&s->id) != TWIST_OK)
            return TWIST_ERR_RESOLVE;
          for (j = 0; j < q->nsub && q->sub[j].id != s->id; j++)
            ;
        }
      while (j < q->nsub);
      if (twist_dns_encode_query (q->host, s->qtype, s->id, &s->pkt,
                                  &s->pktlen) != TWIST_OK)
        return TWIST_ERR_RESOLVE;
      q->nsub++;
    }
  return TWIST_OK;
}
/* Send one of the queries.  Returns TWIST_OK, or why it could not be.  */
static int
send_one (struct dns_query *q, struct twist_endpoint *ep, struct dns_sub *sub)
{
  uint8_t *frame = NULL;
  const uint8_t *data;
  size_t len;
  int rc;

  if (q->doq && q->doq_sent && twist_quic_open_stream (q->conn) != TWIST_OK)
    return TWIST_ERR_TLS;
  sub->sent = 1;
  if (q->doq)
    q->doq_sent = 1;
  if (q->doh)
    {
      uint8_t *http = NULL;
      size_t hn = 0;

      rc = twist_doh_encode_url (q->doh_text, sub->pkt, sub->pktlen, &http, &hn);
      if (rc == TWIST_OK && twist_endpoint_send (ep, http, hn) != TWIST_OK)
        rc = TWIST_ERR_RESOLVE;
      free (http);
      return rc;
    }
  if (q->tcp || q->doq)
    {
      rc = twist_dns_frame_stream (sub->pkt, sub->pktlen, q->doq, &frame, &len);
      if (rc != TWIST_OK)
        return rc;
      data = frame;
    }
  else
    {
      data = sub->pkt;
      len = sub->pktlen;
    }
  rc = twist_endpoint_send (ep, data, len) == TWIST_OK ? TWIST_OK
                                                       : TWIST_ERR_RESOLVE;
  free (frame);
  return rc;
}

/* Send what is to be sent.  Over UDP, TCP and DoT that is all of it, at once:
   the answers are told apart by their ids, and they come in one round trip.
   Over DoQ and DoH the next is sent when the one before has been answered.  */
static void
send_subs (struct dns_query *q, struct twist_endpoint *ep)
{
  int sequential = q->doq || q->doh;
  int i;

  if (ensure_subs (q) != TWIST_OK)
    {
      dns_finish (q, TWIST_ERR_RESOLVE);
      return;
    }
  for (i = 0; i < q->nsub && !q->done; i++)
    {
      struct dns_sub *sub = &q->sub[i];
      int j, waiting = 0, rc;

      if (sub->sent || sub->done)
        continue;
      for (j = 0; j < q->nsub; j++)
        if (q->sub[j].sent && !q->sub[j].done)
          waiting = 1;
      if (sequential && waiting)
        break;
      rc = send_one (q, ep, sub);
      if (rc != TWIST_OK)
        {
          /* This one is lost.  The others go on, and so does what has been
             learned: a query that fails gives nothing but its own error.  */
          sub->done = 1;
          if (q->use_sink && q->sink.type_error != NULL)
            q->sink.type_error (q->sink.user, sub->qtype, rc);
          if (!have_addr (q) && sub->qtype != 65)
            {
              int all = 1;

              for (j = 0; j < q->nsub; j++)
                if (!q->sub[j].done && q->sub[j].qtype != 65)
                  all = 0;
              if (all)
                {
                  dns_finish (q, rc);
                  return;
                }
            }
        }
    }
}


static void
dns_send (struct twist_endpoint *ep)
{
  struct dns_query *q = ep->user_data;
  uint8_t *frame = NULL;
  const uint8_t *data;
  size_t len;

  if (q->done || (q->ddr && q->sent))
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
  send_subs (q, ep);
}
/* Only the records of the type that was asked of are taken: the answer to an
   A query can have, with a CNAME chain, anything.  They are kept for the
   message, and taken in when it is known to be whole (not truncated).  */
static void
on_addr (void *user, const struct twist_dns_addr *addr)
{
  struct dns_query *q = user;
  int f;

  if (q->ddr || (addr->family != 4 && addr->family != 6))
    return;
  if ((q->cur_type == 1 && addr->family != 4)
      || (q->cur_type == 28 && addr->family != 6) || q->cur_type == 65)
    return;
  f = addr->family == 6;
  if (q->ntmp[f] < MAX_GOT)
    q->tmp[f][q->ntmp[f]++] = *addr;
}

static void
commit_message (struct dns_query *q)
{
  int f, i, j;

  for (f = 0; f < 2; f++)
    for (i = 0; i < q->ntmp[f]; i++)
      {
        for (j = 0; j < q->ngot[f]; j++)
          if (strcmp (q->got[f][j].text, q->tmp[f][i].text) == 0)
            break;
        if (j == q->ngot[f] && q->ngot[f] < MAX_GOT)
          q->got[f][q->ngot[f]++] = q->tmp[f][i];
      }
}
static void
on_alpn (void *user, const char *id, size_t len)
{
  struct dns_query *q = user;

  if (q->cur_type != 65 || q->https.nalpn >= 4 || len == 0 || len >= 16)
    return;
  memcpy (q->https.alpn[q->https.nalpn], id, len);
  q->https.alpn[q->https.nalpn][len] = 0;
  q->https.nalpn++;
}
static void
on_port (void *user, int port)
{
  struct dns_query *q = user;

  if (q->cur_type == 65 && port > 0 && port < 65536)
    q->https.port = port;
}
static void
on_https (void *user)
{
  struct dns_query *q = user;

  if (q->cur_type == 65)
    q->https.have_https = 1;
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
/* IPv6 first, then the families taking turns (RFC 8305, section 4), each in the
   order it was given.  */
size_t
twist_dns_sort (struct twist_dns_addr *addrs, size_t n)
{
  struct twist_dns_addr v6[32], v4[32];
  size_t n6 = 0, n4 = 0, i = 0, j = 0, k = 0;

  if (addrs == NULL || n > 32)
    return n;
  for (i = 0; i < n; i++)
    if (addrs[i].family == 6)
      v6[n6++] = addrs[i];
    else
      v4[n4++] = addrs[i];
  i = j = 0;
  while (i < n6 || j < n4)
    {
      if (i < n6)
        addrs[k++] = v6[i++];
      if (j < n4)
        addrs[k++] = v4[j++];
    }
  return n;
}

/* Give the sink the addresses it has not been given, in the order to try them
   in.  The first call is the release of the first addresses.  */
static void
give_addresses (struct dns_query *q)
{
  struct twist_dns_addr list[2 * MAX_GOT];
  size_t n = 0, i;
  int f;

  if (!q->use_sink || (q->emitted[0] >= q->ngot[0] && q->emitted[1] >= q->ngot[1]))
    return;
  for (f = 1; f >= 0; f--)
    for (i = (size_t) q->emitted[f]; i < (size_t) q->ngot[f]; i++)
      list[n++] = q->got[f][i];
  q->emitted[0] = q->ngot[0];
  q->emitted[1] = q->ngot[1];
  q->released = 1;
  twist_dns_sort (list, n);
  for (i = 0; i < n && q->sink.address != NULL; i++)
    q->sink.address (q->sink.user, &list[i]);
}

static long resolution_delay_ms = 50;
static long linger_ms = 2000;

void
twist_dns_set_timing (long delay_ms, long linger)
{
  resolution_delay_ms = delay_ms > 0 ? delay_ms : 50;
  linger_ms = linger > 0 ? linger : 2000;
}

static void
hold_cb (void *user)
{
  struct dns_query *q = user;

  q->hold = NULL;
  q->hold_elapsed = 1;
  if (!q->done)
    progress (q, NULL);
}

/* Waited long enough for the rest: what has come is what there is.  */
static void
linger_cb (void *user)
{
  struct dns_query *q = user;

  q->linger = NULL;
  q->linger_expired = 1;
  if (!q->done)
    dns_finish (q, have_addr (q) ? TWIST_OK : TWIST_ERR_TIMEOUT);
}

/* Something has come, or the time has passed: say what can be said.  With a
   sink (RFC 8305): AAAA addresses are given at once; A addresses are given when
   AAAA has been answered, or its resolution delay after A has passed; more that
   come after are given as they come; HTTPS when it is in; and complete when all
   is answered.  Without one the single address that is wanted is given when it
   can be known: IPv4 when the delay has passed, so nothing waits long for an
   IPv6 answer that may not come.  */
static void
progress (struct dns_query *q, struct twist_endpoint *ep)
{
  struct dns_sub *a4 = sub_of (q, 1);
  struct dns_sub *a6 = sub_of (q, 28);
  struct dns_sub *hs = sub_of (q, 65);
  int a4_has = a4 != NULL && a4->done && q->ngot[0] > 0;
  int pending = (a4 != NULL && !a4->done) || (a6 != NULL && !a6->done);
  int i, unsent = 0;

  if (q->done)
    return;
  /* The first address begins the wait for the rest.  */
  if (have_addr (q) && q->linger == NULL && !q->linger_expired
      && q->loop != NULL)
    twist_loop_schedule (q->loop, twist_loop_now (q->loop) + (uint64_t) linger_ms,
                         linger_cb, q, &q->linger);
  /* A has addresses and AAAA has not been answered: a short wait for it.  */
  if (a4_has && a6 != NULL && !a6->done && !q->hold_elapsed && q->hold == NULL
      && q->loop != NULL)
    twist_loop_schedule (q->loop,
                         twist_loop_now (q->loop) + (uint64_t) resolution_delay_ms,
                         hold_cb, q, &q->hold);
  if (q->use_sink)
    {
      if (q->ngot[1] > 0 || (a4_has && (a6 == NULL || a6->done || q->hold_elapsed)))
        give_addresses (q);
      if (hs != NULL && hs->done && !q->https_given)
        {
          q->https_given = 1;
          if (q->https.have_https && q->sink.https != NULL)
            q->sink.https (q->sink.user, &q->https);
        }
      if (!pending && !have_addr (q))
        {
          dns_finish (q, TWIST_ERR_RESOLVE);
          return;
        }
      if (!pending && (hs == NULL || hs->done))
        {
          dns_finish (q, TWIST_OK);
          return;
        }
    }
  else
    {
      int ready = !pending || (a4_has && q->hold_elapsed);

      if (ready && (!have_addr (q) || hs == NULL || hs->done))
        {
          dns_finish (q, have_addr (q) ? TWIST_OK : TWIST_ERR_RESOLVE);
          return;
        }
    }
  /* DoQ and DoH have one query out at a time: the next goes now.  */
  for (i = 0; i < q->nsub; i++)
    if (!q->sub[i].sent && !q->sub[i].done)
      unsent = 1;
  if (unsent && (q->doq || q->doh) && (ep != NULL || q->ep != NULL))
    dns_send (ep != NULL ? ep : q->ep);
}

/* A query has been answered, or has failed with ERR: take what came, say what
   is to be said, and go on.  */
static void
sub_answered (struct dns_query *q, struct dns_sub *s, struct twist_endpoint *ep)
{
  int got = q->ntmp[0] + q->ntmp[1];

  q->answered = 1;
  /* Truncated over UDP: all that is not answered goes again over TCP.  */
  if (q->saw_tc && !q->tcp && !q->doh && !q->dot && !q->doq)
    {
      q->saw_tc = 0;
      q->ntmp[0] = q->ntmp[1] = 0;
      if (q->loop != NULL)
        twist_loop_post (q->loop, dns_switch_tcp, q);
      else
        dns_finish (q, TWIST_ERR_RESOLVE);
      return;
    }
  s->done = 1;
  if (q->parse_err == TWIST_OK)
    commit_message (q);
  if (q->use_sink && q->sink.type_error != NULL)
    {
      if (q->parse_err != TWIST_OK)
        q->sink.type_error (q->sink.user, s->qtype, q->parse_err);
      else if (s->qtype != 65 && got == 0)
        q->sink.type_error (q->sink.user, s->qtype, TWIST_ERR_RESOLVE);
      else if (s->qtype == 65 && !q->https.have_https)
        q->sink.type_error (q->sink.user, s->qtype, TWIST_ERR_RESOLVE);
    }
  progress (q, ep);
}

/* The query that a message answers, or NULL.  */
static struct dns_sub *
match_sub (struct dns_query *q, const uint8_t *msg, size_t len)
{
  int i;

  for (i = 0; i < q->nsub; i++)
    {
      struct dns_sub *s = &q->sub[i];

      if (!s->sent || s->done)
        continue;
      if (twist_dns_response_ok (msg, len, q->doq ? 0 : s->id, q->host))
        return s;
    }
  return NULL;
}
/* A discovery (DDR) answer: only that, and only here.  */
static void
advance (struct dns_query *q, struct twist_endpoint *ep)
{
  (void) ep;
  if (q->saw_tc && !q->tcp)
    {
      q->saw_tc = 0;
      twist_loop_post (q->loop, dns_switch_tcp, q);
      return;
    }
  q->ddr = 0;
  q->ddr_done = 1;
  twist_loop_post (q->loop, after_ddr, q);
}
static size_t
dns_receive (struct twist_endpoint *ep, const uint8_t *data, size_t len)
{
  struct dns_query *q = ep->user_data;
  struct twist_dns_events ev;
  struct dns_sub *s = NULL;
  size_t n;

  if (q->done || q->switching)
    return len;
  q->saw_tc = 0;
  q->parse_err = TWIST_OK;
  q->ntmp[0] = q->ntmp[1] = 0;
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
      if (q->ddr)
        {
          if (!response_matches (q, data + 2, need))
            return 2 + need;
        }
      else
        {
          s = match_sub (q, data + 2, need);
          if (s == NULL)
            return 2 + need;
          q->cur_type = s->qtype;
        }
      n = twist_dns_stream_receive (data, len, &ev);
    }
  else
    {
      if (q->ddr)
        {
          if (!response_matches (q, data, len))
            return len;
        }
      else
        {
          s = match_sub (q, data, len);
          if (s == NULL)
            return len;
          q->cur_type = s->qtype;
        }
      n = twist_dns_datagram_receive (data, len, &ev);
    }
  if (n == 0)
    return 0;
  if (q->ddr)
    advance (q, ep);
  else
    sub_answered (q, s, ep);
  return n;
}
static void
dns_disconnected (struct twist_endpoint *ep, int error)
{
  struct dns_query *q = ep->user_data;

  if (q->switching || q->done)
    return;
  /* What was learned before the connection went is an answer.  */
  if (have_addr (q))
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
  int i;

  if (q->done)
    return;
  q->switching = 1;
  c = q->conn;
  q->conn = NULL;
  if (c != NULL)
    twist_connection_free (c);
  q->switching = 0;
  /* What was not answered over UDP is asked again over TCP.  */
  for (i = 0; i < q->nsub; i++)
    if (!q->sub[i].done)
      q->sub[i].sent = 0;
  if (open_tcp (q) != TWIST_OK)
    dns_finish (q, TWIST_ERR_RESOLVE);
}
static void
on_doh_msg (void *user, int err, const uint8_t *msg, size_t len)
{
  struct dns_query *q = user;
  struct twist_dns_events ev;
  struct dns_sub *s;

  if (q->done)
    return;
  if (err != TWIST_OK)
    {
      dns_finish (q, err);
      return;
    }
  q->saw_tc = 0;
  q->parse_err = TWIST_OK;
  q->ntmp[0] = q->ntmp[1] = 0;
  memset (&ev, 0, sizeof ev);
  ev.user = q;
  ev.address = on_addr;
  ev.https_alpn = on_alpn;
  ev.https_port = on_port;
  ev.https_rr = on_https;
  ev.truncated = on_trunc;
  ev.failure = on_fail;
  ev.ttl = on_ttl;
  s = match_sub (q, msg, len);
  if (s == NULL)
    {
      dns_finish (q, TWIST_ERR_PROTOCOL);
      return;
    }
  q->cur_type = s->qtype;
  if (twist_dns_datagram_receive (msg, len, &ev) == 0)
    {
      dns_finish (q, TWIST_ERR_PROTOCOL);
      return;
    }
  sub_answered (q, s, q->ep);
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
  int i;

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
  for (i = 0; i < q->nsub; i++)
    if (!q->sub[i].done)
      q->sub[i].sent = 0;
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
  rc = twist_connection_require_name (q->conn,
                                      q->also_name[0] != 0 ? q->also_name
                                                           : NULL);
  if (rc == TWIST_OK)
    rc = twist_connection_start_tls (q->conn, q->peer_name, 1, alpn, 1,
                                     q->cainfo, q->capath, q->certfile,
                                     q->keyfile);
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

/* What a resolver found by discovery has to prove besides its own name:
   that it speaks for the resolver the discovery was asked of.  That was asked
   over plain UDP, so anyone who can answer it can name a resolver of their
   own, with a certificate for that name.  What they cannot have is a
   certificate for the address that was asked.  A resolver the user named has
   no second name.  */
static void
require_asked_address (struct dns_query *q, int discovered)
{
  q->also_name[0] = 0;
  if (discovered
      && inet_ntop (AF_INET, &q->sin.sin_addr, q->also_name,
                    sizeof q->also_name) == NULL)
    q->also_name[0] = 0;
}

static int
connect_doq (struct dns_query *q, const struct twist_dns_addr *addr, int port,
             const char *name, int discovered)
{
  struct twist_connection *conn = NULL;
  struct twist_endpoint *ep;
  struct twist_quic_opts opts;
  int rc;

  rc = remember_peer (q, name, addr, port);
  if (rc != TWIST_OK)
    return rc;
  require_asked_address (q, discovered);
  memset (&opts, 0, sizeof opts);
  opts.also_name = q->also_name[0] != 0 ? q->also_name : NULL;
  rc = twist_quic_dial (q->loop, q->peer_name, "doq", addr, port, q->cainfo, q->capath,
                        q->certfile, q->keyfile, 1, &opts, &conn);
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
             const char *name, int discovered)
{
  int rc = remember_peer (q, name, addr, port);

  if (rc != TWIST_OK)
    return rc;
  require_asked_address (q, discovered);
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
        rc = connect_doq (q, addr, q->doq_parsed->port, q->doq_parsed->host, 0);
      else if (q->boot == TWIST_DNS_DOT && q->dot_parsed != NULL)
        rc = connect_dot (q, addr, q->dot_parsed->port, q->dot_parsed->host, 0);
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
                            q->doq_parsed->host, 0);
      q->boot = TWIST_DNS_DOQ;
      return twist_dns_resolve (q->loop, q->doq_parsed->host, &udp, 1,
                                on_resolver_addr, q);
    }
  if (!q->ddr_done)
    return start_ddr (q);
  if (!q->ddr_doq)
    return TWIST_ERR_UNSUPPORTED;
  return connect_doq (q, &q->ddr_doq_addr, q->ddr_doq_port, q->ddr_doq_name,
                      1);
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
                            q->dot_parsed->host, 0);
      q->boot = TWIST_DNS_DOT;
      return twist_dns_resolve (q->loop, q->dot_parsed->host, &udp, 1,
                                on_resolver_addr, q);
    }
  if (!q->ddr_done)
    return start_ddr (q);
  if (!q->ddr_dot)
    return TWIST_ERR_UNSUPPORTED;
  return connect_dot (q, &q->ddr_dot_addr, q->ddr_dot_port, q->ddr_dot_name,
                      1);
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
    rc = connect_doq (q, &q->ddr_doq_addr, q->ddr_doq_port, q->ddr_doq_name,
                      1);
  else if (cur == TWIST_DNS_DOT && q->ddr_dot)
    rc = connect_dot (q, &q->ddr_dot_addr, q->ddr_dot_port, q->ddr_dot_name,
                      1);
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

int
twist_dns_literal (const char *host, struct twist_dns_addr *out)
{
  struct twist_dns_service svc;

  if (literal (host, &svc) != 1)
    return 0;
  *out = svc.addr;
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

/* An answer that needs no query: to the sink, the address and complete; to a
   caller that takes one, the one.  */
static void
deliver_now (const struct twist_dns_sink *sink,
             void (*svc_cb) (void *, int, const struct twist_dns_service *),
             void (*cb) (void *, int, const struct twist_dns_addr *),
             void *user, const struct twist_dns_service *svc)
{
  if (sink != NULL)
    {
      if (sink->address != NULL)
        sink->address (sink->user, &svc->addr);
      if (sink->complete != NULL)
        sink->complete (sink->user, TWIST_OK);
    }
  else if (svc_cb != NULL)
    svc_cb (user, TWIST_OK, svc);
  else
    cb (user, TWIST_OK, &svc->addr);
}

static int
resolve (struct twist_loop *loop, const char *host, const int *order,
         size_t norder, int want_https, const char *doh_url,
         const char *doq_url, const char *dot_url, int doh_verifypeer,
         const char *cainfo, const char *capath, const char *certfile,
         const char *keyfile, long timeout_ms, struct twist_dns_cache *cache,
         void (*cb) (void *, int, const struct twist_dns_addr *),
         void (*svc_cb) (void *, int, const struct twist_dns_service *),
         const struct twist_dns_sink *sink, void *user)
{
  struct dns_query *q;
  struct twist_dns_service lit;
  int plan[4];
  size_t np = 0;
  int have_doh;
  int have_doq;
  int have_dot;
  int rc;

  if (host == NULL || (cb == NULL && svc_cb == NULL && sink == NULL))
    return TWIST_ERR_INVAL;
  rc = literal (host, &lit);
  if (rc == -2)
    return TWIST_ERR_CONNECT;
  if (rc < 0)
    return TWIST_ERR_RESOLVE;
  if (rc == 1)
    {
      deliver_now (sink, svc_cb, cb, user, &lit);
      return TWIST_OK;
    }
  /* A name that this machine knows, from its hosts file, or that is its own
     (localhost): answered here, at once, before the cache and before any
     network, as an address is.  */
  if (sink != NULL)
    {
      /* The sink is given each family the machine knows the name by.  */
      struct twist_dns_addr both[2];
      int nb = twist_hosts_lookup_all (NULL, host, both);
      int i;

      if (nb == 0)
        nb = twist_dns_local_addrs (host, both);
      if (nb > 0)
        {
          for (i = 0; i < nb; i++)
            if (sink->address != NULL)
              sink->address (sink->user, &both[i]);
          if (sink->complete != NULL)
            sink->complete (sink->user, TWIST_OK);
          return TWIST_OK;
        }
    }
  if (twist_hosts_lookup (NULL, host, &lit.addr) == 1
      || twist_dns_local_name (host, &lit.addr) == 1)
    {
      struct twist_dns_addr found = lit.addr;

      memset (&lit, 0, sizeof lit);
      lit.addr = found;
      deliver_now (sink, svc_cb, cb, user, &lit);
      return TWIST_OK;
    }
  if (loop == NULL)
    return TWIST_ERR_INVAL;
  if (sink != NULL && !want_https && cache != NULL)
    {
      /* Both lists are kept (a list may be kept as empty): then there is
         nothing to ask.  */
      struct twist_dns_addr l6[MAX_GOT], l4[MAX_GOT], all[2 * MAX_GOT];
      uint64_t now = twist_loop_now (loop);
      int n6 = twist_dns_cache_list (cache, host, 28, l6, MAX_GOT, now);
      int n4 = twist_dns_cache_list (cache, host, 1, l4, MAX_GOT, now);

      if (n6 >= 0 && n4 >= 0)
        {
          size_t n = 0, i;

          for (i = 0; i < (size_t) n6; i++)
            all[n++] = l6[i];
          for (i = 0; i < (size_t) n4; i++)
            all[n++] = l4[i];
          twist_dns_sort (all, n);
          for (i = 0; i < n && sink->address != NULL; i++)
            sink->address (sink->user, &all[i]);
          if (n == 0)
            {
              if (sink->type_error != NULL)
                {
                  sink->type_error (sink->user, 28, TWIST_ERR_RESOLVE);
                  sink->type_error (sink->user, 1, TWIST_ERR_RESOLVE);
                }
            }
          if (sink->complete != NULL)
            sink->complete (sink->user, n > 0 ? TWIST_OK : TWIST_ERR_RESOLVE);
          return TWIST_OK;
        }
    }
  if (!want_https && cache != NULL && cb != NULL && sink == NULL)
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
  if (twist_dns_plan_for (order, norder, have_doh, have_doq, have_dot, plan, 4,
                          &np) != TWIST_OK)
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
  q->cache_lead = q->cache != NULL && sink == NULL;
  q->cache_lists = q->cache != NULL && sink != NULL;
  q->host = twist_strdup (host);
  q->cb = cb;
  q->svc_cb = svc_cb;
  q->user = user;
  if (sink != NULL)
    {
      q->use_sink = 1;
      q->sink = *sink;
    }
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
  struct twist_runtime *runtime;

  if (loop == NULL)
    return NULL;
  runtime = twist_loop_runtime (loop);
  return runtime != NULL ? runtime->dns : NULL;
}

static struct twist_dns_cache *
transfer_cache (const struct twist_transfer *transfer)
{
  return loop_cache (transfer->loop);
}

int
twist_dns_resolve (struct twist_loop *loop, const char *host,
                   const int *order, size_t norder,
                   void (*cb) (void *, int, const struct twist_dns_addr *),
                   void *user)
{
  return resolve (loop, host, order, norder, 0, NULL, NULL, NULL, 1, NULL,
                  NULL, NULL, NULL, 0, loop_cache (loop), cb, NULL, NULL, user);
}

int
twist_dns_resolve_service (struct twist_loop *loop, const char *host,
                           const int *order, size_t norder,
                           void (*cb) (void *, int,
                                       const struct twist_dns_service *),
                           void *user)
{
  return resolve (loop, host, order, norder, 1, NULL, NULL, NULL, 1, NULL,
                  NULL, NULL, NULL, 0, NULL, NULL, cb, NULL, user);
}

/* A name is looked up within the time to connect, and no longer than the
   whole transfer may take.  */
static long
transfer_timeout (const struct twist_transfer *transfer)
{
  if (transfer->connect_timeout_ms > 0
      && (transfer->timeout_ms <= 0 || transfer->connect_timeout_ms < transfer->timeout_ms))
    return transfer->connect_timeout_ms;
  return transfer->timeout_ms;
}

int
twist_dns_resolve_transfer (struct twist_transfer *transfer, const char *host,
                            void (*cb) (void *, int, const struct twist_dns_addr *),
                            void *user)
{
  const int *order;
  size_t norder;

  if (transfer == NULL)
    return TWIST_ERR_INVAL;
  order = transfer->dns_order_n > 0 ? transfer->dns_order : NULL;
  norder = transfer->dns_order_n > 0 ? (size_t) transfer->dns_order_n : 0;
  return resolve (transfer->loop, host, order, norder, 0, transfer->doh_url,
                  transfer->doq_url, transfer->dot_url,
                  transfer->doh_verifypeer,
                  transfer->cainfo, transfer->capath, transfer->sslcert,
                  transfer->sslkey,
                  transfer_timeout (transfer), transfer_cache (transfer), cb,
                  NULL, NULL, user);
}

int
twist_dns_resolve_service_transfer (struct twist_transfer *transfer,
                                    const char *host,
                                    void (*cb) (void *, int,
                                                const struct
                                                twist_dns_service *),
                                    void *user)
{
  const int *order;
  size_t norder;

  if (transfer == NULL)
    return TWIST_ERR_INVAL;
  order = transfer->dns_order_n > 0 ? transfer->dns_order : NULL;
  norder = transfer->dns_order_n > 0 ? (size_t) transfer->dns_order_n : 0;
  return resolve (transfer->loop, host, order, norder, 1, transfer->doh_url,
                  transfer->doq_url, transfer->dot_url,
                  transfer->doh_verifypeer,
                  transfer->cainfo, transfer->capath, transfer->sslcert,
                  transfer->sslkey,
                  transfer_timeout (transfer), NULL, NULL, cb, NULL, user);
}

int
twist_dns_resolve_sink (struct twist_loop *loop, const char *host,
                        const int *order, size_t norder, int want_https,
                        struct twist_dns_cache *cache,
                        const struct twist_dns_sink *sink)
{
  if (sink == NULL)
    return TWIST_ERR_INVAL;
  return resolve (loop, host, order, norder, want_https, NULL, NULL, NULL, 1, NULL,
                  NULL, NULL, NULL, 0, cache, NULL, NULL, sink, NULL);
}

int
twist_dns_resolve_sink_transfer (struct twist_transfer *transfer,
                                 const char *host, int want_https,
                                 const struct twist_dns_sink *sink)
{
  const int *order;
  size_t norder;

  if (transfer == NULL || sink == NULL)
    return TWIST_ERR_INVAL;
  order = transfer->dns_order_n > 0 ? transfer->dns_order : NULL;
  norder = transfer->dns_order_n > 0 ? (size_t) transfer->dns_order_n : 0;
  return resolve (transfer->loop, host, order, norder, want_https,
                  transfer->doh_url, transfer->doq_url, transfer->dot_url,
                  transfer->doh_verifypeer, transfer->cainfo, transfer->capath,
                  transfer->sslcert, transfer->sslkey,
                  transfer_timeout (transfer),
                  want_https ? NULL : transfer_cache (transfer), NULL, NULL,
                  sink, NULL);
}
