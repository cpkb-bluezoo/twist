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
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

/* The resolver asks for a name's IPv6 and IPv4 addresses, and its HTTPS record
   if it is wanted, all at once, as separate queries in one flight, and gives
   what it gets as it gets it: IPv6 first, and the families taking turns, as
   RFC 8305 says.  A nameserver here, on the loopback, answers the way a test
   says: at once, late, never, with nothing, or with an error, for each type of
   query; and writes down which came when.  */

static double
now_ms (void)
{
  struct timespec t;

  clock_gettime (CLOCK_MONOTONIC, &t);
  return (double) t.tv_sec * 1000.0 + (double) t.tv_nsec / 1e6;
}

/* How the fake answers a type: */
enum { ANSWER = 0, DROP, NODATA, NXDOMAIN };

struct ns_cfg
{
  int mode;
  int delay_ms;
  int naddr;
  uint8_t addr[4][16];      /* IPv4 in the first four bytes.  */
  int port;                 /* HTTPS: the port parameter, or 0.  */
  const char *alpn;         /* HTTPS: one ALPN id, or NULL.  */
};

struct pending
{
  double due;
  int index;
  size_t len;
  uint8_t msg[512];
  struct sockaddr_in peer;
  socklen_t peerlen;
  int used;
};

struct fake_ns
{
  int fd;
  int port;
  pthread_t thread;
  volatile int stop;
  struct ns_cfg cfg[3];     /* A, AAAA, HTTPS.  */
  int gate;                 /* Answer nothing until this many have come.  */
  pthread_mutex_t mu;
  int nq;
  int qtype[32];
  double at[32];
  int at_first_answer;      /* How many had come when the first was sent.  */
  double first_answer;
  struct pending pend[16];
};

static int
type_index (int qtype)
{
  return qtype == 1 ? 0 : qtype == 28 ? 1 : 2;
}

static size_t
build_answer (const struct fake_ns *ns, const struct pending *p, int qtype,
              uint8_t *out)
{
  const struct ns_cfg *c = &ns->cfg[type_index (qtype)];
  size_t qlen = p->len - 12;
  size_t n = 0;
  int i;
  int an = 0;

  memcpy (out, p->msg, 12 + qlen);
  out[2] = 0x81;
  out[3] = 0x80;
  if (c->mode == NXDOMAIN)
    out[3] |= 3;
  out[6] = out[7] = 0;
  n = 12 + qlen;
  if (c->mode == ANSWER)
    {
      if (qtype == 65)
        {
          uint8_t rd[64];
          size_t r = 0;
          size_t alen = c->alpn != NULL ? strlen (c->alpn) : 0;

          rd[r++] = 0; rd[r++] = 1;     /* priority 1 */
          rd[r++] = 0;                  /* target: the owner */
          if (alen > 0)
            {
              rd[r++] = 0; rd[r++] = 1;
              rd[r++] = 0; rd[r++] = (uint8_t) (alen + 1);
              rd[r++] = (uint8_t) alen;
              memcpy (rd + r, c->alpn, alen);
              r += alen;
            }
          if (c->port != 0)
            {
              rd[r++] = 0; rd[r++] = 3;
              rd[r++] = 0; rd[r++] = 2;
              rd[r++] = (uint8_t) (c->port >> 8);
              rd[r++] = (uint8_t) c->port;
            }
          out[n++] = 0xc0; out[n++] = 0x0c;
          out[n++] = 0; out[n++] = 65; out[n++] = 0; out[n++] = 1;
          out[n++] = 0; out[n++] = 0; out[n++] = 0; out[n++] = 60;
          out[n++] = 0; out[n++] = (uint8_t) r;
          memcpy (out + n, rd, r);
          n += r;
          an = 1;
        }
      else
        for (i = 0; i < c->naddr; i++)
          {
            size_t rl = qtype == 28 ? 16 : 4;

            out[n++] = 0xc0; out[n++] = 0x0c;
            out[n++] = 0; out[n++] = (uint8_t) qtype; out[n++] = 0; out[n++] = 1;
            out[n++] = 0; out[n++] = 0; out[n++] = 0; out[n++] = 60;
            out[n++] = 0; out[n++] = (uint8_t) rl;
            memcpy (out + n, c->addr[i], rl);
            n += rl;
            an++;
          }
    }
  out[7] = (uint8_t) an;
  return n;
}

static void *
ns_serve (void *arg)
{
  struct fake_ns *ns = arg;

  while (!ns->stop)
    {
      struct pollfd pfd = { ns->fd, POLLIN, 0 };
      uint8_t buf[512];
      struct sockaddr_in peer;
      socklen_t plen = sizeof peer;
      ssize_t got;
      double t;
      int i;

      poll (&pfd, 1, 5);
      if (pfd.revents & POLLIN)
        {
          got = recvfrom (ns->fd, buf, sizeof buf, 0, (struct sockaddr *) &peer,
                          &plen);
          if (got >= 12 + 5)
            {
              size_t off = 12;
              int qtype;
              const struct ns_cfg *c;

              while (off < (size_t) got && buf[off] != 0)
                off += 1 + buf[off];
              qtype = (buf[off + 1] << 8) | buf[off + 2];
              c = &ns->cfg[type_index (qtype)];
              pthread_mutex_lock (&ns->mu);
              if (ns->nq < 32)
                {
                  ns->qtype[ns->nq] = qtype;
                  ns->at[ns->nq] = now_ms ();
                }
              ns->nq++;
              for (i = 0; i < 16; i++)
                if (!ns->pend[i].used && c->mode != DROP)
                  {
                    struct pending *p = &ns->pend[i];

                    p->used = 1;
                    p->due = now_ms () + c->delay_ms;
                    p->index = qtype;
                    p->len = (size_t) off + 5;
                    memcpy (p->msg, buf, p->len);
                    p->peer = peer;
                    p->peerlen = plen;
                    break;
                  }
              pthread_mutex_unlock (&ns->mu);
            }
        }
      t = now_ms ();
      pthread_mutex_lock (&ns->mu);
      for (i = 0; i < 16; i++)
        {
          struct pending *p = &ns->pend[i];
          uint8_t out[512];
          size_t n;

          if (!p->used || t < p->due)
            continue;
          /* The gate: nothing is answered until enough have come, or until
             a little while has passed, so that a resolver that asks one after
             another is shown to, and not hung.  */
          if (ns->gate > 0 && ns->nq < ns->gate && t < p->due + 400)
            continue;
          n = build_answer (ns, p, p->index, out);
          if (ns->first_answer == 0)
            {
              ns->first_answer = t;
              ns->at_first_answer = ns->nq;
            }
          sendto (ns->fd, out, n, 0, (struct sockaddr *) &p->peer, p->peerlen);
          p->used = 0;
        }
      pthread_mutex_unlock (&ns->mu);
    }
  return NULL;
}

static int
ns_start (struct fake_ns *ns)
{
  struct sockaddr_in sin;
  socklen_t len = sizeof sin;

  memset (ns, 0, sizeof *ns);
  pthread_mutex_init (&ns->mu, NULL);
  ns->fd = socket (AF_INET, SOCK_DGRAM, 0);
  if (ns->fd < 0)
    return -1;
  memset (&sin, 0, sizeof sin);
  sin.sin_family = AF_INET;
  sin.sin_addr.s_addr = htonl (INADDR_LOOPBACK);
  if (bind (ns->fd, (struct sockaddr *) &sin, sizeof sin) != 0
      || getsockname (ns->fd, (struct sockaddr *) &sin, &len) != 0)
    return -1;
  ns->port = ntohs (sin.sin_port);
  return pthread_create (&ns->thread, NULL, ns_serve, ns) == 0 ? 0 : -1;
}

static void
ns_stop (struct fake_ns *ns)
{
  ns->stop = 1;
  pthread_join (ns->thread, NULL);
  close (ns->fd);
}

static void
set_v4 (struct ns_cfg *c, const char *ip)
{
  struct in_addr a;

  inet_pton (AF_INET, ip, &a);
  memcpy (c->addr[c->naddr++], &a, 4);
}

static void
set_v6 (struct ns_cfg *c, const char *ip)
{
  struct in6_addr a;

  inet_pton (AF_INET6, ip, &a);
  memcpy (c->addr[c->naddr++], &a, 16);
}

/* What the resolver called, in the order it called it.  */
enum { C_ADDRESS = 1, C_HTTPS, C_TYPE_ERROR, C_COMPLETE };

struct got
{
  int n;
  struct
  {
    int kind;
    int err;
    int qtype;
    double at;
    char text[64];
    char alpn[16];
    int port;
  } call[24];
  double start;
  int done;
};

static void
g_address (void *user, const struct twist_dns_addr *a)
{
  struct got *g = user;

  if (g->n >= 24)
    return;
  g->call[g->n].kind = C_ADDRESS;
  g->call[g->n].at = now_ms () - g->start;
  snprintf (g->call[g->n].text, sizeof g->call[g->n].text, "%s", a->text);
  g->n++;
}

static void
g_https (void *user, const struct twist_dns_service *svc)
{
  struct got *g = user;

  if (g->n >= 24)
    return;
  g->call[g->n].kind = C_HTTPS;
  g->call[g->n].at = now_ms () - g->start;
  if (svc->nalpn > 0)
    snprintf (g->call[g->n].alpn, sizeof g->call[g->n].alpn, "%s", svc->alpn[0]);
  g->call[g->n].port = svc->port;
  g->n++;
}

static void
g_type_error (void *user, int qtype, int err)
{
  struct got *g = user;

  if (g->n >= 24)
    return;
  g->call[g->n].kind = C_TYPE_ERROR;
  g->call[g->n].qtype = qtype;
  g->call[g->n].err = err;
  g->call[g->n].at = now_ms () - g->start;
  g->n++;
}

static void
g_complete (void *user, int err)
{
  struct got *g = user;

  if (g->n < 24)
    {
      g->call[g->n].kind = C_COMPLETE;
      g->call[g->n].err = err;
      g->call[g->n].at = now_ms () - g->start;
      g->n++;
    }
  g->done = 1;
}

/* Ask for HOST of the fake and run until it is complete, or MS have passed.  */
static int
ask (struct fake_ns *ns, struct twist_loop *loop, struct got *g,
     const char *host, int want_https, int ms)
{
  struct twist_dns_sink sink;
  int udp = TWIST_DNS_UDP;
  double end;
  int rc;

  memset (g, 0, sizeof *g);
  memset (&sink, 0, sizeof sink);
  sink.user = g;
  sink.address = g_address;
  sink.https = g_https;
  sink.type_error = g_type_error;
  sink.complete = g_complete;
  twist_dns_set_nameserver ("127.0.0.1", ns->port);
  g->start = now_ms ();
  rc = twist_dns_resolve_sink (loop, host, &udp, 1, want_https, &sink);
  end = g->start + ms;
  while (rc == TWIST_OK && !g->done && now_ms () < end)
    twist_loop_run_once_ms (loop, 5);
  return rc;
}

/* The addresses, in the order they were given, joined with spaces.  */
static const char *
seq (const struct got *g)
{
  static char buf[4][300];
  static int rot;
  char *out = buf[rot++ % 4];
  int i;

  out[0] = 0;
  for (i = 0; i < g->n; i++)
    if (g->call[i].kind == C_ADDRESS)
      {
        if (out[0] != 0)
          strcat (out, " ");
        strcat (out, g->call[i].text);
      }
  return out;
}

/* When the nth address was given, in ms from the start; -1 if there is none.  */
static double
at (const struct got *g, int nth)
{
  int i, seen = 0;

  for (i = 0; i < g->n; i++)
    if (g->call[i].kind == C_ADDRESS && seen++ == nth)
      return g->call[i].at;
  return -1;
}

static int
count_kind (const struct got *g, int kind)
{
  int i, n = 0;

  for (i = 0; i < g->n; i++)
    if (g->call[i].kind == kind)
      n++;
  return n;
}

static int
has_type_error (const struct got *g, int qtype)
{
  int i;

  for (i = 0; i < g->n; i++)
    if (g->call[i].kind == C_TYPE_ERROR && g->call[i].qtype == qtype)
      return 1;
  return 0;
}

/* Complete is called last, once, with this.  */
static int
completed (const struct got *g)
{
  return g->n > 0 && g->call[g->n - 1].kind == C_COMPLETE
         && count_kind (g, C_COMPLETE) == 1 ? g->call[g->n - 1].err : -999;
}

static void
fresh (struct fake_ns *ns)
{
  pthread_mutex_lock (&ns->mu);
  ns->nq = 0;
  ns->first_answer = 0;
  ns->at_first_answer = 0;
  memset (ns->cfg, 0, sizeof ns->cfg);
  ns->gate = 0;
  pthread_mutex_unlock (&ns->mu);
}

static void
test_order (void)
{
  size_t i;
  struct twist_dns_addr a[6];
  static const char *in[] = { "192.0.2.1", "192.0.2.2", "2001:db8::1",
                              "2001:db8::2", "192.0.2.3", "2001:db8::3" };
  char out[400] = "";

  for (i = 0; i < 6; i++)
    {
      memset (&a[i], 0, sizeof a[i]);
      a[i].family = strchr (in[i], ':') != NULL ? 6 : 4;
      snprintf (a[i].text, sizeof a[i].text, "%s", in[i]);
    }
  check (twist_dns_sort (a, 6) == 6, "sort keeps them all");
  for (i = 0; i < 6; i++)
    {
      strcat (out, a[i].text);
      strcat (out, " ");
    }
  check (strcmp (out, "2001:db8::1 192.0.2.1 2001:db8::2 192.0.2.2 "
                      "2001:db8::3 192.0.2.3 ") == 0,
         "IPv6 first, and the families take turns, each in its order");
}

static void
test_flight (struct fake_ns *ns, struct twist_loop *loop)
{
  struct got g;
  int i;

  /* Nothing is answered until all the queries are in: one that is asked for
     after the answer to another would never be.  */
  fresh (ns);
  ns->gate = 3;
  set_v4 (&ns->cfg[0], "192.0.2.10");
  set_v6 (&ns->cfg[1], "2001:db8::10");
  ns->cfg[2].alpn = "h2";
  ns->cfg[2].port = 8443;
  check (ask (ns, loop, &g, "flight.test", 1, 3000) == TWIST_OK && g.done,
         "a name with HTTPS wanted is resolved");
  pthread_mutex_lock (&ns->mu);
  check (ns->at_first_answer == 3,
         "A, AAAA and HTTPS are asked before any is answered");
  {
    int has4 = 0, has6 = 0, hasH = 0;

    for (i = 0; i < ns->nq && i < 32; i++)
      {
        has4 |= ns->qtype[i] == 1;
        has6 |= ns->qtype[i] == 28;
        hasH |= ns->qtype[i] == 65;
      }
    check (ns->nq == 3 && has4 && has6 && hasH, "and each once");
  }
  pthread_mutex_unlock (&ns->mu);
  check (strcmp (seq (&g), "2001:db8::10 192.0.2.10") == 0,
         "the addresses, one call each, IPv6 first");
  check (count_kind (&g, C_HTTPS) == 1, "the HTTPS record, once");
  for (i = 0; i < g.n; i++)
    if (g.call[i].kind == C_HTTPS)
      check (strcmp (g.call[i].alpn, "h2") == 0 && g.call[i].port == 8443,
             "with its ALPN and port");
  check (completed (&g) == TWIST_OK, "and then complete, once, last");

  /* Not asked for HTTPS: two queries.  */
  fresh (ns);
  ns->gate = 2;
  set_v4 (&ns->cfg[0], "192.0.2.11");
  set_v6 (&ns->cfg[1], "2001:db8::11");
  check (ask (ns, loop, &g, "two.test", 0, 3000) == TWIST_OK && g.done, "two queries");
  pthread_mutex_lock (&ns->mu);
  check (ns->nq == 2 && ns->at_first_answer == 2,
         "A and AAAA, in one flight, and no HTTPS when it is not wanted");
  pthread_mutex_unlock (&ns->mu);
  check (count_kind (&g, C_HTTPS) == 0, "and no HTTPS call");
}

static void
test_delay (struct fake_ns *ns, struct twist_loop *loop)
{
  struct got g;

  /* A comes first, and AAAA within the resolution delay: both, IPv6 first,
     together.  */
  fresh (ns);
  set_v4 (&ns->cfg[0], "192.0.2.20");
  set_v6 (&ns->cfg[1], "2001:db8::20");
  ns->cfg[1].delay_ms = 20;
  ask (ns, loop, &g, "soon.test", 0, 3000);
  check (strcmp (seq (&g), "2001:db8::20 192.0.2.20") == 0
         && at (&g, 1) - at (&g, 0) < 15,
         "A, and AAAA within the delay: waited for, and IPv6 first");

  /* AAAA much later: A is given after the delay, and not before it, and the
     IPv6 address when it comes.  */
  fresh (ns);
  set_v4 (&ns->cfg[0], "192.0.2.21");
  set_v6 (&ns->cfg[1], "2001:db8::21");
  ns->cfg[1].delay_ms = 250;
  ask (ns, loop, &g, "late.test", 0, 3000);
  check (strcmp (seq (&g), "192.0.2.21 2001:db8::21") == 0,
         "A, and AAAA after the delay: A first, and AAAA when it comes");
  check (at (&g, 0) >= 40 && at (&g, 0) < 200,
         "A came after about the resolution delay, not at once");
  check (at (&g, 1) >= 200, "and AAAA when it came");

  /* AAAA first: IPv6 at once, without waiting for A.  */
  fresh (ns);
  set_v4 (&ns->cfg[0], "192.0.2.22");
  set_v6 (&ns->cfg[1], "2001:db8::22");
  ns->cfg[0].delay_ms = 200;
  ask (ns, loop, &g, "sixfirst.test", 0, 3000);
  check (strcmp (seq (&g), "2001:db8::22 192.0.2.22") == 0,
         "AAAA first: IPv6, then IPv4 when it comes");
  check (at (&g, 0) < 100 && at (&g, 1) >= 150, "IPv6 at once, and IPv4 later");
}

static void
test_failures (struct fake_ns *ns, struct twist_loop *loop)
{
  struct got g;

  /* AAAA never answered: A after the delay, AAAA given up on in the end, and
     complete.  */
  fresh (ns);
  set_v4 (&ns->cfg[0], "192.0.2.30");
  ns->cfg[1].mode = DROP;
  ask (ns, loop, &g, "dropped.test", 0, 3000);
  check (strcmp (seq (&g), "192.0.2.30") == 0 && has_type_error (&g, 28)
         && completed (&g) == TWIST_OK,
         "AAAA never answered: the A address, an error for AAAA, complete");

  /* AAAA with nothing: no wait for it.  */
  fresh (ns);
  set_v4 (&ns->cfg[0], "192.0.2.31");
  ns->cfg[1].mode = NODATA;
  ask (ns, loop, &g, "nodata.test", 0, 3000);
  check (strcmp (seq (&g), "192.0.2.31") == 0 && has_type_error (&g, 28)
         && at (&g, 0) < 40 && completed (&g) == TWIST_OK,
         "AAAA with nothing: A at once, an error for AAAA");

  /* A fails, AAAA is there: IPv6 only.  */
  fresh (ns);
  ns->cfg[0].mode = NXDOMAIN;
  set_v6 (&ns->cfg[1], "2001:db8::32");
  ask (ns, loop, &g, "v6only.test", 0, 3000);
  check (strcmp (seq (&g), "2001:db8::32") == 0 && has_type_error (&g, 1)
         && completed (&g) == TWIST_OK, "A fails, AAAA is there: IPv6 only");

  /* Nothing at all: complete with an error, and no addresses.  */
  fresh (ns);
  ns->cfg[0].mode = NXDOMAIN;
  ns->cfg[1].mode = NXDOMAIN;
  ask (ns, loop, &g, "none.test", 0, 3000);
  check (count_kind (&g, C_ADDRESS) == 0 && has_type_error (&g, 1)
         && has_type_error (&g, 28) && completed (&g) != TWIST_OK
         && completed (&g) != -999, "no such name: complete with an error");

  /* More than one of each family.  */
  fresh (ns);
  set_v4 (&ns->cfg[0], "192.0.2.41");
  set_v4 (&ns->cfg[0], "192.0.2.42");
  set_v6 (&ns->cfg[1], "2001:db8::41");
  set_v6 (&ns->cfg[1], "2001:db8::42");
  ns->cfg[1].delay_ms = 20;
  ask (ns, loop, &g, "many.test", 0, 3000);
  check (strcmp (seq (&g), "2001:db8::41 192.0.2.41 2001:db8::42 192.0.2.42") == 0,
         "two of each: the families take turns");
}

/* The callers that take one address are given one: IPv4 first, so that a path
   that cannot be had does not stop what always worked, and IPv6 when there is
   nothing else.  */
struct one
{
  int calls;
  int err;
  char text[64];
};

static void
on_one (void *user, int err, const struct twist_dns_addr *addr)
{
  struct one *o = user;

  o->calls++;
  o->err = err;
  o->text[0] = 0;
  if (addr != NULL)
    snprintf (o->text, sizeof o->text, "%s", addr->text);
}

static void
ask_one (struct fake_ns *ns, struct twist_loop *loop, struct one *o,
         const char *host)
{
  double end = now_ms () + 3000;

  memset (o, 0, sizeof *o);
  twist_dns_set_nameserver ("127.0.0.1", ns->port);
  {
    int udp = TWIST_DNS_UDP;

    if (twist_dns_resolve (loop, host, &udp, 1, on_one, o) != TWIST_OK)
      return;
  }
  while (o->calls == 0 && now_ms () < end)
    twist_loop_run_once_ms (loop, 5);
}

static void
test_one_address (struct fake_ns *ns, struct twist_loop *loop)
{
  struct one o;

  fresh (ns);
  set_v4 (&ns->cfg[0], "192.0.2.50");
  set_v6 (&ns->cfg[1], "2001:db8::50");
  ask_one (ns, loop, &o, "dual-one.test");
  check (o.calls == 1 && o.err == TWIST_OK && strcmp (o.text, "192.0.2.50") == 0,
         "one address, from both: the IPv4 one");

  fresh (ns);
  ns->cfg[0].mode = NODATA;
  set_v6 (&ns->cfg[1], "2001:db8::51");
  ask_one (ns, loop, &o, "v6-one.test");
  check (o.calls == 1 && o.err == TWIST_OK && strcmp (o.text, "2001:db8::51") == 0,
         "one address, from a name with only IPv6: that one");

  fresh (ns);
  set_v4 (&ns->cfg[0], "192.0.2.52");
  ns->cfg[1].mode = DROP;
  ask_one (ns, loop, &o, "dropped-one.test");
  check (o.calls == 1 && o.err == TWIST_OK && strcmp (o.text, "192.0.2.52") == 0,
         "one address, with AAAA never answered: IPv4, after the delay");
}

int
main (void)
{
  struct fake_ns ns;
  struct twist_loop *loop = twist_loop_new (0);

  if (loop == NULL || ns_start (&ns) != 0)
    {
      fputs ("test-resolve: no loopback to listen on; skipping\n", stderr);
      return 77;
    }
  twist_dns_set_hosts_file ("/nonexistent/twist-hosts");
  twist_dns_set_timing (50, 300);
  test_order ();
  test_flight (&ns, loop);
  test_delay (&ns, loop);
  test_failures (&ns, loop);
  test_one_address (&ns, loop);
  twist_dns_set_timing (0, 0);
  twist_dns_set_nameserver (NULL, 0);
  twist_dns_set_hosts_file (NULL);
  ns_stop (&ns);
  twist_loop_free (loop);
  return tests_finish ();
}
