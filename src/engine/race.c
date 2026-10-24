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
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

/* Connecting to the addresses of a name by racing them (RFC 8305, section 5).

   Each attempt is a connection of its own, made with twist_connection_connect.
   The first address is tried at once.  The next is tried when the connection
   attempt delay has passed since the one before, or at once if that one fails,
   and the earlier attempts are not given up on.  The first to connect gives its
   socket to the target connection, and the rest are closed.

   A callback of a connection must not free the connection that is calling, nor
   what the caller of the race is in the middle of: so everything is freed
   from the loop, later.  The race itself is freed that way after
   twist_race_free, and the callbacks that find it freed do nothing.  */

#define RACE_MAX 16
#define DEFAULT_DELAY_MS 250

static long attempt_delay_ms = DEFAULT_DELAY_MS;
static int (*stall_fn) (const struct twist_dns_addr *addr);

struct race_attempt
{
  struct twist_race *race;
  struct twist_connection *conn;
  int state;                    /* 0: going, 1: failed.  */
  int stalled;                  /* A test's: it hangs.  */
  struct twist_dns_addr addr;
};

struct race_dial;

struct twist_race
{
  struct twist_transfer *transfer;
  struct twist_loop *loop;
  struct twist_connection *target;
  int port;
  struct twist_dns_addr cand[RACE_MAX];
  int ncand;
  int next;                     /* The next candidate to try.  */
  struct race_attempt att[RACE_MAX];
  int inflight;
  uint64_t last_start;
  struct twist_timer *delay;
  struct twist_timer *overall;
  int ended;                    /* No more addresses are coming.  */
  int finished;                 /* Won, failed, or freed.  */
  int freed;
  int have_winner;
  struct twist_dns_addr winner;
  struct race_dial *dial;
};

void
twist_race_set_delay (long ms)
{
  attempt_delay_ms = ms > 0 ? ms : DEFAULT_DELAY_MS;
}

void
twist_race_set_stall (int (*stall) (const struct twist_dns_addr *addr))
{
  stall_fn = stall;
}

static void
conn_free_cb (void *user)
{
  twist_connection_free (user);
}

/* Free a connection from the loop, not from where it may be calling.  */
static void
free_later (struct twist_race *r, struct twist_connection *c)
{
  if (c != NULL && twist_loop_post (r->loop, conn_free_cb, c) != TWIST_OK)
    twist_connection_free (c);
}

static void
cancel_timers (struct twist_race *r)
{
  if (r->delay != NULL)
    {
      twist_timer_cancel (r->delay);
      r->delay = NULL;
    }
  if (r->overall != NULL)
    {
      twist_timer_cancel (r->overall);
      r->overall = NULL;
    }
}

static void
race_next (struct twist_race *r);

/* Everything has been tried, and nothing connected, and no more is coming.  */
static void
check_exhausted (struct twist_race *r)
{
  struct twist_connection *target;

  if (r->finished || !r->ended || r->next < r->ncand || r->inflight > 0)
    return;
  r->finished = 1;
  cancel_timers (r);
  target = r->target;
  if (target != NULL)
    twist_connection_fail (target, TWIST_ERR_CONNECT);
}

static void
race_timeout (void *user)
{
  struct twist_race *r = user;
  struct twist_connection *target = r->target;
  int i;

  r->overall = NULL;
  if (r->finished)
    return;
  r->finished = 1;
  cancel_timers (r);
  for (i = 0; i < RACE_MAX; i++)
    if (r->att[i].conn != NULL)
      {
        free_later (r, r->att[i].conn);
        r->att[i].conn = NULL;
      }
  if (target != NULL)
    twist_connection_fail (target, TWIST_ERR_TIMEOUT);
}

/* The attempt connected.  If it is the first, the target has its socket.  */
static void
attempt_connected (struct twist_endpoint *ep)
{
  struct race_attempt *a = ep->user_data;
  struct twist_race *r = a->race;
  struct twist_connection *winner = a->conn;
  struct twist_connection *target = r->target;
  int i;

  if (r->finished || a->state != 0 || winner == NULL || target == NULL)
    return;
  r->finished = 1;
  cancel_timers (r);
  /* The others are given up on.  */
  for (i = 0; i < RACE_MAX; i++)
    if (&r->att[i] != a && r->att[i].conn != NULL)
      {
        free_later (r, r->att[i].conn);
        r->att[i].conn = NULL;
      }
  a->conn = NULL;
  r->winner = a->addr;
  r->have_winner = 1;
  if (twist_connection_adopt (target, winner) != TWIST_OK)
    twist_connection_fail (target, TWIST_ERR_CONNECT);
  free_later (r, winner);
}

static void
attempt_failed (struct twist_endpoint *ep, int err)
{
  struct race_attempt *a = ep->user_data;
  struct twist_race *r = a->race;

  (void) err;
  if (a->state != 0)
    return;
  a->state = 1;
  r->inflight--;
  free_later (r, a->conn);
  a->conn = NULL;
  if (r->finished)
    return;
  /* This one is lost, and so there is no wait for the next.  */
  if (r->delay != NULL)
    {
      twist_timer_cancel (r->delay);
      r->delay = NULL;
    }
  race_next (r);
}

static void
attempt_disconnected (struct twist_endpoint *ep, int err)
{
  attempt_failed (ep, err);
}

static size_t
attempt_receive (struct twist_endpoint *ep, const uint8_t *data, size_t len)
{
  (void) ep;
  (void) data;
  return len;
}

static const struct twist_protocol_handler attempt_handler = {
  attempt_connected, attempt_receive, attempt_disconnected, NULL,
  attempt_failed, NULL, NULL
};

static size_t
fill_sockaddr (const struct twist_dns_addr *addr, int port,
               struct sockaddr_storage *ss)
{
  memset (ss, 0, sizeof *ss);
  if (addr->family == 6)
    {
      struct sockaddr_in6 *s6 = (struct sockaddr_in6 *) ss;

      s6->sin6_family = AF_INET6;
      memcpy (&s6->sin6_addr, addr->addr, 16);
      s6->sin6_scope_id = addr->scope_id;
      s6->sin6_port = htons ((uint16_t) port);
      return sizeof *s6;
    }
  else
    {
      struct sockaddr_in *s4 = (struct sockaddr_in *) ss;

      s4->sin_family = AF_INET;
      memcpy (&s4->sin_addr, addr->addr, 4);
      s4->sin_port = htons ((uint16_t) port);
      return sizeof *s4;
    }
}

/* Make an attempt to ADDR.  TWIST_OK if it is going (it may have connected
   already, and the race be over), or why not at once.  */
static int
start_attempt (struct twist_race *r, const struct twist_dns_addr *addr)
{
  struct race_attempt *a = &r->att[r->next - 1];
  struct twist_connection *c;
  struct sockaddr_storage ss;
  size_t len;
  int rc;

  a->race = r;
  a->state = 0;
  a->addr = *addr;
  r->last_start = twist_loop_now (r->loop);
  if (stall_fn != NULL && stall_fn (addr))
    {
      a->stalled = 1;
      r->inflight++;
      return TWIST_OK;
    }
  c = twist_connection_new (r->loop);
  if (c == NULL)
    return TWIST_ERR_NOMEM;
  twist_connection_endpoint (c)->user_data = a;
  twist_connection_set_handler (c, &attempt_handler);
  /* Set before the connect: it can connect at once.  */
  a->conn = c;
  r->inflight++;
  len = fill_sockaddr (addr, r->port, &ss);
  rc = twist_connection_connect (c, &ss, len, 0);
  if (rc != TWIST_OK)
    {
      /* No callback has been called.  */
      a->conn = NULL;
      a->state = 1;
      r->inflight--;
      twist_connection_free (c);
      return rc;
    }
  return TWIST_OK;
}

static void
delay_cb (void *user)
{
  struct twist_race *r = user;

  r->delay = NULL;
  if (!r->finished)
    race_next (r);
}

/* Wait the delay from the last attempt for the next, if there is one.  */
static void
arm_delay (struct twist_race *r)
{
  uint64_t due;

  if (r->finished || r->delay != NULL || r->next >= r->ncand)
    return;
  due = r->last_start + (uint64_t) attempt_delay_ms;
  if (twist_loop_schedule (r->loop, due, delay_cb, r, &r->delay) != TWIST_OK)
    r->delay = NULL;
}

/* Try the next address now.  A failure at once is no wait for the next.  */
static void
race_next (struct twist_race *r)
{
  while (!r->finished && r->next < r->ncand)
    {
      const struct twist_dns_addr addr = r->cand[r->next++];
      int rc = start_attempt (r, &addr);

      if (r->finished)
        return;
      if (rc == TWIST_OK)
        {
          arm_delay (r);
          return;
        }
    }
  check_exhausted (r);
}

struct twist_race *
twist_race_new (struct twist_transfer *transfer,
                struct twist_connection *target, int port)
{
  struct twist_race *r;

  if (transfer == NULL || transfer->loop == NULL || target == NULL)
    return NULL;
  r = calloc (1, sizeof *r);
  if (r == NULL)
    return NULL;
  r->transfer = transfer;
  r->loop = transfer->loop;
  r->target = target;
  r->port = port;
  if (transfer->connect_timeout_ms > 0)
    twist_loop_schedule (r->loop,
                         twist_loop_now (r->loop)
                         + (uint64_t) transfer->connect_timeout_ms,
                         race_timeout, r, &r->overall);
  return r;
}

int
twist_race_add (struct twist_race *r, const struct twist_dns_addr *addr)
{
  if (r == NULL || addr == NULL || r->freed)
    return TWIST_ERR_INVAL;
  if (r->ncand >= RACE_MAX)
    return TWIST_ERR_NOMEM;
  r->cand[r->ncand++] = *addr;
  if (r->finished || r->delay != NULL)
    return TWIST_OK;
  if (r->inflight == 0
      || twist_loop_now (r->loop) >= r->last_start + (uint64_t) attempt_delay_ms)
    race_next (r);
  else
    arm_delay (r);
  return TWIST_OK;
}

void
twist_race_end (struct twist_race *r)
{
  if (r == NULL || r->freed)
    return;
  r->ended = 1;
  check_exhausted (r);
}

/* Resolving the name for a race.  The resolver cannot be cancelled, so what it
   calls is a small thing of its own, that the race lets go of when it is freed
   and that is freed when the last of the two is done.  */
struct race_dial
{
  struct twist_race *race;
  int refs;
  int given;
  twist_race_fail_fn fail;
  void *user;
};

static void
dial_unref (struct race_dial *d)
{
  if (--d->refs == 0)
    free (d);
}

static void
dial_address (void *user, const struct twist_dns_addr *addr)
{
  struct race_dial *d = user;

  d->given = 1;
  if (d->race != NULL)
    twist_race_add (d->race, addr);
}

static void
dial_complete (void *user, int err)
{
  struct race_dial *d = user;
  struct twist_race *r = d->race;

  if (r != NULL)
    {
      if (d->given)
        twist_race_end (r);
      else
        {
          /* Nothing to connect to: the caller is told, and the race is over
             without touching the target.  */
          r->finished = 1;
          cancel_timers (r);
          if (d->fail != NULL)
            d->fail (d->user, err != TWIST_OK ? err : TWIST_ERR_RESOLVE);
        }
    }
  dial_unref (d);
}

int
twist_race_dial (struct twist_transfer *transfer,
                 struct twist_connection *target, const char *host, int port,
                 twist_race_fail_fn fail, void *user, struct twist_race **slot)
{
  struct twist_race *r = twist_race_new (transfer, target, port);
  struct race_dial *d;
  struct twist_dns_sink sink;
  int rc;

  if (r == NULL)
    return TWIST_ERR_NOMEM;
  d = calloc (1, sizeof *d);
  if (d == NULL)
    {
      twist_race_free (r);
      return TWIST_ERR_NOMEM;
    }
  d->race = r;
  d->refs = 2;
  d->fail = fail;
  d->user = user;
  r->dial = d;
  if (slot != NULL)
    *slot = r;
  memset (&sink, 0, sizeof sink);
  sink.user = d;
  sink.address = dial_address;
  sink.complete = dial_complete;
  rc = twist_dns_resolve_sink_transfer (transfer, host, 0, &sink);
  if (rc != TWIST_OK)
    {
      /* No callback will come: the resolver's reference is gone, and so is
         the race (which the slot still names, for the caller to forget).  */
      if (slot != NULL)
        *slot = NULL;
      dial_unref (d);
      twist_race_free (r);
      return rc;
    }
  return TWIST_OK;
}

int
twist_race_peer (struct twist_race *r, struct twist_dns_addr *out)
{
  if (r == NULL || out == NULL || !r->have_winner)
    return 0;
  *out = r->winner;
  return 1;
}

static void
race_reap (void *user)
{
  struct twist_race *r = user;
  int i;

  for (i = 0; i < RACE_MAX; i++)
    if (r->att[i].conn != NULL)
      twist_connection_free (r->att[i].conn);
  free (r);
}

void
twist_race_free (struct twist_race *r)
{
  if (r == NULL || r->freed)
    return;
  r->freed = 1;
  r->finished = 1;
  r->target = NULL;
  cancel_timers (r);
  if (r->dial != NULL)
    {
      r->dial->race = NULL;
      dial_unref (r->dial);
      r->dial = NULL;
    }
  if (twist_loop_post (r->loop, race_reap, r) != TWIST_OK)
    race_reap (r);
}
