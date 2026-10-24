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

#include <stdlib.h>
#include <string.h>
#include <strings.h>

#define DNS_CACHE_CAP 256
#define DNS_ADDRS 4

struct dns_ent
{
  char *name;
  int type;
  struct twist_dns_addr addr[DNS_ADDRS];
  int naddr;
  uint64_t expiry;
  struct dns_ent *next;
};

struct dns_wait
{
  void (*cb) (void *, int, const struct twist_dns_addr *);
  void *user;
  struct dns_wait *next;
};

struct dns_flight
{
  struct twist_loop *loop;
  char *name;
  int type;
  struct dns_wait *waiters;
  struct dns_flight *next;
};

struct twist_dns_cache
{
  struct dns_ent *head;
  size_t n;
  struct dns_flight *flights;
};

struct msg_box
{
  struct twist_dns_addr addr[DNS_ADDRS];
  int naddr;
  uint32_t ttl;
  int have_ttl;
};

struct twist_dns_cache *
twist_dns_cache_new (void)
{
  return calloc (1, sizeof (struct twist_dns_cache));
}

static void
free_ent (struct dns_ent *e)
{
  free (e->name);
  free (e);
}

void
twist_dns_cache_free (struct twist_dns_cache *cache)
{
  struct dns_ent *e;
  struct dns_flight *f;

  if (cache == NULL)
    return;
  e = cache->head;
  while (e != NULL)
    {
      struct dns_ent *next = e->next;
      free_ent (e);
      e = next;
    }
  f = cache->flights;
  while (f != NULL)
    {
      struct dns_flight *next = f->next;
      struct dns_wait *w = f->waiters;

      while (w != NULL)
        {
          struct dns_wait *wn = w->next;
          free (w);
          w = wn;
        }
      free (f->name);
      free (f);
      f = next;
    }
  free (cache);
}

static int
same_key (const char *a, int ta, const char *b, int tb)
{
  return ta == tb && a != NULL && b != NULL && strcasecmp (a, b) == 0;
}

static struct dns_ent *
find_ent (struct twist_dns_cache *c, const char *name, int type)
{
  struct dns_ent *e;

  for (e = c->head; e != NULL; e = e->next)
    if (same_key (e->name, e->type, name, type))
      return e;
  return NULL;
}

static void
drop_ent (struct twist_dns_cache *c, struct dns_ent *ent)
{
  struct dns_ent **pp = &c->head;

  while (*pp != NULL)
    {
      if (*pp == ent)
        {
          *pp = ent->next;
          free_ent (ent);
          if (c->n > 0)
            c->n--;
          return;
        }
      pp = &(*pp)->next;
    }
}

static void
evict_soonest (struct twist_dns_cache *c)
{
  struct dns_ent *e;
  struct dns_ent *soon;

  if (c->n < DNS_CACHE_CAP || c->head == NULL)
    return;
  soon = c->head;
  for (e = c->head->next; e != NULL; e = e->next)
    if (e->expiry < soon->expiry)
      soon = e;
  drop_ent (c, soon);
}

static void
on_msg_addr (void *user, const struct twist_dns_addr *addr)
{
  struct msg_box *b = user;

  if (b->naddr >= DNS_ADDRS)
    return;
  b->addr[b->naddr++] = *addr;
}

static void
on_msg_ttl (void *user, uint32_t ttl)
{
  struct msg_box *b = user;

  if (!b->have_ttl || ttl < b->ttl)
    {
      b->ttl = ttl;
      b->have_ttl = 1;
    }
}

/* How long an answer is kept, whatever its TTL says: a forged one could
   otherwise pin an address for the life of the process.  A minute, as curl
   keeps a name.  */
#define DNS_TTL_MAX 60u

static void
store_addrs (struct twist_dns_cache *c, const char *name, int type,
             const struct twist_dns_addr *addr, int naddr, uint32_t ttl_sec,
             uint64_t now_ms)
{
  struct dns_ent *e;
  int n;
  char *copy;

  if (name == NULL || addr == NULL || naddr <= 0 || ttl_sec == 0)
    return;
  if (ttl_sec > DNS_TTL_MAX)
    ttl_sec = DNS_TTL_MAX;
  n = naddr > DNS_ADDRS ? DNS_ADDRS : naddr;
  e = find_ent (c, name, type);
  if (e == NULL)
    {
      evict_soonest (c);
      copy = twist_strdup (name);
      e = calloc (1, sizeof *e);
      if (copy == NULL || e == NULL)
        {
          free (copy);
          free (e);
          return;
        }
      e->name = copy;
      e->type = type;
      e->next = c->head;
      c->head = e;
      c->n++;
    }
  memcpy (e->addr, addr, (size_t) n * sizeof *addr);
  e->naddr = n;
  e->expiry = now_ms + (uint64_t) ttl_sec * 1000u;
}

int
twist_dns_cache_put_msg (struct twist_dns_cache *cache, const char *name,
                         int qtype, const uint8_t *msg, size_t len,
                         uint64_t now_ms)
{
  struct msg_box box;
  struct twist_dns_events ev;

  if (cache == NULL || name == NULL || msg == NULL)
    return TWIST_ERR_INVAL;
  memset (&box, 0, sizeof box);
  memset (&ev, 0, sizeof ev);
  ev.user = &box;
  ev.address = on_msg_addr;
  ev.ttl = on_msg_ttl;
  if (twist_dns_datagram_receive (msg, len, &ev) == 0 || box.naddr == 0)
    return TWIST_ERR_RESOLVE;
  store_addrs (cache, name, qtype, box.addr, box.naddr,
               box.have_ttl ? box.ttl : 0, now_ms);
  return box.have_ttl && box.ttl > 0 ? TWIST_OK : TWIST_ERR_RESOLVE;
}

int
twist_dns_cache_get (struct twist_dns_cache *cache, const char *name,
                     int qtype, struct twist_dns_addr *out, uint64_t now_ms)
{
  struct dns_ent *e;
  int hit = 0;

  if (cache == NULL || name == NULL || out == NULL)
    return 0;
  e = find_ent (cache, name, qtype);
  if (e != NULL && e->expiry <= now_ms)
    {
      drop_ent (cache, e);
      e = NULL;
    }
  if (e != NULL && e->naddr > 0)
    {
      *out = e->addr[0];
      hit = 1;
    }
  return hit;
}

static struct dns_flight *
find_flight (struct twist_dns_cache *c, struct twist_loop *loop,
             const char *name, int type)
{
  struct dns_flight *f;

  for (f = c->flights; f != NULL; f = f->next)
    if (f->loop == loop && same_key (f->name, f->type, name, type))
      return f;
  return NULL;
}

int
twist_dns_cache_begin (struct twist_dns_cache *cache, struct twist_loop *loop,
                       const char *name, int qtype,
                       void (*cb) (void *, int, const struct twist_dns_addr *),
                       void *user, uint64_t now_ms, struct twist_dns_addr *hit)
{
  struct dns_ent *e;
  struct dns_flight *f;
  struct dns_wait *w;

  if (cache == NULL || name == NULL)
    return TWIST_ERR_INVAL;
  e = find_ent (cache, name, qtype);
  if (e != NULL && e->expiry <= now_ms)
    {
      drop_ent (cache, e);
      e = NULL;
    }
  if (e != NULL && e->naddr > 0)
    {
      if (hit != NULL)
        *hit = e->addr[0];
      return 2;
    }
  f = find_flight (cache, loop, name, qtype);
  if (f != NULL)
    {
      w = calloc (1, sizeof *w);
      if (w == NULL)
        {
          return TWIST_ERR_NOMEM;
        }
      w->cb = cb;
      w->user = user;
      w->next = f->waiters;
      f->waiters = w;
      return 1;
    }
  f = calloc (1, sizeof *f);
  if (f == NULL)
    {
      return TWIST_ERR_NOMEM;
    }
  f->name = twist_strdup (name);
  if (f->name == NULL)
    {
      free (f);
      return TWIST_ERR_NOMEM;
    }
  f->loop = loop;
  f->type = qtype;
  f->next = cache->flights;
  cache->flights = f;
  return 0;
}

void
twist_dns_cache_end (struct twist_dns_cache *cache, struct twist_loop *loop,
                     const char *name, int qtype, int err,
                     const struct twist_dns_addr *addr, uint32_t ttl_sec,
                     uint64_t now_ms)
{
  struct dns_flight **pp;
  struct dns_flight *f = NULL;
  struct dns_wait *w;

  if (cache == NULL || name == NULL)
    return;
  if (err == TWIST_OK && addr != NULL && addr->family != 0 && ttl_sec > 0)
    store_addrs (cache, name, qtype, addr, 1, ttl_sec, now_ms);
  pp = &cache->flights;
  while (*pp != NULL)
    {
      if ((*pp)->loop == loop && same_key ((*pp)->name, (*pp)->type, name,
                                           qtype))
        {
          f = *pp;
          *pp = f->next;
          break;
        }
      pp = &(*pp)->next;
    }
  if (f == NULL)
    return;
  w = f->waiters;
  free (f->name);
  free (f);
  while (w != NULL)
    {
      struct dns_wait *next = w->next;

      if (w->cb != NULL)
        w->cb (w->user, err, err == TWIST_OK ? addr : NULL);
      free (w);
      w = next;
    }
}
