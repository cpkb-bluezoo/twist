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

#include <pthread.h>
#include <stdlib.h>
#include <string.h>

#define TWIST_POOL_PER_KEY 8u
#define TWIST_POOL_TOTAL 32u
#define TWIST_POOL_AGE_MS 118000u

struct twist_pool_slot
{
  char *key;
  struct twist_connection *conn;
  struct twist_loop *loop;
  struct twist_timer *timer;
  /* What the connection belongs to, when it is more than a connection: an
     SSH session.  The slot owns it until it is taken.  */
  void *payload;
  void (*payload_free) (void *payload);
  uint64_t idle_at;
  int queued;
  int discarded;
  struct twist_pool *pool;
  struct twist_pool_slot *next;
};

struct twist_pool
{
  struct twist_pool_slot *head;
  size_t n;
  int locked;
  pthread_mutex_t mu;
};

static void slot_discard (struct twist_pool *pool, struct twist_pool_slot *s);

static void
pool_lock (struct twist_pool *pool)
{
  if (pool->locked)
    pthread_mutex_lock (&pool->mu);
}

static void
pool_unlock (struct twist_pool *pool)
{
  if (pool->locked)
    pthread_mutex_unlock (&pool->mu);
}

static void
unlink_slot (struct twist_pool *pool, struct twist_pool_slot *s)
{
  struct twist_pool_slot **pp;

  for (pp = &pool->head; *pp != NULL; pp = &(*pp)->next)
    if (*pp == s)
      {
        *pp = s->next;
        if (pool->n > 0)
          pool->n--;
        s->next = NULL;
        return;
      }
}

static void
discard_posted (void *user)
{
  struct twist_pool_slot *s = user;

  if (s != NULL)
    slot_discard (s->pool, s);
}

static size_t
idle_receive (struct twist_endpoint *ep, const uint8_t *data, size_t len)
{
  struct twist_pool_slot *s = ep->user_data;

  (void) data;
  if (s != NULL && !s->queued && !s->discarded)
    {
      s->queued = 1;
      if (s->timer != NULL)
        {
          twist_timer_cancel (s->timer);
          s->timer = NULL;
        }
      twist_loop_post (s->loop, discard_posted, s);
    }
  return len;
}

static void
idle_closed (struct twist_endpoint *ep, int error)
{
  (void) error;
  idle_receive (ep, NULL, 0);
}

static const struct twist_protocol_handler idle_handler = {
  NULL,
  idle_receive,
  idle_closed,
  NULL,
  idle_closed,
  NULL,
  NULL
};

static void
slot_discard (struct twist_pool *pool, struct twist_pool_slot *s)
{
  struct twist_connection *conn;

  if (s == NULL || s->discarded)
    return;
  s->discarded = 1;
  if (pool != NULL)
    {
      pool_lock (pool);
      unlink_slot (pool, s);
      pool_unlock (pool);
    }
  if (s->timer != NULL)
    {
      twist_timer_cancel (s->timer);
      s->timer = NULL;
    }
  conn = s->conn;
  s->conn = NULL;
  if (conn != NULL)
    {
      struct twist_endpoint *ep = twist_connection_endpoint (conn);

      if (ep != NULL)
        ep->user_data = NULL;
      twist_connection_set_handler (conn, NULL);
      twist_connection_free (conn);
    }
  if (s->payload_free != NULL)
    s->payload_free (s->payload);
  free (s->key);
  free (s);
}

static void
idle_timeout (void *user)
{
  struct twist_pool_slot *s = user;

  s->timer = NULL;
  if (!s->queued)
    slot_discard (s->pool, s);
}

static size_t
count_key (struct twist_pool *pool, const char *key)
{
  struct twist_pool_slot *s;
  size_t n = 0;

  for (s = pool->head; s != NULL; s = s->next)
    if (!s->discarded && s->key != NULL && strcmp (s->key, key) == 0)
      n++;
  return n;
}

/* The idle slot of LOOP that has waited longest, for KEY if given.  Only a
   loop's own slots: its connections, timers and poller belong to the thread
   that runs it, and a pool shared by several loops is touched by all of
   them.  */
static struct twist_pool_slot *
oldest (struct twist_pool *pool, const char *key, struct twist_loop *loop)
{
  struct twist_pool_slot *s;
  struct twist_pool_slot *best = NULL;

  for (s = pool->head; s != NULL; s = s->next)
    {
      if (s->discarded || s->queued || s->loop != loop)
        continue;
      if (key != NULL && (s->key == NULL || strcmp (s->key, key) != 0))
        continue;
      if (best == NULL || s->idle_at <= best->idle_at)
        best = s;
    }
  return best;
}

struct twist_pool *
twist_pool_new (void)
{
  struct twist_pool *pool = calloc (1, sizeof *pool);

  if (pool == NULL)
    return NULL;
  pthread_mutex_init (&pool->mu, NULL);
  return pool;
}

void
twist_pool_free (struct twist_pool *pool)
{
  if (pool == NULL)
    return;
  while (pool->head != NULL)
    slot_discard (pool, pool->head);
  pthread_mutex_destroy (&pool->mu);
  free (pool);
}

/* How many connections are parked.  */
size_t
twist_pool_count (struct twist_pool *pool)
{
  size_t n;

  if (pool == NULL)
    return 0;
  pool_lock (pool);
  n = pool->n;
  pool_unlock (pool);
  return n;
}

void
twist_pool_set_lock (struct twist_pool *pool, int enabled)
{
  if (pool != NULL)
    pool->locked = enabled ? 1 : 0;
}

int
twist_pool_take (struct twist_pool *pool, const char *key,
                 struct twist_connection **out)
{
  return twist_pool_take_payload (pool, key, out, NULL);
}

/* As twist_pool_take; what the connection was parked with comes back in
   *PAYLOAD, and is the caller's.  */
int
twist_pool_take_payload (struct twist_pool *pool, const char *key,
                         struct twist_connection **out, void **payload)
{
  struct twist_pool_slot **pp;

  if (out != NULL)
    *out = NULL;
  if (payload != NULL)
    *payload = NULL;
  if (pool == NULL || key == NULL)
    return TWIST_ERR_INVAL;
  pool_lock (pool);
  for (pp = &pool->head; *pp != NULL; pp = &(*pp)->next)
    if (!(*pp)->queued && !(*pp)->discarded && strcmp ((*pp)->key, key) == 0)
      {
        struct twist_pool_slot *s = *pp;

        *pp = s->next;
        if (pool->n > 0)
          pool->n--;
        pool_unlock (pool);
        if (s->timer != NULL)
          {
            twist_timer_cancel (s->timer);
            s->timer = NULL;
          }
        if (out != NULL)
          *out = s->conn;
        if (payload != NULL)
          *payload = s->payload;
        s->conn = NULL;
        s->payload_free = NULL;
        s->discarded = 1;
        free (s->key);
        free (s);
        return TWIST_OK;
      }
  pool_unlock (pool);
  return TWIST_ERR_AGAIN;
}

int
twist_pool_put_idle (struct twist_pool *pool, const char *key,
                     struct twist_connection *conn, uint64_t now_ms)
{
  return twist_pool_put_idle_payload (pool, key, conn, now_ms, NULL, NULL);
}

int
twist_pool_put_idle_payload (struct twist_pool *pool, const char *key,
                             struct twist_connection *conn, uint64_t now_ms,
                             void *payload, void (*payload_free) (void *))
{
  struct twist_pool_slot *s;
  struct twist_endpoint *ep;
  struct twist_pool_slot *drop;
  struct twist_loop *loop;

  if (pool == NULL || key == NULL || conn == NULL)
    return TWIST_ERR_INVAL;
  ep = twist_connection_endpoint (conn);
  loop = twist_endpoint_loop (ep);
  s = calloc (1, sizeof *s);
  if (s == NULL)
    return TWIST_ERR_NOMEM;
  s->key = twist_strdup (key);
  if (s->key == NULL)
    {
      free (s);
      return TWIST_ERR_NOMEM;
    }
  s->conn = conn;
  s->payload = payload;
  s->payload_free = payload_free;
  s->loop = loop;
  s->idle_at = now_ms;
  s->pool = pool;
  pool_lock (pool);
  while (count_key (pool, key) >= TWIST_POOL_PER_KEY
         || pool->n >= TWIST_POOL_TOTAL)
    {
      drop = oldest (pool, count_key (pool, key) >= TWIST_POOL_PER_KEY
                     ? key : NULL, loop);
      if (drop == NULL)
        break;
      pool_unlock (pool);
      slot_discard (pool, drop);
      pool_lock (pool);
    }
  if (count_key (pool, key) >= TWIST_POOL_PER_KEY
      || pool->n >= TWIST_POOL_TOTAL)
    {
      /* Full of other loops' connections, which are not ours to free.  The
         connection stays with the caller.  */
      pool_unlock (pool);
      free (s->key);
      free (s);
      return TWIST_ERR_AGAIN;
    }
  /* There is room: the pool takes the connection.  This is done with the
     lock held so the slot is whole when anyone can see it.  */
  ep->user_data = s;
  twist_connection_set_handler (conn, &idle_handler);
  if (loop != NULL)
    twist_loop_schedule (loop, now_ms + TWIST_POOL_AGE_MS, idle_timeout, s,
                         &s->timer);
  s->next = pool->head;
  pool->head = s;
  pool->n++;
  pool_unlock (pool);
  return TWIST_OK;
}

/* Discard every connection parked for LOOP.  A loop is freed with the
   multi handle that owns it, and a pool that outlives it, a share's, must
   not keep what is bound to it.  Called on the loop's thread, while it is
   still there.  */
void
twist_pool_drop_loop (struct twist_pool *pool, struct twist_loop *loop)
{
  struct twist_pool_slot *s;

  if (pool == NULL || loop == NULL)
    return;
  for (;;)
    {
      pool_lock (pool);
      for (s = pool->head; s != NULL; s = s->next)
        if (s->loop == loop && !s->discarded)
          break;
      pool_unlock (pool);
      if (s == NULL)
        return;
      slot_discard (pool, s);
    }
}

int
twist_pool_put (struct twist_pool *pool, const char *key,
                struct twist_connection *conn)
{
  struct twist_loop *loop = NULL;
  uint64_t now = 0;

  if (conn != NULL)
    loop = twist_endpoint_loop (twist_connection_endpoint (conn));
  if (loop != NULL)
    now = twist_loop_now (loop);
  return twist_pool_put_idle (pool, key, conn, now);
}

/* Park CONN with PAYLOAD, which PAYLOAD_FREE frees if the connection is
   discarded.  The pool owns both on success; on failure the caller keeps
   both.  */
int
twist_pool_put_payload (struct twist_pool *pool, const char *key,
                        struct twist_connection *conn, void *payload,
                        void (*payload_free) (void *))
{
  struct twist_loop *loop = NULL;
  uint64_t now = 0;

  if (conn != NULL)
    loop = twist_endpoint_loop (twist_connection_endpoint (conn));
  if (loop != NULL)
    now = twist_loop_now (loop);
  return twist_pool_put_idle_payload (pool, key, conn, now, payload,
                                      payload_free);
}

void
twist_pool_expire (struct twist_pool *pool, uint64_t now_ms)
{
  struct twist_pool_slot *s;
  struct twist_pool_slot *next;

  if (pool == NULL)
    return;
  pool_lock (pool);
  s = pool->head;
  pool_unlock (pool);
  while (s != NULL)
    {
      next = s->next;
      if (!s->discarded && !s->queued
          && now_ms >= s->idle_at + TWIST_POOL_AGE_MS)
        slot_discard (pool, s);
      s = next;
    }
}
