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

/* The upload of a transfer as a push source (see twist-int.h), and the
   adapter that makes one of the application's read callback.  */

struct twist_upload
{
  struct twist_upload_producer prod;
  void *prod_user;
  struct twist_upload_consumer cons;
  void *cons_user;
  int attached;
  int paused;
  int finished;
  size_t max;
  /* The producer is under way (RESUME is on the stack): freeing the upload from
     inside it is put off until it returns.  */
  int depth;
  int dead;
};

struct twist_upload *
twist_upload_new (const struct twist_upload_producer *p, void *user)
{
  struct twist_upload *up = calloc (1, sizeof *up);

  if (up == NULL)
    return NULL;
  up->prod = *p;
  up->prod_user = user;
  return up;
}

void
twist_upload_free (struct twist_upload *up)
{
  if (up == NULL)
    return;
  if (up->depth > 0)
    {
      up->dead = 1;
      up->attached = 0;
      return;
    }
  if (up->prod.release != NULL)
    up->prod.release (up->prod_user);
  free (up);
}

int
twist_upload_attach (struct twist_upload *up,
                     const struct twist_upload_consumer *c, void *user,
                     size_t max)
{
  if (up == NULL || c == NULL || up->attached)
    return TWIST_ERR_INVAL;
  up->cons = *c;
  up->cons_user = user;
  up->attached = 1;
  up->paused = 0;
  up->finished = 0;
  up->max = max > 0 ? max : 16384;
  return TWIST_OK;
}

void
twist_upload_detach (struct twist_upload *up)
{
  if (up == NULL)
    return;
  up->attached = 0;
  up->paused = 1;
}

int
twist_upload_active (const struct twist_upload *up)
{
  return up != NULL && up->attached && !up->paused && !up->finished;
}

size_t
twist_upload_max (const struct twist_upload *up)
{
  return up != NULL ? up->max : 0;
}

void
twist_upload_pause (struct twist_upload *up)
{
  if (up == NULL || !up->attached || up->paused)
    return;
  up->paused = 1;
  if (up->prod.pause != NULL)
    up->prod.pause (up->prod_user);
}

void
twist_upload_resume (struct twist_upload *up)
{
  if (up == NULL || !up->attached || up->finished)
    return;
  up->paused = 0;
  if (up->prod.resume != NULL)
    {
      up->depth++;
      up->prod.resume (up->prod_user);
      up->depth--;
      if (up->dead && up->depth == 0)
        twist_upload_free (up);
    }
}

int
twist_upload_push (struct twist_upload *up, const uint8_t *data, size_t len)
{
  int rc;

  if (up == NULL || !up->attached || up->finished)
    return TWIST_ERR_INVAL;
  rc = up->cons.chunk (up->cons_user, data, len);
  if (rc != TWIST_OK)
    twist_upload_finish (up, rc);
  return rc;
}

void
twist_upload_finish (struct twist_upload *up, int err)
{
  if (up == NULL || !up->attached || up->finished)
    return;
  up->finished = 1;
  up->cons.end (up->cons_user, err);
}

int
twist_upload_restart (struct twist_upload *up)
{
  if (up == NULL || up->prod.restart == NULL)
    return TWIST_ERR_REWIND;
  if (up->prod.restart (up->prod_user) != 0)
    return TWIST_ERR_REWIND;
  up->finished = 0;
  return TWIST_OK;
}

/* ---- the adapter over the read callback ---- */

struct read_adapter
{
  struct twist_transfer *transfer;
  struct twist_upload *up;
  int running;
  uint8_t buf[16384];
};

/* Call the application's callback, on the loop's thread, while the consumer
   has not paused the source: a callback that returns at once is read as fast
   as the consumer takes it.  A resume from inside a push does not begin
   another loop; the one that is running goes on.  */
static void
adapter_resume (void *user)
{
  struct read_adapter *a = user;
  struct twist_transfer *t = a->transfer;

  if (a->running)
    return;
  if (t->read_cb == NULL)
    {
      twist_upload_finish (a->up, TWIST_ERR_ABORTED);
      return;
    }
  a->running = 1;
  while (twist_upload_active (a->up))
    {
      size_t want = twist_upload_max (a->up);
      size_t n;

      if (want > sizeof a->buf)
        want = sizeof a->buf;
      n = t->read_cb ((char *) a->buf, 1, want, t->read_data);
      if (n == TWIST_READFUNC_ABORT || n > want)
        {
          twist_upload_finish (a->up, TWIST_ERR_ABORTED);
          break;
        }
      if (n == 0)
        {
          twist_upload_finish (a->up, TWIST_OK);
          break;
        }
      if (twist_upload_push (a->up, a->buf, n) != TWIST_OK)
        break;
    }
  a->running = 0;
}

static void
adapter_pause (void *user)
{
  (void) user;
}

static int
adapter_restart (void *user)
{
  struct read_adapter *a = user;
  struct twist_transfer *t = a->transfer;

  if (t->seek_cb == NULL || t->seek_cb (t->seek_data, 0, 0) != 0)
    return -1;
  return 0;
}

static void
adapter_release (void *user)
{
  free (user);
}

/* Resume at an offset: the seek callback, or read and throw away.  */
static int
adapter_skip (void *user, long long n)
{
  struct read_adapter *a = user;
  struct twist_transfer *t = a->transfer;

  if (n <= 0)
    return 0;
  if (t->seek_cb != NULL && t->seek_cb (t->seek_data, n, 0) == 0)
    return 0;
  while (n > 0)
    {
      size_t want = n > (long long) sizeof a->buf ? sizeof a->buf : (size_t) n;
      size_t got = t->read_cb ((char *) a->buf, 1, want, t->read_data);

      if (got == 0 || got > want)
        return -1;
      n -= (long long) got;
    }
  return 0;
}

static const struct twist_upload_producer adapter_ops = {
  adapter_resume, adapter_pause, adapter_restart, adapter_release, adapter_skip
};

struct twist_upload *
twist_transfer_upload (struct twist_transfer *t)
{
  struct read_adapter *a;

  if (t == NULL)
    return NULL;
  if (t->upload != NULL)
    return t->upload;
  if (t->read_cb == NULL)
    return NULL;
  a = calloc (1, sizeof *a);
  if (a == NULL)
    return NULL;
  a->transfer = t;
  a->up = twist_upload_new (&adapter_ops, a);
  if (a->up == NULL)
    {
      free (a);
      return NULL;
    }
  t->upload = a->up;
  return a->up;
}

int
twist_upload_skip (struct twist_upload *up, long long n)
{
  if (up == NULL)
    return TWIST_ERR_RESUME;
  if (n <= 0)
    return TWIST_OK;
  if (up->prod.skip == NULL || up->prod.skip (up->prod_user, n) != 0)
    return TWIST_ERR_RESUME;
  return TWIST_OK;
}

/* ---- a source over memory ---- */

struct mem_source
{
  struct twist_upload *up;
  const uint8_t *data;
  size_t len;
  size_t off;
  int running;
};

static void
mem_resume (void *user)
{
  struct mem_source *m = user;

  if (m->running)
    return;
  m->running = 1;
  while (twist_upload_active (m->up))
    {
      size_t n = m->len - m->off;
      size_t max = twist_upload_max (m->up);

      if (n == 0)
        {
          twist_upload_finish (m->up, TWIST_OK);
          break;
        }
      if (n > max)
        n = max;
      m->off += n;
      if (twist_upload_push (m->up, m->data + m->off - n, n) != TWIST_OK)
        break;
    }
  m->running = 0;
}

static void
mem_pause (void *user)
{
  (void) user;
}

static int
mem_restart (void *user)
{
  struct mem_source *m = user;

  m->off = 0;
  return 0;
}

static int
mem_skip (void *user, long long n)
{
  struct mem_source *m = user;

  if (n > (long long) (m->len - m->off))
    return -1;
  m->off += (size_t) n;
  return 0;
}

static void
mem_release (void *user)
{
  free (user);
}

static const struct twist_upload_producer mem_ops = {
  mem_resume, mem_pause, mem_restart, mem_release, mem_skip
};

struct twist_upload *
twist_upload_from_memory (const uint8_t *data, size_t len)
{
  struct mem_source *m = calloc (1, sizeof *m);

  if (m == NULL)
    return NULL;
  m->data = data;
  m->len = len;
  m->up = twist_upload_new (&mem_ops, m);
  if (m->up == NULL)
    {
      free (m);
      return NULL;
    }
  return m->up;
}

/* ---- the meter ---- */

void
twist_upmeter_start (struct twist_upmeter *m, struct twist_transfer *t,
                   struct twist_connection *conn)
{
  m->transfer = t;
  m->conn = conn;
  m->base = conn != NULL ? twist_connection_body_written (conn) : 0;
  m->reported = 0;
}

void
twist_upmeter_sync (struct twist_upmeter *m)
{
  uint64_t n;

  if (m == NULL || m->conn == NULL || m->transfer == NULL)
    return;
  n = twist_connection_body_written (m->conn);
  if (n < m->base)
    return;
  n -= m->base;
  if (n > m->reported)
    {
      twist_progress_uploaded (m->transfer, (size_t) (n - m->reported));
      m->reported = n;
    }
}

/* ---- an upload relayed to a connection ---- */

struct twist_relay
{
  struct twist_connection *conn;
  struct twist_endpoint *ep;
  struct twist_upload *up;
  int own_up;
  const struct twist_relay_ops *ops;
  void *user;
  struct twist_upmeter *meter;
};

int
twist_relay_push (struct twist_relay *r, const uint8_t *data, size_t len)
{
  if (r->conn == NULL)
    return r->ep != NULL ? twist_endpoint_send (r->ep, data, len) : TWIST_OK;
  return twist_connection_push (r->conn, data, len, NULL, NULL);
}

static int
relay_chunk (void *user, const uint8_t *data, size_t len)
{
  struct twist_relay *r = user;
  struct twist_upmeter *meter = r->meter;
  int rc;

  rc = r->ops->chunk != NULL ? r->ops->chunk (r->user, r, data, len)
                             : twist_relay_push (r, data, len);
  if (rc != TWIST_OK)
    return rc;			/* The connection has failed; R is gone.  */
  twist_upmeter_sync (meter);
  return TWIST_OK;
}

static void
relay_done (struct twist_relay *r, int err)
{
  struct twist_upload *up = r->up;
  int own = r->own_up;
  const struct twist_relay_ops *ops = r->ops;
  void *user = r->user;

  twist_upmeter_sync (r->meter);
  twist_upload_detach (up);
  if (own)
    twist_upload_free (up);
  free (r);
  ops->end (user, err);
}

static void
relay_finish (void *user, int err)
{
  struct twist_relay *r = user;
  struct twist_connection *conn = r->conn;

  if (err == TWIST_OK && r->ops->finish != NULL
      && r->ops->finish (r->user, r) != TWIST_OK)
    return;			/* Failed; R is gone with the connection.  */
  if (conn == NULL)
    {
      relay_done (r, err);
      return;
    }
  twist_connection_push_end (conn, err);	/* Frees R, via relay_conn_end.  */
  if (err != TWIST_OK)
    twist_connection_fail (conn, err);
}

void
twist_relay_abort (struct twist_relay *r, int err)
{
  struct twist_connection *conn = r->conn;

  if (conn == NULL)
    {
      relay_done (r, err);
      return;
    }
  twist_connection_push_end (conn, err);	/* Frees R.  */
  twist_connection_fail (conn, err);
}

void
twist_relay_done (struct twist_relay *r)
{
  relay_finish (r, TWIST_OK);
}

static const struct twist_upload_consumer relay_consumer = { relay_chunk,
                                                             relay_finish };

static void
relay_conn_pause (void *user)
{
  struct twist_relay *r = user;

  twist_upload_pause (r->up);
}

static void
relay_conn_resume (void *user)
{
  struct twist_relay *r = user;

  twist_upload_resume (r->up);
}

static void
relay_conn_end (void *user, int err)
{
  relay_done (user, err);
}

static const struct twist_source_ops relay_conn_ops = {
  relay_conn_pause, relay_conn_resume, NULL, relay_conn_end
};

int
twist_relay_start (struct twist_connection *conn, struct twist_endpoint *ep,
                   struct twist_upload *up, int own_up, size_t max,
                   const struct twist_relay_ops *ops, void *user,
                   struct twist_upmeter *meter)
{
  struct twist_relay *r;
  int rc;

  if (up == NULL)
    return TWIST_ERR_NOMEM;
  r = calloc (1, sizeof *r);
  if (r == NULL)
    {
      if (own_up)
        twist_upload_free (up);
      return TWIST_ERR_NOMEM;
    }
  r->conn = conn;
  r->ep = ep;
  r->up = up;
  r->own_up = own_up;
  r->ops = ops;
  r->user = user;
  r->meter = meter;
  rc = twist_upload_attach (up, &relay_consumer, r, max);
  if (rc != TWIST_OK)
    goto fail;
  if (conn != NULL)
    {
      rc = twist_connection_attach_source (conn, &relay_conn_ops, r);
      if (rc != TWIST_OK)
        {
          twist_upload_detach (up);
          goto fail;
        }
    }
  twist_upload_resume (up);
  return TWIST_OK;
fail:
  if (own_up)
    twist_upload_free (up);
  free (r);
  return rc;
}
