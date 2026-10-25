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
#include <strings.h>

/* What a runtime knows of each origin its transfers go to.  An origin is
   named by a key without a loop (the scheme, host and port, and the proxy or
   Unix socket); the same with the loop in front is the key of what a loop
   keeps for it.  The table has three parts:

   - For the connections to an origin, which are counted across loops so that
     a limit on them holds for the runtime: how many are held, open or being
     made, and the transfers that wait for room (the slot entries).
   - For each loop, whether a connection being made to the origin may turn out
     to carry several transfers, whether one has been found not to, and the
     transfers that wait to see (the origin entries).
   - Which loop the transfers that may share a connection to an origin are put
     on, so that they find it (the placement entries).

   Waiting is by callback: when what a transfer waits for has happened, its
   RESUME is called, with the table's lock held, so that cancelling the wait is
   ordered against it.  The callback may run on any thread, and does no more
   than post the transfer's next step to the loop it waits on.  The lock is
   held for the table's own memory and those callbacks only, never while
   another lock is taken.  An entry lives while it has anything to say, and is
   freed when it has not.  */

#define PLACE_BOUND 256

struct origin_entry
{
  char *key;			/* With the loop.  */
  long pending;			/* Being made, and may carry several.  */
  int h1_only;			/* One that was made did not.  */
  struct twist_origin_waiter *session_head;
  struct twist_origin_waiter *session_tail;
  struct origin_entry *next;
};

/* Idle connections kept by one loop.  */
struct idle_ref
{
  struct twist_loop *loop;
  long count;
  struct idle_ref *next;
};

struct slot_entry
{
  char *key;			/* Without it.  */
  long active;			/* Connections held, open or being made, and
				   idle ones that are kept.  */
  struct idle_ref *idle;
  long idle_total;
  long evicting;		/* Idle ones asked to close for a waiter.  */
  struct twist_origin_waiter *head;
  struct twist_origin_waiter *tail;
  struct slot_entry *next;
};

struct place_entry
{
  char *key;
  int lane;
  long users;			/* Transfers on it that are not over.  */
  long sessions;		/* Sessions on its lane that are open.  */
  int h1_only;
  struct place_entry *next;
};

/* A proxy found not to forward.  */
struct noforward_entry
{
  char *key;
  struct noforward_entry *next;
};

struct twist_origintab
{
  pthread_mutex_t mu;
  struct noforward_entry *noforward;
  long cap;			/* Connections to one origin; 0: no limit.  */
  void (*evict) (void *user, struct twist_loop *loop, const char *key);
  void *evict_user;
  struct origin_entry *head;
  struct slot_entry *slots;
  struct place_entry *places;
  size_t n_places;
};

/* The part of a key with the loop that is the origin's.  */
static const char *
okey_of (const char *key)
{
  const char *bar = strchr (key, '|');

  return bar != NULL ? bar + 1 : key;
}

/* Whether the string is an https URL.  */
static int
is_https (const char *url)
{
  return url != NULL && strncasecmp (url, "https:", 6) == 0;
}

/* What of the transfer's TLS settings a connection depends on, as a bar and a
   hex digest to add to the origin's key, or nothing at all when they are the
   defaults, so that the key of an ordinary transfer is as it always was.  The
   target's are those of a TLS connection (verification, the authorities, the
   client certificate and key), and count only for an https or wss URL; the
   proxy's count when it is spoken to in TLS, and its credentials when there
   is a proxy, since a tunnel opened by one user is not for another.  A
   connection is made under these and may be used only by a transfer whose own
   are the same, so a key that cannot be made is an error, and never one that
   leaves them out.  Each setting is hashed as a length and its bytes, or an
   N, and a semicolon, so that where one ends and the next begins is not
   lost.  */
static int
tls_identity (const struct twist_transfer *transfer, char *out, size_t cap)
{
  const char *scheme = transfer->url->scheme;
  const char *proxy = twist_transfer_proxy (transfer);
  int tls = scheme != NULL
            && (strcmp (scheme, "https") == 0 || strcmp (scheme, "wss") == 0);
  int proxy_tls = is_https (proxy);
  const char *field[8];
  int nfield = 0;
  int custom = 0;
  size_t total = 0;
  char *text;
  size_t len = 0;
  uint8_t digest[32];
  int i;
  int rc;

  out[0] = 0;
  if (tls)
    {
      field[nfield++] = transfer->verifypeer ? "v" : "n";
      field[nfield++] = transfer->cainfo;
      field[nfield++] = transfer->capath;
      field[nfield++] = transfer->sslcert;
      field[nfield++] = transfer->sslkey;
      custom |= !transfer->verifypeer || transfer->cainfo != NULL
                || transfer->capath != NULL || transfer->sslcert != NULL
                || transfer->sslkey != NULL;
    }
  if (proxy_tls)
    {
      field[nfield++] = transfer->proxy_verifypeer ? "v" : "n";
      field[nfield++] = transfer->proxy_cainfo;
      custom |= !transfer->proxy_verifypeer || transfer->proxy_cainfo != NULL;
    }
  if (proxy != NULL)
    {
      field[nfield++] = transfer->proxy_userpwd;
      custom |= transfer->proxy_userpwd != NULL;
    }
  /* All defaults: nothing to tell one transfer from another.  */
  if (!custom)
    return TWIST_OK;
  if (cap < 34)
    return TWIST_ERR_NOMEM;
  for (i = 0; i < nfield; i++)
    total += (field[i] != NULL ? strlen (field[i]) : 0) + 24;
  text = malloc (total + 1);
  if (text == NULL)
    return TWIST_ERR_NOMEM;
  for (i = 0; i < nfield; i++)
    {
      int n;

      if (field[i] == NULL)
        n = snprintf (text + len, total + 1 - len, "N;");
      else
        n = snprintf (text + len, total + 1 - len, "%zu:%s;",
                      strlen (field[i]), field[i]);
      if (n < 0 || (size_t) n > total - len)
        {
          free (text);
          return TWIST_ERR_NOMEM;
        }
      len += (size_t) n;
    }
  rc = twist_sha256 (text, len, digest);
  memset (text, 0, total + 1);
  free (text);
  if (rc != TWIST_OK)
    return rc;
  out[0] = '|';
  for (i = 0; i < 16; i++)
    snprintf (out + 1 + 2 * i, 3, "%02x", digest[i]);
  return TWIST_OK;
}

int
twist_transfer_origin_okey (struct twist_transfer *transfer, char *buf,
                            size_t cap)
{
  struct twist_url *url;
  int port;
  const char *proxy;
  char sock[160];
  int n;
  int tunnelled;
  int forwarded;

  if (transfer == NULL || transfer->url == NULL)
    return TWIST_ERR_INVAL;
  url = transfer->url;
  port = url->port > 0 ? url->port : twist_url_default_port (url->scheme);
  proxy = twist_transfer_proxy (transfer);
  if (transfer->unix_path != NULL)
    {
      /* The socket is where the connection goes, as a proxy would be.  */
      snprintf (sock, sizeof sock, "unix:%c%s",
                transfer->unix_abstract ? '@' : '/', transfer->unix_path);
      proxy = sock;
    }
  if (proxy == NULL)
    proxy = "-";
  /* An http:// URL through an HTTP or https proxy is forwarded or tunnelled;
     a connection of the one is not one for the other.  */
  tunnelled = transfer->unix_path == NULL && url->scheme != NULL
              && (strcmp (url->scheme, "http") == 0
                  || strcmp (url->scheme, "ws") == 0)
              && twist_route_role (transfer, url->scheme, 0)
                 == TWIST_ROUTE_TCP_TUNNEL;
  forwarded = transfer->unix_path == NULL && url->scheme != NULL
              && (strcmp (url->scheme, "http") == 0
                  || strcmp (url->scheme, "ws") == 0)
              && twist_route_role (transfer, url->scheme, 0)
                 == TWIST_ROUTE_FORWARD;
  /* A request forwarded to a proxy names its origin itself, so what is kept
     is the proxy's: one connection serves them all.  */
  if (forwarded)
    n = snprintf (buf, cap, "fwd|%s", proxy);
  else
    n = snprintf (buf, cap, "%s|%s|%d|%s%s",
                  url->scheme != NULL ? url->scheme : "",
                  url->host != NULL ? url->host : "", port, proxy,
                  tunnelled ? "|T" : "");
  if (n < 0 || (size_t) n >= cap)
    return TWIST_ERR_NOMEM;
  return tls_identity (transfer, buf + n, cap - (size_t) n);
}

int
twist_transfer_origin_key (struct twist_transfer *transfer, char *buf,
                           size_t cap)
{
  int n;
  int rc;

  if (transfer == NULL || transfer->loop == NULL)
    return TWIST_ERR_INVAL;
  n = snprintf (buf, cap, "%p|", (void *) transfer->loop);
  if (n < 0 || (size_t) n >= cap)
    return TWIST_ERR_NOMEM;
  rc = twist_transfer_origin_okey (transfer, buf + n, cap - (size_t) n);
  return rc;
}

void
twist_origintab_note_noforward (struct twist_origintab *tab, const char *key)
{
  struct noforward_entry *e;

  if (tab == NULL || key == NULL)
    return;
  pthread_mutex_lock (&tab->mu);
  for (e = tab->noforward; e != NULL; e = e->next)
    if (strcmp (e->key, key) == 0)
      {
        pthread_mutex_unlock (&tab->mu);
        return;
      }
  e = calloc (1, sizeof *e);
  if (e != NULL)
    {
      e->key = twist_strdup (key);
      if (e->key == NULL)
        free (e);
      else
        {
          e->next = tab->noforward;
          tab->noforward = e;
        }
    }
  pthread_mutex_unlock (&tab->mu);
}

int
twist_origintab_noforward (struct twist_origintab *tab, const char *key)
{
  struct noforward_entry *e;
  int found = 0;

  if (tab == NULL || key == NULL)
    return 0;
  pthread_mutex_lock (&tab->mu);
  for (e = tab->noforward; e != NULL && !found; e = e->next)
    found = strcmp (e->key, key) == 0;
  pthread_mutex_unlock (&tab->mu);
  return found;
}

struct twist_origintab *
twist_origintab_new (void)
{
  struct twist_origintab *tab = calloc (1, sizeof *tab);

  if (tab == NULL)
    return NULL;
  pthread_mutex_init (&tab->mu, NULL);
  return tab;
}

static void
waiters_forget (struct twist_origin_waiter *w)
{
  while (w != NULL)
    {
      struct twist_origin_waiter *next = w->next;

      free (w->key);
      w->key = NULL;
      w->tab = NULL;
      w->next = NULL;
      w->state = TWIST_WAIT_NONE;
      w = next;
    }
}

void
twist_origintab_free (struct twist_origintab *tab)
{
  if (tab == NULL)
    return;
  while (tab->noforward != NULL)
    {
      struct noforward_entry *e = tab->noforward;

      tab->noforward = e->next;
      free (e->key);
      free (e);
    }
  while (tab->head != NULL)
    {
      struct origin_entry *e = tab->head;

      tab->head = e->next;
      waiters_forget (e->session_head);
      free (e->key);
      free (e);
    }
  while (tab->slots != NULL)
    {
      struct slot_entry *e = tab->slots;

      tab->slots = e->next;
      waiters_forget (e->head);
      while (e->idle != NULL)
        {
          struct idle_ref *r = e->idle;

          e->idle = r->next;
          free (r);
        }
      free (e->key);
      free (e);
    }
  while (tab->places != NULL)
    {
      struct place_entry *e = tab->places;

      tab->places = e->next;
      free (e->key);
      free (e);
    }
  pthread_mutex_destroy (&tab->mu);
  free (tab);
}

void
twist_origintab_set_cap (struct twist_origintab *tab, long cap)
{
  pthread_mutex_lock (&tab->mu);
  tab->cap = cap;
  pthread_mutex_unlock (&tab->mu);
}

/* ---- queues ---- */

static void
queue_push (struct twist_origin_waiter **head,
            struct twist_origin_waiter **tail, struct twist_origin_waiter *w,
            int front)
{
  w->next = NULL;
  if (*head == NULL)
    *head = *tail = w;
  else if (front)
    {
      w->next = *head;
      *head = w;
    }
  else
    {
      (*tail)->next = w;
      *tail = w;
    }
}

static struct twist_origin_waiter *
queue_pop (struct twist_origin_waiter **head,
           struct twist_origin_waiter **tail)
{
  struct twist_origin_waiter *w = *head;

  if (w == NULL)
    return NULL;
  *head = w->next;
  if (*head == NULL)
    *tail = NULL;
  w->next = NULL;
  return w;
}

static void
queue_remove (struct twist_origin_waiter **head,
              struct twist_origin_waiter **tail,
              struct twist_origin_waiter *w)
{
  struct twist_origin_waiter *prev = NULL;
  struct twist_origin_waiter *p;

  for (p = *head; p != NULL; prev = p, p = p->next)
    if (p == w)
      {
        if (prev != NULL)
          prev->next = p->next;
        else
          *head = p->next;
        if (*tail == p)
          *tail = prev;
        p->next = NULL;
        return;
      }
}

/* Make W idle, without freeing its key.  */
static void
waiter_idle (struct twist_origin_waiter *w)
{
  w->tab = NULL;
  w->state = TWIST_WAIT_NONE;
  w->next = NULL;
}

/* ---- the entries of a loop ---- */

static struct origin_entry *
entry_find (struct twist_origintab *tab, const char *key)
{
  struct origin_entry *e;

  for (e = tab->head; e != NULL; e = e->next)
    if (strcmp (e->key, key) == 0)
      return e;
  return NULL;
}

static struct origin_entry *
entry_get (struct twist_origintab *tab, const char *key)
{
  struct origin_entry *e = entry_find (tab, key);

  if (e != NULL)
    return e;
  e = calloc (1, sizeof *e);
  if (e == NULL)
    return NULL;
  e->key = twist_strdup (key);
  if (e->key == NULL)
    {
      free (e);
      return NULL;
    }
  e->next = tab->head;
  tab->head = e;
  return e;
}

static void
entry_trim (struct twist_origintab *tab, struct origin_entry *e)
{
  struct origin_entry **pp;

  if (e == NULL || e->pending > 0 || e->session_head != NULL)
    return;
  for (pp = &tab->head; *pp != NULL; pp = &(*pp)->next)
    if (*pp == e)
      {
        *pp = e->next;
        free (e->key);
        free (e);
        return;
      }
}

/* ---- the entries of connections ---- */

static struct slot_entry *
slot_find (struct twist_origintab *tab, const char *okey)
{
  struct slot_entry *e;

  for (e = tab->slots; e != NULL; e = e->next)
    if (strcmp (e->key, okey) == 0)
      return e;
  return NULL;
}

static struct slot_entry *
slot_get (struct twist_origintab *tab, const char *okey)
{
  struct slot_entry *e = slot_find (tab, okey);

  if (e != NULL)
    return e;
  e = calloc (1, sizeof *e);
  if (e == NULL)
    return NULL;
  e->key = twist_strdup (okey);
  if (e->key == NULL)
    {
      free (e);
      return NULL;
    }
  e->next = tab->slots;
  tab->slots = e;
  return e;
}

static void
slot_trim (struct twist_origintab *tab, struct slot_entry *e)
{
  struct slot_entry **pp;

  if (e == NULL || e->active > 0 || e->head != NULL)
    return;
  for (pp = &tab->slots; *pp != NULL; pp = &(*pp)->next)
    if (*pp == e)
      {
        *pp = e->next;
        while (e->idle != NULL)
          {
            struct idle_ref *r = e->idle;

            e->idle = r->next;
            free (r);
          }
        free (e->key);
        free (e);
        return;
      }
}

/* The slot of an entry is free: give it to the first that waits, and tell it.
   The lock is held.  */
static void
slot_pass (struct twist_origintab *tab, struct slot_entry *e)
{
  struct twist_origin_waiter *w;

  while (e->head != NULL && (tab->cap == 0 || e->active < tab->cap))
    {
      w = queue_pop (&e->head, &e->tail);
      e->active++;
      w->state = TWIST_WAIT_GRANTED;
      w->resume (w->user, TWIST_RESUME_GRANTED);
    }
}

/* ---- sessions: the connection being made ---- */

int
twist_origintab_lead (struct twist_origintab *tab, const char *key)
{
  struct origin_entry *e;
  int rc = TWIST_OK;

  pthread_mutex_lock (&tab->mu);
  e = entry_get (tab, key);
  if (e == NULL)
    rc = TWIST_ERR_NOMEM;
  else
    e->pending++;
  pthread_mutex_unlock (&tab->mu);
  return rc;
}

int
twist_origintab_may_lead (struct twist_origintab *tab, const char *key)
{
  struct origin_entry *e;
  int ok;

  pthread_mutex_lock (&tab->mu);
  e = entry_find (tab, key);
  ok = e == NULL || !e->h1_only;
  pthread_mutex_unlock (&tab->mu);
  return ok;
}

int
twist_origintab_park (struct twist_origintab *tab, const char *key,
                      struct twist_origin_waiter *w)
{
  struct origin_entry *e;
  char *copy;
  int parked = 0;

  if (w->state != TWIST_WAIT_NONE)
    return 0;
  copy = twist_strdup (key);
  if (copy == NULL)
    return 0;
  pthread_mutex_lock (&tab->mu);
  e = entry_find (tab, key);
  if (e != NULL && e->pending > 0 && !e->h1_only)
    {
      w->tab = tab;
      w->key = copy;
      w->state = TWIST_WAIT_SESSION;
      queue_push (&e->session_head, &e->session_tail, w, 0);
      parked = 1;
    }
  pthread_mutex_unlock (&tab->mu);
  if (!parked)
    free (copy);
  return parked;
}

void
twist_origintab_settle (struct twist_origintab *tab, const char *key, int how)
{
  struct origin_entry *e;
  struct twist_origin_waiter *w;

  pthread_mutex_lock (&tab->mu);
  e = entry_find (tab, key);
  if (e != NULL)
    {
      if (e->pending > 0)
        e->pending--;
      if (how == TWIST_SETTLE_H1)
        {
          struct place_entry *p;

          e->h1_only = 1;
          /* The origin is not one to put on a loop for the sake of a session.  */
          for (p = tab->places; p != NULL; p = p->next)
            if (strcmp (p->key, okey_of (key)) == 0)
              p->h1_only = 1;
        }
      while ((w = queue_pop (&e->session_head, &e->session_tail)) != NULL)
        {
          free (w->key);
          w->key = NULL;
          waiter_idle (w);
          w->resume (w->user, TWIST_RESUME_SETTLED);
        }
      entry_trim (tab, e);
    }
  pthread_mutex_unlock (&tab->mu);
}

/* ---- the limit on connections ---- */

int
twist_origintab_acquire (struct twist_origintab *tab, const char *key,
                         struct twist_origin_waiter *w, int front)
{
  struct slot_entry *e;
  char *copy = NULL;
  int rc = 1;

  /* W is where the transfer waits if there is no room, and is required.  */
  if (w == NULL || w->state != TWIST_WAIT_NONE)
    return TWIST_ERR_INVAL;
  copy = twist_strdup (key);
  if (copy == NULL)
    return TWIST_ERR_NOMEM;
  pthread_mutex_lock (&tab->mu);
  e = slot_get (tab, okey_of (key));
  if (e == NULL)
    rc = TWIST_ERR_NOMEM;
  else if (tab->cap == 0 || e->active < tab->cap)
    e->active++;
  else
    {
      w->tab = tab;
      w->key = copy;
      copy = NULL;
      w->state = TWIST_WAIT_SLOT;
      queue_push (&e->head, &e->tail, w, front);
      rc = 0;
      /* Those that wait are given a place when one is free.  If connections
         are kept idle, by loops that will not use them for this transfer,
         one of them is asked to close.  */
      if (tab->evict != NULL && e->idle_total > e->evicting)
        {
          struct idle_ref *r = e->idle;
          char lkey[1100];

          while (r != NULL && r->count == 0)
            r = r->next;
          if (r != NULL
              && snprintf (lkey, sizeof lkey, "%p|%s", (void *) r->loop,
                           e->key) < (int) sizeof lkey)
            {
              e->evicting++;
              tab->evict (tab->evict_user, r->loop, lkey);
            }
        }
    }
  pthread_mutex_unlock (&tab->mu);
  free (copy);
  return rc;
}

void
twist_origintab_release (struct twist_origintab *tab, const char *key)
{
  struct slot_entry *e;

  pthread_mutex_lock (&tab->mu);
  e = slot_find (tab, okey_of (key));
  if (e != NULL)
    {
      if (e->active > 0)
        e->active--;
      slot_pass (tab, e);
      slot_trim (tab, e);
    }
  pthread_mutex_unlock (&tab->mu);
}

int
twist_origintab_next_waiter (struct twist_origintab *tab, const char *key,
                             struct twist_loop **loop)
{
  struct slot_entry *e;
  int found = 0;

  pthread_mutex_lock (&tab->mu);
  e = slot_find (tab, okey_of (key));
  if (e != NULL && e->head != NULL)
    {
      *loop = e->head->loop;
      found = 1;
    }
  pthread_mutex_unlock (&tab->mu);
  return found;
}

void
twist_origintab_set_evict (struct twist_origintab *tab,
                           void (*evict) (void *user, struct twist_loop *loop,
                                          const char *key), void *user)
{
  pthread_mutex_lock (&tab->mu);
  tab->evict = evict;
  tab->evict_user = user;
  pthread_mutex_unlock (&tab->mu);
}

/* The connection a transfer held is kept idle by LOOP, and holds its place.  */
void
twist_origintab_idle_add (struct twist_origintab *tab, const char *key,
                          struct twist_loop *loop)
{
  struct slot_entry *e;
  struct idle_ref *r;

  pthread_mutex_lock (&tab->mu);
  e = slot_get (tab, okey_of (key));
  if (e != NULL)
    {
      for (r = e->idle; r != NULL && r->loop != loop; r = r->next)
        ;
      if (r == NULL)
        {
          r = calloc (1, sizeof *r);
          if (r != NULL)
            {
              r->loop = loop;
              r->next = e->idle;
              e->idle = r;
            }
        }
      if (r != NULL)
        {
          r->count++;
          e->idle_total++;
        }
    }
  pthread_mutex_unlock (&tab->mu);
}

/* An idle connection of LOOP is no longer: it was taken, with its place, or it
   was closed, and the place is given back by the caller.  */
void
twist_origintab_idle_del (struct twist_origintab *tab, const char *key,
                          struct twist_loop *loop)
{
  struct slot_entry *e;
  struct idle_ref *r;

  pthread_mutex_lock (&tab->mu);
  e = slot_find (tab, okey_of (key));
  if (e != NULL)
    {
      for (r = e->idle; r != NULL && r->loop != loop; r = r->next)
        ;
      if (r != NULL && r->count > 0)
        {
          r->count--;
          e->idle_total--;
          if (e->evicting > 0)
            e->evicting--;
        }
    }
  pthread_mutex_unlock (&tab->mu);
}

void
twist_origintab_wake (struct twist_origintab *tab, const char *key)
{
  struct slot_entry *e;
  struct twist_origin_waiter *w;

  pthread_mutex_lock (&tab->mu);
  e = slot_find (tab, okey_of (key));
  if (e != NULL && tab->cap != 0 && e->head != NULL)
    {
      /* Not a slot: a stream on a session is free, and the first that waits
         may use it.  If it cannot, it waits again at the head.  */
      w = queue_pop (&e->head, &e->tail);
      free (w->key);
      w->key = NULL;
      waiter_idle (w);
      w->resume (w->user, TWIST_RESUME_WOKEN);
    }
  pthread_mutex_unlock (&tab->mu);
}

void
twist_origintab_cancel (struct twist_origintab *tab,
                        struct twist_origin_waiter *w)
{
  if (tab == NULL)
    {
      free (w->key);
      w->key = NULL;
      w->state = TWIST_WAIT_NONE;
      return;
    }
  pthread_mutex_lock (&tab->mu);
  /* It may have been given its due while this waited for the lock.  */
  if (w->tab == tab && w->key != NULL)
    {
      if (w->state == TWIST_WAIT_SESSION)
        {
          struct origin_entry *e = entry_find (tab, w->key);

          if (e != NULL)
            {
              queue_remove (&e->session_head, &e->session_tail, w);
              entry_trim (tab, e);
            }
        }
      else if (w->state == TWIST_WAIT_SLOT || w->state == TWIST_WAIT_GRANTED)
        {
          struct slot_entry *e = slot_find (tab, okey_of (w->key));

          if (e != NULL)
            {
              if (w->state == TWIST_WAIT_SLOT)
                queue_remove (&e->head, &e->tail, w);
              else if (e->active > 0)
                {
                  /* It was given a slot and has not used it.  */
                  e->active--;
                  slot_pass (tab, e);
                }
              slot_trim (tab, e);
            }
        }
    }
  free (w->key);
  w->key = NULL;
  waiter_idle (w);
  pthread_mutex_unlock (&tab->mu);
}

char *
twist_origin_waiter_take (struct twist_origin_waiter *w)
{
  char *key = w->key;

  w->key = NULL;
  waiter_idle (w);
  return key;
}

/* ---- where transfers go ---- */

static struct place_entry *
place_find (struct twist_origintab *tab, const char *okey)
{
  struct place_entry *e;

  for (e = tab->places; e != NULL; e = e->next)
    if (strcmp (e->key, okey) == 0)
      return e;
  return NULL;
}

int
twist_origintab_pin (struct twist_origintab *tab, const char *okey, int *lane)
{
  struct place_entry *e;
  int rc = 0;

  pthread_mutex_lock (&tab->mu);
  e = place_find (tab, okey);
  if (e != NULL && e->h1_only)
    rc = -1;
  else if (e != NULL)
    {
      e->users++;
      *lane = e->lane;
      rc = 1;
    }
  pthread_mutex_unlock (&tab->mu);
  return rc;
}

int
twist_origintab_pin_set (struct twist_origintab *tab, const char *okey,
                         int lane)
{
  struct place_entry *e;
  int rc = TWIST_OK;

  pthread_mutex_lock (&tab->mu);
  if (tab->n_places >= PLACE_BOUND)
    {
      /* Make room: an origin none of whose transfers is under way.  */
      struct place_entry **pp;

      for (pp = &tab->places; *pp != NULL; pp = &(*pp)->next)
        if ((*pp)->users == 0)
          {
            struct place_entry *old = *pp;

            *pp = old->next;
            free (old->key);
            free (old);
            tab->n_places--;
            break;
          }
    }
  e = calloc (1, sizeof *e);
  if (e == NULL)
    rc = TWIST_ERR_NOMEM;
  else
    {
      e->key = twist_strdup (okey);
      if (e->key == NULL)
        {
          free (e);
          rc = TWIST_ERR_NOMEM;
        }
      else
        {
          e->lane = lane;
          e->users = 1;
          e->next = tab->places;
          tab->places = e;
          tab->n_places++;
        }
    }
  pthread_mutex_unlock (&tab->mu);
  return rc;
}

/* The entry goes when nothing is on it and no session is open on its lane, so
   that the next transfers to the origin are put where there is room; an origin
   found not to share keeps its entry, which says so.  The lock is held.  */
static void
place_trim (struct twist_origintab *tab, struct place_entry *e)
{
  struct place_entry **pp;

  if (e == NULL || e->users > 0 || e->sessions > 0 || e->h1_only)
    return;
  for (pp = &tab->places; *pp != NULL; pp = &(*pp)->next)
    if (*pp == e)
      {
        *pp = e->next;
        free (e->key);
        free (e);
        tab->n_places--;
        return;
      }
}

void
twist_origintab_unpin (struct twist_origintab *tab, const char *okey)
{
  struct place_entry *e;

  pthread_mutex_lock (&tab->mu);
  e = place_find (tab, okey);
  if (e != NULL && e->users > 0)
    e->users--;
  place_trim (tab, e);
  pthread_mutex_unlock (&tab->mu);
}

void
twist_origintab_session (struct twist_origintab *tab, const char *key,
                         int delta)
{
  struct place_entry *e;

  pthread_mutex_lock (&tab->mu);
  e = place_find (tab, okey_of (key));
  if (e != NULL)
    {
      e->sessions += delta;
      if (e->sessions < 0)
        e->sessions = 0;
      place_trim (tab, e);
    }
  pthread_mutex_unlock (&tab->mu);
}
