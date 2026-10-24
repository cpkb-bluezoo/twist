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

/* What a runtime knows of each origin its transfers go to: which loop owns the
   connections to it, how many connections are open or being made, whether one
   that is being made may turn out to carry several transfers, the transfers
   that wait for it, and the transfers that wait for room under the limit on
   connections.  An origin is named by the key of twist_transfer_origin_key.

   Waiting is by callback: when what a transfer waits for has happened, its
   RESUME is called with no lock held, and is to do no more than post the
   transfer's next step to its loop.  An entry lives while it has anything to
   say, and is freed when it has not.  */

struct origin_entry
{
  char *key;
  struct twist_loop *loop;
  long active;			/* Connections held, open or being made.  */
  long pending;			/* Being made, and may carry several.  */
  int h1_only;			/* One that was made did not.  */
  struct twist_origin_waiter *session_head;
  struct twist_origin_waiter *session_tail;
  struct twist_origin_waiter *slot_head;
  struct twist_origin_waiter *slot_tail;
  struct origin_entry *next;
};

struct twist_origintab
{
  pthread_mutex_t mu;
  long cap;			/* Connections to one origin; 0: no limit.  */
  struct origin_entry *head;
};

int
twist_transfer_origin_key (struct twist_transfer *transfer, char *buf,
                           size_t cap)
{
  struct twist_url *url;
  int port;
  const char *proxy;
  char sock[160];
  int n;

  if (transfer == NULL || transfer->url == NULL || transfer->loop == NULL)
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
  n = snprintf (buf, cap, "%p|%s|%s|%d|%s", (void *) transfer->loop,
                url->scheme != NULL ? url->scheme : "",
                url->host != NULL ? url->host : "", port, proxy);
  if (n < 0 || (size_t) n >= cap)
    return TWIST_ERR_NOMEM;
  return TWIST_OK;
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
  while (tab->head != NULL)
    {
      struct origin_entry *e = tab->head;

      tab->head = e->next;
      waiters_forget (e->session_head);
      waiters_forget (e->slot_head);
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
entry_get (struct twist_origintab *tab, const char *key,
           struct twist_loop *loop)
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
  e->loop = loop;
  e->next = tab->head;
  tab->head = e;
  return e;
}

/* Free the entry if it has nothing in it.  */
static void
entry_trim (struct twist_origintab *tab, struct origin_entry *e)
{
  struct origin_entry **pp;

  if (e == NULL || e->active > 0 || e->pending > 0 || e->session_head != NULL
      || e->slot_head != NULL)
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

static int
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
        return 1;
      }
  return 0;
}

/* Tell the waiters in the chain, which are no longer in the entry.  */
static void
waiters_call (struct twist_origin_waiter *chain, int why)
{
  while (chain != NULL)
    {
      struct twist_origin_waiter *next = chain->next;

      chain->next = NULL;
      chain->resume (chain->user, why);
      chain = next;
    }
}

static void
chain_add (struct twist_origin_waiter **head, struct twist_origin_waiter **tail,
           struct twist_origin_waiter *w)
{
  w->next = NULL;
  if (*head == NULL)
    *head = *tail = w;
  else
    {
      (*tail)->next = w;
      *tail = w;
    }
}

int
twist_origintab_lead (struct twist_origintab *tab, const char *key,
                      struct twist_loop *loop)
{
  struct origin_entry *e;
  int rc = TWIST_OK;

  pthread_mutex_lock (&tab->mu);
  e = entry_get (tab, key, loop);
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
  struct twist_origin_waiter *chain = NULL;
  struct twist_origin_waiter *tail = NULL;
  struct twist_origin_waiter *w;

  pthread_mutex_lock (&tab->mu);
  e = entry_find (tab, key);
  if (e != NULL)
    {
      if (e->pending > 0)
        e->pending--;
      if (how == TWIST_SETTLE_H1)
        e->h1_only = 1;
      while ((w = queue_pop (&e->session_head, &e->session_tail)) != NULL)
        {
          free (w->key);
          w->key = NULL;
          w->tab = NULL;
          w->state = TWIST_WAIT_NONE;
          chain_add (&chain, &tail, w);
        }
      entry_trim (tab, e);
    }
  pthread_mutex_unlock (&tab->mu);
  waiters_call (chain, TWIST_RESUME_SETTLED);
}

int
twist_origintab_acquire (struct twist_origintab *tab, const char *key,
                         struct twist_loop *loop,
                         struct twist_origin_waiter *w, int front)
{
  struct origin_entry *e;
  char *copy = NULL;
  int rc = 1;

  /* W is where the transfer waits if there is no room, and is required.  */
  if (w == NULL || w->state != TWIST_WAIT_NONE)
    return TWIST_ERR_INVAL;
  copy = twist_strdup (key);
  if (copy == NULL)
    return TWIST_ERR_NOMEM;
  pthread_mutex_lock (&tab->mu);
  e = entry_get (tab, key, loop);
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
      queue_push (&e->slot_head, &e->slot_tail, w, front);
      rc = 0;
    }
  pthread_mutex_unlock (&tab->mu);
  free (copy);
  return rc;
}

/* The slot of an entry is free: give it to the first that waits.  Called with
   the lock held; returns the waiter, if there is one, to tell afterwards.  */
static struct twist_origin_waiter *
slot_pass (struct twist_origintab *tab, struct origin_entry *e)
{
  struct twist_origin_waiter *w;

  if (e->slot_head == NULL || (tab->cap != 0 && e->active >= tab->cap))
    return NULL;
  w = queue_pop (&e->slot_head, &e->slot_tail);
  e->active++;
  w->state = TWIST_WAIT_GRANTED;
  return w;
}

void
twist_origintab_release (struct twist_origintab *tab, const char *key)
{
  struct origin_entry *e;
  struct twist_origin_waiter *w = NULL;

  pthread_mutex_lock (&tab->mu);
  e = entry_find (tab, key);
  if (e != NULL)
    {
      if (e->active > 0)
        e->active--;
      w = slot_pass (tab, e);
      entry_trim (tab, e);
    }
  pthread_mutex_unlock (&tab->mu);
  if (w != NULL)
    waiters_call (w, TWIST_RESUME_GRANTED);
}

void
twist_origintab_wake (struct twist_origintab *tab, const char *key)
{
  struct origin_entry *e;
  struct twist_origin_waiter *w = NULL;

  pthread_mutex_lock (&tab->mu);
  e = entry_find (tab, key);
  if (e != NULL && tab->cap != 0 && e->slot_head != NULL)
    {
      /* Not a slot: a stream on a session is free, and the first that waits
         may use it.  If it cannot, it waits again at the head.  */
      w = queue_pop (&e->slot_head, &e->slot_tail);
      free (w->key);
      w->key = NULL;
      w->tab = NULL;
      w->state = TWIST_WAIT_NONE;
    }
  pthread_mutex_unlock (&tab->mu);
  if (w != NULL)
    waiters_call (w, TWIST_RESUME_WOKEN);
}

void
twist_origintab_cancel (struct twist_origin_waiter *w)
{
  struct twist_origintab *tab = w->tab;
  struct origin_entry *e;
  struct twist_origin_waiter *pass = NULL;

  if (tab == NULL)
    {
      free (w->key);
      w->key = NULL;
      w->state = TWIST_WAIT_NONE;
      return;
    }
  pthread_mutex_lock (&tab->mu);
  e = w->key != NULL ? entry_find (tab, w->key) : NULL;
  if (w->state == TWIST_WAIT_SESSION && e != NULL)
    queue_remove (&e->session_head, &e->session_tail, w);
  else if (w->state == TWIST_WAIT_SLOT && e != NULL)
    queue_remove (&e->slot_head, &e->slot_tail, w);
  else if (w->state == TWIST_WAIT_GRANTED && e != NULL)
    {
      /* It was given a slot and has not used it.  */
      if (e->active > 0)
        e->active--;
      pass = slot_pass (tab, e);
    }
  if (e != NULL)
    entry_trim (tab, e);
  free (w->key);
  w->key = NULL;
  w->tab = NULL;
  w->state = TWIST_WAIT_NONE;
  w->next = NULL;
  pthread_mutex_unlock (&tab->mu);
  if (pass != NULL)
    waiters_call (pass, TWIST_RESUME_GRANTED);
}

char *
twist_origin_waiter_take (struct twist_origin_waiter *w)
{
  char *key = w->key;

  w->key = NULL;
  w->tab = NULL;
  w->state = TWIST_WAIT_NONE;
  return key;
}
