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

#include "atomic.h"
#include "timer.h"
#include "twist-int.h"

#include <stdlib.h>
#include <string.h>

struct twist_timer
{
  uint64_t deadline;
  twist_atomic_int cancelled;
  void (*cb) (void *);
  void *user;
  size_t index;
  struct twist_timer_heap *heap;
  struct twist_timer *free_next;
  /* The owner's pointer to this timer, if it gave one: cleared when the timer
     fires, before its callback.  A timer is spent then, and the structure is
     used again for another, so a pointer kept to it would cancel that one.  */
  struct twist_timer **slot;
};

struct twist_timer_heap
{
  struct twist_timer **tab;
  size_t n;
  size_t cap;
  size_t cancelled;
  struct twist_timer *free_list;
};

static void
sift_up (struct twist_timer_heap *h, size_t i)
{
  while (i > 0)
    {
      size_t parent = (i - 1) / 2;
      struct twist_timer *a = h->tab[i];
      struct twist_timer *b = h->tab[parent];

      if (a->deadline >= b->deadline)
        break;
      h->tab[i] = b;
      h->tab[parent] = a;
      b->index = i;
      a->index = parent;
      i = parent;
    }
}

static void
sift_down (struct twist_timer_heap *h, size_t i)
{
  for (;;)
    {
      size_t left = i * 2 + 1;
      size_t right = left + 1;
      size_t best = i;

      if (left < h->n && h->tab[left]->deadline < h->tab[best]->deadline)
        best = left;
      if (right < h->n && h->tab[right]->deadline < h->tab[best]->deadline)
        best = right;
      if (best == i)
        break;
      {
        struct twist_timer *tmp = h->tab[i];
        h->tab[i] = h->tab[best];
        h->tab[best] = tmp;
        h->tab[i]->index = i;
        h->tab[best]->index = best;
        i = best;
      }
    }
}

struct twist_timer_heap *
twist_timer_heap_new (void)
{
  return calloc (1, sizeof (struct twist_timer_heap));
}

void
twist_timer_heap_free (struct twist_timer_heap *h)
{
  size_t i;

  if (h == NULL)
    return;
  for (i = 0; i < h->n; i++)
    free (h->tab[i]);
  while (h->free_list != NULL)
    {
      struct twist_timer *t = h->free_list;

      h->free_list = t->free_next;
      free (t);
    }
  free (h->tab);
  free (h);
}

static struct twist_timer *
take_timer (struct twist_timer_heap *h)
{
  struct twist_timer *t = h->free_list;

  if (t != NULL)
    {
      h->free_list = t->free_next;
      memset (t, 0, sizeof *t);
      return t;
    }
  return calloc (1, sizeof *t);
}

static void
give_timer (struct twist_timer_heap *h, struct twist_timer *t)
{
  t->cb = NULL;
  t->user = NULL;
  t->heap = NULL;
  t->free_next = h->free_list;
  h->free_list = t;
}

int
twist_timer_heap_push (struct twist_timer_heap *h, uint64_t deadline,
                       void (*cb) (void *), void *user,
                       struct twist_timer **out)
{
  struct twist_timer *t;

  if (h->n == h->cap)
    {
      size_t cap = h->cap == 0 ? 8 : h->cap * 2;
      struct twist_timer **tab = realloc (h->tab, cap * sizeof *tab);

      if (tab == NULL)
        return TWIST_ERR_NOMEM;
      h->tab = tab;
      h->cap = cap;
    }
  t = take_timer (h);
  if (t == NULL)
    return TWIST_ERR_NOMEM;
  t->deadline = deadline;
  t->cb = cb;
  t->user = user;
  t->slot = out;
  t->heap = h;
  t->index = h->n;
  h->tab[h->n++] = t;
  sift_up (h, t->index);
  if (out != NULL)
    *out = t;
  return TWIST_OK;
}

void
twist_timer_cancel (struct twist_timer *timer)
{
  if (timer == NULL)
    return;
  if (twist_atomic_load (&timer->cancelled) == 0)
    {
      twist_atomic_store (&timer->cancelled, 1);
      if (timer->heap != NULL)
        timer->heap->cancelled++;
    }
}

static void
drop_root (struct twist_timer_heap *h)
{
  struct twist_timer *t = h->tab[0];
  struct twist_timer *last;

  h->n--;
  if (h->n > 0)
    {
      last = h->tab[h->n];
      h->tab[0] = last;
      last->index = 0;
      sift_down (h, 0);
    }
  if (twist_atomic_load (&t->cancelled) && h->cancelled > 0)
    h->cancelled--;
  give_timer (h, t);
}

static void
rebuild_heap (struct twist_timer_heap *h)
{
  size_t i;
  size_t w = 0;

  for (i = 0; i < h->n; i++)
    {
      struct twist_timer *t = h->tab[i];

      if (twist_atomic_load (&t->cancelled))
        give_timer (h, t);
      else
        {
          t->index = w;
          h->tab[w++] = t;
        }
    }
  h->n = w;
  h->cancelled = 0;
  i = h->n / 2;
  while (i > 0)
    {
      i--;
      sift_down (h, i);
    }
}

uint64_t
twist_timer_heap_deadline (struct twist_timer_heap *h)
{
  if (h == NULL || h->n == 0)
    return 0;
  if (h->cancelled > h->n / 2)
    rebuild_heap (h);
  while (h->n > 0 && twist_atomic_load (&h->tab[0]->cancelled))
    drop_root (h);
  if (h->n == 0)
    return 0;
  return h->tab[0]->deadline;
}

int
twist_timer_heap_fire (struct twist_timer_heap *h, uint64_t now)
{
  int ran = 0;

  while (h != NULL && h->n > 0 && h->tab[0]->deadline <= now)
    {
      struct twist_timer *t = h->tab[0];
      struct twist_timer *last = h->tab[--h->n];

      if (h->n > 0)
        {
          h->tab[0] = last;
          last->index = 0;
          sift_down (h, 0);
        }
      if (twist_atomic_load (&t->cancelled))
        {
          if (h->cancelled > 0)
            h->cancelled--;
        }
      else if (t->cb != NULL)
        {
          if (t->slot != NULL && *t->slot == t)
            *t->slot = NULL;
          ran++;
          t->cb (t->user);
        }
      give_timer (h, t);
    }
  return ran;
}
