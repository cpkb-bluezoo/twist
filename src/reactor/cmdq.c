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
#include "cmdq.h"
#include "twist-int.h"

#include <stdlib.h>

/* MPSC queue.  Producers swing the tail with __atomic.  The consumer
   (the loop thread) walks the next pointers.

   A node is allocated by the producer that posts it and freed by the
   consumer once the node after it has been taken.  The nodes were once kept
   on a free list to save the allocations.  That list was a lock-free stack
   popped by every producer, and such a stack cannot be popped by several
   threads safely without protection against the ABA problem: one producer
   reads the top node and the one under it, others take both, the consumer
   puts the first back, and the first producer then makes the node under it,
   which is in use, the top.  Two producers were enough to lose, repeat and
   reorder messages, nearly every time at a million messages, and the list
   was also slower than malloc with more than one producer.  */

struct twist_cmd
{
  void (*fn) (void *);
  void *user;
  struct twist_cmd *next;
};

struct twist_cmdq
{
  struct twist_cmd *stub;
  struct twist_cmd *head;
  struct twist_cmd *tail;
};

struct twist_cmdq *
twist_cmdq_new (void)
{
  struct twist_cmdq *q;
  struct twist_cmd *stub;

  q = calloc (1, sizeof *q);
  stub = calloc (1, sizeof *stub);
  if (q == NULL || stub == NULL)
    {
      free (q);
      free (stub);
      return NULL;
    }
  q->stub = stub;
  q->head = stub;
  q->tail = stub;
  return q;
}

void
twist_cmdq_free (struct twist_cmdq *q)
{
  struct twist_cmd *c;

  if (q == NULL)
    return;
  c = q->head;
  while (c != NULL)
    {
      struct twist_cmd *next = c->next;
      free (c);
      c = next;
    }
  free (q);
}

int
twist_cmdq_push (struct twist_cmdq *q, void (*fn) (void *), void *user)
{
  struct twist_cmd *node;
  struct twist_cmd *prev;

  node = calloc (1, sizeof *node);
  if (node == NULL)
    return TWIST_ERR_NOMEM;
  node->fn = fn;
  node->user = user;
  prev = __atomic_exchange_n (&q->tail, node, __ATOMIC_ACQ_REL);
  __atomic_store_n (&prev->next, node, __ATOMIC_RELEASE);
  return TWIST_OK;
}

void
twist_cmdq_drain (struct twist_cmdq *q)
{
  struct twist_cmd *head;
  struct twist_cmd *next;
  struct twist_cmd *tail;

  if (q == NULL)
    return;
  head = q->head;
  tail = __atomic_load_n (&q->tail, __ATOMIC_ACQUIRE);
  next = __atomic_load_n (&head->next, __ATOMIC_ACQUIRE);
  while (next != NULL)
    {
      void (*fn) (void *) = next->fn;
      void *user = next->user;

      q->head = next;
      free (head);
      head = next;
      if (fn != NULL)
        fn (user);
      if (head == tail)
        break;
      next = __atomic_load_n (&head->next, __ATOMIC_ACQUIRE);
    }
}
