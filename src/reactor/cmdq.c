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
#include "twist-int.h"

#include <stdlib.h>

/* MPSC queue.  Producers swing the tail with __atomic.  The consumer
   (the loop thread) walks the next pointers.  */

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
  struct twist_cmd *spare;
};

static struct twist_cmd *
cmd_take (struct twist_cmdq *q)
{
  struct twist_cmd *n = __atomic_load_n (&q->spare, __ATOMIC_ACQUIRE);

  while (n != NULL)
    {
      struct twist_cmd *next = __atomic_load_n (&n->next, __ATOMIC_ACQUIRE);

      if (__atomic_compare_exchange_n (&q->spare, &n, next, 0,
                                       __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE))
        {
          n->next = NULL;
          n->fn = NULL;
          n->user = NULL;
          return n;
        }
    }
  return calloc (1, sizeof *n);
}

static void
cmd_give (struct twist_cmdq *q, struct twist_cmd *n)
{
  struct twist_cmd *head = __atomic_load_n (&q->spare, __ATOMIC_ACQUIRE);

  n->fn = NULL;
  n->user = NULL;
  do
    n->next = head;
  while (!__atomic_compare_exchange_n (&q->spare, &head, n, 0,
                                       __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE));
}

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
  c = q->spare;
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

  node = cmd_take (q);
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
      cmd_give (q, head);
      head = next;
      if (fn != NULL)
        fn (user);
      if (head == tail)
        break;
      next = __atomic_load_n (&head->next, __ATOMIC_ACQUIRE);
    }
}
