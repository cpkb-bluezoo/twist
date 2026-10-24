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

#include "cmdq.h"
#include "poll.h"
#include "timer.h"
#include "twist-int.h"

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#ifdef HAVE_SYS_EVENTFD_H
# include <sys/eventfd.h>
#endif

struct twist_slot
{
  int fd;
  int interest;
  struct twist_connection *conn;
};

struct twist_loop
{
  struct twist_poll *poll;
  struct twist_timer_heap *timers;
  struct twist_cmdq *cmds;
  int waker_r;
  int waker_w;
  int external;
  struct twist_slot *slots;
  size_t nslots;
  size_t slots_cap;
  int *fd_of;
  size_t fd_of_cap;
  uint64_t (*now_ms_fn) (void *);
  void *now_user;
  uint64_t (*aux_deadline_us) (void *, uint64_t now_us);
  void (*aux_fire) (void *, uint64_t now_us);
  void *aux_user;
  void (*watch_cb) (void *, int fd, int interest);
  void *watch_user;
  struct twist_runtime *runtime;
  struct twist_rbuf *rbufs;
};

struct twist_rbuf
{
  struct twist_rbuf *next;
};

static int
waker_open (int *r, int *w)
{
  int p[2];

#ifdef HAVE_SYS_EVENTFD_H
  int fd = eventfd (0, EFD_CLOEXEC | EFD_NONBLOCK);
  if (fd >= 0)
    {
      *r = fd;
      *w = fd;
      return 0;
    }
#endif
  if (pipe (p) != 0)
    return -1;
  fcntl (p[0], F_SETFL, O_NONBLOCK);
  fcntl (p[1], F_SETFL, O_NONBLOCK);
  *r = p[0];
  *w = p[1];
  return 0;
}

static void
waker_ping (int fd)
{
  uint64_t one = 1;
  if (fd >= 0)
    {
      ssize_t n = write (fd, &one, sizeof one);
      (void) n;
    }
}

static void
waker_drain (int fd)
{
  uint64_t val;
  if (fd < 0)
    return;
  while (read (fd, &val, sizeof val) > 0)
    ;
}

struct twist_loop *
twist_loop_new (int external)
{
  struct twist_loop *loop;

  loop = calloc (1, sizeof *loop);
  if (loop == NULL)
    return NULL;
  loop->external = external;
  loop->timers = twist_timer_heap_new ();
  loop->cmds = twist_cmdq_new ();
  loop->waker_r = -1;
  loop->waker_w = -1;
  if (waker_open (&loop->waker_r, &loop->waker_w) != 0)
    {
      twist_loop_free (loop);
      return NULL;
    }
  if (!external)
    loop->poll = twist_poll_open ();
  if (loop->timers == NULL || loop->cmds == NULL
      || (!external && loop->poll == NULL))
    {
      twist_loop_free (loop);
      return NULL;
    }
  if (loop->poll != NULL && loop->waker_r >= 0)
    twist_poll_set (loop->poll, loop->waker_r, TWIST_INTEREST_READ, loop);
  return loop;
}

void
twist_loop_free (struct twist_loop *loop)
{
  if (loop == NULL)
    return;
  twist_poll_close (loop->poll);
  twist_timer_heap_free (loop->timers);
  twist_cmdq_free (loop->cmds);
  if (loop->waker_r >= 0)
    close (loop->waker_r);
  if (loop->waker_w >= 0 && loop->waker_w != loop->waker_r)
    close (loop->waker_w);
  free (loop->slots);
  free (loop->fd_of);
  while (loop->rbufs != NULL)
    {
      struct twist_rbuf *n = loop->rbufs;

      loop->rbufs = n->next;
      free (n);
    }
  free (loop);
}

void
twist_loop_set_now (struct twist_loop *loop, uint64_t (*now_ms) (void *),
                    void *user)
{
  loop->now_ms_fn = now_ms;
  loop->now_user = user;
}

uint64_t
twist_loop_now (struct twist_loop *loop)
{
  struct timespec ts;

  if (loop != NULL && loop->now_ms_fn != NULL)
    return loop->now_ms_fn (loop->now_user);
  if (clock_gettime (CLOCK_MONOTONIC, &ts) != 0)
    return 0;
  return (uint64_t) ts.tv_sec * 1000u + (uint64_t) ts.tv_nsec / 1000000u;
}

void
twist_loop_set_watch (struct twist_loop *loop,
                      void (*watch) (void *, int fd, int interest),
                      void *user)
{
  loop->watch_cb = watch;
  loop->watch_user = user;
  if (watch != NULL && loop->waker_r >= 0)
    watch (user, loop->waker_r, TWIST_INTEREST_READ);
}

void
twist_loop_set_aux_timeout (struct twist_loop *loop,
                            uint64_t (*deadline_us) (void *, uint64_t now_us),
                            void *user)
{
  loop->aux_deadline_us = deadline_us;
  loop->aux_user = user;
}

void
twist_loop_set_aux_fire (struct twist_loop *loop,
                         void (*fire) (void *, uint64_t now_us))
{
  loop->aux_fire = fire;
}

struct twist_runtime *
twist_loop_runtime (struct twist_loop *loop)
{
  return loop->runtime;
}

void
twist_loop_set_runtime (struct twist_loop *loop, struct twist_runtime *runtime)
{
  loop->runtime = runtime;
}

uint8_t *
twist_loop_take_rbuf (struct twist_loop *loop)
{
  struct twist_rbuf *n;

  if (loop != NULL && loop->rbufs != NULL)
    {
      n = loop->rbufs;
      loop->rbufs = n->next;
      return (uint8_t *) n;
    }
  return malloc (16384);
}

void
twist_loop_give_rbuf (struct twist_loop *loop, uint8_t *buf)
{
  struct twist_rbuf *n;

  if (buf == NULL)
    return;
  if (loop == NULL)
    {
      free (buf);
      return;
    }
  n = (struct twist_rbuf *) buf;
  n->next = loop->rbufs;
  loop->rbufs = n;
}

int
twist_loop_waker (struct twist_loop *loop)
{
  return loop->waker_r;
}

static int
index_fd (struct twist_loop *loop, int fd, int slot_plus)
{
  if (fd < 0)
    return -1;
  if ((size_t) fd >= loop->fd_of_cap)
    {
      size_t ncap = (size_t) fd + 1;
      int *p = realloc (loop->fd_of, ncap * sizeof *p);

      if (p == NULL)
        return -1;
      memset (p + loop->fd_of_cap, 0,
              (ncap - loop->fd_of_cap) * sizeof *p);
      loop->fd_of = p;
      loop->fd_of_cap = ncap;
    }
  loop->fd_of[fd] = slot_plus;
  return 0;
}

static struct twist_slot *
find_slot (struct twist_loop *loop, int fd)
{
  int ix;

  if (fd < 0 || (size_t) fd >= loop->fd_of_cap)
    return NULL;
  ix = loop->fd_of[fd];
  if (ix <= 0 || (size_t) ix > loop->nslots)
    return NULL;
  return &loop->slots[ix - 1];
}

int
twist_loop_watch_fd (struct twist_loop *loop, int fd, int interest,
                     struct twist_connection *conn)
{
  struct twist_slot *slot;
  int rc = TWIST_OK;

  slot = find_slot (loop, fd);
  if (slot == NULL)
    {
      if (loop->nslots == loop->slots_cap)
        {
          size_t cap = loop->slots_cap == 0 ? 8 : loop->slots_cap * 2;
          struct twist_slot *slots = realloc (loop->slots,
                                              cap * sizeof *slots);
          if (slots == NULL)
            return TWIST_ERR_NOMEM;
          loop->slots = slots;
          loop->slots_cap = cap;
        }
      slot = &loop->slots[loop->nslots++];
      slot->fd = fd;
      slot->conn = conn;
      slot->interest = 0;
      index_fd (loop, fd, (int) loop->nslots);
    }
  slot->conn = conn;
  slot->interest = interest;
  if (loop->poll != NULL)
    rc = twist_poll_set (loop->poll, fd, interest, conn);
  if (loop->watch_cb != NULL)
    loop->watch_cb (loop->watch_user, fd, interest);
  return rc;
}

void
twist_loop_unwatch_fd (struct twist_loop *loop, int fd)
{
  struct twist_slot *slot = find_slot (loop, fd);
  size_t i;

  if (slot == NULL)
    return;
  i = (size_t) (slot - loop->slots);
  if (loop->poll != NULL)
    twist_poll_set (loop->poll, fd, 0, NULL);
  if (loop->watch_cb != NULL)
    loop->watch_cb (loop->watch_user, fd, TWIST_POLL_REMOVE);
  if ((size_t) fd < loop->fd_of_cap)
    loop->fd_of[fd] = 0;
  loop->slots[i] = loop->slots[loop->nslots - 1];
  loop->nslots--;
  if (loop->nslots > i && loop->slots[i].fd >= 0
      && (size_t) loop->slots[i].fd < loop->fd_of_cap)
    loop->fd_of[loop->slots[i].fd] = (int) i + 1;
}

int
twist_loop_schedule (struct twist_loop *loop, uint64_t deadline_ms,
                     void (*cb) (void *), void *user, struct twist_timer **out)
{
  return twist_timer_heap_push (loop->timers, deadline_ms, cb, user, out);
}

/* Run what has been posted, and nothing else: no timers, no I/O.  */
void
twist_loop_drain (struct twist_loop *loop)
{
  twist_cmdq_drain (loop->cmds);
}

int
twist_loop_post (struct twist_loop *loop, void (*fn) (void *), void *user)
{
  int rc = twist_cmdq_push (loop->cmds, fn, user);
  if (rc == TWIST_OK)
    waker_ping (loop->waker_w);
  return rc;
}

/* A command made now to be posted later with twist_loop_cmd_post, which cannot
   fail.  NULL if there is no memory.  Free one that is not posted with
   twist_loop_cmd_free.  */
struct twist_cmd *
twist_loop_cmd_new (void (*fn) (void *), void *user)
{
  return twist_cmdq_node_new (fn, user);
}

void
twist_loop_cmd_post (struct twist_loop *loop, struct twist_cmd *cmd)
{
  twist_cmdq_push_node (loop->cmds, cmd);
  waker_ping (loop->waker_w);
}

void
twist_loop_cmd_free (struct twist_cmd *cmd)
{
  twist_cmdq_node_free (cmd);
}

long
twist_loop_next_timeout (struct twist_loop *loop, uint64_t now_ms)
{
  uint64_t best = UINT64_MAX;
  uint64_t heap;

  heap = twist_timer_heap_deadline (loop->timers);
  if (heap != 0)
    best = heap;
  if (loop->aux_deadline_us != NULL)
    {
      uint64_t us = loop->aux_deadline_us (loop->aux_user, now_ms * 1000u);
      if (us != 0)
        {
          uint64_t ms = us / 1000u;
          if (ms < best)
            best = ms;
        }
    }
  if (best == UINT64_MAX)
    return -1;
  if (best <= now_ms)
    return 0;
  if (best - now_ms > 86400000u)
    return 86400000;
  return (long) (best - now_ms);
}

static void
dispatch_fd (struct twist_loop *loop, int fd, int readable, int writable)
{
  struct twist_slot *slot;

  if (fd == loop->waker_r)
    {
      waker_drain (fd);
      twist_cmdq_drain (loop->cmds);
      return;
    }
  slot = find_slot (loop, fd);
  if (slot == NULL || slot->conn == NULL)
    return;
  if (readable)
    twist_connection_on_readable (slot->conn);
  if (writable)
    twist_connection_on_writable (slot->conn);
}

/* Everything the loop runs may call the application, so the handle of a
   runtime is marked as in a call for as long as it does.  */
static void
calls_begin (struct twist_loop *loop)
{
  if (loop->runtime != NULL)
    loop->runtime->in_call++;
}

static void
calls_end (struct twist_loop *loop)
{
  if (loop->runtime != NULL)
    loop->runtime->in_call--;
}

void
twist_loop_on_readable (struct twist_loop *loop, int fd)
{
  calls_begin (loop);
  dispatch_fd (loop, fd, 1, 0);
  calls_end (loop);
}

void
twist_loop_on_writable (struct twist_loop *loop, int fd)
{
  calls_begin (loop);
  dispatch_fd (loop, fd, 0, 1);
  calls_end (loop);
}

static void
fire_aux (struct twist_loop *loop, uint64_t now_ms)
{
  uint64_t now_us;
  uint64_t due;

  if (loop->aux_fire == NULL || loop->aux_deadline_us == NULL)
    return;
  now_us = now_ms * 1000u;
  due = loop->aux_deadline_us (loop->aux_user, now_us);
  if (due != 0 && due <= now_us)
    loop->aux_fire (loop->aux_user, now_us);
}

void
twist_loop_on_timer (struct twist_loop *loop, uint64_t now_ms)
{
  calls_begin (loop);
  twist_timer_heap_fire (loop->timers, now_ms);
  fire_aux (loop, now_ms);
  calls_end (loop);
}

static int run_once_ms (struct twist_loop *loop, int wait_ms);

int
twist_loop_run_once_ms (struct twist_loop *loop, int wait_ms)
{
  int rc;

  calls_begin (loop);
  rc = run_once_ms (loop, wait_ms);
  calls_end (loop);
  return rc;
}

static int
run_once_ms (struct twist_loop *loop, int wait_ms)
{
  struct twist_poll_event ev[TWIST_POLL_BATCH];
  uint64_t now;
  long timeout;
  int drain_cmds = 0;
  int fired;
  int n;
  int i;

  twist_cmdq_drain (loop->cmds);
  now = twist_loop_now (loop);
  fired = twist_timer_heap_fire (loop->timers, now);
  if (loop->external || loop->poll == NULL)
    return TWIST_OK;
  now = twist_loop_now (loop);
  timeout = twist_loop_next_timeout (loop, now);
  twist_runtime_notify_timer (loop->runtime);
  if (wait_ms >= 0)
    timeout = wait_ms;
  /* A timer that ran may have ended a transfer and called the application,
     which has things to do with what it was told; it gets the loop back as
     soon as what is ready has been seen to, not after a wait for more.  */
  if (fired > 0)
    timeout = 0;
  n = twist_poll_wait (loop->poll, ev, TWIST_POLL_BATCH, (int) timeout);
  if (n < 0)
    return TWIST_ERR_CONNECT;
  /* The events of this batch hold connection pointers, so nothing that
     frees a connection may run until every one has been dispatched.  A
     command is such a thing (the deferred frees are posted as commands), and
     the waker's event can come before a connection's: the wake-up is cleared
     where it is met and the queue is drained after the last event.  */
  for (i = 0; i < n; i++)
    {
      if (ev[i].ptr == loop)
        {
          waker_drain (loop->waker_r);
          drain_cmds = 1;
        }
      else if (ev[i].ptr != NULL)
        {
          struct twist_connection *conn = ev[i].ptr;

          if (ev[i].readable)
            twist_connection_on_readable (conn);
          if (ev[i].writable)
            twist_connection_on_writable (conn);
        }
      else
        dispatch_fd (loop, ev[i].fd, ev[i].readable, ev[i].writable);
    }
  if (drain_cmds)
    twist_cmdq_drain (loop->cmds);
  now = twist_loop_now (loop);
  twist_timer_heap_fire (loop->timers, now);
  fire_aux (loop, now);
  return TWIST_OK;
}

int
twist_loop_run_once (struct twist_loop *loop)
{
  return twist_loop_run_once_ms (loop, -1);
}
