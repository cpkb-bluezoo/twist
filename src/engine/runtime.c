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
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>

/* The runtime: event loops, the transfers that run on them, and what they
   keep for each other.  Everything in it is driven by events.  A transfer is
   started, it ends by calling twist_transfer_finish from whatever handler had
   it, and its loop then reports the result to the program in a call of its
   own, after that handler has returned: the program is told from a loop and
   never from inside a protocol handler, and so may do anything to the
   transfer, including free it.

   A runtime has one loop, the program's, which it drives with
   twist_runtime_run_once; or, if it was told to (TWIST_RUNTIMEOPT_THREADS),
   several, the others each in a thread of its own.  Each loop and what only
   it touches is a lane.  A transfer is on one lane for its life.  The program
   calls the runtime from one thread, the driving one, and everything that
   crosses to another lane is a command posted to that lane's loop, whose queue
   orders what was done before the post with what the command does.  The end of
   a transfer on another lane is posted back to the first lane, and the
   program is told of it there.  */

struct twist_lane_live
{
  struct twist_transfer *transfer;
  unsigned long serial;
};

/* A command to a lane about a transfer, which is named by its serial: the
   transfer may be over, and freed, by the time the command runs.  */
struct lane_cmd
{
  struct twist_runtime *runtime;
  struct twist_lane *lane;
  struct twist_transfer *transfer;	/* To start only.  */
  unsigned long serial;
  struct drop_sync *sync;
};

/* The end of a transfer, on its way to the first lane.  */
struct deliver
{
  struct twist_runtime *runtime;
  unsigned long serial;
};

/* The driving thread waiting for a lane to let go of a transfer.  */
struct drop_sync
{
  pthread_mutex_t mu;
  pthread_cond_t cv;
  int done;
  int unposted;
};

static void runtime_watch (void *user, int fd, int interest);
static void lane_stop_cmd (void *user);
static void runtime_evict (void *user, struct twist_loop *loop,
                          const char *key);

static int *
lane_incall (struct twist_lane *lane)
{
  return lane->index == 0 ? &lane->runtime->in_call : &lane->in_call;
}

static void
lane_free (struct twist_lane *lane)
{
  if (lane == NULL)
    return;
  twist_pool_free (lane->pool);
  twist_loop_free (lane->loop);
  if (lane->stop_node != NULL)
    twist_loop_cmd_free (lane->stop_node);
  free (lane->live);
  free (lane);
}

/* An idle connection of the lane that held a place under the limit on
   connections is closed and gone: the place is free.  Not when the runtime is
   being freed, which has let go of the table's users by then.  */
static void
lane_pool_discard (void *user, const char *key)
{
  struct twist_lane *lane = user;
  struct twist_runtime *runtime = lane->runtime;

  if (runtime->closing)
    return;
  twist_origintab_idle_del (runtime->origintab, key, lane->loop);
  twist_origintab_release (runtime->origintab, key);
}

static struct twist_lane *
lane_new (struct twist_runtime *runtime, int index, int embedded)
{
  struct twist_lane *lane = calloc (1, sizeof *lane);

  if (lane == NULL)
    return NULL;
  lane->runtime = runtime;
  lane->index = index;
  lane->loop = twist_loop_new (embedded);
  lane->pool = twist_pool_new ();
  if (lane->loop == NULL || lane->pool == NULL)
    {
      lane_free (lane);
      return NULL;
    }
  twist_loop_set_runtime (lane->loop, runtime);
  twist_loop_set_in_call (lane->loop, lane_incall (lane));
  twist_pool_set_discard (lane->pool, lane_pool_discard, lane);
  if (index != 0)
    {
      lane->stop_node = twist_loop_cmd_new (lane_stop_cmd, lane);
      if (lane->stop_node == NULL)
        {
          lane_free (lane);
          return NULL;
        }
    }
  return lane;
}

/* The lane whose thread this is, if it is one the library started.  */
static __thread struct twist_lane *this_lane;

/* Whether the calling thread is one the runtime started.  Its callbacks run
   there, and may not call the runtime.  */
static int
on_lane_thread (struct twist_runtime *runtime)
{
  return this_lane != NULL && this_lane->runtime == runtime;
}

static struct twist_runtime *
runtime_new (int embedded, twist_watch_callback watch,
             twist_timer_callback timer, void *user)
{
  struct twist_runtime *runtime = calloc (1, sizeof *runtime);
  struct twist_lane *lane;

  if (runtime == NULL)
    return NULL;
  runtime->threads = 1;
  lane = lane_new (runtime, 0, embedded);
  runtime->lanes = calloc (1, sizeof *runtime->lanes);
  if (lane == NULL || runtime->lanes == NULL)
    {
      lane_free (lane);
      free (runtime->lanes);
      free (runtime);
      return NULL;
    }
  runtime->lanes[0] = lane;
  runtime->n_lanes = 1;
  runtime->loop = lane->loop;
  runtime->pool = lane->pool;
  runtime->last_deadline = -2;
  runtime->storage = twist_storage_new (2, 32);
  runtime->dns = twist_dns_cache_new ();
  runtime->jar = twist_jar_new ();
  runtime->hsts = twist_hsts_new ();
  runtime->altsvc = twist_altsvc_new ();
  runtime->origintab = twist_origintab_new ();
  if (runtime->storage == NULL || runtime->dns == NULL || runtime->jar == NULL
      || runtime->hsts == NULL || runtime->altsvc == NULL
      || runtime->origintab == NULL)
    {
      twist_origintab_free (runtime->origintab);
      twist_altsvc_free (runtime->altsvc);
      twist_hsts_free (runtime->hsts);
      twist_jar_free (runtime->jar);
      twist_dns_cache_free (runtime->dns);
      twist_storage_free (runtime->storage);
      lane_free (lane);
      free (runtime->lanes);
      free (runtime);
      return NULL;
    }
  twist_origintab_set_evict (runtime->origintab, runtime_evict, runtime);
  if (embedded)
    {
      runtime->embedded = 1;
      runtime->watch_cb = watch;
      runtime->timer_cb = timer;
      runtime->hook_user = user;
      /* Tells the program of the descriptor that wakes the loop.  */
      twist_loop_set_watch (runtime->loop, runtime_watch, runtime);
    }
  return runtime;
}

twist_runtime *
twist_runtime_new (void)
{
  return runtime_new (0, NULL, NULL, NULL);
}

twist_runtime *
twist_runtime_new_embedded (twist_watch_callback watch,
                            twist_timer_callback timer, void *user)
{
  if (watch == NULL || timer == NULL)
    return NULL;
  return runtime_new (1, watch, timer, user);
}

static void
runtime_watch (void *user, int fd, int interest)
{
  struct twist_runtime *runtime = user;
  int what = TWIST_POLL_NONE;

  if (runtime->watch_cb == NULL)
    return;
  if (interest == TWIST_POLL_REMOVE)
    what = TWIST_POLL_REMOVE;
  else
    {
      if (interest & TWIST_INTEREST_READ)
        what |= TWIST_POLL_IN;
      if (interest & TWIST_INTEREST_WRITE)
        what |= TWIST_POLL_OUT;
    }
  runtime->in_call++;
  runtime->watch_cb (fd, what, runtime->hook_user);
  runtime->in_call--;
}

/* Tell the program's timer hook the time to the loop's next deadline, when
   the deadline is not the one it was last told of (the time to it is always
   running down, so the deadline is what is compared).  One that is due now is
   told every time: what ran since may have made another due, and the program
   that was told "now" and has not waited since would not hear of it.  Called
   wherever the deadline can have moved: when the loop is about to wait, and
   after each call that drives it or changes its transfers, so that a program
   that never waits in the loop is told as well.  */
void
twist_runtime_notify_timer (struct twist_runtime *runtime)
{
  uint64_t now;
  long timeout;
  long long deadline;

  if (runtime == NULL || runtime->timer_cb == NULL || runtime->loop == NULL)
    return;
  now = twist_loop_now (runtime->loop);
  timeout = twist_loop_next_timeout (runtime->loop, now);
  /* None is -1, and one that is due already is 0.  */
  deadline = timeout > 0 ? (long long) now + timeout : timeout;
  if (deadline == runtime->last_deadline && deadline != 0)
    return;
  runtime->last_deadline = deadline;
  runtime->in_call++;
  runtime->timer_cb (timeout, runtime->hook_user);
  runtime->in_call--;
}

/* ---- the transfers of a runtime ---- */

/* Take the entry I out of the list: the transfer is no longer counted on its
   lane or its origin.  */
static void
entry_take (struct twist_runtime *runtime, size_t i, struct twist_started *out)
{
  struct twist_started *e = &runtime->transfers[i];

  *out = *e;
  runtime->lanes[e->lane]->load--;
  if (e->place_key != NULL)
    twist_origintab_unpin (runtime->origintab, e->place_key);
  runtime->transfers[i] = runtime->transfers[runtime->n_transfers - 1];
  runtime->n_transfers--;
}

static int
entry_index (struct twist_runtime *runtime, const struct twist_transfer *t)
{
  size_t i;

  for (i = 0; i < runtime->n_transfers; i++)
    if (runtime->transfers[i].transfer == t)
      return (int) i;
  return -1;
}

/* Take TRANSFER out of the transfers of RUNTIME.  Its handler is already
   gone.  */
static void
remove_transfer (struct twist_runtime *runtime,
                 struct twist_transfer *transfer)
{
  struct twist_started gone;
  int i = entry_index (runtime, transfer);

  if (transfer->reap != NULL)
    {
      twist_timer_cancel (transfer->reap);
      transfer->reap = NULL;
    }
  transfer->started = 0;
  if (i >= 0)
    {
      entry_take (runtime, (size_t) i, &gone);
      free (gone.place_key);
    }
  transfer->runtime = NULL;
  transfer->loop = NULL;
  transfer->lane = NULL;
}

/* ---- the threads ---- */

static void
lane_stop_cmd (void *user)
{
  struct twist_lane *lane = user;

  __atomic_store_n (&lane->stop, 1, __ATOMIC_RELEASE);
}

static void *
lane_main (void *arg)
{
  struct twist_lane *lane = arg;

  this_lane = lane;
  while (!__atomic_load_n (&lane->stop, __ATOMIC_ACQUIRE))
    twist_loop_run_once_ms (lane->loop, -1);
  return NULL;
}

/* Stop and join the threads of the lanes from FIRST on.  */
static void
lanes_stop (struct twist_runtime *runtime, size_t first)
{
  size_t i;

  for (i = first; i < runtime->n_lanes; i++)
    if (runtime->lanes[i]->threaded)
      {
        __atomic_store_n (&runtime->lanes[i]->stop, 1, __ATOMIC_RELEASE);
        /* The loop is woken by any command; this one, made with the lane,
           is so that it is, and posting it cannot fail.  */
        twist_loop_cmd_post (runtime->lanes[i]->loop,
                             runtime->lanes[i]->stop_node);
        runtime->lanes[i]->stop_node = NULL;
      }
  for (i = first; i < runtime->n_lanes; i++)
    if (runtime->lanes[i]->threaded)
      {
        pthread_join (runtime->lanes[i]->thread, NULL);
        runtime->lanes[i]->threaded = 0;
      }
}

/* The lanes there are to be, once, when the first transfer is started.  */
static int
lanes_make (struct twist_runtime *runtime)
{
  struct twist_lane **grown;
  size_t want = (size_t) runtime->threads;
  size_t i;

  if (runtime->n_lanes >= want)
    return TWIST_OK;
  /* The storage pool has a thread for each loop, and two at least.  It has had
     no jobs yet, so it can be made again for them.  */
  if (want > 2)
    {
      struct twist_storage *st = twist_storage_new (want, 32);

      if (st == NULL)
        return TWIST_ERR_NOMEM;
      twist_storage_free (runtime->storage);
      runtime->storage = st;
    }
  grown = realloc (runtime->lanes, want * sizeof *grown);
  if (grown == NULL)
    return TWIST_ERR_NOMEM;
  runtime->lanes = grown;
  for (i = runtime->n_lanes; i < want; i++)
    {
      struct twist_lane *lane = lane_new (runtime, (int) i, 0);

      if (lane == NULL)
        break;
      runtime->lanes[i] = lane;
      runtime->n_lanes = i + 1;
      if (pthread_create (&lane->thread, NULL, lane_main, lane) != 0)
        break;
      lane->threaded = 1;
    }
  if (runtime->n_lanes < want || !runtime->lanes[want - 1]->threaded)
    {
      /* Without all of them there are none but the first.  */
      lanes_stop (runtime, 1);
      for (i = 1; i < runtime->n_lanes; i++)
        lane_free (runtime->lanes[i]);
      runtime->n_lanes = 1;
      return TWIST_ERR_NOMEM;
    }
  return TWIST_OK;
}

/* ---- the lane's list of what it runs ---- */

static int
live_add (struct twist_lane *lane, struct twist_transfer *transfer,
          unsigned long serial)
{
  if (lane->n_live == lane->live_cap)
    {
      size_t cap = lane->live_cap == 0 ? 8 : lane->live_cap * 2;
      struct twist_lane_live *grown = realloc (lane->live,
                                               cap * sizeof *grown);

      if (grown == NULL)
        return TWIST_ERR_NOMEM;
      lane->live = grown;
      lane->live_cap = cap;
    }
  lane->live[lane->n_live].transfer = transfer;
  lane->live[lane->n_live].serial = serial;
  lane->n_live++;
  return TWIST_OK;
}

/* The transfer with SERIAL, and take it out of the list if REMOVE.  */
static struct twist_transfer *
live_find (struct twist_lane *lane, unsigned long serial, int remove)
{
  size_t i;

  for (i = 0; i < lane->n_live; i++)
    if (lane->live[i].serial == serial)
      {
        struct twist_transfer *t = lane->live[i].transfer;

        if (remove)
          lane->live[i] = lane->live[--lane->n_live];
        return t;
      }
  return NULL;
}

/* ---- commands to a lane ---- */

/* The table, with its lock held, asks for an idle connection of LOOP to be
   closed: a transfer on another lane waits for its place.  The lane does it.  */
struct evict_cmd
{
  struct twist_runtime *runtime;
  struct twist_lane *lane;
  char key[1100];
};

static void
lane_evict_cmd (void *user)
{
  struct evict_cmd *c = user;

  if (!c->runtime->closing)
    twist_pool_evict_one (c->lane->pool, c->key);
  free (c);
}

static void
runtime_evict (void *user, struct twist_loop *loop, const char *key)
{
  struct twist_runtime *runtime = user;
  struct evict_cmd *c;
  size_t i;

  for (i = 0; i < runtime->n_lanes; i++)
    if (runtime->lanes[i]->loop == loop)
      break;
  if (i == runtime->n_lanes || strlen (key) >= sizeof c->key)
    return;
  c = calloc (1, sizeof *c);
  if (c == NULL)
    return;
  c->runtime = runtime;
  c->lane = runtime->lanes[i];
  strcpy (c->key, key);
  if (twist_loop_post (loop, lane_evict_cmd, c) != TWIST_OK)
    free (c);
}

static void
lane_start_cmd (void *user)
{
  struct lane_cmd *c = user;
  struct twist_runtime *runtime = c->runtime;

  if (!runtime->closing)
    {
      int *in_call = lane_incall (c->lane);

      if (live_add (c->lane, c->transfer, c->serial) != TWIST_OK)
        twist_transfer_finish (c->transfer, TWIST_ERR_NOMEM);
      else
        {
          (*in_call)++;
          twist_transfer_start (c->transfer);
          (*in_call)--;
        }
    }
  free (c);
}

static void
lane_cancel_cmd (void *user)
{
  struct lane_cmd *c = user;

  if (!c->runtime->closing)
    {
      struct twist_transfer *t = live_find (c->lane, c->serial, 0);
      int *in_call = lane_incall (c->lane);

      /* The loop lets go of its connection when it reports.  */
      if (t != NULL && !t->done)
        {
          (*in_call)++;
          twist_transfer_finish (t, TWIST_ERR_ABORTED);
          (*in_call)--;
        }
    }
  free (c);
}

/* The driving thread is freeing a transfer that is running here: let go of
   what it holds, on this thread, and say whether its end has been posted.  */
static void
lane_drop_cmd (void *user)
{
  struct lane_cmd *c = user;
  struct drop_sync *sync = c->sync;
  struct twist_transfer *t = live_find (c->lane, c->serial, 1);
  int unposted = 0;

  if (t != NULL)
    {
      int *in_call = lane_incall (c->lane);

      (*in_call)++;
      twist_transfer_release (t);
      (*in_call)--;
      if (t->reap != NULL)
        {
          twist_timer_cancel (t->reap);
          t->reap = NULL;
        }
      unposted = t->deliver_node != NULL;
    }
  free (c);
  pthread_mutex_lock (&sync->mu);
  sync->unposted = unposted;
  sync->done = 1;
  pthread_cond_signal (&sync->cv);
  pthread_mutex_unlock (&sync->mu);
}

/* On the first lane: a transfer of another lane is over.  The runtime is there
   until it is freed, and a command that is run after it began to be (the
   queues are emptied then) does nothing.  */
static void
deliver_cmd (void *user)
{
  struct deliver *d = user;
  struct twist_runtime *runtime = d->runtime;
  struct twist_started gone;
  struct twist_transfer *transfer;
  size_t i;
  int result;

  if (runtime->closing)
    {
      free (d);
      return;
    }
  for (i = 0; i < runtime->n_transfers; i++)
    if (runtime->transfers[i].serial == d->serial)
      break;
  if (i == runtime->n_transfers)
    {
      /* It was freed meanwhile.  */
      free (d);
      return;
    }
  entry_take (runtime, i, &gone);
  free (gone.place_key);
  transfer = gone.transfer;
  result = transfer->result;
  transfer->runtime = NULL;
  transfer->loop = NULL;
  transfer->lane = NULL;
  transfer->started = 0;
  transfer->deliver_node = NULL;
  transfer->deliver = NULL;
  free (d);
  if (gone.done_cb != NULL)
    gone.done_cb (transfer, result, gone.done_user);
}

void
twist_runtime_free (twist_runtime *runtime)
{
  size_t i;

  if (runtime == NULL)
    return;
  /* Not from a callback: the transfers and the loop are in use by the call
     that made it.  What is not freed here is not freed at all, which is
     better than freed under a running call.  */
  if (runtime->in_call > 0 || on_lane_thread (runtime))
    return;
  /* The threads end first.  What is left of their transfers is then ours to
     let go of, here, and a command that is run from now on does nothing.  */
  lanes_stop (runtime, 1);
  runtime->closing = 1;
  /* Transfer state releases its connection against the loop and the pool,
     so it goes first, while both are alive.  A transfer still running is
     dropped, with no call to its callback.  */
  for (i = 0; i < runtime->n_transfers; i++)
    {
      struct twist_transfer *t = runtime->transfers[i].transfer;

      /* Its end was not posted if the node is still there.  */
      if (t->deliver_node != NULL)
        {
          twist_loop_cmd_free (t->deliver_node);
          free (t->deliver);
          t->deliver_node = NULL;
          t->deliver = NULL;
        }
      (*lane_incall (runtime->lanes[runtime->transfers[i].lane]))++;
      twist_transfer_release (t);
      (*lane_incall (runtime->lanes[runtime->transfers[i].lane]))--;
    }
  while (runtime->n_transfers > 0)
    remove_transfer (runtime, runtime->transfers[runtime->n_transfers - 1]
                              .transfer);
  for (i = 0; i < runtime->n_lanes; i++)
    {
      twist_pool_free (runtime->lanes[i]->pool);
      runtime->lanes[i]->pool = NULL;
    }
  runtime->pool = NULL;
  twist_dns_cache_free (runtime->dns);
  twist_jar_free (runtime->jar);
  twist_hsts_free (runtime->hsts);
  twist_altsvc_free (runtime->altsvc);
  twist_tunnel_free_all (runtime);
  twist_session_free_all (runtime);
  twist_origintab_free (runtime->origintab);
  twist_storage_free (runtime->storage);
  /* The storage threads are joined, so every job has run and posted its
     completion.  Deliver them: each owns its job and what the job carries,
     and dropped with the loop they would leak.  The runtime is there to be
     asked, as the ends of transfers that are in these queues look at it, and
     it is freed after them.  */
  for (i = runtime->n_lanes; i > 0; i--)
    twist_loop_drain (runtime->lanes[i - 1]->loop);
  for (i = 0; i < runtime->n_lanes; i++)
    {
      runtime->lanes[i]->pool = NULL;
      lane_free (runtime->lanes[i]);
    }
  free (runtime->lanes);
  free (runtime->transfers);
  free (runtime);
}

/* The loop's call, once the handler that ended the transfer has returned:
   release what the transfer holds and let it go.  On the first lane the
   program is told here; on another the end goes to the first lane and the
   program is told there.  */
static void
reap (void *user)
{
  struct twist_transfer *transfer = user;
  struct twist_runtime *runtime = transfer->runtime;
  struct twist_lane *lane = transfer->lane;

  if (runtime == NULL || !transfer->started)
    return;
  if (lane != NULL && lane->index != 0)
    {
      struct twist_cmd *node = transfer->deliver_node;
      int *in_call = lane_incall (lane);

      (*in_call)++;
      twist_transfer_release (transfer);
      (*in_call)--;
      transfer->reap = NULL;
      live_find (lane, transfer->serial, 1);
      /* Not to be touched after this: the program may free it.  */
      transfer->deliver_node = NULL;
      if (node != NULL)
        twist_loop_cmd_post (runtime->loop, node);
      return;
    }
  else
    {
      struct twist_started gone;
      int i = entry_index (runtime, transfer);
      int result = transfer->result;

      runtime->in_call++;
      twist_transfer_release (transfer);
      runtime->in_call--;
      if (i >= 0)
        {
          entry_take (runtime, (size_t) i, &gone);
          free (gone.place_key);
        }
      else
        memset (&gone, 0, sizeof gone);
      if (transfer->reap != NULL)
        {
          twist_timer_cancel (transfer->reap);
          transfer->reap = NULL;
        }
      transfer->started = 0;
      transfer->runtime = NULL;
      transfer->loop = NULL;
      transfer->lane = NULL;
      transfer->done_cb = NULL;
      transfer->done_user = NULL;
      if (gone.done_cb != NULL)
        {
          runtime->in_call++;
          gone.done_cb (transfer, result, gone.done_user);
          runtime->in_call--;
        }
    }
}

/* TRANSFER has ended (twist_transfer_finish): see that the program is told,
   from the loop.  */
int
twist_runtime_finished (struct twist_transfer *transfer)
{
  struct twist_runtime *runtime = transfer->runtime;

  if (runtime == NULL || !transfer->started || transfer->reap != NULL)
    return TWIST_OK;
  return twist_loop_schedule (transfer->loop, twist_loop_now (transfer->loop),
                              reap,
                              transfer, &transfer->reap);
}

int
twist_runtime_detach (struct twist_transfer *transfer)
{
  struct twist_runtime *runtime = transfer->runtime;
  struct twist_lane *lane = transfer->lane;

  if (runtime == NULL)
    return TWIST_OK;
  /* From a callback the transfer may be in use by the call that made it, and
     releasing its connection would free what that call is still running on.
     The same on a thread of the runtime's, where it is not for the program
     to wait.  */
  if (runtime->in_call > 0 || on_lane_thread (runtime))
    return TWIST_ERR_RECURSIVE;
  if (lane != NULL && lane->index != 0 && lane->threaded && !runtime->closing)
    {
      struct drop_sync sync;
      struct lane_cmd *c = calloc (1, sizeof *c);
      struct twist_cmd *node;

      if (c == NULL)
        return TWIST_ERR_NOMEM;
      node = twist_loop_cmd_new (lane_drop_cmd, c);
      if (node == NULL)
        {
          free (c);
          return TWIST_ERR_NOMEM;
        }
      memset (&sync, 0, sizeof sync);
      pthread_mutex_init (&sync.mu, NULL);
      pthread_cond_init (&sync.cv, NULL);
      c->runtime = runtime;
      c->lane = lane;
      c->serial = transfer->serial;
      c->sync = &sync;
      twist_loop_cmd_post (lane->loop, node);
      pthread_mutex_lock (&sync.mu);
      while (!sync.done)
        pthread_cond_wait (&sync.cv, &sync.mu);
      pthread_mutex_unlock (&sync.mu);
      pthread_cond_destroy (&sync.cv);
      pthread_mutex_destroy (&sync.mu);
      if (sync.unposted)
        {
          twist_loop_cmd_free (transfer->deliver_node);
          free (transfer->deliver);
        }
      transfer->deliver_node = NULL;
      transfer->deliver = NULL;
      remove_transfer (runtime, transfer);
      return TWIST_OK;
    }
  runtime->in_call++;
  twist_transfer_release (transfer);
  runtime->in_call--;
  remove_transfer (runtime, transfer);
  twist_runtime_notify_timer (runtime);
  return TWIST_OK;
}

/* The lane with the least to do, looking from where the search last began.  */
static int
lane_least_loaded (struct twist_runtime *runtime)
{
  size_t start = runtime->rotate % runtime->n_lanes;
  size_t best = start;
  size_t i;

  for (i = 1; i < runtime->n_lanes; i++)
    {
      size_t k = (start + i) % runtime->n_lanes;

      if (runtime->lanes[k]->load < runtime->lanes[best]->load)
        best = k;
    }
  runtime->rotate = start + 1;
  return (int) best;
}

/* The lane TRANSFER is to run on.  Those that can share a connection to an
   origin go together, where the origin was first put, so that they find it;
   the rest go where there is least to do.  *PLACE is the origin's key if the
   transfer is counted on it, to be freed.  */
static int
place_transfer (struct twist_runtime *runtime, struct twist_transfer *transfer,
                char **place)
{
  *place = NULL;
  if (runtime->n_lanes == 1)
    return 0;
  if (transfer->url == NULL && transfer->url_string != NULL)
    twist_url_parse_int (transfer->url_string, &transfer->url);
  if (transfer->url != NULL && twist_http_may_multiplex (transfer))
    {
      char okey[1024];

      if (twist_transfer_origin_okey (transfer, okey, sizeof okey) == TWIST_OK)
        {
          int lane = 0;
          int found = twist_origintab_pin (runtime->origintab, okey, &lane);

          if (found == 0)
            {
              lane = lane_least_loaded (runtime);
              if (twist_origintab_pin_set (runtime->origintab, okey, lane)
                  != TWIST_OK)
                return lane;
            }
          if (found >= 0)
            {
              *place = twist_strdup (okey);
              if (*place == NULL)
                twist_origintab_unpin (runtime->origintab, okey);
              return lane;
            }
        }
    }
  return lane_least_loaded (runtime);
}

int
twist_runtime_start (twist_runtime *runtime, twist_transfer *transfer,
                     twist_done_callback done, void *user)
{
  struct lane_cmd *c = NULL;
  struct deliver *d = NULL;
  struct twist_cmd *start_node = NULL;
  struct twist_cmd *deliver_node = NULL;
  struct twist_started *e;
  struct twist_lane *lane;
  char *place = NULL;
  int lane_index;

  if (runtime == NULL || transfer == NULL || transfer->runtime != NULL)
    return TWIST_ERR_INVAL;
  if (on_lane_thread (runtime))
    return TWIST_ERR_RECURSIVE;
  if (runtime->n_transfers == runtime->transfers_cap)
    {
      size_t cap = runtime->transfers_cap == 0 ? 4
                   : runtime->transfers_cap * 2;
      struct twist_started *grown = realloc (runtime->transfers,
                                             cap * sizeof *grown);

      if (grown == NULL)
        return TWIST_ERR_NOMEM;
      runtime->transfers = grown;
      runtime->transfers_cap = cap;
    }
  if (runtime->threads > 1 && runtime->n_lanes == 1)
    {
      int rc = lanes_make (runtime);

      if (rc != TWIST_OK)
        return rc;
    }
  lane_index = place_transfer (runtime, transfer, &place);
  lane = runtime->lanes[lane_index];
  if (lane_index != 0)
    {
      c = calloc (1, sizeof *c);
      d = calloc (1, sizeof *d);
      if (c != NULL)
        start_node = twist_loop_cmd_new (lane_start_cmd, c);
      if (d != NULL)
        deliver_node = twist_loop_cmd_new (deliver_cmd, d);
      if (c == NULL || d == NULL || start_node == NULL || deliver_node == NULL)
        {
          if (place != NULL)
            twist_origintab_unpin (runtime->origintab, place);
          free (place);
          free (c);
          free (d);
          twist_loop_cmd_free (start_node);
          twist_loop_cmd_free (deliver_node);
          return TWIST_ERR_NOMEM;
        }
    }
  e = &runtime->transfers[runtime->n_transfers++];
  e->transfer = transfer;
  e->serial = ++runtime->next_serial;
  e->done_cb = done;
  e->done_user = user;
  e->place_key = place;
  e->lane = lane_index;
  lane->load++;
  transfer->runtime = runtime;
  transfer->lane = lane;
  transfer->loop = lane->loop;
  transfer->serial = e->serial;
  transfer->done_cb = done;
  transfer->done_user = user;
  transfer->started = 1;
  transfer->done = 0;
  runtime->started_any = 1;
  if (lane_index != 0)
    {
      c->runtime = runtime;
      c->lane = lane;
      c->transfer = transfer;
      c->serial = e->serial;
      d->runtime = runtime;
      d->serial = e->serial;
      transfer->deliver_node = deliver_node;
      transfer->deliver = d;
      twist_loop_cmd_post (lane->loop, start_node);
      return TWIST_OK;
    }
  /* A transfer that cannot begin ends here, and is reported as any other.  */
  runtime->in_call++;
  twist_transfer_start (transfer);
  runtime->in_call--;
  twist_runtime_notify_timer (runtime);
  return TWIST_OK;
}

int
twist_runtime_cancel (twist_runtime *runtime, twist_transfer *transfer)
{
  struct twist_lane *lane;

  if (runtime == NULL || transfer == NULL || transfer->runtime != runtime)
    return TWIST_ERR_INVAL;
  if (on_lane_thread (runtime))
    return TWIST_ERR_RECURSIVE;
  lane = transfer->lane;
  if (lane != NULL && lane->index != 0)
    {
      /* Asked of the lane, which knows whether the transfer is over.  */
      struct lane_cmd *c = calloc (1, sizeof *c);
      struct twist_cmd *node;

      if (c == NULL)
        return TWIST_ERR_NOMEM;
      node = twist_loop_cmd_new (lane_cancel_cmd, c);
      if (node == NULL)
        {
          free (c);
          return TWIST_ERR_NOMEM;
        }
      c->runtime = runtime;
      c->lane = lane;
      c->serial = transfer->serial;
      twist_loop_cmd_post (lane->loop, node);
      return TWIST_OK;
    }
  if (!transfer->done)
    {
      twist_transfer_finish (transfer, TWIST_ERR_ABORTED);
      /* Let go of the connection now, unless this is from a call that the
         transfer may be making: then the loop does it when it reports.  */
      if (runtime->in_call == 0)
        {
          runtime->in_call++;
          twist_transfer_release (transfer);
          runtime->in_call--;
        }
    }
  twist_runtime_notify_timer (runtime);
  return TWIST_OK;
}

int
twist_runtime_setopt (twist_runtime *runtime, int option, ...)
{
  va_list ap;
  int rc = TWIST_OK;

  if (runtime == NULL || runtime->started_any)
    return TWIST_ERR_INVAL;
  va_start (ap, option);
  switch (option)
    {
    case TWIST_RUNTIMEOPT_MAX_HOST_CONNECTIONS:
      {
        long n = va_arg (ap, long);

        if (n < 0)
          rc = TWIST_ERR_INVAL;
        else
          twist_origintab_set_cap (runtime->origintab, n);
      }
      break;
    case TWIST_RUNTIMEOPT_THREADS:
      {
        long n = va_arg (ap, long);

        if (n < 1 || n > 64 || runtime->embedded)
          rc = TWIST_ERR_INVAL;
        else
          runtime->threads = n;
      }
      break;
    default:
      rc = TWIST_ERR_INVAL;
      break;
    }
  va_end (ap);
  return rc;
}

int
twist_runtime_run_once (twist_runtime *runtime, int timeout_ms)
{
  if (runtime == NULL || runtime->embedded)
    return TWIST_ERR_INVAL;
  if (runtime->in_call > 0)
    return TWIST_ERR_RECURSIVE;
  return twist_loop_run_once_ms (runtime->loop, timeout_ms);
}

int
twist_runtime_on_ready (twist_runtime *runtime, int fd, int events)
{
  if (runtime == NULL || !runtime->embedded)
    return TWIST_ERR_INVAL;
  if (runtime->in_call > 0)
    return TWIST_ERR_RECURSIVE;
  if (events & TWIST_POLL_IN)
    twist_loop_on_readable (runtime->loop, fd);
  if (events & TWIST_POLL_OUT)
    twist_loop_on_writable (runtime->loop, fd);
  twist_runtime_notify_timer (runtime);
  return TWIST_OK;
}

int
twist_runtime_on_timer (twist_runtime *runtime)
{
  if (runtime == NULL || !runtime->embedded)
    return TWIST_ERR_INVAL;
  if (runtime->in_call > 0)
    return TWIST_ERR_RECURSIVE;
  twist_loop_on_timer (runtime->loop, twist_loop_now (runtime->loop));
  twist_runtime_notify_timer (runtime);
  return TWIST_OK;
}

struct twist_jar *
twist_transfer_jar (struct twist_transfer *transfer)
{
  return transfer != NULL && transfer->use_cookies && transfer->runtime != NULL
         ? transfer->runtime->jar : NULL;
}

struct twist_hsts *
twist_transfer_hsts (struct twist_transfer *transfer)
{
  return transfer != NULL && transfer->use_hsts && transfer->runtime != NULL
         ? transfer->runtime->hsts : NULL;
}

struct twist_altsvc *
twist_transfer_altsvc (struct twist_transfer *transfer)
{
  return transfer != NULL && transfer->use_altsvc && transfer->runtime != NULL
         ? transfer->runtime->altsvc : NULL;
}
