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

/* The runtime: one event loop, the transfers that run on it, and what
   they keep for each other.  Everything in it is driven by events.  A
   transfer is started, it ends by calling twist_transfer_finish from whatever
   handler had it, and the loop then reports the result to the program in a
   call of its own, after that handler has returned: the program is told
   from the loop and never from inside a protocol handler, and so may do
   anything to the transfer, including free it.  */

static void runtime_watch (void *user, int fd, int interest);

static struct twist_runtime *
runtime_new (int embedded, twist_watch_callback watch,
             twist_timer_callback timer, void *user)
{
  struct twist_runtime *runtime = calloc (1, sizeof *runtime);

  if (runtime == NULL)
    return NULL;
  runtime->loop = twist_loop_new (embedded);
  if (runtime->loop == NULL)
    {
      free (runtime);
      return NULL;
    }
  runtime->last_deadline = -2;
  runtime->storage = twist_storage_new (2, 32);
  if (runtime->storage == NULL)
    {
      twist_loop_free (runtime->loop);
      free (runtime);
      return NULL;
    }
  runtime->pool = twist_pool_new ();
  runtime->dns = twist_dns_cache_new ();
  runtime->jar = twist_jar_new ();
  runtime->hsts = twist_hsts_new ();
  runtime->altsvc = twist_altsvc_new ();
  if (runtime->pool == NULL || runtime->dns == NULL || runtime->jar == NULL
      || runtime->hsts == NULL || runtime->altsvc == NULL)
    {
      twist_altsvc_free (runtime->altsvc);
      twist_hsts_free (runtime->hsts);
      twist_jar_free (runtime->jar);
      twist_dns_cache_free (runtime->dns);
      twist_pool_free (runtime->pool);
      twist_storage_free (runtime->storage);
      twist_loop_free (runtime->loop);
      free (runtime);
      return NULL;
    }
  twist_loop_set_runtime (runtime->loop, runtime);
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

/* Take TRANSFER out of the transfers of RUNTIME.  Its handler is already
   gone.  */
static void
remove_transfer (struct twist_runtime *runtime,
                 struct twist_transfer *transfer)
{
  size_t i;

  if (transfer->reap != NULL)
    {
      twist_timer_cancel (transfer->reap);
      transfer->reap = NULL;
    }
  transfer->started = 0;
  for (i = 0; i < runtime->n_transfers; i++)
    if (runtime->transfers[i] == transfer)
      {
        runtime->transfers[i] = runtime->transfers[runtime->n_transfers - 1];
        runtime->n_transfers--;
        break;
      }
  transfer->runtime = NULL;
  transfer->loop = NULL;
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
  if (runtime->in_call > 0)
    return;
  /* Transfer state releases its connection against the loop and the pool,
     so it goes first, while both are alive.  A transfer still running is
     dropped, with no call to its callback.  */
  for (i = 0; i < runtime->n_transfers; i++)
    twist_transfer_release (runtime->transfers[i]);
  while (runtime->n_transfers > 0)
    remove_transfer (runtime, runtime->transfers[runtime->n_transfers - 1]);
  twist_pool_free (runtime->pool);
  twist_dns_cache_free (runtime->dns);
  twist_jar_free (runtime->jar);
  twist_hsts_free (runtime->hsts);
  twist_altsvc_free (runtime->altsvc);
  twist_session_free_all (runtime);
  twist_storage_free (runtime->storage);
  /* The storage threads are joined, so every job has run and posted its
     completion.  Deliver them: each owns its job and what the job carries,
     and dropped with the loop they would leak.  */
  twist_loop_drain (runtime->loop);
  twist_loop_free (runtime->loop);
  free (runtime->transfers);
  free (runtime);
}

/* The loop's call, once the handler that ended the transfer has returned:
   release what the transfer holds, let it go, and tell the program.  */
static void
reap (void *user)
{
  struct twist_transfer *transfer = user;
  struct twist_runtime *runtime = transfer->runtime;
  twist_done_callback cb = transfer->done_cb;
  void *cb_user = transfer->done_user;
  int result = transfer->result;

  if (runtime == NULL || !transfer->started)
    return;
  runtime->in_call++;
  twist_transfer_release (transfer);
  runtime->in_call--;
  remove_transfer (runtime, transfer);
  transfer->done_cb = NULL;
  transfer->done_user = NULL;
  if (cb != NULL)
    {
      runtime->in_call++;
      cb (transfer, result, cb_user);
      runtime->in_call--;
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
  return twist_loop_schedule (runtime->loop, twist_loop_now (runtime->loop),
                              reap,
                              transfer, &transfer->reap);
}

int
twist_runtime_detach (struct twist_transfer *transfer)
{
  struct twist_runtime *runtime = transfer->runtime;

  if (runtime == NULL)
    return TWIST_OK;
  /* From a callback the transfer may be in use by the call that made it, and
     releasing its connection would free what that call is still running on.  */
  if (runtime->in_call > 0)
    return TWIST_ERR_RECURSIVE;
  runtime->in_call++;
  twist_transfer_release (transfer);
  runtime->in_call--;
  remove_transfer (runtime, transfer);
  twist_runtime_notify_timer (runtime);
  return TWIST_OK;
}

int
twist_runtime_start (twist_runtime *runtime, twist_transfer *transfer,
                     twist_done_callback done, void *user)
{
  if (runtime == NULL || transfer == NULL || transfer->runtime != NULL)
    return TWIST_ERR_INVAL;
  if (runtime->n_transfers == runtime->transfers_cap)
    {
      size_t cap = runtime->transfers_cap == 0 ? 4
                   : runtime->transfers_cap * 2;
      struct twist_transfer **grown = realloc (runtime->transfers,
                                               cap * sizeof *grown);

      if (grown == NULL)
        return TWIST_ERR_NOMEM;
      runtime->transfers = grown;
      runtime->transfers_cap = cap;
    }
  runtime->transfers[runtime->n_transfers++] = transfer;
  transfer->runtime = runtime;
  transfer->loop = runtime->loop;
  transfer->done_cb = done;
  transfer->done_user = user;
  transfer->started = 1;
  transfer->done = 0;
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
  if (runtime == NULL || transfer == NULL || transfer->runtime != runtime)
    return TWIST_ERR_INVAL;
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
