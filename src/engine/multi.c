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

#include <stdarg.h>
#include <stdlib.h>

static void multi_watch (void *user, int fd, int interest);

twist_multi *
twist_multi_init (void)
{
  struct twist_multi *multi = calloc (1, sizeof *multi);

  if (multi == NULL)
    return NULL;
  multi->loop = twist_loop_new (0);
  if (multi->loop == NULL)
    {
      free (multi);
      return NULL;
    }
  multi->own_loop = 1;
  multi->last_timeout = -2;
  multi->storage = twist_storage_new (2, 32);
  if (multi->storage == NULL)
    {
      twist_loop_free (multi->loop);
      free (multi);
      return NULL;
    }
  multi->pool = twist_pool_new ();
  multi->dns = twist_dns_cache_new ();
  if (multi->pool == NULL || multi->dns == NULL)
    {
      twist_dns_cache_free (multi->dns);
      twist_pool_free (multi->pool);
      twist_storage_free (multi->storage);
      twist_loop_free (multi->loop);
      free (multi);
      return NULL;
    }
  twist_loop_set_multi (multi->loop, multi);
  twist_loop_set_watch (multi->loop, multi_watch, multi);
  return multi;
}

static void
multi_watch (void *user, int fd, int interest)
{
  struct twist_multi *multi = user;
  int what = TWIST_POLL_NONE;

  if (multi->socket_cb == NULL)
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
  multi->in_call++;
  multi->socket_cb (NULL, fd, what, multi->socket_user, NULL);
  multi->in_call--;
}

/* Remember that POOL, which is not ours, holds or may hold connections
   bound to this handle's loop.  */
void
twist_multi_note_pool (struct twist_multi *multi, struct twist_pool *pool)
{
  size_t i;

  if (multi == NULL || pool == NULL || pool == multi->pool)
    return;
  for (i = 0; i < multi->n_shared_pools; i++)
    if (multi->shared_pools[i] == pool)
      return;
  if (multi->n_shared_pools == multi->cap_shared_pools)
    {
      size_t cap = multi->cap_shared_pools == 0 ? 2 : multi->cap_shared_pools * 2;
      struct twist_pool **grown = realloc (multi->shared_pools,
                                           cap * sizeof *grown);

      if (grown == NULL)
        return;
      multi->shared_pools = grown;
      multi->cap_shared_pools = cap;
    }
  multi->shared_pools[multi->n_shared_pools++] = pool;
}

void
twist_multi_cleanup (twist_multi *multi)
{
  size_t i;

  if (multi == NULL)
    return;
  /* Not from a callback: the handles and the loop are in use by the call
     that made it.  What is not freed here is not freed at all, which is
     better than freed under a running call.  */
  if (multi->in_call > 0)
    return;
  /* Transfer state releases its connection against the loop and the pool,
     so it goes first, while both are alive.  */
  for (i = 0; i < multi->n_easies; i++)
    twist_easy_release_transfer (multi->easies[i]);
  for (i = 0; i < multi->n_easies; i++)
    {
      multi->easies[i]->multi = NULL;
      multi->easies[i]->loop = NULL;
    }
  twist_pool_free (multi->pool);
  twist_dns_cache_free (multi->dns);
  twist_session_free_all (multi);
  twist_storage_free (multi->storage);
  /* The pool's threads are joined, so every job has run and posted its
     completion.  Deliver them: each owns its job and what the job carries,
     and dropped with the loop they would leak.  */
  if (multi->own_loop)
    {
      twist_loop_drain (multi->loop);
      /* A share's pool keeps what it holds after this loop is gone; what is
         bound to the loop must not stay in it.  */
      for (i = 0; i < multi->n_shared_pools; i++)
        twist_pool_drop_loop (multi->shared_pools[i], multi->loop);
      twist_loop_free (multi->loop);
    }
  free (multi->shared_pools);
  free (multi->easies);
  free (multi->done);
  free (multi->done_result);
  free (multi);
}

int
twist_multi_add_handle (twist_multi *multi, twist_easy *easy)
{
  int rc;

  if (multi == NULL || easy == NULL)
    return TWIST_ERR_INVAL;
  if (multi->in_call > 0)
    return TWIST_ERR_RECURSIVE;
  if (easy->multi != NULL)
    return TWIST_ERR_INVAL;
  if (multi->n_easies == multi->easies_cap)
    {
      size_t cap = multi->easies_cap == 0 ? 4 : multi->easies_cap * 2;
      struct twist_easy **grown = realloc (multi->easies, cap * sizeof *grown);
      if (grown == NULL)
        return TWIST_ERR_NOMEM;
      multi->easies = grown;
      multi->easies_cap = cap;
    }
  multi->easies[multi->n_easies++] = easy;
  easy->multi = multi;
  easy->loop = multi->loop;
  if (easy->share != NULL)
    twist_multi_note_pool (multi, easy->share->pool);
  easy->done = 0;
  multi->in_call++;
  rc = twist_transfer_start (easy);
  multi->in_call--;
  return rc;
}

int
twist_multi_remove_handle (twist_multi *multi, twist_easy *easy)
{
  size_t i;

  if (multi == NULL || easy == NULL)
    return TWIST_ERR_INVAL;
  /* curl's answer too, CURLM_RECURSIVE_API_CALL: from a callback the handle
     is in use by the code that called it, and releasing its connection would
     free what that code is still running on.  */
  if (multi->in_call > 0)
    return TWIST_ERR_RECURSIVE;
  for (i = 0; i < multi->n_easies; i++)
    if (multi->easies[i] == easy)
      {
        multi->in_call++;
        twist_easy_release_transfer (easy);
        multi->in_call--;
        multi->easies[i] = multi->easies[multi->n_easies - 1];
        multi->n_easies--;
        easy->multi = NULL;
        easy->loop = NULL;
        return TWIST_OK;
      }
  return TWIST_ERR_INVAL;
}

static int
count_running (struct twist_multi *multi)
{
  size_t i;
  int n = 0;

  for (i = 0; i < multi->n_easies; i++)
    if (!multi->easies[i]->done)
      n++;
  return n;
}

int
twist_multi_perform (twist_multi *multi, int *running)
{
  int rc;

  if (multi == NULL)
    return TWIST_ERR_INVAL;
  if (multi->in_call > 0)
    return TWIST_ERR_RECURSIVE;
  rc = twist_loop_run_once_ms (multi->loop, 0);
  if (running != NULL)
    *running = count_running (multi);
  return rc;
}

int
twist_multi_socket_action (twist_multi *multi, int fd, int ev, int *running)
{
  uint64_t now;

  if (multi == NULL)
    return TWIST_ERR_INVAL;
  if (multi->in_call > 0)
    return TWIST_ERR_RECURSIVE;
  now = twist_loop_now (multi->loop);
  if (fd == TWIST_SOCKET_TIMEOUT)
    twist_loop_on_timer (multi->loop, now);
  else
    {
      if (ev & TWIST_POLL_IN)
        twist_loop_on_readable (multi->loop, fd);
      if (ev & TWIST_POLL_OUT)
        twist_loop_on_writable (multi->loop, fd);
    }
  if (running != NULL)
    *running = count_running (multi);
  return TWIST_OK;
}

int
twist_multi_timeout (twist_multi *multi, long *timeout_ms)
{
  if (multi == NULL || timeout_ms == NULL)
    return TWIST_ERR_INVAL;
  *timeout_ms = twist_loop_next_timeout (multi->loop, twist_loop_now (multi->loop));
  return TWIST_OK;
}

int
twist_multi_setopt (twist_multi *multi, int opt, ...)
{
  va_list ap;

  if (multi == NULL)
    return TWIST_ERR_INVAL;
  va_start (ap, opt);
  switch (opt)
    {
    case TWISTMOPT_SOCKETFUNCTION:
      multi->socket_cb = va_arg (ap, twist_socket_callback);
      if (multi->socket_cb != NULL && multi->loop != NULL
          && twist_loop_waker (multi->loop) >= 0)
        multi_watch (multi, twist_loop_waker (multi->loop),
                     TWIST_INTEREST_READ);
      break;
    case TWISTMOPT_SOCKETDATA:
      multi->socket_user = va_arg (ap, void *);
      break;
    case TWISTMOPT_TIMERFUNCTION:
      multi->timer_cb = va_arg (ap, twist_timer_callback);
      break;
    case TWISTMOPT_TIMERDATA:
      multi->timer_user = va_arg (ap, void *);
      break;
    default:
      va_end (ap);
      return TWIST_ERR_UNSUPPORTED;
    }
  va_end (ap);
  return TWIST_OK;
}

int
twist_multi_info_read (twist_multi *multi, int *msgs_left, twist_easy **easy,
                       int *result)
{
  size_t left;

  if (multi == NULL)
    return TWIST_ERR_INVAL;
  if (multi->done_off >= multi->n_done)
    {
      if (msgs_left != NULL)
        *msgs_left = 0;
      if (easy != NULL)
        *easy = NULL;
      return TWIST_OK;
    }
  if (easy != NULL)
    *easy = multi->done[multi->done_off];
  if (result != NULL)
    *result = multi->done_result[multi->done_off];
  multi->done_off++;
  left = multi->n_done - multi->done_off;
  if (msgs_left != NULL)
    *msgs_left = (int) left;
  return TWIST_OK;
}
