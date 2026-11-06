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

#define XQ_MAX_ 65536

/* The body going to the application's write callback, which can say it is full
   (TWIST_WRITEFUNC_PAUSE).  It then takes none of what it was given; the rest
   that comes is held, and all of it is given again, in order, on resume.  The
   handler stops the peer where it can (the transfer's pause function: an
   HTTP/2 stream's window is not given back, a TCP read is paused), and what
   was already on its way is the most that is held.  */

#define SINK_HELD_MAX (4u * 1024u * 1024u)

/* Pieces of this size go to the callback, as they always have.  */
#define SINK_PIECE 512

static int
hold (struct twist_transfer *t, const uint8_t *data, size_t len)
{
  if (len > SINK_HELD_MAX - t->held_len)
    return -1;
  if (t->held_len + len > t->held_cap)
    {
      size_t cap = t->held_cap == 0 ? 16384 : t->held_cap;
      uint8_t *grown;

      while (cap < t->held_len + len)
        cap *= 2;
      grown = realloc (t->held, cap);
      if (grown == NULL)
        return -1;
      t->held = grown;
      t->held_cap = cap;
    }
  memcpy (t->held + t->held_len, data, len);
  t->held_len += len;
  return 0;
}

/* Give DATA to the callback.  Returns how many it took; sets *PAUSED if it
   said it was full, with none of the piece it was refused taken.  */
static size_t
give (struct twist_transfer *t, const uint8_t *data, size_t len, int *paused)
{
  size_t off = 0;

  *paused = 0;
  while (off < len)
    {
      char buf[SINK_PIECE];
      size_t n = len - off;
      size_t got;

      if (n > sizeof buf)
        n = sizeof buf;
      memcpy (buf, data + off, n);
      got = t->write_cb (buf, 1, n, t->write_data);
      if (got == TWIST_WRITEFUNC_PAUSE)
        {
          *paused = 1;
          return off;
        }
      off += got;
      if (got < n)
        break;
    }
  return off;
}

size_t
twist_deliver (struct twist_transfer *t, const void *data, size_t len)
{
  const uint8_t *p = data;
  size_t off;
  int paused;

  if (t->write_cb == NULL || data == NULL || len == 0)
    return len;
  if (t->sink_paused || t->held_len > 0)
    return hold (t, p, len) == 0 ? len : 0;
  off = give (t, p, len, &paused);
  if (paused)
    {
      t->sink_paused = 1;
      if (hold (t, p + off, len - off) != 0)
        return off;		/* Nowhere to keep it: the transfer stops.  */
      if (t->pause_fn != NULL)
        t->pause_fn (t);
      return len;
    }
  return off;
}

/* Give back what was held, until it is all given or the callback is full
   again.  Returns TWIST_ERR_ABORTED if the callback took less than it was
   given.  */
static int
flush (struct twist_transfer *t)
{
  size_t off = 0;
  int paused = 0;
  int rc = TWIST_OK;

  while (off < t->held_len && !paused)
    {
      size_t got = give (t, t->held + off, t->held_len - off, &paused);

      off += got;
      if (!paused && off < t->held_len)
        {
          rc = TWIST_ERR_ABORTED;
          break;
        }
    }
  if (off >= t->held_len)
    t->held_len = 0;
  else if (off > 0)
    {
      memmove (t->held, t->held + off, t->held_len - off);
      t->held_len -= off;
    }
  t->sink_paused = paused;
  return rc;
}

/* On the thread that runs the transfer.  */
int
twist_transfer_resume_local (struct twist_transfer *t)
{
  int rc = TWIST_OK;

  if (t->sink_paused)
    {
      t->sink_paused = 0;
      if (t->resume_fn != NULL)
        t->resume_fn (t);
      /* The callback may be full again at once, and it may end the
         transfer.  */
      if (!t->done)
        rc = flush (t);
      if (t->sink_paused && t->pause_fn != NULL)
        t->pause_fn (t);
      if (rc != TWIST_OK)
        twist_transfer_finish (t, rc);
    }
  /* An upload that asked to wait (TWIST_READFUNC_PAUSE) goes on.  */
  if (t->upload != NULL && !t->done)
    twist_upload_kick (t->upload);
  twist_sink_gate_check (t);
  return TWIST_OK;
}

int
twist_sink_gate (struct twist_transfer *t, int result)
{
  if (result != TWIST_OK || t->gated)
    return 0;
  if (!t->sink_paused && t->held_len == 0)
    {
      /* Everything has been given to the writer.  It closes once it has it,
         and it is told so now: if what it was given has been written and
         acknowledged already, nothing will come from it afterwards to say that
         it is done.  */
      twist_wsink_close (t);
      if (!twist_wsink_busy (t))
        return 0;
    }
  t->gated = 1;
  t->gated_result = result;
  return 1;
}

/* The writer or the application has room, or the writer is done: if the end of
   the transfer was put off, go on with it when nothing is left to give or
   write.  */
void
twist_sink_gate_check (struct twist_transfer *t)
{
  if (!t->gated || t->sink_paused || t->held_len > 0)
    return;
  /* Everything has been given to the writer: it closes once it has it.  */
  twist_wsink_close (t);
  if (twist_wsink_busy (t))
    return;
  t->gated = 0;
  twist_transfer_finish (t, t->gated_result);
}

int
twist_transfer_resume (struct twist_transfer *t)
{
  if (t == NULL)
    return TWIST_ERR_INVAL;
  if (twist_transfer_remote (t))
    return twist_transfer_post_op (t, TWIST_XOP_RESUME);
  return twist_transfer_resume_local (t);
}

void
twist_sink_clear (struct twist_transfer *t)
{
  free (t->held);
  t->held = NULL;
  t->held_len = t->held_cap = 0;
  t->sink_paused = 0;
}

int
twist_transfer_upload_push (struct twist_transfer *t, const void *data,
                            size_t len, size_t *taken)
{
  size_t none;

  if (t == NULL || (data == NULL && len > 0))
    return TWIST_ERR_INVAL;
  if (taken == NULL)
    taken = &none;
  if (twist_transfer_remote (t))
    {
      /* From another thread: the bytes are copied and queued, up to a limit,
         and the transfer's thread takes them.  */
      size_t take;
      int post = 0;

      *taken = 0;
      if (!t->push_upload)
        return TWIST_ERR_INVAL;
      pthread_mutex_lock (&t->xmu);
      take = XQ_MAX_ > t->xq_len ? XQ_MAX_ - t->xq_len : 0;
      if (take > len)
        take = len;
      if (take > 0)
        {
          if (t->xq_len + take > t->xq_cap)
            {
              size_t cap = t->xq_len + take;
              uint8_t *grown = realloc (t->xq, cap);

              if (grown == NULL)
                {
                  pthread_mutex_unlock (&t->xmu);
                  return TWIST_ERR_NOMEM;
                }
              t->xq = grown;
              t->xq_cap = cap;
            }
          memcpy (t->xq + t->xq_len, data, take);
          t->xq_len += take;
        }
      if (take < len)
        t->xq_wanted = 1;
      if (!t->xq_posted && (take > 0 || t->xq_wanted))
        {
          t->xq_posted = 1;
          post = 1;
        }
      pthread_mutex_unlock (&t->xmu);
      if (post)
        twist_transfer_post_op (t, TWIST_XOP_DRAIN);
      *taken = take;
      return take == 0 && len > 0 ? TWIST_ERR_AGAIN : TWIST_OK;
    }
  return twist_transfer_upload_push_local (t, data, len,
                                           taken != NULL ? taken : &none);
}

int
twist_transfer_upload_end (struct twist_transfer *t, int result)
{
  if (t == NULL)
    return TWIST_ERR_INVAL;
  if (twist_transfer_remote (t))
    {
      int post;

      if (!t->push_upload)
        return TWIST_ERR_INVAL;
      pthread_mutex_lock (&t->xmu);
      t->xq_end = 1;
      t->xq_end_err = result;
      post = !t->xq_posted;
      t->xq_posted = 1;
      pthread_mutex_unlock (&t->xmu);
      return post ? twist_transfer_post_op (t, TWIST_XOP_DRAIN) : TWIST_OK;
    }
  return twist_transfer_upload_end_local (t, result);
}
