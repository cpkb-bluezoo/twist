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
#include <unistd.h>

/* The file I/O of transfers through io_uring (Linux, with liburing).  It is
   the same pipeline as fileio.c's, with the same calls and the same
   guarantees: chunks of TWIST_FIO_CHUNK, TWIST_FIO_PIPELINE of them
   unacknowledged, delivered in order, and nothing called back once the
   transfer is let go of.  What differs is who does the reading: there is no
   worker.  The loop's thread submits a read, the kernel does it, and the
   completion arrives on the loop (a ring has an eventfd, and the loop watches
   it like any descriptor).  So nothing waits for room, and no thread of a pool
   is held for the life of a transfer.  Letting go of a transfer cancels what is
   under way.

   One ring to a loop, made when it is first wanted.  A kernel or a sandbox
   that refuses one, or lacks the operations, leaves the loop with the pool.
   TWIST_NO_URING in the environment does the same.

   The open of a file to read is the transfer's own (it may stat, and it may
   wait on a slow filesystem), so it runs as one short job of the pool and
   hands the descriptor over.

   Everything here runs on the loop's thread but that job.  A twist_fio of this
   kind is freed before the loop it is on.  */

#ifdef HAVE_LIBURING

# include <errno.h>
# include <liburing.h>
# include <stdint.h>
# include <sys/eventfd.h>

# define UIO_MAGIC TWIST_UIO_MAGIC

struct uring
{
  struct io_uring ring;
  int efd;
  struct twist_fd_source *fs;
  size_t nops;			/* Submitted and not yet reaped.  */
  int reaping;
};

struct twist_uio;

/* What a completion carries back: which object and which slot.  A write that
   is finished by a second request is the same slot again.  */
struct uop
{
  struct twist_uio *u;
  int slot;
};

enum { SL_FREE, SL_SUBMITTED, SL_DONE };

struct uslot
{
  uint8_t *buf;
  size_t want;			/* Read: asked for.  Write: to write.  */
  size_t done;			/* Write: written so far.  */
  int state;
  int res;
  uint64_t seq;
  long long off;		/* Write: where this slot goes.  */
  struct uop op;
};

struct twist_uio
{
  int magic;			/* First: fileio.c tells a kind by it.  */
  int dir;			/* 0 read, 1 write.  */
  struct twist_loop *loop;
  struct uring *ring;
  struct twist_storage *st;
  struct twist_fio_read_ops rops;
  struct twist_fio_write_ops wops;
  void *user;
  void (*user_free) (void *);
  int released;
  int paused;
  int delivering;
  int depth;			/* In a call to the application.  */
  int pool_job;			/* The open is on the pool.  */
  int posts;			/* Commands posted to the loop and not run.  */
  int ops_out;			/* Requests in the ring for this object.  */
  int ended;			/* END has been called.  */
  int err;
  char *msg;
  struct uslot slot[TWIST_FIO_PIPELINE];
  /* Commands, made at the start so that posting them cannot fail.  A command
     that was posted belongs to the loop, which frees it once it has run.  */
  struct twist_cmd *cmd;	/* Posted when the open is done.  */
  int cmd_posted;
  struct twist_cmd *end_cmd;	/* Posted to tell of the end of a write.  */
  int end_posted;
  /* Reading.  */
  int fd;
  int own;
  int opened;
  long long off;
  long long left;		/* -1: to the end.  */
  long long size;
  int size_known;
  int size_noted;
  int eof;			/* No more is wanted from the file.  */
  int64_t eof_seq;		/* Slots after this one are not delivered.  */
  uint64_t seq_submit;
  uint64_t seq_deliver;
  /* Writing.  */
  long long woff;
  int plain;			/* Write at the file's position, one at a time.  */
  int end_req;
  int end_sent;
};

static int unavailable_marker;

static void uio_reap (struct uring *r);

static void
ring_free (void *p)
{
  struct uring *r = p;
  int tries = 0;

  if (p == NULL || p == &unavailable_marker)
    return;
  /* What is under way finishes into buffers that belong to objects that are
     still there: wait for it.  */
  while (r->nops > 0 && tries < 200)
    {
      struct __kernel_timespec ts = { 0, 10 * 1000 * 1000 };
      struct io_uring_cqe *cqe = NULL;

      io_uring_submit (&r->ring);
      if (io_uring_wait_cqe_timeout (&r->ring, &cqe, &ts) == 0 && cqe != NULL)
        uio_reap (r);		/* As on the loop.  */
      tries++;
    }
  twist_fd_source_free (r->fs);
  io_uring_queue_exit (&r->ring);
  if (r->efd >= 0)
    close (r->efd);
  free (r);
}

static size_t reap_chunk (void *user, const uint8_t *data, size_t len);
static void reap_end (void *user, int err);
static const struct twist_fd_source_ops ring_ops = { reap_chunk, reap_end };

static struct uring *
ring_of (struct twist_loop *loop)
{
  void *ext = twist_loop_ext (loop);
  struct uring *r;
  struct io_uring_probe *probe;
  int ok;

  if (ext == &unavailable_marker)
    return NULL;
  if (ext != NULL)
    return ext;
  if (getenv ("TWIST_NO_URING") != NULL)
    {
      twist_loop_set_ext (loop, &unavailable_marker, NULL);
      return NULL;
    }
  r = calloc (1, sizeof *r);
  if (r == NULL)
    return NULL;
  r->efd = -1;
  if (io_uring_queue_init (128, &r->ring, 0) != 0)
    {
      free (r);
      twist_loop_set_ext (loop, &unavailable_marker, NULL);
      return NULL;
    }
  probe = io_uring_get_probe_ring (&r->ring);
  ok = probe != NULL && io_uring_opcode_supported (probe, IORING_OP_READ)
       && io_uring_opcode_supported (probe, IORING_OP_WRITE)
       && io_uring_opcode_supported (probe, IORING_OP_ASYNC_CANCEL);
  if (probe != NULL)
    io_uring_free_probe (probe);
  r->efd = eventfd (0, EFD_NONBLOCK | EFD_CLOEXEC);
  if (!ok || r->efd < 0 || io_uring_register_eventfd (&r->ring, r->efd) != 0
      || twist_fd_source_new (loop, r->efd, &ring_ops, r, &r->fs) != TWIST_OK)
    {
      twist_fd_source_free (r->fs);
      io_uring_queue_exit (&r->ring);
      if (r->efd >= 0)
        close (r->efd);
      free (r);
      twist_loop_set_ext (loop, &unavailable_marker, NULL);
      return NULL;
    }
  twist_loop_set_ext (loop, r, ring_free);
  return r;
}

int
twist_uio_usable (struct twist_loop *loop, struct twist_storage *st)
{
  return loop != NULL && st != NULL && twist_storage_threads (st) > 0
         && ring_of (loop) != NULL;
}

int
twist_uio_is (const struct twist_fio *f)
{
  return f != NULL && *(const int *) f == UIO_MAGIC;
}

/* ---- the object ---- */

static void
uio_destroy (struct twist_uio *u)
{
  size_t i;

  for (i = 0; i < TWIST_FIO_PIPELINE; i++)
    free (u->slot[i].buf);
  if (u->own && u->fd >= 0)
    close (u->fd);
  if (u->cmd != NULL && !u->cmd_posted)
    twist_loop_cmd_free (u->cmd);
  if (u->end_cmd != NULL && !u->end_posted)
    twist_loop_cmd_free (u->end_cmd);
  free (u->msg);
  if (u->user_free != NULL)
    u->user_free (u->user);
  free (u);
}

/* Free the record if the transfer is let go of and nothing is left that could
   touch it.  Whether it was freed.  */
static int
uio_maybe_destroy (struct twist_uio *u)
{
  if (u->released && u->depth == 0 && u->ops_out == 0 && !u->pool_job
      && u->posts == 0)
    {
      uio_destroy (u);
      return 1;
    }
  return 0;
}

static void
slot_clear (struct uslot *s)
{
  free (s->buf);
  s->buf = NULL;
  s->state = SL_FREE;
}

/* A request for SLOT is in the ring.  Whether it could be queued.  */
static struct io_uring_sqe *
get_sqe (struct uring *r)
{
  struct io_uring_sqe *sqe = io_uring_get_sqe (&r->ring);

  if (sqe == NULL)
    {
      io_uring_submit (&r->ring);
      sqe = io_uring_get_sqe (&r->ring);
    }
  return sqe;
}

/* ---- reading ---- */

static void read_pump (struct twist_uio *u);

static void
note_size (struct twist_uio *u)
{
  if (!u->size_noted && u->size_known)
    {
      u->size_noted = 1;
      if (u->rops.size != NULL)
        {
          u->depth++;
          u->rops.size (u->user, u->size);
          u->depth--;
        }
    }
}

/* Nothing after the slot LAST (-1: none at all) is wanted.  */
static void
set_eof (struct twist_uio *u, int64_t last)
{
  if (!u->eof || last < u->eof_seq)
    u->eof_seq = last;
  u->eof = 1;
}

/* The read is over, with ERR, after the slot LAST.  */
static void
read_fail (struct twist_uio *u, int err, int64_t last)
{
  if (u->err == TWIST_OK)
    u->err = err;
  set_eof (u, last);
}

/* Tell of the end once nothing of the file is outstanding.  Whether the
   record is gone.  */
static int
read_finish (struct twist_uio *u)
{
  size_t i;

  if (u->ended || !u->eof)
    return 0;
  for (i = 0; i < TWIST_FIO_PIPELINE; i++)
    if (u->slot[i].state != SL_FREE)
      return 0;
  u->ended = 1;
  note_size (u);
  {
    char *msg = u->msg;

    u->msg = NULL;
    u->depth++;
    u->rops.end (u->user, u->err, msg);
    u->depth--;
  }
  return u->released ? uio_maybe_destroy (u) : 0;
}

/* Give the application what has arrived, in order, unless it has said to hold.
   Whether the record is gone.  */
static int
read_deliver (struct twist_uio *u)
{
  if (u->delivering)
    return 0;
  u->delivering = 1;
  while (!u->paused && !u->released)
    {
      struct uslot *s = NULL;
      size_t i;
      int err = TWIST_OK;

      for (i = 0; i < TWIST_FIO_PIPELINE; i++)
        if (u->slot[i].state == SL_DONE
            && u->slot[i].seq == u->seq_deliver)
          {
            s = &u->slot[i];
            break;
          }
      if (s == NULL)
        break;
      u->seq_deliver++;
      if (u->eof && (int64_t) s->seq > u->eof_seq)
        {
          /* Read past the end, or after a failure: not for the application.  */
          slot_clear (s);
          continue;
        }
      if (s->res > 0)
        {
          note_size (u);
          u->depth++;
          err = u->rops.chunk (u->user, s->buf, (size_t) s->res);
          u->depth--;
          if (u->released)
            {
              slot_clear (s);
              u->delivering = 0;
              return uio_maybe_destroy (u);
            }
          if ((size_t) s->res < s->want)
            {
              /* A regular file gives all it is asked for but at its end.  */
              set_eof (u, (int64_t) s->seq);
            }
          if (err != TWIST_OK)
            read_fail (u, err, (int64_t) s->seq);
        }
      else
        {
          if (s->res < 0)
            read_fail (u, TWIST_ERR_FILE, (int64_t) s->seq);
          else
            set_eof (u, (int64_t) s->seq);
        }
      slot_clear (s);
    }
  u->delivering = 0;
  if (u->released)
    return uio_maybe_destroy (u);
  if (read_finish (u))
    return 1;
  read_pump (u);
  return 0;
}

/* Ask for more of the file while there is room for it.  */
static void
read_pump (struct twist_uio *u)
{
  struct uring *r = u->ring;
  int queued = 0;

  if (!u->opened || u->released || u->eof)
    return;
  while (u->left != 0)
    {
      struct uslot *s = NULL;
      size_t want = TWIST_FIO_CHUNK;
      struct io_uring_sqe *sqe;
      size_t i;

      for (i = 0; i < TWIST_FIO_PIPELINE; i++)
        if (u->slot[i].state == SL_FREE)
          {
            s = &u->slot[i];
            break;
          }
      if (s == NULL)
        break;
      if (u->left > 0 && u->left < (long long) want)
        want = (size_t) u->left;
      s->buf = twist_xmalloc (want);
      if (s->buf == NULL)
        {
          read_fail (u, TWIST_ERR_NOMEM, (int64_t) u->seq_submit - 1);
          break;
        }
      sqe = get_sqe (r);
      if (sqe == NULL)
        {
          free (s->buf);
          s->buf = NULL;
          break;		/* Try again when something completes.  */
        }
      s->want = want;
      s->state = SL_SUBMITTED;
      s->seq = u->seq_submit++;
      s->op.u = u;
      s->op.slot = (int) (s - u->slot);
      io_uring_prep_read (sqe, u->fd, s->buf, (unsigned) want, (__u64) u->off);
      io_uring_sqe_set_data (sqe, &s->op);
      u->off += (long long) want;
      if (u->left > 0)
        u->left -= (long long) want;
      u->ops_out++;
      r->nops++;
      queued++;
    }
  if (queued > 0)
    io_uring_submit (&r->ring);
  /* All that was asked for is asked: the last slot is the last.  */
  if (u->left == 0 && !u->eof)
    set_eof (u, (int64_t) u->seq_submit - 1);
  if (u->eof)
    read_finish (u);
}

/* The open is done (on the loop).  */
static void
open_done (void *arg)
{
  struct twist_uio *u = arg;

  u->pool_job = 0;
  if (u->released)
    {
      uio_maybe_destroy (u);
      return;
    }
  if (u->err != TWIST_OK)
    {
      u->eof = 1;
      u->ended = 1;
      {
        char *msg = u->msg;

        u->msg = NULL;
        u->depth++;
        u->rops.end (u->user, u->err, msg);
        u->depth--;
      }
      uio_maybe_destroy (u);
      return;
    }
  u->opened = 1;
  read_pump (u);
}

/* The open, on a thread of the pool.  */
static void
open_work (void *arg)
{
  struct twist_uio *u = arg;
  long long start = 0;
  long long length = -1;
  int fd = -1;
  int own = 0;
  char *msg = NULL;
  int err = u->rops.open (u->user, &fd, &own, &start, &length, &msg);

  u->err = err;
  u->msg = msg;
  if (err == TWIST_OK)
    {
      u->fd = fd;
      u->own = own;
      u->off = start;
      u->left = length;
      if (length >= 0)
        {
          u->size = length;
          u->size_known = 1;
        }
    }
  u->cmd_posted = 1;
  twist_loop_cmd_post (u->loop, u->cmd);
}

static struct twist_uio *
uio_new (struct twist_loop *loop, struct twist_storage *st, int dir)
{
  struct twist_uio *u = calloc (1, sizeof *u);

  if (u == NULL)
    return NULL;
  u->magic = UIO_MAGIC;
  u->dir = dir;
  u->loop = loop;
  u->st = st;
  u->ring = ring_of (loop);
  u->fd = -1;
  u->left = -1;
  u->eof_seq = -1;
  if (u->ring == NULL)
    {
      free (u);
      return NULL;
    }
  return u;
}

int
twist_uio_read_new (struct twist_loop *loop, struct twist_storage *st,
                    const struct twist_fio_read_ops *ops, void *user,
                    struct twist_fio **out)
{
  struct twist_uio *u = uio_new (loop, st, 0);
  int rc;

  *out = NULL;
  if (u == NULL)
    return TWIST_ERR_NOMEM;
  u->rops = *ops;
  u->user = user;
  u->cmd = twist_loop_cmd_new (open_done, u);
  if (u->cmd == NULL)
    {
      free (u);
      return TWIST_ERR_NOMEM;
    }
  u->pool_job = 1;
  rc = twist_storage_submit (st, open_work, u, NULL, NULL, NULL);
  if (rc != TWIST_OK)
    {
      twist_loop_cmd_free (u->cmd);
      free (u);
      return rc;
    }
  u->user_free = ops->release;
  *out = (struct twist_fio *) u;
  return TWIST_OK;
}

/* ---- writing ---- */

static void write_pump_end (struct twist_uio *u);

static void
write_end_run (void *arg)
{
  struct twist_uio *u = arg;

  u->posts--;
  if (u->released)
    {
      uio_maybe_destroy (u);
      return;
    }
  {
    char *msg = u->msg;

    u->msg = NULL;
    u->depth++;
    u->wops.end (u->user, u->err, msg);
    u->depth--;
  }
  if (u->released)
    uio_maybe_destroy (u);
}

/* The write has nothing more to do when it was told it is over, or failed, and
   nothing is under way: close the file and tell the application, from the loop
   and not from the call that made it so.  */
static void
write_pump_end (struct twist_uio *u)
{
  size_t i;

  if (u->end_sent || u->released || (!u->end_req && u->err == TWIST_OK))
    return;
  for (i = 0; i < TWIST_FIO_PIPELINE; i++)
    if (u->slot[i].state != SL_FREE)
      return;
  u->end_sent = 1;
  if (u->own && u->fd >= 0)
    {
      if (close (u->fd) != 0 && u->err == TWIST_OK)
        u->err = TWIST_ERR_FILE;
      u->fd = -1;
    }
  u->posts++;
  u->end_posted = 1;
  twist_loop_cmd_post (u->loop, u->end_cmd);
}

static void
write_submit (struct twist_uio *u, struct uslot *s)
{
  struct uring *r = u->ring;
  struct io_uring_sqe *sqe = get_sqe (r);

  if (sqe == NULL)
    {
      /* The ring is full of requests: this one will be queued by the next
         completion (write_retry).  */
      return;
    }
  io_uring_prep_write (sqe, u->fd, s->buf + s->done,
                       (unsigned) (s->want - s->done),
                       u->plain ? (__u64) -1 : (__u64) (s->off + (long long) s->done));
  io_uring_sqe_set_data (sqe, &s->op);
  s->state = SL_SUBMITTED;
  u->ops_out++;
  r->nops++;
  io_uring_submit (&r->ring);
}

int
twist_uio_write (struct twist_fio *f, const uint8_t *data, size_t len,
                 uint8_t **swap)
{
  struct twist_uio *u = (struct twist_uio *) f;
  struct uslot *s = NULL;
  size_t i;
  int busy = 0;

  if (len > twist_fio_wchunk ())
    return TWIST_ERR_INVAL;
  if (u->end_req)
    return TWIST_ERR_INVAL;
  if (u->err != TWIST_OK)
    return u->err;
  for (i = 0; i < TWIST_FIO_PIPELINE; i++)
    {
      if (u->slot[i].state == SL_FREE && s == NULL)
        s = &u->slot[i];
      else if (u->slot[i].state != SL_FREE)
        busy++;
    }
  /* A file at its own position (not a regular file) has one write at a time:
     the ring does not keep requests in order.  */
  if (s == NULL || (u->plain && busy > 0))
    return 1;
  if (s->buf == NULL || swap != NULL)
    {
      /* A buffer to fill, and, if the caller's goes, the one it gets.  */
      uint8_t *fresh = s->buf;

      if (fresh == NULL)
        {
          fresh = twist_xmalloc (twist_fio_wchunk ());
          if (fresh == NULL)
            return TWIST_ERR_NOMEM;
        }
      if (swap != NULL)
        {
          s->buf = *swap;
          *swap = fresh;
          data = s->buf;
        }
      else
        s->buf = fresh;
    }
  if (len > 0 && data != s->buf)
    memcpy (s->buf, data, len);
  s->want = len;
  s->done = 0;
  s->off = u->woff;
  s->op.u = u;
  s->op.slot = (int) (s - u->slot);
  u->woff += (long long) len;
  if (len == 0)
    return TWIST_OK;
  write_submit (u, s);
  if (s->state != SL_SUBMITTED)
    {
      /* No room in the ring now: hold it, and say there is no room.  The
         caller's buffer is the caller's still.  */
      u->woff -= (long long) len;
      if (swap != NULL)
        {
          uint8_t *mine = s->buf;

          s->buf = *swap;
          *swap = mine;
        }
      return 1;
    }
  return TWIST_OK;
}

void
twist_uio_write_end (struct twist_fio *f)
{
  struct twist_uio *u = (struct twist_uio *) f;

  u->end_req = 1;
  write_pump_end (u);
}

int
twist_uio_write_fd_new (struct twist_loop *loop, struct twist_storage *st,
                        int fd, long long at,
                        const struct twist_fio_write_ops *ops, void *user,
                        struct twist_fio **out)
{
  struct twist_uio *u = uio_new (loop, st, 1);

  *out = NULL;
  if (u == NULL)
    return TWIST_ERR_NOMEM;
  u->wops = *ops;
  u->user = user;
  u->fd = fd;
  u->own = 1;
  u->woff = at < 0 ? 0 : at;
  u->plain = at < 0;
  u->end_cmd = twist_loop_cmd_new (write_end_run, u);
  if (u->end_cmd == NULL)
    {
      free (u);
      return TWIST_ERR_NOMEM;
    }
  u->user_free = ops->release;
  *out = (struct twist_fio *) u;
  return TWIST_OK;
}

/* ---- completions ---- */

static void
write_complete (struct twist_uio *u, struct uslot *s, int res)
{
  if (res < 0)
    {
      if (u->err == TWIST_OK)
        u->err = TWIST_ERR_FILE;
      slot_clear (s);
    }
  else if ((size_t) res < s->want - s->done)
    {
      /* Part of it went: the rest is another request.  */
      s->done += (size_t) res;
      write_submit (u, s);
      if (s->state == SL_SUBMITTED)
        return;
      if (u->err == TWIST_OK)
        u->err = TWIST_ERR_FILE;
      slot_clear (s);
    }
  else
    s->state = SL_FREE;
  if (u->err == TWIST_OK && u->wops.credit != NULL)
    {
      u->depth++;
      u->wops.credit (u->user);
      u->depth--;
    }
  if (!u->released)
    write_pump_end (u);
}

/* One completion.  */
static void
complete (struct twist_uio *u, struct uslot *s, int res)
{
  u->ops_out--;
  if (u->released)
    {
      /* Nobody wants it.  */
      if (u->dir == 0)
        slot_clear (s);
      else
        s->state = SL_FREE;
      uio_maybe_destroy (u);
      return;
    }
  if (u->dir == 0)
    {
      s->res = res;
      s->state = SL_DONE;
      read_deliver (u);
    }
  else
    {
      write_complete (u, s, res);
      if (u->released)
        uio_maybe_destroy (u);
    }
}

static void
uio_reap (struct uring *r)
{
  struct io_uring_cqe *cqe;

  if (r->reaping)
    return;
  r->reaping = 1;
  while (io_uring_peek_cqe (&r->ring, &cqe) == 0)
    {
      struct uop *op = io_uring_cqe_get_data (cqe);
      int res = cqe->res;

      io_uring_cqe_seen (&r->ring, cqe);
      /* A cancel carries no data; the request it cancels completes by itself
         (with ECANCELED).  */
      if (op == NULL)
        continue;
      if (r->nops > 0)
        r->nops--;
      complete (op->u, &op->u->slot[op->slot], res);
    }
  r->reaping = 0;
}

static size_t
reap_chunk (void *user, const uint8_t *data, size_t len)
{
  (void) data;
  uio_reap (user);
  return len;
}

static void
reap_end (void *user, int err)
{
  (void) user;
  (void) err;
}

/* ---- the calls of fileio.c ---- */

void
twist_uio_pause (struct twist_fio *f)
{
  struct twist_uio *u = (struct twist_uio *) f;

  u->paused = 1;
}

void
twist_uio_resume (struct twist_fio *f)
{
  struct twist_uio *u = (struct twist_uio *) f;

  if (!u->paused)
    return;
  u->paused = 0;
  if (u->dir == 0)
    read_deliver (u);
}

int
twist_uio_inflight (struct twist_fio *f)
{
  struct twist_uio *u = (struct twist_uio *) f;
  int n = 0;
  size_t i;

  for (i = 0; i < TWIST_FIO_PIPELINE; i++)
    if (u->slot[i].state != SL_FREE)
      n++;
  return n;
}

void
twist_uio_free (struct twist_fio *f)
{
  struct twist_uio *u = (struct twist_uio *) f;
  struct uring *r = u->ring;
  size_t i;
  int cancelled = 0;

  if (u->released)
    return;
  u->released = 1;
  for (i = 0; i < TWIST_FIO_PIPELINE; i++)
    if (u->slot[i].state == SL_SUBMITTED)
      {
        struct io_uring_sqe *sqe = get_sqe (r);

        if (sqe == NULL)
          continue;
        io_uring_prep_cancel (sqe, &u->slot[i].op, 0);
        io_uring_sqe_set_data (sqe, NULL);
        cancelled++;
      }
  if (cancelled > 0)
    io_uring_submit (&r->ring);
  /* Finished slots hold nothing for anyone now.  */
  for (i = 0; i < TWIST_FIO_PIPELINE; i++)
    if (u->slot[i].state == SL_DONE)
      slot_clear (&u->slot[i]);
  uio_maybe_destroy (u);
}

#else  /* !HAVE_LIBURING */

int
twist_uio_usable (struct twist_loop *loop, struct twist_storage *st)
{
  (void) loop;
  (void) st;
  return 0;
}

int
twist_uio_is (const struct twist_fio *f)
{
  (void) f;
  return 0;
}

int
twist_uio_read_new (struct twist_loop *loop, struct twist_storage *st,
                    const struct twist_fio_read_ops *ops, void *user,
                    struct twist_fio **out)
{
  (void) loop;
  (void) st;
  (void) ops;
  (void) user;
  *out = NULL;
  return TWIST_ERR_UNSUPPORTED;
}

int
twist_uio_write_fd_new (struct twist_loop *loop, struct twist_storage *st,
                        int fd, long long at,
                        const struct twist_fio_write_ops *ops, void *user,
                        struct twist_fio **out)
{
  (void) loop;
  (void) st;
  (void) fd;
  (void) at;
  (void) ops;
  (void) user;
  *out = NULL;
  return TWIST_ERR_UNSUPPORTED;
}

int
twist_uio_write (struct twist_fio *f, const uint8_t *data, size_t len,
                 uint8_t **swap)
{
  (void) f;
  (void) data;
  (void) len;
  (void) swap;
  return TWIST_ERR_INVAL;
}

void
twist_uio_write_end (struct twist_fio *f)
{
  (void) f;
}

void
twist_uio_pause (struct twist_fio *f)
{
  (void) f;
}

void
twist_uio_resume (struct twist_fio *f)
{
  (void) f;
}

int
twist_uio_inflight (struct twist_fio *f)
{
  (void) f;
  return 0;
}

void
twist_uio_free (struct twist_fio *f)
{
  (void) f;
}

#endif
