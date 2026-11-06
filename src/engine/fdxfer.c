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

#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* The descriptors an application gives a transfer (TWISTOPT_READFD and
   TWISTOPT_WRITEFD).  A regular file cannot be polled and goes through the file
   pipeline (twist_fio); anything else is waited for (twist_fd_source,
   twist_fd_sink).  The descriptor is the application's: twist works on a copy
   of it, does not make it non-blocking and, for a file, reads and writes at
   an offset and does not move its position.  */

/* ---- reading: the upload ---- */

struct fd_src
{
  struct twist_transfer *t;
  struct twist_upload *up;
  int fd;
  int regular;
  long long base;		/* Where a file was when it was given.  */
  long long skip;		/* Of a file: bytes of it not to send.  */
  long long discard;		/* Of the rest: bytes to read and throw away.  */
  struct twist_fd_source *fs;
  struct twist_fio *fio;
  uint8_t pend[TWIST_FIO_CHUNK];	/* A chunk of a file, being pushed.  */
  size_t pend_len, pend_off;
  int ended;			/* The file is over; PEND is the last.  */
  int started;
};

/* The open of the file, on the worker, which may run after the upload is let
   go of: what it needs is a record of its own.  */
struct fio_in
{
  struct fd_src *src;		/* The loop's thread only.  */
  int fd;
  long long start;
};

static int
in_open (void *user, int *fd, int *own, long long *start, long long *length,
         char **msg)
{
  struct fio_in *in = user;

  (void) msg;
  *fd = in->fd;
  *own = 1;
  in->fd = -1;
  *start = in->start;
  *length = -1;
  return TWIST_OK;
}

/* Push what is waiting, while the consumer will take it.  */
static void
drain_pending (struct fd_src *s)
{
  while (s->pend_off < s->pend_len && twist_upload_active (s->up))
    {
      size_t max = twist_upload_max (s->up);
      size_t n = s->pend_len - s->pend_off;

      if (max == 0)
        return;
      if (n > max)
        n = max;
      s->pend_off += n;
      if (twist_upload_push (s->up, s->pend + s->pend_off - n, n) != TWIST_OK)
        return;
    }
}

static int
in_chunk (void *user, uint8_t *data, size_t len)
{
  struct fio_in *in = user;
  struct fd_src *s = in->src;

  if (len > sizeof s->pend)
    return TWIST_ERR_ABORTED;
  memcpy (s->pend, data, len);
  s->pend_len = len;
  s->pend_off = 0;
  drain_pending (s);
  /* The consumer has stopped: no more is taken from the file until it goes
     on.  */
  if (s->pend_off < s->pend_len)
    twist_fio_pause (s->fio);
  return TWIST_OK;
}

static void
in_end (void *user, int err, char *msg)
{
  struct fio_in *in = user;
  struct fd_src *s = in->src;

  free (msg);
  s->ended = 1;
  /* The last of it first, if the consumer has not taken it.  */
  if (s->pend_off < s->pend_len)
    return;
  twist_upload_finish (s->up, err);
}

static void
in_release (void *user)
{
  struct fio_in *in = user;

  if (in->fd >= 0)
    close (in->fd);
  free (in);
}

static const struct twist_fio_read_ops in_ops = { in_open, NULL, in_chunk,
                                                  in_end, in_release };

/* The source of a descriptor that is waited for.  */
static size_t
fs_chunk (void *user, const uint8_t *data, size_t len)
{
  struct fd_src *s = user;
  size_t off = 0;

  if (s->discard > 0)
    {
      size_t d = (long long) len < s->discard ? len : (size_t) s->discard;

      s->discard -= (long long) d;
      off = d;
    }
  while (off < len && twist_upload_active (s->up))
    {
      size_t max = twist_upload_max (s->up);
      size_t n = len - off;

      if (max == 0)
        break;
      if (n > max)
        n = max;
      off += n;
      if (twist_upload_push (s->up, data + off - n, n) != TWIST_OK)
        break;
    }
  return off;			/* Less than LEN pauses it.  */
}

static void
fs_end (void *user, int err)
{
  struct fd_src *s = user;

  twist_upload_finish (s->up, err);
}

static const struct twist_fd_source_ops fs_ops = { fs_chunk, fs_end };

static int
src_start (struct fd_src *s)
{
  struct twist_transfer *t = s->t;
  int rc;

  s->started = 1;
  s->ended = 0;
  s->pend_len = s->pend_off = 0;
  if (s->regular)
    {
      struct fio_in *in = calloc (1, sizeof *in);

      if (in == NULL)
        return TWIST_ERR_NOMEM;
      in->src = s;
      in->fd = dup (s->fd);
      in->start = s->base + s->skip;
      if (in->fd < 0 || t->runtime == NULL || t->runtime->xfer == NULL)
        {
          if (in->fd >= 0)
            close (in->fd);
          free (in);
          return TWIST_ERR_INVAL;
        }
      rc = twist_fio_read_new (t->loop, t->runtime->xfer, &in_ops, in, &s->fio);
      if (rc != TWIST_OK)
        {
          close (in->fd);
          free (in);
        }
      return rc;
    }
  rc = twist_fd_source_new (t->loop, s->fd, &fs_ops, s, &s->fs);
  return rc;
}

static void
src_resume (void *user)
{
  struct fd_src *s = user;

  if (!s->started)
    {
      int rc = src_start (s);

      if (rc != TWIST_OK)
        twist_upload_finish (s->up, rc);
      return;
    }
  if (s->fio != NULL)
    {
      drain_pending (s);
      if (s->pend_off >= s->pend_len)
        {
          if (s->ended)
            twist_upload_finish (s->up, TWIST_OK);
          else
            twist_fio_resume (s->fio);
        }
    }
  else if (s->fs != NULL)
    twist_fd_source_resume (s->fs);
}

static void
src_pause (void *user)
{
  struct fd_src *s = user;

  if (s->fio != NULL)
    twist_fio_pause (s->fio);
  else if (s->fs != NULL)
    twist_fd_source_pause (s->fs);
}

static int
src_restart (void *user)
{
  struct fd_src *s = user;

  /* Only a file can be read again; what has gone from a pipe is gone.  */
  if (!s->regular)
    return -1;
  twist_fio_free (s->fio);
  s->fio = NULL;
  s->started = 0;
  s->skip = 0;
  s->pend_len = s->pend_off = 0;
  return 0;
}

static int
src_skip (void *user, long long n)
{
  struct fd_src *s = user;

  if (s->regular)
    s->skip += n;
  else
    s->discard += n;
  return 0;
}

static void
src_release (void *user)
{
  struct fd_src *s = user;

  twist_fio_free (s->fio);
  twist_fd_source_free (s->fs);
  free (s);
}

static const struct twist_upload_producer src_ops = {
  src_resume, src_pause, src_restart, src_release, src_skip
};

struct twist_upload *
twist_fd_upload_new (struct twist_transfer *t)
{
  struct fd_src *s = calloc (1, sizeof *s);
  struct stat st;

  if (s == NULL)
    return NULL;
  s->t = t;
  s->fd = t->read_fd;
  s->regular = fstat (s->fd, &st) == 0 && S_ISREG (st.st_mode);
  if (s->regular)
    {
      off_t at = lseek (s->fd, 0, SEEK_CUR);

      s->base = at >= 0 ? (long long) at : 0;
    }
  s->up = twist_upload_new (&src_ops, s);
  if (s->up == NULL)
    {
      free (s);
      return NULL;
    }
  return s->up;
}

/* ---- writing: the body ---- */

struct fd_wsink
{
  struct twist_transfer *t;
  struct twist_fio *fio;
  struct twist_fd_sink *sink;
  int waiting;			/* The callback said it was full.  */
  int ended;			/* The writer is done (the file is closed).  */
  int closing;
  int failed;
};

static void
wsink_failed (struct fd_wsink *w, int err)
{
  if (w->failed)
    return;
  w->failed = 1;
  twist_transfer_finish (w->t, err);
}

static size_t
wsink_cb (char *ptr, size_t size, size_t nmemb, void *user)
{
  struct fd_wsink *w = user;
  size_t len = size * nmemb;
  int rc;

  if (w->failed || w->closing)
    return 0;
  if (w->fio != NULL)
    {
      if (len > TWIST_FIO_CHUNK)
        len = TWIST_FIO_CHUNK;
      rc = twist_fio_write (w->fio, (const uint8_t *) ptr, len);
      if (rc == 1)
        {
          w->waiting = 1;
          return TWIST_WRITEFUNC_PAUSE;
        }
      return rc == TWIST_OK ? len : 0;
    }
  if (twist_fd_sink_full (w->sink))
    {
      w->waiting = 1;
      return TWIST_WRITEFUNC_PAUSE;
    }
  return twist_fd_sink_write (w->sink, (const uint8_t *) ptr, len) == TWIST_OK
         ? len : 0;
}

/* The writer can take more.  */
static void
wsink_ready (void *user)
{
  struct fd_wsink *w = user;

  if (w->waiting)
    {
      w->waiting = 0;
      twist_transfer_resume_local (w->t);
    }
  twist_sink_gate_check (w->t);
}

static void
wsink_error (void *user, int err)
{
  (void) err;
  wsink_failed (user, TWIST_ERR_ABORTED);
}

static void
wsink_fio_end (void *user, int err, char *msg)
{
  struct fd_wsink *w = user;

  free (msg);
  w->ended = 1;
  if (err != TWIST_OK)
    wsink_failed (w, err);
  else
    twist_sink_gate_check (w->t);
}

static const struct twist_fd_sink_ops sink_ops = { wsink_ready, wsink_error };

static const struct twist_fio_write_ops wfio_ops = { wsink_ready,
                                                     wsink_fio_end, NULL };

int
twist_transfer_fds_setup (struct twist_transfer *t)
{
  struct fd_wsink *w;
  struct stat st;
  int regular;
  int plain;
  int rc;

  if (t->write_fd < 0 || t->wsink != NULL)
    return TWIST_OK;
  w = calloc (1, sizeof *w);
  if (w == NULL)
    return TWIST_ERR_NOMEM;
  w->t = t;
  regular = fstat (t->write_fd, &st) == 0 && S_ISREG (st.st_mode);
  /* A character device that is not a terminal (/dev/null) cannot be waited
     for, nor can it be written to at an offset.  */
  plain = !regular && S_ISCHR (st.st_mode) && !isatty (t->write_fd);
  if (!regular && !plain)
    {
      rc = twist_fd_sink_new (t->loop, t->write_fd, &sink_ops, w, &w->sink);
      if (rc == TWIST_OK)
        goto ready;
      if (rc == TWIST_ERR_NOMEM)
        {
          free (w);
          return rc;
        }
      /* It cannot be waited for after all: it is written to on a thread of
         the pool.  */
    }
  {
    off_t at = regular ? lseek (t->write_fd, 0, SEEK_CUR) : -1;
    int dfd = dup (t->write_fd);

    if (dfd < 0 || t->runtime == NULL || t->runtime->xfer == NULL)
      {
        if (dfd >= 0)
          close (dfd);
        free (w);
        return TWIST_ERR_INVAL;
      }
    if (regular && at < 0)
      at = 0;
    rc = twist_fio_write_fd_new (t->loop, t->runtime->xfer, dfd,
                                 (long long) at, &wfio_ops, w, &w->fio);
    if (rc != TWIST_OK)
      {
        close (dfd);
        free (w);
        return rc;
      }
  }
ready:
  t->wsink = w;
  t->write_cb = wsink_cb;
  t->write_data = w;
  return TWIST_OK;
}

void
twist_wsink_free (struct twist_transfer *t)
{
  struct fd_wsink *w = t->wsink;

  if (w == NULL)
    return;
  t->wsink = NULL;
  twist_fio_free (w->fio);
  twist_fd_sink_free (w->sink);
  free (w);
}

/* Whether the writer still has body to put on its descriptor.  */
int
twist_wsink_busy (struct twist_transfer *t)
{
  struct fd_wsink *w = t->wsink;

  if (w == NULL || w->failed)
    return 0;
  if (w->fio != NULL)
    return !w->ended;
  return twist_fd_sink_pending (w->sink) > 0;
}

/* The transfer is ending: no more is written, and the writer closes once it has
   what it has.  */
void
twist_wsink_close (struct twist_transfer *t)
{
  struct fd_wsink *w = t->wsink;

  if (w == NULL || w->closing)
    return;
  w->closing = 1;
  if (w->fio != NULL)
    twist_fio_write_end (w->fio);
}
