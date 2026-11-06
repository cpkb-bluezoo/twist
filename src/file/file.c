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

#include "gettext.h"
#include "twist-int.h"

#include <ctype.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

/* A file:// transfer reads a regular file with the shared pipeline
   (twist_fio, reactor/fileio.c): a worker of the transfer pool reads chunks
   and the loop hands each to the application.  This file is the part that
   knows about URLs, ranges, messages and the transfer.

   The record is the pipeline's user and is freed by it (file_release), when
   the pipeline is done with it, which may be after the transfer has been let
   go of: the worker's open callback reads PATH and the range from it.  They
   are set before the worker starts and never changed.  TRANSFER is the loop's
   and is cleared when the transfer is let go of.  */

struct twist_file
{
  struct twist_transfer *transfer;
  struct twist_fio *fio;
  size_t total;
  /* The path, percent-decoded, and the range asked for: both made on the
     loop's thread, for the worker.  RANGE_MODE is 0 for none, 1 for A-B or A-
     (RANGE_END -1: to the end), 2 for the last RANGE_END bytes.  */
  char *path;
  int range_mode;
  long long range_start;
  long long range_end;
};

static void
file_release (void *p)
{
  struct twist_file *f = p;

  free (f->path);
  free (f);
}

/* The transfer is let go of: by the application, which no longer wants it, or
   the runtime going away.  It returns at once.  */
static void
file_free (void *p)
{
  struct twist_file *f = p;

  if (f == NULL)
    return;
  f->transfer = NULL;
  twist_fio_free (f->fio);	/* F may be freed by it.  */
}


int
twist_file_check_url (const char *host, const char *path, int path_set)
{
  if (!path_set || path == NULL || path[0] != '/')
    return TWIST_ERR_URL;
  if (host == NULL || host[0] == 0)
    return TWIST_OK;
  if (strcasecmp (host, "localhost") == 0 || strcmp (host, "127.0.0.1") == 0)
    return TWIST_OK;
  return TWIST_ERR_URL;
}

static char *
file_errmsg (const char *path, int reading)
{
  const char *fmt = reading ? _("could not read file %s")
                            : _("could not open file %s");
  size_t n = strlen (fmt) + strlen (path) + 1;
  char *msg = twist_xmalloc (n);

  if (msg == NULL)
    return NULL;
  if (reading)
    snprintf (msg, n, _("could not read file %s"), path);
  else
    snprintf (msg, n, _("could not open file %s"), path);
  return msg;
}

/* The percent-decoded path, in memory of its own; NULL if it holds a NUL,
   which is no part of a name, or there is no memory.  An escape that is not
   two hex digits is left as it is.  */
static char *
decode_path (const char *in, int *nul)
{
  size_t n = strlen (in);
  char *out = twist_xmalloc (n + 1);
  size_t i;
  size_t o = 0;

  *nul = 0;
  if (out == NULL)
    return NULL;
  for (i = 0; i < n; i++)
    {
      unsigned char c = (unsigned char) in[i];

      if (c == '%' && i + 2 < n && isxdigit ((unsigned char) in[i + 1])
          && isxdigit ((unsigned char) in[i + 2]))
        {
          int hi = (unsigned char) in[i + 1];
          int lo = (unsigned char) in[i + 2];

          hi = isdigit (hi) ? hi - '0' : tolower (hi) - 'a' + 10;
          lo = isdigit (lo) ? lo - '0' : tolower (lo) - 'a' + 10;
          c = (unsigned char) ((hi << 4) | lo);
          i += 2;
        }
      if (c == 0)
        {
          *nul = 1;
          free (out);
          return NULL;
        }
      out[o++] = (char) c;
    }
  out[o] = 0;
  return out;
}

/* A number of only digits, not past what a file can be.  */
static int
range_number (const char *s, size_t n, long long *out)
{
  long long v = 0;
  size_t i;

  if (n == 0 || n > 18)
    return -1;
  for (i = 0; i < n; i++)
    {
      if (s[i] < '0' || s[i] > '9')
        return -1;
      v = v * 10 + (s[i] - '0');
    }
  *out = v;
  return 0;
}

/* "A-B", "A-" or "-N", one range, as -r gives it.  */
static int
parse_range (const char *r, struct twist_file *f)
{
  const char *dash = strchr (r, '-');
  size_t len = strlen (r);

  if (dash == NULL || strchr (r, ',') != NULL)
    return TWIST_ERR_RANGE;
  if (dash == r)
    {
      if (range_number (r + 1, len - 1, &f->range_end) != 0
          || f->range_end == 0)
        return TWIST_ERR_RANGE;
      f->range_mode = 2;
      return TWIST_OK;
    }
  if (range_number (r, (size_t) (dash - r), &f->range_start) != 0)
    return TWIST_ERR_RANGE;
  f->range_end = -1;
  if (dash[1] != 0
      && (range_number (dash + 1, len - (size_t) (dash - r) - 1,
                        &f->range_end) != 0 || f->range_end < f->range_start))
    return TWIST_ERR_RANGE;
  f->range_mode = 1;
  return TWIST_OK;
}

/* On the worker: open the file and work out what to read.  */
static int
file_open (void *user, int *out_fd, int *own, long long *start,
           long long *length, char **msg)
{
  struct twist_file *f = user;
  const char *path = f->path;
  int fd;
  struct stat st;
  long long left;
  long long from = 0;

  /* Not blocking, so that a FIFO with nobody at the other end, or the like,
     is looked at and refused and not waited on: the loop does not wait for
     this thread when the transfer is let go of, but --max-time could not end
     it.  A regular file does not mind.  */
  fd = open (path, O_RDONLY | O_NONBLOCK | O_CLOEXEC);
  if (fd < 0)
    {
      *msg = file_errmsg (path, 0);
      return TWIST_ERR_FILE;
    }
  if (fstat (fd, &st) != 0 || !S_ISREG (st.st_mode))
    {
      close (fd);
      *msg = file_errmsg (path, 0);
      return TWIST_ERR_FILE;
    }
  left = (long long) st.st_size;
  if (f->range_mode == 1)
    {
      from = f->range_start;
      if (from >= left)
        {
          close (fd);
          return TWIST_ERR_RANGE;
        }
      if (f->range_end >= 0 && f->range_end < left - 1)
        left = f->range_end + 1;
      left -= from;
    }
  else if (f->range_mode == 2)
    {
      from = f->range_end < left ? left - f->range_end : 0;
      left -= from;
    }
  *out_fd = fd;
  *own = 1;
  *start = from;
  *length = left;
  return TWIST_OK;
}

static void
file_size (void *user, long long size)
{
  struct twist_file *f = user;

  twist_progress_dl_size (f->transfer, size);
}

static int
file_chunk (void *user, uint8_t *data, size_t len)
{
  struct twist_file *f = user;
  struct twist_transfer *transfer = f->transfer;

  if (transfer->write_cb == NULL)
    return TWIST_OK;
  if (twist_deliver (transfer, data, len) < len)
    return TWIST_ERR_ABORTED;
  f->total += len;
  twist_progress_downloaded (transfer, len);
  return TWIST_OK;
}

static void
file_end (void *user, int err, char *msg)
{
  struct twist_file *f = user;
  struct twist_transfer *transfer = f->transfer;

  /* A read that failed has no message of its own: the file is named.  */
  if (err == TWIST_ERR_FILE && msg == NULL)
    msg = file_errmsg (f->path, 1);
  if (err != TWIST_OK)
    twist_transfer_set_error (transfer, msg);
  else
    {
      free (msg);
      transfer->size_download = f->total;
    }
  twist_transfer_finish (transfer, err);	/* F may be freed by it.  */
}

/* The application's write callback is full: the chunks stay unacknowledged, and
   the worker stops after four.  */
static void
file_pause_hook (struct twist_transfer *t)
{
  struct twist_file *f = t->state;

  if (f != NULL && f->fio != NULL)
    twist_fio_pause (f->fio);
}

static void
file_resume_hook (struct twist_transfer *t)
{
  struct twist_file *f = t->state;

  if (f != NULL && f->fio != NULL)
    twist_fio_resume (f->fio);
}

static const struct twist_fio_read_ops file_ops = { file_open, file_size,
                                                    file_chunk, file_end,
                                                    file_release };

int
twist_file_attach (struct twist_transfer *transfer)
{
  struct twist_file *f;
  const char *host;
  const char *path;
  int rc;

  if (transfer == NULL || transfer->url == NULL || transfer->loop == NULL
      || transfer->runtime == NULL || transfer->runtime->xfer == NULL)
    return TWIST_ERR_INVAL;
  host = transfer->url->host;
  path = transfer->url->path;
  rc = twist_file_check_url (host, path, transfer->url->path_set);
  if (rc != TWIST_OK)
    return rc;
  f = calloc (1, sizeof *f);
  if (f == NULL)
    return TWIST_ERR_NOMEM;
  f->transfer = transfer;
  {
    int nul = 0;

    f->path = decode_path (path, &nul);
    if (f->path == NULL)
      {
        free (f);
        return nul ? TWIST_ERR_URL : TWIST_ERR_NOMEM;
      }
  }
  if (transfer->range != NULL && transfer->range[0] != 0)
    {
      rc = parse_range (transfer->range, f);
      if (rc != TWIST_OK)
        {
          free (f->path);
          free (f);
          return rc;
        }
    }
  /* The pipeline's worker waits on the loop for room, so a pool with no
     thread is refused (TWIST_ERR_UNSUPPORTED).  */
  rc = twist_fio_read_new (transfer->loop, transfer->runtime->xfer, &file_ops,
                           f, &f->fio);
  if (rc != TWIST_OK)
    {
      free (f->path);
      free (f);
      return rc;
    }
  transfer->pause_fn = file_pause_hook;
  transfer->resume_fn = file_resume_hook;
  transfer->state = f;
  transfer->state_free = file_free;
  return TWIST_OK;
}
