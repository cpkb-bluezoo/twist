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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* A multipart/form-data body (TWISTOPT_FORM), sent as it is made.

   A form is a list of parts.  The upload that sends it is a push source: the
   MIME writer (mime/writer.c) turns part headers and body pieces into bytes,
   and its sink is the upload, which the connection can pause.  A part of data
   is fed to the writer in pieces as the writer is ready.  A part that is a
   file is read by the file pipeline on a pool of threads, and one that is a
   pipe or terminal is waited for, so the loop never reads a part itself; the
   chunks they give are fed to the writer the same way, and the source is
   paused (the file pipeline stops after a few chunks, a pipe is not read)
   while the writer is full.  Everything below runs on the loop's thread.  */

enum { KIND_NONE, KIND_DATA, KIND_FILE, KIND_FD };

struct twist_formpart
{
  char *name;
  char *filename;
  char *type;
  char **headers;
  size_t nheaders;
  int encoder;
  int kind;
  uint8_t *data;
  size_t len;
  char *path;
  int fd;
};

struct twist_form
{
  int refs;
  int backslash;
  struct twist_formpart **parts;
  size_t n;
  size_t cap;
};

/* ---- building a form ---- */

twist_form *
twist_form_new (void)
{
  twist_form *f = calloc (1, sizeof *f);

  if (f != NULL)
    f->refs = 1;
  return f;
}

struct twist_form *
twist_form_ref (struct twist_form *form)
{
  if (form != NULL)
    __atomic_add_fetch (&form->refs, 1, __ATOMIC_RELAXED);
  return form;
}

static void
part_free (struct twist_formpart *p)
{
  size_t i;

  if (p == NULL)
    return;
  free (p->name);
  free (p->filename);
  free (p->type);
  for (i = 0; i < p->nheaders; i++)
    free (p->headers[i]);
  free (p->headers);
  free (p->data);
  free (p->path);
  free (p);
}

void
twist_form_unref (struct twist_form *form)
{
  size_t i;

  if (form == NULL)
    return;
  if (__atomic_sub_fetch (&form->refs, 1, __ATOMIC_ACQ_REL) != 0)
    return;
  for (i = 0; i < form->n; i++)
    part_free (form->parts[i]);
  free (form->parts);
  free (form);
}

void
twist_form_free (twist_form *form)
{
  twist_form_unref (form);
}

void
twist_form_set_escape (twist_form *form, int backslash)
{
  if (form != NULL)
    form->backslash = backslash != 0;
}

twist_formpart *
twist_form_add (twist_form *form, const char *name)
{
  struct twist_formpart *p;

  if (form == NULL || name == NULL)
    return NULL;
  if (form->n == form->cap)
    {
      size_t cap = form->cap == 0 ? 4 : form->cap * 2;
      struct twist_formpart **grown = realloc (form->parts,
                                               cap * sizeof *grown);

      if (grown == NULL)
        return NULL;
      form->parts = grown;
      form->cap = cap;
    }
  p = calloc (1, sizeof *p);
  if (p == NULL)
    return NULL;
  p->name = twist_strdup (name);
  p->fd = -1;
  if (p->name == NULL)
    {
      free (p);
      return NULL;
    }
  form->parts[form->n++] = p;
  return p;
}

static void
part_clear_value (struct twist_formpart *p)
{
  free (p->data);
  free (p->path);
  p->data = NULL;
  p->path = NULL;
  p->len = 0;
  p->fd = -1;
  p->kind = KIND_NONE;
}

int
twist_formpart_data (twist_formpart *p, const void *data, size_t len)
{
  uint8_t *copy;

  if (p == NULL || (data == NULL && len > 0))
    return TWIST_ERR_INVAL;
  copy = malloc (len > 0 ? len : 1);
  if (copy == NULL)
    return TWIST_ERR_NOMEM;
  if (len > 0)
    memcpy (copy, data, len);
  part_clear_value (p);
  p->data = copy;
  p->len = len;
  p->kind = KIND_DATA;
  return TWIST_OK;
}

int
twist_formpart_file (twist_formpart *p, const char *path)
{
  char *copy;

  if (p == NULL || path == NULL)
    return TWIST_ERR_INVAL;
  copy = twist_strdup (path);
  if (copy == NULL)
    return TWIST_ERR_NOMEM;
  part_clear_value (p);
  p->path = copy;
  p->kind = KIND_FILE;
  return TWIST_OK;
}

int
twist_formpart_fd (twist_formpart *p, int fd)
{
  if (p == NULL || fd < 0)
    return TWIST_ERR_INVAL;
  part_clear_value (p);
  p->fd = fd;
  p->kind = KIND_FD;
  return TWIST_OK;
}

static int
set_string (char **dst, const char *s)
{
  char *copy;

  if (s == NULL)
    {
      free (*dst);
      *dst = NULL;
      return TWIST_OK;
    }
  copy = twist_strdup (s);
  if (copy == NULL)
    return TWIST_ERR_NOMEM;
  free (*dst);
  *dst = copy;
  return TWIST_OK;
}

int
twist_formpart_filename (twist_formpart *p, const char *filename)
{
  return p == NULL ? TWIST_ERR_INVAL : set_string (&p->filename, filename);
}

int
twist_formpart_type (twist_formpart *p, const char *type)
{
  return p == NULL ? TWIST_ERR_INVAL : set_string (&p->type, type);
}

int
twist_formpart_encoder (twist_formpart *p, int encoder)
{
  if (p == NULL || (encoder != TWIST_FORM_BINARY && encoder != TWIST_FORM_BASE64))
    return TWIST_ERR_INVAL;
  p->encoder = encoder;
  return TWIST_OK;
}

int
twist_formpart_header (twist_formpart *p, const char *header)
{
  char **grown;
  char *copy;

  if (p == NULL || header == NULL)
    return TWIST_ERR_INVAL;
  copy = twist_strdup (header);
  if (copy == NULL)
    return TWIST_ERR_NOMEM;
  grown = realloc (p->headers, (p->nheaders + 1) * sizeof *grown);
  if (grown == NULL)
    {
      free (copy);
      return TWIST_ERR_NOMEM;
    }
  p->headers = grown;
  p->headers[p->nheaders++] = copy;
  return TWIST_OK;
}

/* ---- the message ---- */

/* A name or file name as it is written between quotes.  By default `"`, CR and
   LF are percent-encoded; with backslash escaping `"` and `\` get a backslash
   and CR and LF cannot be written (NULL, *ERR set).  */
static char *
escape_name (const char *s, int backslash, int *err)
{
  size_t n = strlen (s);
  char *out = twist_xmalloc (n * 3 + 1);
  size_t o = 0;
  size_t i;

  *err = TWIST_OK;
  if (out == NULL)
    {
      *err = TWIST_ERR_NOMEM;
      return NULL;
    }
  for (i = 0; i < n; i++)
    {
      char c = s[i];

      if (backslash)
        {
          if (c == '\r' || c == '\n')
            {
              free (out);
              *err = TWIST_ERR_INVAL;
              return NULL;
            }
          if (c == '"' || c == '\\')
            out[o++] = '\\';
          out[o++] = c;
        }
      else if (c == '"' || c == '\r' || c == '\n')
        {
          static const char *const enc[] = { "%22", "%0D", "%0A" };
          const char *e = enc[c == '"' ? 0 : (c == '\r' ? 1 : 2)];

          memcpy (out + o, e, 3);
          o += 3;
        }
      else
        out[o++] = c;
    }
  out[o] = 0;
  return out;
}

/* Step I of the head of a part: the boundary, Content-Disposition, Content-Type
   and Content-Transfer-Encoding (always there; empty steps write nothing),
   then the part's own headers.  A step writes at most about a kilobyte.  */
#define HEAD_FIXED 4

static size_t
head_steps (const struct twist_formpart *p)
{
  return HEAD_FIXED + p->nheaders;
}

static int
head_step (struct twist_mime *m, const struct twist_form *form,
           const struct twist_formpart *p, size_t step)
{
  int err;
  char *name;
  char *file = NULL;
  char *line;
  size_t n;
  int rc;

  switch (step)
    {
    case 0:
      return twist_mime_part (m);
    case 1:
      name = escape_name (p->name, form->backslash, &err);
      if (name == NULL)
        return err;
      if (p->filename != NULL)
        {
          file = escape_name (p->filename, form->backslash, &err);
          if (file == NULL)
            {
              free (name);
              return err;
            }
        }
      n = strlen (name) + (file != NULL ? strlen (file) : 0) + 64;
      line = twist_xmalloc (n);
      if (line == NULL)
        {
          free (name);
          free (file);
          return TWIST_ERR_NOMEM;
        }
      if (file != NULL)
        snprintf (line, n, "form-data; name=\"%s\"; filename=\"%s\"", name,
                  file);
      else
        snprintf (line, n, "form-data; name=\"%s\"", name);
      rc = twist_mime_header (m, "Content-Disposition", line);
      free (line);
      free (name);
      free (file);
      return rc;
    case 2:
      return p->type != NULL ? twist_mime_header (m, "Content-Type", p->type)
                             : TWIST_OK;
    case 3:
      return p->encoder == TWIST_FORM_BASE64
             ? twist_mime_header (m, "Content-Transfer-Encoding", "base64")
             : TWIST_OK;
    default:
      {
        const char *h = p->headers[step - HEAD_FIXED];
        const char *colon = strchr (h, ':');
        char *hn;

        if (colon == NULL || colon == h)
          return TWIST_ERR_INVAL;
        hn = twist_xmalloc ((size_t) (colon - h) + 1);
        if (hn == NULL)
          return TWIST_ERR_NOMEM;
        memcpy (hn, h, (size_t) (colon - h));
        hn[colon - h] = 0;
        colon++;
        while (*colon == ' ' || *colon == '\t')
          colon++;
        rc = twist_mime_header (m, hn, colon);
        free (hn);
        return rc;
      }
    }
}

static int
body_start (struct twist_mime *m, const struct twist_formpart *p)
{
  return p->encoder == TWIST_FORM_BASE64 ? twist_mime_body_b64 (m, NULL, 0)
                                         : twist_mime_body (m, NULL, 0);
}

static int
feed (struct twist_mime *m, const struct twist_formpart *p,
      const uint8_t *data, size_t len)
{
  return p->encoder == TWIST_FORM_BASE64 ? twist_mime_body_b64 (m, data, len)
                                         : twist_mime_body (m, data, len);
}

/* ---- the length ---- */

static int
count_take (void *user, const uint8_t *data, size_t len, size_t *taken)
{
  (void) data;
  *(long long *) user += (long long) len;
  *taken = len;
  return 0;
}

/* What N bytes come to in the body of a part.  */
static long long
encoded_size (const struct twist_formpart *p, long long n)
{
  long long groups;

  if (p->encoder != TWIST_FORM_BASE64 || n == 0)
    return n;
  groups = n / 3;
  /* Four characters a group, a partial one as four, and a CRLF after each
     nineteenth whole group (a line of 76).  */
  return groups * 4 + (n % 3 != 0 ? 4 : 0) + 2 * (groups / 19);
}

/* How much of a part there is, or -1 if it is not known before it is read.  */
static long long
part_size (const struct twist_formpart *p)
{
  struct stat st;

  switch (p->kind)
    {
    case KIND_NONE:
      return 0;
    case KIND_DATA:
      return (long long) p->len;
    case KIND_FILE:
      if (stat (p->path, &st) != 0 || !S_ISREG (st.st_mode))
        return -1;
      return (long long) st.st_size;
    default:
      if (fstat (p->fd, &st) != 0 || !S_ISREG (st.st_mode))
        return -1;
      {
        off_t at = lseek (p->fd, 0, SEEK_CUR);

        if (at < 0 || (long long) at > (long long) st.st_size)
          return -1;
        return (long long) st.st_size - (long long) at;
      }
    }
}

/* The length of the whole message, or -1.  The writer is run with empty bodies
   to count what is not a body; a delimiter always has its CRLF (strict), so
   no body changes what is around it.  */
static long long
form_length (const struct twist_form *form)
{
  long long total = 0;
  long long bodies = 0;
  struct twist_mime *m = twist_mime_new_push (count_take, &total);
  size_t i;
  int ok = m != NULL && twist_mime_begin (m, "form-data") == TWIST_OK;

  if (!ok)
    {
      twist_mime_free (m);
      return -1;
    }
  twist_mime_set_strict (m, 1);
  for (i = 0; i < form->n && ok; i++)
    {
      const struct twist_formpart *p = form->parts[i];
      long long sz = part_size (p);
      size_t s;

      if (sz < 0)
        {
          ok = 0;
          break;
        }
      for (s = 0; s < head_steps (p); s++)
        if (head_step (m, form, p, s) != TWIST_OK)
          ok = 0;
      if (ok && body_start (m, p) != TWIST_OK)
        ok = 0;
      bodies += encoded_size (p, sz);
    }
  if (ok && twist_mime_finish (m) != TWIST_OK)
    ok = 0;
  twist_mime_free (m);
  return ok ? total + bodies : -1;
}

/* ---- the source ---- */

enum { PH_PART, PH_BODY, PH_END, PH_DONE };

struct form_src;

/* What a descriptor source calls back with, apart from the source: the source
   cannot be freed from inside one of its own callbacks, and the callbacks that
   are still to come after it is let go of must find nobody.  */
struct form_fs
{
  struct form_src *src;		/* NULL once let go of.  */
  struct twist_fd_source *fs;
};

/* The open of a file part, which runs on a worker and may run after the
   source is gone: it holds what it needs.  */
struct form_in
{
  struct form_src *src;		/* Loop only.  */
  char *path;
  int fd;			/* A duplicate, if the part is a descriptor.  */
  long long start;
};

struct form_src
{
  struct twist_transfer *t;
  struct twist_form *form;
  struct twist_upload *up;
  struct twist_mime *mime;
  size_t idx;
  size_t step;
  int phase;
  size_t mem_off;
  int body_started;
  int body_ended;
  int body_err;
  struct twist_fio *fio;
  struct twist_fd_source *fs;
  struct form_fs *fsctx;
  int held;			/* The body source is paused for the writer.  */
  uint8_t pend[TWIST_FIO_CHUNK];
  size_t pend_len, pend_off;
  int in_pump, again, failed;
};

static void body_stop (struct form_src *s);

static void
fail (struct form_src *s, int err)
{
  if (s->failed)
    return;
  s->failed = 1;
  /* Nothing more is read: a worker waiting to hand over a chunk is let go.  */
  body_stop (s);
  twist_upload_finish (s->up, err);
}

/* The writer's sink is the upload: as much as the consumer will take now.  */
static int
push_take (void *user, const uint8_t *data, size_t len, size_t *taken)
{
  struct form_src *s = user;
  size_t done = 0;

  while (done < len && twist_upload_active (s->up))
    {
      size_t max = twist_upload_max (s->up);
      size_t n = len - done;

      if (max == 0)
        break;
      if (n > max)
        n = max;
      if (twist_upload_push (s->up, data + done, n) != TWIST_OK)
        {
          *taken = done;
          return -1;
        }
      done += n;
    }
  *taken = done;
  return 0;
}

static void form_pump (struct form_src *s);

/* ---- a file part ---- */

static int
in_open (void *user, int *fd, int *own, long long *start, long long *length,
         char **msg)
{
  struct form_in *in = user;
  struct stat st;

  if (in->path != NULL)
    {
      int f = open (in->path, O_RDONLY | O_CLOEXEC);

      if (f < 0 || fstat (f, &st) != 0 || !S_ISREG (st.st_mode))
        {
          size_t n = strlen (in->path) + 32;

          if (f >= 0)
            close (f);
          *msg = twist_xmalloc (n);
          if (*msg != NULL)
            snprintf (*msg, n, "could not read file %s", in->path);
          return TWIST_ERR_FILE;
        }
      *fd = f;
    }
  else
    {
      *fd = in->fd;
      in->fd = -1;
    }
  *own = 1;
  *start = in->start;
  *length = -1;
  return TWIST_OK;
}

/* Feed the chunk that is waiting to the writer; whether it is all in.  */
static int
feed_pend (struct form_src *s)
{
  const struct twist_formpart *p = s->form->parts[s->idx];

  while (s->pend_off < s->pend_len)
    {
      size_t n = s->pend_len - s->pend_off;
      int rc;

      if (!twist_mime_ready (s->mime))
        return 0;
      if (n > TWIST_MIME_PIECE)
        n = TWIST_MIME_PIECE;
      rc = feed (s->mime, p, s->pend + s->pend_off, n);
      if (rc != TWIST_OK)
        {
          fail (s, rc);
          return 0;
        }
      s->pend_off += n;
    }
  s->pend_off = s->pend_len = 0;
  return 1;
}

static int
in_chunk (void *user, uint8_t *data, size_t len)
{
  struct form_in *in = user;
  struct form_src *s = in->src;

  if (s == NULL || len > sizeof s->pend)
    return TWIST_ERR_ABORTED;
  memcpy (s->pend, data, len);
  s->pend_len = len;
  s->pend_off = 0;
  form_pump (s);
  /* The writer is full: no more is taken from the file until it can be.  */
  if (s->pend_off < s->pend_len && s->fio != NULL && !s->held)
    {
      s->held = 1;
      twist_fio_pause (s->fio);
    }
  return TWIST_OK;
}

static void
in_end (void *user, int err, char *msg)
{
  struct form_in *in = user;
  struct form_src *s = in->src;

  free (msg);
  if (s == NULL)
    return;
  s->body_ended = 1;
  s->body_err = err;
  form_pump (s);
}

static void
in_release (void *user)
{
  struct form_in *in = user;

  if (in->fd >= 0)
    close (in->fd);
  free (in->path);
  free (in);
}

static const struct twist_fio_read_ops in_ops = { in_open, NULL, in_chunk,
                                                  in_end, in_release };

/* ---- a part from a pipe or terminal ---- */

static size_t
fs_chunk (void *user, const uint8_t *data, size_t len)
{
  struct form_fs *ctx = user;
  struct form_src *s = ctx->src;
  const struct twist_formpart *p;
  size_t off = 0;

  if (s == NULL)
    return len;
  p = s->form->parts[s->idx];

  form_pump (s);
  while (off < len && !s->failed && twist_upload_active (s->up)
         && twist_mime_ready (s->mime))
    {
      size_t n = len - off;
      int rc;

      if (n > TWIST_MIME_PIECE)
        n = TWIST_MIME_PIECE;
      rc = feed (s->mime, p, data + off, n);
      if (rc != TWIST_OK)
        {
          fail (s, rc);
          break;
        }
      off += n;
    }
  if (off < len)
    s->held = 1;		/* Less than LEN pauses the source.  */
  return off;
}

static void
fs_end (void *user, int err)
{
  struct form_fs *ctx = user;
  struct form_src *s = ctx->src;

  if (s == NULL)
    return;
  s->body_ended = 1;
  s->body_err = err;
  form_pump (s);
}

static const struct twist_fd_source_ops fs_ops = { fs_chunk, fs_end };

static void
fs_retire (void *p)
{
  struct form_fs *ctx = p;

  twist_fd_source_free (ctx->fs);
  free (ctx);
}

static void
body_stop (struct form_src *s)
{
  twist_fio_free (s->fio);
  s->fio = NULL;
  if (s->fs != NULL)
    {
      /* This may be called from a callback of the source: it is paused, and
         freed from the loop when the call is over.  */
      struct form_fs *ctx = s->fsctx;

      ctx->src = NULL;
      ctx->fs = s->fs;
      twist_fd_source_pause (s->fs);
      s->fs = NULL;
      s->fsctx = NULL;
      if (twist_loop_post (s->t->loop, fs_retire, ctx) != TWIST_OK)
        fs_retire (ctx);
    }
}

/* Begin to read the part being sent.  */
static int
body_open (struct form_src *s)
{
  const struct twist_formpart *p = s->form->parts[s->idx];
  struct twist_transfer *t = s->t;
  struct stat st;
  int regular = p->kind == KIND_FILE;

  s->body_ended = 0;
  s->body_err = TWIST_OK;
  s->held = 0;
  s->pend_len = s->pend_off = 0;
  if (p->kind == KIND_FD)
    regular = fstat (p->fd, &st) == 0 && S_ISREG (st.st_mode);
  if (!regular)
    {
      struct form_fs *ctx = calloc (1, sizeof *ctx);
      int rc;

      if (ctx == NULL)
        return TWIST_ERR_NOMEM;
      ctx->src = s;
      rc = twist_fd_source_new (t->loop, p->fd, &fs_ops, ctx, &s->fs);
      if (rc != TWIST_OK)
        {
          free (ctx);
          return rc;
        }
      s->fsctx = ctx;
      return TWIST_OK;
    }
  {
    struct form_in *in = calloc (1, sizeof *in);
    int rc;

    if (in == NULL)
      return TWIST_ERR_NOMEM;
    in->src = s;
    in->fd = -1;
    if (p->kind == KIND_FILE)
      {
        in->path = twist_strdup (p->path);
        if (in->path == NULL)
          {
            free (in);
            return TWIST_ERR_NOMEM;
          }
      }
    else
      {
        off_t at = lseek (p->fd, 0, SEEK_CUR);

        in->fd = dup (p->fd);
        in->start = at >= 0 ? (long long) at : 0;
        if (in->fd < 0)
          {
            free (in);
            return TWIST_ERR_INVAL;
          }
      }
    if (t->runtime == NULL || t->runtime->xfer == NULL)
      {
        in_release (in);
        return TWIST_ERR_UNSUPPORTED;
      }
    rc = twist_fio_read_new (t->loop, t->runtime->xfer, &in_ops, in, &s->fio);
    if (rc != TWIST_OK)
      in_release (in);
    return rc;
  }
}

/* ---- the pump ---- */

static void
next_part (struct form_src *s)
{
  body_stop (s);
  s->idx++;
  s->step = 0;
  s->phase = PH_PART;
  s->body_started = 0;
}

static void
pump_once (struct form_src *s)
{
  struct twist_mime *m = s->mime;

  while (!s->failed && twist_upload_active (s->up))
    {
      const struct twist_formpart *p;
      int rc;

      if (!twist_mime_ready (m))
        {
          if (!twist_mime_paused (m))
            {
              fail (s, TWIST_ERR_ABORTED);
              return;
            }
          rc = twist_mime_resume (m);
          if (rc != TWIST_OK)
            {
              fail (s, rc);
              return;
            }
          if (!twist_mime_ready (m) && twist_mime_pending (m) > 0)
            return;		/* Full: wait for the consumer.  */
        }
      /* A chunk of a file that did not all go in.  */
      if (s->pend_off < s->pend_len)
        {
          if (!feed_pend (s))
            return;
        }
      if (s->held && s->pend_off >= s->pend_len)
        {
          s->held = 0;
          if (s->fio != NULL)
            twist_fio_resume (s->fio);
          else if (s->fs != NULL)
            twist_fd_source_resume (s->fs);
        }
      switch (s->phase)
        {
        case PH_PART:
          if (s->idx == s->form->n)
            {
              rc = twist_mime_finish (m);
              if (rc != TWIST_OK)
                {
                  fail (s, rc);
                  return;
                }
              s->phase = PH_END;
              continue;
            }
          p = s->form->parts[s->idx];
          if (s->step < head_steps (p))
            rc = head_step (m, s->form, p, s->step++);
          else
            {
              rc = body_start (m, p);
              s->phase = PH_BODY;
              s->mem_off = 0;
            }
          if (rc != TWIST_OK)
            {
              fail (s, rc);
              return;
            }
          continue;
        case PH_BODY:
          p = s->form->parts[s->idx];
          if (p->kind == KIND_NONE)
            next_part (s);
          else if (p->kind == KIND_DATA)
            {
              size_t n = p->len - s->mem_off;

              if (n == 0)
                {
                  next_part (s);
                  continue;
                }
              if (n > TWIST_MIME_PIECE)
                n = TWIST_MIME_PIECE;
              rc = feed (m, p, p->data + s->mem_off, n);
              if (rc != TWIST_OK)
                {
                  fail (s, rc);
                  return;
                }
              s->mem_off += n;
            }
          else
            {
              if (!s->body_started)
                {
                  s->body_started = 1;
                  rc = body_open (s);
                  if (rc != TWIST_OK)
                    {
                      fail (s, rc);
                      return;
                    }
                  return;	/* Chunks come to the callbacks.  */
                }
              if (!s->body_ended || s->pend_off < s->pend_len)
                return;
              if (s->body_err != TWIST_OK)
                {
                  fail (s, s->body_err);
                  return;
                }
              next_part (s);
            }
          continue;
        case PH_END:
          if (twist_mime_pending (m) > 0)
            return;
          s->phase = PH_DONE;
          body_stop (s);
          twist_upload_finish (s->up, TWIST_OK);
          return;
        default:
          return;
        }
    }
}

static void
form_pump (struct form_src *s)
{
  if (s->in_pump)
    {
      s->again = 1;
      return;
    }
  s->in_pump = 1;
  do
    {
      s->again = 0;
      pump_once (s);
    }
  while (s->again && !s->failed);
  s->in_pump = 0;
}

static void
src_resume (void *user)
{
  form_pump (user);
}

static void
src_pause (void *user)
{
  struct form_src *s = user;

  if (s->fio != NULL)
    twist_fio_pause (s->fio);
  else if (s->fs != NULL)
    twist_fd_source_pause (s->fs);
  s->held = 1;
}

static int
src_restart (void *user)
{
  struct form_src *s = user;
  size_t i;

  /* What was read from a pipe is gone.  */
  for (i = 0; i < s->form->n; i++)
    {
      const struct twist_formpart *p = s->form->parts[i];
      struct stat st;

      if (p->kind == KIND_FD
          && (fstat (p->fd, &st) != 0 || !S_ISREG (st.st_mode)))
        return -1;
    }
  body_stop (s);
  twist_mime_reset (s->mime);
  s->idx = 0;
  s->step = 0;
  s->phase = PH_PART;
  s->body_started = 0;
  s->failed = 0;
  s->held = 0;
  s->pend_len = s->pend_off = 0;
  return 0;
}

static void
src_stop (void *user)
{
  body_stop (user);
}

static void
src_release (void *user)
{
  struct form_src *s = user;

  body_stop (s);
  twist_mime_free (s->mime);
  twist_form_unref (s->form);
  free (s);
}

static const struct twist_upload_producer src_ops = {
  src_resume, src_pause, src_restart, src_release, NULL, src_stop
};

struct twist_upload *
twist_form_upload_new (struct twist_transfer *t)
{
  struct form_src *s;
  const char *boundary;
  long long len;

  if (t == NULL || t->form == NULL)
    return NULL;
  s = calloc (1, sizeof *s);
  if (s == NULL)
    return NULL;
  s->t = t;
  s->form = twist_form_ref (t->form);
  s->mime = twist_mime_new_push (push_take, s);
  if (s->mime == NULL || twist_mime_begin (s->mime, "form-data") != TWIST_OK)
    {
      twist_mime_free (s->mime);
      twist_form_unref (s->form);
      free (s);
      return NULL;
    }
  twist_mime_set_strict (s->mime, 1);
  boundary = twist_mime_boundary (s->mime);
  snprintf (t->form_boundary, sizeof t->form_boundary, "%s",
            boundary != NULL ? boundary : "");
  /* The length the request carries, if every part's is known.  */
  len = form_length (s->form);
  t->infilesize = len;
  s->up = twist_upload_new (&src_ops, s);
  if (s->up == NULL)
    {
      twist_mime_free (s->mime);
      twist_form_unref (s->form);
      free (s);
      return NULL;
    }
  return s->up;
}
