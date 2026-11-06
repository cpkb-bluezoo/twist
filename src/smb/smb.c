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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* One file from an SMB share, over TCP port 445.

   smb://[user[:password]@]host[:port]/share/path.  The share is the first
   segment of the path; the rest is the file, percent-decoded, as UTF-8 with
   backslashes for separators.  The user is the URL's or -u, and may be
   DOMAIN\user or DOMAIN/user; there is no login without one.

   The session layer (session.c) does the negotiation, the login, the keys and
   the encryption.  This is what is asked of it afterwards:

     CREATE   open the file for reading; its end-of-file value is the size.
     READ     requests of up to the negotiated size, up to READ_WINDOW at a
              time and as many as the credits allow, each at an offset.  The
              answers are written to the application in the order of the file,
              however they arrive: one that comes before an earlier one is
              kept until that is written.  A server may answer with less than
              was asked, and the rest is asked for.  While the application's
              callback is full no more is asked for.
     CLOSE, TREE_DISCONNECT, LOGOFF   in that order, once everything wanted is
              written.

   A resume (-C) starts the download at an offset, and a range (-r) at its
   first byte and stops after its last; both are inside the size the server
   gave.  A listing and an upload are other issues and are refused here.  */

#define READ_WINDOW 8u
#define WRITE_WINDOW 8u
#define PUSH_MAX 8192u
#define SLOTS 32u
#define SMB_STATUS_ACCESS_DENIED 0xC0000022u
#define SMB_STATUS_END_OF_FILE 0xC0000011u
#define FILE_READ_DATA 0x00000001u
#define FILE_READ_ATTRIBUTES 0x00000080u
#define SYNCHRONIZE 0x00100000u
#define FILE_SHARE_ALL 0x00000007u
#define FILE_SHARE_READ 0x00000001u
#define FILE_OPEN 0x00000001u
#define FILE_OPEN_IF 0x00000003u
#define FILE_OVERWRITE_IF 0x00000005u
#define FILE_DIRECTORY_FILE 0x00000001u
#define FILE_NON_DIRECTORY_FILE 0x00000040u
#define FILE_WRITE_DATA 0x00000002u
#define FILE_APPEND_DATA 0x00000004u
#define FILE_WRITE_ATTRIBUTES 0x00000100u
#define FILE_ATTRIBUTE_DIRECTORY 0x00000010u
#define FILE_ATTRIBUTE_READONLY 0x00000001u
#define STATUS_NO_MORE_FILES 0x80000006u
#define STATUS_NO_SUCH_FILE 0xC000000Fu
#define INFO_FILE_ID_BOTH_DIR 0x25
#define RESTART_SCANS 0x01
#define DIR_ENTRY_FIXED 104u

enum
{
  X_NEW,
  X_LOGIN,			/* Until the tree is connected.  */
  X_MKDIR,			/* Making a directory above the file.  */
  X_MKCLOSE,
  X_OPEN,
  X_READ,
  X_WRITE,
  X_LIST,
  X_CLOSE,
  X_TREED,
  X_LOGOFF,
  X_DONE
};

struct slot
{
  uint64_t id;			/* Of the request, once sent.  */
  uint64_t roff;		/* Where the request starts in the file.  */
  uint32_t ask, got;
  uint8_t *buf;			/* What came, while an earlier slot is awaited.  */
  int sent, done;
};

struct twist_smb
{
  struct twist_transfer *transfer;
  struct twist_mail_link link;
  struct twist_endpoint *ep;
  struct twist_smb_session *sess;
  int (*test_send) (void *user, const uint8_t *data, size_t len);
  void *test_user;
  int phase;
  int finished;
  char *path;			/* UTF-8, backslashes.  */
  uint8_t fid[16];
  uint64_t size;
  int have_file;
  uint64_t start, end;		/* The bytes wanted: [start, end).  */
  uint64_t next_req, next_out;
  struct slot slots[SLOTS];
  unsigned nslots;
  struct slot *cur;
  uint32_t cur_before;	/* What it had when its answer began.  */
  uint32_t chunk;
  int hold;			/* The application's callback is full.  */
  int sent_close;
  int ranged;

  /* Upload.  */
  int put;
  int append;
  int make_dirs;
  size_t dir_pos;		/* Into path: where the next directory name ends.  */
  struct twist_upload *up;
  int up_owned;
  uint8_t *wbuf;
  size_t wcap, wlen;
  int src_eof, src_failed;
  int pumping;
  uint64_t put_off;
  struct
  {
    uint64_t id;
    uint32_t len;
  } wr[WRITE_WINDOW];
  unsigned nwr;
  int cur_w;			/* Index of the write being answered, or -1.  */
  int (*test_full) (void *user);

  /* A listing.  */
  int list, list_only;
  int first_query, list_end, list_wait;
  unsigned entries;		/* In the answer being read.  */
};

static const struct twist_ntlm_rand *test_rnd;
static time_t test_now;

void
twist_smb_set_test_now (time_t now)
{
  test_now = now;
}

void
twist_smb_set_test_rnd (const struct twist_ntlm_rand *rnd)
{
  test_rnd = rnd;
}

static void
detail (struct twist_smb *x, const char *msg)
{
  if (twist_transfer_error (x->transfer) == NULL)
    twist_transfer_set_error (x->transfer, twist_strdup (msg));
}

static void
smb_complete (struct twist_smb *x, int err)
{
  if (x == NULL || x->finished)
    return;
  x->finished = 1;
  x->phase = X_DONE;
  twist_transfer_finish (x->transfer, err);
}

/* A failure of the session or of the server's answer.  Once everything
   wanted has been written a failure in the teardown is not the transfer's.  */
static void
smb_fail (struct twist_smb *x, int err)
{
  const struct twist_smb_session_info *info;
  char msg[160];

  if (x->finished)
    return;
  /* Once everything wanted is written (and, for an upload, the file is
     closed) a failure in the teardown is not the transfer's.  */
  if (x->phase >= (x->put ? X_TREED : X_CLOSE))
    {
      smb_complete (x, TWIST_OK);
      return;
    }
  info = x->sess != NULL ? twist_smb_session_info (x->sess) : NULL;
  if (info != NULL && info->status != 0)
    {
      snprintf (msg, sizeof msg, _("the server refused it (NT status "
                                   "0x%08x)"), (unsigned) info->status);
      detail (x, msg);
      if (info->status == SMB_STATUS_ACCESS_DENIED)
        x->transfer->proto_status = 9;
      else if (err == TWIST_ERR_FILE)
        x->transfer->proto_status = 78;
      else if (info->status == SMB_STATUS_END_OF_FILE)
        err = TWIST_ERR_PARTIAL;
    }
  smb_complete (x, err);
}

/* ---- The URL ---- */

static int
hexv (int c)
{
  if (c >= '0' && c <= '9')
    return c - '0';
  if (c >= 'a' && c <= 'f')
    return c - 'a' + 10;
  if (c >= 'A' && c <= 'F')
    return c - 'A' + 10;
  return -1;
}

/* Percent-decode N bytes of S.  A NUL is an error.  */
static char *
decode (const char *s, size_t n)
{
  char *p = malloc (n + 1);
  size_t i, o = 0;

  if (p == NULL)
    return NULL;
  for (i = 0; i < n; i++)
    {
      if (s[i] == '%' && i + 2 < n && hexv (s[i + 1]) >= 0 && hexv (s[i + 2]) >= 0)
        {
          int c = hexv (s[i + 1]) * 16 + hexv (s[i + 2]);

          if (c == 0)
            {
              free (p);
              return NULL;
            }
          p[o++] = (char) c;
          i += 2;
        }
      else
        p[o++] = s[i];
    }
  p[o] = 0;
  return p;
}

/* The share and the path from the URL's path.  */
static int
take_path (struct twist_smb *x, char **share, int *dir)
{
  const char *raw = x->transfer->url->path;
  const char *seg, *slash;
  char *rest, *p;
  size_t n;

  *share = NULL;
  *dir = 0;
  if (raw == NULL || raw[0] != '/' || raw[1] == 0)
    {
      detail (x, _("the URL names no share"));
      return TWIST_ERR_URL;
    }
  seg = raw + 1;
  slash = strchr (seg, '/');
  n = slash != NULL ? (size_t) (slash - seg) : strlen (seg);
  if (n == 0)
    {
      detail (x, _("the URL names no share"));
      return TWIST_ERR_URL;
    }
  *share = decode (seg, n);
  if (*share == NULL || (*share)[0] == 0 || strchr (*share, ':') != NULL
      || strchr (*share, '\\') != NULL)
    {
      free (*share);
      *share = NULL;
      detail (x, _("the share name is not valid"));
      return TWIST_ERR_URL;
    }
  if (slash == NULL || slash[1] == 0)
    {
      *dir = 1;			/* The share itself: a directory.  */
      x->path = twist_strdup ("");
      return x->path != NULL ? TWIST_OK : TWIST_ERR_NOMEM;
    }
  rest = decode (slash + 1, strlen (slash + 1));
  if (rest == NULL)
    {
      detail (x, _("a NUL in the path"));
      return TWIST_ERR_URL;
    }
  /* A colon would name an alternate data stream.  */
  if (strchr (rest, ':') != NULL)
    {
      free (rest);
      detail (x, _("a colon in the path"));
      return TWIST_ERR_URL;
    }
  n = strlen (rest);
  if (n > 0 && rest[n - 1] == '/')
    *dir = 1;
  for (p = rest; *p != 0; p++)
    if (*p == '/')
      *p = '\\';
  x->path = rest;
  return TWIST_OK;
}

/* ---- Sending ---- */

static int
smb_send (void *user, const uint8_t *data, size_t len)
{
  struct twist_smb *x = user;

  if (x->test_send != NULL)
    return x->test_send (x->test_user, data, len);
  if (x->ep == NULL)
    return TWIST_ERR_CLOSED;
  return twist_endpoint_send (x->ep, data, len);
}

/* Whether the connection holds as much as it should of what has not been
   written: nothing more is sent until it says it has room.  */
static int
conn_full (struct twist_smb *x)
{
  if (x->test_full != NULL)
    return x->test_full (x->test_user);
  return x->ep != NULL && twist_endpoint_full (x->ep);
}

/* ---- The range ---- */

static int
digits (const char *s, uint64_t *v, const char **end)
{
  uint64_t a = 0;
  const char *p = s;

  if (*p < '0' || *p > '9')
    return -1;
  while (*p >= '0' && *p <= '9')
    {
      if (a > (UINT64_MAX - 9) / 10)
        return -1;
      a = a * 10 + (uint64_t) (*p - '0');
      p++;
    }
  *v = a;
  *end = p;
  return 0;
}

/* FIRST-LAST, FIRST- or -COUNT.  Sets START and END from SIZE.  */
static int
apply_range (struct twist_smb *x, const char *r)
{
  uint64_t a, b;
  const char *p;

  if (r[0] == '-')
    {
      if (digits (r + 1, &a, &p) != 0 || *p != 0)
        return -1;
      x->start = a < x->size ? x->size - a : 0;
      x->end = x->size;
      return 0;
    }
  if (digits (r, &a, &p) != 0 || *p != '-')
    return -1;
  x->start = a;
  x->end = x->size;
  if (p[1] == 0)
    return 0;
  if (digits (p + 1, &b, &p) != 0 || *p != 0 || b < a || b == UINT64_MAX)
    return -1;
  if (b + 1 < x->end)
    x->end = b + 1;
  return 0;
}

/* ---- Reads ---- */

static void drain (struct twist_smb *x);
static void pump (struct twist_smb *x);

static int
issue (struct twist_smb *x, struct slot *sl)
{
  struct twist_smb_req h;
  uint8_t out[256];
  size_t n;
  int rc = twist_smb_session_request (x->sess, 1, &h);

  if (rc == TWIST_ERR_AGAIN)
    return rc;			/* No credits for it yet.  */
  if (rc != TWIST_OK)
    return rc;
  rc = twist_smb_w_read (out, sizeof out, &n, &h, x->fid, sl->ask - sl->got,
                         sl->roff + sl->got);
  if (rc != TWIST_OK)
    return rc;
  sl->id = h.message_id;
  sl->sent = 1;
  return twist_smb_session_send (x->sess, out, n, NULL, 0);
}

static struct slot *
slot_insert (struct twist_smb *x, uint64_t roff, uint32_t ask, uint32_t got)
{
  unsigned i = 0, j;

  if (x->nslots >= SLOTS)
    return NULL;
  while (i < x->nslots && x->slots[i].roff + x->slots[i].got <= roff)
    i++;
  for (j = x->nslots; j > i; j--)
    x->slots[j] = x->slots[j - 1];
  memset (&x->slots[i], 0, sizeof x->slots[i]);
  x->slots[i].roff = roff;
  x->slots[i].ask = ask;
  x->slots[i].got = got;
  x->nslots++;
  return &x->slots[i];
}

static void
slot_remove (struct twist_smb *x, unsigned i)
{
  free (x->slots[i].buf);
  for (; i + 1 < x->nslots; i++)
    x->slots[i] = x->slots[i + 1];
  x->nslots--;
}

static unsigned
outstanding (const struct twist_smb *x)
{
  unsigned i, n = 0;

  for (i = 0; i < x->nslots; i++)
    if (x->slots[i].sent && !x->slots[i].done)
      n++;
  return n;
}

static void
begin_close (struct twist_smb *x)
{
  struct twist_smb_req h;
  uint8_t out[256];
  size_t n;

  if (x->sent_close)
    return;
  x->sent_close = 1;
  x->phase = X_CLOSE;
  if (twist_smb_session_request (x->sess, 1, &h) != TWIST_OK
      || twist_smb_w_close (out, sizeof out, &n, &h, x->fid) != TWIST_OK
      || twist_smb_session_send (x->sess, out, n, NULL, 0) != TWIST_OK)
    smb_fail (x, TWIST_ERR_PROTOCOL);
}

/* Everything wanted is written.  */
static void
check_complete (struct twist_smb *x)
{
  if (x->phase == X_READ && x->nslots == 0 && x->next_req >= x->end
      && x->next_out >= x->end)
    begin_close (x);
}

static void
pump (struct twist_smb *x)
{
  unsigned i;

  while (x->phase == X_READ && !x->finished && !x->hold
         && !x->transfer->sink_paused)
    {
      struct slot *sl = NULL;
      uint64_t left;
      uint32_t len;
      int rc;

      if (outstanding (x) >= READ_WINDOW)
        break;
      for (i = 0; i < x->nslots; i++)
        if (!x->slots[i].sent)
          {
            sl = &x->slots[i];
            break;
          }
      if (sl == NULL)
        {
          if (x->next_req >= x->end || x->nslots >= SLOTS - 1)
            break;
          left = x->end - x->next_req;
          len = left < x->chunk ? (uint32_t) left : x->chunk;
          sl = slot_insert (x, x->next_req, len, 0);
          if (sl == NULL)
            break;
          x->next_req += len;
        }
      rc = issue (x, sl);
      if (rc == TWIST_ERR_AGAIN)
        break;
      if (rc != TWIST_OK)
        {
          smb_fail (x, rc);
          return;
        }
    }
  check_complete (x);
}

static void
write_out (struct twist_smb *x, const uint8_t *p, size_t n)
{
  twist_deliver (x->transfer, p, n);
  twist_transfer_downloaded (x->transfer, n);
  x->next_out += n;
}

/* Write what is ready, in order of the file.  */
static void
drain (struct twist_smb *x)
{
  while (x->nslots > 0 && x->slots[0].done && !x->finished)
    {
      struct slot *sl = &x->slots[0];

      if (sl->buf != NULL)
        {
          if (sl->roff != x->next_out)
            break;
          write_out (x, sl->buf, sl->got);
        }
      slot_remove (x, 0);
    }
}

/* ---- Events from the session ---- */

static int
on_header (void *u, const struct twist_smb_header *h)
{
  struct twist_smb *x = u;
  unsigned i;

  x->cur = NULL;
  x->cur_w = -1;
  if (x->phase == X_WRITE && h->command == TWIST_SMB_WRITE)
    {
      for (i = 0; i < x->nwr; i++)
        if (x->wr[i].id == h->message_id)
          {
            x->cur_w = (int) i;
            break;
          }
      return TWIST_OK;
    }
  if (x->phase != X_READ || h->command != TWIST_SMB_READ)
    return TWIST_OK;
  for (i = 0; i < x->nslots; i++)
    if (x->slots[i].sent && !x->slots[i].done && x->slots[i].id == h->message_id)
      {
        x->cur = &x->slots[i];
        x->cur_before = x->cur->got;
        break;
      }
  return TWIST_OK;
}

static int
on_create (void *u, const struct twist_smb_create *r)
{
  struct twist_smb *x = u;

  if (x->phase != X_OPEN && x->phase != X_MKDIR)
    return TWIST_ERR_PROTOCOL;
  memcpy (x->fid, r->file_id, 16);
  x->size = r->end_of_file;
  x->have_file = 1;
  return TWIST_OK;
}

static int
on_read (void *u, uint32_t len, uint32_t rem)
{
  struct twist_smb *x = u;

  (void) rem;
  if (x->phase != X_READ || x->cur == NULL
      || len > x->cur->ask - x->cur->got)
    return TWIST_ERR_PROTOCOL;
  return TWIST_OK;
}

static size_t
on_data (void *u, enum twist_smb_data kind, const uint8_t *p, size_t n)
{
  struct twist_smb *x = u;
  struct slot *sl = x->cur;

  if (kind != TWIST_SMB_DATA_READ || sl == NULL || x->finished)
    return n;
  /* The next bytes of the file go straight out; any others wait for the ones
     before them.  */
  if (sl->buf == NULL && sl->roff + sl->got == x->next_out)
    write_out (x, p, n);
  else
    {
      if (sl->buf == NULL)
        {
          sl->buf = malloc (sl->ask);
          if (sl->buf == NULL)
            {
              smb_fail (x, TWIST_ERR_NOMEM);
              return n;
            }
          /* Bytes that went straight out before this are not kept.  */
          sl->roff += sl->got;
          sl->ask -= sl->got;
          sl->got = 0;
        }
      if (n <= sl->ask - sl->got)
        memcpy (sl->buf + sl->got, p, n);
    }
  sl->got += n;
  return n;
}

static int
on_error (void *u, uint32_t status, unsigned ctx, uint32_t n)
{
  struct twist_smb *x = u;
  int err = TWIST_ERR_PROTOCOL;

  (void) ctx;
  (void) n;
  if (x->finished)
    return TWIST_OK;
  if (x->phase == X_LIST
      && (status == STATUS_NO_MORE_FILES
          || (status == STATUS_NO_SUCH_FILE && x->first_query)))
    {
      x->list_end = 1;		/* The end of the directory, or an empty one.  */
      return TWIST_OK;
    }
  /* The NT statuses that say what happened to the file.  */
  switch (status)
    {
    case 0xC0000034u:		/* OBJECT_NAME_NOT_FOUND */
    case 0xC000003Au:		/* OBJECT_PATH_NOT_FOUND */
    case 0xC000000Fu:		/* NO_SUCH_FILE */
    case 0xC00000BAu:		/* FILE_IS_A_DIRECTORY */
      err = TWIST_ERR_FILE;
      break;
    case SMB_STATUS_ACCESS_DENIED:
    case 0xC0000043u:		/* SHARING_VIOLATION */
      err = TWIST_ERR_FILE;
      x->transfer->proto_status = 9;
      break;
    case SMB_STATUS_END_OF_FILE:
      err = TWIST_ERR_PARTIAL;
      break;
    default:
      break;
    }
  /* An upload that fails is exit 25, unless it was not allowed to (9).  */
  if (err == TWIST_ERR_FILE && x->transfer->proto_status == 0)
    x->transfer->proto_status = x->put ? 25 : 78;
  if (x->put && err == TWIST_ERR_PROTOCOL && x->phase >= X_OPEN)
    {
      err = TWIST_ERR_FILE;
      x->transfer->proto_status = 25;
    }
  {
    char msg[200];

    snprintf (msg, sizeof msg, _("%s: the server refused it (NT status "
                                 "0x%08x)"), x->path != NULL ? x->path : "",
              (unsigned) status);
    detail (x, msg);
  }
  smb_complete (x, err);
  return TWIST_OK;
}

static int
on_write (void *u, uint32_t count, uint32_t rem)
{
  struct twist_smb *x = u;

  (void) rem;
  if (x->phase != X_WRITE || x->cur_w < 0)
    return TWIST_ERR_PROTOCOL;
  if (count != x->wr[x->cur_w].len)
    {
      /* A server that writes less than it was sent is not followed.  */
      detail (x, _("the server wrote less than it was sent"));
      smb_complete (x, TWIST_ERR_PARTIAL);
      return TWIST_OK;
    }
  twist_progress_uploaded (x->transfer, count);
  return TWIST_OK;
}

static int
on_qdir (void *u, uint32_t len)
{
  struct twist_smb *x = u;

  (void) len;
  return x->phase == X_LIST ? TWIST_OK : TWIST_ERR_PROTOCOL;
}

static int
on_pending (void *u, uint64_t async_id)
{
  (void) u;
  (void) async_id;
  return TWIST_OK;
}

/* ---- Upload ---- */

static int
send_write (struct twist_smb *x)
{
  struct twist_smb_req h;
  uint8_t head[256];
  size_t n;
  int rc = twist_smb_session_request (x->sess, 1, &h);

  if (rc != TWIST_OK)
    return rc;			/* TWIST_ERR_AGAIN: no credit for it yet.  */
  rc = twist_smb_w_write (head, sizeof head, &n, &h, x->fid, (uint32_t) x->wlen,
                          x->put_off);
  if (rc != TWIST_OK)
    return rc;
  x->wr[x->nwr].id = h.message_id;
  x->wr[x->nwr].len = (uint32_t) x->wlen;
  x->nwr++;
  rc = twist_smb_session_send (x->sess, head, n, x->wbuf, x->wlen);
  x->put_off += x->wlen;
  x->wlen = 0;
  return rc;
}

static void pump_writes (struct twist_smb *x);

/* A chunk of the source, pushed.  It is gathered with the others into writes
   as big as the server takes; the source is paused while there is not room
   for another.  */
static int
up_chunk (void *user, const uint8_t *data, size_t len)
{
  struct twist_smb *x = user;

  if (len > x->wcap - x->wlen)
    return TWIST_ERR_ABORTED;
  memcpy (x->wbuf + x->wlen, data, len);
  x->wlen += len;
  if (x->wcap - x->wlen < 2 * PUSH_MAX)
    twist_upload_pause (x->up);
  pump_writes (x);
  return TWIST_OK;
}

static void
up_end (void *user, int err)
{
  struct twist_smb *x = user;

  if (err == TWIST_OK)
    x->src_eof = 1;
  else
    x->src_failed = err;
  pump_writes (x);
}

static const struct twist_upload_consumer up_ops = { up_chunk, up_end };

/* Send what is gathered, as the window, the credits and the connection allow;
   ask the source for more while there is room; and close the file once the
   source has ended and every write is answered.  A write is not made while
   another is in flight and it could hold more, unless the source has ended,
   so a source that gives a byte at a time makes writes of a good size.  */
static void
pump_writes (struct twist_smb *x)
{
  if (x->pumping)
    return;
  x->pumping = 1;
  while (x->phase == X_WRITE && !x->finished && !x->src_failed)
    {
      size_t before;
      int eof_before;

      if (x->wlen > 0 && x->nwr < WRITE_WINDOW && !conn_full (x)
          && (x->wcap - x->wlen < PUSH_MAX || x->src_eof || x->nwr == 0))
        {
          int rc = send_write (x);

          if (rc == TWIST_ERR_AGAIN)
            break;
          if (rc != TWIST_OK)
            {
              x->pumping = 0;
              smb_fail (x, rc);
              return;
            }
          continue;
        }
      if (!x->src_eof && x->wcap - x->wlen >= 2 * PUSH_MAX)
        {
          before = x->wlen;
          eof_before = x->src_eof;
          twist_upload_resume (x->up);
          if (x->wlen != before || x->src_eof != eof_before || x->src_failed)
            continue;
        }
      break;
    }
  x->pumping = 0;
  if (x->finished)
    return;
  if (x->src_failed)
    {
      smb_complete (x, x->src_failed);
      return;
    }
  if (x->phase == X_WRITE && x->src_eof && x->wlen == 0 && x->nwr == 0)
    begin_close (x);
}

/* The file is open for writing.  */
static void
opened_put (struct twist_smb *x)
{
  struct twist_transfer *t = x->transfer;
  const struct twist_smb_session_info *info = twist_smb_session_info (x->sess);
  long long total = twist_transfer_upload_size (t);

  if (total >= 0)
    twist_progress_ul_size (t, total);
  x->wcap = info->max_write;
  x->wbuf = malloc (x->wcap);
  if (x->wbuf == NULL)
    {
      smb_fail (x, TWIST_ERR_NOMEM);
      return;
    }
  if (t->postfields != NULL)
    {
      size_t n = t->postfieldsize_set && t->postfieldsize >= 0
        ? (size_t) t->postfieldsize : strlen (t->postfields);

      x->up = twist_upload_from_memory ((const uint8_t *) t->postfields, n);
      x->up_owned = 1;
    }
  else
    x->up = twist_transfer_upload (t);
  if (x->up == NULL || twist_upload_attach (x->up, &up_ops, x, PUSH_MAX) != TWIST_OK)
    {
      smb_fail (x, TWIST_ERR_NOMEM);
      return;
    }
  x->put_off = x->append ? x->size : 0;
  x->phase = X_WRITE;
  pump_writes (x);
}

/* A CREATE, for a file or a directory.  */
static int
send_create (struct twist_smb *x, const char *name, uint32_t access,
             uint32_t share, uint32_t disposition, uint32_t options,
             uint32_t attrs)
{
  struct twist_smb_req h;
  struct twist_smb_create_req r;
  uint8_t out[1024];
  size_t n;

  memset (&r, 0, sizeof r);
  r.desired_access = access;
  r.file_attributes = attrs;
  r.share_access = share;
  r.disposition = disposition;
  r.options = options;
  r.name = name;
  if (twist_smb_session_request (x->sess, 1, &h) != TWIST_OK
      || twist_smb_w_create (out, sizeof out, &n, &h, &r) != TWIST_OK
      || twist_smb_session_send (x->sess, out, n, NULL, 0) != TWIST_OK)
    return TWIST_ERR_PROTOCOL;
  return TWIST_OK;
}

static int
send_close_fid (struct twist_smb *x)
{
  struct twist_smb_req h;
  uint8_t out[256];
  size_t n;

  if (twist_smb_session_request (x->sess, 1, &h) != TWIST_OK
      || twist_smb_w_close (out, sizeof out, &n, &h, x->fid) != TWIST_OK
      || twist_smb_session_send (x->sess, out, n, NULL, 0) != TWIST_OK)
    return TWIST_ERR_PROTOCOL;
  return TWIST_OK;
}

/* The next directory above the file that has not been made, if --ftp-create-dirs
   asked for them: its path, or NULL.  */
static char *
next_dir (struct twist_smb *x)
{
  const char *sep;
  char *dir;
  size_t n;

  if (!x->make_dirs)
    return NULL;
  sep = strchr (x->path + x->dir_pos, '\\');
  if (sep == NULL)
    return NULL;
  n = (size_t) (sep - x->path);
  dir = malloc (n + 1);
  if (dir == NULL)
    return NULL;
  memcpy (dir, x->path, n);
  dir[n] = 0;
  x->dir_pos = n + 1;
  return dir;
}

/* The directories, then the file.  */
static void
open_next (struct twist_smb *x)
{
  char *dir = next_dir (x);
  int rc;

  if (dir != NULL)
    {
      x->phase = X_MKDIR;
      rc = send_create (x, dir, FILE_READ_ATTRIBUTES | SYNCHRONIZE,
                        FILE_SHARE_ALL, FILE_OPEN_IF, FILE_DIRECTORY_FILE,
                        FILE_ATTRIBUTE_DIRECTORY);
      free (dir);
    }
  else
    {
      x->phase = X_OPEN;
      if (x->list)
        rc = send_create (x, x->path, FILE_READ_DATA | FILE_READ_ATTRIBUTES
                          | SYNCHRONIZE, FILE_SHARE_ALL, FILE_OPEN,
                          FILE_DIRECTORY_FILE, 0);
      else if (x->put)
        rc = send_create (x, x->path,
                          FILE_WRITE_DATA | FILE_APPEND_DATA
                          | FILE_WRITE_ATTRIBUTES | FILE_READ_ATTRIBUTES
                          | SYNCHRONIZE, FILE_SHARE_READ,
                          x->append ? FILE_OPEN_IF : FILE_OVERWRITE_IF,
                          FILE_NON_DIRECTORY_FILE, 0x80);
      else
        rc = send_create (x, x->path,
                          FILE_READ_DATA | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
                          FILE_SHARE_ALL, FILE_OPEN, FILE_NON_DIRECTORY_FILE, 0);
    }
  if (rc != TWIST_OK)
    smb_fail (x, rc);
}

/* ---- Listing ---- */

static const char *const months[] = {
  "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct",
  "Nov", "Dec"
};

static uint32_t
le32 (const uint8_t *p)
{
  return (uint32_t) p[0] | ((uint32_t) p[1] << 8) | ((uint32_t) p[2] << 16)
    | ((uint32_t) p[3] << 24);
}

static uint64_t
le64 (const uint8_t *p)
{
  return (uint64_t) le32 (p) | ((uint64_t) le32 (p + 4) << 32);
}

/* A time as ls shows it: month, day and the time of day for the last six
   months, the year for anything older (or a little in the future).  */
static void
format_time (uint64_t filetime, char out[16])
{
  time_t t, now = test_now != 0 ? test_now : time (NULL);
  struct tm tm;
  uint64_t secs = filetime / 10000000u;

  /* FILETIME counts from 1601.  */
  t = secs >= 11644473600u ? (time_t) (secs - 11644473600u) : 0;
  if (gmtime_r (&t, &tm) == NULL)
    {
      snprintf (out, 16, "Jan  1  1970");
      return;
    }
  if (t > now - 15778476 && t < now + 3600)
    snprintf (out, 16, "%s %2d %02d:%02d", months[tm.tm_mon], tm.tm_mday,
              tm.tm_hour, tm.tm_min);
  else
    snprintf (out, 16, "%s %2d %5d", months[tm.tm_mon], tm.tm_mday,
              tm.tm_year + 1900);
}

/* One entry (FileIdBothDirectoryInformation), as a line.  */
static int
list_entry (void *u, const uint8_t *p, size_t n)
{
  struct twist_smb *x = u;
  uint8_t name16[TWIST_SMB_ENTRY_MAX];
  char name[3 * TWIST_SMB_ENTRY_MAX / 2 + 8];
  uint8_t line[3 * TWIST_SMB_ENTRY_MAX / 2 + 160];
  size_t namelen, nn, ln = 0;
  uint32_t attrs;
  int dir;

  if (x->finished)
    return TWIST_OK;
  if (x->phase != X_LIST || n < DIR_ENTRY_FIXED)
    return TWIST_ERR_PROTOCOL;
  namelen = le32 (p + 60);
  if (namelen > n - DIR_ENTRY_FIXED)
    return TWIST_ERR_PROTOCOL;
  x->entries++;
  memcpy (name16, p + DIR_ENTRY_FIXED, namelen);
  if (twist_utf8_from_utf16le (name16, namelen, name, sizeof name, &nn)
      != TWIST_OK)
    return TWIST_ERR_PROTOCOL;
  if (x->list_only)
    ln = twist_text_sanitize (line, (const uint8_t *) name, nn);
  else
    {
      char when[16], head[160];
      uint64_t size = le64 (p + 40);

      attrs = le32 (p + 56);
      dir = (attrs & FILE_ATTRIBUTE_DIRECTORY) != 0;
      format_time (le64 (p + 24), when);
      snprintf (head, sizeof head, "%c%s %3u %-8s %-8s %8llu %s ", dir ? 'd' : '-',
                (attrs & FILE_ATTRIBUTE_READONLY) != 0
                ? (dir ? "r-xr-xr-x" : "r--r--r--")
                : (dir ? "rwxr-xr-x" : "rw-r--r--"), 1u, "-", "-",
                (unsigned long long) size, when);
      ln = strlen (head);
      memcpy (line, head, ln);
      ln += twist_text_sanitize (line + ln, (const uint8_t *) name, nn);
    }
  line[ln++] = '\n';
  twist_deliver (x->transfer, line, ln);
  twist_transfer_downloaded (x->transfer, ln);
  return TWIST_OK;
}

static void
send_query (struct twist_smb *x)
{
  struct twist_smb_req h;
  uint8_t out[512];
  size_t n;

  x->entries = 0;
  if (twist_smb_session_request (x->sess, 1, &h) != TWIST_OK
      || twist_smb_w_query_directory (out, sizeof out, &n, &h, x->fid,
                                      INFO_FILE_ID_BOTH_DIR,
                                      x->first_query ? RESTART_SCANS : 0, "*",
                                      65536) != TWIST_OK
      || twist_smb_session_send (x->sess, out, n, NULL, 0) != TWIST_OK)
    smb_fail (x, TWIST_ERR_PROTOCOL);
}

static void
opened_list (struct twist_smb *x)
{
  x->phase = X_LIST;
  x->first_query = 1;
  send_query (x);
}

/* An answer is done: ask for the next, or close.  An answer with no entry in
   it is not progress, and is taken as the end.  */
static void
list_next (struct twist_smb *x)
{
  if (x->list_end || x->entries == 0)
    {
      begin_close (x);
      return;
    }
  x->first_query = 0;
  if (x->transfer->sink_paused)
    {
      x->list_wait = 1;
      return;
    }
  send_query (x);
}

/* The file is open: work out what to read.  */
static void
opened (struct twist_smb *x)
{
  struct twist_transfer *t = x->transfer;
  long long resume = t->resume_from;
  const struct twist_smb_session_info *info = twist_smb_session_info (x->sess);

  x->chunk = info->max_read;
  x->start = 0;
  x->end = x->size;
  if (resume > 0 && t->range != NULL)
    {
      detail (x, _("a resume and a range cannot be used together"));
      smb_complete (x, TWIST_ERR_INVAL);
      return;
    }
  if (resume > 0)
    {
      if ((uint64_t) resume > x->size)
        {
          detail (x, _("the file is shorter than the offset to resume at"));
          smb_complete (x, TWIST_ERR_RESUME);
          return;
        }
      x->start = (uint64_t) resume;
    }
  else if (t->range != NULL)
    {
      if (apply_range (x, t->range) != 0)
        {
          detail (x, _("the range is not FIRST-LAST, FIRST- or -COUNT"));
          smb_complete (x, TWIST_ERR_RANGE);
          return;
        }
      if (x->start > x->size || (x->start == x->size && x->size > 0))
        {
          detail (x, _("the range starts beyond the end of the file"));
          smb_complete (x, TWIST_ERR_RANGE);
          return;
        }
    }
  if (t->nobody)
    x->end = x->start;
  x->next_req = x->next_out = x->start;
  twist_progress_dl_size (t, (long long) (x->end - x->start));
  x->phase = X_READ;
  pump (x);
}

static int
on_empty (void *u, uint16_t cmd)
{
  (void) u;
  (void) cmd;
  return TWIST_OK;
}

static int
on_close (void *u, const struct twist_smb_close *r)
{
  struct twist_smb *x = u;

  (void) r;
  return x->phase == X_CLOSE || x->phase == X_MKCLOSE ? TWIST_OK
                                                       : TWIST_ERR_PROTOCOL;
}

static void
send_simple (struct twist_smb *x, int phase)
{
  struct twist_smb_req h;
  uint8_t out[256];
  size_t n;
  int rc = twist_smb_session_request (x->sess, 1, &h);

  if (rc == TWIST_OK)
    rc = phase == X_TREED ? twist_smb_w_tree_disconnect (out, sizeof out, &n, &h)
                          : twist_smb_w_logoff (out, sizeof out, &n, &h);
  if (rc == TWIST_OK)
    {
      x->phase = phase;
      rc = twist_smb_session_send (x->sess, out, n, NULL, 0);
    }
  if (rc != TWIST_OK)
    smb_complete (x, TWIST_OK);	/* The file is written; the rest is manners.  */
}

static int
on_end (void *u, uint64_t off)
{
  struct twist_smb *x = u;
  struct slot *sl = x->cur;

  (void) off;
  if (x->finished)
    return TWIST_OK;
  switch (x->phase)
    {
    case X_MKDIR:
      x->phase = X_MKCLOSE;
      if (send_close_fid (x) != TWIST_OK)
        smb_fail (x, TWIST_ERR_PROTOCOL);
      break;
    case X_MKCLOSE:
      x->have_file = 0;
      open_next (x);
      break;
    case X_OPEN:
      if (!x->have_file)
        {
          smb_fail (x, TWIST_ERR_PROTOCOL);
          return TWIST_OK;
        }
      if (x->list)
        opened_list (x);
      else if (x->put)
        opened_put (x);
      else
        opened (x);
      break;
    case X_LIST:
      list_next (x);
      break;
    case X_WRITE:
      if (x->cur_w >= 0)
        {
          x->wr[x->cur_w] = x->wr[x->nwr - 1];
          x->nwr--;
          x->cur_w = -1;
        }
      pump_writes (x);
      break;
    case X_READ:
      if (sl == NULL)
        break;
      x->cur = NULL;
      if (sl->got < sl->ask)
        {
          /* Less than was asked: the rest is asked for, by the same slot.
             An answer of nothing is an error, or it would never end.  */
          if (sl->got == x->cur_before)
            {
              smb_fail (x, TWIST_ERR_PROTOCOL);
              return TWIST_OK;
            }
          sl->sent = 0;
        }
      else
        sl->done = 1;
      drain (x);
      pump (x);
      break;
    case X_CLOSE:
      send_simple (x, X_TREED);
      break;
    case X_TREED:
      send_simple (x, X_LOGOFF);
      break;
    case X_LOGOFF:
      smb_complete (x, TWIST_OK);
      break;
    default:
      break;
    }
  return TWIST_OK;
}

/* ---- The session's side ---- */

static void
ops_established (void *u, uint32_t tree)
{
  struct twist_smb *x = u;

  (void) tree;
  twist_mail_link_phase_end (&x->link);
  open_next (x);
}

static void
ops_failure (void *u, int err)
{
  smb_fail (u, err);
}

/* ---- The connection's side ---- */

int
twist_smb_start (struct twist_smb *x)
{
  int rc;

  x->phase = X_LOGIN;
  rc = twist_smb_session_start (x->sess);
  if (rc != TWIST_OK)
    smb_fail (x, rc);
  return rc;
}

size_t
twist_smb_receive (struct twist_smb *x, const uint8_t *data, size_t len)
{
  if (x == NULL || x->sess == NULL)
    return 0;
  if (x->finished)
    return len;
  return twist_smb_session_receive (x->sess, data, len);
}

/* The connection has written what it held: an upload goes on.  */
void
twist_smb_drained (struct twist_smb *x)
{
  if (x != NULL && x->put && !x->finished)
    pump_writes (x);
}

static void
smb_write_ready (struct twist_endpoint *ep)
{
  twist_smb_drained (ep->user_data);
}

static void
smb_connected (struct twist_endpoint *ep)
{
  struct twist_smb *x = ep->user_data;

  x->ep = ep;
  ep->on_write_ready = smb_write_ready;
  twist_smb_start (x);
}

static size_t
smb_on_recv (struct twist_endpoint *ep, const uint8_t *data, size_t len)
{
  struct twist_smb *x = ep->user_data;

  x->ep = ep;
  return twist_smb_receive (x, data, len);
}

static void
smb_disconnected (struct twist_endpoint *ep, int error)
{
  struct twist_smb *x = ep->user_data;

  if (!x->finished)
    smb_fail (x, error != TWIST_OK ? error : TWIST_ERR_CLOSED);
}

static void
smb_error (struct twist_endpoint *ep, int error)
{
  struct twist_smb *x = ep->user_data;

  if (!x->finished && error != TWIST_OK && error != TWIST_ERR_CLOSED)
    smb_fail (x, error);
}

static void
smb_secure (struct twist_endpoint *ep, const char *alpn, size_t alpn_len)
{
  (void) ep;
  (void) alpn;
  (void) alpn_len;
}

static const struct twist_protocol_handler smb_handler = {
  smb_connected,
  smb_on_recv,
  smb_disconnected,
  smb_secure,
  smb_error,
  NULL,
  NULL
};

/* The application's callback is full: the connection stops reading, and what
   is on its way is held by the transfer.  */
static void
smb_pause_hook (struct twist_transfer *t)
{
  struct twist_smb *x = t->state;

  if (x != NULL && x->ep != NULL)
    twist_endpoint_pause_read (x->ep);
}

static void
smb_resume_hook (struct twist_transfer *t)
{
  struct twist_smb *x = t->state;

  if (x == NULL)
    return;
  if (x->ep != NULL)
    twist_endpoint_resume_read (x->ep);
  if (x->list_wait)
    {
      x->list_wait = 0;
      send_query (x);
      return;
    }
  pump (x);
}

void
twist_smb_test_seam (struct twist_smb *x,
                     int (*send) (void *user, const uint8_t *data, size_t len),
                     int (*full) (void *user), void *user)
{
  x->test_send = send;
  x->test_full = full;
  x->test_user = user;
}

void
twist_smb_free (void *p)
{
  struct twist_smb *x = p;
  unsigned i;

  if (x == NULL)
    return;
  for (i = 0; i < x->nslots; i++)
    free (x->slots[i].buf);
  if (x->up != NULL)
    {
      twist_upload_detach (x->up);
      if (x->up_owned)
        twist_upload_free (x->up);
    }
  free (x->wbuf);
  twist_smb_session_free (x->sess);
  twist_mail_link_close (&x->link);
  free (x->path);
  free (x);
}

struct twist_smb *
twist_smb_new (struct twist_transfer *transfer, int live)
{
  struct twist_smb *x;
  struct twist_smb_events up;
  struct twist_smb_session_ops ops;
  struct twist_smb_session_config cfg;
  const char *user, *pass, *sep;
  char *share = NULL, *domain = NULL, *login = NULL;
  int dir = 0, rc;

  (void) live;
  if (transfer == NULL || transfer->url == NULL || transfer->url->host == NULL)
    return NULL;
  x = calloc (1, sizeof *x);
  if (x == NULL)
    return NULL;
  x->transfer = transfer;
  transfer->state = x;
  transfer->state_free = twist_smb_free;
  transfer->pause_fn = smb_pause_hook;
  transfer->resume_fn = smb_resume_hook;
  rc = take_path (x, &share, &dir);
  if (rc != TWIST_OK)
    goto bad;
  x->put = twist_transfer_has_source (transfer) || transfer->postfields != NULL;
  x->cur_w = -1;
  if (dir && x->put)
    {
      detail (x, _("the path names a directory; give the name of the file to "
                   "upload to"));
      rc = TWIST_ERR_URL;
      goto bad;
    }
  x->list = dir || transfer->dirlistonly;
  if (x->list && x->put)
    {
      detail (x, _("a listing cannot be uploaded"));
      rc = TWIST_ERR_INVAL;
      goto bad;
    }
  if (x->list)
    {
      if (transfer->range != NULL || transfer->resume_from != 0)
        {
          detail (x, _("a range or a resume does not apply to a directory "
                       "listing"));
          rc = TWIST_ERR_INVAL;
          goto bad;
        }
      x->list_only = transfer->dirlistonly;
    }
  if (x->put)
    {
      if (transfer->range != NULL || transfer->resume_from != 0)
        {
          detail (x, _("a range or a resume does not apply to an upload"));
          rc = TWIST_ERR_INVAL;
          goto bad;
        }
      x->append = transfer->append;
      x->make_dirs = transfer->create_missing_dirs;
    }
  if (x->list)
    {
      /* The directory, without the slash that ended its name.  */
      size_t pl = strlen (x->path);

      while (pl > 0 && x->path[pl - 1] == '\\')
        x->path[--pl] = 0;
    }
  user = twist_mail_user (transfer);
  pass = twist_mail_pass (transfer);
  if (user == NULL)
    {
      detail (x, _("smb needs a user name"));
      rc = TWIST_ERR_AUTH;
      goto bad;
    }
  /* DOMAIN\user or DOMAIN/user.  */
  sep = strpbrk (user, "\\/");
  if (sep != NULL)
    {
      domain = malloc ((size_t) (sep - user) + 1);
      login = twist_strdup (sep + 1);
      if (domain != NULL)
        {
          memcpy (domain, user, (size_t) (sep - user));
          domain[sep - user] = 0;
        }
      if (domain == NULL || login == NULL)
        {
          rc = TWIST_ERR_NOMEM;
          goto bad;
        }
      user = login;
    }
  memset (&cfg, 0, sizeof cfg);
  cfg.domain = domain != NULL ? domain : "";
  cfg.user = user;
  cfg.password = pass;
  cfg.host = transfer->url->host;
  cfg.share = share;
  cfg.rnd = test_rnd;
  memset (&ops, 0, sizeof ops);
  ops.user = x;
  ops.send = smb_send;
  ops.established = ops_established;
  ops.failure = ops_failure;
  memset (&up, 0, sizeof up);
  up.user = x;
  up.header = on_header;
  up.create = on_create;
  up.close = on_close;
  up.read = on_read;
  up.write = on_write;
  up.query_directory = on_qdir;
  up.entry = list_entry;
  up.data = on_data;
  up.error = on_error;
  up.pending = on_pending;
  up.empty = on_empty;
  up.message_end = on_end;
  x->sess = twist_smb_session_new (&cfg, &ops, &up);
  if (x->sess == NULL)
    {
      rc = user[0] == 0 ? TWIST_ERR_AUTH : TWIST_ERR_NOMEM;
      goto bad;
    }
  free (share);
  free (domain);
  free (login);
  return x;
bad:
  free (share);
  free (domain);
  free (login);
  smb_complete (x, rc);
  return x;
}

int
twist_smb_attach (struct twist_transfer *transfer)
{
  struct twist_smb *x;
  int rc;

  x = twist_smb_new (transfer, 1);
  if (x == NULL)
    return TWIST_ERR_NOMEM;
  if (x->finished)
    return transfer->result;
  rc = twist_mail_link_open (&x->link, transfer, &smb_handler, x,
                             ops_failure);
  if (rc != TWIST_OK)
    smb_complete (x, rc);
  else
    twist_mail_link_phase_begin (&x->link);
  return transfer->done ? transfer->result : TWIST_OK;
}
