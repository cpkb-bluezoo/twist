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
#define SLOTS 32u
#define SMB_STATUS_ACCESS_DENIED 0xC0000022u
#define SMB_STATUS_END_OF_FILE 0xC0000011u
#define FILE_READ_DATA 0x00000001u
#define FILE_READ_ATTRIBUTES 0x00000080u
#define SYNCHRONIZE 0x00100000u
#define FILE_SHARE_ALL 0x00000007u
#define FILE_OPEN 0x00000001u
#define FILE_NON_DIRECTORY_FILE 0x00000040u

enum
{
  X_NEW,
  X_LOGIN,			/* Until the tree is connected.  */
  X_OPEN,
  X_READ,
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
};

static const struct twist_ntlm_rand *test_rnd;

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
  if (x->phase >= X_CLOSE)
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

  if (x->phase != X_OPEN)
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
  if (err == TWIST_ERR_FILE && x->transfer->proto_status == 0)
    x->transfer->proto_status = 78;
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
on_pending (void *u, uint64_t async_id)
{
  (void) u;
  (void) async_id;
  return TWIST_OK;
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
  return x->phase == X_CLOSE ? TWIST_OK : TWIST_ERR_PROTOCOL;
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
    case X_OPEN:
      if (!x->have_file)
        {
          smb_fail (x, TWIST_ERR_PROTOCOL);
          return TWIST_OK;
        }
      opened (x);
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
  struct twist_smb_req h;
  struct twist_smb_create_req r;
  uint8_t out[1024];
  size_t n;

  (void) tree;
  twist_mail_link_phase_end (&x->link);
  x->phase = X_OPEN;
  memset (&r, 0, sizeof r);
  r.desired_access = FILE_READ_DATA | FILE_READ_ATTRIBUTES | SYNCHRONIZE;
  r.share_access = FILE_SHARE_ALL;
  r.disposition = FILE_OPEN;
  r.options = FILE_NON_DIRECTORY_FILE;
  r.name = x->path;
  if (twist_smb_session_request (x->sess, 1, &h) != TWIST_OK
      || twist_smb_w_create (out, sizeof out, &n, &h, &r) != TWIST_OK
      || twist_smb_session_send (x->sess, out, n, NULL, 0) != TWIST_OK)
    smb_fail (x, TWIST_ERR_PROTOCOL);
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

static void
smb_connected (struct twist_endpoint *ep)
{
  struct twist_smb *x = ep->user_data;

  x->ep = ep;
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
  pump (x);
}

void
twist_smb_test_seam (struct twist_smb *x,
                     int (*send) (void *user, const uint8_t *data, size_t len),
                     void *user)
{
  x->test_send = send;
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
  if (dir || transfer->dirlistonly)
    {
      detail (x, _("listing a directory over smb is not supported"));
      rc = TWIST_ERR_UNSUPPORTED;
      goto bad;
    }
  if (twist_transfer_has_source (transfer) || transfer->postfields != NULL)
    {
      detail (x, _("uploading over smb is not supported"));
      rc = TWIST_ERR_UNSUPPORTED;
      goto bad;
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
