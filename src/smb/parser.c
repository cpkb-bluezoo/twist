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

/* The SMB2 response parser; see twist-int.h for what it promises.

   A frame is the four-byte direct TCP header (a zero byte and a 24-bit
   length) and one message.  The message is the 64-byte header, a fixed body
   whose size depends on the command, and up to three regions that the fixed
   body points at.  Each region is taken in order: padding before it is
   skipped (at most PAD_MAX bytes), then its bytes are delivered, then the
   next region's.  What is left after the last is skipped if it is a few
   bytes of padding and is an error if it is more.  */

#define PAD_MAX 8
#define TAIL_MAX 8
#define DEFAULT_MAX_FRAME (128 * 1024)

enum
{
  ST_FRAME,			/* The four-byte frame header.  */
  ST_MSGHEAD,			/* The protocol id, then the rest of the header.  */
  ST_FIXED,			/* The fixed body.  */
  ST_SKIP,
  ST_DATA,
  ST_ENT,			/* A directory entry.  */
  ST_CTXH,			/* A negotiate context's header.  */
  ST_CTXD,			/* And its data.  */
  ST_DONE			/* A message with no framing is over.  */
};

enum
{
  AFTER_PAD,			/* Padding before a region.  */
  AFTER_CTXPAD,			/* Padding before a negotiate context.  */
  AFTER_REGION,			/* A region that is skipped.  */
  AFTER_END,			/* The tail of the message.  */
  AFTER_CIPHER			/* An encrypted message.  */
};

enum
{
  B_ERROR,
  B_PENDING,
  B_NEGOTIATE,
  B_SETUP,
  B_EMPTY,
  B_TREE,
  B_CREATE,
  B_CLOSE,
  B_READ,
  B_WRITE,
  B_QINFO,
  B_QDIR
};

enum
{
  R_SKIP,
  R_DATA,
  R_ENTRIES,
  R_CONTEXTS
};

struct region
{
  int kind;
  int data_kind;
  uint64_t off, len;
};

struct twist_smb_parser
{
  struct twist_smb_events ev;
  size_t max_frame;
  int framed;
  int st;
  int failed;
  uint8_t sc[TWIST_SMB_ENTRY_MAX];
  size_t need, have;
  uint64_t pos;			/* In the stream.  */
  size_t mlen, mpos;		/* The message, and where in it we are.  */
  int plain;
  struct twist_smb_header hdr;
  int body;
  struct region reg[3];
  int nreg, ri;
  uint64_t rem;			/* Left of the region, or of the skip.  */
  int data_kind;
  int after;
  size_t ent_len;
  unsigned ctx_left;
  size_t ctx_len;
};

static uint16_t
rd16 (const uint8_t *p)
{
  return (uint16_t) (p[0] | (p[1] << 8));
}

static uint32_t
rd32 (const uint8_t *p)
{
  return (uint32_t) rd16 (p) | ((uint32_t) rd16 (p + 2) << 16);
}

static uint64_t
rd64 (const uint8_t *p)
{
  return (uint64_t) rd32 (p) | ((uint64_t) rd32 (p + 4) << 32);
}

#define CALL(p, f, ...) \
  ((p)->ev.f != NULL ? (p)->ev.f ((p)->ev.user, __VA_ARGS__) : TWIST_OK)

struct twist_smb_parser *
twist_smb_parser_new (const struct twist_smb_events *ev)
{
  struct twist_smb_parser *p;

  if (ev == NULL)
    return NULL;
  p = calloc (1, sizeof *p);
  if (p == NULL)
    return NULL;
  p->ev = *ev;
  p->max_frame = DEFAULT_MAX_FRAME;
  p->framed = 1;
  p->st = ST_FRAME;
  p->need = 4;
  return p;
}

void
twist_smb_parser_free (struct twist_smb_parser *p)
{
  free (p);
}

void
twist_smb_parser_set_limit (struct twist_smb_parser *p, size_t max_frame)
{
  if (p != NULL)
    p->max_frame = max_frame;
}

static int
perr (void)
{
  return TWIST_ERR_PROTOCOL;
}

static int
gather (struct twist_smb_parser *p, const uint8_t *d, size_t n, size_t *used)
{
  size_t k = p->need - p->have;

  if (k > n)
    k = n;
  memcpy (p->sc + p->have, d, k);
  p->have += k;
  *used = k;
  return p->have == p->need;
}

static void
to_gather (struct twist_smb_parser *p, int st, size_t need)
{
  p->st = st;
  p->need = need;
  p->have = 0;
}

static int next_region (struct twist_smb_parser *p);

static int
end_message (struct twist_smb_parser *p)
{
  int rc = CALL (p, message_end, p->pos);

  if (p->framed)
    to_gather (p, ST_FRAME, 4);
  else
    p->st = ST_DONE;
  return rc;
}

static int
enter_skip (struct twist_smb_parser *p, uint64_t n, int after)
{
  p->st = ST_SKIP;
  p->rem = n;
  p->after = after;
  return TWIST_OK;
}

static int
region_done (struct twist_smb_parser *p)
{
  p->ri++;
  return next_region (p);
}

/* Whatever follows the last region is a few bytes of padding, or an error.  */
static int
tail (struct twist_smb_parser *p)
{
  size_t left = p->mlen - p->mpos;

  if (left > TAIL_MAX)
    return perr ();
  if (left == 0)
    return end_message (p);
  return enter_skip (p, left, AFTER_END);
}

static void
add_region (struct twist_smb_parser *p, int kind, int data_kind, uint64_t off,
            uint64_t len)
{
  if (len == 0)
    return;
  p->reg[p->nreg].kind = kind;
  p->reg[p->nreg].data_kind = data_kind;
  p->reg[p->nreg].off = off;
  p->reg[p->nreg].len = len;
  p->nreg++;
}

/* A negotiate context starts on an 8-byte boundary of the message.  */
static int
ctx_start (struct twist_smb_parser *p)
{
  to_gather (p, ST_CTXH, 8);
  return TWIST_OK;
}

static int
begin_ctx (struct twist_smb_parser *p)
{
  size_t pad;

  if (p->ctx_left == 0)
    return region_done (p);
  pad = (8 - p->mpos % 8) % 8;
  if (pad > p->mlen - p->mpos || 8 > p->mlen - p->mpos - pad)
    return perr ();
  if (pad == 0)
    return ctx_start (p);
  return enter_skip (p, pad, AFTER_CTXPAD);
}

static int
begin_region (struct twist_smb_parser *p)
{
  const struct region *r = &p->reg[p->ri];

  p->rem = r->len;
  switch (r->kind)
    {
    case R_SKIP:
      return enter_skip (p, r->len, AFTER_REGION);
    case R_DATA:
      p->data_kind = r->data_kind;
      p->st = ST_DATA;
      return TWIST_OK;
    case R_ENTRIES:
      if (p->rem < 4)
        return perr ();
      p->ent_len = 0;
      to_gather (p, ST_ENT, 4);
      return TWIST_OK;
    default:			/* R_CONTEXTS */
      return begin_ctx (p);
    }
}

/* The next region has to start at or after where the parser is, a few bytes
   on at most, and end inside the message.  */
static int
next_region (struct twist_smb_parser *p)
{
  const struct region *r;

  if (p->ri >= p->nreg)
    return tail (p);
  r = &p->reg[p->ri];
  if (r->off < p->mpos || r->off - p->mpos > PAD_MAX || r->off > p->mlen
      || r->len > p->mlen - r->off)
    return perr ();
  if (r->kind == R_CONTEXTS && r->off % 8 != 0)
    return perr ();
  if (r->off == p->mpos)
    return begin_region (p);
  return enter_skip (p, r->off - p->mpos, AFTER_PAD);
}

static int
skip_done (struct twist_smb_parser *p)
{
  switch (p->after)
    {
    case AFTER_PAD:
      return begin_region (p);
    case AFTER_CTXPAD:
      return ctx_start (p);
    case AFTER_REGION:
      return region_done (p);
    case AFTER_END:
      return end_message (p);
    default:			/* AFTER_CIPHER */
      to_gather (p, ST_FRAME, 4);
      return TWIST_OK;
    }
}

/* ---- Fixed bodies ---- */

/* The body of a response, from the command and the status.  The size is the
   fixed part (the structure size, less its one byte of buffer for those that
   have one) and SS the structure size the server has to give.  */
static int
body_for (uint16_t cmd, uint32_t status, size_t *fixed, unsigned *ss)
{
  int kind;

  if (status == TWIST_SMB_STATUS_PENDING)
    kind = B_PENDING;
  else if (status == TWIST_SMB_STATUS_SUCCESS
           || (cmd == TWIST_SMB_SESSION_SETUP
               && status == TWIST_SMB_STATUS_MORE_PROCESSING)
           || (status == TWIST_SMB_STATUS_BUFFER_OVERFLOW
               && (cmd == TWIST_SMB_READ || cmd == TWIST_SMB_QUERY_INFO)))
    switch (cmd)
      {
      case TWIST_SMB_NEGOTIATE:
        kind = B_NEGOTIATE;
        break;
      case TWIST_SMB_SESSION_SETUP:
        kind = B_SETUP;
        break;
      case TWIST_SMB_LOGOFF:
      case TWIST_SMB_TREE_DISCONNECT:
        kind = B_EMPTY;
        break;
      case TWIST_SMB_TREE_CONNECT:
        kind = B_TREE;
        break;
      case TWIST_SMB_CREATE:
        kind = B_CREATE;
        break;
      case TWIST_SMB_CLOSE:
        kind = B_CLOSE;
        break;
      case TWIST_SMB_READ:
        kind = B_READ;
        break;
      case TWIST_SMB_WRITE:
        kind = B_WRITE;
        break;
      case TWIST_SMB_QUERY_INFO:
        kind = B_QINFO;
        break;
      case TWIST_SMB_QUERY_DIRECTORY:
        kind = B_QDIR;
        break;
      default:
        return -1;
      }
  else
    kind = B_ERROR;
  switch (kind)
    {
    case B_NEGOTIATE:
      *fixed = 64, *ss = 65;
      break;
    case B_CREATE:
      *fixed = 88, *ss = 89;
      break;
    case B_CLOSE:
      *fixed = 60, *ss = 60;
      break;
    case B_TREE:
      *fixed = 16, *ss = 16;
      break;
    case B_EMPTY:
      *fixed = 4, *ss = 4;
      break;
    case B_READ:
    case B_WRITE:
      *fixed = 16, *ss = 17;
      break;
    default:			/* Setup, query, error, pending.  */
      *fixed = 8, *ss = 9;
      break;
    }
  return kind;
}

static int
on_header (struct twist_smb_parser *p)
{
  const uint8_t *b = p->sc;
  struct twist_smb_header *h = &p->hdr;
  size_t fixed;
  unsigned ss;
  int rc;

  if (rd16 (b + 4) != TWIST_SMB_HEADER)
    return perr ();
  memset (h, 0, sizeof *h);
  h->credit_charge = rd16 (b + 6);
  h->status = rd32 (b + 8);
  h->command = rd16 (b + 12);
  h->credits = rd16 (b + 14);
  h->flags = rd32 (b + 16);
  h->next_command = rd32 (b + 20);
  h->message_id = rd64 (b + 24);
  if ((h->flags & TWIST_SMB_FLAG_ASYNC) != 0)
    h->async_id = rd64 (b + 32);
  else
    h->tree_id = rd32 (b + 36);
  h->session_id = rd64 (b + 40);
  memcpy (h->signature, b + 48, 16);
  /* A response says it is one, and is the only message of its frame.  */
  if ((h->flags & TWIST_SMB_FLAG_SERVER_TO_REDIR) == 0 || h->next_command != 0)
    return perr ();
  p->body = body_for (h->command, h->status, &fixed, &ss);
  if (p->body < 0)
    return perr ();
  if (p->body == B_PENDING && (h->flags & TWIST_SMB_FLAG_ASYNC) == 0)
    return perr ();
  if (p->mlen - p->mpos < fixed)
    return perr ();
  rc = CALL (p, header, h);
  if (rc != TWIST_OK)
    return rc;
  to_gather (p, ST_FIXED, fixed);
  return TWIST_OK;
}

static int
on_transform (struct twist_smb_parser *p)
{
  const uint8_t *b = p->sc;
  struct twist_smb_transform t;
  int rc;

  if (!p->framed)
    return perr ();
  memset (&t, 0, sizeof t);
  memcpy (t.signature, b + 4, 16);
  memcpy (t.nonce, b + 20, 16);
  t.original_size = rd32 (b + 36);
  t.flags = rd16 (b + 42);
  t.session_id = rd64 (b + 44);
  /* The ciphertext is the rest of the frame and is as long as the message it
     holds; the flags say it is encrypted.  */
  if (t.flags != 1 || t.original_size < TWIST_SMB_HEADER
      || t.original_size != p->mlen - p->mpos)
    return perr ();
  t.ciphertext_offset = p->pos;
  t.ciphertext_len = t.original_size;
  rc = CALL (p, transform, &t);
  if (rc != TWIST_OK)
    return rc;
  return enter_skip (p, t.ciphertext_len, AFTER_CIPHER);
}

static int
on_msghead (struct twist_smb_parser *p)
{
  if (p->need == 4)
    {
      /* The protocol id says which header follows.  */
      if (memcmp (p->sc, "\xfe" "SMB", 4) == 0)
        {
          p->plain = 1;
          p->need = TWIST_SMB_HEADER;
        }
      else if (memcmp (p->sc, "\xfd" "SMB", 4) == 0)
        {
          p->plain = 0;
          p->need = TWIST_SMB_TRANSFORM_HEADER;
        }
      else
        return perr ();
      if (p->mlen < p->need)
        return perr ();
      return TWIST_OK;
    }
  return p->plain ? on_header (p) : on_transform (p);
}

static int
on_fixed (struct twist_smb_parser *p)
{
  const uint8_t *b = p->sc;
  const struct twist_smb_header *h = &p->hdr;
  size_t fixed;
  unsigned ss;
  int rc = TWIST_OK;

  body_for (h->command, h->status, &fixed, &ss);
  if (rd16 (b) != ss)
    return perr ();
  p->nreg = 0;
  p->ri = 0;
  switch (p->body)
    {
    case B_ERROR:
    case B_PENDING:
      {
        uint32_t count = rd32 (b + 4);

        if (p->body == B_PENDING)
          {
            rc = CALL (p, pending, h->async_id);
            add_region (p, R_SKIP, 0, TWIST_SMB_HEADER + 8, count);
          }
        else
          {
            rc = CALL (p, error, h->status, b[2], count);
            add_region (p, R_DATA, TWIST_SMB_DATA_ERROR, TWIST_SMB_HEADER + 8,
                        count);
          }
        break;
      }
    case B_NEGOTIATE:
      {
        struct twist_smb_negotiate r;
        uint16_t dialect = rd16 (b + 4);

        memset (&r, 0, sizeof r);
        r.security_mode = rd16 (b + 2);
        r.dialect = dialect;
        r.context_count = dialect == TWIST_SMB_DIALECT_311 ? rd16 (b + 6) : 0;
        memcpy (r.server_guid, b + 8, 16);
        r.capabilities = rd32 (b + 24);
        r.max_transact = rd32 (b + 28);
        r.max_read = rd32 (b + 32);
        r.max_write = rd32 (b + 36);
        r.system_time = rd64 (b + 40);
        r.server_start_time = rd64 (b + 48);
        rc = CALL (p, negotiate, &r);
        add_region (p, R_DATA, TWIST_SMB_DATA_SECURITY, rd16 (b + 56),
                    rd16 (b + 58));
        if (r.context_count > 0)
          {
            uint64_t off = rd32 (b + 60);

            if (off > p->mlen)
              return perr ();
            p->ctx_left = r.context_count;
            add_region (p, R_CONTEXTS, 0, off, p->mlen - off);
            if (p->nreg == 0 || p->reg[p->nreg - 1].kind != R_CONTEXTS)
              return perr ();
          }
        break;
      }
    case B_SETUP:
      rc = CALL (p, session_setup, rd16 (b + 2));
      add_region (p, R_DATA, TWIST_SMB_DATA_SECURITY, rd16 (b + 4),
                  rd16 (b + 6));
      break;
    case B_EMPTY:
      rc = CALL (p, empty, h->command);
      break;
    case B_TREE:
      {
        struct twist_smb_tree_connect r;

        r.share_type = b[2];
        r.share_flags = rd32 (b + 4);
        r.capabilities = rd32 (b + 8);
        r.maximal_access = rd32 (b + 12);
        rc = CALL (p, tree_connect, &r);
        break;
      }
    case B_CREATE:
      {
        struct twist_smb_create r;

        memset (&r, 0, sizeof r);
        r.oplock_level = b[2];
        r.flags = b[3];
        r.action = rd32 (b + 4);
        r.creation_time = rd64 (b + 8);
        r.last_access_time = rd64 (b + 16);
        r.last_write_time = rd64 (b + 24);
        r.change_time = rd64 (b + 32);
        r.allocation_size = rd64 (b + 40);
        r.end_of_file = rd64 (b + 48);
        r.attributes = rd32 (b + 56);
        memcpy (r.file_id, b + 64, 16);
        r.contexts_len = rd32 (b + 84);
        rc = CALL (p, create, &r);
        add_region (p, R_DATA, TWIST_SMB_DATA_CREATE_CONTEXTS, rd32 (b + 80),
                    r.contexts_len);
        break;
      }
    case B_CLOSE:
      {
        struct twist_smb_close r;

        memset (&r, 0, sizeof r);
        r.flags = rd16 (b + 2);
        r.creation_time = rd64 (b + 8);
        r.last_access_time = rd64 (b + 16);
        r.last_write_time = rd64 (b + 24);
        r.change_time = rd64 (b + 32);
        r.allocation_size = rd64 (b + 40);
        r.end_of_file = rd64 (b + 48);
        r.attributes = rd32 (b + 56);
        rc = CALL (p, close, &r);
        break;
      }
    case B_READ:
      rc = CALL (p, read, rd32 (b + 4), rd32 (b + 8));
      add_region (p, R_DATA, TWIST_SMB_DATA_READ, b[2], rd32 (b + 4));
      break;
    case B_WRITE:
      /* No channel information: there is no RDMA to use it with.  */
      if (rd16 (b + 14) != 0)
        return perr ();
      rc = CALL (p, write, rd32 (b + 4), rd32 (b + 8));
      break;
    case B_QINFO:
      rc = CALL (p, query_info, rd32 (b + 4));
      add_region (p, R_DATA, TWIST_SMB_DATA_INFO, rd16 (b + 2), rd32 (b + 4));
      break;
    default:			/* B_QDIR */
      rc = CALL (p, query_directory, rd32 (b + 4));
      add_region (p, R_ENTRIES, 0, rd16 (b + 2), rd32 (b + 4));
      break;
    }
  if (rc != TWIST_OK)
    return rc;
  return next_region (p);
}

static int
on_entry (struct twist_smb_parser *p)
{
  size_t elen;
  int rc;

  if (p->ent_len == 0)
    {
      /* The first four bytes say how far the next entry is, or that this one
         is the last and runs to the end of the region.  */
      uint32_t next = rd32 (p->sc);

      elen = next != 0 ? next : (p->rem > TWIST_SMB_ENTRY_MAX
                                 ? TWIST_SMB_ENTRY_MAX + 1 : (size_t) p->rem);
      if (next != 0 && (next % 8 != 0 || next < 8 || next > p->rem))
        return perr ();
      if (elen > TWIST_SMB_ENTRY_MAX || elen < 4)
        return perr ();
      p->ent_len = elen;
      if (elen > p->have)
        {
          p->need = elen;
          return TWIST_OK;
        }
    }
  elen = p->ent_len;
  rc = CALL (p, entry, p->sc, elen);
  if (rc != TWIST_OK)
    return rc;
  p->rem -= elen;
  p->ent_len = 0;
  if (p->rem == 0)
    return region_done (p);
  if (p->rem < 4)
    return perr ();
  to_gather (p, ST_ENT, 4);
  return TWIST_OK;
}

static int on_ctxd (struct twist_smb_parser *p);

static int
on_ctxh (struct twist_smb_parser *p)
{
  uint16_t dlen = rd16 (p->sc + 2);

  if (dlen > TWIST_SMB_CTX_MAX || dlen > p->mlen - p->mpos)
    return perr ();
  p->ctx_len = dlen;
  p->need = 8 + (size_t) dlen;
  p->st = ST_CTXD;
  if (dlen == 0)
    return on_ctxd (p);		/* Nothing more to wait for.  */
  return TWIST_OK;
}

static int
on_ctxd (struct twist_smb_parser *p)
{
  struct twist_smb_context c;
  const uint8_t *d = p->sc + 8;
  size_t n = p->ctx_len;
  unsigned i;
  int rc;

  memset (&c, 0, sizeof c);
  c.type = rd16 (p->sc);
  c.data = d;
  c.len = n;
  if (c.type == TWIST_SMB_CTX_PREAUTH)
    {
      unsigned cnt;
      size_t salt;

      if (n < 4)
        return perr ();
      cnt = rd16 (d);
      salt = rd16 (d + 2);
      if (cnt > 8 || 4 + 2 * (size_t) cnt + salt != n)
        return perr ();
      c.count = cnt;
      for (i = 0; i < cnt; i++)
        c.algs[i] = rd16 (d + 4 + 2 * i);
      c.salt = d + 4 + 2 * cnt;
      c.salt_len = salt;
    }
  else if (c.type == TWIST_SMB_CTX_ENCRYPTION || c.type == TWIST_SMB_CTX_SIGNING)
    {
      unsigned cnt;

      if (n < 2)
        return perr ();
      cnt = rd16 (d);
      if (cnt > 8 || 2 + 2 * (size_t) cnt != n)
        return perr ();
      c.count = cnt;
      for (i = 0; i < cnt; i++)
        c.algs[i] = rd16 (d + 2 + 2 * i);
    }
  rc = CALL (p, context, &c);
  if (rc != TWIST_OK)
    return rc;
  p->ctx_left--;
  return begin_ctx (p);
}

static int
on_frame (struct twist_smb_parser *p)
{
  size_t len;

  if (p->sc[0] != 0)
    return perr ();
  len = ((size_t) p->sc[1] << 16) | ((size_t) p->sc[2] << 8) | p->sc[3];
  if (len == 0 || len > p->max_frame)
    return perr ();
  p->mlen = len;
  p->mpos = 0;
  to_gather (p, ST_MSGHEAD, 4);
  return TWIST_OK;
}

static int
gathered (struct twist_smb_parser *p)
{
  int rc;

  switch (p->st)
    {
    case ST_FRAME:
      return on_frame (p);
    case ST_MSGHEAD:
      /* A plain message is announced once its header is in, so that the
         offset is the header's first byte.  */
      if (p->need > 4 && p->plain && p->have == p->need)
        {
          rc = CALL (p, message_begin, p->pos - p->need, p->mlen);
          if (rc != TWIST_OK)
            return rc;
        }
      return on_msghead (p);
    case ST_FIXED:
      return on_fixed (p);
    case ST_ENT:
      return on_entry (p);
    case ST_CTXH:
      return on_ctxh (p);
    default:			/* ST_CTXD */
      return on_ctxd (p);
    }
}

static size_t
receive (struct twist_smb_parser *p, const uint8_t *data, size_t len)
{
  size_t off = 0;
  int rc = TWIST_OK, stop = 0;

  if (p->failed)
    return len;
  while (off < len && rc == TWIST_OK && p->st != ST_DONE)
    {
      size_t avail = len - off, used = 0;
      int inmsg = p->st != ST_FRAME;

      switch (p->st)
        {
        case ST_SKIP:
          used = p->rem < avail ? (size_t) p->rem : avail;
          p->rem -= used;
          break;
        case ST_DATA:
          {
            size_t n = p->rem < avail ? (size_t) p->rem : avail;

            if (p->ev.data != NULL)
              used = p->ev.data (p->ev.user, (enum twist_smb_data) p->data_kind,
                                 data + off, n);
            else
              used = n;
            if (used > n)
              used = n;
            stop = used < n;
            p->rem -= used;
            break;
          }
        default:
          if (gather (p, data + off, avail, &used))
            {
              /* Count the bytes before the handler looks at the state.  */
              off += used;
              p->pos += used;
              if (inmsg)
                p->mpos += used;
              rc = gathered (p);
              continue;
            }
          break;
        }
      off += used;
      p->pos += used;
      if (inmsg)
        p->mpos += used;
      if (rc != TWIST_OK)
        break;
      if (p->st == ST_SKIP && p->rem == 0)
        rc = skip_done (p);
      else if (p->st == ST_DATA && p->rem == 0)
        rc = region_done (p);
      if (rc == TWIST_OK && stop)
        break;			/* The consumer asked to wait.  */
    }
  if (rc != TWIST_OK)
    {
      p->failed = 1;
      if (p->ev.failure != NULL)
        p->ev.failure (p->ev.user, rc);
      return len;
    }
  return off;
}

size_t
twist_smb_parser_receive (struct twist_smb_parser *p, const uint8_t *data,
                          size_t len)
{
  if (p == NULL)
    return 0;
  return receive (p, data, len);
}

int
twist_smb_parser_message (struct twist_smb_parser *p, const uint8_t *msg,
                          size_t len)
{
  size_t took;

  if (p == NULL || (msg == NULL && len > 0) || p->failed)
    return TWIST_ERR_INVAL;
  if (p->st != ST_FRAME || p->have != 0)
    return TWIST_ERR_INVAL;
  if (len < 4 || len > p->max_frame)
    {
      p->failed = 1;
      if (p->ev.failure != NULL)
        p->ev.failure (p->ev.user, TWIST_ERR_PROTOCOL);
      return TWIST_ERR_PROTOCOL;
    }
  p->framed = 0;
  p->mlen = len;
  p->mpos = 0;
  to_gather (p, ST_MSGHEAD, 4);
  took = receive (p, msg, len);
  p->framed = 1;
  if (p->failed)
    return TWIST_ERR_PROTOCOL;
  if (took != len || p->st != ST_DONE)
    {
      /* A message cut short, or a consumer that stopped it.  */
      p->failed = 1;
      if (p->ev.failure != NULL)
        p->ev.failure (p->ev.user, TWIST_ERR_PROTOCOL);
      return TWIST_ERR_PROTOCOL;
    }
  to_gather (p, ST_FRAME, 4);
  return TWIST_OK;
}
