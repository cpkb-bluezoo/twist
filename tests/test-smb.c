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

#include "check.h"
#include "twist-int.h"

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* The SMB2 parser and writer.  Responses are built here byte by byte, from
   the layouts of MS-SMB2, fed to the parser whole and in pieces of one and
   three bytes, and the events are compared as text.  */

struct msg
{
  uint8_t b[8192];
  size_t n;
};

static void
p8 (struct msg *m, unsigned v)
{
  m->b[m->n++] = (uint8_t) v;
}

static void
p16 (struct msg *m, unsigned v)
{
  p8 (m, v);
  p8 (m, v >> 8);
}

static void
p32 (struct msg *m, uint32_t v)
{
  p16 (m, v & 0xffff);
  p16 (m, v >> 16);
}

static void
p64 (struct msg *m, uint64_t v)
{
  p32 (m, (uint32_t) v);
  p32 (m, (uint32_t) (v >> 32));
}

static void
pz (struct msg *m, size_t n)
{
  while (n-- > 0)
    p8 (m, 0);
}

static void
pb (struct msg *m, const void *d, size_t n)
{
  memcpy (m->b + m->n, d, n);
  m->n += n;
}

/* A frame under construction: four bytes for the length, then the message.  */
static void
frame_start (struct msg *m)
{
  m->n = 4;
}

static void
frame_end (struct msg *m)
{
  size_t len = m->n - 4;

  m->b[0] = 0;
  m->b[1] = (uint8_t) (len >> 16);
  m->b[2] = (uint8_t) (len >> 8);
  m->b[3] = (uint8_t) len;
}

#define SERVER 0x1u
#define ASYNC 0x2u

/* The header of a response; msg is the message id, and TREE the tree id (or the
   async id if the flags say so).  */
static void
header (struct msg *m, unsigned cmd, uint32_t status, uint32_t flags,
        uint64_t msgid, uint64_t tree_or_async)
{
  frame_start (m);
  pb (m, "\xfe" "SMB", 4);
  p16 (m, 64);
  p16 (m, 1);			/* Credit charge.  */
  p32 (m, status);
  p16 (m, cmd);
  p16 (m, 31);			/* Credits granted.  */
  p32 (m, flags);
  p32 (m, 0);			/* Next command.  */
  p64 (m, msgid);
  if ((flags & ASYNC) != 0)
    p64 (m, tree_or_async);
  else
    {
      p32 (m, 0);
      p32 (m, (uint32_t) tree_or_async);
    }
  p64 (m, 0x1122334455667788ull);	/* Session.  */
  pb (m, "SIGNATURE-SIGN-16", 16);
}

/* ---- The events as text ---- */

struct log
{
  char t[4096];
  size_t take;			/* Most the data callback takes, or 0 for all.  */
  int fails, err;
  uint8_t data[4096];
  size_t data_n;
  int entries;
  int last_kind;
};

#define ADD(g, ...) \
  do \
    { \
      size_t n_ = strlen ((g)->t); \
      snprintf ((g)->t + n_, sizeof (g)->t - n_, __VA_ARGS__); \
    } \
  while (0)

static int
e_begin (void *u, uint64_t off, size_t len)
{
  ADD ((struct log *) u, "begin(%" PRIu64 ",%zu) ", off, len);
  return TWIST_OK;
}

static int
e_header (void *u, const struct twist_smb_header *h)
{
  ((struct log *) u)->last_kind = 0;
  ADD ((struct log *) u, "hdr(cmd=%u st=%08x fl=%x id=%" PRIu64 " cr=%u/%u sess=%"
       PRIx64 " tree=%u async=%" PRIu64 " sig=%.4s) ", h->command, h->status,
       h->flags, h->message_id, h->credit_charge, h->credits, h->session_id,
       h->tree_id, h->async_id, (const char *) h->signature);
  return TWIST_OK;
}

static int
e_transform (void *u, const struct twist_smb_transform *t)
{
  ADD ((struct log *) u, "transform(sess=%" PRIx64 " orig=%u flags=%u at=%"
       PRIu64 " len=%zu n0=%02x) ", t->session_id, t->original_size, t->flags,
       t->ciphertext_offset, t->ciphertext_len, t->nonce[0]);
  return TWIST_OK;
}

static int
e_negotiate (void *u, const struct twist_smb_negotiate *r)
{
  ADD ((struct log *) u, "negotiate(mode=%u dialect=%x ctx=%u guid0=%02x caps=%x "
       "tx=%u rd=%u wr=%u) ", r->security_mode, r->dialect, r->context_count,
       r->server_guid[0], r->capabilities, r->max_transact, r->max_read,
       r->max_write);
  return TWIST_OK;
}

static int
e_context (void *u, const struct twist_smb_context *c)
{
  struct log *g = u;
  unsigned i;

  ADD (g, "ctx(%u len=%zu", c->type, c->len);
  for (i = 0; i < c->count; i++)
    ADD (g, " %u", c->algs[i]);
  if (c->salt != NULL)
    ADD (g, " salt=%zu:%02x", c->salt_len, c->salt_len > 0 ? c->salt[0] : 0);
  ADD (g, ") ");
  return TWIST_OK;
}

static int
e_setup (void *u, uint16_t f)
{
  ADD ((struct log *) u, "setup(flags=%u) ", f);
  return TWIST_OK;
}

static int
e_tree (void *u, const struct twist_smb_tree_connect *r)
{
  ADD ((struct log *) u, "tree(type=%u flags=%x caps=%x access=%x) ",
       r->share_type, r->share_flags, r->capabilities, r->maximal_access);
  return TWIST_OK;
}

static int
e_create (void *u, const struct twist_smb_create *r)
{
  ADD ((struct log *) u, "create(oplock=%u action=%u eof=%" PRIu64 " alloc=%"
       PRIu64 " attr=%x id=%02x..%02x ctx=%u) ", r->oplock_level, r->action,
       r->end_of_file, r->allocation_size, r->attributes, r->file_id[0],
       r->file_id[15], r->contexts_len);
  return TWIST_OK;
}

static int
e_close (void *u, const struct twist_smb_close *r)
{
  ADD ((struct log *) u, "close(flags=%u eof=%" PRIu64 " attr=%x) ", r->flags,
       r->end_of_file, r->attributes);
  return TWIST_OK;
}

static int
e_read (void *u, uint32_t len, uint32_t rem)
{
  ADD ((struct log *) u, "read(%u,%u) ", len, rem);
  return TWIST_OK;
}

static int
e_write (void *u, uint32_t count, uint32_t rem)
{
  ADD ((struct log *) u, "write(%u,%u) ", count, rem);
  return TWIST_OK;
}

static int
e_qinfo (void *u, uint32_t n)
{
  ADD ((struct log *) u, "qinfo(%u) ", n);
  return TWIST_OK;
}

static int
e_qdir (void *u, uint32_t n)
{
  ADD ((struct log *) u, "qdir(%u) ", n);
  return TWIST_OK;
}

static int
e_empty (void *u, uint16_t cmd)
{
  ADD ((struct log *) u, "empty(%u) ", cmd);
  return TWIST_OK;
}

static int
e_error (void *u, uint32_t st, unsigned ctx, uint32_t n)
{
  ADD ((struct log *) u, "error(%08x ctx=%u bytes=%u) ", st, ctx, n);
  return TWIST_OK;
}

static int
e_pending (void *u, uint64_t async)
{
  ADD ((struct log *) u, "pending(%" PRIu64 ") ", async);
  return TWIST_OK;
}

static size_t
e_data (void *u, enum twist_smb_data kind, const uint8_t *p, size_t n)
{
  struct log *g = u;

  if (g->take != 0 && n > g->take)
    n = g->take;
  if (g->data_n + n <= sizeof g->data)
    memcpy (g->data + g->data_n, p, n);
  g->data_n += n;
  /* Slices are not logged one by one, as the cut depends on the pieces the
     bytes arrive in; their kind and their total are.  */
  if ((int) kind != g->last_kind)
    ADD (g, "d%d ", (int) kind);
  g->last_kind = (int) kind;
  return n;
}

static int
e_entry (void *u, const uint8_t *p, size_t n)
{
  struct log *g = u;

  g->entries++;
  ADD (g, "entry(%zu:%c) ", n, p[4]);
  return TWIST_OK;
}

static int
e_end (void *u, uint64_t off)
{
  ADD ((struct log *) u, "end(%" PRIu64 ") ", off);
  return TWIST_OK;
}

static void
e_fail (void *u, int err)
{
  struct log *g = u;

  g->fails++;
  g->err = err;
}

static struct twist_smb_events
events (struct log *g)
{
  struct twist_smb_events ev;

  memset (&ev, 0, sizeof ev);
  ev.user = g;
  ev.message_begin = e_begin;
  ev.header = e_header;
  ev.transform = e_transform;
  ev.negotiate = e_negotiate;
  ev.context = e_context;
  ev.session_setup = e_setup;
  ev.tree_connect = e_tree;
  ev.create = e_create;
  ev.close = e_close;
  ev.read = e_read;
  ev.write = e_write;
  ev.query_info = e_qinfo;
  ev.query_directory = e_qdir;
  ev.empty = e_empty;
  ev.error = e_error;
  ev.pending = e_pending;
  ev.data = e_data;
  ev.entry = e_entry;
  ev.message_end = e_end;
  ev.failure = e_fail;
  return ev;
}

/* Feed a stream in pieces; a short return leaves a tail that is offered
   again.  Returns what was consumed.  */
static size_t
feed (struct twist_smb_parser *p, const uint8_t *d, size_t n, size_t piece)
{
  size_t off = 0, stuck = 0;

  while (off < n)
    {
      size_t c = n - off < piece ? n - off : piece;
      size_t used = twist_smb_parser_receive (p, d + off, c);

      off += used;
      if (used == 0)
        {
          if (++stuck > 3)
            break;
        }
      else
        stuck = 0;
    }
  return off;
}

/* The same stream in three ways must give the same events.  */
static void
same_in_pieces (const char *what, const struct msg *m, const char *want)
{
  static const size_t pieces[] = { 0, 1, 3 };
  size_t i;
  char label[160];

  for (i = 0; i < 3; i++)
    {
      struct log *g = calloc (1, sizeof *g);
      struct twist_smb_events ev = events (g);
      struct twist_smb_parser *p = twist_smb_parser_new (&ev);
      size_t piece = pieces[i] == 0 ? m->n : pieces[i];
      size_t used = feed (p, m->b, m->n, piece);

      snprintf (label, sizeof label, "smb: %s (%s)", what,
                pieces[i] == 0 ? "whole" : pieces[i] == 1 ? "1-byte pieces"
                : "3-byte pieces");
      check (used == m->n && g->fails == 0 && strcmp (g->t, want) == 0, label);
      if (used != m->n || g->fails != 0 || strcmp (g->t, want) != 0)
        fprintf (stderr, "  got:  %s\n  want: %s\n  used %zu of %zu fails %d\n",
                 g->t, want, used, m->n, g->fails);
      twist_smb_parser_free (p);
      free (g);
    }
}

/* ---- Responses ---- */

#define HDR_TAIL "cr=1/31 sess=1122334455667788"

static void
fixed_pad (struct msg *m, size_t upto)
{
  while (m->n < upto)
    p8 (m, 0);
}

static void
build_negotiate (struct msg *m)
{
  size_t i;

  header (m, 0, 0, SERVER, 0, 0);
  p16 (m, 65);
  p16 (m, 3);			/* Security mode.  */
  p16 (m, 0x311);
  p16 (m, 3);			/* Contexts.  */
  for (i = 0; i < 16; i++)
    p8 (m, 0xa0 + i);
  p32 (m, 0x2f);
  p32 (m, 65536);
  p32 (m, 65536);
  p32 (m, 65536);
  p64 (m, 1);
  p64 (m, 2);
  p16 (m, 128);			/* Security buffer.  */
  p16 (m, 4);
  p32 (m, 136);			/* Contexts, after padding.  */
  pb (m, "ABCD", 4);
  pz (m, 4);
  p16 (m, 1);			/* Pre-authentication integrity.  */
  p16 (m, 38);
  p32 (m, 0);
  p16 (m, 1);
  p16 (m, 32);
  p16 (m, 1);
  for (i = 0; i < 32; i++)
    p8 (m, 0x5a);
  pz (m, 2);
  p16 (m, 2);			/* Encryption.  */
  p16 (m, 4);
  p32 (m, 0);
  p16 (m, 1);
  p16 (m, 2);
  pz (m, 4);
  p16 (m, 8);			/* Signing.  */
  p16 (m, 4);
  p32 (m, 0);
  p16 (m, 1);
  p16 (m, 1);
  frame_end (m);
}

static void
build_setup (struct msg *m)
{
  header (m, 1, 0xC0000016u, SERVER, 1, 0);
  p16 (m, 9);
  p16 (m, 0);
  p16 (m, 72);
  p16 (m, 5);
  pb (m, "TOKEN", 5);
  frame_end (m);
}

static void
build_tree (struct msg *m)
{
  header (m, 3, 0, SERVER, 2, 5);
  p16 (m, 16);
  p8 (m, 1);
  p8 (m, 0);
  p32 (m, 0x800);
  p32 (m, 8);
  p32 (m, 0x1f01ff);
  frame_end (m);
}

/* PAD bytes follow the body; CTX bytes of create contexts at offset 152.  */
static void
build_create (struct msg *m, size_t pad, size_t ctx)
{
  size_t i;

  header (m, 5, 0, SERVER, 3, 5);
  p16 (m, 89);
  p8 (m, 0);
  p8 (m, 0);
  p32 (m, 1);
  p64 (m, 11);
  p64 (m, 12);
  p64 (m, 13);
  p64 (m, 14);
  p64 (m, 4096);
  p64 (m, 1234);
  p32 (m, 0x20);
  p32 (m, 0);
  for (i = 0; i < 16; i++)
    p8 (m, 0x10 + i);
  p32 (m, ctx > 0 ? 152 : 0);
  p32 (m, (uint32_t) ctx);
  fixed_pad (m, 4 + 152 + ctx + pad);
  frame_end (m);
}

static void
build_close (struct msg *m)
{
  header (m, 6, 0, SERVER, 4, 5);
  p16 (m, 60);
  p16 (m, 1);
  p32 (m, 0);
  p64 (m, 1);
  p64 (m, 2);
  p64 (m, 3);
  p64 (m, 4);
  p64 (m, 4096);
  p64 (m, 1234);
  p32 (m, 0x20);
  frame_end (m);
}

static void
build_read (struct msg *m, unsigned dlen, unsigned offset, size_t pad)
{
  unsigned i;

  header (m, 8, 0, SERVER, 5, 5);
  p16 (m, 17);
  p8 (m, offset);
  p8 (m, 0);
  p32 (m, dlen);
  p32 (m, 0);
  p32 (m, 0);
  pz (m, pad);
  for (i = 0; i < dlen; i++)
    p8 (m, i);
  frame_end (m);
}

static void
build_write (struct msg *m)
{
  header (m, 9, 0, SERVER, 6, 5);
  p16 (m, 17);
  p16 (m, 0);
  p32 (m, 65536);
  p32 (m, 0);
  p16 (m, 0);
  p16 (m, 0);
  frame_end (m);
}

static void
build_qinfo (struct msg *m)
{
  unsigned i;

  header (m, 16, 0, SERVER, 7, 5);
  p16 (m, 9);
  p16 (m, 72);
  p32 (m, 40);
  for (i = 0; i < 40; i++)
    p8 (m, i);
  frame_end (m);
}

/* Entries A, B and C of 24, 32 and 16 bytes; NEXT gives A's offset.  */
static void
build_qdir (struct msg *m, uint32_t next_a, uint32_t out_len)
{
  header (m, 14, 0, SERVER, 8, 5);
  p16 (m, 9);
  p16 (m, 72);
  p32 (m, out_len);
  p32 (m, next_a);
  p8 (m, 'A');
  pz (m, 19);
  p32 (m, 32);
  p8 (m, 'B');
  pz (m, 27);
  p32 (m, 0);
  p8 (m, 'C');
  pz (m, 11);
  frame_end (m);
}

static void
build_empty (struct msg *m, unsigned cmd)
{
  header (m, cmd, 0, SERVER, 9, 5);
  p16 (m, 4);
  p16 (m, 0);
  frame_end (m);
}

static void
build_error (struct msg *m, unsigned cmd, uint32_t status, uint32_t flags,
             uint64_t tree_or_async, size_t data)
{
  size_t i;

  header (m, cmd, status, flags | SERVER, 10, tree_or_async);
  p16 (m, 9);
  p8 (m, 0);
  p8 (m, 0);
  p32 (m, (uint32_t) data);
  for (i = 0; i < (data > 0 ? data : 1); i++)
    p8 (m, 0xee);
  frame_end (m);
}

static void
build_transform (struct msg *m, size_t orig, unsigned flags, size_t actual)
{
  size_t i;

  frame_start (m);
  pb (m, "\xfd" "SMB", 4);
  pb (m, "TAGTAGTAGTAGTAG!", 16);
  p8 (m, 0x77);
  pz (m, 15);
  p32 (m, (uint32_t) orig);
  p16 (m, 0);
  p16 (m, flags);
  p64 (m, 0x1122334455667788ull);
  for (i = 0; i < actual; i++)
    p8 (m, (unsigned) i);
  frame_end (m);
}

static void
append (struct msg *a, const struct msg *b)
{
  memcpy (a->b + a->n, b->b, b->n);
  a->n += b->n;
}

static void
test_responses (void)
{
  struct msg m, m2, m3;

  build_negotiate (&m);
  same_in_pieces ("a NEGOTIATE response with three contexts", &m,
    "begin(4,212) hdr(cmd=0 st=00000000 fl=1 id=0 " HDR_TAIL " tree=0 async=0 sig=SIGN) "
    "negotiate(mode=3 dialect=311 ctx=3 guid0=a0 caps=2f tx=65536 rd=65536 wr=65536) "
    "d1 ctx(1 len=38 1 salt=32:5a) ctx(2 len=4 2) ctx(8 len=4 1) end(216) ");
  build_setup (&m);
  same_in_pieces ("a SESSION_SETUP response, more processing required", &m,
    "begin(4,77) hdr(cmd=1 st=c0000016 fl=1 id=1 " HDR_TAIL " tree=0 async=0 sig=SIGN) "
    "setup(flags=0) d1 end(81) ");
  build_tree (&m);
  same_in_pieces ("a TREE_CONNECT response", &m,
    "begin(4,80) hdr(cmd=3 st=00000000 fl=1 id=2 " HDR_TAIL " tree=5 async=0 sig=SIGN) "
    "tree(type=1 flags=800 caps=8 access=1f01ff) end(84) ");
  build_create (&m, 0, 0);
  same_in_pieces ("a CREATE response", &m,
    "begin(4,152) hdr(cmd=5 st=00000000 fl=1 id=3 " HDR_TAIL " tree=5 async=0 sig=SIGN) "
    "create(oplock=0 action=1 eof=1234 alloc=4096 attr=20 id=10..1f ctx=0) end(156) ");
  build_create (&m, 1, 0);
  same_in_pieces ("a CREATE response with its one byte of buffer", &m,
    "begin(4,153) hdr(cmd=5 st=00000000 fl=1 id=3 " HDR_TAIL " tree=5 async=0 sig=SIGN) "
    "create(oplock=0 action=1 eof=1234 alloc=4096 attr=20 id=10..1f ctx=0) end(157) ");
  build_create (&m, 0, 16);
  same_in_pieces ("a CREATE response with create contexts", &m,
    "begin(4,168) hdr(cmd=5 st=00000000 fl=1 id=3 " HDR_TAIL " tree=5 async=0 sig=SIGN) "
    "create(oplock=0 action=1 eof=1234 alloc=4096 attr=20 id=10..1f ctx=16) d4 end(172) ");
  build_close (&m);
  same_in_pieces ("a CLOSE response", &m,
    "begin(4,124) hdr(cmd=6 st=00000000 fl=1 id=4 " HDR_TAIL " tree=5 async=0 sig=SIGN) "
    "close(flags=1 eof=1234 attr=20) end(128) ");
  build_read (&m, 100, 0x50, 0);
  same_in_pieces ("a READ response", &m,
    "begin(4,180) hdr(cmd=8 st=00000000 fl=1 id=5 " HDR_TAIL " tree=5 async=0 sig=SIGN) "
    "read(100,0) d2 end(184) ");
  build_read (&m, 0, 0x50, 0);
  same_in_pieces ("a READ response with no data", &m,
    "begin(4,80) hdr(cmd=8 st=00000000 fl=1 id=5 " HDR_TAIL " tree=5 async=0 sig=SIGN) "
    "read(0,0) end(84) ");
  build_read (&m, 100, 0x54, 4);
  same_in_pieces ("a READ response with padding before the data", &m,
    "begin(4,184) hdr(cmd=8 st=00000000 fl=1 id=5 " HDR_TAIL " tree=5 async=0 sig=SIGN) "
    "read(100,0) d2 end(188) ");
  build_write (&m);
  same_in_pieces ("a WRITE response", &m,
    "begin(4,80) hdr(cmd=9 st=00000000 fl=1 id=6 " HDR_TAIL " tree=5 async=0 sig=SIGN) "
    "write(65536,0) end(84) ");
  build_qinfo (&m);
  same_in_pieces ("a QUERY_INFO response", &m,
    "begin(4,112) hdr(cmd=16 st=00000000 fl=1 id=7 " HDR_TAIL " tree=5 async=0 sig=SIGN) "
    "qinfo(40) d3 end(116) ");
  build_qdir (&m, 24, 72);
  same_in_pieces ("a QUERY_DIRECTORY response of three entries", &m,
    "begin(4,144) hdr(cmd=14 st=00000000 fl=1 id=8 " HDR_TAIL " tree=5 async=0 sig=SIGN) "
    "qdir(72) entry(24:A) entry(32:B) entry(16:C) end(148) ");
  build_empty (&m, 2);
  same_in_pieces ("a LOGOFF response", &m,
    "begin(4,68) hdr(cmd=2 st=00000000 fl=1 id=9 " HDR_TAIL " tree=5 async=0 sig=SIGN) "
    "empty(2) end(72) ");
  build_empty (&m, 4);
  same_in_pieces ("a TREE_DISCONNECT response", &m,
    "begin(4,68) hdr(cmd=4 st=00000000 fl=1 id=9 " HDR_TAIL " tree=5 async=0 sig=SIGN) "
    "empty(4) end(72) ");
  build_error (&m, 14, TWIST_SMB_STATUS_NO_MORE_FILES, 0, 5, 0);
  same_in_pieces ("an error response with no data", &m,
    "begin(4,73) hdr(cmd=14 st=80000006 fl=1 id=10 " HDR_TAIL " tree=5 async=0 sig=SIGN) "
    "error(80000006 ctx=0 bytes=0) end(77) ");
  build_error (&m, 5, 0xC0000034u, 0, 5, 8);
  same_in_pieces ("an error response with data", &m,
    "begin(4,80) hdr(cmd=5 st=c0000034 fl=1 id=10 " HDR_TAIL " tree=5 async=0 sig=SIGN) "
    "error(c0000034 ctx=0 bytes=8) d5 end(84) ");
  build_error (&m, 8, TWIST_SMB_STATUS_PENDING, ASYNC, 77, 0);
  same_in_pieces ("an interim response is an event and not a result", &m,
    "begin(4,73) hdr(cmd=8 st=00000103 fl=3 id=10 " HDR_TAIL " tree=0 async=77 sig=SIGN) "
    "pending(77) end(77) ");

  /* Messages in a row, and an encrypted one between them.  */
  build_tree (&m);
  build_transform (&m2, 100, 1, 100);
  build_write (&m3);
  append (&m, &m2);
  append (&m, &m3);
  same_in_pieces ("messages in a row, with an encrypted one between", &m,
    "begin(4,80) hdr(cmd=3 st=00000000 fl=1 id=2 " HDR_TAIL " tree=5 async=0 sig=SIGN) "
    "tree(type=1 flags=800 caps=8 access=1f01ff) end(84) "
    "transform(sess=1122334455667788 orig=100 flags=1 at=140 len=100 n0=77) "
    "begin(244,80) hdr(cmd=9 st=00000000 fl=1 id=6 " HDR_TAIL " tree=5 async=0 sig=SIGN) "
    "write(65536,0) end(324) ");
}

/* A consumer that takes a few bytes at a time gets all of them, in order.  */
static void
test_backpressure (void)
{
  struct msg m;
  struct log *g = calloc (1, sizeof *g);
  struct twist_smb_events ev = events (g);
  struct twist_smb_parser *p = twist_smb_parser_new (&ev);
  size_t i, used;
  int ok = 1;

  build_read (&m, 100, 0x50, 0);
  g->take = 7;
  used = feed (p, m.b, m.n, m.n);
  check (used == m.n && g->data_n == 100, "smb: a consumer taking 7 bytes at a time gets all 100");
  for (i = 0; i < 100; i++)
    if (g->data[i] != i)
      ok = 0;
  check (ok, "smb: and in order");
  check (strstr (g->t, "end(184)") != NULL && g->fails == 0,
         "smb: and the message ends once, afterwards");
  twist_smb_parser_free (p);
  free (g);
}

static void
test_message_mode (void)
{
  struct msg m;
  struct log *g = calloc (1, sizeof *g);
  struct twist_smb_events ev = events (g);
  struct twist_smb_parser *p = twist_smb_parser_new (&ev);

  build_tree (&m);
  check (twist_smb_parser_message (p, m.b + 4, m.n - 4) == TWIST_OK,
         "smb: a message with no framing is taken");
  check (strcmp (g->t, "begin(0,80) hdr(cmd=3 st=00000000 fl=1 id=2 " HDR_TAIL
                 " tree=5 async=0 sig=SIGN) tree(type=1 flags=800 caps=8 "
                 "access=1f01ff) end(80) ") == 0,
         "smb: with the same events and offsets from its own start");
  check (twist_smb_parser_message (p, m.b + 4, m.n - 4) == TWIST_OK
         && twist_smb_parser_message (p, m.b + 4, m.n - 10) == TWIST_ERR_PROTOCOL
         && g->fails == 1, "smb: one cut short is refused");
  twist_smb_parser_free (p);
  free (g);
}

/* A response that is wrong is refused, once, and nothing after it is read.  */
static void
refused (const char *what, const uint8_t *d, size_t n, size_t limit)
{
  static const size_t pieces[] = { 0, 1 };
  size_t i;
  char label[160];

  for (i = 0; i < 2; i++)
    {
      struct log *g = calloc (1, sizeof *g);
      struct twist_smb_events ev = events (g);
      struct twist_smb_parser *p = twist_smb_parser_new (&ev);
      struct msg after;

      if (limit > 0)
        twist_smb_parser_set_limit (p, limit);
      feed (p, d, n, pieces[i] == 0 ? n : 1);
      snprintf (label, sizeof label, "smb: %s (%s)", what,
                i == 0 ? "whole" : "1-byte pieces");
      check (g->fails == 1 && g->err == TWIST_ERR_PROTOCOL, label);
      if (g->fails != 1)
        fprintf (stderr, "  log: %s\n", g->t);
      build_tree (&after);
      g->t[0] = 0;
      check (twist_smb_parser_receive (p, after.b, after.n) == after.n
             && g->t[0] == 0 && g->fails == 1,
             "smb: and nothing after a refusal is read");
      twist_smb_parser_free (p);
      free (g);
    }
}

static void
test_refusals (void)
{
  struct msg m;
  uint8_t zero4[4] = { 0, 0, 0, 0 };

  build_tree (&m);
  m.b[0] = 1;
  refused ("a frame that does not start with a zero byte", m.b, m.n, 0);
  refused ("a frame of no length", zero4, 4, 0);
  build_read (&m, 100, 0x50, 0);
  refused ("a frame over the limit", m.b, m.n, 100);
  build_tree (&m);
  m.b[4] = 0xfc;
  refused ("a compressed message", m.b, m.n, 0);
  build_tree (&m);
  m.b[4 + 24 - 4] = 0;
  m.b[4 + 20] = 1;
  refused ("a compound response", m.b, m.n, 0);
  build_tree (&m);
  m.b[4 + 16] = 0;
  refused ("a message that is not from the server", m.b, m.n, 0);
  build_tree (&m);
  m.b[4 + 4] = 63;
  refused ("a header of the wrong size", m.b, m.n, 0);
  build_tree (&m);
  m.b[4 + 64] = 17;
  refused ("a body of the wrong structure size", m.b, m.n, 0);
  build_tree (&m);
  m.b[4 + 12] = 13;
  refused ("a command that is not one of ours", m.b, m.n, 0);
  build_read (&m, 100, 0x40, 0);
  refused ("data whose offset goes back into the header", m.b, m.n, 0);
  build_read (&m, 100, 0x50, 0);
  m.b[4 + 64 + 4] = 200;
  refused ("data that runs past the message", m.b, m.n, 0);
  build_read (&m, 100, 0x64, 20);
  refused ("data after more padding than alignment needs", m.b, m.n, 0);
  build_negotiate (&m);
  m.b[4 + 64 + 60] = 128;
  refused ("negotiate contexts that overlap the security buffer", m.b, m.n, 0);
  build_negotiate (&m);
  m.b[4 + 64 + 6] = 4;
  refused ("more negotiate contexts than the message has", m.b, m.n, 0);
  build_negotiate (&m);
  m.b[4 + 136 + 2] = 0x58;
  m.b[4 + 136 + 3] = 0x02;
  refused ("a negotiate context longer than the limit", m.b, m.n, 0);
  build_negotiate (&m);
  m.b[4 + 136 + 8] = 9;
  refused ("a pre-authentication context whose counts do not add up", m.b, m.n, 0);
  build_qdir (&m, 20, 72);
  refused ("a directory entry whose next offset is not aligned", m.b, m.n, 0);
  build_qdir (&m, 400, 72);
  refused ("a directory entry whose next offset leaves the buffer", m.b, m.n, 0);
  build_qdir (&m, 4, 72);
  refused ("a directory entry whose next offset is too small", m.b, m.n, 0);
  build_qdir (&m, 24, 72);
  m.b[4 + 64 + 2] = 60;
  refused ("a directory buffer that starts inside the fixed body", m.b, m.n, 0);
  build_tree (&m);
  pz (&m, 20);
  frame_end (&m);
  refused ("bytes after the last field of a message", m.b, m.n, 0);
  build_error (&m, 8, TWIST_SMB_STATUS_PENDING, 0, 5, 0);
  refused ("an interim response that is not asynchronous", m.b, m.n, 0);
  build_create (&m, 0, 0);
  m.b[0] = 0;
  m.b[1] = 0;
  m.b[2] = 0;
  m.b[3] = 70;
  refused ("a message shorter than its fixed body", m.b, 4 + 70, 0);
  build_transform (&m, 99, 1, 100);
  refused ("a transform whose size is not its ciphertext", m.b, m.n, 0);
  build_transform (&m, 100, 0, 100);
  refused ("a transform that does not say it is encrypted", m.b, m.n, 0);
  build_write (&m);
  m.b[4 + 64 + 14] = 1;
  refused ("a WRITE response with channel information", m.b, m.n, 0);
}

/* ---- The writer ---- */

static const char ref_neg[] =
    "000000b6fe534d42400001000000000000004000000000000000000007000000"
    "0000000000000000050000008877665544332211000000000000000000000000"
    "00000000240001000300000040000000303132333435363738393a3b3c3d3e3f"
    "6800000003000000110300000100260000000000010020000100000102030405"
    "060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f000002000600"
    "0000000002000400020000000800060000000000020002000100";
static const char ref_setup[] =
    "00000062fe534d42400001000000000001004000000000000000000007000000"
    "0000000000000000050000008877665544332211000000000000000000000000"
    "0000000019000001000000000000000058000a000000000000000000544f4b45"
    "4e2d424c4f42";
static const char ref_tree[] =
    "0000005efe534d42400001000000000003004000000000000000000007000000"
    "0000000000000000050000008877665544332211000000000000000000000000"
    "0000000009000000480016005c005c007300720076005c007300680061007200"
    "6500";
static const char ref_create[] =
    "00000088fe534d42400001000000000005004000000000000000000007000000"
    "0000000000000000050000008877665544332211000000000000000000000000"
    "0000000039000000020000000000000000000000000000000000000080000000"
    "0000000001000000010000006000000078001000000000000000000064006900"
    "72005c00660069006c006500";
static const char ref_create_empty[] =
    "00000079fe534d42400001000000000005004000000000000000000007000000"
    "0000000000000000050000008877665544332211000000000000000000000000"
    "0000000039000000020000000000000000000000000000000000000080000000"
    "0000000001000000010000006000000078000000000000000000000000";
static const char ref_close[] =
    "00000058fe534d42400001000000000006004000000000000000000007000000"
    "0000000000000000050000008877665544332211000000000000000000000000"
    "000000001800000000000000101112131415161718191a1b1c1d1e1f";
static const char ref_read[] =
    "00000071fe534d42400001000000000008004000000000000000000007000000"
    "0000000000000000050000008877665544332211000000000000000000000000"
    "0000000031005000000001000000000001000000101112131415161718191a1b"
    "1c1d1e1f0000000000000000000000000000000000";
static const char ref_write[] =
    "000013f8fe534d42400001000000000009004000000000000000000007000000"
    "0000000000000000050000008877665544332211000000000000000000000000"
    "0000000031007000881300000700000000000000101112131415161718191a1b"
    "1c1d1e1f00000000000000000000000000000000";
static const char ref_qinfo[] =
    "00000069fe534d42400001000000000010004000000000000000000007000000"
    "0000000000000000050000008877665544332211000000000000000000000000"
    "0000000029000105280000006800000000000000000000000000000010111213"
    "1415161718191a1b1c1d1e1f00";
static const char ref_qdir[] =
    "00000062fe534d4240000100000000000e004000000000000000000007000000"
    "0000000000000000050000008877665544332211000000000000000000000000"
    "000000002100250000000000101112131415161718191a1b1c1d1e1f60000200"
    "000001002a00";
static const char ref_logoff[] =
    "00000044fe534d42400001000000000002004000000000000000000007000000"
    "0000000000000000050000008877665544332211000000000000000000000000"
    "0000000004000000";
static const char ref_treed[] =
    "00000044fe534d42400001000000000004004000000000000000000007000000"
    "0000000000000000050000008877665544332211000000000000000000000000"
    "0000000004000000";

static size_t
unhex (const char *h, uint8_t *out)
{
  size_t n = strlen (h) / 2, i;

  for (i = 0; i < n; i++)
    {
      unsigned v;

      sscanf (h + 2 * i, "%2x", &v);
      out[i] = (uint8_t) v;
    }
  return n;
}

static void
same_frame (const char *what, const uint8_t *got, size_t n, const char *hex)
{
  uint8_t w[8192];
  size_t wn = unhex (hex, w);

  check (wn == n && memcmp (got, w, n) == 0, what);
  if (wn != n || memcmp (got, w, n) != 0)
    fprintf (stderr, "  %s: %zu bytes, wanted %zu\n", what, n, wn);
}

static void
test_writer (void)
{
  uint8_t out[8192], fid[16];
  size_t n, i;
  struct twist_smb_req h;
  struct twist_smb_negotiate_req nr;
  struct twist_smb_create_req cr;

  memset (&h, 0, sizeof h);
  h.credit_charge = 1;
  h.credits = 64;
  h.message_id = 7;
  h.session_id = 0x1122334455667788ull;
  h.tree_id = 5;
  for (i = 0; i < 16; i++)
    fid[i] = (uint8_t) (0x10 + i);

  memset (&nr, 0, sizeof nr);
  nr.security_mode = 3;
  nr.capabilities = 0x40;
  for (i = 0; i < 16; i++)
    nr.client_guid[i] = (uint8_t) (0x30 + i);
  nr.n_dialects = 1;
  nr.dialects[0] = TWIST_SMB_DIALECT_311;
  nr.n_hashes = 1;
  nr.hashes[0] = TWIST_SMB_HASH_SHA512;
  nr.salt_len = 32;
  for (i = 0; i < 32; i++)
    nr.salt[i] = (uint8_t) i;
  nr.n_ciphers = 2;
  nr.ciphers[0] = TWIST_SMB_CIPHER_AES256_GCM;
  nr.ciphers[1] = TWIST_SMB_CIPHER_AES128_GCM;
  nr.n_signing = 2;
  nr.signing[0] = TWIST_SMB_SIGN_AES_GMAC;
  nr.signing[1] = TWIST_SMB_SIGN_AES_CMAC;
  check (twist_smb_w_negotiate (out, sizeof out, &n, &h, &nr) == TWIST_OK, "smb: NEGOTIATE made");
  same_frame ("smb: NEGOTIATE request, with the three contexts aligned", out, n, ref_neg);
  check (twist_smb_w_negotiate (out, 100, &n, &h, &nr) == TWIST_ERR_INVAL,
         "smb: a buffer too small for NEGOTIATE is refused");
  nr.n_hashes = 0;
  nr.n_ciphers = 0;
  nr.n_signing = 0;
  check (twist_smb_w_negotiate (out, sizeof out, &n, &h, &nr) == TWIST_OK
         && n == 4 + 64 + 36 + 2 && out[64 + 4 + 28] == 0,
         "smb: NEGOTIATE with no contexts has none");

  check (twist_smb_w_session_setup (out, sizeof out, &n, &h, 1, 0,
                                    (const uint8_t *) "TOKEN-BLOB", 10) == TWIST_OK,
         "smb: SESSION_SETUP made");
  same_frame ("smb: SESSION_SETUP request", out, n, ref_setup);
  twist_smb_w_tree_connect (out, sizeof out, &n, &h, "\\\\srv\\share");
  same_frame ("smb: TREE_CONNECT request", out, n, ref_tree);
  memset (&cr, 0, sizeof cr);
  cr.desired_access = 0x80;
  cr.share_access = 1;
  cr.disposition = 1;
  cr.options = 0x60;
  cr.name = "dir\\file";
  twist_smb_w_create (out, sizeof out, &n, &h, &cr);
  same_frame ("smb: CREATE request", out, n, ref_create);
  cr.name = "";
  twist_smb_w_create (out, sizeof out, &n, &h, &cr);
  same_frame ("smb: CREATE request with no name has its byte of buffer", out, n,
              ref_create_empty);
  twist_smb_w_close (out, sizeof out, &n, &h, fid);
  same_frame ("smb: CLOSE request", out, n, ref_close);
  twist_smb_w_read (out, sizeof out, &n, &h, fid, 65536, 0x100000000ull);
  same_frame ("smb: READ request", out, n, ref_read);
  twist_smb_w_write (out, sizeof out, &n, &h, fid, 5000, 7);
  same_frame ("smb: WRITE request, whose length counts the data that follows",
              out, n, ref_write);
  check (n == 4 + 64 + 48, "smb: and holds the header and fixed body only");
  twist_smb_w_query_info (out, sizeof out, &n, &h, fid, 1, 5, 40);
  same_frame ("smb: QUERY_INFO request", out, n, ref_qinfo);
  twist_smb_w_query_directory (out, sizeof out, &n, &h, fid, 0x25, 0, "*", 65536);
  same_frame ("smb: QUERY_DIRECTORY request", out, n, ref_qdir);
  twist_smb_w_logoff (out, sizeof out, &n, &h);
  same_frame ("smb: LOGOFF request", out, n, ref_logoff);
  twist_smb_w_tree_disconnect (out, sizeof out, &n, &h);
  same_frame ("smb: TREE_DISCONNECT request", out, n, ref_treed);
  check (twist_smb_w_close (out, 20, &n, &h, fid) == TWIST_ERR_INVAL,
         "smb: a buffer too small for CLOSE is refused");
  check (twist_smb_w_tree_connect (out, sizeof out, &n, &h, "") == TWIST_ERR_INVAL,
         "smb: no share path is refused");
  check (twist_smb_w_tree_connect (out, sizeof out, &n, &h, "\\\\s\\\xff") == TWIST_ERR_INVAL,
         "smb: a path that is not UTF-8 is refused");
}

int
main (void)
{
  test_responses ();
  test_backpressure ();
  test_message_mode ();
  test_refusals ();
  test_writer ();
  return tests_finish ();
}
