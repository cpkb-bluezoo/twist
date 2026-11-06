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

#include <string.h>

/* The requests an SMB2 client sends, each made into a caller's buffer as a
   whole frame.  The buffer is bounded and nothing is allocated; a WRITE's
   data is not copied in, the caller sends it after the frame.  */

struct wb
{
  uint8_t *b;
  size_t cap, n;
  int err;
};

static void
w8 (struct wb *w, unsigned v)
{
  if (w->err || w->n >= w->cap)
    {
      w->err = 1;
      return;
    }
  w->b[w->n++] = (uint8_t) v;
}

static void
w16 (struct wb *w, unsigned v)
{
  w8 (w, v);
  w8 (w, v >> 8);
}

static void
w32 (struct wb *w, uint32_t v)
{
  w16 (w, v & 0xffff);
  w16 (w, v >> 16);
}

static void
w64 (struct wb *w, uint64_t v)
{
  w32 (w, (uint32_t) v);
  w32 (w, (uint32_t) (v >> 32));
}

static void
wbytes (struct wb *w, const void *p, size_t n)
{
  if (w->err || n > w->cap - w->n)
    {
      w->err = 1;
      return;
    }
  if (n > 0)
    memcpy (w->b + w->n, p, n);
  w->n += n;
}

static void
wzero (struct wb *w, size_t n)
{
  if (w->err || n > w->cap - w->n)
    {
      w->err = 1;
      return;
    }
  memset (w->b + w->n, 0, n);
  w->n += n;
}

/* A string as UTF-16LE.  Returns its length in bytes.  */
static size_t
wstr (struct wb *w, const char *s)
{
  size_t n = 0;

  if (w->err)
    return 0;
  if (twist_utf16le_from_utf8 (s, strlen (s), 0, w->b + w->n, w->cap - w->n,
                               &n) != TWIST_OK)
    {
      w->err = 1;
      return 0;
    }
  w->n += n;
  return n;
}

/* Where in the message the next byte goes: offsets in a request count from
   the first byte of the header, after the four of the frame.  */
static size_t
mpos (const struct wb *w)
{
  return w->n - 4;
}

static void
begin (struct wb *w, uint8_t *out, size_t cap, uint16_t command,
       const struct twist_smb_req *h)
{
  w->b = out;
  w->cap = cap;
  w->n = 0;
  w->err = 0;
  wzero (w, 4);			/* The frame length, set at the end.  */
  wbytes (w, "\xfe" "SMB", 4);
  w16 (w, TWIST_SMB_HEADER);
  w16 (w, h->credit_charge);
  w32 (w, 0);			/* Channel sequence and reserved.  */
  w16 (w, command);
  w16 (w, h->credits);
  w32 (w, h->flags);
  w32 (w, 0);			/* No compound requests.  */
  w64 (w, h->message_id);
  w32 (w, 0);			/* Reserved, as these are not asynchronous.  */
  w32 (w, h->tree_id);
  w64 (w, h->session_id);
  wzero (w, 16);		/* The signature, which the session fills.  */
}

/* END is the data that follows the frame, which the length field counts.  */
static int
finish (struct wb *w, size_t extra, size_t *len)
{
  size_t total;

  if (w->err)
    return TWIST_ERR_INVAL;
  total = w->n - 4 + extra;
  if (total >= (size_t) 1 << 24)
    return TWIST_ERR_INVAL;
  w->b[0] = 0;
  w->b[1] = (uint8_t) (total >> 16);
  w->b[2] = (uint8_t) (total >> 8);
  w->b[3] = (uint8_t) total;
  *len = w->n;
  return TWIST_OK;
}

#define START(cmd) \
  struct wb w; \
  if (out == NULL || len == NULL || h == NULL) \
    return TWIST_ERR_INVAL; \
  begin (&w, out, cap, cmd, h)

static void
align8 (struct wb *w)
{
  wzero (w, (8 - mpos (w) % 8) % 8);
}

static void
context_head (struct wb *w, unsigned type, size_t dlen)
{
  w16 (w, type);
  w16 (w, (unsigned) dlen);
  w32 (w, 0);
}

int
twist_smb_w_negotiate (uint8_t *out, size_t cap, size_t *len,
                       const struct twist_smb_req *h,
                       const struct twist_smb_negotiate_req *r)
{
  unsigned i, nctx = 0;
  size_t ctx_off_at;

  START (TWIST_SMB_NEGOTIATE);
  if (r == NULL || r->n_dialects == 0 || r->n_dialects > 8 || r->n_hashes > 4
      || r->n_ciphers > 4 || r->n_signing > 4 || r->salt_len > sizeof r->salt)
    return TWIST_ERR_INVAL;
  nctx = (r->n_hashes > 0) + (r->n_ciphers > 0) + (r->n_signing > 0);
  w16 (&w, 36);
  w16 (&w, r->n_dialects);
  w16 (&w, r->security_mode);
  w16 (&w, 0);
  w32 (&w, r->capabilities);
  wbytes (&w, r->client_guid, 16);
  ctx_off_at = w.n;
  w32 (&w, 0);			/* The contexts' offset, set below.  */
  w16 (&w, nctx);
  w16 (&w, 0);
  for (i = 0; i < r->n_dialects; i++)
    w16 (&w, r->dialects[i]);
  if (nctx > 0 && !w.err)
    {
      size_t off;

      align8 (&w);
      off = mpos (&w);
      w.b[ctx_off_at] = (uint8_t) off;
      w.b[ctx_off_at + 1] = (uint8_t) (off >> 8);
      if (r->n_hashes > 0)
        {
          context_head (&w, TWIST_SMB_CTX_PREAUTH,
                        4 + 2 * (size_t) r->n_hashes + r->salt_len);
          w16 (&w, r->n_hashes);
          w16 (&w, r->salt_len);
          for (i = 0; i < r->n_hashes; i++)
            w16 (&w, r->hashes[i]);
          wbytes (&w, r->salt, r->salt_len);
          if (--nctx > 0)
            align8 (&w);
        }
      if (r->n_ciphers > 0)
        {
          context_head (&w, TWIST_SMB_CTX_ENCRYPTION,
                        2 + 2 * (size_t) r->n_ciphers);
          w16 (&w, r->n_ciphers);
          for (i = 0; i < r->n_ciphers; i++)
            w16 (&w, r->ciphers[i]);
          if (--nctx > 0)
            align8 (&w);
        }
      if (r->n_signing > 0)
        {
          context_head (&w, TWIST_SMB_CTX_SIGNING,
                        2 + 2 * (size_t) r->n_signing);
          w16 (&w, r->n_signing);
          for (i = 0; i < r->n_signing; i++)
            w16 (&w, r->signing[i]);
        }
    }
  return finish (&w, 0, len);
}

int
twist_smb_w_session_setup (uint8_t *out, size_t cap, size_t *len,
                           const struct twist_smb_req *h, uint8_t security_mode,
                           uint64_t previous_session, const uint8_t *blob,
                           size_t blob_len)
{
  START (TWIST_SMB_SESSION_SETUP);
  if ((blob == NULL && blob_len > 0) || blob_len > 0xffff)
    return TWIST_ERR_INVAL;
  w16 (&w, 25);
  w8 (&w, 0);			/* Flags: not binding.  */
  w8 (&w, security_mode);
  w32 (&w, 0);			/* Capabilities.  */
  w32 (&w, 0);			/* Channel.  */
  w16 (&w, TWIST_SMB_HEADER + 24);
  w16 (&w, (unsigned) blob_len);
  w64 (&w, previous_session);
  wbytes (&w, blob, blob_len);
  return finish (&w, 0, len);
}

static int
empty_body (uint8_t *out, size_t cap, size_t *len,
            const struct twist_smb_req *h, uint16_t command)
{
  START (command);
  w16 (&w, 4);
  w16 (&w, 0);
  return finish (&w, 0, len);
}

int
twist_smb_w_logoff (uint8_t *out, size_t cap, size_t *len,
                    const struct twist_smb_req *h)
{
  return empty_body (out, cap, len, h, TWIST_SMB_LOGOFF);
}

int
twist_smb_w_tree_disconnect (uint8_t *out, size_t cap, size_t *len,
                             const struct twist_smb_req *h)
{
  return empty_body (out, cap, len, h, TWIST_SMB_TREE_DISCONNECT);
}

int
twist_smb_w_tree_connect (uint8_t *out, size_t cap, size_t *len,
                          const struct twist_smb_req *h, const char *path)
{
  size_t at, n;

  START (TWIST_SMB_TREE_CONNECT);
  if (path == NULL || path[0] == 0)
    return TWIST_ERR_INVAL;
  w16 (&w, 9);
  w16 (&w, 0);
  w16 (&w, TWIST_SMB_HEADER + 8);
  at = w.n;
  w16 (&w, 0);
  n = wstr (&w, path);
  w.b[at] = (uint8_t) n;
  w.b[at + 1] = (uint8_t) (n >> 8);
  return n > 0xffff ? TWIST_ERR_INVAL : finish (&w, 0, len);
}

int
twist_smb_w_create (uint8_t *out, size_t cap, size_t *len,
                    const struct twist_smb_req *h,
                    const struct twist_smb_create_req *r)
{
  size_t at, n = 0;

  START (TWIST_SMB_CREATE);
  if (r == NULL)
    return TWIST_ERR_INVAL;
  w16 (&w, 57);
  w8 (&w, 0);			/* Security flags.  */
  w8 (&w, 0);			/* No oplock.  */
  w32 (&w, 2);			/* Impersonation.  */
  w64 (&w, 0);
  w64 (&w, 0);
  w32 (&w, r->desired_access);
  w32 (&w, r->file_attributes);
  w32 (&w, r->share_access);
  w32 (&w, r->disposition);
  w32 (&w, r->options);
  w16 (&w, TWIST_SMB_HEADER + 56);
  at = w.n;
  w16 (&w, 0);
  w32 (&w, 0);			/* No create contexts.  */
  w32 (&w, 0);
  if (r->name != NULL && r->name[0] != 0)
    n = wstr (&w, r->name);
  else
    w8 (&w, 0);			/* The buffer is one byte even when empty.  */
  w.b[at] = (uint8_t) n;
  w.b[at + 1] = (uint8_t) (n >> 8);
  return n > 0xffff ? TWIST_ERR_INVAL : finish (&w, 0, len);
}

int
twist_smb_w_close (uint8_t *out, size_t cap, size_t *len,
                   const struct twist_smb_req *h, const uint8_t file_id[16])
{
  START (TWIST_SMB_CLOSE);
  if (file_id == NULL)
    return TWIST_ERR_INVAL;
  w16 (&w, 24);
  w16 (&w, 0);
  w32 (&w, 0);
  wbytes (&w, file_id, 16);
  return finish (&w, 0, len);
}

int
twist_smb_w_read (uint8_t *out, size_t cap, size_t *len,
                  const struct twist_smb_req *h, const uint8_t file_id[16],
                  uint32_t length, uint64_t offset)
{
  START (TWIST_SMB_READ);
  if (file_id == NULL)
    return TWIST_ERR_INVAL;
  w16 (&w, 49);
  w8 (&w, TWIST_SMB_HEADER + 16);	/* Where the data should be.  */
  w8 (&w, 0);
  w32 (&w, length);
  w64 (&w, offset);
  wbytes (&w, file_id, 16);
  w32 (&w, 0);			/* Minimum count.  */
  w32 (&w, 0);			/* Channel.  */
  w32 (&w, 0);			/* Remaining bytes.  */
  w16 (&w, 0);
  w16 (&w, 0);
  w8 (&w, 0);			/* The buffer, which is one byte.  */
  return finish (&w, 0, len);
}

int
twist_smb_w_write (uint8_t *out, size_t cap, size_t *len,
                   const struct twist_smb_req *h, const uint8_t file_id[16],
                   uint32_t data_len, uint64_t offset)
{
  START (TWIST_SMB_WRITE);
  if (file_id == NULL)
    return TWIST_ERR_INVAL;
  w16 (&w, 49);
  w16 (&w, TWIST_SMB_HEADER + 48);
  w32 (&w, data_len);
  w64 (&w, offset);
  wbytes (&w, file_id, 16);
  w32 (&w, 0);			/* Channel.  */
  w32 (&w, 0);			/* Remaining bytes.  */
  w16 (&w, 0);
  w16 (&w, 0);
  w32 (&w, 0);			/* Flags.  */
  return finish (&w, data_len, len);
}

int
twist_smb_w_query_info (uint8_t *out, size_t cap, size_t *len,
                        const struct twist_smb_req *h,
                        const uint8_t file_id[16], uint8_t info_type,
                        uint8_t info_class, uint32_t output_len)
{
  START (TWIST_SMB_QUERY_INFO);
  if (file_id == NULL)
    return TWIST_ERR_INVAL;
  w16 (&w, 41);
  w8 (&w, info_type);
  w8 (&w, info_class);
  w32 (&w, output_len);
  w16 (&w, TWIST_SMB_HEADER + 40);
  w16 (&w, 0);
  w32 (&w, 0);			/* No input buffer.  */
  w32 (&w, 0);			/* Additional information.  */
  w32 (&w, 0);			/* Flags.  */
  wbytes (&w, file_id, 16);
  w8 (&w, 0);
  return finish (&w, 0, len);
}

int
twist_smb_w_query_directory (uint8_t *out, size_t cap, size_t *len,
                             const struct twist_smb_req *h,
                             const uint8_t file_id[16], uint8_t info_class,
                             uint8_t flags, const char *pattern,
                             uint32_t output_len)
{
  size_t at, n = 0;

  START (TWIST_SMB_QUERY_DIRECTORY);
  if (file_id == NULL)
    return TWIST_ERR_INVAL;
  w16 (&w, 33);
  w8 (&w, info_class);
  w8 (&w, flags);
  w32 (&w, 0);			/* File index.  */
  wbytes (&w, file_id, 16);
  w16 (&w, TWIST_SMB_HEADER + 32);
  at = w.n;
  w16 (&w, 0);
  w32 (&w, output_len);
  if (pattern != NULL && pattern[0] != 0)
    n = wstr (&w, pattern);
  else
    w8 (&w, 0);
  w.b[at] = (uint8_t) n;
  w.b[at + 1] = (uint8_t) (n >> 8);
  return n > 0xffff ? TWIST_ERR_INVAL : finish (&w, 0, len);
}
