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
#include "ssh/ssh-int.h"

#include <foxtrot/chan.h>
#include <foxtrot/sftp.h>
#include <foxtrot/status.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* One file over SFTP, down or up.  scp:// is this too.

   The session is logged in.  Open a session channel, ask for the "sftp"
   subsystem, bind an SFTP client to the channel, and then:

   Download.  Open the file and read it until the end.  Reads are
   pipelined: up to SFTP_WINDOW are outstanding, each for a chunk of the
   file, and the answers are written out in order of offset however they
   arrive.  A server may answer a read with less than was asked; the rest is
   asked for again at once.  End of file is a status, and counts only when
   every byte before it has been written.  A download may start part way (a
   resume, or the start of a range) and may stop part way (the end of a
   range); the size of the file is asked for only when that is needed to
   check a resume or to find the start of a range counted from the end.

   Upload.  Open the file for writing and send the data in chunks, up to
   SFTP_WINDOW outstanding, then close it.  A resume skips the data that is
   already there, on both sides: the first bytes of the source are not sent
   and the writes go on at that offset of the file, which is not truncated.
   The offset is given, or found by asking the server how big the file is.  */

#define SFTP_CHUNK 32768u
#define SFTP_WINDOW 16u

/* Tags of requests that are not reads.  A read's tag is its slot.  A write's
   is TAG_WRITE plus its length.  A transfer is a download or an upload, never
   both, so these cannot be confused with slots.  */
#define TAG_OPEN ((void *) 1)
#define TAG_CLOSE ((void *) 2)
#define TAG_STAT ((void *) 3)
#define TAG_FSTAT ((void *) 4)
#define TAG_WRITE 16u

#define NEW_FILE_MODE 0644

struct slot
{
  struct slot *next;
  uint64_t offset;
  uint32_t want;		/* What the request asks for.  */
  uint32_t got;			/* What came.  */
  uint8_t *data;
  int sent;			/* The request has gone out.  */
  int answered;
  int eof;			/* The answer was end of file.  */
};

struct twist_sftp_xfer
{
  struct twist_ssh *ssh;
  gf_sftp_client *client;
  uint32_t chan;
  int have_chan;
  char *path;
  uint8_t handle[GF_SFTP_MAX_HANDLE];
  size_t hlen;
  int have_handle;
  int put;
  int closing;

  /* Download.  */
  struct slot *slots;
  unsigned used;		/* Slots not yet written out.  */
  uint64_t start;		/* The first byte wanted.  */
  uint64_t next_req;		/* The next new chunk starts here.  */
  uint64_t next_out;		/* The next byte to write.  */
  int has_end;
  uint64_t end;			/* One past the last byte wanted.  */
  int suffix;			/* A range counted from the end of the file.  */
  uint64_t suffix_len;
  int ranged;			/* A range was asked for.  */
  int check_resume;		/* The file must be as long as START.  */
  int eof;			/* Everything wanted is written.  */

  /* Upload.  */
  uint64_t put_off;		/* Where the next write goes in the file.  */
  uint64_t skip;		/* Bytes of the source not to send.  */
  int resume;			/* Continue a file; do not truncate it.  */
  int auto_resume;		/* Ask the server how much there is.  */
  size_t src_pos;		/* Into postfields.  */
  int src_eof;
  uint8_t chunk[SFTP_CHUNK];	/* Read from the source, not yet sent.  */
  size_t chunk_len;
  unsigned outstanding;		/* Writes not yet answered.  */
};

static void fail (struct twist_sftp_xfer *g, int err, const char *detail);

void
twist_sftp_free (struct twist_sftp_xfer *g)
{
  if (g == NULL)
    return;
  while (g->slots != NULL)
    {
      struct slot *n = g->slots->next;

      free (g->slots->data);
      free (g->slots);
      g->slots = n;
    }
  free (g->path);
  free (g);
}

/* ---- the path ---- */

static int
hexval (int c)
{
  if (c >= '0' && c <= '9')
    return c - '0';
  if (c >= 'a' && c <= 'f')
    return c - 'a' + 10;
  if (c >= 'A' && c <= 'F')
    return c - 'A' + 10;
  return -1;
}

/* The path the URL names, as SFTP wants it.  "/~/x" is x, relative to
   where the server puts the user; any other path is absolute.  Fails for
   what is not one file: a directory, or for scp a wildcard (which the
   shell of an scp server would expand and SFTP does not).  */
static int
file_path (struct twist_ssh *s, int put, char **out)
{
  struct twist_easy *e = s->easy;
  const char *raw = e->url->path != NULL ? e->url->path : "/";
  size_t n = strlen (raw), i, o = 0;
  char *p = malloc (n + 1);
  const char *use;

  if (p == NULL)
    return TWIST_ERR_NOMEM;
  for (i = 0; i < n; i++)
    {
      if (raw[i] == '%' && i + 2 < n && hexval (raw[i + 1]) >= 0
          && hexval (raw[i + 2]) >= 0)
        {
          int c = hexval (raw[i + 1]) * 16 + hexval (raw[i + 2]);

          if (c == 0)
            {
              free (p);
              twist_ssh_detail (s, _("a NUL in the path"));
              return TWIST_ERR_URL;
            }
          p[o++] = (char) c;
          i += 2;
        }
      else
        p[o++] = raw[i];
    }
  p[o] = 0;
  if (strncmp (p, "/~/", 3) == 0)
    use = p + 3;
  else if (strcmp (p, "/~") == 0)
    use = ".";
  else
    use = p;
  if (use[0] == 0 || use[strlen (use) - 1] == '/')
    {
      free (p);
      if (put)
        {
          twist_ssh_detail (s, _("the path names a directory; give the "
                                 "name of the file to upload to"));
          return TWIST_ERR_URL;
        }
      twist_ssh_detail (s, _("a directory listing over SFTP is not "
                             "implemented yet"));
      return TWIST_ERR_UNSUPPORTED;
    }
  if (e->url->scheme != NULL && strcmp (e->url->scheme, "scp") == 0
      && strpbrk (use, "*?[") != NULL)
    {
      free (p);
      twist_ssh_detail (s, _("scp:// names one file; wildcards are not "
                             "expanded"));
      return TWIST_ERR_URL;
    }
  *out = twist_strdup (use);
  free (p);
  return *out != NULL ? TWIST_OK : TWIST_ERR_NOMEM;
}

/* ---- what is asked for ---- */

/* A number made of digits only, in *V; the end of it in *END.  */
static int
digits (const char *s, uint64_t *v, const char **end)
{
  char *e;
  unsigned long long x;

  if (*s < '0' || *s > '9')
    return -1;
  errno = 0;
  x = strtoull (s, &e, 10);
  if (errno != 0)
    return -1;
  *v = x;
  *end = e;
  return 0;
}

/* "FIRST-LAST", "FIRST-" or "-COUNT" (the last COUNT bytes).  */
static int
parse_range (struct twist_sftp_xfer *g, const char *r)
{
  uint64_t a, b;
  const char *p;

  if (r[0] == '-')
    {
      if (digits (r + 1, &a, &p) != 0 || *p != 0 || a == 0)
        return -1;
      g->suffix = 1;
      g->suffix_len = a;
      return 0;
    }
  if (digits (r, &a, &p) != 0 || *p != '-')
    return -1;
  g->start = a;
  if (p[1] == 0)
    return 0;
  if (digits (p + 1, &b, &p) != 0 || *p != 0 || b < a || b == UINT64_MAX)
    return -1;
  g->has_end = 1;
  g->end = b + 1;
  return 0;
}

/* The size of the data to upload, from postfields.  */
static size_t
source_size (const struct twist_easy *e)
{
  if (e->postfieldsize_set && e->postfieldsize >= 0)
    return (size_t) e->postfieldsize;
  return strlen (e->postfields);
}

/* Work out from the easy handle what this transfer is.  */
static int
plan (struct twist_sftp_xfer *g)
{
  struct twist_easy *e = g->ssh->easy;
  long long resume = e->resume_from;

  g->put = e->postfields != NULL || e->read_cb != NULL;
  if (g->put)
    {
      if (e->range != NULL)
        {
          twist_ssh_detail (g->ssh, _("a range does not apply to an upload"));
          return TWIST_ERR_INVAL;
        }
      if (resume < -1)
        return TWIST_ERR_INVAL;
      if (resume == -1)
        {
          g->auto_resume = 1;
          g->resume = 1;
        }
      else if (resume > 0)
        {
          g->skip = (uint64_t) resume;
          g->put_off = g->skip;
          g->resume = 1;
        }
      return TWIST_OK;
    }
  if (resume < 0)
    {
      twist_ssh_detail (g->ssh, _("a download cannot find its own offset; "
                                  "give one"));
      return TWIST_ERR_INVAL;
    }
  if (resume > 0 && e->range != NULL)
    {
      twist_ssh_detail (g->ssh, _("a resume and a range cannot be used "
                                  "together"));
      return TWIST_ERR_INVAL;
    }
  if (resume > 0)
    {
      g->start = (uint64_t) resume;
      g->check_resume = 1;
    }
  else if (e->range != NULL)
    {
      if (parse_range (g, e->range) != 0)
        {
          twist_ssh_detail (g->ssh, _("the range is not FIRST-LAST, FIRST- "
                                      "or -COUNT"));
          return TWIST_ERR_RANGE;
        }
      g->ranged = 1;
    }
  g->next_req = g->next_out = g->start;
  return TWIST_OK;
}

/* ---- ending ---- */

static void
fail (struct twist_sftp_xfer *g, int err, const char *detail)
{
  if (detail != NULL)
    twist_ssh_detail (g->ssh, detail);
  twist_ssh_finish (g->ssh, err);
}

/* An SFTP status that is not what was wanted.  Missing and forbidden files
   carry the exit status the curl tool gives them, and so does an upload that
   fails for any other reason.  */
static void
fail_status (struct twist_sftp_xfer *g, const gf_sftp_response *r)
{
  char msg[512];
  const char *what;
  int status = g->put ? 25 : 79;

  switch (r->status)
    {
    case GF_FX_NO_SUCH_FILE:
      what = _("no such file");
      if (!g->put)
        status = 78;
      break;
    case GF_FX_PERMISSION_DENIED:
      what = _("permission denied");
      status = 9;
      break;
    default:
      what = _("the server could not do it");
      break;
    }
  snprintf (msg, sizeof msg, "%s: %s%s%.*s", g->path, what,
            r->message.len > 0 ? " (" : "", (int) r->message.len,
            r->message.data != NULL ? (const char *) r->message.data : "");
  if (r->message.len > 0 && strlen (msg) + 2 < sizeof msg)
    strcat (msg, ")");
  g->ssh->easy->proto_status = status;
  fail (g, TWIST_ERR_FILE, msg);
}

static void
close_file (struct twist_sftp_xfer *g)
{
  if (g->closing)
    return;
  g->closing = 1;
  if (gf_sftp_client_close (g->client, g->handle, g->hlen, TAG_CLOSE, NULL)
      != GF_OK)
    fail (g, TWIST_ERR_PROTOCOL, _("the SFTP close failed"));
}

/* ---- reading ---- */

static struct slot *
add_slot (struct twist_sftp_xfer *g, uint64_t offset, uint32_t want)
{
  struct slot *sl = calloc (1, sizeof *sl);

  if (sl == NULL)
    return NULL;
  sl->offset = offset;
  sl->want = want;
  sl->next = g->slots;
  g->slots = sl;
  g->used++;
  return sl;
}

static void
drop_slot (struct twist_sftp_xfer *g, struct slot *sl)
{
  struct slot **pp;

  for (pp = &g->slots; *pp != NULL; pp = &(*pp)->next)
    if (*pp == sl)
      {
        *pp = sl->next;
        break;
      }
  free (sl->data);
  free (sl);
  g->used--;
}

/* Send what is waiting to go, then new chunks while there is room.  */
static void
pump_reads (struct twist_sftp_xfer *g)
{
  struct slot *sl;
  int rc;

  if (!g->have_handle || g->eof || g->closing || twist_ssh_done (g->ssh))
    return;
  for (sl = g->slots; sl != NULL; sl = sl->next)
    {
      if (sl->sent)
        continue;
      rc = gf_sftp_client_read (g->client, g->handle, g->hlen, sl->offset,
                                sl->want, sl, NULL);
      if (rc == GF_ERR_AGAIN)
        return;
      if (rc != GF_OK)
        {
          fail (g, TWIST_ERR_PROTOCOL, _("the SFTP request failed"));
          return;
        }
      sl->sent = 1;
    }
  while (g->used < SFTP_WINDOW)
    {
      uint32_t want = SFTP_CHUNK;

      if (g->has_end)
        {
          if (g->next_req >= g->end)
            break;
          if (g->end - g->next_req < want)
            want = (uint32_t) (g->end - g->next_req);
        }
      sl = add_slot (g, g->next_req, want);
      if (sl == NULL)
        {
          fail (g, TWIST_ERR_NOMEM, NULL);
          return;
        }
      rc = gf_sftp_client_read (g->client, g->handle, g->hlen, sl->offset,
                                sl->want, sl, NULL);
      if (rc == GF_ERR_AGAIN)
        {
          drop_slot (g, sl);
          /* With nothing outstanding no answer is coming to try again.  */
          if (g->used == 0)
            fail (g, TWIST_ERR_PROTOCOL, _("the SFTP request was refused"));
          return;
        }
      if (rc != GF_OK)
        {
          fail (g, TWIST_ERR_PROTOCOL, _("the SFTP request failed"));
          return;
        }
      sl->sent = 1;
      g->next_req += want;
    }
}

static struct slot *
slot_at (struct twist_sftp_xfer *g, uint64_t offset)
{
  struct slot *sl;

  for (sl = g->slots; sl != NULL; sl = sl->next)
    if (sl->answered && sl->offset == offset)
      return sl;
  return NULL;
}

/* Write out what is next in order, as far as it has arrived.  Returns 0
   if the transfer ended.  */
static int
deliver (struct twist_sftp_xfer *g)
{
  struct twist_easy *e = g->ssh->easy;
  struct slot *sl;

  while (!g->eof && (sl = slot_at (g, g->next_out)) != NULL)
    {
      if (sl->eof)
        {
          /* The file ends before the first byte wanted: a range the file
             cannot give.  */
          if (g->ranged && g->next_out == g->start && g->start > 0)
            {
              fail (g, TWIST_ERR_RANGE,
                    _("the range starts beyond the end of the file"));
              return 0;
            }
          g->eof = 1;
          drop_slot (g, sl);
          break;
        }
      if (e->write_cb != NULL)
        {
          size_t put = twist_write_bytes (e->write_cb, e->write_data,
                                          sl->data, sl->got);

          if (put < sl->got)
            {
              fail (g, TWIST_ERR_ABORTED, NULL);
              return 0;
            }
        }
      e->size_download += sl->got;
      g->next_out += sl->got;
      drop_slot (g, sl);
      if (g->has_end && g->next_out >= g->end)
        g->eof = 1;
    }
  if (g->eof)
    close_file (g);
  return !twist_ssh_done (g->ssh);
}

/* A read was answered.  */
static void
read_response (struct twist_sftp_xfer *g, struct slot *sl,
               const gf_sftp_response *r)
{
  if (g->closing)
    {
      /* The file is done; this answer is not wanted.  */
      drop_slot (g, sl);
      return;
    }
  sl->answered = 1;
  if (r->type == GF_FXP_DATA)
    {
      if (r->data.len == 0 || r->data.len > sl->want)
        {
          fail (g, TWIST_ERR_PROTOCOL,
                _("the server sent a read answer of the wrong size"));
          return;
        }
      sl->data = malloc (r->data.len);
      if (sl->data == NULL)
        {
          fail (g, TWIST_ERR_NOMEM, NULL);
          return;
        }
      memcpy (sl->data, r->data.data, r->data.len);
      sl->got = (uint32_t) r->data.len;
      if (sl->got < sl->want)
        {
          /* Less than asked: ask again for the rest, from where this stops.  */
          struct slot *rest = add_slot (g, sl->offset + sl->got,
                                        sl->want - sl->got);

          if (rest == NULL)
            {
              fail (g, TWIST_ERR_NOMEM, NULL);
              return;
            }
          sl->want = sl->got;
        }
    }
  else if (r->type == GF_FXP_STATUS && r->status == GF_FX_EOF)
    sl->eof = 1;
  else if (r->type == GF_FXP_STATUS)
    {
      fail_status (g, r);
      return;
    }
  else
    {
      fail (g, TWIST_ERR_PROTOCOL, _("an unexpected SFTP answer to a read"));
      return;
    }
  if (deliver (g))
    pump_reads (g);
}

/* The size of the file is in: settle where a download starts and ends, and
   begin.  */
static void
got_size (struct twist_sftp_xfer *g, const gf_sftp_response *r)
{
  int have = r->type == GF_FXP_ATTRS && (r->attrs.flags & GF_FILEXFER_ATTR_SIZE);
  uint64_t size = have ? r->attrs.size : 0;

  if (r->type == GF_FXP_STATUS)
    {
      fail_status (g, r);
      return;
    }
  if (g->suffix)
    {
      if (!have)
        {
          fail (g, TWIST_ERR_RANGE,
                _("the server does not say how big the file is, so the end "
                  "of it cannot be found"));
          return;
        }
      g->start = size > g->suffix_len ? size - g->suffix_len : 0;
      g->has_end = 1;
      g->end = size;
      g->next_req = g->next_out = g->start;
    }
  else if (g->check_resume && have)
    {
      if (size < g->start)
        {
          fail (g, TWIST_ERR_RESUME,
                _("the remote file is shorter than the offset to resume at"));
          return;
        }
      if (size == g->start)
        {
          /* Nothing is left.  */
          g->eof = 1;
          deliver (g);
          return;
        }
    }
  if (g->has_end && g->start >= g->end)
    {
      g->eof = 1;
      deliver (g);
      return;
    }
  pump_reads (g);
}

/* ---- writing ---- */

/* Fill the chunk from the source if it is empty.  1 if there is a chunk to
   send, 0 at the end of the data, -1 if the source failed.  */
static int
fill_chunk (struct twist_sftp_xfer *g)
{
  struct twist_easy *e = g->ssh->easy;
  size_t n;

  if (g->chunk_len > 0)
    return 1;
  if (g->src_eof)
    return 0;
  if (e->postfields != NULL)
    {
      size_t total = source_size (e);

      if (g->src_pos >= total)
        {
          g->src_eof = 1;
          return 0;
        }
      n = total - g->src_pos;
      if (n > SFTP_CHUNK)
        n = SFTP_CHUNK;
      memcpy (g->chunk, e->postfields + g->src_pos, n);
      g->src_pos += n;
      g->chunk_len = n;
      return 1;
    }
  n = e->read_cb ((char *) g->chunk, 1, SFTP_CHUNK, e->read_data);
  if (n == 0)
    {
      g->src_eof = 1;
      return 0;
    }
  if (n > SFTP_CHUNK)
    return -1;
  g->chunk_len = n;
  return 1;
}

/* Throw away the first SKIP bytes of the source: they are on the server.  */
static int
discard_source (struct twist_sftp_xfer *g)
{
  struct twist_easy *e = g->ssh->easy;
  uint64_t left = g->skip;

  if (left == 0)
    return 0;
  if (e->postfields != NULL)
    {
      if (left > source_size (e))
        return -1;
      g->src_pos = (size_t) left;
      return 0;
    }
  while (left > 0)
    {
      size_t want = left < SFTP_CHUNK ? (size_t) left : SFTP_CHUNK;
      size_t n = e->read_cb ((char *) g->chunk, 1, want, e->read_data);

      if (n == 0 || n > want)
        return -1;
      left -= n;
    }
  return 0;
}

static void
pump_writes (struct twist_sftp_xfer *g)
{
  int have;

  if (!g->have_handle || g->closing || twist_ssh_done (g->ssh))
    return;
  while (g->outstanding < SFTP_WINDOW)
    {
      int rc;

      have = fill_chunk (g);
      if (have < 0)
        {
          fail (g, TWIST_ERR_ABORTED, NULL);
          return;
        }
      if (have == 0)
        break;
      rc = gf_sftp_client_write (g->client, g->handle, g->hlen, g->put_off,
                                 g->chunk, g->chunk_len,
                                 (void *) (uintptr_t) (TAG_WRITE
                                                       + g->chunk_len), NULL);
      if (rc == GF_ERR_AGAIN)
        {
          /* The chunk is kept for the next try.  With nothing outstanding
             no answer is coming to try again.  */
          if (g->outstanding == 0)
            fail (g, TWIST_ERR_PROTOCOL, _("the SFTP request was refused"));
          return;
        }
      if (rc != GF_OK)
        {
          fail (g, TWIST_ERR_PROTOCOL, _("the SFTP request failed"));
          return;
        }
      g->put_off += g->chunk_len;
      g->chunk_len = 0;
      g->outstanding++;
    }
  if (g->src_eof && g->chunk_len == 0 && g->outstanding == 0)
    close_file (g);
}

/* The file is open for writing.  */
static void
begin_writes (struct twist_sftp_xfer *g)
{
  if (discard_source (g) != 0)
    {
      fail (g, TWIST_ERR_RESUME,
            _("the data to upload is shorter than the offset to resume at"));
      return;
    }
  pump_writes (g);
}

static void
write_response (struct twist_sftp_xfer *g, const gf_sftp_response *r)
{
  if (r->type != GF_FXP_STATUS)
    {
      fail (g, TWIST_ERR_PROTOCOL, _("an unexpected SFTP answer to a write"));
      return;
    }
  if (r->status != GF_FX_OK)
    {
      fail_status (g, r);
      return;
    }
  if (g->outstanding > 0)
    g->outstanding--;
  pump_writes (g);
}

/* ---- the file ---- */

static void
open_file (struct twist_sftp_xfer *g)
{
  gf_sftp_attrs attrs;
  uint32_t flags = GF_FXF_READ;

  memset (&attrs, 0, sizeof attrs);
  if (g->put)
    {
      flags = GF_FXF_WRITE | GF_FXF_CREAT;
      if (!g->resume)
        flags |= GF_FXF_TRUNC;
      attrs.flags = GF_FILEXFER_ATTR_PERMISSIONS;
      attrs.permissions = NEW_FILE_MODE;
    }
  if (gf_sftp_client_open (g->client, g->path, flags, &attrs, TAG_OPEN, NULL)
      != GF_OK)
    fail (g, TWIST_ERR_PROTOCOL, _("the SFTP open failed"));
}

/* An upload that continues a file needs to know how big the file is.  */
static void
size_of_remote (struct twist_sftp_xfer *g)
{
  if (gf_sftp_client_stat (g->client, g->path, TAG_STAT, NULL) != GF_OK)
    fail (g, TWIST_ERR_PROTOCOL, _("the SFTP request failed"));
}

/* The answer to the size of the file an upload continues.  */
static void
remote_size (struct twist_sftp_xfer *g, const gf_sftp_response *r)
{
  uint64_t size = 0;

  if (r->type == GF_FXP_ATTRS)
    {
      if (!(r->attrs.flags & GF_FILEXFER_ATTR_SIZE))
        {
          fail (g, TWIST_ERR_RESUME,
                _("the server does not say how big the remote file is"));
          return;
        }
      size = r->attrs.size;
    }
  else if (r->type == GF_FXP_STATUS && r->status == GF_FX_NO_SUCH_FILE)
    {
      if (!g->auto_resume)
        {
          fail (g, TWIST_ERR_RESUME,
                _("the remote file to resume does not exist"));
          return;
        }
    }
  else if (r->type == GF_FXP_STATUS)
    {
      fail_status (g, r);
      return;
    }
  if (g->auto_resume)
    g->skip = g->put_off = size;
  else if (size < g->skip)
    {
      fail (g, TWIST_ERR_RESUME,
            _("the remote file is shorter than the offset to resume at"));
      return;
    }
  open_file (g);
}

static int
sftp_response (void *user, const gf_sftp_response *r)
{
  struct twist_sftp_xfer *g = user;

  if (twist_ssh_done (g->ssh))
    return 0;
  if (r->tag == TAG_OPEN)
    {
      if (r->type != GF_FXP_HANDLE)
        {
          if (r->type == GF_FXP_STATUS)
            fail_status (g, r);
          else
            fail (g, TWIST_ERR_PROTOCOL, _("an unexpected SFTP answer"));
          return 0;
        }
      if (r->handle.len == 0 || r->handle.len > sizeof g->handle)
        {
          fail (g, TWIST_ERR_PROTOCOL, _("the server sent a bad file handle"));
          return 0;
        }
      memcpy (g->handle, r->handle.data, r->handle.len);
      g->hlen = r->handle.len;
      g->have_handle = 1;
      if (g->put)
        begin_writes (g);
      else if (g->check_resume || g->suffix)
        {
          if (gf_sftp_client_fstat (g->client, g->handle, g->hlen, TAG_FSTAT,
                                    NULL) != GF_OK)
            fail (g, TWIST_ERR_PROTOCOL, _("the SFTP request failed"));
        }
      else
        pump_reads (g);
      return 0;
    }
  if (r->tag == TAG_STAT)
    {
      remote_size (g, r);
      return 0;
    }
  if (r->tag == TAG_FSTAT)
    {
      got_size (g, r);
      return 0;
    }
  if (r->tag == TAG_CLOSE)
    {
      twist_ssh_finish (g->ssh, TWIST_OK);
      return 0;
    }
  if (g->put)
    write_response (g, r);
  else
    read_response (g, r->tag, r);
  return 0;
}

static int
sftp_ready (void *user)
{
  struct twist_sftp_xfer *g = user;

  if (g->put && (g->auto_resume || g->skip > 0))
    size_of_remote (g);
  else
    open_file (g);
  return 0;
}

static void
sftp_disconnect (void *user, int status)
{
  struct twist_sftp_xfer *g = user;
  char msg[128];

  if (twist_ssh_done (g->ssh))
    return;
  snprintf (msg, sizeof msg, _("the SFTP session failed (%d)"), status);
  fail (g, TWIST_ERR_PROTOCOL, msg);
}

/* ---- the channel ---- */

int
twist_sftp_authenticated (void *user, gf_slice username)
{
  struct twist_ssh *s = user;
  struct twist_sftp_xfer *g;
  int rc;

  (void) username;
  g = calloc (1, sizeof *g);
  if (g == NULL)
    {
      twist_ssh_finish (s, TWIST_ERR_NOMEM);
      return 0;
    }
  g->ssh = s;
  s->sftp = g;
  rc = plan (g);
  if (rc == TWIST_OK)
    rc = file_path (s, g->put, &g->path);
  if (rc != TWIST_OK)
    {
      twist_ssh_finish (s, rc);
      return 0;
    }
  if (gf_chans_open_session (gf_session_channels (s->session), &g->chan, 0, 0)
      != GF_OK)
    {
      fail (g, TWIST_ERR_PROTOCOL, _("cannot open a channel"));
      return 0;
    }
  g->have_chan = 1;
  return 0;
}

int
twist_sftp_confirmed (void *user, uint32_t id)
{
  struct twist_ssh *s = user;

  if (s->sftp == NULL || id != s->sftp->chan)
    return 0;
  if (gf_chans_request_subsystem (gf_session_channels (s->session), id, "sftp",
                                  1) != GF_OK)
    fail (s->sftp, TWIST_ERR_PROTOCOL,
          _("cannot ask for the sftp subsystem"));
  return 0;
}

int
twist_sftp_channel_failed (void *user, uint32_t id, uint32_t reason,
                           gf_slice text)
{
  struct twist_ssh *s = user;
  char msg[256];

  (void) reason;
  if (s->sftp == NULL || id != s->sftp->chan)
    return 0;
  snprintf (msg, sizeof msg, _("the server would not open a channel: %.*s"),
            (int) text.len, text.data != NULL ? (const char *) text.data : "");
  fail (s->sftp, TWIST_ERR_PROTOCOL, msg);
  return 0;
}

int
twist_sftp_request_reply (void *user, uint32_t id, int success)
{
  struct twist_ssh *s = user;
  struct twist_sftp_xfer *g = s->sftp;
  gf_sftp_client_config cfg;
  gf_sftp_client_events ev;

  if (g == NULL || id != g->chan)
    return 0;
  if (!success)
    {
      fail (g, TWIST_ERR_UNSUPPORTED,
            _("the server has no SFTP subsystem; twist does not implement "
              "the old SCP protocol"));
      return 0;
    }
  memset (&cfg, 0, sizeof cfg);
  memset (&ev, 0, sizeof ev);
  ev.user = g;
  ev.ready = sftp_ready;
  ev.response = sftp_response;
  ev.disconnect = sftp_disconnect;
  if (gf_session_sftp_client (s->session, id, &cfg, &ev, &g->client) != GF_OK)
    fail (g, TWIST_ERR_PROTOCOL, _("cannot start the SFTP client"));
  return 0;
}

int
twist_sftp_channel_closed (void *user, uint32_t id)
{
  struct twist_ssh *s = user;

  if (s->sftp == NULL || id != s->sftp->chan)
    return 0;
  /* The session frees the client with the channel.  */
  s->sftp->client = NULL;
  if (!twist_ssh_done (s) && !s->ending)
    fail (s->sftp, TWIST_ERR_CLOSED, _("the server closed the channel"));
  return 0;
}
