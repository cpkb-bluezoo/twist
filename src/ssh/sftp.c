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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Download one file over SFTP.  scp:// is this too.

   The session is logged in.  Open a session channel, ask for the "sftp"
   subsystem, bind an SFTP client to the channel, open the file and read it
   until the end.

   Reads are pipelined: up to SFTP_WINDOW are outstanding, each for a chunk
   of the file, and the answers are written out in order of offset however
   they arrive.  A server may answer a read with less than was asked; the
   rest is asked for again at once.  End of file is a status, and counts
   only when every byte before it has been written.  */

#define SFTP_CHUNK 32768u
#define SFTP_WINDOW 16u

/* Tags of requests that are not reads.  A read's tag is its slot.  */
#define TAG_OPEN ((void *) 1)
#define TAG_CLOSE ((void *) 2)

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

struct twist_sftp_get
{
  struct twist_ssh *ssh;
  gf_sftp_client *client;
  uint32_t chan;
  int have_chan;
  char *path;
  uint8_t handle[GF_SFTP_MAX_HANDLE];
  size_t hlen;
  int have_handle;
  struct slot *slots;
  unsigned used;		/* Slots not yet written out.  */
  uint64_t next_req;		/* The next new chunk starts here.  */
  uint64_t next_out;		/* The next byte to write.  */
  int eof;			/* Everything up to the end is written.  */
  int closing;
};

static void fail (struct twist_sftp_get *g, int err, const char *detail);

void
twist_sftp_free (struct twist_sftp_get *g)
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
file_path (struct twist_ssh *s, char **out)
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

/* ---- ending ---- */

static void
fail (struct twist_sftp_get *g, int err, const char *detail)
{
  if (detail != NULL)
    twist_ssh_detail (g->ssh, detail);
  twist_ssh_finish (g->ssh, err);
}

/* An SFTP status that is not what was wanted.  Missing and forbidden files
   carry the exit status the curl tool gives them.  */
static void
fail_status (struct twist_sftp_get *g, const gf_sftp_response *r)
{
  char msg[512];
  const char *what;
  int status = 79;

  switch (r->status)
    {
    case GF_FX_NO_SUCH_FILE:
      what = _("no such file");
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

/* ---- reading ---- */

static struct slot *
add_slot (struct twist_sftp_get *g, uint64_t offset, uint32_t want)
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
drop_slot (struct twist_sftp_get *g, struct slot *sl)
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
pump (struct twist_sftp_get *g)
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
      sl = add_slot (g, g->next_req, SFTP_CHUNK);
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
      g->next_req += SFTP_CHUNK;
    }
}

static struct slot *
slot_at (struct twist_sftp_get *g, uint64_t offset)
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
deliver (struct twist_sftp_get *g)
{
  struct twist_easy *e = g->ssh->easy;
  struct slot *sl;

  while (!g->eof && (sl = slot_at (g, g->next_out)) != NULL)
    {
      if (sl->eof)
        {
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
    }
  if (g->eof && !g->closing)
    {
      g->closing = 1;
      if (gf_sftp_client_close (g->client, g->handle, g->hlen, TAG_CLOSE,
                                NULL) != GF_OK)
        {
          fail (g, TWIST_ERR_PROTOCOL, _("the SFTP close failed"));
          return 0;
        }
    }
  return 1;
}

/* A read was answered.  */
static void
read_response (struct twist_sftp_get *g, struct slot *sl,
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
    pump (g);
}

static int
sftp_response (void *user, const gf_sftp_response *r)
{
  struct twist_sftp_get *g = user;

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
      pump (g);
      return 0;
    }
  if (r->tag == TAG_CLOSE)
    {
      twist_ssh_finish (g->ssh, TWIST_OK);
      return 0;
    }
  read_response (g, r->tag, r);
  return 0;
}

static int
sftp_ready (void *user)
{
  struct twist_sftp_get *g = user;
  gf_sftp_attrs none;

  memset (&none, 0, sizeof none);
  if (gf_sftp_client_open (g->client, g->path, GF_FXF_READ, &none, TAG_OPEN,
                           NULL) != GF_OK)
    {
      fail (g, TWIST_ERR_PROTOCOL, _("the SFTP open failed"));
      return 0;
    }
  return 0;
}

static void
sftp_disconnect (void *user, int status)
{
  struct twist_sftp_get *g = user;
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
  struct twist_sftp_get *g;
  int rc;

  (void) username;
  g = calloc (1, sizeof *g);
  if (g == NULL)
    {
      twist_ssh_finish (s, TWIST_ERR_NOMEM);
      return 0;
    }
  g->ssh = s;
  s->get = g;
  rc = file_path (s, &g->path);
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

  if (s->get == NULL || id != s->get->chan)
    return 0;
  if (gf_chans_request_subsystem (gf_session_channels (s->session), id, "sftp",
                                  1) != GF_OK)
    fail (s->get, TWIST_ERR_PROTOCOL, _("cannot ask for the sftp subsystem"));
  return 0;
}

int
twist_sftp_channel_failed (void *user, uint32_t id, uint32_t reason,
                           gf_slice text)
{
  struct twist_ssh *s = user;
  char msg[256];

  (void) reason;
  if (s->get == NULL || id != s->get->chan)
    return 0;
  snprintf (msg, sizeof msg, _("the server would not open a channel: %.*s"),
            (int) text.len, text.data != NULL ? (const char *) text.data : "");
  fail (s->get, TWIST_ERR_PROTOCOL, msg);
  return 0;
}

int
twist_sftp_request_reply (void *user, uint32_t id, int success)
{
  struct twist_ssh *s = user;
  struct twist_sftp_get *g = s->get;
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

  if (s->get == NULL || id != s->get->chan)
    return 0;
  /* The session frees the client with the channel.  */
  s->get->client = NULL;
  if (!twist_ssh_done (s) && !s->ending)
    fail (s->get, TWIST_ERR_CLOSED, _("the server closed the channel"));
  return 0;
}
