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
#include "ssh/ssh-int.h"

#include <foxtrot/chan.h>
#include <foxtrot/crypto.h>
#include <foxtrot/key.h>
#include <foxtrot/knownhosts.h>
#include <foxtrot/session.h>
#include <foxtrot/sftp.h>
#include <foxtrot/status.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

/* The twist handler is the client; a foxtrot session is the server, in the
   same process, authenticating and serving a file over SFTP.  Each side's
   output is collected and handed to the other, so the exchange can be cut
   into pieces of any size.  HOME is a directory of our own, so that nothing
   of the person running the tests is read.  */

#define PIPE_MAX (2 * 1024 * 1024)
#define FILE_LEN 100000
#define BIG_LEN 1300000

struct pipe
{
  uint8_t data[PIPE_MAX];
  size_t len;
};

/* An entry of a directory: its name, and the server's long form of it.  */
struct dent
{
  const char *name;
  const char *longname;
};

struct server
{
  struct pipe out;
  gf_session *s;
  gf_key *host;
  gf_key *authorized;		/* The user key the server accepts.  */
  const char *password;		/* The password it accepts, or NULL.  */
  int refuse_sftp;		/* Answer no to the subsystem request.  */
  size_t max_read;		/* Most it answers a read with; 0: as asked.  */
  const uint8_t *file;
  size_t filelen;
  gf_sftp_server *sftp;
  char opened[128];
  int closed_handle;
  int closed;
  uint32_t reason;
  /* The file that can be written, up.bin, and what was done to it.  */
  uint8_t *up;
  size_t up_len, up_cap;
  int up_exists;
  uint32_t up_flags;
  int up_perms;			/* -1: none asked.  */
  unsigned writes;
  uint64_t first_write;
  unsigned reads;
  uint64_t first_read;
  uint32_t write_status;	/* Answer writes with this instead of OK.  */
  int hide_size;		/* Say nothing of a file's size.  */
  /* The directory being listed.  */
  const struct dent *dents;
  size_t ndents, dpos;
  unsigned batch;		/* Entries to a READDIR answer.  */
  unsigned readdirs;
};

static uint64_t now_us = 1000000;
static char home[256];
static uint8_t content[FILE_LEN];

static int
pipe_write (struct pipe *p, const uint8_t *data, size_t len)
{
  if (p->len + len > sizeof p->data)
    return -1;
  memcpy (p->data + p->len, data, len);
  p->len += len;
  return 0;
}

static int
client_sink (void *user, const uint8_t *data, size_t len)
{
  return pipe_write (user, data, len);
}

/* ---- the server ---- */

static int
sv_write (void *user, const uint8_t *data, size_t len)
{
  struct server *sv = user;

  return pipe_write (&sv->out, data, len);
}

static int
sv_auth_request (void *user, const gf_auth_request *req)
{
  struct server *sv = user;
  int ok = 0;

  if (req->user.len != 5 || memcmp (req->user.data, "alice", 5) != 0)
    return gf_session_auth_reject (sv->s, 0) != GF_OK;
  if (req->method == GF_AUTH_PASSWORD && sv->password != NULL)
    ok = req->password.len == strlen (sv->password)
         && memcmp (req->password.data, sv->password, req->password.len) == 0;
  else if (req->method == GF_AUTH_PUBLICKEY && sv->authorized != NULL
           && gf_key_equal (req->key, sv->authorized))
    {
      if (!req->has_signature)
        return gf_session_auth_pk_ok (sv->s) != GF_OK;
      ok = 1;
    }
  if (ok)
    return gf_session_auth_accept (sv->s) != GF_OK;
  return gf_session_auth_reject (sv->s, 0) != GF_OK;
}

static int
sv_channel_open (void *user, const gf_chan_open *o)
{
  struct server *sv = user;

  if (o->type != GF_CHAN_SESSION)
    return gf_session_channel_reject (sv->s, o->id,
                                      GF_OPEN_ADMINISTRATIVELY_PROHIBITED,
                                      "sessions only") != GF_OK;
  return gf_session_channel_accept (sv->s, o->id, 0, 0) != GF_OK;
}

static int
is_data (const char *p)
{
  return strcmp (p, "/data.bin") == 0 || strcmp (p, "data.bin") == 0;
}

static int
is_up (const char *p)
{
  return strcmp (p, "/up.bin") == 0 || strcmp (p, "up.bin") == 0;
}

static int
sv_attrs_size (struct server *sv, uint32_t id, uint64_t size)
{
  gf_sftp_attrs a;

  memset (&a, 0, sizeof a);
  if (!sv->hide_size)
    {
      a.flags = GF_FILEXFER_ATTR_SIZE;
      a.size = size;
    }
  return gf_sftp_server_attrs (sv->sftp, id, &a) != GF_OK;
}


/* The directories the server has: a short one whose names are awkward
   (spaces, a newline, a terminal escape, UTF-8 and the UTF-8 form of a C1
   control), an empty one, and a big one made by the test.  */
static const struct dent main_dir[] = {
  { ".", "drwxr-xr-x    3 u g 4096 Oct 21 14:04 ." },
  { "..", "drwxr-xr-x    4 u g 4096 Oct 21 14:04 .." },
  { "plain.txt", "-rw-r--r--    1 u g    6 Oct 21 14:04 plain.txt" },
  { "with space.txt", "-rw-r--r--    1 u g    1 Oct 21 14:04 with space.txt" },
  { "esc\033[31mred", "-rw-r--r--    1 u g    1 Oct 21 14:04 esc\033[31mred" },
  { "new\nline", "-rw-r--r--    1 u g    1 Oct 21 14:04 new\nline" },
  { "caf\xc3\xa9", "-rw-r--r--    1 u g    1 Oct 21 14:04 caf\xc3\xa9" },
  { "csi\xc2\x9b" "31m", "-rw-r--r--    1 u g    1 Oct 21 14:04 csi\xc2\x9b" "31m" },
  { "nolong", "" }
};
#define MAIN_DIR_N (sizeof main_dir / sizeof main_dir[0])

struct big_ent
{
  char name[32];
  char lng[80];
};

static struct dent *big_dir;
static struct big_ent *big_ents;
#define BIG_DIR_N 2500

static void
make_big_dir (void)
{
  size_t i;

  big_dir = calloc (BIG_DIR_N, sizeof *big_dir);
  big_ents = calloc (BIG_DIR_N, sizeof *big_ents);
  for (i = 0; i < BIG_DIR_N; i++)
    {
      snprintf (big_ents[i].name, sizeof big_ents[i].name, "file%04u",
                (unsigned) i);
      snprintf (big_ents[i].lng, sizeof big_ents[i].lng,
                "-rw-r--r--    1 u g %4u Jan  1 00:00 file%04u",
                (unsigned) i, (unsigned) i);
      big_dir[i].name = big_ents[i].name;
      big_dir[i].longname = big_ents[i].lng;
    }
}

static int
sv_opendir (struct server *sv, const gf_sftp_request *req, const char *path)
{
  static const uint8_t dh[] = { 'D', '1' };

  snprintf (sv->opened, sizeof sv->opened, "%s", path);
  sv->dents = NULL;
  sv->ndents = sv->dpos = 0;
  if (strcmp (path, "/dir") == 0 || strcmp (path, "sub") == 0
      || strcmp (path, ".") == 0 || strcmp (path, "/") == 0)
    {
      sv->dents = main_dir;
      sv->ndents = MAIN_DIR_N;
    }
  else if (strcmp (path, "/big") == 0)
    {
      sv->dents = big_dir;
      sv->ndents = BIG_DIR_N;
    }
  else if (strcmp (path, "/empty") != 0)
    {
      if (strcmp (path, "/denied") == 0)
        return gf_sftp_server_status (sv->sftp, req->id,
                                      GF_FX_PERMISSION_DENIED,
                                      "not for you") != GF_OK;
      return gf_sftp_server_status (sv->sftp, req->id, GF_FX_NO_SUCH_FILE,
                                    "No such file") != GF_OK;
    }
  return gf_sftp_server_handle (sv->sftp, req->id, dh, sizeof dh) != GF_OK;
}

static int
sv_readdir (struct server *sv, const gf_sftp_request *req)
{
  gf_sftp_name names[256];
  size_t n = 0;
  unsigned batch = sv->batch != 0 && sv->batch <= 256 ? sv->batch : 3;

  sv->readdirs++;
  if (sv->dpos >= sv->ndents)
    return gf_sftp_server_status (sv->sftp, req->id, GF_FX_EOF, "") != GF_OK;
  memset (names, 0, sizeof names);
  while (n < batch && sv->dpos < sv->ndents)
    {
      const struct dent *d = &sv->dents[sv->dpos++];

      names[n].filename.data = (const uint8_t *) d->name;
      names[n].filename.len = strlen (d->name);
      names[n].longname.data = (const uint8_t *) d->longname;
      names[n].longname.len = strlen (d->longname);
      n++;
    }
  return gf_sftp_server_names (sv->sftp, req->id, n, names) != GF_OK;
}

static int
sv_sftp_request (void *user, const gf_sftp_request *req)
{
  struct server *sv = user;
  static const uint8_t fh[] = { 'F', '1' };
  static const uint8_t uh[] = { 'U', '1' };
  char path[128];
  int is_u = req->handle.len == 2 && req->handle.data[0] == 'U';

  snprintf (path, sizeof path, "%.*s", (int) req->path.len,
            (const char *) req->path.data);
  switch (req->type)
    {
    case GF_FXP_OPEN:
      snprintf (sv->opened, sizeof sv->opened, "%s", path);
      if (is_data (path) && !(req->pflags & GF_FXF_WRITE))
        return gf_sftp_server_handle (sv->sftp, req->id, fh,
                                      sizeof fh) != GF_OK;
      if (is_up (path) && (req->pflags & GF_FXF_WRITE))
        {
          if (!sv->up_exists && !(req->pflags & GF_FXF_CREAT))
            return gf_sftp_server_status (sv->sftp, req->id,
                                          GF_FX_NO_SUCH_FILE, "") != GF_OK;
          if (req->pflags & GF_FXF_TRUNC)
            sv->up_len = 0;
          sv->up_exists = 1;
          sv->up_flags = req->pflags;
          sv->up_perms = (req->attrs.flags & GF_FILEXFER_ATTR_PERMISSIONS)
                         ? (int) req->attrs.permissions : -1;
          return gf_sftp_server_handle (sv->sftp, req->id, uh,
                                        sizeof uh) != GF_OK;
        }
      if (strcmp (path, "/denied") == 0)
        return gf_sftp_server_status (sv->sftp, req->id,
                                      GF_FX_PERMISSION_DENIED,
                                      "not for you") != GF_OK;
      return gf_sftp_server_status (sv->sftp, req->id, GF_FX_NO_SUCH_FILE,
                                    "") != GF_OK;
    case GF_FXP_READ:
      {
        size_t n;

        if (sv->reads++ == 0)
          sv->first_read = req->offset;
        if (is_u || req->offset >= sv->filelen)
          return gf_sftp_server_status (sv->sftp, req->id, GF_FX_EOF,
                                        "") != GF_OK;
        n = sv->filelen - (size_t) req->offset;
        if (n > req->length)
          n = req->length;
        if (sv->max_read != 0 && n > sv->max_read)
          n = sv->max_read;
        return gf_sftp_server_data (sv->sftp, req->id,
                                    sv->file + req->offset, n) != GF_OK;
      }
    case GF_FXP_WRITE:
      {
        size_t end = (size_t) req->offset + req->data.len;

        if (sv->writes++ == 0)
          sv->first_write = req->offset;
        if (!is_u)
          return gf_sftp_server_status (sv->sftp, req->id, GF_FX_FAILURE,
                                        "not open for writing") != GF_OK;
        if (sv->write_status != 0)
          return gf_sftp_server_status (sv->sftp, req->id, sv->write_status,
                                        "no room") != GF_OK;
        if (end > sv->up_cap)
          {
            uint8_t *grown = realloc (sv->up, end + 4096);

            if (grown == NULL)
              return 1;
            sv->up = grown;
            sv->up_cap = end + 4096;
          }
        if ((size_t) req->offset > sv->up_len)
          memset (sv->up + sv->up_len, 0, (size_t) req->offset - sv->up_len);
        memcpy (sv->up + req->offset, req->data.data, req->data.len);
        if (end > sv->up_len)
          sv->up_len = end;
        return gf_sftp_server_status (sv->sftp, req->id, GF_FX_OK, "")
               != GF_OK;
      }
    case GF_FXP_OPENDIR:
      return sv_opendir (sv, req, path);
    case GF_FXP_READDIR:
      return sv_readdir (sv, req);
    case GF_FXP_FSTAT:
      return sv_attrs_size (sv, req->id, is_u ? sv->up_len : sv->filelen);
    case GF_FXP_STAT:
      if (is_data (path))
        return sv_attrs_size (sv, req->id, sv->filelen);
      if (is_up (path) && sv->up_exists)
        return sv_attrs_size (sv, req->id, sv->up_len);
      return gf_sftp_server_status (sv->sftp, req->id, GF_FX_NO_SUCH_FILE,
                                    "") != GF_OK;
    case GF_FXP_CLOSE:
      sv->closed_handle = 1;
      return gf_sftp_server_status (sv->sftp, req->id, GF_FX_OK, "") != GF_OK;
    default:
      return gf_sftp_server_status (sv->sftp, req->id, GF_FX_OP_UNSUPPORTED,
                                    "") != GF_OK;
    }
}

static int
sv_channel_request (void *user, const gf_chan_request *q)
{
  struct server *sv = user;
  gf_chans *ch = gf_session_channels (sv->s);
  gf_sftp_server_config sc;
  gf_sftp_server_events se;

  if (q->type != GF_REQ_SUBSYSTEM || sv->refuse_sftp)
    return q->want_reply ? gf_chans_reply (ch, q->id, 0) != GF_OK : 0;
  if (gf_chans_reply (ch, q->id, 1) != GF_OK)
    return 1;
  memset (&sc, 0, sizeof sc);
  memset (&se, 0, sizeof se);
  se.user = sv;
  se.request = sv_sftp_request;
  return gf_session_sftp_server (sv->s, q->id, &sc, &se, &sv->sftp) != GF_OK;
}

static void
sv_closed (void *user, int error, uint32_t reason, gf_slice text)
{
  struct server *sv = user;

  (void) error;
  (void) text;
  sv->closed = 1;
  sv->reason = reason;
}

static int
server_new (struct server *sv)
{
  gf_session_config cfg;
  gf_session_events ev;

  memset (sv, 0, sizeof *sv);
  memset (&cfg, 0, sizeof cfg);
  memset (&ev, 0, sizeof ev);
  if (gf_key_generate (&sv->host, GF_KEY_ED25519, 0) != GF_OK
      || gf_key_generate (&sv->authorized, GF_KEY_ED25519, 0) != GF_OK)
    return -1;
  sv->password = "secret";
  sv->file = content;
  sv->filelen = sizeof content;
  cfg.conn.software = "testd_1";
  cfg.conn.host_keys = &sv->host;
  cfg.conn.nhost_keys = 1;
  cfg.server_auth.methods = GF_AUTH_PASSWORD | GF_AUTH_PUBLICKEY;
  ev.user = sv;
  ev.write = sv_write;
  ev.auth_request = sv_auth_request;
  ev.channel_open = sv_channel_open;
  ev.channel_request = sv_channel_request;
  ev.closed = sv_closed;
  if (gf_session_server_new (&sv->s, &cfg, &ev) != GF_OK)
    return -1;
  return gf_session_start (sv->s, now_us) == GF_OK ? 0 : -1;
}

static void
server_free (struct server *sv)
{
  free (sv->up);
  gf_session_free (sv->s);
  gf_key_free (sv->host);
  gf_key_free (sv->authorized);
}

/* ---- the pipes ---- */

struct world
{
  struct twist_ssh *ssh;
  struct server *sv;
  struct pipe c2s;
};

/* Take everything out of PIPE and give it to FN in pieces of CHUNK.  */
static size_t
drain (struct pipe *p, size_t chunk,
       void (*fn) (struct world *, const uint8_t *, size_t), struct world *w)
{
  size_t off = 0;
  size_t total = p->len;

  while (off < p->len)
    {
      size_t n = p->len - off;

      if (n > chunk)
        n = chunk;
      fn (w, p->data + off, n);
      off += n;
    }
  p->len = 0;
  return total;
}

static void
to_client (struct world *w, const uint8_t *data, size_t len)
{
  twist_ssh_receive (w->ssh, data, len);
}

static void
to_server (struct world *w, const uint8_t *data, size_t len)
{
  if (w->sv != NULL && w->sv->s != NULL)
    gf_session_receive (w->sv->s, now_us, data, len);
}

/* Run the exchange until nothing moves or the transfer ends.  */
static void
pump (struct world *w, struct twist_easy *easy, size_t chunk)
{
  int i;

  for (i = 0; i < 5000 && !easy->done; i++)
    {
      size_t moved = 0;

      moved += drain (&w->c2s, chunk, to_server, w);
      moved += drain (&w->sv->out, chunk, to_client, w);
      if (moved == 0)
        break;
    }
}

/* What the transfer wrote.  */
static uint8_t got[2 * FILE_LEN];
static size_t got_len;
static size_t collect_limit;	/* Refuse data past this much; 0: no limit.  */

static size_t
collect (char *ptr, size_t size, size_t nmemb, void *user)
{
  size_t n = size * nmemb;

  (void) user;
  if (got_len + n > sizeof got
      || (collect_limit != 0 && got_len + n > collect_limit))
    return 0;
  memcpy (got + got_len, ptr, n);
  got_len += n;
  return n;
}

static void
write_file (const char *path, const char *text, size_t len, int mode)
{
  FILE *fp = fopen (path, "wb");

  if (fp != NULL)
    {
      fwrite (text, 1, len, fp);
      fclose (fp);
      chmod (path, (mode_t) mode);
    }
}

/* A known_hosts file at HOME/known_hosts that knows KEY as the key of the
   test host (none if KEY is NULL); returns its path in PATH.  */
static void
known_hosts_with (const gf_key *key, char *path, size_t cap)
{
  char line[512];
  size_t n = 0;

  snprintf (path, cap, "%s/known_hosts", home);
  if (key != NULL
      && gf_knownhosts_format (line, sizeof line, &n, "127.0.0.1", 22, key, 0)
         == GF_OK)
    write_file (path, line, n, 0600);
  else
    write_file (path, "", 0, 0600);
}

/* The things a test varies.  */
struct setup
{
  const char *url;
  int verify;			/* Check the host key.  */
  const char *password;		/* NULL: none.  */
  const char *keyfile;
  const char *known_hosts;
  const char *pin;
  size_t chunk;
  uint8_t *upload;		/* Data to upload; NULL: a download.  */
  size_t upload_len;
  int streamed;			/* Give it through a read callback.  */
  long long resume;
  const char *range;
  int list_only;
};

/* Every field, so that none is forgotten: URL, whether to check the host key,
   and the password; the rest is for the test to set.  */
#define SETUP(url, verify, pw) \
  { (url), (verify), (pw), NULL, NULL, NULL, 0, NULL, 0, 0, 0, NULL, 0 }

/* The read callback for a streamed upload: it hands out the data in pieces
   of an awkward size.  */
static const uint8_t *feed_data;
static size_t feed_len, feed_pos, feed_piece;

static size_t
feed (char *ptr, size_t size, size_t nmemb, void *user)
{
  size_t n = feed_len - feed_pos;

  (void) user;
  if (n > size * nmemb)
    n = size * nmemb;
  if (n > feed_piece)
    n = feed_piece;
  memcpy (ptr, feed_data + feed_pos, n);
  feed_pos += n;
  return n;
}

static struct twist_easy *
start (struct world *w, struct server *sv, const struct setup *su)
{
  struct twist_easy *easy = twist_easy_init ();

  check (twist_url_parse_int (su->url, &easy->url) == TWIST_OK, "url");
  easy->verifypeer = su->verify;
  if (su->password != NULL)
    twist_easy_setopt (easy, TWISTOPT_PASSWORD, su->password);
  if (su->keyfile != NULL)
    twist_easy_setopt (easy, TWISTOPT_SSLKEY, su->keyfile);
  if (su->known_hosts != NULL)
    twist_easy_setopt (easy, TWISTOPT_SSH_KNOWNHOSTS, su->known_hosts);
  if (su->pin != NULL)
    twist_easy_setopt (easy, TWISTOPT_SSH_HOST_PUBLIC_KEY_SHA256, su->pin);
  easy->write_cb = collect;
  got_len = 0;
  if (su->upload != NULL && su->streamed)
    {
      feed_data = su->upload;
      feed_len = su->upload_len;
      feed_pos = 0;
      feed_piece = 7001;
      easy->read_cb = feed;
    }
  else if (su->upload != NULL)
    {
      twist_easy_setopt (easy, TWISTOPT_POSTFIELDS, (char *) su->upload);
      twist_easy_setopt (easy, TWISTOPT_POSTFIELDSIZE, (long) su->upload_len);
    }
  if (su->resume != 0)
    twist_easy_setopt (easy, TWISTOPT_RESUME_FROM, su->resume);
  if (su->range != NULL)
    twist_easy_setopt (easy, TWISTOPT_RANGE, su->range);
  if (su->list_only)
    twist_easy_setopt (easy, TWISTOPT_DIRLISTONLY, 1L);
  w->sv = sv;
  w->c2s.len = 0;
  w->ssh = twist_ssh_new (easy, 0);
  check (w->ssh != NULL, "ssh new");
  twist_ssh_set_sink (w->ssh, client_sink, &w->c2s);
  twist_ssh_set_time (w->ssh, now_us);
  return easy;
}

/* Run a whole transfer; the caller looks at the result.  */
static struct twist_easy *
run (struct world *w, struct server *sv, const struct setup *su)
{
  struct twist_easy *easy = start (w, sv, su);
  int rc = twist_ssh_start (w->ssh);

  /* The endpoint callback ends a transfer that cannot start with the code
     start returned.  */
  if (rc != TWIST_OK && !easy->done)
    twist_easy_finish (easy, rc);
  if (rc == TWIST_OK)
    pump (w, easy, su->chunk != 0 ? su->chunk : 65536);
  return easy;
}

static int
detail_has (struct twist_easy *easy, const char *text)
{
  const char *d = twist_easy_error (easy);

  return d != NULL && strstr (d, text) != NULL;
}

/* ---- the tests ---- */

/* The file arrives whole and in order, at several chunk sizes down to one
   byte at a time, and the session says goodbye.  */
static void
test_download (size_t chunk)
{
  struct server sv;
  struct world w;
  struct twist_easy *easy;
  struct setup su = SETUP ("sftp://alice@127.0.0.1/data.bin", 0, "secret");

  check (server_new (&sv) == 0, "server");
  su.chunk = chunk;
  easy = run (&w, &sv, &su);
  gf_session_receive (sv.s, now_us, w.c2s.data, w.c2s.len);
  check (easy->done && easy->result == TWIST_OK, "download ends well");
  check (got_len == sizeof content && memcmp (got, content, got_len) == 0,
         "the file is whole");
  check (easy->size_download == sizeof content, "size counted");
  check (strcmp (sv.opened, "/data.bin") == 0, "absolute path");
  check (sv.closed_handle, "handle closed");
  check (sv.closed && sv.reason == GF_DISCONNECT_BY_APPLICATION,
         "server told goodbye");
  twist_easy_cleanup (easy);
  server_free (&sv);
}

/* A server that answers reads with less than was asked.  */
static void
test_short_reads (void)
{
  struct server sv;
  struct world w;
  struct twist_easy *easy;
  struct setup su = SETUP ("sftp://alice@127.0.0.1/data.bin", 0, "secret");

  check (server_new (&sv) == 0, "server");
  sv.max_read = 5000;
  easy = run (&w, &sv, &su);
  check (easy->done && easy->result == TWIST_OK, "short reads end well");
  check (got_len == sizeof content && memcmp (got, content, got_len) == 0,
         "short reads: the file is whole");
  twist_easy_cleanup (easy);
  server_free (&sv);
}

static void
test_empty_file (void)
{
  struct server sv;
  struct world w;
  struct twist_easy *easy;
  struct setup su = SETUP ("sftp://alice@127.0.0.1/data.bin", 0, "secret");

  check (server_new (&sv) == 0, "server");
  sv.filelen = 0;
  easy = run (&w, &sv, &su);
  check (easy->done && easy->result == TWIST_OK && got_len == 0,
         "an empty file");
  twist_easy_cleanup (easy);
  server_free (&sv);
}

/* scp:// is the same transfer; /~/ is relative to the user's directory.  */
static void
test_paths (void)
{
  struct server sv;
  struct world w;
  struct twist_easy *easy;
  struct setup su = SETUP ("scp://alice@127.0.0.1/~/data.bin", 0, "secret");

  check (server_new (&sv) == 0, "server");
  easy = run (&w, &sv, &su);
  check (easy->done && easy->result == TWIST_OK, "scp ends well");
  check (strcmp (sv.opened, "data.bin") == 0, "home relative path");
  check (got_len == sizeof content, "scp: the file");
  twist_easy_cleanup (easy);
  server_free (&sv);

  /* Percent escapes are decoded.  */
  check (server_new (&sv) == 0, "server 2");
  su.url = "sftp://alice@127.0.0.1/%64ata.bin";
  easy = run (&w, &sv, &su);
  check (easy->done && easy->result == TWIST_OK
         && strcmp (sv.opened, "/data.bin") == 0, "percent escape");
  twist_easy_cleanup (easy);
  server_free (&sv);

  /* A wildcard in an scp URL is refused up front.  */
  check (server_new (&sv) == 0, "server 3");
  su.url = "scp://alice@127.0.0.1/dir/*.txt";
  easy = run (&w, &sv, &su);
  check (easy->done && easy->result == TWIST_ERR_URL
         && detail_has (easy, "wildcards"), "scp wildcard");
  twist_easy_cleanup (easy);
  server_free (&sv);
}

/* What the server says about the file reaches the curl tool's status.  */
static void
test_file_errors (void)
{
  struct server sv;
  struct world w;
  struct twist_easy *easy;
  struct setup su = SETUP ("sftp://alice@127.0.0.1/nope", 0, "secret");

  check (server_new (&sv) == 0, "server");
  easy = run (&w, &sv, &su);
  check (easy->done && easy->result == TWIST_ERR_FILE
         && easy->proto_status == 78 && detail_has (easy, "no such file")
         && detail_has (easy, "/nope"), "no such file");
  twist_easy_cleanup (easy);
  server_free (&sv);
  check (server_new (&sv) == 0, "server 2");
  su.url = "sftp://alice@127.0.0.1/denied";
  easy = run (&w, &sv, &su);
  check (easy->done && easy->result == TWIST_ERR_FILE
         && easy->proto_status == 9 && detail_has (easy, "not for you"),
         "permission denied");
  twist_easy_cleanup (easy);
  server_free (&sv);
}

/* No sftp subsystem: scp:// is not served by the old protocol.  */
static void
test_no_subsystem (void)
{
  struct server sv;
  struct world w;
  struct twist_easy *easy;
  struct setup su = SETUP ("scp://alice@127.0.0.1/data.bin", 0, "secret");

  check (server_new (&sv) == 0, "server");
  sv.refuse_sftp = 1;
  easy = run (&w, &sv, &su);
  check (easy->done && easy->result == TWIST_ERR_UNSUPPORTED
         && detail_has (easy, "no SFTP subsystem"), "no subsystem");
  twist_easy_cleanup (easy);
  server_free (&sv);
}

/* Passwords, keys given and keys found, and what is said when none works.  */
static void
test_auth (void)
{
  struct server sv;
  struct world w;
  struct twist_easy *easy;
  struct setup su = SETUP ("sftp://alice@127.0.0.1/data.bin", 0, "wrong");
  char keytext[2048], keyfile[300], ssh_dir[300], usual[320];
  size_t kn = 0;

  check (server_new (&sv) == 0, "server");
  easy = run (&w, &sv, &su);
  check (easy->done && easy->result == TWIST_ERR_AUTH
         && detail_has (easy, "permission denied"), "wrong password");
  twist_easy_cleanup (easy);
  server_free (&sv);

  check (server_new (&sv) == 0, "server 2");
  su.password = NULL;
  easy = run (&w, &sv, &su);
  check (easy->done && easy->result == TWIST_ERR_AUTH
         && detail_has (easy, "no private key or password"), "no credentials");
  twist_easy_cleanup (easy);
  server_free (&sv);

  /* A key named with --key: the one the server authorizes.  */
  check (server_new (&sv) == 0, "server 3");
  check (gf_key_to_openssh_private (sv.authorized, keytext, sizeof keytext,
                                    &kn) == GF_OK, "key text");
  snprintf (keyfile, sizeof keyfile, "%s/mykey", home);
  write_file (keyfile, keytext, kn, 0600);
  su.keyfile = keyfile;
  easy = run (&w, &sv, &su);
  check (easy->done && easy->result == TWIST_OK
         && got_len == sizeof content, "key file");
  twist_easy_cleanup (easy);
  server_free (&sv);

  /* The same key where ssh looks for it, with nothing named.  */
  check (server_new (&sv) == 0, "server 4");
  check (gf_key_to_openssh_private (sv.authorized, keytext, sizeof keytext,
                                    &kn) == GF_OK, "key text 2");
  snprintf (ssh_dir, sizeof ssh_dir, "%s/.ssh", home);
  mkdir (ssh_dir, 0700);
  snprintf (usual, sizeof usual, "%s/id_ed25519", ssh_dir);
  write_file (usual, keytext, kn, 0600);
  su.keyfile = NULL;
  easy = run (&w, &sv, &su);
  check (easy->done && easy->result == TWIST_OK, "usual key file");
  twist_easy_cleanup (easy);
  server_free (&sv);
  unlink (usual);

  /* A key file that is not a key, and one that is missing.  */
  check (server_new (&sv) == 0, "server 5");
  write_file (keyfile, "not a key\n", 10, 0600);
  su.keyfile = keyfile;
  easy = run (&w, &sv, &su);
  check (easy->done && easy->result == TWIST_ERR_AUTH
         && detail_has (easy, "cannot use"), "bad key file");
  twist_easy_cleanup (easy);
  server_free (&sv);
  check (server_new (&sv) == 0, "server 6");
  su.keyfile = "/nonexistent/key";
  easy = run (&w, &sv, &su);
  check (easy->done && easy->result == TWIST_ERR_FILE
         && detail_has (easy, "cannot read the private key"), "no key file");
  twist_easy_cleanup (easy);
  server_free (&sv);
  unlink (keyfile);
  rmdir (ssh_dir);
}

/* The host key: known_hosts, a pin, and -k.  */
static void
test_host_key (void)
{
  struct server sv;
  struct world w;
  struct twist_easy *easy;
  struct setup su = SETUP ("sftp://alice@127.0.0.1/data.bin", 1, "secret");
  char kh[300], fp[64];
  gf_key *other = NULL;

  /* Known: the transfer goes through.  */
  check (server_new (&sv) == 0, "server");
  known_hosts_with (sv.host, kh, sizeof kh);
  su.known_hosts = kh;
  easy = run (&w, &sv, &su);
  check (easy->done && easy->result == TWIST_OK, "known host");
  twist_easy_cleanup (easy);
  server_free (&sv);

  /* Not in the file.  */
  check (server_new (&sv) == 0, "server 2");
  known_hosts_with (NULL, kh, sizeof kh);
  easy = run (&w, &sv, &su);
  check (easy->done && easy->result == TWIST_ERR_HOSTKEY
         && detail_has (easy, "not in known_hosts")
         && detail_has (easy, "SHA256:"), "unknown host");
  check (got_len == 0, "nothing written for an unknown host");
  twist_easy_cleanup (easy);
  server_free (&sv);

  /* A different key for the host.  */
  check (server_new (&sv) == 0, "server 3");
  check (gf_key_generate (&other, GF_KEY_ED25519, 0) == GF_OK, "other key");
  known_hosts_with (other, kh, sizeof kh);
  easy = run (&w, &sv, &su);
  check (easy->done && easy->result == TWIST_ERR_HOSTKEY
         && detail_has (easy, "CHANGED"), "changed host key");
  twist_easy_cleanup (easy);
  gf_key_free (other);

  /* -k skips the file.  */
  server_free (&sv);
  check (server_new (&sv) == 0, "server 4");
  su.verify = 0;
  easy = run (&w, &sv, &su);
  check (easy->done && easy->result == TWIST_OK, "-k skips known_hosts");
  twist_easy_cleanup (easy);

  /* A pin is trusted without the file, with or without "SHA256:" and
     padding; a wrong one fails even with -k.  */
  server_free (&sv);
  check (server_new (&sv) == 0, "server 5");
  gf_key_fingerprint (sv.host, fp, sizeof fp);
  su.verify = 1;
  su.pin = fp + 7;
  known_hosts_with (NULL, kh, sizeof kh);
  easy = run (&w, &sv, &su);
  check (easy->done && easy->result == TWIST_OK, "pinned host");
  twist_easy_cleanup (easy);
  server_free (&sv);
  check (server_new (&sv) == 0, "server 6");
  su.pin = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
  su.verify = 0;
  easy = run (&w, &sv, &su);
  check (easy->done && easy->result == TWIST_ERR_HOSTKEY
         && detail_has (easy, "pinned"), "wrong pin, even with -k");
  twist_easy_cleanup (easy);
  server_free (&sv);

  /* A known_hosts file that was named and cannot be read.  */
  check (server_new (&sv) == 0, "server 7");
  su.pin = NULL;
  su.verify = 1;
  su.known_hosts = "/nonexistent/known_hosts";
  easy = run (&w, &sv, &su);
  check (easy->done && easy->result == TWIST_ERR_FILE
         && detail_has (easy, "known_hosts"), "named known_hosts unreadable");
  twist_easy_cleanup (easy);
  server_free (&sv);
  unlink (kh);
}


/* ---- upload, resume and ranges ---- */

static uint8_t big[BIG_LEN];

static void
preload (struct server *sv, const uint8_t *data, size_t n)
{
  sv->up = malloc (n + 1);
  memcpy (sv->up, data, n);
  sv->up_len = sv->up_cap = n;
  sv->up_exists = 1;
}

static int
got_is (const uint8_t *expect, size_t n)
{
  return got_len == n && (n == 0 || memcmp (got, expect, n) == 0);
}

static int
uploaded_is (const struct server *sv, const uint8_t *expect, size_t n)
{
  return sv->up_len == n && (n == 0 || memcmp (sv->up, expect, n) == 0);
}

/* More than the pipeline holds, from memory and through a read callback.
   The file is created and truncated, with the mode curl gives a new file.  */
static void
test_upload (size_t chunk, int streamed)
{
  struct server sv;
  struct world w;
  struct twist_easy *easy;
  struct setup su = SETUP ("sftp://alice@127.0.0.1/up.bin", 0, "secret");

  check (server_new (&sv) == 0, "server");
  su.upload = big;
  su.upload_len = sizeof big;
  su.streamed = streamed;
  su.chunk = chunk;
  easy = run (&w, &sv, &su);
  gf_session_receive (sv.s, now_us, w.c2s.data, w.c2s.len);
  check (easy->done && easy->result == TWIST_OK, "upload ends well");
  check (uploaded_is (&sv, big, sizeof big), "the whole file arrived");
  check ((sv.up_flags & (GF_FXF_WRITE | GF_FXF_CREAT | GF_FXF_TRUNC))
         == (GF_FXF_WRITE | GF_FXF_CREAT | GF_FXF_TRUNC),
         "created and truncated");
  check (sv.up_perms == 0644, "new files are 0644");
  check (sv.first_write == 0, "from the start");
  check (sv.writes >= 40, "in chunks");
  check (sv.closed_handle, "handle closed");
  twist_easy_cleanup (easy);
  server_free (&sv);
}

/* Nothing to send still makes the file, and a longer file that was there
   is gone.  scp:// is the same.  */
static void
test_upload_empty_and_replace (void)
{
  static uint8_t none[1] = { 0 };
  struct server sv;
  struct world w;
  struct twist_easy *easy;
  struct setup su = SETUP ("scp://alice@127.0.0.1/up.bin", 0, "secret");

  check (server_new (&sv) == 0, "server");
  su.upload = none;
  su.upload_len = 0;
  easy = run (&w, &sv, &su);
  check (easy->done && easy->result == TWIST_OK && sv.up_exists
         && sv.up_len == 0 && sv.writes == 0, "an empty file");
  twist_easy_cleanup (easy);
  server_free (&sv);

  check (server_new (&sv) == 0, "server 2");
  preload (&sv, big, 500000);
  su.upload = content;
  su.upload_len = sizeof content;
  easy = run (&w, &sv, &su);
  check (easy->done && easy->result == TWIST_OK
         && uploaded_is (&sv, content, sizeof content),
         "a longer file is replaced, not overwritten in place");
  twist_easy_cleanup (easy);
  server_free (&sv);
}

/* Continue an upload: the offset given, found by asking, and the file not
   there yet.  What was already on the server is not sent again and not
   truncated.  */
static void
test_upload_resume (void)
{
  struct server sv;
  struct world w;
  struct twist_easy *easy;
  struct setup su = SETUP ("sftp://alice@127.0.0.1/up.bin", 0, "secret");

  su.upload = content;
  su.upload_len = sizeof content;

  check (server_new (&sv) == 0, "server");
  preload (&sv, content, 40000);
  su.resume = 40000;
  easy = run (&w, &sv, &su);
  check (easy->done && easy->result == TWIST_OK
         && uploaded_is (&sv, content, sizeof content), "resume at an offset");
  check (sv.first_write == 40000, "the first write is at the offset");
  check (!(sv.up_flags & GF_FXF_TRUNC), "not truncated");
  twist_easy_cleanup (easy);
  server_free (&sv);

  /* Ask the server how much it has.  */
  check (server_new (&sv) == 0, "server 2");
  preload (&sv, content, 25000);
  su.resume = -1;
  easy = run (&w, &sv, &su);
  check (easy->done && easy->result == TWIST_OK
         && uploaded_is (&sv, content, sizeof content) && sv.first_write == 25000
         && !(sv.up_flags & GF_FXF_TRUNC), "resume by asking");
  twist_easy_cleanup (easy);
  server_free (&sv);

  /* Asking, and there is no file: it starts from nothing.  */
  check (server_new (&sv) == 0, "server 3");
  easy = run (&w, &sv, &su);
  check (easy->done && easy->result == TWIST_OK
         && uploaded_is (&sv, content, sizeof content) && sv.first_write == 0
         && (sv.up_flags & GF_FXF_CREAT), "asking about a file not there");
  twist_easy_cleanup (easy);
  server_free (&sv);

  /* Through a read callback, which has to throw the start away.  */
  check (server_new (&sv) == 0, "server 4");
  preload (&sv, content, 30000);
  su.resume = 30000;
  su.streamed = 1;
  easy = run (&w, &sv, &su);
  check (easy->done && easy->result == TWIST_OK
         && uploaded_is (&sv, content, sizeof content), "resume, streamed");
  twist_easy_cleanup (easy);
  server_free (&sv);
  su.streamed = 0;

  /* An offset the files do not agree with.  */
  check (server_new (&sv) == 0, "server 5");
  preload (&sv, content, 10000);
  su.resume = 40000;
  easy = run (&w, &sv, &su);
  check (easy->done && easy->result == TWIST_ERR_RESUME
         && detail_has (easy, "shorter") && sv.writes == 0,
         "the remote file is shorter than the offset");
  twist_easy_cleanup (easy);
  server_free (&sv);

  check (server_new (&sv) == 0, "server 6");
  easy = run (&w, &sv, &su);
  check (easy->done && easy->result == TWIST_ERR_RESUME
         && detail_has (easy, "does not exist"), "no file to resume");
  twist_easy_cleanup (easy);
  server_free (&sv);

  check (server_new (&sv) == 0, "server 7");
  preload (&sv, content, 60000);
  su.upload_len = 1000;
  su.resume = 5000;
  easy = run (&w, &sv, &su);
  check (easy->done && easy->result == TWIST_ERR_RESUME
         && detail_has (easy, "data to upload is shorter"),
         "the data is shorter than the offset");
  twist_easy_cleanup (easy);
  server_free (&sv);
  su.upload_len = sizeof content;
  su.streamed = 1;
  check (server_new (&sv) == 0, "server 8");
  preload (&sv, content, 60000);
  su.upload_len = 1000;
  easy = run (&w, &sv, &su);
  check (easy->done && easy->result == TWIST_ERR_RESUME,
         "the data is shorter than the offset, streamed");
  twist_easy_cleanup (easy);
  server_free (&sv);
}

/* What goes wrong with an upload, and the curl tool's status for it.  */
static void
test_upload_errors (void)
{
  struct server sv;
  struct world w;
  struct twist_easy *easy;
  struct setup su = SETUP ("sftp://alice@127.0.0.1/nodir/x", 0, "secret");

  su.upload = content;
  su.upload_len = sizeof content;

  check (server_new (&sv) == 0, "server");
  easy = run (&w, &sv, &su);
  check (easy->done && easy->result == TWIST_ERR_FILE
         && easy->proto_status == 25 && detail_has (easy, "/nodir/x"),
         "cannot create the file");
  twist_easy_cleanup (easy);
  server_free (&sv);

  check (server_new (&sv) == 0, "server 2");
  su.url = "sftp://alice@127.0.0.1/denied";
  easy = run (&w, &sv, &su);
  check (easy->done && easy->result == TWIST_ERR_FILE
         && easy->proto_status == 9, "an open refused is access denied");
  twist_easy_cleanup (easy);
  server_free (&sv);

  su.url = "sftp://alice@127.0.0.1/up.bin";
  check (server_new (&sv) == 0, "server 3");
  sv.write_status = GF_FX_FAILURE;
  easy = run (&w, &sv, &su);
  check (easy->done && easy->result == TWIST_ERR_FILE
         && easy->proto_status == 25 && detail_has (easy, "no room"),
         "a write fails");
  twist_easy_cleanup (easy);
  server_free (&sv);

  check (server_new (&sv) == 0, "server 4");
  sv.write_status = GF_FX_PERMISSION_DENIED;
  easy = run (&w, &sv, &su);
  check (easy->done && easy->result == TWIST_ERR_FILE
         && easy->proto_status == 9, "a write is refused");
  twist_easy_cleanup (easy);
  server_free (&sv);

  /* A directory, and what a library caller can get wrong.  */
  check (server_new (&sv) == 0, "server 5");
  su.url = "sftp://alice@127.0.0.1/dir/";
  easy = run (&w, &sv, &su);
  check (easy->done && easy->result == TWIST_ERR_URL
         && detail_has (easy, "names a directory"), "upload to a directory");
  twist_easy_cleanup (easy);
  server_free (&sv);

  check (server_new (&sv) == 0, "server 6");
  su.url = "sftp://alice@127.0.0.1/up.bin";
  su.range = "0-9";
  easy = run (&w, &sv, &su);
  check (easy->done && easy->result == TWIST_ERR_INVAL
         && detail_has (easy, "range does not apply"), "a range and an upload");
  twist_easy_cleanup (easy);
  server_free (&sv);
}

/* Download from an offset, and the checks that go with it.  */
static void
test_download_resume (void)
{
  struct server sv;
  struct world w;
  struct twist_easy *easy;
  struct setup su = SETUP ("sftp://alice@127.0.0.1/data.bin", 0, "secret");

  check (server_new (&sv) == 0, "server");
  su.resume = 30000;
  easy = run (&w, &sv, &su);
  check (easy->done && easy->result == TWIST_OK
         && got_is (content + 30000, sizeof content - 30000)
         && sv.first_read == 30000, "resume a download");
  check (easy->size_download == sizeof content - 30000, "only the rest counted");
  twist_easy_cleanup (easy);
  server_free (&sv);

  /* All of it is there already.  */
  check (server_new (&sv) == 0, "server 2");
  su.resume = (long long) sizeof content;
  easy = run (&w, &sv, &su);
  check (easy->done && easy->result == TWIST_OK && got_len == 0
         && sv.reads == 0, "nothing left to fetch");
  twist_easy_cleanup (easy);
  server_free (&sv);

  /* More than there is.  */
  check (server_new (&sv) == 0, "server 3");
  su.resume = 200000;
  easy = run (&w, &sv, &su);
  check (easy->done && easy->result == TWIST_ERR_RESUME && sv.reads == 0
         && detail_has (easy, "shorter"), "resume beyond the end");
  twist_easy_cleanup (easy);
  server_free (&sv);

  /* A server that does not say how big the file is cannot be checked, and
     the transfer goes on.  */
  check (server_new (&sv) == 0, "server 4");
  sv.hide_size = 1;
  su.resume = 30000;
  easy = run (&w, &sv, &su);
  check (easy->done && easy->result == TWIST_OK
         && got_is (content + 30000, sizeof content - 30000),
         "resume without a size");
  twist_easy_cleanup (easy);
  server_free (&sv);

  /* A library caller cannot ask a download to find its own offset.  */
  check (server_new (&sv) == 0, "server 5");
  su.resume = -1;
  easy = run (&w, &sv, &su);
  check (easy->done && easy->result == TWIST_ERR_INVAL, "no automatic offset");
  twist_easy_cleanup (easy);
  server_free (&sv);

  check (server_new (&sv) == 0, "server 6");
  su.resume = 100;
  su.range = "0-9";
  easy = run (&w, &sv, &su);
  check (easy->done && easy->result == TWIST_ERR_INVAL
         && detail_has (easy, "cannot be used together"), "resume and range");
  twist_easy_cleanup (easy);
  server_free (&sv);
}

/* One range, and what its bytes are.  */
static void
range_case (const char *range, size_t from, size_t n, int max_read,
            const char *what)
{
  struct server sv;
  struct world w;
  struct twist_easy *easy;
  struct setup su = SETUP ("sftp://alice@127.0.0.1/data.bin", 0, "secret");

  check (server_new (&sv) == 0, "server");
  sv.max_read = (size_t) max_read;
  su.range = range;
  easy = run (&w, &sv, &su);
  check (easy->done && easy->result == TWIST_OK && got_is (content + from, n),
         what);
  twist_easy_cleanup (easy);
  server_free (&sv);
}

static void
range_error (const char *range, int hide_size, const char *what)
{
  struct server sv;
  struct world w;
  struct twist_easy *easy;
  struct setup su = SETUP ("sftp://alice@127.0.0.1/data.bin", 0, "secret");

  check (server_new (&sv) == 0, "server");
  sv.hide_size = hide_size;
  su.range = range;
  easy = run (&w, &sv, &su);
  check (easy->done && easy->result == TWIST_ERR_RANGE, what);
  twist_easy_cleanup (easy);
  server_free (&sv);
}

static void
test_ranges (void)
{
  range_case ("100-199", 100, 100, 0, "FIRST-LAST");
  range_case ("0-0", 0, 1, 0, "one byte");
  range_case ("32760-32780", 32760, 21, 0, "across a chunk boundary");
  range_case ("99990-", 99990, 10, 0, "FIRST-");
  range_case ("-50", sizeof content - 50, 50, 0, "the last COUNT bytes");
  range_case ("-500000", 0, sizeof content, 0, "COUNT longer than the file");
  range_case ("0-99999", 0, sizeof content, 0, "the whole file as a range");
  range_case ("0-1000000", 0, sizeof content, 0, "LAST beyond the end");
  range_case ("1000-70000", 1000, 69001, 5000, "short reads in a range");
  range_error ("-50", 1, "the end of a file of unknown size");
  range_error ("200000-", 0, "FIRST beyond the end");
  range_error ("bogus", 0, "not a range");
  range_error ("5-2", 0, "LAST before FIRST");
  range_error ("1-2,5-6", 0, "more than one range");
  range_error ("-0", 0, "an empty tail");
  range_error ("", 0, "an empty range");
}

/* ---- directory listings ---- */

static int
text_is (const char *expect)
{
  return got_len == strlen (expect) && memcmp (got, expect, got_len) == 0;
}

/* The listing of main_dir.  What a server sends is not to be trusted with
   the terminal or the line structure of the output: a newline in a name
   would make a line that is not an entry, and a control character can do
   anything to a terminal.  Control characters, and the UTF-8 form of the C1
   ones, come out as ?.  */
#define MAIN_DIR_LONG \
  "drwxr-xr-x    3 u g 4096 Oct 21 14:04 .\n" \
  "drwxr-xr-x    4 u g 4096 Oct 21 14:04 ..\n" \
  "-rw-r--r--    1 u g    6 Oct 21 14:04 plain.txt\n" \
  "-rw-r--r--    1 u g    1 Oct 21 14:04 with space.txt\n" \
  "-rw-r--r--    1 u g    1 Oct 21 14:04 esc?[31mred\n" \
  "-rw-r--r--    1 u g    1 Oct 21 14:04 new?line\n" \
  "-rw-r--r--    1 u g    1 Oct 21 14:04 caf\xc3\xa9\n" \
  "-rw-r--r--    1 u g    1 Oct 21 14:04 csi?31m\n" \
  "nolong\n"
#define MAIN_DIR_NAMES \
  ".\n..\nplain.txt\nwith space.txt\nesc?[31mred\nnew?line\ncaf\xc3\xa9\n" \
  "csi?31m\nnolong\n"

static void
list_case (const char *url, int list_only, const char *expect,
           const char *path_seen, const char *what)
{
  struct server sv;
  struct world w;
  struct twist_easy *easy;
  struct setup su = SETUP (url, 0, "secret");

  check (server_new (&sv) == 0, "server");
  su.list_only = list_only;
  easy = run (&w, &sv, &su);
  check (easy->done && easy->result == TWIST_OK && text_is (expect), what);
  check (strcmp (sv.opened, path_seen) == 0, "the directory asked for");
  check (sv.closed_handle, "the directory handle was closed");
  twist_easy_cleanup (easy);
  server_free (&sv);
}

/* The state of a test is large (a server and a world hold megabytes of pipe),
   so the cases are called one after another, not from inside each other.  */
static void
test_listing_more (void)
{
  struct server sv;
  struct world w;
  struct twist_easy *easy;
  struct setup su = SETUP ("sftp://alice@127.0.0.1/big/", 0, "secret");
  char line[96], *want;
  size_t i, off = 0;

  /* Nothing in it.  */
  check (server_new (&sv) == 0, "server");
  su.url = "sftp://alice@127.0.0.1/empty/";
  easy = run (&w, &sv, &su);
  check (easy->done && easy->result == TWIST_OK && got_len == 0,
         "an empty directory");
  twist_easy_cleanup (easy);
  server_free (&sv);

  /* More entries than one answer holds, in the order the server gave.  */
  check (server_new (&sv) == 0, "server");
  sv.batch = 64;
  su.url = "sftp://alice@127.0.0.1/big/";
  easy = run (&w, &sv, &su);
  want = malloc (BIG_DIR_N * 96);
  for (i = 0; i < BIG_DIR_N; i++)
    off += (size_t) snprintf (want + off, 96, "%s\n", big_dir[i].longname);
  check (easy->done && easy->result == TWIST_OK && got_len == off
         && memcmp (got, want, off) == 0, "a big directory, in order");
  check (sv.readdirs >= BIG_DIR_N / 64, "read in many answers");
  snprintf (line, sizeof line, "%s\n", big_dir[BIG_DIR_N - 1].longname);
  check (got_len >= strlen (line)
         && memcmp (got + got_len - strlen (line), line, strlen (line)) == 0,
         "the last entry");
  free (want);
  twist_easy_cleanup (easy);
  server_free (&sv);

  /* What the server says about a directory that cannot be listed.  */
  check (server_new (&sv) == 0, "server");
  su.url = "sftp://alice@127.0.0.1/nope/";
  easy = run (&w, &sv, &su);
  check (easy->done && easy->result == TWIST_ERR_FILE
         && easy->proto_status == 78 && detail_has (easy, "directory")
         && detail_has (easy, "/nope"), "no such directory");
  twist_easy_cleanup (easy);
  server_free (&sv);
  check (server_new (&sv) == 0, "server");
  su.url = "sftp://alice@127.0.0.1/denied/";
  easy = run (&w, &sv, &su);
  check (easy->done && easy->result == TWIST_ERR_FILE
         && easy->proto_status == 9 && detail_has (easy, "not for you"),
         "a directory that may not be listed");
  twist_easy_cleanup (easy);
  server_free (&sv);
  check (server_new (&sv) == 0, "server");
  su.url = "sftp://alice@127.0.0.1/data.bin/";
  easy = run (&w, &sv, &su);
  check (easy->done && easy->result == TWIST_ERR_FILE
         && easy->proto_status == 78, "a file with a slash after it");
  twist_easy_cleanup (easy);
  server_free (&sv);

  /* The application refuses the text part way.  */
  check (server_new (&sv) == 0, "server");
  su.url = "sftp://alice@127.0.0.1/dir/";
  collect_limit = 60;
  easy = run (&w, &sv, &su);
  collect_limit = 0;
  check (easy->done && easy->result == TWIST_ERR_ABORTED,
         "a listing the application refuses");
  twist_easy_cleanup (easy);
  server_free (&sv);

  /* A range or a resume means nothing for a directory.  */
  check (server_new (&sv) == 0, "server");
  su.range = "0-9";
  easy = run (&w, &sv, &su);
  check (easy->done && easy->result == TWIST_ERR_INVAL
         && detail_has (easy, "does not apply"), "a range and a directory");
  twist_easy_cleanup (easy);
  server_free (&sv);
  check (server_new (&sv) == 0, "server");
  su.range = NULL;
  su.resume = 10;
  easy = run (&w, &sv, &su);
  check (easy->done && easy->result == TWIST_ERR_INVAL
         && detail_has (easy, "does not apply"), "a resume and a directory");
  twist_easy_cleanup (easy);
  server_free (&sv);

  /* scp does not list: it names one file.  */
  check (server_new (&sv) == 0, "server");
  su.resume = 0;
  su.url = "scp://alice@127.0.0.1/dir/";
  easy = run (&w, &sv, &su);
  check (easy->done && easy->result == TWIST_ERR_FILE
         && easy->proto_status == 78 && detail_has (easy, "sftp://")
         && got_len == 0, "scp does not list a directory");
  twist_easy_cleanup (easy);
  server_free (&sv);
}

static void
test_listing (void)
{
  /* The server's long form of each entry, as it sent them, and names only.  */
  list_case ("sftp://alice@127.0.0.1/dir/", 0, MAIN_DIR_LONG, "/dir",
             "a listing, long form");
  list_case ("sftp://alice@127.0.0.1/dir/", 1, MAIN_DIR_NAMES, "/dir",
             "a listing, names only");
  /* Every way of naming a directory.  */
  list_case ("sftp://alice@127.0.0.1/", 1, MAIN_DIR_NAMES, "/", "the root");
  list_case ("sftp://alice@127.0.0.1", 1, MAIN_DIR_NAMES, "/",
             "no path at all");
  list_case ("sftp://alice@127.0.0.1/~/", 1, MAIN_DIR_NAMES, ".",
             "the home directory");
  list_case ("sftp://alice@127.0.0.1/~/sub/", 1, MAIN_DIR_NAMES, "sub",
             "a directory under home");
  list_case ("sftp://alice@127.0.0.1/dir///", 1, MAIN_DIR_NAMES, "/dir",
             "slashes at the end");
  test_listing_more ();
}

/* A peer that is not SSH-2.  */
static void
test_bad_peer (void)
{
  static const char old[] = "SSH-1.5-ancient\r\n";
  struct twist_easy *easy;
  struct world w;
  struct server sv;
  struct setup su = SETUP ("sftp://alice@127.0.0.1/data.bin", 0, "secret");

  memset (&sv, 0, sizeof sv);
  easy = start (&w, &sv, &su);
  check (twist_ssh_start (w.ssh) == TWIST_OK, "start");
  twist_ssh_receive (w.ssh, (const uint8_t *) old, sizeof old - 1);
  check (easy->done && easy->result == TWIST_ERR_PROTOCOL, "SSH-1 refused");
  twist_easy_cleanup (easy);
}

/* A server that never answers: the key exchange has a deadline, and the
   timeout is reported as one.  */
static void
test_timeout (void)
{
  struct twist_easy *easy;
  struct world w;
  struct server sv;
  struct setup su = SETUP ("sftp://alice@127.0.0.1/data.bin", 0, "secret");
  uint64_t due;

  memset (&sv, 0, sizeof sv);
  easy = start (&w, &sv, &su);
  check (twist_ssh_start (w.ssh) == TWIST_OK, "start");
  due = twist_ssh_deadline (w.ssh);
  check (due != UINT64_MAX && due > now_us, "deadline set");
  twist_ssh_set_time (w.ssh, due);
  twist_ssh_timeout (w.ssh);
  check (easy->done && easy->result == TWIST_ERR_TIMEOUT, "timeout");
  twist_easy_cleanup (easy);
}

/* No user name at all.  */
static void
test_no_user (void)
{
  struct twist_easy *easy = twist_easy_init ();
  struct twist_ssh *ssh;
  struct pipe *sink = calloc (1, sizeof *sink);

  check (twist_url_parse_int ("sftp://127.0.0.1/data.bin", &easy->url)
         == TWIST_OK, "url");
  ssh = twist_ssh_new (easy, 0);
  twist_ssh_set_sink (ssh, client_sink, sink);
  check (twist_ssh_start (ssh) == TWIST_ERR_AUTH
         && detail_has (easy, "no user name"), "no user");
  twist_easy_cleanup (easy);
  free (sink);
}

/* Wait, driving the loop, until COND holds or about two seconds pass.  */
#define WAIT_FOR(multi, cond)                                           \
  do                                                                    \
    {                                                                   \
      struct timespec nap_ = { 0, 2000000 };                            \
      int running_ = 0, spins_;                                         \
                                                                        \
      for (spins_ = 0; spins_ < 1000 && !(cond); spins_++)              \
        {                                                               \
          twist_multi_perform ((multi), &running_);                     \
          nanosleep (&nap_, NULL);                                      \
        }                                                               \
    }                                                                   \
  while (0)

/* Put EASY on MULTI's loop and storage pool without starting a transfer:
   twist_multi_add_handle would start the real handler, which dials.  The
   handler under test is driven by hand.  */
static void
attach_by_hand (struct twist_multi *multi, struct twist_easy *easy)
{
  easy->multi = multi;
  easy->loop = multi->loop;
}

/* With a real loop and storage pool the files are read and parsed on a
   worker thread, and the loop takes the result.  The key and the
   known_hosts file are the server's, so the transfer only succeeds if what
   the worker made is what the session uses.  */
static void
test_off_the_loop (void)
{
  struct server sv;
  struct world w;
  struct twist_multi *multi = twist_multi_init ();
  struct twist_easy *easy = twist_easy_init ();
  char keytext[2048], keyfile[300], kh[300];
  size_t kn = 0;

  check (multi != NULL && server_new (&sv) == 0, "server and multi");
  check (gf_key_to_openssh_private (sv.authorized, keytext, sizeof keytext,
                                    &kn) == GF_OK, "key text");
  snprintf (keyfile, sizeof keyfile, "%s/poolkey", home);
  write_file (keyfile, keytext, kn, 0600);
  known_hosts_with (sv.host, kh, sizeof kh);
  check (twist_url_parse_int ("sftp://alice@127.0.0.1/data.bin", &easy->url)
         == TWIST_OK, "url");
  twist_easy_setopt (easy, TWISTOPT_SSLKEY, keyfile);
  twist_easy_setopt (easy, TWISTOPT_SSH_KNOWNHOSTS, kh);
  easy->write_cb = collect;
  got_len = 0;
  attach_by_hand (multi, easy);
  w.sv = &sv;
  w.c2s.len = 0;
  w.ssh = twist_ssh_new (easy, 0);
  twist_ssh_set_sink (w.ssh, client_sink, &w.c2s);
  check (twist_ssh_start (w.ssh) == TWIST_OK, "start submits the job");
  /* The server's first bytes can arrive before the files are loaded.  A
     handler that cannot use them yet must not take them: the connection
     keeps what is not taken and offers it again.  The session cannot exist
     yet, because the loop has not run.  */
  {
    size_t took = twist_ssh_receive (w.ssh, sv.out.data, sv.out.len);

    check (took == 0, "bytes offered before the session exists are not taken");
    if (took > 0)
      {
        memmove (sv.out.data, sv.out.data + took, sv.out.len - took);
        sv.out.len -= took;
      }
  }
  WAIT_FOR (multi, w.c2s.len > 0 || easy->done);
  check (w.c2s.len > 0, "the session started when the job was done");
  check (w.ssh->load_thread_set
         && !pthread_equal (w.ssh->load_thread, pthread_self ()),
         "the files were read off the loop thread");
  pump (&w, easy, 65536);
  check (easy->done && easy->result == TWIST_OK
         && got_len == sizeof content && memcmp (got, content, got_len) == 0,
         "download with a key and known_hosts loaded by the pool");
  twist_easy_cleanup (easy);
  twist_multi_cleanup (multi);
  server_free (&sv);
  unlink (keyfile);
  unlink (kh);
}

/* What the job finds wrong comes back through the loop as the end of the
   transfer.  */
static void
test_off_the_loop_errors (void)
{
  struct server sv;
  struct world w;
  struct twist_multi *multi = twist_multi_init ();
  struct twist_easy *easy = twist_easy_init ();

  check (multi != NULL && server_new (&sv) == 0, "server and multi");
  check (twist_url_parse_int ("sftp://alice@127.0.0.1/data.bin", &easy->url)
         == TWIST_OK, "url");
  twist_easy_setopt (easy, TWISTOPT_SSLKEY, "/nonexistent/key");
  attach_by_hand (multi, easy);
  w.sv = &sv;
  w.c2s.len = 0;
  w.ssh = twist_ssh_new (easy, 0);
  twist_ssh_set_sink (w.ssh, client_sink, &w.c2s);
  check (twist_ssh_start (w.ssh) == TWIST_OK, "start submits the job");
  WAIT_FOR (multi, easy->done);
  check (easy->done && easy->result == TWIST_ERR_FILE
         && detail_has (easy, "cannot read the private key"),
         "the job's error ends the transfer");
  check (w.c2s.len == 0, "nothing was sent");
  twist_easy_cleanup (easy);
  twist_multi_cleanup (multi);
  server_free (&sv);
}

/* A transfer that goes away while its job is queued or running: the job
   finishes by itself and frees what it made.  Whichever happens first, the
   result must not be touched; valgrind finds it if it is.  */
static void
test_abandoned_job (void)
{
  int i;

  for (i = 0; i < 60; i++)
    {
      struct twist_multi *multi = twist_multi_init ();
      struct twist_easy *easy = twist_easy_init ();
      struct twist_ssh *ssh;
      struct pipe *sink = calloc (1, sizeof *sink);
      struct timespec nap = { 0, 300000 * (i % 7) };

      check (multi != NULL && sink != NULL, "multi");
      check (twist_url_parse_int ("sftp://alice@127.0.0.1/data.bin",
                                  &easy->url) == TWIST_OK, "url");
      twist_easy_setopt (easy, TWISTOPT_PASSWORD, "secret");
      twist_easy_setopt (easy, TWISTOPT_SSL_VERIFYPEER, 0L);
      attach_by_hand (multi, easy);
      ssh = twist_ssh_new (easy, 0);
      twist_ssh_set_sink (ssh, client_sink, sink);
      check (twist_ssh_start (ssh) == TWIST_OK, "start");
      nanosleep (&nap, NULL);
      /* Drop the transfer, then let the loop see whatever the job posted.  */
      twist_easy_cleanup (easy);
      {
        int running = 0, k;

        for (k = 0; k < 20; k++)
          twist_multi_perform (multi, &running);
      }
      twist_multi_cleanup (multi);
      free (sink);
    }
}

int
main (void)
{
  size_t i;

  /* foxtrot refuses a libgcrypt older than the version it was written
     against, and then nothing here can run.  Say so, and skip.  */
  if (gf_crypto_init () != GF_OK)
    {
      fputs ("test-ssh: libgcrypt is older than foxtrot requires "
             "(1.12.4); skipping\n", stderr);
      return 77;
    }
  snprintf (home, sizeof home, "/tmp/twist-test-ssh-%ld", (long) getpid ());
  mkdir (home, 0700);
  setenv ("HOME", home, 1);
  for (i = 0; i < sizeof content; i++)
    content[i] = (uint8_t) (i * 7 + (i >> 8));
  for (i = 0; i < sizeof big; i++)
    big[i] = (uint8_t) (i * 13 + (i >> 11) + 5);
  make_big_dir ();
  test_download (65536);
  test_download (64);
  test_download (1);
  test_short_reads ();
  test_empty_file ();
  test_paths ();
  test_file_errors ();
  test_upload (65536, 0);
  test_upload (4096, 1);
  test_upload_empty_and_replace ();
  test_upload_resume ();
  test_upload_errors ();
  test_download_resume ();
  test_ranges ();
  test_listing ();
  test_no_subsystem ();
  test_auth ();
  test_host_key ();
  test_bad_peer ();
  test_timeout ();
  test_no_user ();
  test_off_the_loop ();
  test_off_the_loop_errors ();
  test_abandoned_job ();
  rmdir (home);
  return tests_finish ();
}
