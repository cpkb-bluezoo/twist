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
#include <unistd.h>

/* The twist handler is the client; a foxtrot session is the server, in the
   same process, authenticating and serving a file over SFTP.  Each side's
   output is collected and handed to the other, so the exchange can be cut
   into pieces of any size.  HOME is a directory of our own, so that nothing
   of the person running the tests is read.  */

#define PIPE_MAX (1024 * 1024)
#define FILE_LEN 100000

struct pipe
{
  uint8_t data[PIPE_MAX];
  size_t len;
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
sv_sftp_request (void *user, const gf_sftp_request *req)
{
  struct server *sv = user;
  static const uint8_t handle[] = { 'F', '1' };

  switch (req->type)
    {
    case GF_FXP_OPEN:
      snprintf (sv->opened, sizeof sv->opened, "%.*s", (int) req->path.len,
                (const char *) req->path.data);
      if (strcmp (sv->opened, "/data.bin") == 0
          || strcmp (sv->opened, "data.bin") == 0)
        return gf_sftp_server_handle (sv->sftp, req->id, handle,
                                      sizeof handle) != GF_OK;
      if (strcmp (sv->opened, "/denied") == 0)
        return gf_sftp_server_status (sv->sftp, req->id,
                                      GF_FX_PERMISSION_DENIED,
                                      "not for you") != GF_OK;
      return gf_sftp_server_status (sv->sftp, req->id, GF_FX_NO_SUCH_FILE,
                                    "") != GF_OK;
    case GF_FXP_READ:
      {
        size_t n;

        if (req->offset >= sv->filelen)
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

static size_t
collect (char *ptr, size_t size, size_t nmemb, void *user)
{
  size_t n = size * nmemb;

  (void) user;
  if (got_len + n > sizeof got)
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
};

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
  struct setup su = { "sftp://alice@127.0.0.1/data.bin", 0, "secret", NULL,
                      NULL, NULL, 0 };

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
  struct setup su = { "sftp://alice@127.0.0.1/data.bin", 0, "secret", NULL,
                      NULL, NULL, 0 };

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
  struct setup su = { "sftp://alice@127.0.0.1/data.bin", 0, "secret", NULL,
                      NULL, NULL, 0 };

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
  struct setup su = { "scp://alice@127.0.0.1/~/data.bin", 0, "secret", NULL,
                      NULL, NULL, 0 };

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

  /* A wildcard in an scp URL, and a directory, are refused up front.  */
  check (server_new (&sv) == 0, "server 3");
  su.url = "scp://alice@127.0.0.1/dir/*.txt";
  easy = run (&w, &sv, &su);
  check (easy->done && easy->result == TWIST_ERR_URL
         && detail_has (easy, "wildcards"), "scp wildcard");
  twist_easy_cleanup (easy);
  server_free (&sv);
  check (server_new (&sv) == 0, "server 4");
  su.url = "sftp://alice@127.0.0.1/dir/";
  easy = run (&w, &sv, &su);
  check (easy->done && easy->result == TWIST_ERR_UNSUPPORTED
         && detail_has (easy, "listing"), "directory");
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
  struct setup su = { "sftp://alice@127.0.0.1/nope", 0, "secret", NULL, NULL,
                      NULL, 0 };

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
  struct setup su = { "scp://alice@127.0.0.1/data.bin", 0, "secret", NULL,
                      NULL, NULL, 0 };

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
  struct setup su = { "sftp://alice@127.0.0.1/data.bin", 0, "wrong", NULL,
                      NULL, NULL, 0 };
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
  struct setup su = { "sftp://alice@127.0.0.1/data.bin", 1, "secret", NULL,
                      NULL, NULL, 0 };
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

/* A peer that is not SSH-2.  */
static void
test_bad_peer (void)
{
  static const char old[] = "SSH-1.5-ancient\r\n";
  struct twist_easy *easy;
  struct world w;
  struct server sv;
  struct setup su = { "sftp://alice@127.0.0.1/data.bin", 0, "secret", NULL,
                      NULL, NULL, 0 };

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
  struct setup su = { "sftp://alice@127.0.0.1/data.bin", 0, "secret", NULL,
                      NULL, NULL, 0 };
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
  test_download (65536);
  test_download (64);
  test_download (1);
  test_short_reads ();
  test_empty_file ();
  test_paths ();
  test_file_errors ();
  test_no_subsystem ();
  test_auth ();
  test_host_key ();
  test_bad_peer ();
  test_timeout ();
  test_no_user ();
  rmdir (home);
  return tests_finish ();
}
