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
#include <foxtrot/wire.h>
#include <foxtrot/crypto.h>
#include <foxtrot/key.h>
#include <foxtrot/knownhosts.h>
#include <foxtrot/session.h>
#include <foxtrot/sftp.h>
#include <foxtrot/status.h>

#include <arpa/inet.h>
#include <errno.h>
#include <ifaddrs.h>
#include <netdb.h>
#include <net/if.h>
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
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

/* What a hostile server puts in a status message: a terminal escape that sets
   the title, a line break and a carriage return to forge lines of output, a
   C1 control in UTF-8, and a good deal of text.  */
#define HOSTILE_TEXT "ok\033]0;pwned\007\nforged: line\rX\302\233[2J" \
  "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" \
  "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" \
  "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

struct server
{
  struct pipe out;
  gf_session *s;
  gf_key *host;
  int host_shared;		/* The key is another server's; not freed.  */
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
  /* More keys the server accepts, and the fingerprints it was offered, in
     order.  */
  gf_key *also[4];
  size_t nalso;
  char offered[16][64];
  unsigned noffered;
  /* Keyboard-interactive: what it asks, and what it was told.  */
  int kbd_mode;
  int kbd_stage;
  unsigned kbd_requests;
  size_t kbd_answers;		/* How many answers the last round had.  */
  size_t kbd_first_len;		/* The length of the first.  */
  /* The directory being listed.  */
  const struct dent *dents;
  size_t ndents, dpos;
  unsigned batch;		/* Entries to a READDIR answer.  */
  unsigned readdirs;
  /* What the requests other than reads and writes were, in order.  */
  struct
  {
    char what[12];
    char a[96], b[96];
    gf_sftp_attrs attrs;
  } ops[24];
  unsigned nops;
  char made[4][128];		/* Directories that mkdir made.  */
  unsigned nmade;
  uint32_t max_read_len;	/* The most any read asked for.  */
  unsigned cert_probes;		/* Certificates offered, and signed with.  */
  unsigned cert_logins;
  /* Answer the reads just past the end at once, which the client needs, and
     hold those far past it until the file is closed: a server may answer in
     any order.  */
  int late_eof;
  int hold_first;		/* Never answer the first read.  */
  uint32_t held[64];
  size_t nheld;
  int release_held;		/* Answer them now: the close was answered.  */
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

/* ---- keyboard-interactive, from the server ---- */

enum
{
  KBD_NONE = 0,
  KBD_PASSWORD,			/* One hidden prompt.  */
  KBD_TWO,			/* Two hidden prompts: a password and a code.  */
  KBD_ECHOED,			/* One prompt that is shown as typed.  */
  KBD_INFO_FIRST,		/* A round with no prompt, then a password.  */
  KBD_HOSTILE			/* An echoed prompt full of control characters.  */
};

static int
sv_kbd_prompt (struct server *sv)
{
  static const int hidden[2] = { 0, 0 };
  static const int shown[1] = { 1 };
  static const char *const password[1] = { "Password: " };
  static const char *const two[2] = { "Password: ", "Verification code: " };
  static const char *const user[1] = { "Username: " };
  static const char *const hostile[1] = { "Code:\033[31m\nDELETE ALL\r" };

  switch (sv->kbd_mode)
    {
    case KBD_PASSWORD:
      return gf_session_auth_kbdint_prompt (sv->s, "", "", 1, password, hidden);
    case KBD_TWO:
      return gf_session_auth_kbdint_prompt (sv->s, "", "", 2, two, hidden);
    case KBD_ECHOED:
      return gf_session_auth_kbdint_prompt (sv->s, "", "", 1, user, shown);
    case KBD_HOSTILE:
      return gf_session_auth_kbdint_prompt (sv->s, "", "", 1, hostile, shown);
    case KBD_INFO_FIRST:
      if (sv->kbd_stage == 0)
        return gf_session_auth_kbdint_prompt (sv->s, "info", "welcome", 0,
                                              NULL, NULL);
      return gf_session_auth_kbdint_prompt (sv->s, "", "", 1, password, hidden);
    default:
      return gf_session_auth_reject (sv->s, 0);
    }
}

static int
sv_kbd_response (void *user, const gf_slice *responses, size_t n)
{
  struct server *sv = user;

  sv->kbd_answers = n;
  sv->kbd_first_len = n > 0 ? responses[0].len : 0;
  if (sv->kbd_mode == KBD_INFO_FIRST && sv->kbd_stage == 0)
    {
      sv->kbd_stage = 1;
      return sv_kbd_prompt (sv) != GF_OK;
    }
  if ((sv->kbd_mode == KBD_PASSWORD || sv->kbd_mode == KBD_INFO_FIRST)
      && n == 1 && sv->password != NULL && responses[0].len == strlen (sv->password)
      && memcmp (responses[0].data, sv->password, responses[0].len) == 0)
    return gf_session_auth_accept (sv->s) != GF_OK;
  return gf_session_auth_reject (sv->s, 0) != GF_OK;
}

static unsigned next_server_methods;	/* For the next server; then reset.  */
/* When set, every server has this host key: one server, met again.  */
static gf_key *shared_host;
/* When set, every server trusts this CA for user certificates.  */
static const gf_key *trusted_ca;

static uint64_t
sv_unix_time (void *user)
{
  (void) user;
  return (uint64_t) time (NULL);
}

static int
sv_auth_request (void *user, const gf_auth_request *req)
{
  struct server *sv = user;
  int ok = 0;

  if (req->user.len != 5 || memcmp (req->user.data, "alice", 5) != 0)
    return gf_session_auth_reject (sv->s, 0) != GF_OK;
  if (req->method == GF_AUTH_KBDINT)
    {
      sv->kbd_requests++;
      sv->kbd_stage = 0;
      return sv_kbd_prompt (sv) != GF_OK;
    }
  if (req->method == GF_AUTH_PASSWORD && sv->password != NULL)
    ok = req->password.len == strlen (sv->password)
         && memcmp (req->password.data, sv->password, req->password.len) == 0;
  else if (req->method == GF_AUTH_PUBLICKEY)
    {
      int known = sv->authorized != NULL && gf_key_equal (req->key, sv->authorized);
      size_t i;

      /* A certificate got here only if the machine found it good: a trusted
         CA, its dates, the user among its principals.  */
      if (req->certificate)
        {
          known = 1;
          if (req->has_signature)
            sv->cert_logins++;
          else
            sv->cert_probes++;
        }

      for (i = 0; i < sv->nalso; i++)
        if (gf_key_equal (req->key, sv->also[i]))
          known = 1;
      if (!req->has_signature && sv->noffered < 16)
        gf_key_fingerprint (req->key, sv->offered[sv->noffered++], 64);
      if (known && !req->has_signature)
        return gf_session_auth_pk_ok (sv->s) != GF_OK;
      ok = known;
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
      a.flags = GF_FILEXFER_ATTR_SIZE | GF_FILEXFER_ATTR_UIDGID
                | GF_FILEXFER_ATTR_PERMISSIONS | GF_FILEXFER_ATTR_ACMODTIME;
      a.size = size;
      a.uid = 1000;
      a.gid = 100;
      a.permissions = 0100644;
      a.atime = 111;
      a.mtime = 222;
    }
  return gf_sftp_server_attrs (sv->sftp, id, &a) != GF_OK;
}

static void
log_op (struct server *sv, const char *what, const char *a, const char *b,
        const gf_sftp_attrs *attrs)
{
  if (sv->nops >= sizeof sv->ops / sizeof sv->ops[0])
    return;
  snprintf (sv->ops[sv->nops].what, sizeof sv->ops[0].what, "%s", what);
  snprintf (sv->ops[sv->nops].a, sizeof sv->ops[0].a, "%s", a);
  snprintf (sv->ops[sv->nops].b, sizeof sv->ops[0].b, "%s", b);
  if (attrs != NULL)
    sv->ops[sv->nops].attrs = *attrs;
  sv->nops++;
}

static int
dir_exists (const struct server *sv, const char *p)
{
  unsigned i;

  if (strcmp (p, "/dir") == 0)
    return 1;
  for (i = 0; i < sv->nmade; i++)
    if (strcmp (sv->made[i], p) == 0)
      return 1;
  return 0;
}

/* A place to upload up.bin to: its directories all exist.  */
static int
up_place (const struct server *sv, const char *p)
{
  const char *slash = strrchr (p, '/');
  char dir[96];
  char *cut;

  if (is_up (p))
    return 1;
  if (slash == NULL || strcmp (slash, "/up.bin") != 0 || slash == p)
    return 0;
  snprintf (dir, sizeof dir, "%.*s", (int) (slash - p), p);
  /* Every directory above must be there.  */
  for (cut = dir + 1; (cut = strchr (cut, '/')) != NULL; cut++)
    {
      char save = *cut;

      *cut = 0;
      if (!dir_exists (sv, dir))
        return 0;
      *cut = save;
    }
  return dir_exists (sv, dir);
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
      log_op (sv, "open", path, "", NULL);
      if (is_data (path) && !(req->pflags & GF_FXF_WRITE))
        return gf_sftp_server_handle (sv->sftp, req->id, fh,
                                      sizeof fh) != GF_OK;
      if (up_place (sv, path) && (req->pflags & GF_FXF_WRITE))
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
      if (strcmp (path, "/hostile") == 0)
        return gf_sftp_server_status (sv->sftp, req->id,
                                      GF_FX_PERMISSION_DENIED,
                                      HOSTILE_TEXT) != GF_OK;
      return gf_sftp_server_status (sv->sftp, req->id, GF_FX_NO_SUCH_FILE,
                                    "") != GF_OK;
    case GF_FXP_READ:
      {
        size_t n;

        if (sv->reads++ == 0)
          {
            sv->first_read = req->offset;
            if (sv->hold_first && !is_u && sv->nheld < 64)
              {
                sv->held[sv->nheld++] = req->id;
                return 0;
              }
          }
        if (req->length > sv->max_read_len)
          sv->max_read_len = req->length;
        if (!is_u && sv->late_eof && sv->nheld < 64
            && req->offset >= sv->filelen + 65536)
          {
            sv->held[sv->nheld++] = req->id;
            return 0;
          }
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
      log_op (sv, "stat", path, "", NULL);
      if (is_data (path))
        return sv_attrs_size (sv, req->id, sv->filelen);
      if (is_up (path) && sv->up_exists)
        return sv_attrs_size (sv, req->id, sv->up_len);
      return gf_sftp_server_status (sv->sftp, req->id, GF_FX_NO_SUCH_FILE,
                                    "") != GF_OK;
    case GF_FXP_MKDIR:
      log_op (sv, "mkdir", path, "", &req->attrs);
      if (dir_exists (sv, path) || strcmp (path, "/bad") == 0
          || sv->nmade >= 4)
        return gf_sftp_server_status (sv->sftp, req->id, GF_FX_FAILURE,
                                      "Failure") != GF_OK;
      snprintf (sv->made[sv->nmade++], sizeof sv->made[0], "%s", path);
      return gf_sftp_server_status (sv->sftp, req->id, GF_FX_OK, "") != GF_OK;
    case GF_FXP_REMOVE:
    case GF_FXP_RMDIR:
      log_op (sv, req->type == GF_FXP_REMOVE ? "remove" : "rmdir", path, "",
              NULL);
      if (strcmp (path, "/gone") == 0)
        return gf_sftp_server_status (sv->sftp, req->id, GF_FX_NO_SUCH_FILE,
                                      "") != GF_OK;
      if (strcmp (path, "/denied") == 0)
        return gf_sftp_server_status (sv->sftp, req->id,
                                      GF_FX_PERMISSION_DENIED, "") != GF_OK;
      if (strcmp (path, "/hostile") == 0)
        return gf_sftp_server_status (sv->sftp, req->id,
                                      GF_FX_PERMISSION_DENIED,
                                      HOSTILE_TEXT) != GF_OK;
      return gf_sftp_server_status (sv->sftp, req->id, GF_FX_OK, "") != GF_OK;
    case GF_FXP_RENAME:
    case GF_FXP_SYMLINK:
      {
        char second[96];

        snprintf (second, sizeof second, "%.*s", (int) req->path2.len,
                  (const char *) req->path2.data);
        log_op (sv, req->type == GF_FXP_RENAME ? "rename" : "symlink", path,
                second, NULL);
        return gf_sftp_server_status (sv->sftp, req->id, GF_FX_OK, "")
               != GF_OK;
      }
    case GF_FXP_SETSTAT:
      log_op (sv, "setstat", path, "", &req->attrs);
      if (strcmp (path, "/denied") == 0)
        return gf_sftp_server_status (sv->sftp, req->id,
                                      GF_FX_PERMISSION_DENIED, "") != GF_OK;
      return gf_sftp_server_status (sv->sftp, req->id, GF_FX_OK, "") != GF_OK;
    case GF_FXP_REALPATH:
      {
        gf_sftp_name name;

        log_op (sv, "realpath", path, "", NULL);
        memset (&name, 0, sizeof name);
        name.filename.data = (const uint8_t *) "/home/alice";
        name.filename.len = 11;
        return gf_sftp_server_names (sv->sftp, req->id, 1, &name) != GF_OK;
      }
    case GF_FXP_CLOSE:
      log_op (sv, "close", "", "", NULL);
      sv->closed_handle = 1;
      sv->release_held = sv->nheld > 0;
      return gf_sftp_server_status (sv->sftp, req->id, GF_FX_OK, "") != GF_OK;
    default:
      return gf_sftp_server_status (sv->sftp, req->id, GF_FX_OP_UNSUPPORTED,
                                    "") != GF_OK;
    }
}

/* The answers held back, sent after the close's.  */
static void
sv_release_held (struct server *sv)
{
  sv->release_held = 0;
  while (sv->nheld > 0)
    if (gf_sftp_server_status (sv->sftp, sv->held[--sv->nheld], GF_FX_EOF, "")
        != GF_OK)
      return;
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
  if (shared_host != NULL)
    {
      sv->host = shared_host;
      sv->host_shared = 1;
    }
  else if (gf_key_generate (&sv->host, GF_KEY_ED25519, 0) != GF_OK)
    return -1;
  if (gf_key_generate (&sv->authorized, GF_KEY_ED25519, 0) != GF_OK)
    return -1;
  sv->password = "secret";
  sv->file = content;
  sv->filelen = sizeof content;
  cfg.conn.software = "testd_1";
  cfg.conn.host_keys = &sv->host;
  cfg.conn.nhost_keys = 1;
  cfg.server_auth.methods = next_server_methods != 0
                            ? next_server_methods
                            : GF_AUTH_PASSWORD | GF_AUTH_PUBLICKEY;
  next_server_methods = 0;
  if (trusted_ca != NULL)
    {
      static const gf_key *cas[1];

      cas[0] = trusted_ca;
      cfg.server_auth.trusted_user_cas = cas;
      cfg.server_auth.ntrusted_user_cas = 1;
    }
  ev.unix_time = sv_unix_time;
  ev.user = sv;
  ev.auth_kbdint_response = sv_kbd_response;
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
  size_t i;

  for (i = 0; i < sv->nalso; i++)
    gf_key_free (sv->also[i]);
  free (sv->up);
  gf_session_free (sv->s);
  if (!sv->host_shared)
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
pump (struct world *w, struct twist_transfer *transfer, size_t chunk)
{
  int i;

  for (i = 0; i < 5000 && !transfer->done; i++)
    {
      size_t moved = 0;

      moved += drain (&w->c2s, chunk, to_server, w);
      moved += drain (&w->sv->out, chunk, to_client, w);
      if (moved == 0)
        break;
    }
}

/* As pump, with a loop to run: the files and the agent come back through it.
   Gives up after about three seconds in which nothing moves.  */
static void pump_with_loop (struct twist_runtime *runtime, struct world *w,
                            struct twist_transfer *transfer, size_t chunk);

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
pump_with_loop (struct twist_runtime *runtime, struct world *w,
                struct twist_transfer *transfer, size_t chunk)
{
  int idle = 0;
  struct timespec nap = { 0, 2000000 };

  while (!transfer->done && idle < 1500)
    {
      size_t moved = drain (&w->c2s, chunk, to_server, w);

      /* A connection keeps what the handler does not take, and offers it
         again; this pipe cannot, so the server's bytes wait until the
         client has a session to read them.  */
      if (w->ssh->session != NULL)
        moved += drain (&w->sv->out, chunk, to_client, w);
      twist_runtime_run_once (runtime, 0);
      if (moved != 0)
        idle = 0;
      else
        {
          idle++;
          nanosleep (&nap, NULL);
        }
    }
}

static void
write_file (const char *path, const char *text, size_t len, int mode)
{
  FILE *fp = fopen (path, "wb");

  if (fp != NULL)
    {
      /* On the open file, and before anything is written: the mode is of the
         file that was opened, not of whatever the path names a moment later,
         and a key is never in the file with the default mode.  */
      if (fchmod (fileno (fp), (mode_t) mode) == 0)
        fwrite (text, 1, len, fp);
      fclose (fp);
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
  struct twist_runtime *runtime;	/* Run on a real loop.  */
  const char *agent;		/* The agent socket option.  */
  unsigned agent_timeout_ms;
  struct twist_slist *quote, *postquote;
  int create_dirs;		/* Make missing directories for an upload.  */
  int nobody;			/* -I.  */
  int headers;			/* Collect what goes to the header callback.  */
};

/* Every field, so that none is forgotten: URL, whether to check the host key,
   and the password; the rest is for the test to set.  */
#define SETUP(url, verify, pw) \
  { (url), (verify), (pw), NULL, NULL, NULL, 0, NULL, 0, 0, 0, NULL, 0, NULL, NULL, 0, \
    NULL, NULL, 0, 0, 0 }

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

static size_t header_collect (char *ptr, size_t size, size_t nmemb, void *user);

static struct twist_transfer *
start (struct world *w, struct server *sv, const struct setup *su)
{
  struct twist_transfer *transfer = twist_transfer_new ();

  check (twist_url_parse_int (su->url, &transfer->url) == TWIST_OK, "url");
  transfer->verifypeer = su->verify;
  if (su->password != NULL)
    twist_transfer_setopt (transfer, TWISTOPT_PASSWORD, su->password);
  if (su->keyfile != NULL)
    twist_transfer_setopt (transfer, TWISTOPT_SSLKEY, su->keyfile);
  if (su->known_hosts != NULL)
    twist_transfer_setopt (transfer, TWISTOPT_SSH_KNOWNHOSTS, su->known_hosts);
  if (su->pin != NULL)
    twist_transfer_setopt (transfer, TWISTOPT_SSH_HOST_PUBLIC_KEY_SHA256,
                           su->pin);
  transfer->write_cb = collect;
  got_len = 0;
  if (su->upload != NULL && su->streamed)
    {
      feed_data = su->upload;
      feed_len = su->upload_len;
      feed_pos = 0;
      feed_piece = 7001;
      transfer->read_cb = feed;
    }
  else if (su->upload != NULL)
    {
      twist_transfer_setopt (transfer, TWISTOPT_POSTFIELDS,
                             (char *) su->upload);
      twist_transfer_setopt (transfer, TWISTOPT_POSTFIELDSIZE,
                             (long) su->upload_len);
    }
  if (su->resume != 0)
    twist_transfer_setopt (transfer, TWISTOPT_RESUME_FROM, su->resume);
  if (su->range != NULL)
    twist_transfer_setopt (transfer, TWISTOPT_RANGE, su->range);
  if (su->list_only)
    twist_transfer_setopt (transfer, TWISTOPT_DIRLISTONLY, 1L);
  if (su->quote != NULL)
    twist_transfer_setopt (transfer, TWISTOPT_QUOTE, su->quote);
  if (su->postquote != NULL)
    twist_transfer_setopt (transfer, TWISTOPT_POSTQUOTE, su->postquote);
  if (su->create_dirs)
    twist_transfer_setopt (transfer, TWISTOPT_CREATE_MISSING_DIRS, 1L);
  if (su->nobody)
    twist_transfer_setopt (transfer, TWISTOPT_NOBODY, 1L);
  if (su->headers)
    twist_transfer_setopt (transfer, TWISTOPT_HEADERFUNCTION, header_collect);
  w->sv = sv;
  w->c2s.len = 0;
  if (su->agent != NULL)
    twist_transfer_setopt (transfer, TWISTOPT_SSH_AGENT_SOCKET, su->agent);
  if (su->runtime != NULL)
    {
      transfer->runtime = su->runtime;
      transfer->loop = su->runtime->loop;
    }
  w->ssh = twist_ssh_new (transfer, 0);
  if (su->agent_timeout_ms != 0)
    w->ssh->agent_timeout_ms = su->agent_timeout_ms;
  check (w->ssh != NULL, "ssh new");
  twist_ssh_set_sink (w->ssh, client_sink, &w->c2s);
  twist_ssh_set_time (w->ssh, now_us);
  return transfer;
}

/* Run a whole transfer; the caller looks at the result.  */
static struct twist_transfer *
run (struct world *w, struct server *sv, const struct setup *su)
{
  struct twist_transfer *transfer = start (w, sv, su);
  int rc = twist_ssh_start (w->ssh);

  /* The endpoint callback ends a transfer that cannot start with the code
     start returned.  */
  if (rc != TWIST_OK && !transfer->done)
    twist_transfer_finish (transfer, rc);
  if (rc == TWIST_OK && su->runtime != NULL)
    pump_with_loop (su->runtime, w, transfer,
                    su->chunk != 0 ? su->chunk : 65536);
  else if (rc == TWIST_OK)
    pump (w, transfer, su->chunk != 0 ? su->chunk : 65536);
  return transfer;
}

static int
detail_has (struct twist_transfer *transfer, const char *text)
{
  const char *d = twist_transfer_error (transfer);

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
  struct twist_transfer *transfer;
  struct setup su = SETUP ("sftp://alice@127.0.0.1/data.bin", 0, "secret");

  check (server_new (&sv) == 0, "server");
  su.chunk = chunk;
  transfer = run (&w, &sv, &su);
  gf_session_receive (sv.s, now_us, w.c2s.data, w.c2s.len);
  check (transfer->done && transfer->result == TWIST_OK, "download ends well");
  check (got_len == sizeof content && memcmp (got, content, got_len) == 0,
         "the file is whole");
  check (transfer->size_download == sizeof content, "size counted");
  check (strcmp (sv.opened, "/data.bin") == 0, "absolute path");
  check (sv.closed_handle, "handle closed");
  check (sv.closed && sv.reason == GF_DISCONNECT_BY_APPLICATION,
         "server told goodbye");
  twist_transfer_free (transfer);
  server_free (&sv);
}

/* A server that answers reads with less than was asked.  */
static void
test_short_reads (void)
{
  struct server sv;
  struct world w;
  struct twist_transfer *transfer;
  struct setup su = SETUP ("sftp://alice@127.0.0.1/data.bin", 0, "secret");

  check (server_new (&sv) == 0, "server");
  sv.max_read = 5000;
  transfer = run (&w, &sv, &su);
  check (transfer->done && transfer->result == TWIST_OK,
         "short reads end well");
  check (got_len == sizeof content && memcmp (got, content, got_len) == 0,
         "short reads: the file is whole");
  twist_transfer_free (transfer);
  server_free (&sv);
}

static void
test_empty_file (void)
{
  struct server sv;
  struct world w;
  struct twist_transfer *transfer;
  struct setup su = SETUP ("sftp://alice@127.0.0.1/data.bin", 0, "secret");

  check (server_new (&sv) == 0, "server");
  sv.filelen = 0;
  transfer = run (&w, &sv, &su);
  check (transfer->done && transfer->result == TWIST_OK && got_len == 0,
         "an empty file");
  twist_transfer_free (transfer);
  server_free (&sv);
}

/* scp:// is the same transfer; /~/ is relative to the user's directory.  */
static void
test_paths (void)
{
  struct server sv;
  struct world w;
  struct twist_transfer *transfer;
  struct setup su = SETUP ("scp://alice@127.0.0.1/~/data.bin", 0, "secret");

  check (server_new (&sv) == 0, "server");
  transfer = run (&w, &sv, &su);
  check (transfer->done && transfer->result == TWIST_OK, "scp ends well");
  check (strcmp (sv.opened, "data.bin") == 0, "home relative path");
  check (got_len == sizeof content, "scp: the file");
  twist_transfer_free (transfer);
  server_free (&sv);

  /* Percent escapes are decoded.  */
  check (server_new (&sv) == 0, "server 2");
  su.url = "sftp://alice@127.0.0.1/%64ata.bin";
  transfer = run (&w, &sv, &su);
  check (transfer->done && transfer->result == TWIST_OK
         && strcmp (sv.opened, "/data.bin") == 0, "percent escape");
  twist_transfer_free (transfer);
  server_free (&sv);

  /* A wildcard in an scp URL is refused up front.  */
  check (server_new (&sv) == 0, "server 3");
  su.url = "scp://alice@127.0.0.1/dir/*.txt";
  transfer = run (&w, &sv, &su);
  check (transfer->done && transfer->result == TWIST_ERR_URL
         && detail_has (transfer, "wildcards"), "scp wildcard");
  twist_transfer_free (transfer);
  server_free (&sv);
}

/* What the server says about the file reaches the exit status.  */
static void
test_file_errors (void)
{
  struct server sv;
  struct world w;
  struct twist_transfer *transfer;
  struct setup su = SETUP ("sftp://alice@127.0.0.1/nope", 0, "secret");

  check (server_new (&sv) == 0, "server");
  transfer = run (&w, &sv, &su);
  check (transfer->done && transfer->result == TWIST_ERR_FILE
         && transfer->proto_status == 78
         && detail_has (transfer, "no such file")
         && detail_has (transfer, "/nope"), "no such file");
  twist_transfer_free (transfer);
  server_free (&sv);
  check (server_new (&sv) == 0, "server 2");
  su.url = "sftp://alice@127.0.0.1/denied";
  transfer = run (&w, &sv, &su);
  check (transfer->done && transfer->result == TWIST_ERR_FILE
         && transfer->proto_status == 9
         && detail_has (transfer, "not for you"),
         "permission denied");
  twist_transfer_free (transfer);
  server_free (&sv);
}

/* No sftp subsystem: scp:// is not served by the old protocol.  */
static void
test_no_subsystem (void)
{
  struct server sv;
  struct world w;
  struct twist_transfer *transfer;
  struct setup su = SETUP ("scp://alice@127.0.0.1/data.bin", 0, "secret");

  check (server_new (&sv) == 0, "server");
  sv.refuse_sftp = 1;
  transfer = run (&w, &sv, &su);
  check (transfer->done && transfer->result == TWIST_ERR_UNSUPPORTED
         && detail_has (transfer, "no SFTP subsystem"), "no subsystem");
  twist_transfer_free (transfer);
  server_free (&sv);
}

/* Passwords, keys given and keys found, and what is said when none works.  */
static void
test_auth (void)
{
  struct server sv;
  struct world w;
  struct twist_transfer *transfer;
  struct setup su = SETUP ("sftp://alice@127.0.0.1/data.bin", 0, "wrong");
  char keytext[2048], keyfile[300], ssh_dir[300], usual[320];
  size_t kn = 0;

  check (server_new (&sv) == 0, "server");
  transfer = run (&w, &sv, &su);
  check (transfer->done && transfer->result == TWIST_ERR_AUTH
         && detail_has (transfer, "permission denied"), "wrong password");
  twist_transfer_free (transfer);
  server_free (&sv);

  check (server_new (&sv) == 0, "server 2");
  su.password = NULL;
  transfer = run (&w, &sv, &su);
  check (transfer->done && transfer->result == TWIST_ERR_AUTH
         && detail_has (transfer, "no private key or password"),
         "no credentials");
  twist_transfer_free (transfer);
  server_free (&sv);

  /* A key named with --key: the one the server authorizes.  */
  check (server_new (&sv) == 0, "server 3");
  check (gf_key_to_openssh_private (sv.authorized, keytext, sizeof keytext,
                                    &kn) == GF_OK, "key text");
  snprintf (keyfile, sizeof keyfile, "%s/mykey", home);
  write_file (keyfile, keytext, kn, 0600);
  su.keyfile = keyfile;
  transfer = run (&w, &sv, &su);
  check (transfer->done && transfer->result == TWIST_OK
         && got_len == sizeof content, "key file");
  twist_transfer_free (transfer);
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
  transfer = run (&w, &sv, &su);
  check (transfer->done && transfer->result == TWIST_OK, "usual key file");
  twist_transfer_free (transfer);
  server_free (&sv);
  unlink (usual);

  /* A key file that is not a key, and one that is missing.  */
  check (server_new (&sv) == 0, "server 5");
  write_file (keyfile, "not a key\n", 10, 0600);
  su.keyfile = keyfile;
  transfer = run (&w, &sv, &su);
  check (transfer->done && transfer->result == TWIST_ERR_AUTH
         && detail_has (transfer, "cannot use"), "bad key file");
  twist_transfer_free (transfer);
  server_free (&sv);
  check (server_new (&sv) == 0, "server 6");
  su.keyfile = "/nonexistent/key";
  transfer = run (&w, &sv, &su);
  check (transfer->done && transfer->result == TWIST_ERR_FILE
         && detail_has (transfer, "cannot read the private key"),
         "no key file");
  twist_transfer_free (transfer);
  server_free (&sv);
  unlink (keyfile);
  rmdir (ssh_dir);
}

/* ---- user certificates ---- */

/* A certificate by CA for KEY, for the user PRINCIPAL, good from AFTER to
   BEFORE (seconds from now), written as the .pub line to PATH.  */
static void
write_cert (const gf_key *ca, const gf_key *key, const char *principal,
            long after, long before, const char *path)
{
  gf_cert_spec spec;
  const char *names[1];
  gf_key *cert = NULL;
  char line[2048];
  size_t n = 0;
  uint64_t now = (uint64_t) time (NULL);

  names[0] = principal;
  memset (&spec, 0, sizeof spec);
  spec.type = GF_CERT_USER;
  spec.serial = 7;
  spec.key_id = "test";
  spec.principals = names;
  spec.nprincipals = 1;
  spec.valid_after = now + (uint64_t) after;
  spec.valid_before = now + (uint64_t) before;
  spec.allow = GF_CERT_ALLOW_ALL;
  check (gf_cert_sign (&cert, ca, key, &spec, 0) == GF_OK, "sign a cert");
  check (gf_key_to_text (cert, line, sizeof line, &n) == GF_OK, "cert text");
  line[n++] = '\n';
  write_file (path, line, n, 0644);
  gf_key_free (cert);
}

static void
write_private (const gf_key *key, const char *path)
{
  char text[4096];
  size_t n = 0;

  check (gf_key_to_openssh_private (key, text, sizeof text, &n) == GF_OK,
         "private key text");
  write_file (path, text, n, 0600);
}

/* The server trusts a CA and does not know the user's key.  One thing about
   the certificate varies in each case: if it is right the login works, and
   if not it does not, and the message says why when twist can tell.  */
static void
cert_case (const char *what, const gf_key *ca, const gf_key *signer,
           const gf_key *for_key, const char *principal, long after,
           long before, int want_ok, const char *want_note, int known_plain,
           int usual_path)
{
  struct server sv;
  struct world w;
  struct twist_transfer *transfer;
  struct setup su = SETUP ("sftp://alice@127.0.0.1/data.bin", 0, NULL);
  gf_key *user = NULL;
  char ssh_dir[300], keyfile[400], certfile[420];

  check (gf_key_generate (&user, GF_KEY_ED25519, 0) == GF_OK, "user key");
  trusted_ca = ca;
  check (server_new (&sv) == 0, "server");
  trusted_ca = NULL;
  sv.password = NULL;
  if (known_plain)
    sv.also[sv.nalso++] = user;
  snprintf (ssh_dir, sizeof ssh_dir, "%s/.ssh", home);
  mkdir (ssh_dir, 0700);
  if (usual_path)
    snprintf (keyfile, sizeof keyfile, "%s/id_ed25519", ssh_dir);
  else
    snprintf (keyfile, sizeof keyfile, "%s/mykey", home);
  snprintf (certfile, sizeof certfile, "%s-cert.pub", keyfile);
  write_private (user, keyfile);
  if (principal != NULL)
    write_cert (signer != NULL ? signer : ca, for_key != NULL ? for_key : user,
                principal, after, before, certfile);
  if (!usual_path)
    su.keyfile = keyfile;
  transfer = run (&w, &sv, &su);
  if (want_ok)
    check (transfer->done && transfer->result == TWIST_OK
           && got_len == sizeof content,
           what);
  else
    check (transfer->done && transfer->result == TWIST_ERR_AUTH
           && got_len == 0,
           what);
  if (want_note != NULL)
    {
      check (detail_has (transfer, want_note), what);
      if (!detail_has (transfer, want_note))
        fprintf (stderr, "  message: %s\n", twist_transfer_error (transfer));
    }
  if (want_ok && !known_plain)
    {
      check (sv.cert_logins == 1, "logged in with the certificate");
      check (sv.noffered == 1 && sv.cert_probes == 1,
             "only the certificate was offered, so it comes first");
    }
  twist_transfer_free (transfer);
  if (known_plain)
    sv.nalso = 0;
  server_free (&sv);
  gf_key_free (user);
  unlink (keyfile);
  unlink (certfile);
  rmdir (ssh_dir);
}

static void
test_certificates (void)
{
  gf_key *ca = NULL, *other_ca = NULL, *stranger = NULL;

  check (gf_key_generate (&ca, GF_KEY_ED25519, 0) == GF_OK, "ca");
  check (gf_key_generate (&other_ca, GF_KEY_ED25519, 0) == GF_OK, "ca 2");
  check (gf_key_generate (&stranger, GF_KEY_ED25519, 0) == GF_OK, "key 2");

  /*        what, ca, signer, for-key, principal, from, to, ok, note,
            plain-known, usual-path  */
  cert_case ("a certificate beside the named key", ca, NULL, NULL, "alice",
             -3600, 3600, 1, NULL, 0, 0);
  cert_case ("a certificate beside the usual key", ca, NULL, NULL, "alice",
             -3600, 3600, 1, NULL, 0, 1);
  cert_case ("no certificate: the key alone is not let in", ca, NULL, NULL,
             NULL, 0, 0, 0, NULL, 0, 0);
  cert_case ("a certificate from a CA the server does not trust", ca,
             other_ca, NULL, "alice", -3600, 3600, 0, NULL, 0, 0);
  cert_case ("an expired certificate is said to be", ca, NULL, NULL, "alice",
             -7200, -3600, 0, "expired", 0, 0);
  cert_case ("a certificate not yet good is said to be", ca, NULL, NULL,
             "alice", 3600, 7200, 0, "not yet", 0, 0);
  cert_case ("a certificate for another user is said to be", ca, NULL, NULL,
             "bob", -3600, 3600, 0, "not for the user alice", 0, 0);
  cert_case ("a certificate for another key is said to be", ca, NULL,
             stranger, "alice", -3600, 3600, 0, "not for this key", 0, 0);
  /* The key the server knows still works when the certificate is no good.  */
  cert_case ("a bad certificate does not stop the key", ca, NULL, stranger,
             "alice", -3600, 3600, 1, NULL, 1, 0);
  gf_key_free (ca);
  gf_key_free (other_ca);
  gf_key_free (stranger);
}

/* The user name and password in the URL are percent-encoded, and the server
   is given what they say, not how they are written.  The password here holds
   the three characters that cannot be written as they are.  */
static void
test_url_credentials (void)
{
  struct server sv;
  struct world w;
  struct twist_transfer *transfer;
  struct setup su = SETUP ("sftp://%61lice:p%40ss%3Aw%2Frd%25@127.0.0.1/data.bin",
                           0, NULL);

  check (server_new (&sv) == 0, "server");
  sv.password = "p@ss:w/rd%";
  transfer = run (&w, &sv, &su);
  check (transfer->done && transfer->result == TWIST_OK
         && got_len == sizeof content,
         "login with an encoded user name and password");
  twist_transfer_free (transfer);
  server_free (&sv);

  /* Written the other way, it is the encoded text that is wrong.  */
  check (server_new (&sv) == 0, "server");
  sv.password = "p%40ss%3Aw%2Frd%25";
  transfer = run (&w, &sv, &su);
  check (transfer->done && transfer->result == TWIST_ERR_AUTH,
         "the encoded text is not the password");
  twist_transfer_free (transfer);
  server_free (&sv);
}

/* The host key: known_hosts, a pin, and -k.  */
static void
test_host_key (void)
{
  struct server sv;
  struct world w;
  struct twist_transfer *transfer;
  struct setup su = SETUP ("sftp://alice@127.0.0.1/data.bin", 1, "secret");
  char kh[300], fp[64];
  gf_key *other = NULL;

  /* Known: the transfer goes through.  */
  check (server_new (&sv) == 0, "server");
  known_hosts_with (sv.host, kh, sizeof kh);
  su.known_hosts = kh;
  transfer = run (&w, &sv, &su);
  check (transfer->done && transfer->result == TWIST_OK, "known host");
  twist_transfer_free (transfer);
  server_free (&sv);

  /* Not in the file.  */
  check (server_new (&sv) == 0, "server 2");
  known_hosts_with (NULL, kh, sizeof kh);
  transfer = run (&w, &sv, &su);
  check (transfer->done && transfer->result == TWIST_ERR_HOSTKEY
         && detail_has (transfer, "not in known_hosts")
         && detail_has (transfer, "SHA256:"), "unknown host");
  check (got_len == 0, "nothing written for an unknown host");
  twist_transfer_free (transfer);
  server_free (&sv);

  /* A different key for the host.  */
  check (server_new (&sv) == 0, "server 3");
  check (gf_key_generate (&other, GF_KEY_ED25519, 0) == GF_OK, "other key");
  known_hosts_with (other, kh, sizeof kh);
  transfer = run (&w, &sv, &su);
  check (transfer->done && transfer->result == TWIST_ERR_HOSTKEY
         && detail_has (transfer, "CHANGED"), "changed host key");
  twist_transfer_free (transfer);
  gf_key_free (other);

  /* -k skips the file.  */
  server_free (&sv);
  check (server_new (&sv) == 0, "server 4");
  su.verify = 0;
  transfer = run (&w, &sv, &su);
  check (transfer->done && transfer->result == TWIST_OK,
         "-k skips known_hosts");
  twist_transfer_free (transfer);

  /* A pin is trusted without the file, with or without "SHA256:" and
     padding; a wrong one fails even with -k.  */
  server_free (&sv);
  check (server_new (&sv) == 0, "server 5");
  gf_key_fingerprint (sv.host, fp, sizeof fp);
  su.verify = 1;
  su.pin = fp + 7;
  known_hosts_with (NULL, kh, sizeof kh);
  transfer = run (&w, &sv, &su);
  check (transfer->done && transfer->result == TWIST_OK, "pinned host");
  twist_transfer_free (transfer);
  server_free (&sv);
  check (server_new (&sv) == 0, "server 6");
  su.pin = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
  su.verify = 0;
  transfer = run (&w, &sv, &su);
  check (transfer->done && transfer->result == TWIST_ERR_HOSTKEY
         && detail_has (transfer, "pinned"), "wrong pin, even with -k");
  twist_transfer_free (transfer);
  server_free (&sv);

  /* A known_hosts file that was named and cannot be read.  */
  check (server_new (&sv) == 0, "server 7");
  su.pin = NULL;
  su.verify = 1;
  su.known_hosts = "/nonexistent/known_hosts";
  transfer = run (&w, &sv, &su);
  check (transfer->done && transfer->result == TWIST_ERR_FILE
         && detail_has (transfer, "known_hosts"),
         "named known_hosts unreadable");
  twist_transfer_free (transfer);
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
   The file is created and truncated, with the mode a new file gets.  */
static void
test_upload (size_t chunk, int streamed)
{
  struct server sv;
  struct world w;
  struct twist_transfer *transfer;
  struct setup su = SETUP ("sftp://alice@127.0.0.1/up.bin", 0, "secret");

  check (server_new (&sv) == 0, "server");
  su.upload = big;
  su.upload_len = sizeof big;
  su.streamed = streamed;
  su.chunk = chunk;
  transfer = run (&w, &sv, &su);
  gf_session_receive (sv.s, now_us, w.c2s.data, w.c2s.len);
  check (transfer->done && transfer->result == TWIST_OK, "upload ends well");
  check (uploaded_is (&sv, big, sizeof big), "the whole file arrived");
  check ((sv.up_flags & (GF_FXF_WRITE | GF_FXF_CREAT | GF_FXF_TRUNC))
         == (GF_FXF_WRITE | GF_FXF_CREAT | GF_FXF_TRUNC),
         "created and truncated");
  check (sv.up_perms == 0644, "new files are 0644");
  check (sv.first_write == 0, "from the start");
  check (sv.writes >= 40, "in chunks");
  check (sv.closed_handle, "handle closed");
  twist_transfer_free (transfer);
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
  struct twist_transfer *transfer;
  struct setup su = SETUP ("scp://alice@127.0.0.1/up.bin", 0, "secret");

  check (server_new (&sv) == 0, "server");
  su.upload = none;
  su.upload_len = 0;
  transfer = run (&w, &sv, &su);
  check (transfer->done && transfer->result == TWIST_OK && sv.up_exists
         && sv.up_len == 0 && sv.writes == 0, "an empty file");
  twist_transfer_free (transfer);
  server_free (&sv);

  check (server_new (&sv) == 0, "server 2");
  preload (&sv, big, 500000);
  su.upload = content;
  su.upload_len = sizeof content;
  transfer = run (&w, &sv, &su);
  check (transfer->done && transfer->result == TWIST_OK
         && uploaded_is (&sv, content, sizeof content),
         "a longer file is replaced, not overwritten in place");
  twist_transfer_free (transfer);
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
  struct twist_transfer *transfer;
  struct setup su = SETUP ("sftp://alice@127.0.0.1/up.bin", 0, "secret");

  su.upload = content;
  su.upload_len = sizeof content;

  check (server_new (&sv) == 0, "server");
  preload (&sv, content, 40000);
  su.resume = 40000;
  transfer = run (&w, &sv, &su);
  check (transfer->done && transfer->result == TWIST_OK
         && uploaded_is (&sv, content, sizeof content), "resume at an offset");
  check (sv.first_write == 40000, "the first write is at the offset");
  check (!(sv.up_flags & GF_FXF_TRUNC), "not truncated");
  twist_transfer_free (transfer);
  server_free (&sv);

  /* Ask the server how much it has.  */
  check (server_new (&sv) == 0, "server 2");
  preload (&sv, content, 25000);
  su.resume = -1;
  transfer = run (&w, &sv, &su);
  check (transfer->done && transfer->result == TWIST_OK
         && uploaded_is (&sv, content, sizeof content) && sv.first_write == 25000
         && !(sv.up_flags & GF_FXF_TRUNC), "resume by asking");
  twist_transfer_free (transfer);
  server_free (&sv);

  /* Asking, and there is no file: it starts from nothing.  */
  check (server_new (&sv) == 0, "server 3");
  transfer = run (&w, &sv, &su);
  check (transfer->done && transfer->result == TWIST_OK
         && uploaded_is (&sv, content, sizeof content) && sv.first_write == 0
         && (sv.up_flags & GF_FXF_CREAT), "asking about a file not there");
  twist_transfer_free (transfer);
  server_free (&sv);

  /* Through a read callback, which has to throw the start away.  */
  check (server_new (&sv) == 0, "server 4");
  preload (&sv, content, 30000);
  su.resume = 30000;
  su.streamed = 1;
  transfer = run (&w, &sv, &su);
  check (transfer->done && transfer->result == TWIST_OK
         && uploaded_is (&sv, content, sizeof content), "resume, streamed");
  twist_transfer_free (transfer);
  server_free (&sv);
  su.streamed = 0;

  /* An offset the files do not agree with.  */
  check (server_new (&sv) == 0, "server 5");
  preload (&sv, content, 10000);
  su.resume = 40000;
  transfer = run (&w, &sv, &su);
  check (transfer->done && transfer->result == TWIST_ERR_RESUME
         && detail_has (transfer, "shorter") && sv.writes == 0,
         "the remote file is shorter than the offset");
  twist_transfer_free (transfer);
  server_free (&sv);

  check (server_new (&sv) == 0, "server 6");
  transfer = run (&w, &sv, &su);
  check (transfer->done && transfer->result == TWIST_ERR_RESUME
         && detail_has (transfer, "does not exist"), "no file to resume");
  twist_transfer_free (transfer);
  server_free (&sv);

  check (server_new (&sv) == 0, "server 7");
  preload (&sv, content, 60000);
  su.upload_len = 1000;
  su.resume = 5000;
  transfer = run (&w, &sv, &su);
  check (transfer->done && transfer->result == TWIST_ERR_RESUME
         && detail_has (transfer, "data to upload is shorter"),
         "the data is shorter than the offset");
  twist_transfer_free (transfer);
  server_free (&sv);
  su.upload_len = sizeof content;
  su.streamed = 1;
  check (server_new (&sv) == 0, "server 8");
  preload (&sv, content, 60000);
  su.upload_len = 1000;
  transfer = run (&w, &sv, &su);
  check (transfer->done && transfer->result == TWIST_ERR_RESUME,
         "the data is shorter than the offset, streamed");
  twist_transfer_free (transfer);
  server_free (&sv);
}

/* What goes wrong with an upload, and the exit status for it.  */
static void
test_upload_errors (void)
{
  struct server sv;
  struct world w;
  struct twist_transfer *transfer;
  struct setup su = SETUP ("sftp://alice@127.0.0.1/nodir/x", 0, "secret");

  su.upload = content;
  su.upload_len = sizeof content;

  check (server_new (&sv) == 0, "server");
  transfer = run (&w, &sv, &su);
  check (transfer->done && transfer->result == TWIST_ERR_FILE
         && transfer->proto_status == 25 && detail_has (transfer, "/nodir/x"),
         "cannot create the file");
  twist_transfer_free (transfer);
  server_free (&sv);

  check (server_new (&sv) == 0, "server 2");
  su.url = "sftp://alice@127.0.0.1/denied";
  transfer = run (&w, &sv, &su);
  check (transfer->done && transfer->result == TWIST_ERR_FILE
         && transfer->proto_status == 9, "an open refused is access denied");
  twist_transfer_free (transfer);
  server_free (&sv);

  su.url = "sftp://alice@127.0.0.1/up.bin";
  check (server_new (&sv) == 0, "server 3");
  sv.write_status = GF_FX_FAILURE;
  transfer = run (&w, &sv, &su);
  check (transfer->done && transfer->result == TWIST_ERR_FILE
         && transfer->proto_status == 25 && detail_has (transfer, "no room"),
         "a write fails");
  twist_transfer_free (transfer);
  server_free (&sv);

  check (server_new (&sv) == 0, "server 4");
  sv.write_status = GF_FX_PERMISSION_DENIED;
  transfer = run (&w, &sv, &su);
  check (transfer->done && transfer->result == TWIST_ERR_FILE
         && transfer->proto_status == 9, "a write is refused");
  twist_transfer_free (transfer);
  server_free (&sv);

  /* A directory, and what a library caller can get wrong.  */
  check (server_new (&sv) == 0, "server 5");
  su.url = "sftp://alice@127.0.0.1/dir/";
  transfer = run (&w, &sv, &su);
  check (transfer->done && transfer->result == TWIST_ERR_URL
         && detail_has (transfer, "names a directory"),
         "upload to a directory");
  twist_transfer_free (transfer);
  server_free (&sv);

  check (server_new (&sv) == 0, "server 6");
  su.url = "sftp://alice@127.0.0.1/up.bin";
  su.range = "0-9";
  transfer = run (&w, &sv, &su);
  check (transfer->done && transfer->result == TWIST_ERR_INVAL
         && detail_has (transfer, "range does not apply"), "a range and an upload");
  twist_transfer_free (transfer);
  server_free (&sv);
}

/* ---- quote commands and missing directories ---- */

static char hdr_text[1024];
static size_t hdr_len;

static size_t
header_collect (char *ptr, size_t size, size_t nmemb, void *user)
{
  size_t n = size * nmemb;

  (void) user;
  if (hdr_len + n < sizeof hdr_text)
    {
      memcpy (hdr_text + hdr_len, ptr, n);
      hdr_len += n;
      hdr_text[hdr_len] = 0;
    }
  return n;
}

/* What the server was asked, in order, as "what a b|what a b".  */
static const char *
ops_text (const struct server *sv)
{
  static char out[2048];
  unsigned i;

  out[0] = 0;
  for (i = 0; i < sv->nops; i++)
    {
      size_t used = strlen (out);

      snprintf (out + used, sizeof out - used, "%s%s%s%s%s%s", i ? "|" : "",
                sv->ops[i].what, sv->ops[i].a[0] ? " " : "", sv->ops[i].a,
                sv->ops[i].b[0] ? " " : "", sv->ops[i].b);
    }
  return out;
}

static struct twist_slist *
commands (const char *a, const char *b, const char *c)
{
  struct twist_slist *l = NULL;

  if (a != NULL)
    l = twist_slist_append (l, a);
  if (b != NULL)
    l = twist_slist_append (l, b);
  if (c != NULL)
    l = twist_slist_append (l, c);
  return l;
}

/* One transfer with quote commands; the caller looks at what became of it.  */
static struct twist_transfer *
quote_run (struct world *w, struct server *sv, struct setup *su,
           struct twist_slist *pre, struct twist_slist *post)
{
  su->quote = pre;
  su->postquote = post;
  hdr_len = 0;
  hdr_text[0] = 0;
  return run (w, sv, su);
}

static int
op_is (const struct server *sv, unsigned i, const char *what, const char *a,
       const char *b)
{
  return i < sv->nops && strcmp (sv->ops[i].what, what) == 0
         && strcmp (sv->ops[i].a, a) == 0 && strcmp (sv->ops[i].b, b) == 0;
}

static void
test_quote_order (void)
{
  struct server sv;
  struct world w;
  struct twist_transfer *transfer;
  struct setup su = SETUP ("sftp://alice@127.0.0.1/data.bin", 0, "secret");
  struct twist_slist *pre, *post;

  /* Before the transfer.  */
  check (server_new (&sv) == 0, "server");
  pre = commands ("mkdir /newdir", NULL, NULL);
  transfer = quote_run (&w, &sv, &su, pre, NULL);
  check (transfer->done && transfer->result == TWIST_OK
         && got_len == sizeof content,
         "a quote command before the transfer");
  check (strcmp (ops_text (&sv), "mkdir /newdir|open /data.bin|close") == 0,
         "it ran first");
  twist_transfer_free (transfer);
  server_free (&sv);
  twist_slist_free_all (pre);

  /* After it.  */
  check (server_new (&sv) == 0, "server 2");
  post = commands ("rm /old", NULL, NULL);
  transfer = quote_run (&w, &sv, &su, NULL, post);
  check (transfer->done && transfer->result == TWIST_OK
         && got_len == sizeof content,
         "a quote command after the transfer");
  check (strcmp (ops_text (&sv), "open /data.bin|close|remove /old") == 0,
         "it ran last");
  twist_transfer_free (transfer);
  server_free (&sv);
  twist_slist_free_all (post);

  /* Both, in order.  */
  check (server_new (&sv) == 0, "server 3");
  pre = commands ("mkdir /a", "rename /a /b", NULL);
  post = commands ("rmdir /b", NULL, NULL);
  transfer = quote_run (&w, &sv, &su, pre, post);
  check (transfer->done && transfer->result == TWIST_OK, "both");
  check (strcmp (ops_text (&sv), "mkdir /a|rename /a /b|open /data.bin|close"
                 "|rmdir /b") == 0, "in the order given, one at a time");
  twist_transfer_free (transfer);
  server_free (&sv);
  twist_slist_free_all (pre);
  twist_slist_free_all (post);
}

static void
test_quote_failures (void)
{
  struct server sv;
  struct world w;
  struct twist_transfer *transfer;
  struct setup su = SETUP ("sftp://alice@127.0.0.1/data.bin", 0, "secret");
  struct twist_slist *pre, *post;

  /* The server refuses: the transfer is not made.  */
  check (server_new (&sv) == 0, "server");
  pre = commands ("rm /gone", NULL, NULL);
  transfer = quote_run (&w, &sv, &su, pre, NULL);
  check (transfer->done && transfer->result == TWIST_ERR_QUOTE && got_len == 0
         && transfer->proto_status == 21, "a quote command that fails");
  check (detail_has (transfer, "rm command failed")
         && detail_has (transfer, "no such file"), "and says which and why");
  check (strcmp (ops_text (&sv), "remove /gone") == 0,
         "nothing is transferred after it");
  twist_transfer_free (transfer);
  server_free (&sv);
  twist_slist_free_all (pre);

  /* * goes on.  */
  check (server_new (&sv) == 0, "server 2");
  pre = commands ("*rm /gone", "mkdir /after", NULL);
  transfer = quote_run (&w, &sv, &su, pre, NULL);
  check (transfer->done && transfer->result == TWIST_OK
         && got_len == sizeof content,
         "* goes on after a failure");
  check (strcmp (ops_text (&sv), "remove /gone|mkdir /after|open /data.bin"
                 "|close") == 0, "with the rest");
  twist_transfer_free (transfer);
  server_free (&sv);
  twist_slist_free_all (pre);

  /* A permission is told from a missing file.  */
  check (server_new (&sv) == 0, "server 3");
  pre = commands ("rm /denied", NULL, NULL);
  transfer = quote_run (&w, &sv, &su, pre, NULL);
  check (transfer->done && transfer->result == TWIST_ERR_QUOTE
         && detail_has (transfer, "permission denied"), "permission denied");
  twist_transfer_free (transfer);
  server_free (&sv);
  twist_slist_free_all (pre);

  /* After the transfer: it was made, and the command failed.  */
  check (server_new (&sv) == 0, "server 4");
  post = commands ("rm /gone", NULL, NULL);
  transfer = quote_run (&w, &sv, &su, NULL, post);
  check (transfer->done && transfer->result == TWIST_ERR_QUOTE
         && got_len == sizeof content && transfer->proto_status == 21,
         "a quote command after the transfer that fails");
  twist_transfer_free (transfer);
  server_free (&sv);
  twist_slist_free_all (post);

  /* A transfer that fails does not run them.  */
  check (server_new (&sv) == 0, "server 5");
  su.url = "sftp://alice@127.0.0.1/missing";
  post = commands ("rm /old", NULL, NULL);
  transfer = quote_run (&w, &sv, &su, NULL, post);
  check (transfer->done && transfer->result == TWIST_ERR_FILE
         && transfer->proto_status == 78, "a transfer that fails");
  check (strcmp (ops_text (&sv), "open /missing") == 0,
         "does not run the commands after it");
  twist_transfer_free (transfer);
  server_free (&sv);
  twist_slist_free_all (post);
  su.url = "sftp://alice@127.0.0.1/data.bin";

  /* A command that cannot be read ends it before anything is sent, with * as
     well.  */
  check (server_new (&sv) == 0, "server 6");
  pre = commands ("*frob x", NULL, NULL);
  transfer = quote_run (&w, &sv, &su, pre, NULL);
  check (transfer->done && transfer->result == TWIST_ERR_QUOTE
         && detail_has (transfer, "Unknown SFTP command") && sv.nops == 0
         && got_len == 0, "a command that cannot be read");
  twist_transfer_free (transfer);
  server_free (&sv);
  twist_slist_free_all (pre);
}

static void
test_quote_commands (void)
{
  struct server sv;
  struct world w;
  struct twist_transfer *transfer;
  struct setup su = SETUP ("sftp://alice@127.0.0.1/data.bin", 0, "secret");
  struct twist_slist *pre;

  check (server_new (&sv) == 0, "server 2");
  pre = commands ("chmod 600 /data.bin", NULL, NULL);
  transfer = quote_run (&w, &sv, &su, pre, NULL);
  check (transfer->done && transfer->result == TWIST_OK
         && op_is (&sv, 0, "setstat", "/data.bin", "")
         && sv.ops[0].attrs.flags == GF_FILEXFER_ATTR_PERMISSIONS
         && sv.ops[0].attrs.permissions == 0600, "chmod sets the mode only");
  twist_transfer_free (transfer);
  server_free (&sv);
  twist_slist_free_all (pre);

  /* The owner and group go together on the wire; the one not named is kept.  */
  check (server_new (&sv) == 0, "server 3");
  pre = commands ("chown 5 /data.bin", NULL, NULL);
  transfer = quote_run (&w, &sv, &su, pre, NULL);
  check (transfer->done && transfer->result == TWIST_OK
         && op_is (&sv, 0, "stat", "/data.bin", "")
         && op_is (&sv, 1, "setstat", "/data.bin", "")
         && sv.ops[1].attrs.flags == GF_FILEXFER_ATTR_UIDGID
         && sv.ops[1].attrs.uid == 5 && sv.ops[1].attrs.gid == 100,
         "chown keeps the group");
  twist_transfer_free (transfer);
  server_free (&sv);
  twist_slist_free_all (pre);

  check (server_new (&sv) == 0, "server 4");
  pre = commands ("chgrp 7 /data.bin", NULL, NULL);
  transfer = quote_run (&w, &sv, &su, pre, NULL);
  check (transfer->done && transfer->result == TWIST_OK
         && sv.ops[1].attrs.uid == 1000 && sv.ops[1].attrs.gid == 7,
         "chgrp keeps the owner");
  twist_transfer_free (transfer);
  server_free (&sv);
  twist_slist_free_all (pre);

  check (server_new (&sv) == 0, "server 5");
  pre = commands ("mtime \"Thu, 02 Jan 2020 10:00:00 GMT\" /data.bin",
                  "atime \"Thu, 02 Jan 2020 11:00:00 GMT\" /data.bin", NULL);
  transfer = quote_run (&w, &sv, &su, pre, NULL);
  check (transfer->done && transfer->result == TWIST_OK
         && sv.ops[1].attrs.flags == GF_FILEXFER_ATTR_ACMODTIME
         && sv.ops[1].attrs.mtime == 1577959200 && sv.ops[1].attrs.atime == 111
         && sv.ops[3].attrs.atime == 1577962800 && sv.ops[3].attrs.mtime == 222,
         "mtime keeps the access time and atime the modification time");
  twist_transfer_free (transfer);
  server_free (&sv);
  twist_slist_free_all (pre);

  check (server_new (&sv) == 0, "server 6");
  pre = commands ("ln /target /linkname", NULL, NULL);
  transfer = quote_run (&w, &sv, &su, pre, NULL);
  check (transfer->done && transfer->result == TWIST_OK
         && op_is (&sv, 0, "symlink", "/linkname", "/target"),
         "ln makes the second a link to the first");
  twist_transfer_free (transfer);
  server_free (&sv);
  twist_slist_free_all (pre);

  /* A path with a space needs quotes.  */
  check (server_new (&sv) == 0, "server 7");
  pre = commands ("rename \"/a b\" \"/c d\"", NULL, NULL);
  transfer = quote_run (&w, &sv, &su, pre, NULL);
  check (transfer->done && transfer->result == TWIST_OK
         && op_is (&sv, 0, "rename", "/a b", "/c d"), "quoted paths");
  twist_transfer_free (transfer);
  server_free (&sv);
  twist_slist_free_all (pre);
}

/* pwd writes the server's words to the header callback.  */
static void
test_quote_pwd (void)
{
  struct server sv;
  struct world w;
  struct twist_transfer *transfer;
  struct setup su = SETUP ("sftp://alice@127.0.0.1/data.bin", 0, "secret");
  struct twist_slist *pre;

  su.headers = 1;
  check (server_new (&sv) == 0, "server");
  pre = commands ("pwd", NULL, NULL);
  transfer = quote_run (&w, &sv, &su, pre, NULL);
  check (transfer->done && transfer->result == TWIST_OK
         && strcmp (hdr_text, "257 \"/home/alice\" is current directory.\n")
            == 0, "pwd is said as a header");
  check (strcmp (ops_text (&sv), "realpath .|open /data.bin|close") == 0,
         "it asks for the real path of .");
  check (got_len == sizeof content, "and the file is still fetched");
  twist_transfer_free (transfer);
  server_free (&sv);
  twist_slist_free_all (pre);
}

/* -I: only the quote commands, and the file must be there.  */
static void
test_quote_only (void)
{
  struct server sv;
  struct world w;
  struct twist_transfer *transfer;
  struct setup su = SETUP ("sftp://alice@127.0.0.1/data.bin", 0, "secret");
  struct twist_slist *pre, *post;

  su.nobody = 1;
  check (server_new (&sv) == 0, "server");
  pre = commands ("mkdir /q", NULL, NULL);
  post = commands ("rm /old", NULL, NULL);
  transfer = quote_run (&w, &sv, &su, pre, post);
  check (transfer->done && transfer->result == TWIST_OK && got_len == 0,
         "no body: only the commands");
  check (strcmp (ops_text (&sv), "mkdir /q|stat /data.bin|remove /old") == 0,
         "the file is looked for, between them");
  twist_transfer_free (transfer);
  server_free (&sv);
  twist_slist_free_all (pre);
  twist_slist_free_all (post);

  check (server_new (&sv) == 0, "server 2");
  su.url = "sftp://alice@127.0.0.1/missing";
  transfer = quote_run (&w, &sv, &su, NULL, NULL);
  check (transfer->done && transfer->result == TWIST_ERR_FILE
         && transfer->proto_status == 78,
         "no body for a file that is not there");
  twist_transfer_free (transfer);
  server_free (&sv);

  /* A directory: nothing to look at.  */
  check (server_new (&sv) == 0, "server 3");
  su.url = "sftp://alice@127.0.0.1/dir/";
  pre = commands ("mkdir /q", NULL, NULL);
  transfer = quote_run (&w, &sv, &su, pre, NULL);
  check (transfer->done && transfer->result == TWIST_OK && got_len == 0
         && strcmp (ops_text (&sv), "mkdir /q") == 0, "a directory with -I");
  twist_transfer_free (transfer);
  server_free (&sv);
  twist_slist_free_all (pre);
}

/* Commands go with a listing and an upload too.  */
static void
test_quote_with_list_and_upload (void)
{
  struct server sv;
  struct world w;
  struct twist_transfer *transfer;
  struct setup su = SETUP ("sftp://alice@127.0.0.1/dir/", 0, "secret");
  struct twist_slist *pre, *post;

  check (server_new (&sv) == 0, "server");
  pre = commands ("mkdir /q", NULL, NULL);
  transfer = quote_run (&w, &sv, &su, pre, NULL);
  check (transfer->done && transfer->result == TWIST_OK && got_len > 0
         && op_is (&sv, 0, "mkdir", "/q", ""), "before a listing");
  twist_transfer_free (transfer);
  server_free (&sv);
  twist_slist_free_all (pre);

  su.url = "sftp://alice@127.0.0.1/up.bin";
  su.upload = content;
  su.upload_len = sizeof content;
  check (server_new (&sv) == 0, "server 2");
  post = commands ("rename /up.bin /done.bin", NULL, NULL);
  transfer = quote_run (&w, &sv, &su, NULL, post);
  check (transfer->done && transfer->result == TWIST_OK
         && uploaded_is (&sv, content, sizeof content), "an upload");
  check (op_is (&sv, sv.nops - 1, "rename", "/up.bin", "/done.bin"),
         "and a command after it");
  twist_transfer_free (transfer);
  server_free (&sv);
  twist_slist_free_all (post);
}

static void
test_create_dirs (void)
{
  struct server sv;
  struct world w;
  struct twist_transfer *transfer;
  struct setup su = SETUP ("sftp://alice@127.0.0.1/newa/newb/up.bin", 0,
                           "secret");

  su.upload = content;
  su.upload_len = sizeof content;

  /* Without the option the upload fails, as before.  */
  check (server_new (&sv) == 0, "server");
  transfer = run (&w, &sv, &su);
  check (transfer->done && transfer->result == TWIST_ERR_FILE
         && transfer->proto_status == 25
         && strcmp (ops_text (&sv), "open /newa/newb/up.bin") == 0,
         "a missing directory is an error");
  twist_transfer_free (transfer);
  server_free (&sv);

  /* With it, the directories are made and the open is tried again.  */
  su.create_dirs = 1;
  check (server_new (&sv) == 0, "server 2");
  transfer = run (&w, &sv, &su);
  check (transfer->done && transfer->result == TWIST_OK
         && uploaded_is (&sv, content, sizeof content), "the directories made");
  check (strcmp (ops_text (&sv), "open /newa/newb/up.bin|mkdir /newa"
                 "|mkdir /newa/newb|open /newa/newb/up.bin|close") == 0,
         "each one, from the top, then the open again");
  check (sv.ops[1].attrs.flags == GF_FILEXFER_ATTR_PERMISSIONS
         && sv.ops[1].attrs.permissions == 0755, "with mode 0755");
  twist_transfer_free (transfer);
  server_free (&sv);

  /* One that is there already: its mkdir fails and that is not an error.  */
  su.url = "sftp://alice@127.0.0.1/dir/sub/up.bin";
  check (server_new (&sv) == 0, "server 3");
  transfer = run (&w, &sv, &su);
  check (transfer->done && transfer->result == TWIST_OK
         && strcmp (ops_text (&sv), "open /dir/sub/up.bin|mkdir /dir"
                    "|mkdir /dir/sub|open /dir/sub/up.bin|close") == 0,
         "a directory that exists is not made again");
  twist_transfer_free (transfer);
  server_free (&sv);

  /* Where making them does not help, the error is the open's, once.  */
  su.url = "sftp://alice@127.0.0.1/bad/up.bin";
  check (server_new (&sv) == 0, "server 4");
  transfer = run (&w, &sv, &su);
  check (transfer->done && transfer->result == TWIST_ERR_FILE
         && transfer->proto_status == 25
         && strcmp (ops_text (&sv), "open /bad/up.bin|mkdir /bad"
                    "|open /bad/up.bin") == 0, "the open is tried once more");
  twist_transfer_free (transfer);
  server_free (&sv);

  /* A download is not helped by it.  */
  su.url = "sftp://alice@127.0.0.1/nodir/data.bin";
  su.upload = NULL;
  check (server_new (&sv) == 0, "server 5");
  transfer = run (&w, &sv, &su);
  check (transfer->done && transfer->result == TWIST_ERR_FILE
         && strcmp (ops_text (&sv), "open /nodir/data.bin") == 0,
         "a download does not make directories");
  twist_transfer_free (transfer);
  server_free (&sv);
}

/* A source that gives some data and then fails to read: an end of file would
   leave a short file that looks whole, so the callback says it failed.  */
static size_t
flaky_read (char *ptr, size_t size, size_t nmemb, void *user)
{
  int *calls = user;

  (void) size;
  (void) nmemb;
  if ((*calls)++ == 0)
    {
      memset (ptr, 'x', 5000);
      return 5000;
    }
  return TWIST_READFUNC_ABORT;
}

static void
test_upload_read_error (void)
{
  struct server sv;
  struct world w;
  struct twist_transfer *transfer;
  struct setup su = SETUP ("sftp://alice@127.0.0.1/up.bin", 0, "secret");
  int calls = 0;

  su.upload = content;
  su.upload_len = sizeof content;
  su.streamed = 1;
  check (server_new (&sv) == 0, "server");
  transfer = start (&w, &sv, &su);
  transfer->read_cb = flaky_read;
  transfer->read_data = &calls;
  check (twist_ssh_start (w.ssh) == TWIST_OK, "start");
  pump (&w, transfer, 65536);
  check (transfer->done && transfer->result == TWIST_ERR_ABORTED && calls >= 2,
         "a read that fails ends the upload with an error");
  check (!sv.closed_handle || sv.up_len <= 5000,
         "no more than was read was sent");
  twist_transfer_free (transfer);
  server_free (&sv);
}

/* Download from an offset, and the checks that go with it.  */
static void
test_download_resume (void)
{
  struct server sv;
  struct world w;
  struct twist_transfer *transfer;
  struct setup su = SETUP ("sftp://alice@127.0.0.1/data.bin", 0, "secret");

  check (server_new (&sv) == 0, "server");
  su.resume = 30000;
  transfer = run (&w, &sv, &su);
  check (transfer->done && transfer->result == TWIST_OK
         && got_is (content + 30000, sizeof content - 30000)
         && sv.first_read == 30000, "resume a download");
  check (transfer->size_download == sizeof content - 30000, "only the rest counted");
  twist_transfer_free (transfer);
  server_free (&sv);

  /* All of it is there already.  */
  check (server_new (&sv) == 0, "server 2");
  su.resume = (long long) sizeof content;
  transfer = run (&w, &sv, &su);
  check (transfer->done && transfer->result == TWIST_OK && got_len == 0
         && sv.reads == 0, "nothing left to fetch");
  twist_transfer_free (transfer);
  server_free (&sv);

  /* More than there is.  */
  check (server_new (&sv) == 0, "server 3");
  su.resume = 200000;
  transfer = run (&w, &sv, &su);
  check (transfer->done && transfer->result == TWIST_ERR_RESUME
         && sv.reads == 0
         && detail_has (transfer, "shorter"), "resume beyond the end");
  twist_transfer_free (transfer);
  server_free (&sv);

  /* A server that does not say how big the file is cannot be checked, and
     the transfer goes on.  */
  check (server_new (&sv) == 0, "server 4");
  sv.hide_size = 1;
  su.resume = 30000;
  transfer = run (&w, &sv, &su);
  check (transfer->done && transfer->result == TWIST_OK
         && got_is (content + 30000, sizeof content - 30000),
         "resume without a size");
  twist_transfer_free (transfer);
  server_free (&sv);

  /* A library caller cannot ask a download to find its own offset.  */
  check (server_new (&sv) == 0, "server 5");
  su.resume = -1;
  transfer = run (&w, &sv, &su);
  check (transfer->done && transfer->result == TWIST_ERR_INVAL,
         "no automatic offset");
  twist_transfer_free (transfer);
  server_free (&sv);

  check (server_new (&sv) == 0, "server 6");
  su.resume = 100;
  su.range = "0-9";
  transfer = run (&w, &sv, &su);
  check (transfer->done && transfer->result == TWIST_ERR_INVAL
         && detail_has (transfer, "cannot be used together"),
         "resume and range");
  twist_transfer_free (transfer);
  server_free (&sv);
}

/* One range, and what its bytes are.  */
static void
range_case (const char *range, size_t from, size_t n, int max_read,
            const char *what)
{
  struct server sv;
  struct world w;
  struct twist_transfer *transfer;
  struct setup su = SETUP ("sftp://alice@127.0.0.1/data.bin", 0, "secret");

  check (server_new (&sv) == 0, "server");
  sv.max_read = (size_t) max_read;
  su.range = range;
  transfer = run (&w, &sv, &su);
  check (transfer->done && transfer->result == TWIST_OK
         && got_is (content + from, n),
         what);
  twist_transfer_free (transfer);
  server_free (&sv);
}

static void
range_error (const char *range, int hide_size, const char *what)
{
  struct server sv;
  struct world w;
  struct twist_transfer *transfer;
  struct setup su = SETUP ("sftp://alice@127.0.0.1/data.bin", 0, "secret");

  check (server_new (&sv) == 0, "server");
  sv.hide_size = hide_size;
  su.range = range;
  transfer = run (&w, &sv, &su);
  check (transfer->done && transfer->result == TWIST_ERR_RANGE, what);
  twist_transfer_free (transfer);
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
  struct twist_transfer *transfer;
  struct setup su = SETUP (url, 0, "secret");

  check (server_new (&sv) == 0, "server");
  su.list_only = list_only;
  transfer = run (&w, &sv, &su);
  check (transfer->done && transfer->result == TWIST_OK && text_is (expect),
         what);
  check (strcmp (sv.opened, path_seen) == 0, "the directory asked for");
  check (sv.closed_handle, "the directory handle was closed");
  twist_transfer_free (transfer);
  server_free (&sv);
}

/* The state of a test is large (a server and a world hold megabytes of pipe),
   so the cases are called one after another, not from inside each other.  */
static void
test_listing_more (void)
{
  struct server sv;
  struct world w;
  struct twist_transfer *transfer;
  struct setup su = SETUP ("sftp://alice@127.0.0.1/big/", 0, "secret");
  char line[96], *want;
  size_t i, off = 0;

  /* Nothing in it.  */
  check (server_new (&sv) == 0, "server");
  su.url = "sftp://alice@127.0.0.1/empty/";
  transfer = run (&w, &sv, &su);
  check (transfer->done && transfer->result == TWIST_OK && got_len == 0,
         "an empty directory");
  twist_transfer_free (transfer);
  server_free (&sv);

  /* More entries than one answer holds, in the order the server gave.  */
  check (server_new (&sv) == 0, "server");
  sv.batch = 64;
  su.url = "sftp://alice@127.0.0.1/big/";
  transfer = run (&w, &sv, &su);
  want = malloc (BIG_DIR_N * 96);
  for (i = 0; i < BIG_DIR_N; i++)
    off += (size_t) snprintf (want + off, 96, "%s\n", big_dir[i].longname);
  check (transfer->done && transfer->result == TWIST_OK && got_len == off
         && memcmp (got, want, off) == 0, "a big directory, in order");
  check (sv.readdirs >= BIG_DIR_N / 64, "read in many answers");
  snprintf (line, sizeof line, "%s\n", big_dir[BIG_DIR_N - 1].longname);
  check (got_len >= strlen (line)
         && memcmp (got + got_len - strlen (line), line, strlen (line)) == 0,
         "the last entry");
  free (want);
  twist_transfer_free (transfer);
  server_free (&sv);

  /* What the server says about a directory that cannot be listed.  */
  check (server_new (&sv) == 0, "server");
  su.url = "sftp://alice@127.0.0.1/nope/";
  transfer = run (&w, &sv, &su);
  check (transfer->done && transfer->result == TWIST_ERR_FILE
         && transfer->proto_status == 78 && detail_has (transfer, "directory")
         && detail_has (transfer, "/nope"), "no such directory");
  twist_transfer_free (transfer);
  server_free (&sv);
  check (server_new (&sv) == 0, "server");
  su.url = "sftp://alice@127.0.0.1/denied/";
  transfer = run (&w, &sv, &su);
  check (transfer->done && transfer->result == TWIST_ERR_FILE
         && transfer->proto_status == 9
         && detail_has (transfer, "not for you"),
         "a directory that may not be listed");
  twist_transfer_free (transfer);
  server_free (&sv);
  check (server_new (&sv) == 0, "server");
  su.url = "sftp://alice@127.0.0.1/data.bin/";
  transfer = run (&w, &sv, &su);
  check (transfer->done && transfer->result == TWIST_ERR_FILE
         && transfer->proto_status == 78, "a file with a slash after it");
  twist_transfer_free (transfer);
  server_free (&sv);

  /* The application refuses the text part way.  */
  check (server_new (&sv) == 0, "server");
  su.url = "sftp://alice@127.0.0.1/dir/";
  collect_limit = 60;
  transfer = run (&w, &sv, &su);
  collect_limit = 0;
  check (transfer->done && transfer->result == TWIST_ERR_ABORTED,
         "a listing the application refuses");
  twist_transfer_free (transfer);
  server_free (&sv);

  /* A range or a resume means nothing for a directory.  */
  check (server_new (&sv) == 0, "server");
  su.range = "0-9";
  transfer = run (&w, &sv, &su);
  check (transfer->done && transfer->result == TWIST_ERR_INVAL
         && detail_has (transfer, "does not apply"),
         "a range and a directory");
  twist_transfer_free (transfer);
  server_free (&sv);
  check (server_new (&sv) == 0, "server");
  su.range = NULL;
  su.resume = 10;
  transfer = run (&w, &sv, &su);
  check (transfer->done && transfer->result == TWIST_ERR_INVAL
         && detail_has (transfer, "does not apply"),
         "a resume and a directory");
  twist_transfer_free (transfer);
  server_free (&sv);

  /* scp does not list: it names one file.  */
  check (server_new (&sv) == 0, "server");
  su.resume = 0;
  su.url = "scp://alice@127.0.0.1/dir/";
  transfer = run (&w, &sv, &su);
  check (transfer->done && transfer->result == TWIST_ERR_FILE
         && transfer->proto_status == 78 && detail_has (transfer, "sftp://")
         && got_len == 0, "scp does not list a directory");
  twist_transfer_free (transfer);
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

/* ---- an ssh-agent ---- */

/* An agent in the test, on a Unix socket with its own thread, speaking the
   protocol of draft-ietf-sshm-ssh-agent.  It holds keys it can sign with,
   and can misbehave in the ways an agent can.  Its counters are read after
   it has been stopped, which joins the thread.  */

#define AG_KEYS 12
#define AG_CONNS 4

struct agent
{
  int listen_fd;
  char path[108];
  pthread_t thread;
  int stop;
  int fd[AG_CONNS];
  uint8_t in[AG_CONNS][8192];
  size_t inlen[AG_CONNS];
  gf_key *keys[AG_KEYS];	/* Not owned.  */
  size_t nkeys;
  /* What it does wrong.  */
  int junk;			/* An identity that is not a key, first.  */
  int refuse_sign;		/* FAILURE for a request to sign.  */
  int close_on_sign;		/* Hang up on one.  */
  int silent;			/* Never answers a request for identities.  */
  int garbage;			/* Answers it with a frame of length 0.  */
  int oversize;			/* Or with one over the limit.  */
  int bind_reply;		/* 6, 5 or 28 for session-bind; 0: 5.  */
  /* What it saw.  */
  unsigned connections, id_requests, sign_requests, binds;
  uint32_t last_flags;
  uint8_t bind_host[512];
  size_t bind_host_len;
  uint8_t bind_session[128];
  size_t bind_session_len;
};

static void
put32 (uint8_t *p, uint32_t v)
{
  p[0] = (uint8_t) (v >> 24);
  p[1] = (uint8_t) (v >> 16);
  p[2] = (uint8_t) (v >> 8);
  p[3] = (uint8_t) v;
}

static void
ag_reply (int fd, const uint8_t *payload, size_t n)
{
  uint8_t head[4];

  put32 (head, (uint32_t) n);
  if (write (fd, head, 4) == 4 && n > 0)
    (void) !write (fd, payload, n);
}

static void
ag_identities (struct agent *a, int fd)
{
  uint8_t buf[8192];
  gf_writer w;
  size_t i, blen;

  if (a->silent)
    return;
  if (a->garbage)
    {
      ag_reply (fd, NULL, 0);
      return;
    }
  if (a->oversize)
    {
      uint8_t head[4];

      put32 (head, 300000);
      (void) !write (fd, head, 4);
      return;
    }
  gf_writer_init (&w, buf, sizeof buf);
  gf_wr_u8 (&w, 12);
  gf_wr_u32 (&w, (uint32_t) (a->nkeys + (a->junk ? 1 : 0)));
  if (a->junk)
    {
      gf_wr_string (&w, "not a key", 9);
      gf_wr_string (&w, "junk", 4);
    }
  for (i = 0; i < a->nkeys; i++)
    {
      const uint8_t *blob = gf_key_blob (a->keys[i], &blen);

      gf_wr_string (&w, blob, blen);
      gf_wr_string (&w, "test key", 8);
    }
  ag_reply (fd, buf, w.len);
}

static void
ag_sign (struct agent *a, int idx, const uint8_t *p, size_t n)
{
  gf_reader r;
  gf_slice blob, data;
  uint32_t flags;
  uint8_t sig[1024], out[1100];
  size_t i, siglen = 0, nalgs;
  gf_writer w;

  a->sign_requests++;
  if (a->close_on_sign)
    {
      close (a->fd[idx]);
      a->fd[idx] = -1;
      return;
    }
  gf_reader_init (&r, p + 1, n - 1);
  if (gf_rd_string (&r, &blob) != GF_OK || gf_rd_string (&r, &data) != GF_OK
      || gf_rd_u32 (&r, &flags) != GF_OK || a->refuse_sign)
    {
      static const uint8_t fail[] = { 5 };

      ag_reply (a->fd[idx], fail, 1);
      return;
    }
  a->last_flags = flags;
  for (i = 0; i < a->nkeys; i++)
    {
      size_t blen;
      const uint8_t *kb = gf_key_blob (a->keys[i], &blen);
      const enum gf_sigalg *algs = gf_key_sigalgs (a->keys[i], &nalgs);
      enum gf_sigalg alg = algs[0];

      if (blen != blob.len || memcmp (kb, blob.data, blen) != 0)
        continue;
      if (gf_key_type (a->keys[i]) == GF_KEY_RSA)
        alg = (flags & 4u) ? GF_SIG_RSA_SHA2_512 : GF_SIG_RSA_SHA2_256;
      if (gf_key_sign (a->keys[i], alg, data.data, data.len, sig, sizeof sig,
                       &siglen) != GF_OK)
        break;
      gf_writer_init (&w, out, sizeof out);
      gf_wr_u8 (&w, 14);
      gf_wr_string (&w, sig, siglen);
      ag_reply (a->fd[idx], out, w.len);
      return;
    }
  {
    static const uint8_t fail[] = { 5 };

    ag_reply (a->fd[idx], fail, 1);
  }
}

static void
ag_extension (struct agent *a, int idx, const uint8_t *p, size_t n)
{
  gf_reader r;
  gf_slice name, host, session, sig;
  int fwd;
  uint8_t reply = (uint8_t) (a->bind_reply != 0 ? a->bind_reply : 5);

  gf_reader_init (&r, p + 1, n - 1);
  if (gf_rd_string (&r, &name) == GF_OK && gf_slice_equals (name, "session-bind@openssh.com")
      && gf_rd_string (&r, &host) == GF_OK && gf_rd_string (&r, &session) == GF_OK
      && gf_rd_string (&r, &sig) == GF_OK && gf_rd_bool (&r, &fwd) == GF_OK
      && gf_rd_finish (&r) == GF_OK && !fwd)
    {
      a->binds++;
      if (host.len <= sizeof a->bind_host)
        {
          memcpy (a->bind_host, host.data, host.len);
          a->bind_host_len = host.len;
        }
      if (session.len <= sizeof a->bind_session)
        {
          memcpy (a->bind_session, session.data, session.len);
          a->bind_session_len = session.len;
        }
    }
  else
    reply = 5;
  ag_reply (a->fd[idx], &reply, 1);
}

static void
ag_frame (struct agent *a, int idx, const uint8_t *p, size_t n)
{
  switch (p[0])
    {
    case 11:
      a->id_requests++;
      ag_identities (a, a->fd[idx]);
      break;
    case 13:
      ag_sign (a, idx, p, n);
      break;
    case 27:
      ag_extension (a, idx, p, n);
      break;
    default:
      {
        static const uint8_t fail[] = { 5 };

        ag_reply (a->fd[idx], fail, 1);
      }
    }
}

static void *
ag_serve (void *arg)
{
  struct agent *a = arg;
  struct pollfd fds[AG_CONNS + 1];
  int map[AG_CONNS + 1];
  int i, n;

  while (!__atomic_load_n (&a->stop, __ATOMIC_ACQUIRE))
    {
      n = 0;
      fds[n].fd = a->listen_fd;
      fds[n].events = POLLIN;
      map[n++] = -1;
      for (i = 0; i < AG_CONNS; i++)
        if (a->fd[i] >= 0)
          {
            fds[n].fd = a->fd[i];
            fds[n].events = POLLIN;
            map[n++] = i;
          }
      if (poll (fds, (nfds_t) n, 20) <= 0)
        continue;
      if (fds[0].revents & POLLIN)
        {
          int c = accept (a->listen_fd, NULL, NULL);

          for (i = 0; c >= 0 && i < AG_CONNS; i++)
            if (a->fd[i] < 0)
              {
                a->fd[i] = c;
                a->inlen[i] = 0;
                a->connections++;
                c = -1;
              }
          if (c >= 0)
            close (c);
        }
      for (i = 1; i < n; i++)
        {
          int idx = map[i];
          ssize_t nread;

          if (!(fds[i].revents & (POLLIN | POLLHUP)) || a->fd[idx] < 0)
            continue;
          nread = read (a->fd[idx], a->in[idx] + a->inlen[idx],
                        sizeof a->in[idx] - a->inlen[idx]);
          if (nread <= 0)
            {
              close (a->fd[idx]);
              a->fd[idx] = -1;
              continue;
            }
          a->inlen[idx] += (size_t) nread;
          while (a->fd[idx] >= 0 && a->inlen[idx] >= 4)
            {
              size_t len = ((size_t) a->in[idx][0] << 24)
                           | ((size_t) a->in[idx][1] << 16)
                           | ((size_t) a->in[idx][2] << 8) | a->in[idx][3];

              if (len == 0 || len + 4 > sizeof a->in[idx])
                {
                  close (a->fd[idx]);
                  a->fd[idx] = -1;
                  break;
                }
              if (a->inlen[idx] < len + 4)
                break;
              ag_frame (a, idx, a->in[idx] + 4, len);
              if (a->fd[idx] >= 0)
                {
                  memmove (a->in[idx], a->in[idx] + 4 + len,
                           a->inlen[idx] - 4 - len);
                  a->inlen[idx] -= 4 + len;
                }
            }
        }
    }
  for (i = 0; i < AG_CONNS; i++)
    if (a->fd[i] >= 0)
      close (a->fd[i]);
  return NULL;
}

static int agent_serial;

static int
agent_start (struct agent *a)
{
  struct sockaddr_un sa;
  int i;

  memset (a, 0, sizeof *a);
  for (i = 0; i < AG_CONNS; i++)
    a->fd[i] = -1;
  /* A Unix socket's path is short; the scratch directories are not.  */
  snprintf (a->path, sizeof a->path, "/tmp/twist-agent-%ld-%d.sock",
            (long) getpid (), agent_serial++);
  unlink (a->path);
  a->listen_fd = socket (AF_UNIX, SOCK_STREAM, 0);
  if (a->listen_fd < 0)
    return -1;
  memset (&sa, 0, sizeof sa);
  sa.sun_family = AF_UNIX;
  snprintf (sa.sun_path, sizeof sa.sun_path, "%s", a->path);
  if (bind (a->listen_fd, (struct sockaddr *) &sa, sizeof sa) != 0
      || listen (a->listen_fd, 4) != 0)
    return -1;
  return pthread_create (&a->thread, NULL, ag_serve, a);
}

static void
agent_stop (struct agent *a)
{
  __atomic_store_n (&a->stop, 1, __ATOMIC_RELEASE);
  pthread_join (a->thread, NULL);
  close (a->listen_fd);
  unlink (a->path);
}

/* One transfer through an agent, and what came of it.  */
struct acase
{
  int nwrong;			/* Keys the server does not know, first.  */
  int junk, refuse_sign, close_on_sign, silent, garbage, oversize;
  int bind_reply;
  int rsa;			/* The agent's key is an RSA key.  */
  int no_agent_key;		/* The agent holds none of the right key.  */
  int agent_listens;		/* 0: the socket is a path with no agent.  */
  const char *option;		/* The socket option; NULL: not set.  */
  int env;			/* Name the socket in SSH_AUTH_SOCK.  */
  int file_key;			/* A key the server knows in ~/.ssh.  */
  int explicit_key;		/* --key, the right key.  */
  int password;			/* The client has a password, right.  */
  unsigned timeout_ms;		/* For the identities.  */
  int abandon;			/* Let go before the agent answers.  */
};

struct aresult
{
  int done, result;
  char detail[320];
  unsigned connections, id_requests, sign_requests, binds;
  uint32_t flags;
  int bind_match;		/* The bind named the host key and session.  */
  unsigned noffered;
  char first_offered[64];
  char authorized_fp[64];
  char file_key_fp[64];
  size_t got;
};

static void
run_acase (const struct acase *c, struct aresult *res)
{
  struct server *sv = calloc (1, sizeof *sv);
  struct world *w = calloc (1, sizeof *w);
  struct agent ag;
  gf_key *wrong[AG_KEYS];
  struct twist_runtime *runtime = twist_runtime_new ();
  struct twist_transfer *transfer;
  struct setup su = SETUP ("sftp://alice@127.0.0.1/data.bin", 0, NULL);
  char keytext[2048], path[320], ssh_dir[300];
  size_t kn = 0;
  int i, nwrong = c->nwrong;

  memset (res, 0, sizeof *res);
  check (sv != NULL && w != NULL && runtime != NULL, "agent case allocation");
  check (server_new (sv) == 0, "server");
  sv->password = c->password ? "secret" : NULL;
  if (c->rsa)
    {
      gf_key_free (sv->authorized);
      check (gf_key_generate (&sv->authorized, GF_KEY_RSA, 2048) == GF_OK,
             "rsa key");
    }
  gf_key_fingerprint (sv->authorized, res->authorized_fp, 64);
  if (c->agent_listens)
    check (agent_start (&ag) == 0, "agent");
  else
    {
      memset (&ag, 0, sizeof ag);
      snprintf (ag.path, sizeof ag.path, "/tmp/twist-no-agent-%ld.sock",
                (long) getpid ());
      unlink (ag.path);
    }
  for (i = 0; i < nwrong && i < AG_KEYS - 1; i++)
    {
      check (gf_key_generate (&wrong[i], GF_KEY_ED25519, 0) == GF_OK, "wrong");
      ag.keys[ag.nkeys++] = wrong[i];
    }
  if (!c->no_agent_key)
    ag.keys[ag.nkeys++] = sv->authorized;
  ag.junk = c->junk;
  ag.refuse_sign = c->refuse_sign;
  ag.close_on_sign = c->close_on_sign;
  ag.silent = c->silent;
  ag.garbage = c->garbage;
  ag.oversize = c->oversize;
  ag.bind_reply = c->bind_reply;

  if (c->file_key)
    {
      check (gf_key_generate (&sv->also[0], GF_KEY_ED25519, 0) == GF_OK,
             "file key");
      sv->nalso = 1;
      gf_key_fingerprint (sv->also[0], res->file_key_fp, 64);
      check (gf_key_to_openssh_private (sv->also[0], keytext, sizeof keytext,
                                        &kn) == GF_OK, "file key text");
      snprintf (ssh_dir, sizeof ssh_dir, "%s/.ssh", home);
      mkdir (ssh_dir, 0700);
      snprintf (path, sizeof path, "%s/id_ed25519", ssh_dir);
      write_file (path, keytext, kn, 0600);
    }
  if (c->explicit_key)
    {
      check (gf_key_to_openssh_private (sv->authorized, keytext,
                                        sizeof keytext, &kn) == GF_OK,
             "key text");
      snprintf (path, sizeof path, "%s/explicit", home);
      write_file (path, keytext, kn, 0600);
      su.keyfile = path;
    }
  if (c->password)
    su.password = "secret";
  if (c->env)
    setenv ("SSH_AUTH_SOCK", ag.path, 1);
  else
    unsetenv ("SSH_AUTH_SOCK");
  su.runtime = runtime;
  su.agent = c->option != NULL && strcmp (c->option, "path") == 0
             ? ag.path : c->option;
  su.agent_timeout_ms = c->timeout_ms;

  transfer = start (w, sv, &su);
  if (c->abandon)
    {
      struct timespec nap = { 0, 20000000 };

      check (twist_ssh_start (w->ssh) == TWIST_OK, "start");
      nanosleep (&nap, NULL);
      twist_transfer_free (transfer);
      twist_runtime_free (runtime);
      goto stop;
    }
  {
    int rc = twist_ssh_start (w->ssh);

    if (rc != TWIST_OK && !transfer->done)
      twist_transfer_finish (transfer, rc);
    if (rc == TWIST_OK)
      pump_with_loop (runtime, w, transfer, 65536);
  }
  res->done = transfer->done;
  res->result = transfer->result;
  snprintf (res->detail, sizeof res->detail, "%s",
            twist_transfer_error (transfer) != NULL
            ? twist_transfer_error (transfer) : "");
  res->got = got_len;
  if (getenv ("ACASE_DEBUG") != NULL)
    fprintf (stderr, "DBG case: done=%d result=%d detail='%s' got=%zu\n",
             res->done, res->result, res->detail, res->got);
  res->noffered = sv->noffered;
  if (sv->noffered > 0)
    snprintf (res->first_offered, sizeof res->first_offered, "%s",
              sv->offered[0]);
  twist_transfer_free (transfer);
  twist_runtime_free (runtime);
stop:
  if (c->agent_listens)
    {
      agent_stop (&ag);
      res->connections = ag.connections;
      res->id_requests = ag.id_requests;
      res->sign_requests = ag.sign_requests;
      res->binds = ag.binds;
      res->flags = ag.last_flags;
      if (ag.binds > 0)
        {
          size_t hl;
          const uint8_t *hb = gf_key_blob (sv->host, &hl);
          const gf_conn_info *info = gf_session_info (sv->s);

          res->bind_match = info != NULL && ag.bind_host_len == hl
                            && memcmp (ag.bind_host, hb, hl) == 0
                            && ag.bind_session_len == info->session_id_len
                            && memcmp (ag.bind_session, info->session_id,
                                       ag.bind_session_len) == 0;
        }
    }
  for (i = 0; i < nwrong && i < AG_KEYS - 1; i++)
    gf_key_free (wrong[i]);
  server_free (sv);
  free (sv);
  free (w);
  unsetenv ("SSH_AUTH_SOCK");
  if (c->file_key)
    {
      snprintf (path, sizeof path, "%s/.ssh/id_ed25519", home);
      unlink (path);
      snprintf (path, sizeof path, "%s/.ssh", home);
      rmdir (path);
    }
  if (c->explicit_key)
    {
      snprintf (path, sizeof path, "%s/explicit", home);
      unlink (path);
    }
}

static int
detail_contains (const struct aresult *r, const char *text)
{
  return strstr (r->detail, text) != NULL;
}

/* The agent signs for a key the server knows, and the client has nothing
   else: no password, no key file.  */
static void
test_agent_login (void)
{
  struct acase c = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, "path", 0, 0, 0, 0, 0, 0 };
  struct aresult r;

  run_acase (&c, &r);
  check (r.done && r.result == TWIST_OK && r.got == FILE_LEN, "login by agent");
  check (r.connections == 1 && r.id_requests == 1 && r.sign_requests == 1,
         "one connection, one list, one signature");
  check (r.flags == 0, "an Ed25519 signature needs no flags");

  /* The socket named by the environment, with the option not set.  */
  c.option = NULL;
  c.env = 1;
  run_acase (&c, &r);
  check (r.done && r.result == TWIST_OK && r.sign_requests == 1,
         "SSH_AUTH_SOCK is used when the option is not");

  /* An empty option means no agent, whatever the environment says.  */
  c.option = "";
  c.password = 1;
  run_acase (&c, &r);
  check (r.done && r.result == TWIST_OK && r.connections == 0,
         "an empty option turns the agent off");
  c.password = 0;

  /* A key that is not one is skipped, and the real one still works.  */
  c.option = "path";
  c.env = 0;
  c.junk = 1;
  run_acase (&c, &r);
  check (r.done && r.result == TWIST_OK && r.sign_requests == 1,
         "an identity that is not a key is skipped");
}

/* Keys the server does not know come first.  There is no limit of twist's
   own: the server's decides.  */
static void
test_agent_many_keys (void)
{
  struct acase c = { 7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, "path", 0, 0, 0, 0, 0, 0 };
  struct aresult r;

  run_acase (&c, &r);
  check (r.done && r.result == TWIST_OK && r.sign_requests == 1,
         "the right key is the eighth");
  check (r.noffered == 8, "all eight were offered, in turn");
  check (strcmp (r.first_offered, r.authorized_fp) != 0,
         "the agent's order is kept: the right key was not first");
}

/* A key named on the command line is used alone.  Without one the agent's
   come before the files'.  */
static void
test_agent_precedence (void)
{
  struct acase c = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, "path", 0, 0, 1, 0, 0, 0 };
  struct aresult r;

  run_acase (&c, &r);
  check (r.done && r.result == TWIST_OK && r.connections == 0,
         "a named key is used without asking the agent");

  c.explicit_key = 0;
  c.file_key = 1;
  run_acase (&c, &r);
  check (r.done && r.result == TWIST_OK && r.sign_requests == 1
         && strcmp (r.first_offered, r.authorized_fp) == 0,
         "the agent's key is offered before the file's");

  /* An agent with nothing for the server goes on to the files.  */
  c.no_agent_key = 1;
  run_acase (&c, &r);
  check (r.done && r.result == TWIST_OK && r.id_requests == 1
         && r.sign_requests == 0
         && strcmp (r.first_offered, r.file_key_fp) == 0,
         "an empty agent leaves the files' keys");
}

/* An agent that will not sign, or hangs up when asked, costs its key and
   nothing else.  The password still works.  */
static void
test_agent_refusal (void)
{
  struct acase c = { 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, "path", 0, 0, 0, 1, 0, 0 };
  struct aresult r;

  run_acase (&c, &r);
  check (r.done && r.result == TWIST_OK && r.sign_requests == 1,
         "an agent that refuses to sign: the password does");
  c.refuse_sign = 0;
  c.close_on_sign = 1;
  run_acase (&c, &r);
  check (r.done && r.result == TWIST_OK && r.sign_requests == 1,
         "an agent that hangs up on a request: the password does");

  /* With nothing else to try, the failure says why.  */
  c.password = 0;
  run_acase (&c, &r);
  check (r.done && r.result == TWIST_ERR_AUTH
         && detail_contains (&r, "ssh-agent"),
         "the agent is named when it was the only hope");
}

/* An agent that is not there, or says nonsense.  Never fatal by itself.  */
static void
test_agent_failures (void)
{
  struct acase c = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, "path", 0, 0, 0, 1, 0, 0 };
  struct aresult r;

  /* The socket has nothing behind it.  */
  run_acase (&c, &r);
  check (r.done && r.result == TWIST_OK, "no agent at the socket: password");
  c.password = 0;
  run_acase (&c, &r);
  check (r.done && r.result == TWIST_ERR_AUTH
         && detail_contains (&r, "ssh-agent: cannot connect"),
         "and it says so when nothing else was left");

  /* A path no Unix socket can have.  */
  c.password = 1;
  c.option = "/tmp/01234567890123456789012345678901234567890123456789"
             "0123456789012345678901234567890123456789012345678901234567890123456789";
  run_acase (&c, &r);
  check (r.done && r.result == TWIST_OK, "a path that is too long: password");
  c.password = 0;
  run_acase (&c, &r);
  check (r.done && detail_contains (&r, "too long"),
         "a path that is too long is said to be");

  /* An agent that answers with nonsense.  */
  c.agent_listens = 1;
  c.option = "path";
  c.password = 1;
  c.garbage = 1;
  run_acase (&c, &r);
  check (r.done && r.result == TWIST_OK && r.sign_requests == 0,
         "a frame of length 0 from the agent: password");
  c.garbage = 0;
  c.oversize = 1;
  run_acase (&c, &r);
  check (r.done && r.result == TWIST_OK && r.sign_requests == 0,
         "a frame over the limit from the agent: password");
  c.oversize = 0;

  /* An agent that never answers: given a few moments, not the transfer's
     whole life.  */
  c.silent = 1;
  c.timeout_ms = 200;
  run_acase (&c, &r);
  check (r.done && r.result == TWIST_OK && r.id_requests == 1,
         "an agent that never answers: password after the wait");
  c.password = 0;
  run_acase (&c, &r);
  check (r.done && r.result == TWIST_ERR_AUTH
         && detail_contains (&r, "did not answer"),
         "and it is said to have been silent");
}

/* RSA keys: the algorithm decides the flags.  */
static void
test_agent_rsa (void)
{
  struct acase c = { 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, "path", 0, 0, 0, 0, 0, 0 };
  struct aresult r;

  run_acase (&c, &r);
  check (r.done && r.result == TWIST_OK && r.sign_requests == 1
         && (r.flags == 2 || r.flags == 4), "an RSA key signs with SHA-2 flags");
}

/* An agent holding keys restricted to a destination wants to be told which
   server this is, with the host key and the session identifier.  Whatever it
   answers, the login goes on.  */
static void
test_agent_session_bind (void)
{
  struct acase c = { 0, 0, 0, 0, 0, 0, 0, 6, 0, 0, 1, "path", 0, 0, 0, 0, 0, 0 };
  struct aresult r;

  run_acase (&c, &r);
  check (r.done && r.result == TWIST_OK && r.binds == 1 && r.bind_match,
         "the agent is told the host key and the session");
  c.bind_reply = 5;
  run_acase (&c, &r);
  check (r.done && r.result == TWIST_OK && r.binds == 1,
         "an agent that answers FAILURE to it is still used");
  c.bind_reply = 28;
  run_acase (&c, &r);
  check (r.done && r.result == TWIST_OK && r.binds == 1,
         "and so is one that does not know the extension");
}

/* The transfer is let go of while the agent has not answered.  Nothing may
   be touched afterwards; valgrind finds it if it is.  */
static void
test_agent_abandoned (void)
{
  struct acase c = { 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 1, "path", 0, 0, 0, 0, 0, 1 };
  struct aresult r;
  int i;

  for (i = 0; i < 3; i++)
    run_acase (&c, &r);
  check (1, "abandoned while the agent was asked");
}

/* ---- keyboard-interactive, from the client ---- */

static void
kbd_case (unsigned methods, int mode, const char *client_password,
          const char *server_password, int expect_ok, unsigned requests,
          const char *what)
{
  struct server sv;
  struct world w;
  struct twist_transfer *transfer;
  struct setup su = SETUP ("sftp://alice@127.0.0.1/data.bin", 0, NULL);

  next_server_methods = methods;
  check (server_new (&sv) == 0, "server");
  sv.kbd_mode = mode;
  sv.password = server_password;
  su.password = client_password;
  transfer = run (&w, &sv, &su);
  check (transfer->done && (expect_ok ? transfer->result == TWIST_OK
                                      : transfer->result == TWIST_ERR_AUTH),
         what);
  check (sv.kbd_requests == requests, "the method was tried as often as it should be");
  twist_transfer_free (transfer);
  server_free (&sv);
}

/* A server that asks for the password as a question, and not as the
   password method, is answered with the password.  */
/* The cases that need the state of a test are separate from those that are
   one call of kbd_case, so the large frames are never nested.  */
static void
test_kbdint_more (void)
{
  struct server sv;
  struct world w;
  struct twist_transfer *transfer;
  struct setup su = SETUP ("sftp://alice@127.0.0.1/data.bin", 0, "secret");
  const unsigned kbd_only = GF_AUTH_PUBLICKEY | GF_AUTH_KBDINT;
  const unsigned both = GF_AUTH_PUBLICKEY | GF_AUTH_KBDINT | GF_AUTH_PASSWORD;

  /* Two questions: the password is not given to either.  The password
     method is still there.  */
  next_server_methods = both;
  check (server_new (&sv) == 0, "server");
  sv.kbd_mode = KBD_TWO;
  transfer = run (&w, &sv, &su);
  check (transfer->done && transfer->result == TWIST_OK, "two questions: the password method works");
  check (sv.kbd_answers == 2 && sv.kbd_first_len == 0,
         "and the questions were answered with nothing");
  twist_transfer_free (transfer);
  server_free (&sv);

  /* With nothing else, the failure says what was asked.  */
  next_server_methods = kbd_only;
  check (server_new (&sv) == 0, "server");
  sv.kbd_mode = KBD_TWO;
  transfer = run (&w, &sv, &su);
  check (transfer->done && transfer->result == TWIST_ERR_AUTH
         && detail_has (transfer, "keyboard-interactive")
         && detail_has (transfer, "more than one"),
         "two questions, nothing else");
  check (sv.kbd_first_len == 0, "the password was not sent");
  twist_transfer_free (transfer);
  server_free (&sv);

  /* A question that is shown as it is typed is not a password.  */
  next_server_methods = kbd_only;
  check (server_new (&sv) == 0, "server");
  sv.kbd_mode = KBD_ECHOED;
  transfer = run (&w, &sv, &su);
  check (transfer->done && transfer->result == TWIST_ERR_AUTH
         && detail_has (transfer, "Username") && sv.kbd_first_len == 0,
         "a question that is not hidden gets no password, and is named");
  twist_transfer_free (transfer);
  server_free (&sv);

  /* What a server calls a question is not trusted with the terminal.  */
  next_server_methods = kbd_only;
  check (server_new (&sv) == 0, "server");
  sv.kbd_mode = KBD_HOSTILE;
  transfer = run (&w, &sv, &su);
  check (transfer->done && transfer->result == TWIST_ERR_AUTH
         && detail_has (transfer, "Code:") && !detail_has (transfer, "\033")
         && !detail_has (transfer, "\n") && !detail_has (transfer, "\r"),
         "the question is shown without its control characters");
  twist_transfer_free (transfer);
  server_free (&sv);
}

static void
test_kbdint (void)
{
  const unsigned kbd_only = GF_AUTH_PUBLICKEY | GF_AUTH_KBDINT;
  const unsigned both = GF_AUTH_PUBLICKEY | GF_AUTH_KBDINT | GF_AUTH_PASSWORD;

  kbd_case (kbd_only, KBD_PASSWORD, "secret", "secret", 1, 1,
            "a password given to a question");
  kbd_case (kbd_only, KBD_PASSWORD, "wrong", "secret", 0, 1,
            "a wrong password to a question");
  /* With nothing to answer it, the method is not tried.  */
  kbd_case (kbd_only, KBD_PASSWORD, NULL, "secret", 0, 0,
            "no password: no question asked");
  /* A round with nothing to answer comes first.  */
  kbd_case (kbd_only, KBD_INFO_FIRST, "secret", "secret", 1, 1,
            "a round with no question, then the password");
  /* When the server offers both, the question is first.  */
  kbd_case (both, KBD_PASSWORD, "secret", "secret", 1, 1,
            "both offered: the question is answered");
  test_kbdint_more ();
}

/* A peer that is not SSH-2.  */
static void
test_bad_peer (void)
{
  static const char old[] = "SSH-1.5-ancient\r\n";
  struct twist_transfer *transfer;
  struct world w;
  struct server sv;
  struct setup su = SETUP ("sftp://alice@127.0.0.1/data.bin", 0, "secret");

  memset (&sv, 0, sizeof sv);
  transfer = start (&w, &sv, &su);
  check (twist_ssh_start (w.ssh) == TWIST_OK, "start");
  twist_ssh_receive (w.ssh, (const uint8_t *) old, sizeof old - 1);
  check (transfer->done && transfer->result == TWIST_ERR_PROTOCOL,
         "SSH-1 refused");
  twist_transfer_free (transfer);
}

/* A server that never answers: the key exchange has a deadline, and the
   timeout is reported as one.  */
static void
test_timeout (void)
{
  struct twist_transfer *transfer;
  struct world w;
  struct server sv;
  struct setup su = SETUP ("sftp://alice@127.0.0.1/data.bin", 0, "secret");
  uint64_t due;

  memset (&sv, 0, sizeof sv);
  transfer = start (&w, &sv, &su);
  check (twist_ssh_start (w.ssh) == TWIST_OK, "start");
  due = twist_ssh_deadline (w.ssh);
  check (due != UINT64_MAX && due > now_us, "deadline set");
  twist_ssh_set_time (w.ssh, due);
  twist_ssh_timeout (w.ssh);
  check (transfer->done && transfer->result == TWIST_ERR_TIMEOUT, "timeout");
  twist_transfer_free (transfer);
}

/* No user name at all.  */
static void
test_no_user (void)
{
  struct twist_transfer *transfer = twist_transfer_new ();
  struct twist_ssh *ssh;
  struct pipe *sink = calloc (1, sizeof *sink);

  check (twist_url_parse_int ("sftp://127.0.0.1/data.bin", &transfer->url)
         == TWIST_OK, "url");
  ssh = twist_ssh_new (transfer, 0);
  twist_ssh_set_sink (ssh, client_sink, sink);
  check (twist_ssh_start (ssh) == TWIST_ERR_AUTH
         && detail_has (transfer, "no user name"), "no user");
  twist_transfer_free (transfer);
  free (sink);
}

/* Wait, driving the loop, until COND holds or about two seconds pass.  */
#define WAIT_FOR(runtime, cond)                                         \
  do                                                                    \
    {                                                                   \
      struct timespec nap_ = { 0, 2000000 };                            \
      int spins_;                                                       \
                                                                        \
      for (spins_ = 0; spins_ < 1000 && !(cond); spins_++)              \
        {                                                               \
          twist_runtime_run_once ((runtime), 0);                        \
          nanosleep (&nap_, NULL);                                      \
        }                                                               \
    }                                                                   \
  while (0)

/* Put TRANSFER on RUNTIME's loop and storage pool without starting a transfer:
   twist_runtime_start would start the real handler, which dials.  The handler
   under test is driven by hand, and the runtime has nothing to report
   of it.  */
static void
attach_by_hand (struct twist_runtime *runtime, struct twist_transfer *transfer)
{
  transfer->runtime = runtime;
  transfer->loop = runtime->loop;
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
  struct twist_runtime *runtime = twist_runtime_new ();
  struct twist_transfer *transfer = twist_transfer_new ();
  char keytext[2048], keyfile[300], kh[300];
  size_t kn = 0;

  check (runtime != NULL && server_new (&sv) == 0, "server and runtime");
  check (gf_key_to_openssh_private (sv.authorized, keytext, sizeof keytext,
                                    &kn) == GF_OK, "key text");
  snprintf (keyfile, sizeof keyfile, "%s/poolkey", home);
  write_file (keyfile, keytext, kn, 0600);
  known_hosts_with (sv.host, kh, sizeof kh);
  check (twist_url_parse_int ("sftp://alice@127.0.0.1/data.bin",
                              &transfer->url)
         == TWIST_OK, "url");
  twist_transfer_setopt (transfer, TWISTOPT_SSLKEY, keyfile);
  twist_transfer_setopt (transfer, TWISTOPT_SSH_KNOWNHOSTS, kh);
  transfer->write_cb = collect;
  got_len = 0;
  attach_by_hand (runtime, transfer);
  w.sv = &sv;
  w.c2s.len = 0;
  w.ssh = twist_ssh_new (transfer, 0);
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
  WAIT_FOR (runtime, w.c2s.len > 0 || transfer->done);
  check (w.c2s.len > 0, "the session started when the job was done");
  check (w.ssh->load_thread_set
         && !pthread_equal (w.ssh->load_thread, pthread_self ()),
         "the files were read off the loop thread");
  pump (&w, transfer, 65536);
  check (transfer->done && transfer->result == TWIST_OK
         && got_len == sizeof content && memcmp (got, content, got_len) == 0,
         "download with a key and known_hosts loaded by the pool");
  twist_transfer_free (transfer);
  twist_runtime_free (runtime);
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
  struct twist_runtime *runtime = twist_runtime_new ();
  struct twist_transfer *transfer = twist_transfer_new ();

  check (runtime != NULL && server_new (&sv) == 0, "server and runtime");
  check (twist_url_parse_int ("sftp://alice@127.0.0.1/data.bin",
                              &transfer->url)
         == TWIST_OK, "url");
  twist_transfer_setopt (transfer, TWISTOPT_SSLKEY, "/nonexistent/key");
  attach_by_hand (runtime, transfer);
  w.sv = &sv;
  w.c2s.len = 0;
  w.ssh = twist_ssh_new (transfer, 0);
  twist_ssh_set_sink (w.ssh, client_sink, &w.c2s);
  check (twist_ssh_start (w.ssh) == TWIST_OK, "start submits the job");
  WAIT_FOR (runtime, transfer->done);
  check (transfer->done && transfer->result == TWIST_ERR_FILE
         && detail_has (transfer, "cannot read the private key"),
         "the job's error ends the transfer");
  check (w.c2s.len == 0, "nothing was sent");
  twist_transfer_free (transfer);
  twist_runtime_free (runtime);
  server_free (&sv);
}

/* ---- a server on a socket, for the connections that are kept ---- */

#define TS_CONNS 8

struct ts_conn
{
  int fd;
  struct server *sv;
};

struct tcp_server
{
  int lfd, port;
  pthread_t thread;
  volatile int stop;
  gf_key *host;
  struct ts_conn conns[TS_CONNS];
  pthread_mutex_t mu;
  unsigned accepted;		/* Connections made to it.  */
  int hang_up;			/* Asked to close every connection.  */
  size_t up_len;		/* What was uploaded, on any of them.  */
  unsigned up_sum;
  int late_eof;			/* Set on each server it makes.  */
  uint32_t max_read;		/* The most a read asked for, on any.  */
  char urlhost[128];		/* The host as a URL writes it.  */
  char khost[128];		/* As known_hosts names it.  */
};

static void
ts_close (struct ts_conn *c)
{
  if (c->fd < 0)
    return;
  close (c->fd);
  c->fd = -1;
  server_free (c->sv);
  free (c->sv);
  c->sv = NULL;
}

static void
ts_flush (struct ts_conn *c)
{
  struct pipe *out = &c->sv->out;
  size_t off = 0;

  while (off < out->len)
    {
      ssize_t n = send (c->fd, out->data + off, out->len - off, MSG_NOSIGNAL);

      if (n <= 0)
        {
          if (n < 0 && errno == EINTR)
            continue;
          break;
        }
      off += (size_t) n;
    }
  out->len = 0;
}

static unsigned
sum_of (const uint8_t *p, size_t n)
{
  unsigned sum = 0;
  size_t i;

  for (i = 0; i < n; i++)
    sum = sum * 31 + p[i];
  return sum;
}

static void
ts_note_upload (struct tcp_server *ts, const struct server *sv)
{
  pthread_mutex_lock (&ts->mu);
  if (sv->max_read_len > ts->max_read)
    ts->max_read = sv->max_read_len;
  if (sv->up_len != 0)
    {
      ts->up_len = sv->up_len;
      ts->up_sum = sum_of (sv->up, sv->up_len);
    }
  pthread_mutex_unlock (&ts->mu);
}

static void *
ts_serve (void *arg)
{
  struct tcp_server *ts = arg;
  static uint8_t buf[65536];

  while (!ts->stop)
    {
      struct pollfd fds[TS_CONNS + 1];
      int which[TS_CONNS + 1];
      int n = 0, i, hang;

      fds[n].fd = ts->lfd;
      fds[n].events = POLLIN;
      which[n++] = -1;
      for (i = 0; i < TS_CONNS; i++)
        if (ts->conns[i].fd >= 0)
          {
            fds[n].fd = ts->conns[i].fd;
            fds[n].events = POLLIN;
            which[n++] = i;
          }
      poll (fds, (nfds_t) n, 10);
      pthread_mutex_lock (&ts->mu);
      hang = ts->hang_up;
      pthread_mutex_unlock (&ts->mu);
      if (hang)
        {
          for (i = 0; i < TS_CONNS; i++)
            ts_close (&ts->conns[i]);
          pthread_mutex_lock (&ts->mu);
          ts->hang_up = 0;
          pthread_mutex_unlock (&ts->mu);
          continue;
        }
      for (i = 0; i < n; i++)
        {
          struct ts_conn *c;
          ssize_t nread;

          if (!(fds[i].revents & (POLLIN | POLLHUP | POLLERR)))
            continue;
          if (which[i] < 0)
            {
              int fd = accept (ts->lfd, NULL, NULL), k;

              if (fd < 0)
                continue;
              for (k = 0; k < TS_CONNS && ts->conns[k].fd >= 0; k++)
                ;
              if (k == TS_CONNS)
                {
                  close (fd);
                  continue;
                }
              c = &ts->conns[k];
              c->sv = calloc (1, sizeof *c->sv);
              if (c->sv == NULL || server_new (c->sv) != 0)
                {
                  free (c->sv);
                  c->sv = NULL;
                  close (fd);
                  continue;
                }
              c->fd = fd;
              c->sv->late_eof = ts->late_eof;
              pthread_mutex_lock (&ts->mu);
              ts->accepted++;
              pthread_mutex_unlock (&ts->mu);
              ts_flush (c);
              continue;
            }
          c = &ts->conns[which[i]];
          nread = read (c->fd, buf, sizeof buf);
          if (nread <= 0)
            {
              ts_close (c);
              continue;
            }
          gf_session_receive (c->sv->s, now_us, buf, (size_t) nread);
          ts_flush (c);
          if (c->sv->release_held)
            {
              /* Later, and in a segment of their own.  */
              struct timespec late = { 0, 150000000 };

              nanosleep (&late, NULL);
              sv_release_held (c->sv);
              ts_flush (c);
            }
          ts_note_upload (ts, c->sv);
          if (c->sv->closed)
            ts_close (c);
        }
    }
  return NULL;
}

/* Where a test server listens.  */
enum
{
  TS_V4 = 0,			/* 127.0.0.1 */
  TS_V6,			/* ::1 */
  TS_ZONE			/* A link-local address, reached by its zone.  */
};

/* The first link-local IPv6 address of an interface that is up: the address
   and the interface's name.  0 if the machine has none.  */
static int
link_local (struct in6_addr *addr, unsigned *scope, char *name)
{
  struct ifaddrs *list, *a;
  int found = 0;

  if (getifaddrs (&list) != 0)
    return 0;
  for (a = list; a != NULL && !found; a = a->ifa_next)
    {
      const struct sockaddr_in6 *s6 = (const struct sockaddr_in6 *) a->ifa_addr;

      if (a->ifa_addr == NULL || a->ifa_addr->sa_family != AF_INET6
          || !(a->ifa_flags & IFF_UP) || (a->ifa_flags & IFF_LOOPBACK)
          /* A tunnel (utun, a VPN) takes what is sent to its own address out
             to the other end and not back, and the connection hangs.  */
          || (a->ifa_flags & IFF_POINTOPOINT)
          || !IN6_IS_ADDR_LINKLOCAL (&s6->sin6_addr))
        continue;
      *addr = s6->sin6_addr;
      /* The BSDs and Mac OS put the interface's index in the address, in the
         bytes that are zero in a link-local one; it is the zone, which is
         named separately, and is not part of the address.  */
      addr->s6_addr[2] = addr->s6_addr[3] = 0;
      *scope = if_nametoindex (a->ifa_name);
      snprintf (name, IF_NAMESIZE, "%s", a->ifa_name);
      found = *scope != 0;
    }
  freeifaddrs (list);
  return found;
}

/* 0: listening.  -1: failed.  1: this machine cannot do it (no IPv6, no
   link-local address); the test is skipped.  */
static int
ts_start_on (struct tcp_server *ts, int where)
{
  struct sockaddr_in sin;
  struct sockaddr_in6 sin6;
  struct sockaddr *sa = (struct sockaddr *) &sin;
  socklen_t len = sizeof sin, salen = sizeof sin;
  int i, one = 1;

  memset (ts, 0, sizeof *ts);
  for (i = 0; i < TS_CONNS; i++)
    ts->conns[i].fd = -1;
  pthread_mutex_init (&ts->mu, NULL);
  snprintf (ts->urlhost, sizeof ts->urlhost, "127.0.0.1");
  snprintf (ts->khost, sizeof ts->khost, "127.0.0.1");
  memset (&sin, 0, sizeof sin);
  sin.sin_family = AF_INET;
  sin.sin_addr.s_addr = htonl (INADDR_LOOPBACK);
  if (where != TS_V4)
    {
      char text[INET6_ADDRSTRLEN], name[IF_NAMESIZE] = "";

      memset (&sin6, 0, sizeof sin6);
      sin6.sin6_family = AF_INET6;
      if (where == TS_V6)
        sin6.sin6_addr = in6addr_loopback;
      else if (!link_local (&sin6.sin6_addr, &sin6.sin6_scope_id, name))
        return 1;
      inet_ntop (AF_INET6, &sin6.sin6_addr, text, sizeof text);
      if (where == TS_V6)
        {
          snprintf (ts->urlhost, sizeof ts->urlhost, "[%s]", text);
          snprintf (ts->khost, sizeof ts->khost, "%s", text);
        }
      else
        {
          snprintf (ts->urlhost, sizeof ts->urlhost, "[%s%%25%s]", text, name);
          snprintf (ts->khost, sizeof ts->khost, "%s%%%s", text, name);
        }
      sa = (struct sockaddr *) &sin6;
      salen = len = sizeof sin6;
    }
  if (gf_key_generate (&ts->host, GF_KEY_ED25519, 0) != GF_OK)
    return -1;
  ts->lfd = socket (sa->sa_family, SOCK_STREAM, 0);
  if (ts->lfd < 0)
    return where == TS_V4 ? -1 : 1;
  setsockopt (ts->lfd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
  if (bind (ts->lfd, sa, salen) != 0)
    {
      close (ts->lfd);
      gf_key_free (ts->host);
      return where == TS_V4 ? -1 : 1;
    }
  if (listen (ts->lfd, 8) != 0 || getsockname (ts->lfd, sa, &len) != 0)
    return -1;
  ts->port = ntohs (where == TS_V4 ? sin.sin_port : sin6.sin6_port);
  shared_host = ts->host;
  return pthread_create (&ts->thread, NULL, ts_serve, ts) == 0 ? 0 : -1;
}

static int
ts_start (struct tcp_server *ts)
{
  return ts_start_on (ts, TS_V4);
}

static void
ts_stop (struct tcp_server *ts)
{
  int i;

  ts->stop = 1;
  pthread_join (ts->thread, NULL);
  for (i = 0; i < TS_CONNS; i++)
    ts_close (&ts->conns[i]);
  close (ts->lfd);
  shared_host = NULL;
  gf_key_free (ts->host);
  pthread_mutex_destroy (&ts->mu);
}

static unsigned
ts_accepted (struct tcp_server *ts)
{
  unsigned n;

  pthread_mutex_lock (&ts->mu);
  n = ts->accepted;
  pthread_mutex_unlock (&ts->mu);
  return n;
}

/* The server closes everything it holds, and the call returns when it has.  */
static void
ts_hang_up (struct tcp_server *ts)
{
  struct timespec nap = { 0, 2000000 };
  int i, again = 1;

  pthread_mutex_lock (&ts->mu);
  ts->hang_up = 1;
  pthread_mutex_unlock (&ts->mu);
  for (i = 0; i < 2000 && again; i++)
    {
      pthread_mutex_lock (&ts->mu);
      again = ts->hang_up;
      pthread_mutex_unlock (&ts->mu);
      if (again)
        nanosleep (&nap, NULL);
    }
}

static void
ts_uploaded (struct tcp_server *ts, size_t *len, unsigned *sum)
{
  pthread_mutex_lock (&ts->mu);
  *len = ts->up_len;
  *sum = ts->up_sum;
  pthread_mutex_unlock (&ts->mu);
}

/* A handle that logs in as alice with PASSWORD, with the host key checked
   against KNOWN_HOSTS (VERIFY) or not.  */
static struct twist_transfer *
tcp_transfer (int verify, const char *password, const char *known_hosts)
{
  struct twist_transfer *transfer = twist_transfer_new ();

  check (transfer != NULL, "transfer");
  twist_transfer_setopt (transfer, TWISTOPT_SSL_VERIFYPEER, verify ? 1L : 0L);
  twist_transfer_setopt (transfer, TWISTOPT_PASSWORD, password);
  if (known_hosts != NULL)
    twist_transfer_setopt (transfer, TWISTOPT_SSH_KNOWNHOSTS, known_hosts);
  twist_transfer_setopt (transfer, TWISTOPT_SSH_AGENT_SOCKET, "");
  twist_transfer_setopt (transfer, TWISTOPT_WRITEFUNCTION, collect);
  return transfer;
}

/* Fetch a URL on the server with TRANSFER, in RUNTIME, as a command line with
   two URLs would: the same handle and the same loop each time.  */
static int
tcp_get (struct twist_runtime *runtime, struct twist_transfer *transfer,
         const struct tcp_server *ts, const char *scheme, const char *path)
{
  char url[200];

  snprintf (url, sizeof url, "%s://alice@%s:%d%s", scheme, ts->urlhost,
            ts->port, path);
  twist_transfer_setopt (transfer, TWISTOPT_URL, url);
  got_len = 0;
  return check_perform_in (runtime, transfer);
}

static int
got_data (void)
{
  return got_len == sizeof content && memcmp (got, content, got_len) == 0;
}

/* The second URL on a host is fetched on the connection the first made: the
   key exchange, the login and the SFTP channel happen once.  */
static void
test_reuse_basic (void)
{
  struct tcp_server ts;
  struct twist_runtime *runtime;
  struct twist_transfer *transfer;
  char kh[300], line[300];
  size_t n = 0;

  check (ts_start (&ts) == 0, "server");
  snprintf (kh, sizeof kh, "%s/known_hosts", home);
  check (gf_knownhosts_format (line, sizeof line, &n, ts.khost,
                               (unsigned) ts.port, ts.host, 0) == GF_OK,
         "known_hosts line");
  write_file (kh, line, n, 0600);
  runtime = twist_runtime_new ();
  transfer = tcp_transfer (1, "secret", kh);
  check (tcp_get (runtime, transfer, &ts, "sftp", "/data.bin") == TWIST_OK
         && got_data (), "the first file");
  check (ts_accepted (&ts) == 1, "one connection");
  check (twist_pool_count (runtime->pool) == 1, "the session is kept");
  check (tcp_get (runtime, transfer, &ts, "sftp", "/data.bin") == TWIST_OK
         && got_data (), "the second file");
  check (ts_accepted (&ts) == 1, "the second file used the same connection");
  check (twist_pool_count (runtime->pool) == 1, "and it is kept again");
  /* scp:// and sftp:// are the same transfer, so the same session.  */
  check (tcp_get (runtime, transfer, &ts, "scp", "/data.bin") == TWIST_OK
         && got_data (), "scp after sftp");
  check (ts_accepted (&ts) == 1, "scp used it too");
  twist_transfer_free (transfer);
  twist_runtime_free (runtime);
  ts_stop (&ts);
  unlink (kh);
}

/* An upload and a download on one session, and a listing.  */
static void
test_reuse_mixed (void)
{
  struct tcp_server ts;
  struct twist_runtime *runtime;
  struct twist_transfer *down, *up;
  static uint8_t body[30000];
  size_t i, len;
  unsigned sum;

  check (ts_start (&ts) == 0, "server");
  for (i = 0; i < sizeof body; i++)
    body[i] = (uint8_t) (i * 3 + 1);
  runtime = twist_runtime_new ();
  down = tcp_transfer (0, "secret", NULL);
  up = tcp_transfer (0, "secret", NULL);
  twist_transfer_setopt (up, TWISTOPT_POSTFIELDS, (char *) body);
  twist_transfer_setopt (up, TWISTOPT_POSTFIELDSIZE, (long) sizeof body);
  check (tcp_get (runtime, down, &ts, "sftp", "/data.bin") == TWIST_OK
         && got_data (), "download");
  check (tcp_get (runtime, up, &ts, "sftp", "/up.bin") == TWIST_OK, "upload");
  ts_uploaded (&ts, &len, &sum);
  check (len == sizeof body && sum == sum_of (body, sizeof body),
         "the upload arrived whole");
  check (tcp_get (runtime, down, &ts, "sftp", "/dir/") == TWIST_OK
         && got_len > 0, "a listing");
  check (tcp_get (runtime, down, &ts, "sftp", "/data.bin") == TWIST_OK
         && got_data (), "a download after all that");
  check (ts_accepted (&ts) == 1, "all of it on one connection");
  twist_transfer_free (down);
  twist_transfer_free (up);
  twist_runtime_free (runtime);
  ts_stop (&ts);
}

/* What a session was logged in with is part of what it is.  A handle with
   another password, or one that checks the host key where the last did
   not, gets a connection of its own and is held to its own terms.  */
static void
test_reuse_terms (void)
{
  struct tcp_server ts;
  struct twist_runtime *runtime;
  struct twist_transfer *lax, *wrong, *strict, *pinned;
  char kh[300], fp[64];
  unsigned before;

  check (ts_start (&ts) == 0, "server");
  snprintf (kh, sizeof kh, "%s/known_hosts", home);
  write_file (kh, "", 0, 0600);
  runtime = twist_runtime_new ();
  /* The same file as the strict handle names below, so that whether the
     host key is checked is all that tells them apart.  */
  lax = tcp_transfer (0, "secret", kh);
  check (tcp_get (runtime, lax, &ts, "sftp", "/data.bin") == TWIST_OK
         && got_data (), "logged in without checking the host key");
  check (twist_pool_count (runtime->pool) == 1, "kept");

  /* A password that is wrong must be tried, not borrowed from the session.  */
  wrong = tcp_transfer (0, "not-the-password", NULL);
  check (tcp_get (runtime, wrong, &ts, "sftp", "/data.bin") == TWIST_ERR_AUTH
         && got_len == 0, "another password is not let in by the first");
  check (ts_accepted (&ts) == 2, "it made its own connection");

  /* The host is not in known_hosts: the earlier session must not stand in
     for the check.  */
  strict = tcp_transfer (1, "secret", kh);
  check (tcp_get (runtime, strict, &ts, "sftp",
                  "/data.bin") == TWIST_ERR_HOSTKEY
         && got_len == 0, "checking the host key is not skipped");
  check (ts_accepted (&ts) == 3, "and it made its own connection");

  /* A pin that is not the server's, with the check off, still fails.  */
  pinned = tcp_transfer (0, "secret", NULL);
  twist_transfer_setopt (pinned, TWISTOPT_SSH_HOST_PUBLIC_KEY_SHA256,
                         "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
  check (tcp_get (runtime, pinned, &ts, "sftp",
                  "/data.bin") == TWIST_ERR_HOSTKEY
         && got_len == 0, "a wrong pin is not skipped");
  /* The right one is accepted, on a connection of its own.  */
  gf_key_fingerprint (ts.host, fp, sizeof fp);
  twist_transfer_setopt (pinned, TWISTOPT_SSH_HOST_PUBLIC_KEY_SHA256, fp + 7);
  check (tcp_get (runtime, pinned, &ts, "sftp", "/data.bin") == TWIST_OK
         && got_data (), "the right pin");
  /* The first handle still has its session.  */
  before = ts_accepted (&ts);
  check (tcp_get (runtime, lax, &ts, "sftp", "/data.bin") == TWIST_OK
         && got_data (), "the first handle again");
  check (ts_accepted (&ts) == before, "on the connection it had");
  twist_transfer_free (lax);
  twist_transfer_free (wrong);
  twist_transfer_free (strict);
  twist_transfer_free (pinned);
  twist_runtime_free (runtime);
  ts_stop (&ts);
  unlink (kh);
}

/* A server that hangs up on an idle connection: the next URL gets a new one
   and succeeds.  */
static void
test_reuse_hung_up (void)
{
  struct tcp_server ts;
  struct twist_runtime *runtime;
  struct twist_transfer *transfer;
  struct timespec nap = { 0, 50000000 };

  check (ts_start (&ts) == 0, "server");
  runtime = twist_runtime_new ();
  transfer = tcp_transfer (0, "secret", NULL);
  check (tcp_get (runtime, transfer, &ts, "sftp", "/data.bin") == TWIST_OK
         && got_data (), "first");
  ts_hang_up (&ts);
  /* Give the close time to reach us.  */
  nanosleep (&nap, NULL);
  check (tcp_get (runtime, transfer, &ts, "sftp", "/data.bin") == TWIST_OK
         && got_data (), "after the server hung up");
  check (ts_accepted (&ts) == 2, "on a new connection");
  twist_transfer_free (transfer);
  twist_runtime_free (runtime);
  ts_stop (&ts);
}

/* A server that answers the close before it has answered every read: the
   answers still to come would reach whoever has the connection next, so the
   session is not kept, and the next URL gets one that is clean.  */
static void
test_reuse_unanswered (void)
{
  struct tcp_server ts;
  struct twist_runtime *runtime;
  struct twist_transfer *transfer;

  check (ts_start (&ts) == 0, "server");
  ts.late_eof = 1;
  runtime = twist_runtime_new ();
  transfer = tcp_transfer (0, "secret", NULL);
  check (tcp_get (runtime, transfer, &ts, "sftp", "/data.bin") == TWIST_OK
         && got_data (), "the first");
  check (twist_pool_count (runtime->pool) == 0,
         "a session with requests unanswered is not kept");
  check (tcp_get (runtime, transfer, &ts, "sftp", "/data.bin") == TWIST_OK
         && got_data (), "the second");
  check (ts_accepted (&ts) == 2, "on a connection of its own");
  twist_transfer_free (transfer);
  twist_runtime_free (runtime);
  ts_stop (&ts);
}

/* After a transfer that failed, the next one works.  */
static void
test_reuse_after_error (void)
{
  struct tcp_server ts;
  struct twist_runtime *runtime;
  struct twist_transfer *transfer;

  check (ts_start (&ts) == 0, "server");
  runtime = twist_runtime_new ();
  transfer = tcp_transfer (0, "secret", NULL);
  check (tcp_get (runtime, transfer, &ts, "sftp", "/data.bin") == TWIST_OK,
         "ok");
  check (tcp_get (runtime, transfer, &ts, "sftp", "/missing") != TWIST_OK,
         "a file that is not there");
  check (tcp_get (runtime, transfer, &ts, "sftp", "/data.bin") == TWIST_OK
         && got_data (), "and then one that is");
  twist_transfer_free (transfer);
  twist_runtime_free (runtime);
  ts_stop (&ts);
}

/* Two transfers at once cannot share a session; each makes one, and both
   are kept for later.  */
static void
test_reuse_concurrent (void)
{
  struct tcp_server ts;
  struct twist_runtime *runtime;
  struct twist_transfer *a, *b;
  char url[200];
  struct check_job ja = { 0, 0, 0 }, jb = { 0, 0, 0 };
  int i;

  check (ts_start (&ts) == 0, "server");
  runtime = twist_runtime_new ();
  a = tcp_transfer (0, "secret", NULL);
  b = tcp_transfer (0, "secret", NULL);
  snprintf (url, sizeof url, "sftp://alice@127.0.0.1:%d/data.bin", ts.port);
  twist_transfer_setopt (a, TWISTOPT_URL, url);
  twist_transfer_setopt (b, TWISTOPT_URL, url);
  got_len = 0;
  check (twist_runtime_start (runtime, a, check_job_done, &ja) == TWIST_OK
         && twist_runtime_start (runtime, b, check_job_done, &jb) == TWIST_OK,
         "both started");
  /* Bound it by time.  */
  for (i = 0; i < 10000 && !(ja.done && jb.done); i++)
    twist_runtime_run_once (runtime, 5);
  check (ja.done && jb.done && ja.result == TWIST_OK && jb.result == TWIST_OK,
         "both finished");
  check (ts_accepted (&ts) == 2, "two connections");
  check (twist_pool_count (runtime->pool) == 2, "both kept");
  check (tcp_get (runtime, a, &ts, "sftp", "/data.bin") == TWIST_OK
         && got_data (), "a third");
  check (ts_accepted (&ts) == 2, "used one of them");
  twist_transfer_free (a);
  twist_transfer_free (b);
  twist_runtime_free (runtime);
  ts_stop (&ts);
}

/* ---- rate limits ---- */

static double
seconds (void)
{
  struct timespec t;

  clock_gettime (CLOCK_MONOTONIC, &t);
  return (double) t.tv_sec + (double) t.tv_nsec / 1e9;
}

/* A limit is on the average over the transfer, so 100000 bytes at 100000 a
   second take about a second: the last chunk goes at 0.98 s.  No limit takes
   a few milliseconds on a loopback.  */
static void
test_limits (void)
{
  struct tcp_server ts;
  struct twist_runtime *runtime;
  struct twist_transfer *down, *up, *both;
  double t0, took;
  size_t len;
  unsigned sum;

  check (ts_start (&ts) == 0, "server");
  runtime = twist_runtime_new ();

  down = tcp_transfer (0, "secret", NULL);
  t0 = seconds ();
  check (tcp_get (runtime, down, &ts, "sftp", "/data.bin") == TWIST_OK
         && got_data (), "unlimited");
  took = seconds () - t0;
  check (took < 0.6, "an unlimited download is quick");

  twist_transfer_setopt (down, TWISTOPT_MAX_RECV_SPEED_LARGE,
                         (uint64_t) 100000);
  t0 = seconds ();
  check (tcp_get (runtime, down, &ts, "sftp", "/data.bin") == TWIST_OK
         && got_data (), "limited download");
  took = seconds () - t0;
  check (took >= 0.85 && took < 2.5, "a download keeps to the limit");
  if (took < 0.85 || took >= 2.5)
    fprintf (stderr, "  took %.2f s\n", took);

  /* A limit on sending does not slow a download.  */
  both = tcp_transfer (0, "secret", NULL);
  twist_transfer_setopt (both, TWISTOPT_MAX_SEND_SPEED_LARGE, (uint64_t) 1000);
  t0 = seconds ();
  check (tcp_get (runtime, both, &ts, "sftp", "/data.bin") == TWIST_OK
         && got_data (), "a send limit and a download");
  check (seconds () - t0 < 0.6, "is not slowed by the send limit");

  up = tcp_transfer (0, "secret", NULL);
  twist_transfer_setopt (up, TWISTOPT_POSTFIELDS, (char *) content);
  twist_transfer_setopt (up, TWISTOPT_POSTFIELDSIZE, (long) sizeof content);
  twist_transfer_setopt (up, TWISTOPT_MAX_SEND_SPEED_LARGE, (uint64_t) 100000);
  t0 = seconds ();
  check (tcp_get (runtime, up, &ts, "sftp", "/up.bin") == TWIST_OK,
         "limited upload");
  took = seconds () - t0;
  ts_uploaded (&ts, &len, &sum);
  check (len == sizeof content && sum == sum_of (content, sizeof content),
         "the upload arrived whole");
  check (took >= 0.85 && took < 2.5, "an upload keeps to the limit");
  if (took < 0.85 || took >= 2.5)
    fprintf (stderr, "  took %.2f s\n", took);

  twist_transfer_free (down);
  twist_transfer_free (both);
  twist_transfer_free (up);
  twist_runtime_free (runtime);
  ts_stop (&ts);
}

/* A slow limit means small requests, so that a transfer does not go in
   lumps: at 2000 a second the reads are of 1000.  */
static void
test_limit_chunks (void)
{
  struct tcp_server ts;
  struct twist_runtime *runtime;
  struct twist_transfer *transfer;
  double t0, took;

  check (ts_start (&ts) == 0, "server");
  runtime = twist_runtime_new ();
  transfer = tcp_transfer (0, "secret", NULL);
  twist_transfer_setopt (transfer, TWISTOPT_RANGE, "0-3999");
  twist_transfer_setopt (transfer, TWISTOPT_MAX_RECV_SPEED_LARGE,
                         (uint64_t) 2000);
  t0 = seconds ();
  check (tcp_get (runtime, transfer, &ts, "sftp", "/data.bin") == TWIST_OK
         && got_len == 4000 && memcmp (got, content, 4000) == 0,
         "four thousand bytes at two thousand a second");
  took = seconds () - t0;
  check (took >= 1.3 && took < 3.5, "take about two seconds");
  if (took < 1.3 || took >= 3.5)
    fprintf (stderr, "  took %.2f s\n", took);
  pthread_mutex_lock (&ts.mu);
  check (ts.max_read > 0 && ts.max_read <= 1000, "in requests of 1000");
  pthread_mutex_unlock (&ts.mu);
  twist_transfer_free (transfer);
  twist_runtime_free (runtime);
  ts_stop (&ts);
}

/* ---- IPv6 ---- */

/* A server on ::1: the host is in brackets in the URL and known_hosts names
   it as [::1]:PORT.  The session is kept for the next URL as for any host.  */
static void
test_ipv6_literal (void)
{
  struct tcp_server ts;
  struct twist_runtime *runtime;
  struct twist_transfer *transfer;
  char kh[300], line[300];
  size_t n = 0;
  int up = ts_start_on (&ts, TS_V6);

  if (up != 0)
    {
      fputs ("test-ssh: no IPv6 loopback; skipping the IPv6 tests\n", stderr);
      return;
    }
  snprintf (kh, sizeof kh, "%s/known_hosts", home);
  check (gf_knownhosts_format (line, sizeof line, &n, ts.khost,
                               (unsigned) ts.port, ts.host, 0) == GF_OK
         && strncmp (line, "[::1]:", 6) == 0, "known_hosts names [::1]:port");
  write_file (kh, line, n, 0600);
  runtime = twist_runtime_new ();
  transfer = tcp_transfer (1, "secret", kh);
  check (tcp_get (runtime, transfer, &ts, "sftp", "/data.bin") == TWIST_OK
         && got_data (), "a download from [::1] with the host key checked");
  check (tcp_get (runtime, transfer, &ts, "sftp", "/data.bin") == TWIST_OK
         && got_data () && ts_accepted (&ts) == 1, "and the next URL reuses it");
  {
    char *eff = NULL;

    twist_transfer_getinfo (transfer, TWISTINFO_EFFECTIVE_URL, &eff);
    check (eff != NULL && strstr (eff, "//[::1]:") != NULL,
           "the effective URL keeps the brackets");
  }

  /* With nothing in known_hosts the address is refused.  A new runtime:
     the connection already made was trusted when it was made, and a kept one
     is not checked again.  */
  write_file (kh, "", 0, 0600);
  twist_transfer_free (transfer);
  twist_runtime_free (runtime);
  runtime = twist_runtime_new ();
  transfer = tcp_transfer (1, "secret", kh);
  check (tcp_get (runtime, transfer, &ts, "sftp",
                  "/data.bin") == TWIST_ERR_HOSTKEY
         && got_len == 0, "an address that is not in known_hosts");
  twist_transfer_free (transfer);
  twist_runtime_free (runtime);
  ts_stop (&ts);
  unlink (kh);
}

/* A link-local address is reached by an interface; the URL names it, and the
   connection goes only where that says.  */
static void
test_ipv6_zone (void)
{
  struct tcp_server ts;
  struct twist_runtime *runtime;
  struct twist_transfer *transfer;
  char kh[300], line[400];
  size_t n = 0;
  int up = ts_start_on (&ts, TS_ZONE);

  if (up != 0)
    {
      fputs ("test-ssh: no link-local IPv6 address; skipping the zone test\n",
             stderr);
      return;
    }
  snprintf (kh, sizeof kh, "%s/known_hosts", home);
  check (gf_knownhosts_format (line, sizeof line, &n, ts.khost,
                               (unsigned) ts.port, ts.host, 0) == GF_OK,
         "known_hosts line for a zone");
  write_file (kh, line, n, 0600);
  runtime = twist_runtime_new ();
  transfer = tcp_transfer (1, "secret", kh);
  check (tcp_get (runtime, transfer, &ts, "sftp", "/data.bin") == TWIST_OK
         && got_data (), "a download from a link-local address by its zone");
  twist_transfer_free (transfer);
  twist_runtime_free (runtime);
  ts_stop (&ts);
  unlink (kh);
}

/* The default port: known_hosts has the address bare, as ssh writes it, and a
   port that is not the default in brackets.  */
static void
test_ipv6_known_hosts (void)
{
  struct server sv;
  struct world w;
  struct twist_transfer *transfer;
  struct setup su = SETUP ("sftp://alice@[::1]/data.bin", 1, "secret");
  char kh[300], line[400];
  size_t n = 0;

  snprintf (kh, sizeof kh, "%s/known_hosts", home);
  su.known_hosts = kh;

  check (server_new (&sv) == 0, "server");
  check (gf_knownhosts_format (line, sizeof line, &n, "::1", 22, sv.host, 0)
         == GF_OK && strncmp (line, "::1 ", 4) == 0,
         "the default port is written without brackets");
  write_file (kh, line, n, 0600);
  transfer = run (&w, &sv, &su);
  check (transfer->done && transfer->result == TWIST_OK,
         "found on the default port");
  twist_transfer_free (transfer);
  server_free (&sv);

  check (server_new (&sv) == 0, "server 2");
  check (gf_knownhosts_format (line, sizeof line, &n, "2001:db8::1", 22,
                               sv.host, 0) == GF_OK, "other line");
  write_file (kh, line, n, 0600);
  transfer = run (&w, &sv, &su);
  check (transfer->done && transfer->result == TWIST_ERR_HOSTKEY
         && detail_has (transfer, "::1"), "another address is not this one");
  twist_transfer_free (transfer);
  server_free (&sv);

  /* A port that is not the default: [addr]:port.  */
  su.url = "sftp://alice@[::1]:2222/data.bin";
  check (server_new (&sv) == 0, "server 3");
  check (gf_knownhosts_format (line, sizeof line, &n, "::1", 2222, sv.host, 0)
         == GF_OK && strncmp (line, "[::1]:2222 ", 11) == 0, "bracketed");
  write_file (kh, line, n, 0600);
  transfer = run (&w, &sv, &su);
  check (transfer->done && transfer->result == TWIST_OK,
         "found on another port");
  twist_transfer_free (transfer);
  server_free (&sv);

  /* A zone is part of the name, as ssh keeps it.  */
  su.url = "sftp://alice@[fe80::1%25eth0]/data.bin";
  check (server_new (&sv) == 0, "server 4");
  check (gf_knownhosts_format (line, sizeof line, &n, "fe80::1%eth0", 22,
                               sv.host, 0) == GF_OK, "zone line");
  write_file (kh, line, n, 0600);
  transfer = run (&w, &sv, &su);
  check (transfer->done && transfer->result == TWIST_OK,
         "a zone in known_hosts");
  twist_transfer_free (transfer);
  server_free (&sv);
  unlink (kh);
}


/* ---- proxies ---- */

/* An HTTP CONNECT or a SOCKS5 proxy on the loopback, in front of whatever the
   transfer asks for.  It records what it was asked, and can be told to refuse,
   to want credentials, to send a long reply, or to send the server's first
   bytes in the same write as its own reply.  */

enum
{
  PX_HTTP_KIND = 0,
  PX_SOCKS_KIND
};

struct px
{
  int lfd, port, kind;
  pthread_t thread;
  volatile int stop;
  int coalesce;			/* The server's first bytes with the reply.  */
  int refuse_http;		/* Answer CONNECT with this status.  */
  int refuse_socks;		/* Answer the request with this code.  */
  int bigheader;		/* A reply of three thousand bytes of header.  */
  const char *user, *pass;	/* Wanted, or NULL.  */
  pthread_mutex_t mu;
  unsigned connects;		/* Tunnels opened.  */
  char target[320];		/* What the last was asked for.  */
  int atyp;			/* SOCKS: the address type.  */
  unsigned active;		/* Threads at work.  */
};

struct px_conn
{
  struct px *px;
  int fd;
};

static int
px_read_exact (int fd, uint8_t *buf, size_t n)
{
  size_t have = 0;

  while (have < n)
    {
      ssize_t r = read (fd, buf + have, n - have);

      if (r <= 0)
        return -1;
      have += (size_t) r;
    }
  return 0;
}

static int
px_upstream (const char *host, const char *port)
{
  struct addrinfo hints, *res, *a;
  int fd = -1;

  memset (&hints, 0, sizeof hints);
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = AI_NUMERICHOST | AI_NUMERICSERV;
  if (getaddrinfo (host, port, &hints, &res) != 0)
    return -1;
  for (a = res; a != NULL && fd < 0; a = a->ai_next)
    {
      int s = socket (a->ai_family, a->ai_socktype, a->ai_protocol);

      if (s >= 0 && connect (s, a->ai_addr, a->ai_addrlen) == 0)
        fd = s;
      else if (s >= 0)
        close (s);
    }
  freeaddrinfo (res);
  return fd;
}

/* Copy both ways until one end closes or the proxy is stopped.  */
static void
px_relay (struct px *px, int a, int b)
{
  uint8_t buf[16384];

  while (!px->stop)
    {
      struct pollfd f[2] = { { a, POLLIN, 0 }, { b, POLLIN, 0 } };
      int i;

      if (poll (f, 2, 100) <= 0)
        continue;
      for (i = 0; i < 2; i++)
        if (f[i].revents & (POLLIN | POLLHUP | POLLERR))
          {
            ssize_t r = read (f[i].fd, buf, sizeof buf);

            if (r <= 0)
              return;
            if (send (i == 0 ? b : a, buf, (size_t) r, MSG_NOSIGNAL) < 0)
              return;
          }
    }
}

/* The server's first bytes, if it sends any soon, to go with the reply.  */
static size_t
px_first_bytes (int up, uint8_t *buf, size_t cap)
{
  struct pollfd f = { up, POLLIN, 0 };

  if (poll (&f, 1, 1000) > 0)
    {
      ssize_t r = read (up, buf, cap);

      if (r > 0)
        return (size_t) r;
    }
  return 0;
}

static void
px_note (struct px *px, const char *target, int atyp)
{
  pthread_mutex_lock (&px->mu);
  snprintf (px->target, sizeof px->target, "%s", target);
  px->atyp = atyp;
  pthread_mutex_unlock (&px->mu);
}

static void
px_http (struct px *px, int fd)
{
  char req[8192];
  size_t n = 0;
  char host[256], port[16], line[200];
  char *sp, *colon;
  uint8_t first[4096];
  size_t nfirst = 0;
  int up;
  char reply[4096];
  size_t rl;

  while (n < sizeof req - 1)
    {
      ssize_t r = read (fd, req + n, 1);

      if (r <= 0)
        return;
      n += 1;
      if (n >= 4 && memcmp (req + n - 4, "\r\n\r\n", 4) == 0)
        break;
    }
  req[n] = 0;
  if (strncmp (req, "CONNECT ", 8) != 0)
    return;
  sp = strchr (req + 8, ' ');
  if (sp == NULL)
    return;
  snprintf (line, sizeof line, "%.*s", (int) (sp - req - 8), req + 8);
  px_note (px, line, 0);
  if (px->refuse_http != 0)
    {
      rl = (size_t) snprintf (reply, sizeof reply, "HTTP/1.1 %d No\r\n"
                              "Content-Length: 0\r\n\r\n", px->refuse_http);
      send (fd, reply, rl, MSG_NOSIGNAL);
      return;
    }
  if (px->user != NULL)
    {
      char cred[200], want[300];
      const char *h = strstr (req, "\r\nProxy-Authorization: Basic ");
      static const char b64[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
      size_t i, o = 0, cl;

      snprintf (cred, sizeof cred, "%s:%s", px->user, px->pass);
      cl = strlen (cred);
      for (i = 0; i < cl; i += 3)
        {
          uint32_t v = (uint32_t) (uint8_t) cred[i] << 16;

          if (i + 1 < cl)
            v |= (uint32_t) (uint8_t) cred[i + 1] << 8;
          if (i + 2 < cl)
            v |= (uint8_t) cred[i + 2];
          want[o++] = b64[(v >> 18) & 63];
          want[o++] = b64[(v >> 12) & 63];
          want[o++] = i + 1 < cl ? b64[(v >> 6) & 63] : '=';
          want[o++] = i + 2 < cl ? b64[v & 63] : '=';
        }
      want[o] = 0;
      if (h == NULL || strncmp (h + 29, want, o) != 0 || h[29 + o] != '\r')
        {
          static const char no[] = "HTTP/1.1 407 Proxy Authentication "
            "Required\r\nProxy-Authenticate: Basic realm=\"x\"\r\n"
            "Content-Length: 0\r\n\r\n";

          send (fd, no, sizeof no - 1, MSG_NOSIGNAL);
          return;
        }
    }
  colon = strrchr (line, ':');
  if (colon == NULL)
    return;
  snprintf (port, sizeof port, "%s", colon + 1);
  *colon = 0;
  snprintf (host, sizeof host, "%s", line[0] == '[' ? line + 1 : line);
  if (host[0] != 0 && host[strlen (host) - 1] == ']')
    host[strlen (host) - 1] = 0;
  up = px_upstream (host, port);
  if (up < 0)
    {
      static const char bad[] = "HTTP/1.1 502 Bad Gateway\r\n"
        "Content-Length: 0\r\n\r\n";

      send (fd, bad, sizeof bad - 1, MSG_NOSIGNAL);
      return;
    }
  rl = (size_t) snprintf (reply, sizeof reply,
                          "HTTP/1.1 200 Connection established\r\n");
  if (px->bigheader)
    {
      memcpy (reply + rl, "X-Pad: ", 7);
      rl += 7;
      memset (reply + rl, 'a', 3000);
      rl += 3000;
      memcpy (reply + rl, "\r\n", 2);
      rl += 2;
    }
  memcpy (reply + rl, "\r\n", 2);
  rl += 2;
  if (px->coalesce)
    nfirst = px_first_bytes (up, first, sizeof first);
  pthread_mutex_lock (&px->mu);
  px->connects++;
  pthread_mutex_unlock (&px->mu);
  /* One write: the reply and the server's banner together.  */
  memcpy (reply + rl, first, nfirst);
  send (fd, reply, rl + nfirst, MSG_NOSIGNAL);
  px_relay (px, fd, up);
  close (up);
}

static void
px_socks (struct px *px, int fd)
{
  uint8_t g[2], methods[256], req[300], reply[10 + 4096];
  char host[260], port[16], target[300];
  int atyp, up, have_pw = 0;
  size_t i, nfirst = 0, alen;
  uint8_t first[4096];

  if (px_read_exact (fd, g, 2) != 0 || g[0] != 5
      || px_read_exact (fd, methods, g[1]) != 0)
    return;
  for (i = 0; i < g[1]; i++)
    if (methods[i] == 2)
      have_pw = 1;
  if (px->user != NULL)
    {
      uint8_t a[2], u[256], pl, p[256];

      if (!have_pw)
        {
          send (fd, "\x05\xff", 2, MSG_NOSIGNAL);
          return;
        }
      send (fd, "\x05\x02", 2, MSG_NOSIGNAL);
      if (px_read_exact (fd, a, 2) != 0 || px_read_exact (fd, u, a[1]) != 0
          || px_read_exact (fd, &pl, 1) != 0 || px_read_exact (fd, p, pl) != 0)
        return;
      if (a[1] != strlen (px->user) || memcmp (u, px->user, a[1]) != 0
          || pl != strlen (px->pass) || memcmp (p, px->pass, pl) != 0)
        {
          send (fd, "\x01\x01", 2, MSG_NOSIGNAL);
          return;
        }
      send (fd, "\x01\x00", 2, MSG_NOSIGNAL);
    }
  else
    send (fd, "\x05\x00", 2, MSG_NOSIGNAL);
  if (px_read_exact (fd, req, 4) != 0)
    return;
  atyp = req[3];
  if (atyp == 1)
    {
      if (px_read_exact (fd, req + 4, 6) != 0)
        return;
      inet_ntop (AF_INET, req + 4, host, sizeof host);
      snprintf (port, sizeof port, "%u", (req[8] << 8) | req[9]);
    }
  else if (atyp == 4)
    {
      if (px_read_exact (fd, req + 4, 18) != 0)
        return;
      inet_ntop (AF_INET6, req + 4, host, sizeof host);
      snprintf (port, sizeof port, "%u", (req[20] << 8) | req[21]);
    }
  else if (atyp == 3)
    {
      if (px_read_exact (fd, req + 4, 1) != 0)
        return;
      alen = req[4];
      if (px_read_exact (fd, req + 5, alen + 2) != 0)
        return;
      snprintf (host, sizeof host, "%.*s", (int) alen, (char *) req + 5);
      snprintf (port, sizeof port, "%u", (req[5 + alen] << 8) | req[6 + alen]);
    }
  else
    return;
  snprintf (target, sizeof target, "%s:%s", host, port);
  px_note (px, target, atyp);
  memset (reply, 0, 10);
  reply[0] = 5;
  reply[3] = 1;
  if (px->refuse_socks != 0)
    {
      reply[1] = (uint8_t) px->refuse_socks;
      send (fd, reply, 10, MSG_NOSIGNAL);
      return;
    }
  up = px_upstream (host, port);
  if (up < 0)
    {
      reply[1] = 4;
      send (fd, reply, 10, MSG_NOSIGNAL);
      return;
    }
  if (px->coalesce)
    nfirst = px_first_bytes (up, first, sizeof first);
  pthread_mutex_lock (&px->mu);
  px->connects++;
  pthread_mutex_unlock (&px->mu);
  memcpy (reply + 10, first, nfirst);
  send (fd, reply, 10 + nfirst, MSG_NOSIGNAL);
  px_relay (px, fd, up);
  close (up);
}

static void *
px_serve_conn (void *arg)
{
  struct px_conn *c = arg;

  if (c->px->kind == PX_HTTP_KIND)
    px_http (c->px, c->fd);
  else
    px_socks (c->px, c->fd);
  close (c->fd);
  pthread_mutex_lock (&c->px->mu);
  c->px->active--;
  pthread_mutex_unlock (&c->px->mu);
  free (c);
  return NULL;
}

static void *
px_serve (void *arg)
{
  struct px *px = arg;

  while (!px->stop)
    {
      struct pollfd f = { px->lfd, POLLIN, 0 };
      struct px_conn *c;
      pthread_t t;
      int fd;

      if (poll (&f, 1, 50) <= 0)
        continue;
      fd = accept (px->lfd, NULL, NULL);
      if (fd < 0)
        continue;
      c = malloc (sizeof *c);
      if (c == NULL)
        {
          close (fd);
          continue;
        }
      c->px = px;
      c->fd = fd;
      pthread_mutex_lock (&px->mu);
      px->active++;
      pthread_mutex_unlock (&px->mu);
      if (pthread_create (&t, NULL, px_serve_conn, c) != 0)
        {
          pthread_mutex_lock (&px->mu);
          px->active--;
          pthread_mutex_unlock (&px->mu);
          close (fd);
          free (c);
        }
      else
        pthread_detach (t);
    }
  return NULL;
}

static int
px_start (struct px *px, int kind)
{
  struct sockaddr_in sin;
  socklen_t len = sizeof sin;
  int one = 1;

  memset (px, 0, sizeof *px);
  px->kind = kind;
  pthread_mutex_init (&px->mu, NULL);
  px->lfd = socket (AF_INET, SOCK_STREAM, 0);
  if (px->lfd < 0)
    return -1;
  setsockopt (px->lfd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
  memset (&sin, 0, sizeof sin);
  sin.sin_family = AF_INET;
  sin.sin_addr.s_addr = htonl (INADDR_LOOPBACK);
  if (bind (px->lfd, (struct sockaddr *) &sin, sizeof sin) != 0
      || listen (px->lfd, 8) != 0
      || getsockname (px->lfd, (struct sockaddr *) &sin, &len) != 0)
    return -1;
  px->port = ntohs (sin.sin_port);
  return pthread_create (&px->thread, NULL, px_serve, px) == 0 ? 0 : -1;
}

static void
px_stop (struct px *px)
{
  int i;

  px->stop = 1;
  pthread_join (px->thread, NULL);
  for (i = 0; i < 100; i++)
    {
      struct timespec nap = { 0, 30000000 };
      unsigned a;

      pthread_mutex_lock (&px->mu);
      a = px->active;
      pthread_mutex_unlock (&px->mu);
      if (a == 0)
        break;
      nanosleep (&nap, NULL);
    }
  close (px->lfd);
  pthread_mutex_destroy (&px->mu);
}

static unsigned
px_connects (struct px *px)
{
  unsigned n;

  pthread_mutex_lock (&px->mu);
  n = px->connects;
  pthread_mutex_unlock (&px->mu);
  return n;
}

static void
px_target (struct px *px, char *out, size_t cap, int *atyp)
{
  pthread_mutex_lock (&px->mu);
  snprintf (out, cap, "%s", px->target);
  *atyp = px->atyp;
  pthread_mutex_unlock (&px->mu);
}

/* The URL of a proxy of this kind on this port, with credentials if wanted.  */
static void
px_url (const struct px *px, const char *userinfo, char *out, size_t cap)
{
  snprintf (out, cap, "%s://%s%s127.0.0.1:%d",
            px->kind == PX_HTTP_KIND ? "http" : "socks5",
            userinfo != NULL ? userinfo : "", userinfo != NULL ? "@" : "",
            px->port);
}

static struct twist_transfer *
proxied_transfer (const char *proxy_url)
{
  struct twist_transfer *transfer = tcp_transfer (0, "secret", NULL);

  twist_transfer_setopt (transfer, TWISTOPT_PROXY, proxy_url);
  return transfer;
}

static void
test_proxy_kind (int kind)
{
  const char *name = kind == PX_HTTP_KIND ? "http" : "socks5";
  struct tcp_server ts;
  struct px px;
  struct twist_runtime *runtime;
  struct twist_transfer *transfer;
  char url[200], what[100], target[320], want[160];
  int atyp;

  check (ts_start (&ts) == 0 && px_start (&px, kind) == 0, "servers");
  runtime = twist_runtime_new ();
  px_url (&px, NULL, url, sizeof url);

  /* A download through the proxy, and what the proxy was asked for.  */
  transfer = proxied_transfer (url);
  snprintf (what, sizeof what, "%s: a download through the proxy", name);
  check (tcp_get (runtime, transfer, &ts, "sftp", "/data.bin") == TWIST_OK
         && got_data (), what);
  px_target (&px, target, sizeof target, &atyp);
  snprintf (want, sizeof want, "127.0.0.1:%d", ts.port);
  check (strcmp (target, want) == 0
         && (kind == PX_HTTP_KIND || atyp == 1),
         "the proxy was asked for the server, as an address");
  check (ts_accepted (&ts) == 1 && px_connects (&px) == 1, "one tunnel");

  /* The next URL uses the tunnel.  */
  snprintf (what, sizeof what, "%s: the next URL uses the same tunnel", name);
  check (tcp_get (runtime, transfer, &ts, "sftp", "/data.bin") == TWIST_OK
         && got_data () && ts_accepted (&ts) == 1 && px_connects (&px) == 1,
         what);

  /* Without the proxy it is another connection; a session made through one
     proxy is not another's.  */
  {
    struct twist_transfer *direct = tcp_transfer (0, "secret", NULL);

    check (tcp_get (runtime, direct, &ts, "sftp", "/data.bin") == TWIST_OK
           && ts_accepted (&ts) == 2 && px_connects (&px) == 1,
           "a transfer without the proxy does not take the tunnel");
    twist_transfer_free (direct);
  }
  twist_transfer_free (transfer);
  twist_runtime_free (runtime);
  px_stop (&px);
  ts_stop (&ts);
}

/* The server speaks first.  Its banner comes in the same write as the
   proxy's reply, and must not be lost.  */
static void
test_proxy_banner_with_reply (int kind)
{
  struct tcp_server ts;
  struct px px;
  struct twist_runtime *runtime;
  struct twist_transfer *transfer;
  char url[200], what[100];

  check (ts_start (&ts) == 0 && px_start (&px, kind) == 0, "servers");
  px.coalesce = 1;
  runtime = twist_runtime_new ();
  px_url (&px, NULL, url, sizeof url);
  transfer = proxied_transfer (url);
  snprintf (what, sizeof what, "%s: the banner that comes with the reply",
            kind == PX_HTTP_KIND ? "http" : "socks5");
  check (tcp_get (runtime, transfer, &ts, "sftp", "/data.bin") == TWIST_OK
         && got_data (), what);
  twist_transfer_free (transfer);
  twist_runtime_free (runtime);
  px_stop (&px);
  ts_stop (&ts);
}

static void
test_proxy_refusals (void)
{
  struct tcp_server ts;
  struct px px;
  struct twist_runtime *runtime;
  struct twist_transfer *transfer;
  char url[200];

  /* CONNECT refused: the words of the refusal, and the status.  */
  check (ts_start (&ts) == 0 && px_start (&px, PX_HTTP_KIND) == 0, "servers");
  px.refuse_http = 403;
  runtime = twist_runtime_new ();
  px_url (&px, NULL, url, sizeof url);
  transfer = proxied_transfer (url);
  check (tcp_get (runtime, transfer, &ts, "sftp",
                  "/data.bin") == TWIST_ERR_PROXY
         && transfer->proto_status == 56
         && detail_has (transfer, "CONNECT tunnel failed, response 403")
         && got_len == 0 && ts_accepted (&ts) == 0, "a CONNECT that is refused");
  twist_transfer_free (transfer);
  twist_runtime_free (runtime);
  px_stop (&px);

  /* A proxy that cannot reach the server.  */
  check (px_start (&px, PX_HTTP_KIND) == 0, "proxy");
  runtime = twist_runtime_new ();
  px_url (&px, NULL, url, sizeof url);
  transfer = proxied_transfer (url);
  twist_transfer_setopt (transfer, TWISTOPT_URL, "sftp://alice@127.0.0.1:1/x");
  check (check_perform_in (runtime, transfer) == TWIST_ERR_PROXY
         && detail_has (transfer, "response 502"), "a server the proxy cannot reach");
  twist_transfer_free (transfer);
  twist_runtime_free (runtime);
  px_stop (&px);

  /* SOCKS refused.  */
  check (px_start (&px, PX_SOCKS_KIND) == 0, "socks proxy");
  px.refuse_socks = 5;
  runtime = twist_runtime_new ();
  px_url (&px, NULL, url, sizeof url);
  transfer = proxied_transfer (url);
  check (tcp_get (runtime, transfer, &ts, "sftp",
                  "/data.bin") == TWIST_ERR_PROXY
         && transfer->proto_status == 97
         && detail_has (transfer, "Can't complete SOCKS5 connection to 127.0.0.1. (5)")
         && ts_accepted (&ts) == 0, "a SOCKS request that is refused");
  twist_transfer_free (transfer);
  twist_runtime_free (runtime);
  px_stop (&px);

  /* No proxy there at all.  */
  runtime = twist_runtime_new ();
  transfer = proxied_transfer ("http://127.0.0.1:1");
  check (tcp_get (runtime, transfer, &ts, "sftp",
                  "/data.bin") == TWIST_ERR_CONNECT,
         "no proxy listening");
  twist_transfer_free (transfer);
  twist_runtime_free (runtime);

  /* A kind that is not spoken.  */
  runtime = twist_runtime_new ();
  transfer = proxied_transfer ("socks4://127.0.0.1:1080");
  check (tcp_get (runtime, transfer, &ts, "sftp", "/data.bin") == TWIST_ERR_UNSUPPORTED
         && detail_has (transfer, "not supported"),
         "a SOCKS4 proxy is refused");
  twist_transfer_free (transfer);
  /* An https proxy is spoken to, in TLS; with none there it is a refused
     connection and not the clear text of the SSH banner.  */
  transfer = proxied_transfer ("https://127.0.0.1:1");
  check (tcp_get (runtime, transfer, &ts, "sftp",
                  "/data.bin") == TWIST_ERR_CONNECT,
         "no https proxy listening");
  twist_transfer_free (transfer);
  twist_runtime_free (runtime);
  ts_stop (&ts);
}

static void
test_proxy_credentials (int kind)
{
  const char *name = kind == PX_HTTP_KIND ? "http" : "socks5";
  struct tcp_server ts;
  struct px px;
  struct twist_runtime *runtime;
  struct twist_transfer *transfer;
  char url[200], what[120];
  unsigned before;
  const char *none_msg = kind == PX_HTTP_KIND
    ? "response 407" : "No authentication method was acceptable.";
  const char *bad_msg = kind == PX_HTTP_KIND
    ? "response 407" : "User was rejected by the SOCKS5 server (1 1).";

  check (ts_start (&ts) == 0 && px_start (&px, kind) == 0, "servers");
  px.user = "pxuser";
  px.pass = "px:pass";
  runtime = twist_runtime_new ();

  px_url (&px, NULL, url, sizeof url);
  transfer = proxied_transfer (url);
  snprintf (what, sizeof what, "%s: a proxy that wants credentials, none given",
            name);
  check (tcp_get (runtime, transfer, &ts, "sftp",
                  "/data.bin") == TWIST_ERR_PROXY
         && detail_has (transfer, none_msg), what);
  twist_transfer_free (transfer);

  px_url (&px, "pxuser:px%3Apass", url, sizeof url);
  transfer = proxied_transfer (url);
  snprintf (what, sizeof what, "%s: credentials in the proxy's URL", name);
  check (tcp_get (runtime, transfer, &ts, "sftp", "/data.bin") == TWIST_OK
         && got_data (), what);
  twist_transfer_free (transfer);

  px_url (&px, NULL, url, sizeof url);
  transfer = proxied_transfer (url);
  twist_transfer_setopt (transfer, TWISTOPT_PROXYUSERPWD, "pxuser:px:pass");
  snprintf (what, sizeof what, "%s: credentials from the option", name);
  check (tcp_get (runtime, transfer, &ts, "sftp", "/data.bin") == TWIST_OK
         && got_data (), what);
  /* The tunnel is kept; credentials that are wrong are not let through it.  */
  twist_transfer_setopt (transfer, TWISTOPT_PROXYUSERPWD, "pxuser:wrong");
  snprintf (what, sizeof what, "%s: other credentials do not take the tunnel",
            name);
  before = ts_accepted (&ts);
  check (tcp_get (runtime, transfer, &ts, "sftp",
                  "/data.bin") == TWIST_ERR_PROXY
         && detail_has (transfer, bad_msg) && ts_accepted (&ts) == before,
         what);
  twist_transfer_free (transfer);

  px_url (&px, "pxuser:wrong", url, sizeof url);
  transfer = proxied_transfer (url);
  snprintf (what, sizeof what, "%s: wrong credentials", name);
  check (tcp_get (runtime, transfer, &ts, "sftp",
                  "/data.bin") == TWIST_ERR_PROXY
         && detail_has (transfer, bad_msg), what);
  twist_transfer_free (transfer);
  twist_runtime_free (runtime);
  px_stop (&px);
  ts_stop (&ts);
  (void) none_msg;
}

/* A reply with a great deal of header in it.  */
static void
test_proxy_long_reply (void)
{
  struct tcp_server ts;
  struct px px;
  struct twist_runtime *runtime;
  struct twist_transfer *transfer;
  char url[200];

  check (ts_start (&ts) == 0 && px_start (&px, PX_HTTP_KIND) == 0, "servers");
  px.bigheader = 1;
  px.coalesce = 1;
  runtime = twist_runtime_new ();
  px_url (&px, NULL, url, sizeof url);
  transfer = proxied_transfer (url);
  check (tcp_get (runtime, transfer, &ts, "sftp", "/data.bin") == TWIST_OK
         && got_data (), "a reply of three thousand bytes, and the banner");
  twist_transfer_free (transfer);
  twist_runtime_free (runtime);
  px_stop (&px);
  ts_stop (&ts);
}

/* An IPv6 server behind each kind of proxy: brackets in CONNECT, an address of
   the right kind in SOCKS.  */
static void
test_proxy_ipv6 (int kind)
{
  struct tcp_server ts;
  struct px px;
  struct twist_runtime *runtime;
  struct twist_transfer *transfer;
  char url[200], target[320], want[160];
  int atyp;

  if (ts_start_on (&ts, TS_V6) != 0)
    return;
  check (px_start (&px, kind) == 0, "proxy");
  runtime = twist_runtime_new ();
  px_url (&px, NULL, url, sizeof url);
  transfer = proxied_transfer (url);
  check (tcp_get (runtime, transfer, &ts, "sftp", "/data.bin") == TWIST_OK
         && got_data (), "an IPv6 server through a proxy");
  px_target (&px, target, sizeof target, &atyp);
  if (kind == PX_HTTP_KIND)
    snprintf (want, sizeof want, "[::1]:%d", ts.port);
  else
    snprintf (want, sizeof want, "::1:%d", ts.port);
  check (strcmp (target, want) == 0 && (kind == PX_HTTP_KIND || atyp == 4),
         kind == PX_HTTP_KIND ? "CONNECT [::1]:port"
                              : "SOCKS asked for an IPv6 address");
  twist_transfer_free (transfer);
  twist_runtime_free (runtime);
  px_stop (&px);
  ts_stop (&ts);
}

static void
test_proxies (void)
{
  test_proxy_kind (PX_HTTP_KIND);
  test_proxy_kind (PX_SOCKS_KIND);
  test_proxy_banner_with_reply (PX_HTTP_KIND);
  test_proxy_banner_with_reply (PX_SOCKS_KIND);
  test_proxy_long_reply ();
  test_proxy_refusals ();
  test_proxy_credentials (PX_HTTP_KIND);
  test_proxy_credentials (PX_SOCKS_KIND);
  test_proxy_ipv6 (PX_HTTP_KIND);
  test_proxy_ipv6 (PX_SOCKS_KIND);
}

/* ---- the connect timeout ---- */

/* A server that takes the connection and says nothing, or sends its banner
   and nothing after.  */
struct stall
{
  int lfd, port, banner;
  pthread_t thread;
  volatile int stop;
  int fds[16];
  int nfds;
};

static void *
stall_serve (void *arg)
{
  struct stall *st = arg;

  while (!st->stop)
    {
      struct pollfd f = { st->lfd, POLLIN, 0 };
      int fd;

      if (poll (&f, 1, 50) <= 0)
        continue;
      fd = accept (st->lfd, NULL, NULL);
      if (fd < 0)
        continue;
      if (st->banner)
        send (fd, "SSH-2.0-stall_1\r\n", 17, MSG_NOSIGNAL);
      if (st->nfds < 16)
        st->fds[st->nfds++] = fd;
      else
        close (fd);
    }
  return NULL;
}

static int
stall_start (struct stall *st, int banner)
{
  struct sockaddr_in sin;
  socklen_t len = sizeof sin;

  memset (st, 0, sizeof *st);
  st->banner = banner;
  st->lfd = socket (AF_INET, SOCK_STREAM, 0);
  if (st->lfd < 0)
    return -1;
  memset (&sin, 0, sizeof sin);
  sin.sin_family = AF_INET;
  sin.sin_addr.s_addr = htonl (INADDR_LOOPBACK);
  if (bind (st->lfd, (struct sockaddr *) &sin, sizeof sin) != 0
      || listen (st->lfd, 8) != 0
      || getsockname (st->lfd, (struct sockaddr *) &sin, &len) != 0)
    return -1;
  st->port = ntohs (sin.sin_port);
  return pthread_create (&st->thread, NULL, stall_serve, st) == 0 ? 0 : -1;
}

static void
stall_stop (struct stall *st)
{
  int i;

  st->stop = 1;
  pthread_join (st->thread, NULL);
  for (i = 0; i < st->nfds; i++)
    close (st->fds[i]);
  close (st->lfd);
}

/* Fetch from PORT with a connect timeout of MS, optionally through PROXY;
   how long it took, in seconds, is in *TOOK.  */
static int
timed_get (struct twist_runtime *runtime, int port, const char *proxy, long ms,
           double *took)
{
  struct twist_transfer *transfer = tcp_transfer (0, "secret", NULL);
  char url[100];
  double t0 = seconds ();
  int rc;

  snprintf (url, sizeof url, "sftp://alice@127.0.0.1:%d/data.bin", port);
  twist_transfer_setopt (transfer, TWISTOPT_URL, url);
  twist_transfer_setopt (transfer, TWISTOPT_CONNECTTIMEOUT_MS, ms);
  if (proxy != NULL)
    twist_transfer_setopt (transfer, TWISTOPT_PROXY, proxy);
  got_len = 0;
  rc = check_perform_in (runtime, transfer);
  *took = seconds () - t0;
  twist_transfer_free (transfer);
  return rc;
}

/* The connect timeout is for all of making the connection: the TCP connect,
   the proxy and the SSH handshake up to the login.  A server that takes the
   connection and does not go on is given up on, where before it was waited
   for for ever.  */
/* foxtrot gives a key exchange 60 seconds unless told otherwise.  The time
   allowed for connecting is the user's: it is what the key exchange gets.  */
static void
test_connect_timeout_kex (void)
{
  struct server sv;
  struct world w;
  struct twist_transfer *transfer;
  struct setup su = SETUP ("sftp://alice@127.0.0.1/data.bin", 0, "secret");

  check (server_new (&sv) == 0, "server");
  transfer = start (&w, &sv, &su);
  twist_transfer_setopt (transfer, TWISTOPT_CONNECTTIMEOUT_MS, 120000L);
  check (twist_ssh_start (w.ssh) == TWIST_OK, "start");
  pump (&w, transfer, 65536);
  check (transfer->done && transfer->result == TWIST_OK
         && w.ssh->config.conn.kex_timeout_us == 120000000u,
         "the key exchange has the connect timeout");
  twist_transfer_free (transfer);
  server_free (&sv);
}

static void
test_connect_timeout (void)
{
  test_connect_timeout_kex ();
  struct stall silent, banner;
  struct tcp_server ts;
  struct twist_runtime *runtime;
  struct twist_transfer *transfer;
  char proxy[80];
  double took;

  check (stall_start (&silent, 0) == 0 && stall_start (&banner, 1) == 0
         && ts_start (&ts) == 0, "servers");
  runtime = twist_runtime_new ();

  check (timed_get (runtime, silent.port, NULL, 500,
                    &took) == TWIST_ERR_TIMEOUT
         && took >= 0.4 && took < 2.0, "a server that says nothing");
  if (took < 0.4 || took >= 2.0)
    fprintf (stderr, "  took %.2f s\n", took);
  check (timed_get (runtime, banner.port, NULL, 500,
                    &took) == TWIST_ERR_TIMEOUT
         && took >= 0.4 && took < 2.0, "a server that sends only its banner");
  snprintf (proxy, sizeof proxy, "http://127.0.0.1:%d", silent.port);
  check (timed_get (runtime, ts.port, proxy, 500, &took) == TWIST_ERR_TIMEOUT
         && took >= 0.4 && took < 2.0, "an HTTP proxy that says nothing");
  snprintf (proxy, sizeof proxy, "socks5://127.0.0.1:%d", silent.port);
  check (timed_get (runtime, ts.port, proxy, 500, &took) == TWIST_ERR_TIMEOUT
         && took >= 0.4 && took < 2.0, "a SOCKS proxy that says nothing");
  check (ts_accepted (&ts) == 0, "and the server behind it was not reached");

  /* The timeout ends at the login: a transfer that goes on longer is not cut
     off by it.  This one takes about a second at its rate.  */
  transfer = tcp_transfer (0, "secret", NULL);
  twist_transfer_setopt (transfer, TWISTOPT_CONNECTTIMEOUT_MS, 400L);
  twist_transfer_setopt (transfer, TWISTOPT_MAX_RECV_SPEED_LARGE,
                         (uint64_t) 100000);
  {
    double t0 = seconds ();

    check (tcp_get (runtime, transfer, &ts, "sftp", "/data.bin") == TWIST_OK
           && got_data (), "a transfer that outlasts the connect timeout");
    took = seconds () - t0;
    check (took > 0.8, "and did take longer than it");
  }

  /* A session that is kept needs no connecting, so a connect timeout that is
     too short for anything does not touch it.  */
  twist_transfer_setopt (transfer, TWISTOPT_MAX_RECV_SPEED_LARGE,
                         (uint64_t) 0);
  twist_transfer_setopt (transfer, TWISTOPT_CONNECTTIMEOUT_MS, 1L);
  check (tcp_get (runtime, transfer, &ts, "sftp", "/data.bin") == TWIST_OK
         && got_data () && ts_accepted (&ts) == 1,
         "a kept session is not subject to it");
  twist_transfer_free (transfer);

  /* The total timeout still ends a server that stalls.  */
  transfer = tcp_transfer (0, "secret", NULL);
  {
    char url[100];
    double t0 = seconds ();

    snprintf (url, sizeof url, "sftp://alice@127.0.0.1:%d/x", banner.port);
    twist_transfer_setopt (transfer, TWISTOPT_URL, url);
    twist_transfer_setopt (transfer, TWISTOPT_TIMEOUT_MS, 500L);
    check (check_perform_in (runtime, transfer) == TWIST_ERR_TIMEOUT
           && seconds () - t0 < 2.0, "the total timeout, as before");
  }
  twist_transfer_free (transfer);
  twist_runtime_free (runtime);
  ts_stop (&ts);
  stall_stop (&banner);
  stall_stop (&silent);
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
      struct twist_runtime *runtime = twist_runtime_new ();
      struct twist_transfer *transfer = twist_transfer_new ();
      struct twist_ssh *ssh;
      struct pipe *sink = calloc (1, sizeof *sink);
      struct timespec nap = { 0, 300000 * (i % 7) };

      check (runtime != NULL && sink != NULL, "runtime");
      check (twist_url_parse_int ("sftp://alice@127.0.0.1/data.bin",
                                  &transfer->url) == TWIST_OK, "url");
      twist_transfer_setopt (transfer, TWISTOPT_PASSWORD, "secret");
      twist_transfer_setopt (transfer, TWISTOPT_SSL_VERIFYPEER, 0L);
      attach_by_hand (runtime, transfer);
      ssh = twist_ssh_new (transfer, 0);
      twist_ssh_set_sink (ssh, client_sink, sink);
      check (twist_ssh_start (ssh) == TWIST_OK, "start");
      nanosleep (&nap, NULL);
      /* Drop the transfer, then let the loop see whatever the job posted.  */
      twist_transfer_free (transfer);
      {
        int k;

        for (k = 0; k < 20; k++)
          twist_runtime_run_once (runtime, 0);
      }
      twist_runtime_free (runtime);
      free (sink);
    }
}

/* The text of an error that a server wrote is shown on the terminal and
   written to the output of -w, so it is not given the terminal: control
   characters, and the C1 ones in UTF-8, are made "?", as for a listing, and
   it is of a length that fits.  It was copied as it came.  */
static int
has_control (const char *s)
{
  const unsigned char *p;

  for (p = (const unsigned char *) s; *p != 0; p++)
    if (*p < 0x20 || *p == 0x7f || (*p == 0xc2 && p[1] >= 0x80 && p[1] < 0xa0))
      return 1;
  return 0;
}

static void
test_server_text_is_clean (void)
{
  struct server sv;
  struct world w;
  struct twist_transfer *transfer;
  struct setup su = SETUP ("sftp://alice@127.0.0.1/hostile", 0, "secret");
  struct twist_slist *pre;

  check (server_new (&sv) == 0, "server");
  transfer = run (&w, &sv, &su);
  check (transfer->done && transfer->result == TWIST_ERR_FILE
         && twist_transfer_error (transfer) != NULL
         && detail_has (transfer, "permission denied"),
         "a hostile status still fails the transfer");
  check (twist_transfer_error (transfer) != NULL && !has_control (twist_transfer_error (transfer)),
         "and its message has no control character in it");
  check (twist_transfer_error (transfer) != NULL && strlen (twist_transfer_error (transfer)) < 300,
         "and it is not longer than fits");
  twist_transfer_free (transfer);
  server_free (&sv);

  check (server_new (&sv) == 0, "server 2");
  su.url = "sftp://alice@127.0.0.1/";
  pre = commands ("rm /hostile", NULL, NULL);
  transfer = quote_run (&w, &sv, &su, pre, NULL);
  check (transfer->done && transfer->result == TWIST_ERR_QUOTE
         && twist_transfer_error (transfer) != NULL
         && !has_control (twist_transfer_error (transfer)),
         "the same for a command that fails");
  twist_transfer_free (transfer);
  server_free (&sv);
  twist_slist_free_all (pre);
}

/* A server may answer a read with less than was asked, and then the rest is
   asked for.  One that holds the first read and answers every other with a
   single byte makes a slot for each answer that cannot be delivered, and
   another for the rest, with no end: memory grew with the server's patience,
   and each answer scanned the list.  The number of reads in hand is limited,
   and a server that goes past it is not answering reads.  */
static void
test_short_read_flood (void)
{
  struct server sv;
  struct world w;
  struct twist_transfer *transfer;
  struct setup su = SETUP ("sftp://alice@127.0.0.1/data.bin", 0, "secret");
  size_t n = 16 * 32768;
  uint8_t *bigfile = malloc (n);

  check (bigfile != NULL, "a bigfile file");
  memset (bigfile, 'z', n);
  check (server_new (&sv) == 0, "server");
  sv.file = bigfile;
  sv.filelen = n;
  sv.max_read = 1;
  sv.hold_first = 1;
  transfer = run (&w, &sv, &su);
  check (transfer->done && transfer->result == TWIST_ERR_PROTOCOL,
         "a server that answers reads a byte at a time and holds one is refused");
  check (sv.reads < 3000, "after a bounded number of reads");
  twist_transfer_free (transfer);
  server_free (&sv);
  free (bigfile);

  /* An ordinary server that answers in smaller pieces than asked, in order, is
     not.  */
  check (server_new (&sv) == 0, "server 2");
  sv.max_read = 600;
  transfer = run (&w, &sv, &su);
  check (transfer->done && transfer->result == TWIST_OK, "small pieces in order are fine");
  twist_transfer_free (transfer);
  server_free (&sv);
}

static int run_tests (void);

/* The tests keep servers and pipes of 2 MiB and more in their frames, which
   Linux's 8 MiB stack holds and Mac OS's, for a thread other than the first
   (512 KiB), does not, nor the first for a function with two of them.  So
   they run on a thread whose stack is made big enough.  */
#define TEST_STACK (256UL * 1024 * 1024)

static void *
run_thread (void *arg)
{
  *(int *) arg = run_tests ();
  return NULL;
}

int
main (void)
{
  pthread_attr_t attr;
  pthread_t thread;
  int status = 1;

  if (pthread_attr_init (&attr) != 0
      || pthread_attr_setstacksize (&attr, TEST_STACK) != 0
      || pthread_create (&thread, &attr, run_thread, &status) != 0)
    return run_tests ();
  pthread_join (thread, NULL);
  return status;
}

static int
run_tests (void)
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
  test_upload_read_error ();
  test_quote_order ();
  test_quote_failures ();
  test_quote_commands ();
  test_quote_pwd ();
  test_quote_only ();
  test_quote_with_list_and_upload ();
  test_create_dirs ();
  test_download_resume ();
  test_ranges ();
  test_listing ();
  test_agent_login ();
  test_agent_many_keys ();
  test_agent_precedence ();
  test_agent_refusal ();
  test_agent_failures ();
  test_agent_rsa ();
  test_agent_session_bind ();
  test_agent_abandoned ();
  test_no_subsystem ();
  test_server_text_is_clean ();
  test_short_read_flood ();
  test_auth ();
  test_url_credentials ();
  test_kbdint ();
  test_certificates ();
  test_host_key ();
  test_bad_peer ();
  test_timeout ();
  test_no_user ();
  test_off_the_loop ();
  test_off_the_loop_errors ();
  test_abandoned_job ();
  alarm (240);
  test_reuse_basic ();
  test_reuse_mixed ();
  test_reuse_terms ();
  test_reuse_hung_up ();
  test_reuse_after_error ();
  test_reuse_unanswered ();
  test_reuse_concurrent ();
  test_limits ();
  test_limit_chunks ();
  test_ipv6_known_hosts ();
  test_ipv6_literal ();
  test_ipv6_zone ();
  test_proxies ();
  test_connect_timeout ();
  rmdir (home);
  return tests_finish ();
}
