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
#include "smbsrv.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* smb:// as a download and as an upload, against the scripted server of smbsrv.c: a whole
   login, then the file as the handler asks for it.  The server can answer
   as a real one does not always: with less than was asked, with answers out
   of order, with an error for the file or the share.  */

#define FILE_SIZE 150000u
#define FILE_MAX (1u << 20)

struct scen
{
  int strict_dirs;		/* A file whose directories are not there is refused.  */
  uint32_t write_status;	/* An error for the writes.  */
  int short_write;		/* Say one byte fewer was written.  */
  int short_reads;		/* Answer half of what is asked.  */
  int reorder;			/* Answer the reads that are waiting backwards.  */
  uint32_t create_status;	/* An error for the CREATE.  */
  uint32_t size;
  struct srv_opts o;
};

struct tx
{
  struct twist_transfer *t;
  struct twist_smb *x;
  struct smbsrv srv;
  struct scen sc;
  uint8_t *q[512];
  size_t qn[512];
  unsigned qhead, qtail;
  int stage;			/* Frames of the login handled.  */
  uint8_t *held[64];
  size_t heldn[64];
  unsigned nheld;
  uint8_t out[FILE_MAX + 16];
  size_t out_n;
  size_t piece;
  int pause_once, paused_seen;
  unsigned reads, reads_while_paused;
  char cmds[256];
  char name[64];
  int saw_domain;
  /* The server's side of a listing.  */
  struct
  {
    uint16_t name[64];
    unsigned nlen;
    uint32_t attrs;
    uint64_t size, mtime;
  } ents[16];
  unsigned nents, page, queries, qpos;
  int empty_nosuch;
  int restart_first;
  /* The server's side of an upload.  */
  uint8_t store[FILE_MAX + 16];
  size_t store_len;
  int store_exists;
  uint32_t disposition;
  char dirs[256];
  unsigned writes;
  unsigned max_write_len;
  int stalled;
};

static uint8_t
file_byte (size_t i)
{
  return (uint8_t) (i * 7 + i / 251);
}

static size_t
on_write (char *p, size_t size, size_t nmemb, void *u)
{
  struct tx *z = u;
  size_t n = size * nmemb;

  if (z->pause_once && !z->paused_seen)
    {
      z->paused_seen = 1;
      return TWIST_WRITEFUNC_PAUSE;
    }
  if (z->out_n + n <= sizeof z->out)
    memcpy (z->out + z->out_n, p, n);
  z->out_n += n;
  return n;
}

static int
is_full (void *u)
{
  return ((struct tx *) u)->stalled;
}

static int
to_server (void *u, const uint8_t *d, size_t n)
{
  struct tx *z = u;

  z->q[z->qtail] = malloc (n);
  memcpy (z->q[z->qtail], d, n);
  z->qn[z->qtail++] = n;
  return TWIST_OK;
}

/* A message of the server's to the handler, framed, in pieces.  */
static void
to_client (void *u, const uint8_t *m, size_t n)
{
  struct tx *z = u;
  uint8_t *f = malloc (n + 4);
  size_t off = 0, stuck = 0;

  f[0] = 0;
  f[1] = (uint8_t) (n >> 16);
  f[2] = (uint8_t) (n >> 8);
  f[3] = (uint8_t) n;
  memcpy (f + 4, m, n);
  while (off < n + 4 && stuck < 3)
    {
      size_t c = n + 4 - off < z->piece ? n + 4 - off : z->piece;
      size_t used = twist_smb_receive (z->x, f + off, c);

      off += used;
      stuck = used == 0 ? stuck + 1 : 0;
    }
  free (f);
}

static void
note (struct tx *z, char c)
{
  size_t n = strlen (z->cmds);

  if (n + 1 < sizeof z->cmds)
    {
      z->cmds[n] = c;
      z->cmds[n + 1] = 0;
    }
}

static void
body_error (struct msg *m, unsigned cmd, uint32_t status, uint64_t id)
{
  header (m, cmd, status, 0, id, SESSION_ID, 5);
  p16 (m, 9);
  p8 (m, 0);
  p8 (m, 0);
  p32 (m, 0);
  p8 (m, 0);
}

static void
answer_read (struct tx *z, const uint8_t *req)
{
  struct msg r;
  uint32_t len = req[64 + 4] | (req[64 + 5] << 8) | (req[64 + 6] << 16)
    | ((uint32_t) req[64 + 7] << 24);
  uint64_t off = 0, id = 0;
  size_t i, give;

  for (i = 0; i < 8; i++)
    {
      off |= (uint64_t) req[64 + 8 + i] << (8 * i);
      id |= (uint64_t) req[24 + i] << (8 * i);
    }
  give = len;
  if (off + give > z->sc.size)
    give = off < z->sc.size ? (size_t) (z->sc.size - off) : 0;
  if (z->sc.short_reads && give > 1)
    give /= 2;
  header (&r, 8, 0, 0, id, SESSION_ID, 5);
  p16 (&r, 17);
  p8 (&r, 0x50);
  p8 (&r, 0);
  p32 (&r, (uint32_t) give);
  p32 (&r, 0);
  p32 (&r, 0);
  for (i = 0; i < give; i++)
    p8 (&r, file_byte ((size_t) off + i));
  srv_seal (&z->srv, &r);
}

static void
handle (struct tx *z, const uint8_t *f, size_t n)
{
  struct msg plain, r;
  uint64_t id = 0;
  size_t i;

  if (z->stage == 0)
    {
      srv_negotiate (&z->srv, f, n);
      z->stage = 1;
      return;
    }
  if (z->stage == 1)
    {
      srv_setup1 (&z->srv, f, n);
      z->stage = 2;
      return;
    }
  if (z->stage == 2)
    {
      /* The AUTHENTICATE carries the domain, from DOMAIN\user.  */
      static const uint8_t dom[] = { 'D', 0, 'o', 0, 'm', 0, 'a', 0, 'i', 0, 'n', 0 };

      for (i = 0; i + sizeof dom <= n; i++)
        if (memcmp (f + i, dom, sizeof dom) == 0)
          z->saw_domain = 1;
      srv_setup2 (&z->srv, f, n);
      z->stage = 3;
      return;
    }
  if (z->stage == 3)
    {
      srv_tree (&z->srv, f, n, 5);
      z->stage = 4;
      return;
    }
  if (srv_open (&z->srv, f, n, &plain) != 0)
    {
      note (z, '!');
      return;
    }
  for (i = 0; i < 8; i++)
    id |= (uint64_t) plain.b[24 + i] << (8 * i);
  switch (plain.b[12])
    {
    case 5:			/* CREATE */
      {
        size_t off = plain.b[64 + 44] | (plain.b[64 + 45] << 8);
        size_t nl = plain.b[64 + 46] | (plain.b[64 + 47] << 8);
        char name[64];
        uint32_t disp = plain.b[64 + 36];
        uint32_t opts = plain.b[64 + 40];
        uint64_t eof = z->sc.size;

        for (i = 0; i < nl / 2 && i + 1 < sizeof name; i++)
          name[i] = (char) plain.b[off + 2 * i];
        name[i] = 0;
        snprintf (z->name, sizeof z->name, "%s", name);
        z->disposition = disp;
        if ((opts & 1) != 0)
          {
            /* A directory.  */
            note (z, 'M');
            if (strlen (z->dirs) + strlen (name) + 2 < sizeof z->dirs)
              {
                strcat (z->dirs, name);
                strcat (z->dirs, ";");
              }
            eof = 0;
          }
        else
          {
            note (z, 'O');
            if (z->sc.strict_dirs && strchr (name, '\\') != NULL)
              {
                /* The directory above has to have been made.  */
                char dir[64], probe[72];
                const char *last = strrchr (name, '\\');

                memcpy (dir, name, (size_t) (last - name));
                dir[last - name] = 0;
                snprintf (probe, sizeof probe, "%s;", dir);
                if (strstr (z->dirs, probe) == NULL)
                  {
                    body_error (&r, 5, 0xC000003Au, id);
                    srv_seal (&z->srv, &r);
                    return;
                  }
              }
            if (disp == 5)
              {
                z->store_len = 0;
                z->store_exists = 1;
              }
            else if (disp == 3 && !z->store_exists)
              z->store_exists = 1;
            if (disp == 3 || disp == 5)
              eof = z->store_len;
          }
        if (z->sc.create_status != 0)
          {
            body_error (&r, 5, z->sc.create_status, id);
            srv_seal (&z->srv, &r);
            return;
          }
        header (&r, 5, 0, 0, id, SESSION_ID, 5);
        p16 (&r, 89);
        p8 (&r, 0);
        p8 (&r, 0);
        p32 (&r, 1);
        pz (&r, 32);
        p64 (&r, eof);
        p64 (&r, eof);
        p32 (&r, 0x20);
        p32 (&r, 0);
        for (i = 0; i < 16; i++)
          p8 (&r, 0xc0 + i);
        p32 (&r, 0);
        p32 (&r, 0);
        srv_seal (&z->srv, &r);
        return;
      }
    case 14:			/* QUERY_DIRECTORY */
      {
        unsigned first = z->queries, k, sent = 0;
        size_t lenpos, base, start, prev_start = 0;

        note (z, 'Q');
        z->queries++;
        if (first == 0)
          z->restart_first = plain.b[64 + 3] == 1;
        if (z->qpos >= z->nents)
          {
            body_error (&r, 14, z->empty_nosuch && first == 0 ? 0xC000000Fu
                                                              : 0x80000006u, id);
            srv_seal (&z->srv, &r);
            return;
          }
        header (&r, 14, 0, 0, id, SESSION_ID, 5);
        p16 (&r, 9);
        p16 (&r, 72);
        lenpos = r.n;
        p32 (&r, 0);
        base = r.n;
        for (k = z->qpos; k < z->nents && sent < z->page; k++, sent++)
          {
            start = r.n;
            if (sent > 0)
              {
                uint32_t off = (uint32_t) (start - prev_start);

                r.b[prev_start] = (uint8_t) off;
                r.b[prev_start + 1] = (uint8_t) (off >> 8);
              }
            p32 (&r, 0);
            p32 (&r, 0);
            p64 (&r, z->ents[k].mtime);
            p64 (&r, z->ents[k].mtime);
            p64 (&r, z->ents[k].mtime);
            p64 (&r, z->ents[k].mtime);
            p64 (&r, z->ents[k].size);
            p64 (&r, z->ents[k].size);
            p32 (&r, z->ents[k].attrs);
            p32 (&r, z->ents[k].nlen * 2);
            p32 (&r, 0);
            pz (&r, 2 + 24 + 2);
            p64 (&r, k + 1);
            for (i = 0; i < z->ents[k].nlen; i++)
              p16 (&r, z->ents[k].name[i]);
            while ((r.n - start) % 8)
              p8 (&r, 0);
            prev_start = start;
          }
        z->qpos = k;
        {
          uint32_t total = (uint32_t) (r.n - base);

          r.b[lenpos] = (uint8_t) total;
          r.b[lenpos + 1] = (uint8_t) (total >> 8);
          r.b[lenpos + 2] = (uint8_t) (total >> 16);
        }
        srv_seal (&z->srv, &r);
        return;
      }
    case 9:			/* WRITE */
      {
        uint32_t len = plain.b[64 + 4] | (plain.b[64 + 5] << 8)
          | (plain.b[64 + 6] << 16) | ((uint32_t) plain.b[64 + 7] << 24);
        uint64_t off = 0;
        size_t doff = plain.b[64 + 2] | (plain.b[64 + 3] << 8);

        for (i = 0; i < 8; i++)
          off |= (uint64_t) plain.b[64 + 8 + i] << (8 * i);
        note (z, 'W');
        z->writes++;
        if (len > z->max_write_len)
          z->max_write_len = len;
        if (z->sc.write_status != 0)
          {
            body_error (&r, 9, z->sc.write_status, id);
            srv_seal (&z->srv, &r);
            return;
          }
        if (off + len <= FILE_MAX && doff + len <= plain.n)
          {
            memcpy (z->store + off, plain.b + doff, len);
            if (off + len > z->store_len)
              z->store_len = (size_t) (off + len);
          }
        header (&r, 9, 0, 0, id, SESSION_ID, 5);
        p16 (&r, 17);
        p16 (&r, 0);
        p32 (&r, z->sc.short_write ? len - 1 : len);
        p32 (&r, 0);
        p16 (&r, 0);
        p16 (&r, 0);
        srv_seal (&z->srv, &r);
        return;
      }
    case 8:			/* READ */
      note (z, 'R');
      z->reads++;
      if (z->paused_seen && z->t->sink_paused)
        z->reads_while_paused++;
      if (z->sc.reorder && z->nheld < 64)
        {
          z->held[z->nheld] = malloc (plain.n);
          memcpy (z->held[z->nheld], plain.b, plain.n);
          z->heldn[z->nheld++] = plain.n;
          return;
        }
      answer_read (z, plain.b);
      return;
    case 6:			/* CLOSE */
      note (z, 'C');
      header (&r, 6, 0, 0, id, SESSION_ID, 5);
      p16 (&r, 60);
      p16 (&r, 0);
      pz (&r, 56);
      srv_seal (&z->srv, &r);
      return;
    case 4:
    case 2:
      note (z, plain.b[12] == 4 ? 'D' : 'L');
      header (&r, plain.b[12], 0, 0, id, SESSION_ID, 5);
      p16 (&r, 4);
      p16 (&r, 0);
      srv_seal (&z->srv, &r);
      return;
    default:
      note (z, '?');
    }
}

static void
serve (struct tx *z)
{
  for (;;)
    {
      while (z->qhead < z->qtail)
        {
          size_t k = z->qhead++;

          handle (z, z->q[k], z->qn[k]);
          free (z->q[k]);
        }
      if (z->nheld > 0)
        {
          /* The waiting reads, answered last first.  */
          while (z->nheld > 0)
            {
              z->nheld--;
              answer_read (z, z->held[z->nheld]);
              free (z->held[z->nheld]);
            }
          continue;
        }
      break;
    }
}

static int calls;

/* The client's random values, fixed as in test-smb-session: the GUID, the
   salt, the nonce start, then the NTLM client challenge and session key.  */
static int
fill (void *u, void *buf, size_t len)
{
  size_t i;
  int call = ++calls;

  (void) u;
  for (i = 0; i < len; i++)
    ((uint8_t *) buf)[i] = call == 1 ? 0x11 : call == 2 ? 0x22
      : call == 3 ? (uint8_t) (i + 1) : call == 4 ? 0xaa : 0x55;
  return 0;
}

static const struct twist_ntlm_rand rnd = { fill, NULL };

static struct tx *
begin (const char *url, const char *user, struct scen sc)
{
  struct tx *z = calloc (1, sizeof *z);

  z->sc = sc;
  calls = 0;
  twist_smb_set_test_rnd (&rnd);
  if (z->sc.size == 0)
    z->sc.size = FILE_SIZE;
  z->piece = 1 << 20;
  z->t = twist_transfer_new ();
  twist_url_parse_int (url, &z->t->url);
  z->t->write_cb = on_write;
  z->t->write_data = z;
  if (user != NULL)
    {
      twist_transfer_setopt (z->t, TWISTOPT_USERNAME, user);
      twist_transfer_setopt (z->t, TWISTOPT_PASSWORD, "Password");
    }
  return z;
}

static void
launch (struct tx *z)
{
  z->x = twist_smb_new (z->t, 0);
  if (z->x == NULL || z->t->done)
    return;
  srv_init (&z->srv, z->sc.o, to_client, z);
  twist_smb_test_seam (z->x, to_server, is_full, z);
  twist_smb_start (z->x);
  serve (z);
  if (getenv ("SMB_DEBUG") != NULL)
    fprintf (stderr, "  done %d result %d stage %d cmds %s out %zu err %s\n",
             z->t->done, z->t->result, z->stage, z->cmds, z->out_n,
             twist_transfer_error (z->t) != NULL ? twist_transfer_error (z->t) : "-");
}

static void
finish (struct tx *z)
{
  twist_transfer_free (z->t);
  free (z);
}

static int
same (const struct tx *z, size_t from, size_t n)
{
  size_t i;

  if (z->out_n != n)
    return 0;
  for (i = 0; i < n; i++)
    if (z->out[i] != file_byte (from + i))
      return 0;
  return 1;
}

static struct scen
plain_scen (void)
{
  struct scen sc;

  memset (&sc, 0, sizeof sc);
  sc.o = srv_good ();
  sc.size = FILE_SIZE;
  return sc;
}

#define URL "smb://server.example/share/dir/file.bin"

static void
test_download (void)
{
  struct tx *z;
  struct scen sc = plain_scen ();
  size_t pieces[] = { 1 << 20, 4099 };
  size_t k;

  for (k = 0; k < 2; k++)
    {
      z = begin (URL, "Domain\\User", sc);
      z->piece = pieces[k];
      launch (z);
      check (z->t->done && z->t->result == TWIST_OK, "smb: a download ends well");
      check (same (z, 0, FILE_SIZE), "smb: with every byte, in order");
      check (strcmp (z->name, "dir\\file.bin") == 0,
             "smb: the file is named with backslashes");
      check (z->saw_domain, "smb: DOMAIN\\user sends the domain");
      check (z->t->progress.downloaded == (long long) FILE_SIZE
             && z->t->progress.size_dl == (long long) FILE_SIZE,
             "smb: and the meter has the size and the count");
      check (z->cmds[0] == 'O' && z->cmds[1] == 'R'
             && strcmp (z->cmds + strlen (z->cmds) - 3, "CDL") == 0,
             "smb: CREATE, the reads, then CLOSE, TREE_DISCONNECT and LOGOFF");
      check (z->reads == 3, "smb: 150000 bytes are three reads of 64 KiB");
      finish (z);
    }
  z = begin (URL, "Domain/User", sc);
  launch (z);
  check (z->t->done && z->t->result == TWIST_OK && z->saw_domain,
         "smb: DOMAIN/user works as well");
  finish (z);

  sc.short_reads = 1;
  z = begin (URL, "Domain\\User", sc);
  launch (z);
  check (z->t->done && z->t->result == TWIST_OK && same (z, 0, FILE_SIZE),
         "smb: answers of half what was asked are asked for again");
  finish (z);

  sc = plain_scen ();
  sc.reorder = 1;
  z = begin (URL, "Domain\\User", sc);
  launch (z);
  check (z->t->done && z->t->result == TWIST_OK && same (z, 0, FILE_SIZE),
         "smb: answers that come last first are written in order");
  finish (z);

  sc = plain_scen ();
  sc.size = 0;
  z = begin (URL, "Domain\\User", sc);
  z->sc.size = 1;
  launch (z);
  check (z->t->done && z->t->result == TWIST_OK && same (z, 0, 1),
         "smb: a file of one byte");
  finish (z);
}

static void
test_ranges (void)
{
  struct tx *z;
  struct scen sc = plain_scen ();
  static const struct
  {
    const char *r;
    size_t from, n;
    int err;
    const char *what;
  } v[] = {
    { "100-1099", 100, 1000, TWIST_OK, "smb: a range" },
    { "149000-", 149000, 1000, TWIST_OK, "smb: a range to the end" },
    { "-500", 149500, 500, TWIST_OK, "smb: the last 500 bytes" },
    { "0-0", 0, 1, TWIST_OK, "smb: a range of one byte" },
    { "100-99999999", 100, FILE_SIZE - 100, TWIST_OK,
      "smb: a range that ends past the end is cut there" },
    { "200000-", 0, 0, TWIST_ERR_RANGE, "smb: a range beyond the end is refused" },
    { "x-3", 0, 0, TWIST_ERR_RANGE, "smb: a range that is not one is refused" }
  };
  size_t i;

  for (i = 0; i < sizeof v / sizeof v[0]; i++)
    {
      z = begin (URL, "Domain\\User", sc);
      twist_transfer_setopt (z->t, TWISTOPT_RANGE, v[i].r);
      launch (z);
      check (z->t->done && z->t->result == v[i].err, v[i].what);
      if (v[i].err == TWIST_OK)
        check (same (z, v[i].from, v[i].n), "smb: and it is those bytes");
      finish (z);
    }
  z = begin (URL, "Domain\\User", sc);
  twist_transfer_setopt (z->t, TWISTOPT_RESUME_FROM, (long long) 100000);
  launch (z);
  check (z->t->done && z->t->result == TWIST_OK && same (z, 100000, 50000),
         "smb: a resume starts at its offset");
  check (z->t->progress.size_dl == 50000, "smb: and the meter counts what is left");
  finish (z);
  z = begin (URL, "Domain\\User", sc);
  twist_transfer_setopt (z->t, TWISTOPT_RESUME_FROM, (long long) FILE_SIZE);
  launch (z);
  check (z->t->done && z->t->result == TWIST_OK && z->out_n == 0,
         "smb: a resume at the end has nothing to fetch");
  finish (z);
  z = begin (URL, "Domain\\User", sc);
  twist_transfer_setopt (z->t, TWISTOPT_RESUME_FROM, (long long) (FILE_SIZE + 1));
  launch (z);
  check (z->t->done && z->t->result == TWIST_ERR_RESUME,
         "smb: a resume past the end is a bad resume");
  finish (z);
  z = begin (URL, "Domain\\User", sc);
  twist_transfer_setopt (z->t, TWISTOPT_RESUME_FROM, (long long) 5);
  twist_transfer_setopt (z->t, TWISTOPT_RANGE, "1-2");
  launch (z);
  check (z->t->done && z->t->result == TWIST_ERR_INVAL,
         "smb: a resume and a range together are refused");
  finish (z);
}

static void
test_failures (void)
{
  struct tx *z;
  struct scen sc = plain_scen ();

  sc.create_status = 0xC0000034u;
  z = begin (URL, "Domain\\User", sc);
  launch (z);
  check (z->t->done && z->t->result == TWIST_ERR_FILE && z->t->proto_status == 78,
         "smb: a file that is not there is exit 78");
  finish (z);
  sc.create_status = 0xC0000022u;
  z = begin (URL, "Domain\\User", sc);
  launch (z);
  check (z->t->done && z->t->result == TWIST_ERR_FILE && z->t->proto_status == 9,
         "smb: access denied is exit 9");
  finish (z);
  sc = plain_scen ();
  sc.o.login_status = 0xC000006Du;
  z = begin (URL, "Domain\\User", sc);
  launch (z);
  check (z->t->done && z->t->result == TWIST_ERR_AUTH,
         "smb: a refused login is an authentication error");
  finish (z);
  sc = plain_scen ();
  sc.o.tree_status = 0xC00000CCu;
  z = begin (URL, "Domain\\User", sc);
  launch (z);
  check (z->t->done && z->t->result == TWIST_ERR_FILE && z->t->proto_status == 78,
         "smb: a share that is not there is exit 78");
  finish (z);
  sc = plain_scen ();
  sc.o.tree_status = 0xC0000022u;
  z = begin (URL, "Domain\\User", sc);
  launch (z);
  check (z->t->done && z->t->proto_status == 9,
         "smb: a share that refuses the user is exit 9");
  finish (z);
  /* No user name, no login: nothing is sent.  */
  z = begin (URL, NULL, sc);
  launch (z);
  check (z->t->done && z->t->result == TWIST_ERR_AUTH && z->qtail == 0,
         "smb: no user name is refused before anything is sent");
  finish (z);
  /* Anonymous by an empty name is the same.  */
  z = begin (URL, "", sc);
  launch (z);
  check (z->t->done && z->t->result == TWIST_ERR_AUTH,
         "smb: an empty user name is refused");
  finish (z);
}

static void
test_urls (void)
{
  static const struct
  {
    const char *url;
    int err;
    const char *what;
  } v[] = {
    { "smb://server.example/", TWIST_ERR_URL, "smb: no share is a malformed URL" },
    { "smb://server.example", TWIST_ERR_URL, "smb: no path is a malformed URL" },
    { "smb://server.example//file", TWIST_ERR_URL, "smb: an empty share is a malformed URL" },
    { "smb://server.example/sh%00are/f", TWIST_ERR_URL, "smb: a NUL in the share is malformed" },
    { "smb://server.example/share/f%00x", TWIST_ERR_URL, "smb: a NUL in the path is malformed" },
    { "smb://server.example/share/f:stream", TWIST_ERR_URL, "smb: a colon in the path is malformed" },
    { "smb://server.example/share/f%3Astream", TWIST_ERR_URL, "smb: an encoded colon is too" }
  };
  size_t i;
  struct scen sc = plain_scen ();

  for (i = 0; i < sizeof v / sizeof v[0]; i++)
    {
      struct tx *z = begin (v[i].url, "Domain\\User", sc);

      launch (z);
      check (z->t->done && z->t->result == v[i].err, v[i].what);
      check (z->qtail == 0, "smb: and nothing was sent");
      finish (z);
    }
  {
    struct tx *z = begin ("smb://server.example/sh%61re/d%69r/f%20x.bin", "Domain\\User", sc);

    launch (z);
    check (z->t->done && strcmp (z->name, "dir\\f x.bin") == 0,
           "smb: the path is percent-decoded");
    finish (z);
  }
}

static void
test_pause (void)
{
  struct tx *z;
  struct scen sc = plain_scen ();
  unsigned reads_at_pause;

  /* A file of sixteen chunks: eight reads fit in the window.  */
  sc.size = 1000000;
  z = begin (URL, "Domain\\User", sc);
  z->pause_once = 1;
  launch (z);
  check (z->paused_seen && !z->t->done && z->t->sink_paused,
         "smb: a full callback pauses the transfer");
  reads_at_pause = z->reads;
  check (reads_at_pause == 8, "smb: with the window of eight reads in hand and no more");
  serve (z);
  check (z->reads == reads_at_pause && !z->t->done,
         "smb: nothing more is asked for while it is paused");
  twist_transfer_resume (z->t);
  serve (z);
  check (z->reads > reads_at_pause && z->t->done && z->t->result == TWIST_OK
         && same (z, 0, 1000000),
         "smb: it goes on when resumed, and every byte arrives in order");
  finish (z);
}


/* ---- Uploads ---- */

static const uint8_t *push_src;
static size_t push_len, push_pos;
static int push_ended;

/* Push what is left of the source in pieces of PIECE bytes, as far as the
   transfer takes it, and end it when it is all pushed.  */
static void
push_more (struct tx *z, size_t piece)
{
  while (push_pos < push_len)
    {
      size_t n = push_len - push_pos < piece ? push_len - push_pos : piece;
      size_t taken = 0;
      int rc = twist_transfer_upload_push (z->t, push_src + push_pos, n, &taken);

      push_pos += taken;
      if (rc != TWIST_OK || taken < n)
        return;
    }
  if (!push_ended)
    {
      push_ended = 1;
      twist_transfer_upload_end (z->t, TWIST_OK);
    }
}

static struct tx *
begin_put (const char *url, struct scen sc, const uint8_t *data, size_t n)
{
  struct tx *z = begin (url, "Domain\\User", sc);

  push_src = data;
  push_len = n;
  push_pos = 0;
  push_ended = 0;
  twist_transfer_setopt (z->t, TWISTOPT_UPLOAD_PUSH, 1L);
  return z;
}

/* Run an upload to its end, pushing PIECE bytes at a time.  */
static void
run_put (struct tx *z, size_t piece)
{
  int idle = 0;
  unsigned iter;

  if (z->x == NULL)
    launch (z);
  for (iter = 0; iter < 400000 && !z->t->done && idle < 4; iter++)
    {
      size_t before = push_pos;

      push_more (z, piece);
      serve (z);
      idle = push_pos == before && z->qhead == z->qtail && !push_ended
        ? idle + 1 : 0;
    }
}

static uint8_t *
pattern (size_t n)
{
  uint8_t *d = malloc (n);
  size_t i;

  for (i = 0; i < n; i++)
    d[i] = (uint8_t) (i * 31 + i / 13);
  return d;
}

#define PURL "smb://server.example/share/dir/up.bin"

static void
test_upload (void)
{
  struct scen sc = plain_scen ();
  struct tx *z;
  uint8_t *data = pattern (150000);
  size_t pieces[] = { 1, 100000 }, k;

  for (k = 0; k < 2; k++)
    {
      z = begin_put (PURL, sc, data, 150000);
      run_put (z, pieces[k]);
      check (z->t->done && z->t->result == TWIST_OK, "smb: an upload ends well");
      check (z->store_len == 150000 && memcmp (z->store, data, 150000) == 0,
             "smb: and the file is what was sent");
      check (z->disposition == 5, "smb: the file is created, or replaced");
      check (z->t->progress.uploaded == 150000,
             "smb: the meter counts what the server wrote");
      check (z->cmds[0] == 'O' && strcmp (z->cmds + strlen (z->cmds) - 3, "CDL") == 0
             && strchr (z->cmds, 'R') == NULL,
             "smb: CREATE, the writes, CLOSE, TREE_DISCONNECT and LOGOFF");
      check (z->max_write_len <= 65536 && z->writes <= 24,
             "smb: writes are gathered, not one for each byte of the source");
      finish (z);
    }
  /* A file that is there is replaced, not added to.  */
  z = begin_put (PURL, sc, data, 1000);
  z->store_exists = 1;
  z->store_len = 5000;
  memset (z->store, 0xee, 5000);
  run_put (z, 777);
  check (z->t->done && z->t->result == TWIST_OK && z->store_len == 1000
         && memcmp (z->store, data, 1000) == 0,
         "smb: a file that is there is replaced");
  finish (z);
  /* An empty file.  */
  z = begin_put (PURL, sc, data, 0);
  run_put (z, 10);
  check (z->t->done && z->t->result == TWIST_OK && z->store_exists
         && z->store_len == 0 && z->writes == 0,
         "smb: an upload of nothing makes an empty file");
  finish (z);
  /* The data of a POST.  */
  z = begin (PURL, "Domain\\User", sc);
  twist_transfer_setopt (z->t, TWISTOPT_POSTFIELDS, "hello, smb");
  launch (z);
  check (z->t->done && z->t->result == TWIST_OK && z->store_len == 10
         && memcmp (z->store, "hello, smb", 10) == 0,
         "smb: data given whole is uploaded too");
  finish (z);
  free (data);
}

static void
test_append (void)
{
  struct scen sc = plain_scen ();
  struct tx *z;
  uint8_t *data = pattern (30000);

  z = begin_put (PURL, sc, data, 30000);
  twist_transfer_setopt (z->t, TWISTOPT_APPEND, 1L);
  z->store_exists = 1;
  z->store_len = 1000;
  memset (z->store, 0xaa, 1000);
  run_put (z, 4096);
  check (z->t->done && z->t->result == TWIST_OK && z->disposition == 3,
         "smb: -a opens the file without replacing it");
  check (z->store_len == 31000 && z->store[999] == 0xaa
         && memcmp (z->store + 1000, data, 30000) == 0,
         "smb: and writes at the end of what is there");
  finish (z);
  z = begin_put (PURL, sc, data, 100);
  twist_transfer_setopt (z->t, TWISTOPT_APPEND, 1L);
  run_put (z, 100);
  check (z->t->done && z->t->result == TWIST_OK && z->store_len == 100
         && memcmp (z->store, data, 100) == 0,
         "smb: -a makes the file if it is not there");
  finish (z);
  free (data);
}

static void
test_dirs (void)
{
  struct scen sc = plain_scen ();
  struct tx *z;
  uint8_t *data = pattern (500);

  sc.strict_dirs = 1;
  z = begin_put ("smb://server.example/share/a/b/c.bin", sc, data, 500);
  twist_transfer_setopt (z->t, TWISTOPT_CREATE_MISSING_DIRS, 1L);
  run_put (z, 500);
  check (z->t->done && z->t->result == TWIST_OK && z->store_len == 500
         && strcmp (z->dirs, "a;a\\b;") == 0,
         "smb: --ftp-create-dirs makes the directories, outermost first");
  check (strncmp (z->cmds, "MCMCO", 5) == 0,
         "smb: each is opened and the file after them");
  finish (z);
  z = begin_put ("smb://server.example/share/a/b/c.bin", sc, data, 500);
  run_put (z, 500);
  check (z->t->done && z->t->result == TWIST_ERR_FILE && z->t->proto_status == 25,
         "smb: without it, a missing directory is an upload failure (25)");
  finish (z);
  free (data);
}

static void
test_stall (void)
{
  struct scen sc = plain_scen ();
  struct tx *z;
  uint8_t *data = pattern (120000);
  size_t before;

  z = begin_put (PURL, sc, data, 120000);
  z->stalled = 1;
  launch (z);
  {
    int i;

    for (i = 0; i < 40; i++)
      {
        push_more (z, 1000);
        serve (z);
      }
  }
  check (strchr (z->cmds, 'W') == NULL && !z->t->done,
         "smb: a connection that is full is sent no write");
  check (push_pos > 30000 && push_pos < 70000,
         "smb: and the source is held back after about what fits in a write");
  before = push_pos;
  {
    int i;

    for (i = 0; i < 5; i++)
      {
        push_more (z, 1000);
        serve (z);
      }
  }
  check (push_pos == before, "smb: it takes no more while it waits");
  z->stalled = 0;
  twist_smb_drained (z->x);
  run_put (z, 1000);
  check (z->t->done && z->t->result == TWIST_OK && z->store_len == 120000
         && memcmp (z->store, data, 120000) == 0,
         "smb: it goes on when the connection has room, and every byte arrives");
  finish (z);
  free (data);
}

static void
test_put_failures (void)
{
  struct scen sc = plain_scen ();
  struct tx *z;
  uint8_t *data = pattern (1000);

  sc.write_status = 0xC000007Fu;
  z = begin_put (PURL, sc, data, 1000);
  run_put (z, 1000);
  check (z->t->done && z->t->result == TWIST_ERR_FILE && z->t->proto_status == 25,
         "smb: a disk that is full is an upload failure (25)");
  finish (z);
  sc = plain_scen ();
  sc.create_status = 0xC0000022u;
  z = begin_put (PURL, sc, data, 1000);
  run_put (z, 1000);
  check (z->t->done && z->t->proto_status == 9,
         "smb: a file the user may not write is exit 9");
  finish (z);
  sc = plain_scen ();
  sc.short_write = 1;
  z = begin_put (PURL, sc, data, 1000);
  run_put (z, 1000);
  check (z->t->done && z->t->result == TWIST_ERR_PARTIAL,
         "smb: a server that writes less than it was sent is not followed");
  finish (z);
  sc = plain_scen ();
  z = begin_put (PURL, sc, data, 1000);
  launch (z);
  twist_transfer_upload_push (z->t, data, 500, &(size_t) { 0 });
  twist_transfer_upload_end (z->t, TWIST_ERR_ABORTED);
  serve (z);
  push_more (z, 10);
  serve (z);
  check (z->t->done && z->t->result == TWIST_ERR_ABORTED,
         "smb: a source that fails fails the transfer");
  finish (z);
  z = begin_put ("smb://server.example/share/dir/", sc, data, 1000);
  launch (z);
  check (z->t->done && z->t->result == TWIST_ERR_URL && z->qtail == 0,
         "smb: an upload to a directory is a malformed URL");
  finish (z);
  z = begin_put (PURL, sc, data, 1000);
  twist_transfer_setopt (z->t, TWISTOPT_RANGE, "1-2");
  launch (z);
  check (z->t->done && z->t->result == TWIST_ERR_INVAL,
         "smb: a range does not apply to an upload");
  finish (z);
  free (data);
}


/* ---- Listings ---- */

static void
add_ent (struct tx *z, const char *ascii, uint32_t attrs, uint64_t size,
         uint64_t mtime)
{
  unsigned i, n = z->nents++;

  for (i = 0; ascii[i] != 0; i++)
    z->ents[n].name[i] = (uint8_t) ascii[i];
  z->ents[n].nlen = i;
  z->ents[n].attrs = attrs;
  z->ents[n].size = size;
  z->ents[n].mtime = mtime;
}

static void
add_raw (struct tx *z, const uint16_t *units, unsigned n, uint32_t attrs,
         uint64_t size, uint64_t mtime)
{
  unsigned k = z->nents++, i;

  for (i = 0; i < n; i++)
    z->ents[k].name[i] = units[i];
  z->ents[k].nlen = n;
  z->ents[k].attrs = attrs;
  z->ents[k].size = size;
  z->ents[k].mtime = mtime;
}

#define FT_2001 126256467060000000ull
#define FT_1999 125911583400000000ull
#define FT_RECENT 134116128000000000ull
#define NOW 1767225600

static void
fill_dir (struct tx *z)
{
  static const uint16_t cafe[] = { 'c', 'a', 'f', 0xe9, ' ', 0xd83d, 0xde00 };
  static const uint16_t evil[] = { 'e', 'v', '\n', 'i', 'l' };

  add_ent (z, "report.txt", 0x20, 1234, FT_2001);
  add_ent (z, "photos", 0x10, 0, FT_1999);
  add_ent (z, "locked.doc", 0x21, 99999999, FT_2001);
  add_raw (z, cafe, 7, 0x20, 5, FT_2001);
  add_raw (z, evil, 5, 0x20, 7, FT_2001);
  z->page = 2;
}

static const char long_listing[] =
  "-rw-r--r--   1 -        -            1234 Feb  3  2001 report.txt\n"
  "drwxr-xr-x   1 -        -               0 Dec 31  1999 photos\n"
  "-r--r--r--   1 -        -        99999999 Feb  3  2001 locked.doc\n"
  "-rw-r--r--   1 -        -               5 Feb  3  2001 caf\xc3\xa9 \xf0\x9f\x98\x80\n"
  "-rw-r--r--   1 -        -               7 Feb  3  2001 ev?il\n";

static const char name_listing[] =
  "report.txt\nphotos\nlocked.doc\ncaf\xc3\xa9 \xf0\x9f\x98\x80\nev?il\n";

static int
out_is (const struct tx *z, const char *want)
{
  return z->out_n == strlen (want) && memcmp (z->out, want, z->out_n) == 0;
}

static void
test_listing (void)
{
  struct scen sc = plain_scen ();
  struct tx *z;
  size_t pieces[] = { 1 << 20, 997 }, k;

  twist_smb_set_test_now (NOW);
  for (k = 0; k < 2; k++)
    {
      z = begin ("smb://server.example/share/dir/", "Domain\\User", sc);
      fill_dir (z);
      z->piece = pieces[k];
      launch (z);
      check (z->t->done && z->t->result == TWIST_OK, "smb: a listing ends well");
      check (out_is (z, long_listing), "smb: the entries are lines of the long form");
      check (strcmp (z->name, "dir") == 0 && z->restart_first,
             "smb: the directory is named without its slash, and the scan restarted");
      check (z->queries == 4, "smb: three answers of two, two and one, and the end");
      check (strlen (z->cmds) > 4 && strncmp (z->cmds, "MQQQQ", 5) == 0
             && strcmp (z->cmds + strlen (z->cmds) - 3, "CDL") == 0,
             "smb: opened, queried until no more files, then closed");
      check (z->t->progress.downloaded == (long long) strlen (long_listing),
             "smb: and the meter counts what was written");
      finish (z);
    }
  z = begin ("smb://server.example/share/dir", "Domain\\User", sc);
  fill_dir (z);
  twist_transfer_setopt (z->t, TWISTOPT_DIRLISTONLY, 1L);
  launch (z);
  check (z->t->done && z->t->result == TWIST_OK && out_is (z, name_listing),
         "smb: -l writes the names, one to a line, for a path with no slash");
  finish (z);
  z = begin ("smb://server.example/share/dir/", "Domain\\User", sc);
  add_ent (z, "recent.txt", 0x20, 10, FT_RECENT);
  z->page = 4;
  launch (z);
  check (out_is (z, "-rw-r--r--   1 -        -              10 Dec 31 00:00 recent.txt\n"),
         "smb: a recent time is shown as the time of day");
  finish (z);
  z = begin ("smb://server.example/share", "Domain\\User", sc);
  fill_dir (z);
  launch (z);
  check (z->t->done && z->t->result == TWIST_OK && z->name[0] == 0
         && out_is (z, long_listing), "smb: the share alone is listed from its root");
  finish (z);
  /* Nothing in it.  */
  z = begin ("smb://server.example/share/dir/", "Domain\\User", sc);
  z->page = 3;
  launch (z);
  check (z->t->done && z->t->result == TWIST_OK && z->out_n == 0 && z->queries == 1,
         "smb: an empty directory is an empty listing");
  finish (z);
  z = begin ("smb://server.example/share/dir/", "Domain\\User", sc);
  z->empty_nosuch = 1;
  launch (z);
  check (z->t->done && z->t->result == TWIST_OK && z->out_n == 0,
         "smb: so is one the server says has no such file in");
  finish (z);
  /* A name that is not UTF-16.  */
  {
    static const uint16_t bad[] = { 'a', 0xd800, 'b' };
    static const uint16_t bad2[] = { 'a', 0xdc00 };

    z = begin ("smb://server.example/share/dir/", "Domain\\User", sc);
    add_raw (z, bad, 3, 0x20, 1, FT_2001);
    z->page = 2;
    launch (z);
    check (z->t->done && z->t->result == TWIST_ERR_PROTOCOL && z->out_n == 0,
           "smb: a name with an unpaired high surrogate is a protocol error");
    finish (z);
    z = begin ("smb://server.example/share/dir/", "Domain\\User", sc);
    add_raw (z, bad2, 2, 0x20, 1, FT_2001);
    z->page = 2;
    launch (z);
    check (z->t->done && z->t->result == TWIST_ERR_PROTOCOL,
           "smb: so is one with a low surrogate on its own");
    finish (z);
  }
  /* A directory that is not there.  */
  sc.create_status = 0xC0000034u;
  z = begin ("smb://server.example/share/nope/", "Domain\\User", sc);
  launch (z);
  check (z->t->done && z->t->result == TWIST_ERR_FILE && z->t->proto_status == 78,
         "smb: a directory that is not there is exit 78");
  finish (z);
  sc = plain_scen ();
  z = begin ("smb://server.example/share/dir/", "Domain\\User", sc);
  twist_transfer_setopt (z->t, TWISTOPT_RANGE, "1-2");
  launch (z);
  check (z->t->done && z->t->result == TWIST_ERR_INVAL,
         "smb: a range does not apply to a listing");
  finish (z);
  twist_smb_set_test_now (0);
}

static void
test_listing_pause (void)
{
  struct scen sc = plain_scen ();
  struct tx *z;

  twist_smb_set_test_now (NOW);
  z = begin ("smb://server.example/share/dir/", "Domain\\User", sc);
  fill_dir (z);
  z->pause_once = 1;
  launch (z);
  check (z->paused_seen && !z->t->done && z->queries == 1,
         "smb: a full callback holds the next QUERY_DIRECTORY back");
  serve (z);
  check (z->queries == 1, "smb: and nothing more is asked while it waits");
  twist_transfer_resume (z->t);
  serve (z);
  check (z->t->done && z->t->result == TWIST_OK && out_is (z, long_listing),
         "smb: it goes on when resumed, and every line is there, in order");
  finish (z);
  twist_smb_set_test_now (0);
}

int
main (void)
{
  test_download ();
  test_ranges ();
  test_failures ();
  test_urls ();
  test_pause ();
  test_upload ();
  test_append ();
  test_dirs ();
  test_stall ();
  test_put_failures ();
  test_listing ();
  test_listing_pause ();
  return tests_finish ();
}
