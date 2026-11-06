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

/* smb:// as a download, against the scripted server of smbsrv.c: a whole
   login, then the file as the handler asks for it.  The server can answer
   as a real one does not always: with less than was asked, with answers out
   of order, with an error for the file or the share.  */

#define FILE_SIZE 150000u
#define FILE_MAX (1u << 20)

struct scen
{
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
        uint32_t opts = plain.b[64 + 40] | (plain.b[64 + 41] << 8);

        for (i = 0; i < nl / 2 && i + 1 < sizeof name; i++)
          name[i] = (char) plain.b[off + 2 * i];
        name[i] = 0;
        snprintf (z->name, sizeof z->name, "%s", name);
        note (z, 'O');
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
        p64 (&r, z->sc.size);
        p64 (&r, z->sc.size);
        p32 (&r, 0x20);
        p32 (&r, 0);
        for (i = 0; i < 16; i++)
          p8 (&r, 0xc0 + i);
        p32 (&r, 0);
        p32 (&r, 0);
        (void) opts;
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
  twist_smb_test_seam (z->x, to_server, z);
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
    { "smb://server.example/share/f%3Astream", TWIST_ERR_URL, "smb: an encoded colon is too" },
    { "smb://server.example/share/", TWIST_ERR_UNSUPPORTED, "smb: a directory is another issue" },
    { "smb://server.example/share", TWIST_ERR_UNSUPPORTED, "smb: so is the share itself" }
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

int
main (void)
{
  test_download ();
  test_ranges ();
  test_failures ();
  test_urls ();
  test_pause ();
  return tests_finish ();
}
