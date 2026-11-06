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

#include <quickstep/crypto.h>
#include <quickstep/status.h>

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* The SMB 3.1.1 session layer, against a server written here: it reads what
   the client sends, keeps the pre-authentication hash itself, derives the same
   keys, signs the last SESSION_SETUP response, and encrypts its answers.  The
   SPNEGO tokens are the ones of test-spnego, whose NTLM values the random hook
   fixes, so the session key is known to both ends.  Then each way a server
   can break the profile is tried.  */

static const char hex_cli2[] =
    "a182014b30820147a0030a0101a282012a048201264e544c4d53535000030000"
    "00180018006c00000092009200840000000c000c005800000008000800640000"
    "00000000006c000000100010001601000015028862000000000000000f6c6b23"
    "556cf5b10c5db06e0e39be147f44006f006d00610069006e0055007300650072"
    "00000000000000000000000000000000000000000000000000af266edc3a241c"
    "e8fc95c4d4bb78cf7801010000000000000011223344556677aaaaaaaaaaaaaa"
    "aa0000000002000c0044004f004d00410049004e0001000c0053004500520056"
    "0045005200070008000011223344556677060004000200000009002600630069"
    "00660073002f007300650072007600650072002e006500780061006d0070006c"
    "00650000000000000000006b5baf876b39edafc7e6588026d6d748a312041001"
    "00000022a3984fefbb9c3200000000";
static const char hex_init[] =
    "604806062b0601050502a03e303ca00e300c060a2b06010401823702020aa22a"
    "04284e544c4d5353500001000000150288620000000028000000000000002800"
    "0000000000000000000f";


struct env
{
  struct twist_smb_session *s;
  uint8_t frames[16][16384];
  size_t flen[16];
  int nframes, taken;
  int failures, err, established;
  uint32_t tree;
  struct smbsrv srv;
  int calls;
  /* What the upper layer saw.  */
  char log[1024];
  uint8_t data[4096];
  size_t data_n, take;
};

static int
rnd_fill (void *u, void *buf, size_t len)
{
  struct env *e = u;
  int call = ++e->calls;
  size_t i;

  for (i = 0; i < len; i++)
    ((uint8_t *) buf)[i] = call == 1 ? 0x11 : call == 2 ? 0x22
      : call == 3 ? (uint8_t) (i + 1) : call == 4 ? 0xaa : 0x55;
  return 0;
}

static int
ops_send (void *u, const uint8_t *d, size_t n)
{
  struct env *e = u;

  memcpy (e->frames[e->nframes], d, n);
  e->flen[e->nframes++] = n;
  return TWIST_OK;
}

static void
ops_established (void *u, uint32_t tree)
{
  struct env *e = u;

  e->established++;
  e->tree = tree;
}

static void
ops_failure (void *u, int err)
{
  struct env *e = u;

  e->failures++;
  e->err = err;
}

#define LOG(e, ...) \
  do \
    { \
      size_t n_ = strlen ((e)->log); \
      snprintf ((e)->log + n_, sizeof (e)->log - n_, __VA_ARGS__); \
    } \
  while (0)

static int
up_read (void *u, uint32_t len, uint32_t rem)
{
  LOG ((struct env *) u, "read(%u,%u) ", len, rem);
  return TWIST_OK;
}

static size_t
up_data (void *u, enum twist_smb_data kind, const uint8_t *p, size_t n)
{
  struct env *e = u;

  (void) kind;
  if (e->take != 0 && n > e->take)
    n = e->take;
  memcpy (e->data + e->data_n, p, n);
  e->data_n += n;
  return n;
}

static int
up_end (void *u, uint64_t off)
{
  (void) off;
  LOG ((struct env *) u, "end ");
  return TWIST_OK;
}

static void env_give (void *u, const uint8_t *m, size_t n);

static struct env *
setup (struct srv_opts o)
{
  static struct twist_smb_session_ops ops;
  static struct twist_smb_events up;
  struct twist_smb_session_config cfg;
  static struct twist_ntlm_rand rnd;
  struct env *e = calloc (1, sizeof *e);

  rnd.fill = rnd_fill;
  rnd.user = e;
  ops.user = e;
  ops.send = ops_send;
  ops.established = ops_established;
  ops.failure = ops_failure;
  memset (&up, 0, sizeof up);
  up.user = e;
  up.read = up_read;
  up.data = up_data;
  up.message_end = up_end;
  memset (&cfg, 0, sizeof cfg);
  cfg.domain = "Domain";
  cfg.user = "User";
  cfg.password = "Password";
  cfg.host = "server.example";
  cfg.share = "share";
  cfg.rnd = &rnd;
  e->s = twist_smb_session_new (&cfg, &ops, &up);
  srv_init (&e->srv, o, env_give, e);
  return e;
}

/* Frame a message and give it to the session, in pieces of PIECE bytes.  */
static size_t piece = 100000;

static size_t
give (struct env *e, const uint8_t *m, size_t n)
{
  uint8_t *f = malloc (n + 4);
  size_t off = 0, used, stuck = 0;

  f[0] = 0;
  f[1] = (uint8_t) (n >> 16);
  f[2] = (uint8_t) (n >> 8);
  f[3] = (uint8_t) n;
  memcpy (f + 4, m, n);
  while (off < n + 4 && stuck < 3)
    {
      size_t c = n + 4 - off < piece ? n + 4 - off : piece;

      used = twist_smb_session_receive (e->s, f + off, c);
      off += used;
      stuck = used == 0 ? stuck + 1 : 0;
    }
  free (f);
  return off;
}

/* A message of the server's, with its framing, to the session.  */
static void
env_give (void *u, const uint8_t *m, size_t n)
{
  give (u, m, n);
}

static const uint8_t *
last_frame (struct env *e, size_t *n)
{
  *n = e->flen[e->nframes - 1];
  return e->frames[e->nframes - 1];
}

/* The whole login, up to the last thing the server says before the tree.  */
static void
login (struct env *e)
{
  size_t n;
  const uint8_t *f;

  twist_smb_session_start (e->s);
  f = last_frame (e, &n);
  srv_negotiate (&e->srv, f, n);
  if (e->failures)
    return;
  f = last_frame (e, &n);
  srv_setup1 (&e->srv, f, n);
  if (e->failures)
    return;
  f = last_frame (e, &n);
  srv_setup2 (&e->srv, f, n);
  if (e->failures)
    return;
  f = last_frame (e, &n);
  if (srv_tree (&e->srv, f, n, 5) != 0)
    check (0, "session: the TREE_CONNECT request opens and is a TREE_CONNECT");
}

static void
done (struct env *e)
{
  twist_smb_session_free (e->s);
  free (e);
}

/* ---- Tests ---- */

static void
check_login (const char *what, struct env *e)
{
  char label[200];
  const uint8_t *f;
  uint8_t blob[4096], want[4096];
  size_t n, bl, wl;

  if (e->failures != 0 || e->established != 1)
    fprintf (stderr, "  %s: failures %d err %d established %d frames %d\n", what,
             e->failures, e->err, e->established, e->nframes);
  snprintf (label, sizeof label, "session: %s: the tree is connected", what);
  check (e->failures == 0 && e->established == 1 && e->tree == 5, label);
  snprintf (label, sizeof label, "session: %s: four frames were sent", what);
  check (e->nframes == 4, label);
  if (e->nframes < 4)
    return;
  f = e->frames[0];
  snprintf (label, sizeof label, "session: %s: NEGOTIATE first, in the clear", what);
  check (f[4] == 0xfe && f[4 + 12] == 0 && e->flen[0] > 100, label);
  f = e->frames[1];
  wl = unhex (hex_init, want);
  bl = f[4 + 64 + 14] | (f[4 + 64 + 15] << 8);
  memcpy (blob, f + 4 + 88, bl);
  snprintf (label, sizeof label, "session: %s: SESSION_SETUP carries the NegTokenInit", what);
  check (f[4 + 12] == 1 && bl == wl && memcmp (blob, want, wl) == 0, label);
  f = e->frames[2];
  wl = unhex (hex_cli2, want);
  bl = f[4 + 64 + 14] | (f[4 + 64 + 15] << 8);
  snprintf (label, sizeof label, "session: %s: the second SESSION_SETUP carries the AUTHENTICATE", what);
  check (bl == wl && memcmp (f + 4 + 88, want, wl) == 0
         && f[4 + 40] == 0x88 && f[4 + 47] == 0x11, label);
  f = last_frame (e, &n);
  (void) f;
  snprintf (label, sizeof label, "session: %s: the TREE_CONNECT is a transform", what);
  check (e->frames[3][4] == 0xfd && e->flen[3] > 52, label);
}

static void
test_good (const char *what, struct srv_opts o, size_t pc)
{
  struct env *e;
  struct msg m, r;
  struct twist_smb_req h;
  const struct twist_smb_session_info *info;
  uint8_t fid[16] = { 0 }, out[256];
  size_t n, i;
  char label[200];

  piece = pc;
  e = setup (o);
  login (e);
  check_login (what, e);
  info = twist_smb_session_info (e->s);
  snprintf (label, sizeof label, "session: %s: the negotiated profile", what);
  check (info->cipher == o.cipher && info->session_id == SESSION_ID
         && info->tree_id == 5 && info->max_read == 65536
         && info->max_write == 65536 && info->max_transact == 65536
         && info->signing == (o.signing == 0xffff ? TWIST_SMB_SIGN_AES_CMAC : o.signing),
         label);
  /* A request, sealed; the server reads it, and answers, sealed.  */
  snprintf (label, sizeof label, "session: %s: a request gets an id and costs a credit", what);
  i = twist_smb_session_credits (e->s);
  check (twist_smb_session_request (e->s, 1, &h) == TWIST_OK
         && h.message_id == 4 && h.session_id == SESSION_ID && h.tree_id == 5
         && twist_smb_session_credits (e->s) == i - 1, label);
  twist_smb_w_read (out, sizeof out, &n, &h, fid, 20, 0);
  check (twist_smb_session_send (e->s, out, n, NULL, 0) == TWIST_OK
         && e->nframes == 5 && e->frames[4][4] == 0xfd,
         "session: a READ is sent as a transform");
  check (srv_open (&e->srv, e->frames[4], e->flen[4], &m) == 0 && m.b[12] == 8
         && m.n == 64 + 48 + 1, "session: and the server opens it");
  header (&r, 8, 0, 0, 4, SESSION_ID, 5);
  p16 (&r, 17);
  p8 (&r, 0x50);
  p8 (&r, 0);
  p32 (&r, 20);
  p32 (&r, 0);
  p32 (&r, 0);
  for (i = 0; i < 20; i++)
    p8 (&r, (unsigned) i);
  srv_seal (&e->srv, &r);
  snprintf (label, sizeof label, "session: %s: the response reaches the caller", what);
  check (e->failures == 0 && e->data_n == 20 && strcmp (e->log, "read(20,0) end ") == 0,
         label);
  /* The same id again was not asked for.  */
  srv_seal (&e->srv, &r);
  snprintf (label, sizeof label, "session: %s: an answer to nothing outstanding is refused", what);
  check (e->failures == 1 && e->err == TWIST_ERR_PROTOCOL, label);
  done (e);
  piece = 100000;
}

/* A server that breaks the profile at one point.  */
static void
test_refused (const char *what, struct srv_opts o, int err)
{
  struct env *e = setup (o);
  char label[200];

  login (e);
  snprintf (label, sizeof label, "session: %s is refused (%d)", what, err);
  check (e->failures == 1 && e->err == err && e->established == 0, label);
  if (e->failures != 1)
    fprintf (stderr, "  %s: failures %d err %d established %d frames %d\n", what,
             e->failures, e->err, e->established, e->nframes);
  /* Nothing after the failure is read, and the keys are gone.  */
  check (twist_smb_session_receive (e->s, (const uint8_t *) "\0\0\0\1x", 5) == 5
         && e->failures == 1, "session: and nothing after a refusal is read");
  done (e);
}

static void
test_backpressure (void)
{
  struct env *e = setup (srv_good ());
  struct msg r;
  struct twist_smb_req h;
  uint8_t out[256], fid[16] = { 0 };
  size_t n, i;
  int rounds = 0;

  login (e);
  twist_smb_session_request (e->s, 1, &h);
  twist_smb_w_read (out, sizeof out, &n, &h, fid, 20, 0);
  twist_smb_session_send (e->s, out, n, NULL, 0);
  e->take = 6;
  header (&r, 8, 0, 0, 4, SESSION_ID, 5);
  p16 (&r, 17);
  p8 (&r, 0x50);
  p8 (&r, 0);
  p32 (&r, 20);
  p32 (&r, 0);
  p32 (&r, 0);
  for (i = 0; i < 20; i++)
    p8 (&r, (unsigned) i);
  srv_seal (&e->srv, &r);
  check (e->data_n == 6 && e->failures == 0, "session: a consumer that takes 6 bytes gets 6");
  check (twist_smb_session_receive (e->s, (const uint8_t *) "\0\0\0\1x", 5) == 0,
         "session: and the session reads nothing more while it waits");
  while (e->data_n < 20 && rounds++ < 10)
    twist_smb_session_resume (e->s);
  check (e->data_n == 20 && strstr (e->log, "end") != NULL && e->failures == 0,
         "session: and resumes where it stopped");
  for (i = 0; i < 20; i++)
    if (e->data[i] != i)
      break;
  check (i == 20, "session: with the bytes in order");
  done (e);
}

int
main (void)
{
  struct srv_opts o;
  size_t pieces[] = { 100000, 1, 7 }, i;

  for (i = 0; i < 3; i++)
    {
      char w[64];

      snprintf (w, sizeof w, "AES-128-GCM, CMAC (pieces of %zu)", pieces[i]);
      test_good (w, srv_good (), pieces[i]);
    }
  o = srv_good ();
  o.cipher = TWIST_SMB_CIPHER_AES256_GCM;
  o.signing = TWIST_SMB_SIGN_AES_GMAC;
  test_good ("AES-256-GCM, GMAC", o, 100000);
  o = srv_good ();
  o.signing = TWIST_SMB_SIGN_AES_GMAC;
  test_good ("AES-128-GCM, GMAC", o, 13);
  o = srv_good ();
  o.signing = 0xffff;
  test_good ("no signing context, so CMAC", o, 100000);
  test_backpressure ();

  o = srv_good ();
  o.dialect = 0x302;
  test_refused ("an older dialect", o, TWIST_ERR_PROTOCOL);
  o = srv_good ();
  o.cipher = TWIST_SMB_CIPHER_AES128_CCM;
  test_refused ("AES-128-CCM", o, TWIST_ERR_PROTOCOL);
  o = srv_good ();
  o.cipher = TWIST_SMB_CIPHER_AES256_CCM;
  test_refused ("a cipher that was not offered", o, TWIST_ERR_PROTOCOL);
  o = srv_good ();
  o.cipher = 0;
  test_refused ("a server with no encryption context", o, TWIST_ERR_PROTOCOL);
  o = srv_good ();
  o.mode = 0;
  test_refused ("a server that cannot sign", o, TWIST_ERR_PROTOCOL);
  o = srv_good ();
  o.compression = 1;
  test_refused ("a compression context", o, TWIST_ERR_PROTOCOL);
  o = srv_good ();
  o.hash = 0;
  test_refused ("no pre-authentication context", o, TWIST_ERR_PROTOCOL);
  o = srv_good ();
  o.hash = 2;
  test_refused ("a hash other than SHA-512", o, TWIST_ERR_PROTOCOL);
  o = srv_good ();
  o.two_hashes = 1;
  test_refused ("two pre-authentication hashes", o, TWIST_ERR_PROTOCOL);
  o = srv_good ();
  o.signing = TWIST_SMB_SIGN_HMAC_SHA256;
  test_refused ("HMAC-SHA256 signing, which was not offered", o, TWIST_ERR_PROTOCOL);
  o = srv_good ();
  o.max_read = 100;
  test_refused ("a read size too small to use", o, TWIST_ERR_PROTOCOL);
  o = srv_good ();
  o.unsigned_final = 1;
  test_refused ("an unsigned final SESSION_SETUP response", o, TWIST_ERR_PROTOCOL);
  o = srv_good ();
  o.bad_final_sig = 1;
  test_refused ("a final SESSION_SETUP response with a bad signature", o, TWIST_ERR_PROTOCOL);
  o = srv_good ();
  o.mitm = 1;
  test_refused ("a NEGOTIATE response changed on the way (the hash differs)", o, TWIST_ERR_PROTOCOL);
  o = srv_good ();
  o.session_flags = 1;
  test_refused ("a guest session", o, TWIST_ERR_AUTH);
  o = srv_good ();
  o.session_flags = 2;
  test_refused ("a null session", o, TWIST_ERR_AUTH);
  o = srv_good ();
  o.login_status = 0xC000006Du;
  test_refused ("a refused login", o, TWIST_ERR_AUTH);
  o = srv_good ();
  o.plain_tree = 1;
  test_refused ("a TREE_CONNECT response that is not encrypted", o, TWIST_ERR_PROTOCOL);
  o = srv_good ();
  o.bad_tag = 1;
  test_refused ("a message with a bad tag", o, TWIST_ERR_PROTOCOL);
  o = srv_good ();
  o.wrong_session = 1;
  test_refused ("a transform for another session", o, TWIST_ERR_PROTOCOL);
  o = srv_good ();
  o.tree_msgid = 9;
  test_refused ("a response with an id that was never sent", o, TWIST_ERR_PROTOCOL);
  {
    /* A nonce twice in a row: the second message.  */
    struct env *e;
    struct msg r;
    struct twist_smb_req h;
    uint8_t out[256], fid[16] = { 0 };
    size_t n;

    o = srv_good ();
    o.repeat_nonce = 1;
    e = setup (o);
    login (e);
    twist_smb_session_request (e->s, 1, &h);
    twist_smb_w_read (out, sizeof out, &n, &h, fid, 0, 0);
    twist_smb_session_send (e->s, out, n, NULL, 0);
    header (&r, 8, 0, 0, 4, SESSION_ID, 5);
    p16 (&r, 17);
    p8 (&r, 0x50);
    p8 (&r, 0);
    p32 (&r, 0);
    p32 (&r, 0);
    p32 (&r, 0);
    check (e->failures == 0 && e->established == 1, "session: first, the login is fine");
    srv_seal (&e->srv, &r);
    check (e->failures == 1 && e->err == TWIST_ERR_PROTOCOL,
           "session: a server nonce equal to the last one is refused");
    done (e);
  }
  return tests_finish ();
}
