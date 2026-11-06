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

static const char hex_srv1[] =
    "a1818e30818ba0030a0101a10c060a2b06010401823702020aa27604744e544c"
    "4d53535000020000000c000c003800000015028a620123456789abcdef000000"
    "000000000030003000440000000a00614a0000000f5300450052005600450052"
    "0002000c0044004f004d00410049004e0001000c005300450052005600450052"
    "0007000800001122334455667700000000";
static const char hex_srv2[] =
    "a11b3019a0030a0100a3120410010000007dd6da05648a73ae00000000";
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

/* ---- Bytes ---- */

struct msg
{
  uint8_t b[16384];
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

#define SESSION_ID 0x1122334455667788ull

/* A response message (no framing).  */
static void
header (struct msg *m, unsigned cmd, uint32_t status, uint32_t flags,
        uint64_t msgid, uint64_t session, uint32_t tree)
{
  m->n = 0;
  pb (m, "\xfe" "SMB", 4);
  p16 (m, 64);
  p16 (m, 1);
  p32 (m, status);
  p16 (m, cmd);
  p16 (m, 31);
  p32 (m, flags | 1);
  p32 (m, 0);
  p64 (m, msgid);
  p32 (m, 0);
  p32 (m, tree);
  p64 (m, session);
  pz (m, 16);
}

/* ---- The server ---- */

struct opts
{
  unsigned dialect;
  unsigned mode;
  unsigned caps;
  unsigned cipher;		/* 0: no encryption context.  */
  unsigned signing;		/* 0xffff: no signing context.  */
  unsigned hash;
  int compression;
  int two_hashes;
  unsigned session_flags;
  int unsigned_final;
  int bad_final_sig;
  int plain_tree;		/* The tree response is not encrypted.  */
  int bad_tag;
  int wrong_session;
  int repeat_nonce;
  uint32_t login_status;	/* Refuse the login with this at the end.  */
  uint32_t max_read;
  uint64_t tree_msgid;
  int mitm;
};

struct env
{
  struct twist_smb_session *s;
  struct opts o;
  uint8_t frames[16][16384];
  size_t flen[16];
  int nframes, taken;
  int failures, err, established;
  uint32_t tree;
  /* The server's side of the keys.  */
  uint8_t hash[64];
  uint8_t sign[16], c2s[32], s2c[32];
  size_t keylen;
  uint64_t nonce;
  uint8_t last_nonce[16];
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

static struct opts
good (void)
{
  struct opts o;

  memset (&o, 0, sizeof o);
  o.dialect = 0x311;
  o.mode = 3;
  o.caps = 0x44;
  o.cipher = TWIST_SMB_CIPHER_AES128_GCM;
  o.signing = TWIST_SMB_SIGN_AES_CMAC;
  o.hash = 1;
  o.max_read = 8 * 1024 * 1024;
  o.tree_msgid = 3;
  return o;
}

static struct env *
setup (struct opts o)
{
  static struct twist_smb_session_ops ops;
  static struct twist_smb_events up;
  struct twist_smb_session_config cfg;
  static struct twist_ntlm_rand rnd;
  struct env *e = calloc (1, sizeof *e);

  e->o = o;
  e->nonce = 0x1000;
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
  return e;
}

static void
hash_in (struct env *e, const uint8_t *m, size_t n)
{
  uint8_t *b = malloc (64 + n);

  memcpy (b, e->hash, 64);
  memcpy (b + 64, m, n);
  twist_sha512 (b, 64 + n, e->hash);
  free (b);
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

static const uint8_t *
last_frame (struct env *e, size_t *n)
{
  *n = e->flen[e->nframes - 1];
  return e->frames[e->nframes - 1];
}

/* The server's NEGOTIATE response, hashed after the client's request.  */
static void
server_negotiate (struct env *e)
{
  struct msg m;
  const struct opts *o = &e->o;
  unsigned nctx = 0;
  size_t i, ctx_at, start;
  size_t n;
  const uint8_t *req = last_frame (e, &n);

  memset (e->hash, 0, 64);
  hash_in (e, req + 4, n - 4);
  header (&m, 0, 0, 0, 0, 0, 0);
  p16 (&m, 65);
  p16 (&m, o->mode);
  p16 (&m, o->dialect);
  nctx = (o->hash != 0) + (o->cipher != 0) + (o->signing != 0xffff)
    + (o->compression != 0);
  p16 (&m, o->dialect == 0x311 ? nctx : 0);
  for (i = 0; i < 16; i++)
    p8 (&m, 0xa0 + i);
  p32 (&m, o->caps);
  p32 (&m, 65536 * 4);
  p32 (&m, o->max_read);
  p32 (&m, 65536 * 4);
  p64 (&m, 1);
  p64 (&m, 2);
  p16 (&m, 128);
  p16 (&m, 4);
  ctx_at = m.n;
  p32 (&m, 0);
  pb (&m, "ABCD", 4);
  pz (&m, 4);
  start = m.n;
  m.b[ctx_at] = (uint8_t) start;
  m.b[ctx_at + 1] = (uint8_t) (start >> 8);
  if (o->hash != 0)
    {
      unsigned algs = o->two_hashes ? 2 : 1;

      p16 (&m, 1);
      p16 (&m, 4 + 2 * algs + 32);
      p32 (&m, 0);
      p16 (&m, algs);
      p16 (&m, 32);
      p16 (&m, o->hash);
      if (o->two_hashes)
        p16 (&m, 2);
      for (i = 0; i < 32; i++)
        p8 (&m, 0x5a);
      while ((m.n - 0) % 8)
        p8 (&m, 0);
    }
  if (o->cipher != 0)
    {
      p16 (&m, 2);
      p16 (&m, 4);
      p32 (&m, 0);
      p16 (&m, 1);
      p16 (&m, o->cipher);
      while (m.n % 8)
        p8 (&m, 0);
    }
  if (o->signing != 0xffff)
    {
      p16 (&m, 8);
      p16 (&m, 4);
      p32 (&m, 0);
      p16 (&m, 1);
      p16 (&m, o->signing);
      while (m.n % 8)
        p8 (&m, 0);
    }
  if (o->compression)
    {
      p16 (&m, 3);
      p16 (&m, 10);
      p32 (&m, 0);
      p16 (&m, 1);
      p16 (&m, 0);
      p32 (&m, 0);
      p16 (&m, 1);
      while (m.n % 8)
        p8 (&m, 0);
    }
  hash_in (e, m.b, m.n);
  if (e->o.mitm)
    m.b[64 + 8] ^= 1;		/* The client is not told what the server hashed.  */
  give (e, m.b, m.n);
}

static void
server_setup1 (struct env *e)
{
  struct msg m;
  uint8_t tok[4096];
  size_t tl = unhex (hex_srv1, tok), n;
  const uint8_t *req = last_frame (e, &n);

  hash_in (e, req + 4, n - 4);
  header (&m, 1, 0xC0000016u, 0, 1, SESSION_ID, 0);
  p16 (&m, 9);
  p16 (&m, 0);
  p16 (&m, 72);
  p16 (&m, (unsigned) tl);
  pb (&m, tok, tl);
  hash_in (e, m.b, m.n);
  give (e, m.b, m.n);
}

static void
derive (struct env *e)
{
  uint8_t sk[16];
  unsigned bits = e->o.cipher == TWIST_SMB_CIPHER_AES256_GCM ? 256 : 128;

  memset (sk, 0x55, 16);
  e->keylen = bits / 8;
  twist_smb_kdf (sk, 16, "SMBSigningKey", 14, e->hash, 64, 128, e->sign);
  twist_smb_kdf (sk, 16, "SMBC2SCipherKey", 16, e->hash, 64, bits, e->c2s);
  twist_smb_kdf (sk, 16, "SMBS2CCipherKey", 16, e->hash, 64, bits, e->s2c);
}

static void
sign_msg (struct env *e, struct msg *m)
{
  uint8_t sig[16];

  memset (m->b + 48, 0, 16);
  if (e->o.signing == TWIST_SMB_SIGN_AES_GMAC)
    {
      uint8_t nonce[12];

      memset (nonce, 0, 12);
      memcpy (nonce, m->b + 24, 8);
      nonce[8] = 1;
      gq_aead_seal (GQ_AEAD_AES_128_GCM, e->sign, 16, nonce, m->b, m->n, NULL,
                    0, sig, 16);
    }
  else
    twist_cmac_aes128 (e->sign, m->b, m->n, sig);
  memcpy (m->b + 48, sig, 16);
}

static void
server_setup2 (struct env *e)
{
  struct msg m;
  uint8_t tok[4096];
  size_t tl = unhex (hex_srv2, tok), n;
  const uint8_t *req = last_frame (e, &n);

  hash_in (e, req + 4, n - 4);
  derive (e);
  header (&m, 1, e->o.login_status, e->o.unsigned_final ? 0 : 8, 2, SESSION_ID, 0);
  if (e->o.login_status != 0)
    {
      p16 (&m, 9);
      p8 (&m, 0);
      p8 (&m, 0);
      p32 (&m, 0);
      p8 (&m, 0);
    }
  else
    {
      p16 (&m, 9);
      p16 (&m, e->o.session_flags);
      p16 (&m, 72);
      p16 (&m, (unsigned) tl);
      pb (&m, tok, tl);
      if (!e->o.unsigned_final)
        sign_msg (e, &m);
      if (e->o.bad_final_sig)
        m.b[50] ^= 1;
    }
  give (e, m.b, m.n);
}

/* A response from the server, encrypted.  */
static void
server_seal (struct env *e, const struct msg *plain)
{
  struct msg f;
  uint8_t *t, nonce[12];
  size_t i;
  enum gq_aead alg = e->o.cipher == TWIST_SMB_CIPHER_AES256_GCM
    ? GQ_AEAD_AES_256_GCM : GQ_AEAD_AES_128_GCM;

  f.n = 0;
  pb (&f, "\xfd" "SMB", 4);
  pz (&f, 16);
  for (i = 0; i < 8; i++)
    p8 (&f, (unsigned) ((e->nonce >> (8 * i)) & 0xff));
  pz (&f, 8);
  p32 (&f, (uint32_t) plain->n);
  p16 (&f, 0);
  p16 (&f, 1);
  p64 (&f, e->o.wrong_session ? 99 : SESSION_ID);
  t = f.b;
  if (e->o.repeat_nonce && e->nonce != 0x1000)
    memcpy (t + 20, e->last_nonce, 12);
  memcpy (nonce, t + 20, 12);
  memcpy (e->last_nonce, t + 20, 12);
  pb (&f, plain->b, plain->n);
  gq_aead_seal (alg, e->s2c, e->keylen, nonce, t + 20, 32, f.b + 52, plain->n,
                f.b + 52, plain->n + 16);
  memcpy (t + 4, f.b + 52 + plain->n, 16);
  if (e->o.bad_tag)
    t[4] ^= 1;
  e->nonce++;
  give (e, f.b, 52 + plain->n);
}

/* What the client sent, decrypted.  */
static int
client_open (struct env *e, const uint8_t *f, size_t n, struct msg *plain)
{
  uint8_t buf[16384 + 16], nonce[12];
  size_t len = n - 4, orig;
  enum gq_aead alg = e->o.cipher == TWIST_SMB_CIPHER_AES256_GCM
    ? GQ_AEAD_AES_256_GCM : GQ_AEAD_AES_128_GCM;

  if (len < 52 || memcmp (f + 4, "\xfd" "SMB", 4) != 0)
    return -1;
  memcpy (buf, f + 4, len);
  orig = len - 52;
  memcpy (buf + len, buf + 4, 16);
  memcpy (nonce, buf + 20, 12);
  if (gq_aead_open (alg, e->c2s, e->keylen, nonce, buf + 20, 32, buf + 52,
                    orig + 16, buf + 52, orig) != GQ_OK)
    return -1;
  memcpy (plain->b, buf + 52, orig);
  plain->n = orig;
  return 0;
}

static void
server_tree (struct env *e)
{
  struct msg m, plain;
  size_t n;
  const uint8_t *f = last_frame (e, &n);

  if (client_open (e, f, n, &plain) != 0 || plain.b[12] != 3)
    {
      check (0, "session: the TREE_CONNECT request opens and is a TREE_CONNECT");
      return;
    }
  header (&m, 3, 0, 0, e->o.tree_msgid, SESSION_ID, 5);
  p16 (&m, 16);
  p8 (&m, 1);
  p8 (&m, 0);
  p32 (&m, 0x8000);
  p32 (&m, 8);
  p32 (&m, 0x1f01ff);
  if (e->o.plain_tree)
    give (e, m.b, m.n);
  else
    server_seal (e, &m);
}

/* The whole login, up to the last thing the server says before the tree.  */
static void
login (struct env *e)
{
  twist_smb_session_start (e->s);
  server_negotiate (e);
  if (e->failures)
    return;
  server_setup1 (e);
  if (e->failures)
    return;
  server_setup2 (e);
  if (e->failures)
    return;
  server_tree (e);
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
test_good (const char *what, struct opts o, size_t pc)
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
  check (client_open (e, e->frames[4], e->flen[4], &m) == 0 && m.b[12] == 8
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
  server_seal (e, &r);
  snprintf (label, sizeof label, "session: %s: the response reaches the caller", what);
  check (e->failures == 0 && e->data_n == 20 && strcmp (e->log, "read(20,0) end ") == 0,
         label);
  /* The same id again was not asked for.  */
  server_seal (e, &r);
  snprintf (label, sizeof label, "session: %s: an answer to nothing outstanding is refused", what);
  check (e->failures == 1 && e->err == TWIST_ERR_PROTOCOL, label);
  done (e);
  piece = 100000;
}

/* A server that breaks the profile at one point.  */
static void
test_refused (const char *what, struct opts o, int err)
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
  struct env *e = setup (good ());
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
  server_seal (e, &r);
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
  struct opts o;
  size_t pieces[] = { 100000, 1, 7 }, i;

  for (i = 0; i < 3; i++)
    {
      char w[64];

      snprintf (w, sizeof w, "AES-128-GCM, CMAC (pieces of %zu)", pieces[i]);
      test_good (w, good (), pieces[i]);
    }
  o = good ();
  o.cipher = TWIST_SMB_CIPHER_AES256_GCM;
  o.signing = TWIST_SMB_SIGN_AES_GMAC;
  test_good ("AES-256-GCM, GMAC", o, 100000);
  o = good ();
  o.signing = TWIST_SMB_SIGN_AES_GMAC;
  test_good ("AES-128-GCM, GMAC", o, 13);
  o = good ();
  o.signing = 0xffff;
  test_good ("no signing context, so CMAC", o, 100000);
  test_backpressure ();

  o = good ();
  o.dialect = 0x302;
  test_refused ("an older dialect", o, TWIST_ERR_PROTOCOL);
  o = good ();
  o.cipher = TWIST_SMB_CIPHER_AES128_CCM;
  test_refused ("AES-128-CCM", o, TWIST_ERR_PROTOCOL);
  o = good ();
  o.cipher = TWIST_SMB_CIPHER_AES256_CCM;
  test_refused ("a cipher that was not offered", o, TWIST_ERR_PROTOCOL);
  o = good ();
  o.cipher = 0;
  test_refused ("a server with no encryption context", o, TWIST_ERR_PROTOCOL);
  o = good ();
  o.caps = 0x04;
  test_refused ("a server without the encryption capability", o, TWIST_ERR_PROTOCOL);
  o = good ();
  o.mode = 0;
  test_refused ("a server that cannot sign", o, TWIST_ERR_PROTOCOL);
  o = good ();
  o.compression = 1;
  test_refused ("a compression context", o, TWIST_ERR_PROTOCOL);
  o = good ();
  o.hash = 0;
  test_refused ("no pre-authentication context", o, TWIST_ERR_PROTOCOL);
  o = good ();
  o.hash = 2;
  test_refused ("a hash other than SHA-512", o, TWIST_ERR_PROTOCOL);
  o = good ();
  o.two_hashes = 1;
  test_refused ("two pre-authentication hashes", o, TWIST_ERR_PROTOCOL);
  o = good ();
  o.signing = TWIST_SMB_SIGN_HMAC_SHA256;
  test_refused ("HMAC-SHA256 signing, which was not offered", o, TWIST_ERR_PROTOCOL);
  o = good ();
  o.max_read = 100;
  test_refused ("a read size too small to use", o, TWIST_ERR_PROTOCOL);
  o = good ();
  o.unsigned_final = 1;
  test_refused ("an unsigned final SESSION_SETUP response", o, TWIST_ERR_PROTOCOL);
  o = good ();
  o.bad_final_sig = 1;
  test_refused ("a final SESSION_SETUP response with a bad signature", o, TWIST_ERR_PROTOCOL);
  o = good ();
  o.mitm = 1;
  test_refused ("a NEGOTIATE response changed on the way (the hash differs)", o, TWIST_ERR_PROTOCOL);
  o = good ();
  o.session_flags = 1;
  test_refused ("a guest session", o, TWIST_ERR_AUTH);
  o = good ();
  o.session_flags = 2;
  test_refused ("a null session", o, TWIST_ERR_AUTH);
  o = good ();
  o.login_status = 0xC000006Du;
  test_refused ("a refused login", o, TWIST_ERR_AUTH);
  o = good ();
  o.plain_tree = 1;
  test_refused ("a TREE_CONNECT response that is not encrypted", o, TWIST_ERR_PROTOCOL);
  o = good ();
  o.bad_tag = 1;
  test_refused ("a message with a bad tag", o, TWIST_ERR_PROTOCOL);
  o = good ();
  o.wrong_session = 1;
  test_refused ("a transform for another session", o, TWIST_ERR_PROTOCOL);
  o = good ();
  o.tree_msgid = 9;
  test_refused ("a response with an id that was never sent", o, TWIST_ERR_PROTOCOL);
  {
    /* A nonce twice in a row: the second message.  */
    struct env *e;
    struct msg r;
    struct twist_smb_req h;
    uint8_t out[256], fid[16] = { 0 };
    size_t n;

    o = good ();
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
    server_seal (e, &r);
    check (e->failures == 1 && e->err == TWIST_ERR_PROTOCOL,
           "session: a server nonce equal to the last one is refused");
    done (e);
  }
  return tests_finish ();
}
