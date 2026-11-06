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

#include <quickstep/crypto.h>
#include <quickstep/status.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* The SMB 3.1.1 session layer; twist-int.h has the profile.

   Phases: NEGOTIATE and SESSION_SETUP are in the clear, each response held
   whole (to 64 KiB) so that the pre-authentication hash is taken over exactly
   its bytes; TREE_CONNECT and everything after it travel in transform
   headers.  The hash starts at 64 zero bytes and is chained with SHA-512
   over the NEGOTIATE request and response and each SESSION_SETUP request and
   each response that asks for more; the final response is not in it.  Keys
   are made from the hash as it stands when the last request has gone, which
   is when the response to check can arrive.  */

#define SETUP_MAX 65536
#define SEC_MAX 4400
#define OUT_MAX 64
#define REQ_CREDITS 32
#define IO_MAX 65536
#define IO_MIN 4096

#define CAP_LARGE_MTU 0x04u
#define CAP_ENCRYPTION 0x40u
#define SESSION_GUEST 0x0001u
#define SESSION_NULL 0x0002u

enum
{
  P_NEW,
  P_NEG,
  P_SETUP,
  P_TREE,
  P_EST,
  P_DONE,			/* Logged off.  */
  P_FAILED
};

struct twist_smb_session
{
  struct twist_smb_session_ops ops;
  struct twist_smb_events up;
  struct twist_ntlm_rand rnd;
  struct twist_spnego *sp;
  struct twist_smb_parser *parser;
  char unc[512];
  int phase;
  int failed;

  /* Receiving.  */
  uint8_t fh[4];
  size_t fh_have;
  int in_body;
  size_t flen, fgot;
  uint8_t *rbuf;
  const uint8_t *dbuf;
  size_t dlen, doff;
  int paused;

  /* Ids and credits.  */
  uint64_t next_id;
  unsigned credits;
  struct
  {
    uint64_t id;
    unsigned charge;
  } out[OUT_MAX];
  unsigned nout;

  /* What the NEGOTIATE response said.  */
  struct
  {
    uint16_t dialect, mode, cipher, signing;
    uint32_t caps, max_read, max_write, max_transact;
    int got_preauth, got_enc, got_sign, bad;
    unsigned context_count;
  } neg;
  struct twist_smb_session_info info;
  uint8_t hash[64];

  /* SESSION_SETUP.  */
  int round;
  uint16_t session_flags;
  uint8_t sec[SEC_MAX];
  size_t sec_len;
  int sec_over;
  uint8_t sign_key[16], enc_key[32], dec_key[32];
  size_t key_len;
  int keys_ready;

  /* Encryption.  */
  uint64_t nonce_ctr;
  uint8_t last_nonce[12];
  int have_last;

  /* The message being delivered.  */
  struct twist_smb_header hdr;
  int got_error;
  uint32_t err_status;
  uint8_t share_type;
};

/* ---- Errors ---- */

static void
wipe_keys (struct twist_smb_session *s)
{
  gq_wipe (s->sign_key, sizeof s->sign_key);
  gq_wipe (s->enc_key, sizeof s->enc_key);
  gq_wipe (s->dec_key, sizeof s->dec_key);
  s->keys_ready = 0;
}

static void
fail (struct twist_smb_session *s, int err)
{
  if (s->failed)
    return;
  s->failed = 1;
  s->phase = P_FAILED;
  wipe_keys (s);
  if (s->ops.failure != NULL)
    s->ops.failure (s->ops.user, err);
}

/* What the server's refusal of a login, a share or a file is, in twist's
   terms.  */
static int
status_error (uint32_t status)
{
  switch (status)
    {
    case 0xC000006Du:		/* LOGON_FAILURE */
    case 0xC000006Eu:		/* ACCOUNT_RESTRICTION */
    case 0xC0000071u:		/* PASSWORD_EXPIRED */
    case 0xC0000072u:		/* ACCOUNT_DISABLED */
    case 0xC0000234u:		/* ACCOUNT_LOCKED_OUT */
    case 0xC0000022u:		/* ACCESS_DENIED */
      return TWIST_ERR_AUTH;
    case 0xC00000CCu:		/* BAD_NETWORK_NAME */
    case 0xC0000034u:		/* OBJECT_NAME_NOT_FOUND */
    case 0xC000003Au:		/* OBJECT_PATH_NOT_FOUND */
    case 0xC000000Fu:		/* NO_SUCH_FILE */
      return TWIST_ERR_FILE;
    default:
      return TWIST_ERR_PROTOCOL;
    }
}

/* ---- Hash and keys ---- */

static int
hash_update (struct twist_smb_session *s, const uint8_t *msg, size_t len)
{
  uint8_t *buf = malloc (64 + len);
  int rc;

  if (buf == NULL)
    return TWIST_ERR_NOMEM;
  memcpy (buf, s->hash, 64);
  memcpy (buf + 64, msg, len);
  rc = twist_sha512 (buf, 64 + len, s->hash);
  free (buf);
  return rc;
}

/* The signing key and the two cipher keys, from the session key and the hash
   (MS-SMB2 3.1.4.2).  */
static int
derive_keys (struct twist_smb_session *s)
{
  uint8_t sk[16];
  unsigned bits = s->neg.cipher == TWIST_SMB_CIPHER_AES256_GCM ? 256 : 128;
  int rc;

  if (twist_spnego_session_key (s->sp, sk) != TWIST_OK)
    return TWIST_ERR_AUTH;
  s->key_len = bits / 8;
  rc = twist_smb_kdf (sk, 16, "SMBSigningKey", 14, s->hash, 64, 128,
                      s->sign_key);
  if (rc == TWIST_OK)
    rc = twist_smb_kdf (sk, 16, "SMBC2SCipherKey", 16, s->hash, 64, bits,
                        s->enc_key);
  if (rc == TWIST_OK)
    rc = twist_smb_kdf (sk, 16, "SMBS2CCipherKey", 16, s->hash, 64, bits,
                        s->dec_key);
  gq_wipe (sk, sizeof sk);
  s->keys_ready = rc == TWIST_OK;
  return rc;
}

static enum gq_aead
aead_alg (const struct twist_smb_session *s)
{
  return s->neg.cipher == TWIST_SMB_CIPHER_AES256_GCM ? GQ_AEAD_AES_256_GCM
                                                      : GQ_AEAD_AES_128_GCM;
}

/* The signature of a message under the signing key, with its signature field
   taken as zero: AES-CMAC, or AES-GMAC with the message id and the role as
   nonce (MS-SMB2 3.1.4.1).  The field is put back.  */
static int
signature_of (const struct twist_smb_session *s, uint8_t *msg, size_t len,
              int response, uint8_t out[16])
{
  uint8_t saved[16];
  int rc;

  if (len < TWIST_SMB_HEADER)
    return TWIST_ERR_PROTOCOL;
  memcpy (saved, msg + 48, 16);
  memset (msg + 48, 0, 16);
  if (s->neg.signing == TWIST_SMB_SIGN_AES_GMAC)
    {
      uint8_t nonce[12];

      memset (nonce, 0, sizeof nonce);
      memcpy (nonce, msg + 24, 8);	/* The message id, as on the wire.  */
      nonce[8] = response ? 1 : 0;
      rc = gq_aead_seal (GQ_AEAD_AES_128_GCM, s->sign_key, 16, nonce, msg, len,
                         NULL, 0, out, 16) == GQ_OK ? TWIST_OK
                                                    : TWIST_ERR_PROTOCOL;
    }
  else
    rc = twist_cmac_aes128 (s->sign_key, msg, len, out) == TWIST_OK
      ? TWIST_OK : TWIST_ERR_PROTOCOL;
  memcpy (msg + 48, saved, 16);
  return rc;
}

static int
random_bytes (struct twist_smb_session *s, void *buf, size_t len)
{
  if (s->rnd.fill != NULL)
    return s->rnd.fill (s->rnd.user, buf, len) == 0 ? TWIST_OK
                                                      : TWIST_ERR_PROTOCOL;
  return gq_random (buf, len) == GQ_OK ? TWIST_OK : TWIST_ERR_PROTOCOL;
}

/* ---- Ids and credits ---- */

static int
alloc_id (struct twist_smb_session *s, unsigned charge, struct twist_smb_req *h)
{
  if (charge == 0 || charge > s->credits || s->nout >= OUT_MAX)
    return TWIST_ERR_AGAIN;
  memset (h, 0, sizeof *h);
  h->credit_charge = (uint16_t) charge;
  h->credits = REQ_CREDITS;
  h->message_id = s->next_id;
  h->session_id = s->info.session_id;
  h->tree_id = s->info.tree_id;
  s->out[s->nout].id = s->next_id;
  s->out[s->nout].charge = charge;
  s->nout++;
  s->next_id += charge;
  s->credits -= charge;
  return TWIST_OK;
}

int
twist_smb_session_request (struct twist_smb_session *s, unsigned charge,
                           struct twist_smb_req *h)
{
  if (s == NULL || h == NULL || s->phase != P_EST)
    return TWIST_ERR_INVAL;
  return alloc_id (s, charge, h);
}

unsigned
twist_smb_session_credits (const struct twist_smb_session *s)
{
  return s != NULL ? s->credits : 0;
}

const struct twist_smb_session_info *
twist_smb_session_info (const struct twist_smb_session *s)
{
  return s != NULL ? &s->info : NULL;
}

/* A response has to answer a request that was sent and not yet answered; an
   interim one leaves it outstanding.  Its credits are ours.  */
static int
account (struct twist_smb_session *s, const struct twist_smb_header *h)
{
  unsigned i;

  for (i = 0; i < s->nout; i++)
    if (s->out[i].id == h->message_id)
      break;
  if (i == s->nout)
    return TWIST_ERR_PROTOCOL;
  if (h->status != TWIST_SMB_STATUS_PENDING)
    {
      s->out[i] = s->out[s->nout - 1];
      s->nout--;
    }
  s->credits = s->credits + h->credits > 0xffff ? 0xffff
                                                : s->credits + h->credits;
  return TWIST_OK;
}

/* ---- Sealing ---- */

/* A request as one transform: the frame, the header with the tag in its
   signature field, and the ciphertext of MSG and then DATA.  OUT has room for
   all of it and for a tag after.  */
static int
seal (struct twist_smb_session *s, const uint8_t *msg, size_t msglen,
      const uint8_t *data, size_t dlen, uint8_t *out, size_t cap, size_t *outlen)
{
  size_t total = msglen + dlen, i;
  uint8_t *t = out + 4;
  uint8_t *pt = out + 4 + TWIST_SMB_TRANSFORM_HEADER;

  if (!s->keys_ready || s->nonce_ctr == UINT64_MAX)
    return TWIST_ERR_PROTOCOL;
  if (total + 4 + TWIST_SMB_TRANSFORM_HEADER + 16 > cap
      || total + TWIST_SMB_TRANSFORM_HEADER >= (size_t) 1 << 24)
    return TWIST_ERR_INVAL;
  out[0] = 0;
  out[1] = (uint8_t) ((total + TWIST_SMB_TRANSFORM_HEADER) >> 16);
  out[2] = (uint8_t) ((total + TWIST_SMB_TRANSFORM_HEADER) >> 8);
  out[3] = (uint8_t) (total + TWIST_SMB_TRANSFORM_HEADER);
  memset (t, 0, TWIST_SMB_TRANSFORM_HEADER);
  memcpy (t, "\xfd" "SMB", 4);
  for (i = 0; i < 8; i++)
    t[20 + i] = (uint8_t) (s->nonce_ctr >> (8 * i));
  t[36] = (uint8_t) total;
  t[37] = (uint8_t) (total >> 8);
  t[38] = (uint8_t) (total >> 16);
  t[39] = (uint8_t) (total >> 24);
  t[42] = 1;			/* Encrypted.  */
  for (i = 0; i < 8; i++)
    t[44 + i] = (uint8_t) (s->info.session_id >> (8 * i));
  memcpy (pt, msg, msglen);
  if (dlen > 0)
    memcpy (pt + msglen, data, dlen);
  if (gq_aead_seal (aead_alg (s), s->enc_key, s->key_len, t + 20, t + 20, 32,
                    pt, total, pt, total + 16) != GQ_OK)
    return TWIST_ERR_PROTOCOL;
  memcpy (t + 4, pt + total, 16);	/* The tag goes in the header.  */
  s->nonce_ctr++;
  *outlen = 4 + TWIST_SMB_TRANSFORM_HEADER + total;
  return TWIST_OK;
}

int
twist_smb_session_send (struct twist_smb_session *s, const uint8_t *frame,
                        size_t len, const uint8_t *data, size_t data_len)
{
  uint8_t *out;
  size_t cap, n = 0;
  int rc;

  if (s == NULL || frame == NULL || len < 4 + TWIST_SMB_HEADER
      || (data == NULL && data_len > 0)
      || (s->phase != P_TREE && s->phase != P_EST))
    return TWIST_ERR_INVAL;
  cap = len + data_len + TWIST_SMB_TRANSFORM_HEADER + 16;
  out = malloc (cap);
  if (out == NULL)
    return TWIST_ERR_NOMEM;
  rc = seal (s, frame + 4, len - 4, data, data_len, out, cap, &n);
  if (rc == TWIST_OK)
    rc = s->ops.send (s->ops.user, out, n);
  gq_wipe (out, cap);
  free (out);
  if (rc != TWIST_OK && rc != TWIST_ERR_INVAL)
    fail (s, rc);
  return rc;
}

int
twist_smb_session_logoff (struct twist_smb_session *s)
{
  struct twist_smb_req h;
  uint8_t out[128];
  size_t n;
  int rc;

  if (s == NULL || s->phase != P_EST)
    return TWIST_ERR_INVAL;
  rc = alloc_id (s, 1, &h);
  if (rc != TWIST_OK)
    return rc;
  rc = twist_smb_w_logoff (out, sizeof out, &n, &h);
  return rc != TWIST_OK ? rc : twist_smb_session_send (s, out, n, NULL, 0);
}

/* A transform received: the tag is checked before any of the message is
   given to anything, and the plaintext is left in place.  Returns its offset
   and length in the buffer.  */
static int
unseal (struct twist_smb_session *s, uint8_t *m, size_t len, size_t *off,
        size_t *plen)
{
  size_t orig;
  uint64_t sess = 0;
  unsigned i;

  if (len < TWIST_SMB_TRANSFORM_HEADER + TWIST_SMB_HEADER
      || memcmp (m, "\xfd" "SMB", 4) != 0)
    return TWIST_ERR_PROTOCOL;
  orig = (size_t) m[36] | ((size_t) m[37] << 8) | ((size_t) m[38] << 16)
    | ((size_t) m[39] << 24);
  for (i = 0; i < 8; i++)
    sess |= (uint64_t) m[44 + i] << (8 * i);
  if (orig != len - TWIST_SMB_TRANSFORM_HEADER || orig < TWIST_SMB_HEADER
      || m[42] != 1 || m[43] != 0 || sess != s->info.session_id)
    return TWIST_ERR_PROTOCOL;
  /* A nonce is not used twice in a row.  */
  if (s->have_last && memcmp (s->last_nonce, m + 20, 12) == 0)
    return TWIST_ERR_PROTOCOL;
  memcpy (s->last_nonce, m + 20, 12);
  s->have_last = 1;
  /* The tag follows the ciphertext for the primitive.  */
  memcpy (m + len, m + 4, 16);
  if (gq_aead_open (aead_alg (s), s->dec_key, s->key_len, m + 20, m + 20, 32,
                    m + TWIST_SMB_TRANSFORM_HEADER, orig + 16,
                    m + TWIST_SMB_TRANSFORM_HEADER, orig) != GQ_OK)
    return TWIST_ERR_PROTOCOL;
  *off = TWIST_SMB_TRANSFORM_HEADER;
  *plen = orig;
  return TWIST_OK;
}

/* ---- Requests in the clear ---- */

static int
send_plain (struct twist_smb_session *s, const uint8_t *frame, size_t n)
{
  return s->ops.send (s->ops.user, frame, n);
}

static int
send_session_setup (struct twist_smb_session *s, const uint8_t *tok, size_t len)
{
  uint8_t out[SEC_MAX + 512];
  struct twist_smb_req h;
  size_t n;
  int rc = alloc_id (s, 1, &h);

  if (rc != TWIST_OK)
    return rc;
  rc = twist_smb_w_session_setup (out, sizeof out, &n, &h, 3, 0, tok, len);
  if (rc != TWIST_OK)
    return rc;
  rc = hash_update (s, out + 4, n - 4);
  if (rc != TWIST_OK)
    return rc;
  /* The last request has gone once the AUTHENTICATE is in it, and the keys
     are made from the hash that includes it.  */
  if (s->round == 2)
    {
      rc = derive_keys (s);
      if (rc != TWIST_OK)
        return rc;
    }
  return send_plain (s, out, n);
}

static int
send_tree_connect (struct twist_smb_session *s)
{
  uint8_t out[1024];
  struct twist_smb_req h;
  size_t n;
  int rc = alloc_id (s, 1, &h);

  if (rc != TWIST_OK)
    return rc;
  rc = twist_smb_w_tree_connect (out, sizeof out, &n, &h, s->unc);
  if (rc != TWIST_OK)
    return rc;
  s->phase = P_TREE;
  return twist_smb_session_send (s, out, n, NULL, 0);
}

int
twist_smb_session_start (struct twist_smb_session *s)
{
  struct twist_smb_negotiate_req r;
  struct twist_smb_req h;
  uint8_t out[1024];
  size_t n;
  uint64_t start = 0;
  int rc;

  if (s == NULL || s->phase != P_NEW)
    return TWIST_ERR_INVAL;
  memset (&r, 0, sizeof r);
  r.security_mode = 3;		/* Signing enabled and required.  */
  r.capabilities = CAP_LARGE_MTU | CAP_ENCRYPTION;
  r.n_dialects = 1;
  r.dialects[0] = TWIST_SMB_DIALECT_311;
  r.n_hashes = 1;
  r.hashes[0] = TWIST_SMB_HASH_SHA512;
  r.salt_len = 32;
  r.n_ciphers = 2;
  r.ciphers[0] = TWIST_SMB_CIPHER_AES256_GCM;
  r.ciphers[1] = TWIST_SMB_CIPHER_AES128_GCM;
  r.n_signing = 2;
  r.signing[0] = TWIST_SMB_SIGN_AES_GMAC;
  r.signing[1] = TWIST_SMB_SIGN_AES_CMAC;
  if (random_bytes (s, r.client_guid, 16) != TWIST_OK
      || random_bytes (s, r.salt, 32) != TWIST_OK
      || random_bytes (s, &start, 8) != TWIST_OK)
    {
      fail (s, TWIST_ERR_PROTOCOL);
      return TWIST_ERR_PROTOCOL;
    }
  s->nonce_ctr = start >> 1;	/* Far from wrapping.  */
  rc = alloc_id (s, 1, &h);
  if (rc == TWIST_OK)
    rc = twist_smb_w_negotiate (out, sizeof out, &n, &h, &r);
  if (rc == TWIST_OK)
    {
      memset (s->hash, 0, 64);
      rc = hash_update (s, out + 4, n - 4);
    }
  if (rc == TWIST_OK)
    {
      s->phase = P_NEG;
      rc = send_plain (s, out, n);
    }
  if (rc != TWIST_OK)
    fail (s, rc);
  return rc;
}

/* ---- Events from the parser ---- */

#define FWD(s, f, ...) \
  ((s)->phase == P_EST && (s)->up.f != NULL \
   ? (s)->up.f ((s)->up.user, __VA_ARGS__) : TWIST_OK)

static int
on_begin (void *u, uint64_t off, size_t len)
{
  struct twist_smb_session *s = u;

  s->got_error = 0;
  s->sec_len = 0;
  s->sec_over = 0;
  return FWD (s, message_begin, off, len);
}

static int
on_header (void *u, const struct twist_smb_header *h)
{
  struct twist_smb_session *s = u;
  int rc;

  s->hdr = *h;
  /* The command has to be the one the phase is waiting for, and a session
     that has an id keeps it.  */
  switch (s->phase)
    {
    case P_NEG:
      if (h->command != TWIST_SMB_NEGOTIATE)
        return TWIST_ERR_PROTOCOL;
      break;
    case P_SETUP:
      if (h->command != TWIST_SMB_SESSION_SETUP)
        return TWIST_ERR_PROTOCOL;
      if (s->info.session_id != 0 && h->session_id != s->info.session_id)
        return TWIST_ERR_PROTOCOL;
      break;
    case P_TREE:
      if (h->command != TWIST_SMB_TREE_CONNECT
          || h->session_id != s->info.session_id)
        return TWIST_ERR_PROTOCOL;
      break;
    case P_EST:
      if (h->session_id != s->info.session_id)
        return TWIST_ERR_PROTOCOL;
      break;
    default:
      return TWIST_ERR_PROTOCOL;
    }
  rc = account (s, h);
  if (rc != TWIST_OK)
    return rc;
  return FWD (s, header, h);
}

static int
on_pending (void *u, uint64_t async_id)
{
  struct twist_smb_session *s = u;

  /* An interim answer is for requests that take a while; the setup does
     not.  */
  if (s->phase != P_EST)
    return TWIST_ERR_PROTOCOL;
  return FWD (s, pending, async_id);
}

static int
on_error (void *u, uint32_t status, unsigned ctx, uint32_t n)
{
  struct twist_smb_session *s = u;

  s->got_error = 1;
  s->err_status = status;
  return FWD (s, error, status, ctx, n);
}

static int
on_negotiate (void *u, const struct twist_smb_negotiate *r)
{
  struct twist_smb_session *s = u;

  if (s->phase != P_NEG)
    return TWIST_ERR_PROTOCOL;
  memset (&s->neg, 0, sizeof s->neg);
  s->neg.dialect = r->dialect;
  s->neg.mode = r->security_mode;
  s->neg.caps = r->capabilities;
  s->neg.max_read = r->max_read;
  s->neg.max_write = r->max_write;
  s->neg.max_transact = r->max_transact;
  s->neg.context_count = r->context_count;
  s->neg.signing = TWIST_SMB_SIGN_AES_CMAC;
  return TWIST_OK;
}

/* Each context is checked against what was offered; one that is offered
   twice, or one that was not asked for, is a violation of the profile.  */
static int
on_context (void *u, const struct twist_smb_context *c)
{
  struct twist_smb_session *s = u;

  if (s->phase != P_NEG)
    return TWIST_ERR_PROTOCOL;
  switch (c->type)
    {
    case TWIST_SMB_CTX_PREAUTH:
      if (s->neg.got_preauth || c->count != 1
          || c->algs[0] != TWIST_SMB_HASH_SHA512)
        s->neg.bad = 1;
      s->neg.got_preauth = 1;
      break;
    case TWIST_SMB_CTX_ENCRYPTION:
      if (s->neg.got_enc || c->count != 1
          || (c->algs[0] != TWIST_SMB_CIPHER_AES256_GCM
              && c->algs[0] != TWIST_SMB_CIPHER_AES128_GCM))
        s->neg.bad = 1;
      else
        s->neg.cipher = c->algs[0];
      s->neg.got_enc = 1;
      break;
    case TWIST_SMB_CTX_SIGNING:
      if (s->neg.got_sign || c->count != 1
          || (c->algs[0] != TWIST_SMB_SIGN_AES_GMAC
              && c->algs[0] != TWIST_SMB_SIGN_AES_CMAC))
        s->neg.bad = 1;
      else
        s->neg.signing = c->algs[0];
      s->neg.got_sign = 1;
      break;
    case TWIST_SMB_CTX_COMPRESSION:
      s->neg.bad = 1;		/* Never asked for.  */
      break;
    default:
      break;
    }
  return TWIST_OK;
}

static int
on_setup (void *u, uint16_t flags)
{
  struct twist_smb_session *s = u;

  if (s->phase != P_SETUP)
    return TWIST_ERR_PROTOCOL;
  s->session_flags = flags;
  return TWIST_OK;
}

static int
on_tree (void *u, const struct twist_smb_tree_connect *r)
{
  struct twist_smb_session *s = u;

  if (s->phase != P_TREE)
    return TWIST_ERR_PROTOCOL;
  s->share_type = r->share_type;
  return TWIST_OK;
}

static size_t
on_data (void *u, enum twist_smb_data kind, const uint8_t *p, size_t n)
{
  struct twist_smb_session *s = u;

  if (s->phase == P_EST)
    return s->up.data != NULL ? s->up.data (s->up.user, kind, p, n) : n;
  if (kind == TWIST_SMB_DATA_SECURITY)
    {
      if (n > sizeof s->sec - s->sec_len)
        s->sec_over = 1;
      else
        {
          memcpy (s->sec + s->sec_len, p, n);
          s->sec_len += n;
        }
    }
  return n;
}

static int
on_empty (void *u, uint16_t command)
{
  struct twist_smb_session *s = u;
  int rc = FWD (s, empty, command);

  /* The session is over, and so are its keys.  */
  if (s->phase == P_EST && command == TWIST_SMB_LOGOFF)
    {
      wipe_keys (s);
      s->phase = P_DONE;
    }
  return rc;
}

static int
on_create (void *u, const struct twist_smb_create *r)
{
  return FWD ((struct twist_smb_session *) u, create, r);
}

static int
on_close (void *u, const struct twist_smb_close *r)
{
  return FWD ((struct twist_smb_session *) u, close, r);
}

static int
on_read (void *u, uint32_t a, uint32_t b)
{
  return FWD ((struct twist_smb_session *) u, read, a, b);
}

static int
on_write (void *u, uint32_t a, uint32_t b)
{
  return FWD ((struct twist_smb_session *) u, write, a, b);
}

static int
on_qinfo (void *u, uint32_t n)
{
  return FWD ((struct twist_smb_session *) u, query_info, n);
}

static int
on_qdir (void *u, uint32_t n)
{
  return FWD ((struct twist_smb_session *) u, query_directory, n);
}

static int
on_entry (void *u, const uint8_t *p, size_t n)
{
  return FWD ((struct twist_smb_session *) u, entry, p, n);
}

/* ---- The ends of messages: the state machine ---- */

static int
finish_negotiate (struct twist_smb_session *s, const uint8_t *msg, size_t len)
{
  uint8_t tok[SEC_MAX];
  size_t toklen;
  int rc;

  if (s->got_error)
    return status_error (s->err_status);
  if (s->hdr.status != TWIST_SMB_STATUS_SUCCESS
      || s->neg.dialect != TWIST_SMB_DIALECT_311
      || (s->neg.mode & 1) == 0
      || (s->neg.caps & CAP_ENCRYPTION) == 0
      || !s->neg.got_preauth || !s->neg.got_enc || s->neg.bad
      || s->neg.max_read < IO_MIN || s->neg.max_write < IO_MIN
      || s->neg.max_transact < IO_MIN)
    return TWIST_ERR_PROTOCOL;
  rc = hash_update (s, msg, len);
  if (rc != TWIST_OK)
    return rc;
  /* One encrypted message has to fit the input buffer; throughput comes from
     requests in flight, not from large ones.  */
  s->info.cipher = s->neg.cipher;
  s->info.signing = s->neg.signing;
  s->info.max_read = s->neg.max_read < IO_MAX ? s->neg.max_read : IO_MAX;
  s->info.max_write = s->neg.max_write < IO_MAX ? s->neg.max_write : IO_MAX;
  s->info.max_transact = s->neg.max_transact < IO_MAX ? s->neg.max_transact
                                                      : IO_MAX;
  twist_smb_parser_set_limit (s->parser, TWIST_SMB_FRAME_MAX);
  rc = twist_spnego_start (s->sp, tok, sizeof tok, &toklen);
  if (rc != TWIST_OK)
    return TWIST_ERR_AUTH;
  s->phase = P_SETUP;
  s->round = 1;
  return send_session_setup (s, tok, toklen);
}

static int
finish_setup (struct twist_smb_session *s, const uint8_t *msg, size_t len)
{
  uint8_t tok[SEC_MAX + 512];
  size_t toklen = 0;
  int done = 0, rc;

  if (s->got_error)
    return status_error (s->err_status);
  if (s->sec_over)
    return TWIST_ERR_PROTOCOL;
  if (s->round == 1)
    {
      if (s->hdr.status != TWIST_SMB_STATUS_MORE_PROCESSING
          || s->hdr.session_id == 0)
        return TWIST_ERR_PROTOCOL;
      s->info.session_id = s->hdr.session_id;
      rc = hash_update (s, msg, len);
      if (rc != TWIST_OK)
        return rc;
      rc = twist_spnego_step (s->sp, s->sec, s->sec_len, tok, sizeof tok,
                              &toklen, &done);
      if (rc != TWIST_OK || done)
        return TWIST_ERR_AUTH;
      s->round = 2;
      return send_session_setup (s, tok, toklen);
    }
  /* The last response: success, from a session that is neither a guest's nor
     a null one, and the server's last SPNEGO token.  Its signature was
     checked before the message was read.  */
  if (s->hdr.status != TWIST_SMB_STATUS_SUCCESS)
    return TWIST_ERR_PROTOCOL;
  if ((s->session_flags & (SESSION_GUEST | SESSION_NULL)) != 0)
    return TWIST_ERR_AUTH;
  rc = twist_spnego_step (s->sp, s->sec, s->sec_len, tok, sizeof tok, &toklen,
                          &done);
  if (rc != TWIST_OK || !done)
    return TWIST_ERR_AUTH;
  return send_tree_connect (s);
}

static int
finish_tree (struct twist_smb_session *s)
{
  if (s->got_error)
    return status_error (s->err_status);
  if (s->hdr.status != TWIST_SMB_STATUS_SUCCESS || s->share_type != 1)
    return TWIST_ERR_PROTOCOL;	/* Only a disk share is read.  */
  s->info.tree_id = s->hdr.tree_id;
  s->phase = P_EST;
  if (s->ops.established != NULL)
    s->ops.established (s->ops.user, s->info.tree_id);
  return TWIST_OK;
}

static int
on_end (void *u, uint64_t off)
{
  struct twist_smb_session *s = u;
  int rc = TWIST_OK;

  (void) off;
  switch (s->phase)
    {
    case P_NEG:
      rc = finish_negotiate (s, s->dbuf, s->dlen);
      break;
    case P_SETUP:
      rc = finish_setup (s, s->dbuf, s->dlen);
      break;
    case P_TREE:
      rc = finish_tree (s);
      break;
    case P_EST:
    case P_DONE:
      rc = s->up.message_end != NULL && s->phase == P_EST
        ? s->up.message_end (s->up.user, off) : TWIST_OK;
      break;
    default:
      break;
    }
  return rc;
}

static void
on_fail (void *u, int err)
{
  fail (u, err);
}

/* ---- Receiving ---- */

static void
drain (struct twist_smb_session *s)
{
  while (s->doff < s->dlen && !s->failed)
    {
      size_t used = twist_smb_parser_receive (s->parser, s->dbuf + s->doff,
                                              s->dlen - s->doff);

      s->doff += used;
      if (s->failed || twist_smb_parser_failed (s->parser))
        return;
      if (s->doff < s->dlen)
        {
          s->paused = 1;	/* The consumer asked to wait.  */
          return;
        }
    }
  s->paused = 0;
  if (!s->failed && !twist_smb_parser_done (s->parser))
    fail (s, TWIST_ERR_PROTOCOL);
}

static void
deliver (struct twist_smb_session *s, const uint8_t *m, size_t len)
{
  s->dbuf = m;
  s->dlen = len;
  s->doff = 0;
  if (twist_smb_parser_begin_message (s->parser, len) != TWIST_OK)
    {
      fail (s, TWIST_ERR_PROTOCOL);
      return;
    }
  drain (s);
}

void
twist_smb_session_resume (struct twist_smb_session *s)
{
  if (s != NULL && s->paused && !s->failed)
    drain (s);
}

static uint32_t
le32 (const uint8_t *p)
{
  return (uint32_t) p[0] | ((uint32_t) p[1] << 8) | ((uint32_t) p[2] << 16)
    | ((uint32_t) p[3] << 24);
}

static void
process_frame (struct twist_smb_session *s)
{
  uint8_t *m = s->rbuf;
  size_t len = s->flen, off, plen;
  int rc;

  switch (s->phase)
    {
    case P_NEG:
    case P_SETUP:
      if (len < TWIST_SMB_HEADER || memcmp (m, "\xfe" "SMB", 4) != 0)
        {
          fail (s, TWIST_ERR_PROTOCOL);
          return;
        }
      /* The last SESSION_SETUP response, success, has to be signed: the
         signature is the check that the negotiate exchange was not changed on
         the way, since the keys come from the hash of it.  */
      if (s->phase == P_SETUP && s->round == 2 && le32 (m + 8) == 0
          && m[12] == TWIST_SMB_SESSION_SETUP && m[13] == 0)
        {
          uint8_t want[16];

          if (!s->keys_ready || (le32 (m + 16) & TWIST_SMB_FLAG_SIGNED) == 0
              || signature_of (s, m, len, 1, want) != TWIST_OK
              || !gq_ct_equal (want, m + 48, 16))
            {
              fail (s, TWIST_ERR_PROTOCOL);
              return;
            }
        }
      deliver (s, m, len);
      return;
    case P_TREE:
    case P_EST:
      /* Nothing that is not encrypted is read.  */
      rc = unseal (s, m, len, &off, &plen);
      if (rc != TWIST_OK)
        {
          fail (s, rc);
          return;
        }
      deliver (s, m + off, plen);
      return;
    default:
      fail (s, TWIST_ERR_PROTOCOL);
    }
}

size_t
twist_smb_session_receive (struct twist_smb_session *s, const uint8_t *data,
                           size_t len)
{
  size_t off = 0;

  if (s == NULL)
    return 0;
  if (s->failed)
    return len;
  if (s->paused || s->phase == P_NEW)
    return 0;
  while (off < len && !s->failed && !s->paused)
    {
      size_t n;

      if (!s->in_body)
        {
          n = 4 - s->fh_have;
          if (n > len - off)
            n = len - off;
          memcpy (s->fh + s->fh_have, data + off, n);
          s->fh_have += n;
          off += n;
          if (s->fh_have == 4)
            {
              size_t max = s->phase == P_NEG || s->phase == P_SETUP
                ? SETUP_MAX : TWIST_SMB_FRAME_MAX;

              s->flen = ((size_t) s->fh[1] << 16) | ((size_t) s->fh[2] << 8)
                | s->fh[3];
              if (s->fh[0] != 0 || s->flen == 0 || s->flen > max)
                {
                  fail (s, TWIST_ERR_PROTOCOL);
                  break;
                }
              s->in_body = 1;
              s->fgot = 0;
              s->fh_have = 0;
            }
        }
      else
        {
          n = s->flen - s->fgot;
          if (n > len - off)
            n = len - off;
          memcpy (s->rbuf + s->fgot, data + off, n);
          s->fgot += n;
          off += n;
          if (s->fgot == s->flen)
            {
              s->in_body = 0;
              process_frame (s);
            }
        }
    }
  return s->failed ? len : off;
}

/* ---- Making and freeing ---- */

struct twist_smb_session *
twist_smb_session_new (const struct twist_smb_session_config *cfg,
                       const struct twist_smb_session_ops *ops,
                       const struct twist_smb_events *up)
{
  struct twist_smb_session *s;
  struct twist_smb_events ev;

  if (cfg == NULL || ops == NULL || ops->send == NULL || cfg->host == NULL
      || cfg->share == NULL || cfg->share[0] == 0)
    return NULL;
  s = calloc (1, sizeof *s);
  if (s == NULL)
    return NULL;
  s->ops = *ops;
  if (up != NULL)
    s->up = *up;
  if (cfg->rnd != NULL)
    s->rnd = *cfg->rnd;
  if (snprintf (s->unc, sizeof s->unc, "\\\\%s\\%s", cfg->host, cfg->share)
      >= (int) sizeof s->unc)
    goto bad;
  s->sp = twist_spnego_new (cfg->domain, cfg->user, cfg->password, cfg->host,
                            cfg->rnd);
  s->rbuf = malloc (TWIST_SMB_FRAME_MAX + 16);
  memset (&ev, 0, sizeof ev);
  ev.user = s;
  ev.message_begin = on_begin;
  ev.header = on_header;
  ev.negotiate = on_negotiate;
  ev.context = on_context;
  ev.session_setup = on_setup;
  ev.tree_connect = on_tree;
  ev.create = on_create;
  ev.close = on_close;
  ev.read = on_read;
  ev.write = on_write;
  ev.query_info = on_qinfo;
  ev.query_directory = on_qdir;
  ev.empty = on_empty;
  ev.error = on_error;
  ev.pending = on_pending;
  ev.data = on_data;
  ev.entry = on_entry;
  ev.message_end = on_end;
  ev.failure = on_fail;
  s->parser = twist_smb_parser_new (&ev);
  if (s->sp == NULL || s->rbuf == NULL || s->parser == NULL)
    goto bad;
  twist_smb_parser_set_limit (s->parser, SETUP_MAX);
  s->next_id = 0;
  s->credits = 1;		/* The one the connection starts with.  */
  s->phase = P_NEW;
  return s;
bad:
  twist_smb_session_free (s);
  return NULL;
}

void
twist_smb_session_free (struct twist_smb_session *s)
{
  if (s == NULL)
    return;
  twist_smb_parser_free (s->parser);
  twist_spnego_free (s->sp);
  free (s->rbuf);
  gq_wipe (s, sizeof *s);
  free (s);
}
