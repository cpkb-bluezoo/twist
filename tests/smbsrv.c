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

#include "smbsrv.h"

#include <quickstep/crypto.h>
#include <quickstep/status.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

size_t
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

void
p8 (struct msg *m, unsigned v)
{
  m->b[m->n++] = (uint8_t) v;
}

void
p16 (struct msg *m, unsigned v)
{
  p8 (m, v);
  p8 (m, v >> 8);
}

void
p32 (struct msg *m, uint32_t v)
{
  p16 (m, v & 0xffff);
  p16 (m, v >> 16);
}

void
p64 (struct msg *m, uint64_t v)
{
  p32 (m, (uint32_t) v);
  p32 (m, (uint32_t) (v >> 32));
}

void
pz (struct msg *m, size_t n)
{
  while (n-- > 0)
    p8 (m, 0);
}

void
pb (struct msg *m, const void *d, size_t n)
{
  memcpy (m->b + m->n, d, n);
  m->n += n;
}

/* A response message (no framing).  */
void
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


struct srv_opts
srv_good (void)
{
  struct srv_opts o;

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


void
srv_init (struct smbsrv *v, struct srv_opts o,
          void (*give) (void *user, const uint8_t *m, size_t n), void *user)
{
  memset (v, 0, sizeof *v);
  v->o = o;
  v->nonce = 0x1000;
  v->give = give;
  v->user = user;
}

static void
hash_in (struct smbsrv *v, const uint8_t *m, size_t n)
{
  uint8_t *b = malloc (64 + n);

  memcpy (b, v->hash, 64);
  memcpy (b + 64, m, n);
  twist_sha512 (b, 64 + n, v->hash);
  free (b);
}

/* The server's NEGOTIATE response, hashed after the client's request.  */
void
srv_negotiate (struct smbsrv *v, const uint8_t *req, size_t n)
{
  struct msg m;
  const struct srv_opts *o = &v->o;
  unsigned nctx = 0;
  size_t i, ctx_at, start;

  memset (v->hash, 0, 64);
  hash_in (v, req + 4, n - 4);
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
  hash_in (v, m.b, m.n);
  if (v->o.mitm)
    m.b[64 + 8] ^= 1;		/* The client is not told what the server hashed.  */
  v->give (v->user, m.b, m.n);
}

void
srv_setup1 (struct smbsrv *v, const uint8_t *req, size_t n)
{
  struct msg m;
  uint8_t tok[4096];
  size_t tl = unhex (hex_srv1, tok);

  hash_in (v, req + 4, n - 4);
  header (&m, 1, 0xC0000016u, 0, 1, SESSION_ID, 0);
  p16 (&m, 9);
  p16 (&m, 0);
  p16 (&m, 72);
  p16 (&m, (unsigned) tl);
  pb (&m, tok, tl);
  hash_in (v, m.b, m.n);
  v->give (v->user, m.b, m.n);
}

static void
derive (struct smbsrv *v)
{
  uint8_t sk[16];
  unsigned bits = v->o.cipher == TWIST_SMB_CIPHER_AES256_GCM ? 256 : 128;

  memset (sk, 0x55, 16);
  v->keylen = bits / 8;
  twist_smb_kdf (sk, 16, "SMBSigningKey", 14, v->hash, 64, 128, v->sign);
  twist_smb_kdf (sk, 16, "SMBC2SCipherKey", 16, v->hash, 64, bits, v->c2s);
  twist_smb_kdf (sk, 16, "SMBS2CCipherKey", 16, v->hash, 64, bits, v->s2c);
}

static void
sign_msg (struct smbsrv *v, struct msg *m)
{
  uint8_t sig[16];

  memset (m->b + 48, 0, 16);
  if (v->o.signing == TWIST_SMB_SIGN_AES_GMAC)
    {
      uint8_t nonce[12];

      memset (nonce, 0, 12);
      memcpy (nonce, m->b + 24, 8);
      nonce[8] = 1;
      gq_aead_seal (GQ_AEAD_AES_128_GCM, v->sign, 16, nonce, m->b, m->n, NULL,
                    0, sig, 16);
    }
  else
    twist_cmac_aes128 (v->sign, m->b, m->n, sig);
  memcpy (m->b + 48, sig, 16);
}

void
srv_setup2 (struct smbsrv *v, const uint8_t *req, size_t n)
{
  struct msg m;
  uint8_t tok[4096];
  size_t tl = unhex (hex_srv2, tok);

  hash_in (v, req + 4, n - 4);
  derive (v);
  header (&m, 1, v->o.login_status, v->o.unsigned_final ? 0 : 8, 2, SESSION_ID, 0);
  if (v->o.login_status != 0)
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
      p16 (&m, v->o.session_flags);
      p16 (&m, 72);
      p16 (&m, (unsigned) tl);
      pb (&m, tok, tl);
      if (!v->o.unsigned_final)
        sign_msg (v, &m);
      if (v->o.bad_final_sig)
        m.b[50] ^= 1;
    }
  v->give (v->user, m.b, m.n);
}

/* A response from the server, encrypted.  */
void
srv_seal (struct smbsrv *v, const struct msg *plain)
{
  struct msg f;
  uint8_t *t, nonce[12];
  size_t i;
  enum gq_aead alg = v->o.cipher == TWIST_SMB_CIPHER_AES256_GCM
    ? GQ_AEAD_AES_256_GCM : GQ_AEAD_AES_128_GCM;

  f.n = 0;
  pb (&f, "\xfd" "SMB", 4);
  pz (&f, 16);
  for (i = 0; i < 8; i++)
    p8 (&f, (unsigned) ((v->nonce >> (8 * i)) & 0xff));
  pz (&f, 8);
  p32 (&f, (uint32_t) plain->n);
  p16 (&f, 0);
  p16 (&f, 1);
  p64 (&f, v->o.wrong_session ? 99 : SESSION_ID);
  t = f.b;
  if (v->o.repeat_nonce && v->nonce != 0x1000)
    memcpy (t + 20, v->last_nonce, 12);
  memcpy (nonce, t + 20, 12);
  memcpy (v->last_nonce, t + 20, 12);
  pb (&f, plain->b, plain->n);
  gq_aead_seal (alg, v->s2c, v->keylen, nonce, t + 20, 32, f.b + 52, plain->n,
                f.b + 52, plain->n + 16);
  memcpy (t + 4, f.b + 52 + plain->n, 16);
  if (v->o.bad_tag)
    t[4] ^= 1;
  v->nonce++;
  v->give (v->user, f.b, 52 + plain->n);
}

/* What the client sent, decrypted.  */
int
srv_open (struct smbsrv *v, const uint8_t *f, size_t n, struct msg *plain)
{
  uint8_t buf[72000 + 16], nonce[12];
  size_t len = n - 4, orig;
  enum gq_aead alg = v->o.cipher == TWIST_SMB_CIPHER_AES256_GCM
    ? GQ_AEAD_AES_256_GCM : GQ_AEAD_AES_128_GCM;

  if (len < 52 || memcmp (f + 4, "\xfd" "SMB", 4) != 0)
    return -1;
  memcpy (buf, f + 4, len);
  orig = len - 52;
  memcpy (buf + len, buf + 4, 16);
  memcpy (nonce, buf + 20, 12);
  if (gq_aead_open (alg, v->c2s, v->keylen, nonce, buf + 20, 32, buf + 52,
                    orig + 16, buf + 52, orig) != GQ_OK)
    return -1;
  memcpy (plain->b, buf + 52, orig);
  plain->n = orig;
  return 0;
}

int
srv_tree (struct smbsrv *v, const uint8_t *f, size_t n, uint32_t tree_id)
{
  struct msg m, plain;

  if (srv_open (v, f, n, &plain) != 0 || plain.b[12] != 3)
    return -1;
  header (&m, 3, v->o.tree_status, 0, v->o.tree_msgid, SESSION_ID, tree_id);
  if (v->o.tree_status != 0)
    {
      p16 (&m, 9);
      p16 (&m, 0);
      p32 (&m, 0);
      p8 (&m, 0);
    }
  else
    {
      p16 (&m, 16);
      p8 (&m, 1);
      p8 (&m, 0);
      p32 (&m, 0x8000);
      p32 (&m, 8);
      p32 (&m, 0x1f01ff);
    }
  if (v->o.plain_tree)
    v->give (v->user, m.b, m.n);
  else
    srv_seal (v, &m);
  return 0;
}
