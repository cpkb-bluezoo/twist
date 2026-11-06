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

/* An NTLMv2 initiator (MS-NLMP) as a codec: it reads and writes the three
   messages and does no I/O.  SMB carries them inside SPNEGO.

   What it sends and what it refuses is narrow on purpose.  It sends the
   NTLMv2 response only, with a zero LM response; never LM or NTLMv1, and never
   an anonymous or a null session.  It refuses a CHALLENGE that does not
   agree to 128-bit keys, extended session security, target information,
   signing and key exchange, or whose target information has no timestamp.
   The target information is kept whole, since the response and the MIC are
   made over it; that and the messages are bounded, and a server that sends
   more than the bound is refused.

   The password is turned into the NTLMv2 key when the client is made and is
   wiped there.  Every error is TWIST_ERR_AUTH.  */

/* NegotiateFlags.  */
#define F_UNICODE	0x00000001u
#define F_REQUEST_TARGET 0x00000004u
#define F_SIGN		0x00000010u
#define F_NTLM		0x00000200u
#define F_EXTSESS	0x00080000u
#define F_TARGET_INFO	0x00800000u
#define F_VERSION	0x02000000u
#define F_128		0x20000000u
#define F_KEY_EXCH	0x40000000u

#define F_OFFERED (F_UNICODE | F_REQUEST_TARGET | F_SIGN | F_NTLM | F_EXTSESS \
                   | F_TARGET_INFO | F_VERSION | F_128 | F_KEY_EXCH)
#define F_REQUIRED (F_UNICODE | F_SIGN | F_EXTSESS | F_TARGET_INFO | F_128 \
                    | F_KEY_EXCH)

/* AV pair identifiers.  */
#define AV_EOL		0
#define AV_FLAGS	6
#define AV_TIMESTAMP	7
#define AV_TARGET_NAME	9
#define AV_CHANNEL	10

#define NTLM_NEGOTIATE_LEN 40
#define NTLM_AUTH_HDR 88		/* Up to and including the MIC.  */
#define NTLM_CHAL_MAX 4096
#define NTLM_TI_MAX 2048
#define NTLM_NAME_MAX 512		/* Bytes of UTF-16LE.  */

enum
{
  S_NEW,
  S_NEGOTIATED,
  S_FED,
  S_PARSED,
  S_DONE,
  S_FAILED
};

struct twist_ntlm
{
  struct twist_ntlm_rand rnd;
  int state;
  uint8_t respkey[16];
  uint8_t domain[NTLM_NAME_MAX];
  size_t domlen;
  uint8_t user[NTLM_NAME_MAX];
  size_t userlen;
  uint8_t target[NTLM_NAME_MAX];	/* cifs/host */
  size_t targetlen;
  uint8_t neg[NTLM_NEGOTIATE_LEN];
  uint8_t chal[NTLM_CHAL_MAX];
  size_t chal_len;
  uint32_t flags;
  uint8_t srv_chal[8];
  size_t ti_off, ti_len;
  uint8_t timestamp[8];
  uint8_t session_key[16];
  uint8_t sign_c[16], sign_s[16];
  struct twist_rc4 seal_c, seal_s;
  uint32_t seq_c, seq_s;
};

/* ---- Text ---- */

/* The simple upper-casing NTOWFv2 asks of the user name: Latin, Greek and
   Cyrillic letters.  Any other character is left as it is.  */
static uint32_t
upper_cp (uint32_t c)
{
  if (c < 0x80)
    return c >= 'a' && c <= 'z' ? c - 32 : c;
  if (c == 0xb5)
    return 0x39c;
  if (c >= 0xe0 && c <= 0xfe && c != 0xf7)
    return c - 32;
  if (c == 0xff)
    return 0x178;
  if (c == 0x131)
    return 'I';
  if (c == 0x17f)
    return 'S';
  if ((c >= 0x100 && c <= 0x137) || (c >= 0x14a && c <= 0x177))
    return (c & 1) ? c - 1 : c;
  if (c >= 0x139 && c <= 0x148)
    return (c & 1) ? c : c - 1;
  if (c == 0x17a || c == 0x17c || c == 0x17e)
    return c - 1;
  if (c >= 0x3b1 && c <= 0x3c9)
    return c == 0x3c2 ? 0x3a3 : c - 32;
  if (c == 0x3ac)
    return 0x386;
  if (c >= 0x3ad && c <= 0x3af)
    return c - 37;
  if (c == 0x3cc)
    return 0x38c;
  if (c == 0x3cd || c == 0x3ce)
    return c - 63;
  if (c >= 0x430 && c <= 0x44f)
    return c - 32;
  if (c >= 0x450 && c <= 0x45f)
    return c - 80;
  return c;
}

int
twist_utf16le_from_utf8 (const char *s, size_t slen, int upper, uint8_t *out,
                         size_t cap, size_t *outlen)
{
  const uint8_t *p = (const uint8_t *) s;
  size_t i = 0, n = 0;

  if (outlen == NULL || (s == NULL && slen > 0) || (out == NULL && cap > 0))
    return TWIST_ERR_INVAL;
  while (i < slen)
    {
      uint32_t c = p[i];
      int extra, k;
      uint32_t min;

      if (c < 0x80)
        extra = 0, min = 0;
      else if (c >= 0xc2 && c <= 0xdf)
        extra = 1, c &= 0x1f, min = 0x80;
      else if (c >= 0xe0 && c <= 0xef)
        extra = 2, c &= 0x0f, min = 0x800;
      else if (c >= 0xf0 && c <= 0xf4)
        extra = 3, c &= 0x07, min = 0x10000;
      else
        return TWIST_ERR_INVAL;
      if ((size_t) extra > slen - i - 1)
        return TWIST_ERR_INVAL;
      for (k = 1; k <= extra; k++)
        {
          if ((p[i + k] & 0xc0) != 0x80)
            return TWIST_ERR_INVAL;
          c = (c << 6) | (p[i + k] & 0x3f);
        }
      i += (size_t) extra + 1;
      if (c < min || c > 0x10ffff || (c >= 0xd800 && c <= 0xdfff))
        return TWIST_ERR_INVAL;
      if (upper)
        c = upper_cp (c);
      if (c >= 0x10000)
        {
          uint32_t v = c - 0x10000;
          uint16_t hi = (uint16_t) (0xd800 + (v >> 10));
          uint16_t lo = (uint16_t) (0xdc00 + (v & 0x3ff));

          if (cap - n < 4 || n > cap)
            return TWIST_ERR_INVAL;
          out[n++] = (uint8_t) hi;
          out[n++] = (uint8_t) (hi >> 8);
          out[n++] = (uint8_t) lo;
          out[n++] = (uint8_t) (lo >> 8);
        }
      else
        {
          if (n > cap || cap - n < 2)
            return TWIST_ERR_INVAL;
          out[n++] = (uint8_t) c;
          out[n++] = (uint8_t) (c >> 8);
        }
    }
  *outlen = n;
  return TWIST_OK;
}

/* ---- Keys ---- */

/* HMAC-MD5 over two pieces, which are joined for the one-shot primitive.  */
static int
hmac2 (const uint8_t *key, size_t keylen, const void *a, size_t alen,
       const void *b, size_t blen, uint8_t out[16])
{
  uint8_t *buf = malloc (alen + blen + 1);
  int rc;

  if (buf == NULL)
    return TWIST_ERR_NOMEM;
  memcpy (buf, a, alen);
  if (blen > 0)
    memcpy (buf + alen, b, blen);
  rc = twist_hmac_md5 (key, keylen, buf, alen + blen, out);
  gq_wipe (buf, alen + blen + 1);
  free (buf);
  return rc;
}

int
twist_ntlm_ntowfv2 (const char *user, const char *domain, const char *password,
                    uint8_t key[16])
{
  uint8_t pw[2048], id[2 * NTLM_NAME_MAX], hash[16];
  size_t pwn, un, dn;
  int rc;

  if (user == NULL || password == NULL || key == NULL)
    return TWIST_ERR_INVAL;
  if (domain == NULL)
    domain = "";
  if (twist_utf16le_from_utf8 (password, strlen (password), 0, pw, sizeof pw,
                               &pwn) != TWIST_OK
      || twist_utf16le_from_utf8 (user, strlen (user), 1, id, NTLM_NAME_MAX,
                                  &un) != TWIST_OK
      || twist_utf16le_from_utf8 (domain, strlen (domain), 0, id + un,
                                  sizeof id - un, &dn) != TWIST_OK)
    {
      gq_wipe (pw, sizeof pw);
      return TWIST_ERR_AUTH;
    }
  rc = twist_md4 (pw, pwn, hash);
  gq_wipe (pw, sizeof pw);
  if (rc == TWIST_OK)
    rc = twist_hmac_md5 (hash, 16, id, un + dn, key);
  gq_wipe (hash, sizeof hash);
  return rc == TWIST_OK ? TWIST_OK : TWIST_ERR_AUTH;
}

int
twist_ntlm_v2_response (const uint8_t respkey[16], const uint8_t server_chal[8],
                        const uint8_t *temp, size_t templen,
                        uint8_t proof[16], uint8_t base_key[16])
{
  if (respkey == NULL || server_chal == NULL || temp == NULL || proof == NULL
      || base_key == NULL)
    return TWIST_ERR_INVAL;
  if (hmac2 (respkey, 16, server_chal, 8, temp, templen, proof) != TWIST_OK)
    return TWIST_ERR_AUTH;
  if (twist_hmac_md5 (respkey, 16, proof, 16, base_key) != TWIST_OK)
    return TWIST_ERR_AUTH;
  return TWIST_OK;
}

/* MS-NLMP 3.4.5.2 and 3.4.5.3: the signing and the sealing keys.  */
static int
derive_key (const uint8_t session_key[16], const char *magic, size_t magiclen,
            uint8_t out[16])
{
  uint8_t buf[16 + 80];

  if (magiclen > 80)
    return TWIST_ERR_INVAL;
  memcpy (buf, session_key, 16);
  memcpy (buf + 16, magic, magiclen);
  twist_md5 (buf, 16 + magiclen, out);
  gq_wipe (buf, sizeof buf);
  return TWIST_OK;
}

int
twist_ntlm_session_keys (const uint8_t session_key[16], uint8_t sign_c[16],
                         uint8_t seal_c[16], uint8_t sign_s[16],
                         uint8_t seal_s[16])
{
#define M(s) s, sizeof s
  if (session_key == NULL || sign_c == NULL || seal_c == NULL
      || sign_s == NULL || seal_s == NULL)
    return TWIST_ERR_INVAL;
  derive_key (session_key,
              M ("session key to client-to-server signing key magic constant"),
              sign_c);
  derive_key (session_key,
              M ("session key to client-to-server sealing key magic constant"),
              seal_c);
  derive_key (session_key,
              M ("session key to server-to-client signing key magic constant"),
              sign_s);
  derive_key (session_key,
              M ("session key to server-to-client sealing key magic constant"),
              seal_s);
#undef M
  return TWIST_OK;
}

/* ---- Messages ---- */

static void
put16 (uint8_t *p, unsigned v)
{
  p[0] = (uint8_t) v;
  p[1] = (uint8_t) (v >> 8);
}

static void
put32 (uint8_t *p, uint32_t v)
{
  put16 (p, v & 0xffff);
  put16 (p + 2, v >> 16);
}

static unsigned
get16 (const uint8_t *p)
{
  return (unsigned) p[0] | ((unsigned) p[1] << 8);
}

static uint32_t
get32 (const uint8_t *p)
{
  return (uint32_t) get16 (p) | ((uint32_t) get16 (p + 2) << 16);
}

/* A security buffer: length, the same again as the maximum, and the offset.  */
static void
put_field (uint8_t *p, size_t len, size_t off)
{
  put16 (p, (unsigned) len);
  put16 (p + 2, (unsigned) len);
  put32 (p + 4, (uint32_t) off);
}

static const uint8_t sig[8] = { 'N', 'T', 'L', 'M', 'S', 'S', 'P', 0 };

/* The version structure: nothing that is of use to a server.  */
static void
put_version (uint8_t *p)
{
  memset (p, 0, 8);
  p[7] = 0x0f;
}

struct twist_ntlm *
twist_ntlm_new (const char *domain, const char *user, const char *password,
                const char *host, const struct twist_ntlm_rand *rnd)
{
  struct twist_ntlm *n;
  char spn[300];
  size_t i;

  if (user == NULL || user[0] == 0 || password == NULL || host == NULL
      || strlen (host) + 6 >= sizeof spn)
    return NULL;
  if (domain == NULL)
    domain = "";
  n = calloc (1, sizeof *n);
  if (n == NULL)
    return NULL;
  if (rnd != NULL)
    n->rnd = *rnd;
  snprintf (spn, sizeof spn, "cifs/%s", host);
  if (twist_ntlm_ntowfv2 (user, domain, password, n->respkey) != TWIST_OK
      || twist_utf16le_from_utf8 (domain, strlen (domain), 0, n->domain,
                                  sizeof n->domain, &n->domlen) != TWIST_OK
      || twist_utf16le_from_utf8 (user, strlen (user), 0, n->user,
                                  sizeof n->user, &n->userlen) != TWIST_OK
      || twist_utf16le_from_utf8 (spn, strlen (spn), 0, n->target,
                                  sizeof n->target, &n->targetlen) != TWIST_OK)
    {
      twist_ntlm_free (n);
      return NULL;
    }
  for (i = 0; i < sizeof spn; i++)
    spn[i] = 0;
  return n;
}

void
twist_ntlm_free (struct twist_ntlm *n)
{
  if (n == NULL)
    return;
  gq_wipe (n, sizeof *n);
  free (n);
}

static int
random_bytes (struct twist_ntlm *n, uint8_t *buf, size_t len)
{
  if (n->rnd.fill != NULL)
    return n->rnd.fill (n->rnd.user, buf, len) == 0 ? TWIST_OK
                                                      : TWIST_ERR_AUTH;
  return gq_random (buf, len) == GQ_OK ? TWIST_OK : TWIST_ERR_AUTH;
}

int
twist_ntlm_negotiate (struct twist_ntlm *n, uint8_t *out, size_t cap,
                      size_t *len)
{
  if (n == NULL || out == NULL || len == NULL || n->state != S_NEW)
    return TWIST_ERR_INVAL;
  if (cap < NTLM_NEGOTIATE_LEN)
    return TWIST_ERR_INVAL;
  memset (n->neg, 0, sizeof n->neg);
  memcpy (n->neg, sig, 8);
  put32 (n->neg + 8, 1);
  put32 (n->neg + 12, F_OFFERED);
  put_field (n->neg + 16, 0, NTLM_NEGOTIATE_LEN);	/* Domain.  */
  put_field (n->neg + 24, 0, NTLM_NEGOTIATE_LEN);	/* Workstation.  */
  put_version (n->neg + 32);
  memcpy (out, n->neg, NTLM_NEGOTIATE_LEN);
  *len = NTLM_NEGOTIATE_LEN;
  n->state = S_NEGOTIATED;
  return TWIST_OK;
}

int
twist_ntlm_feed (struct twist_ntlm *n, const uint8_t *data, size_t len)
{
  if (n == NULL || (data == NULL && len > 0))
    return TWIST_ERR_INVAL;
  if (n->state != S_NEGOTIATED && n->state != S_FED)
    return TWIST_ERR_INVAL;
  if (len > sizeof n->chal - n->chal_len)
    {
      n->state = S_FAILED;
      return TWIST_ERR_AUTH;
    }
  if (len > 0)
    memcpy (n->chal + n->chal_len, data, len);
  n->chal_len += len;
  n->state = S_FED;
  return TWIST_OK;
}

/* A security buffer inside the message: it has to be there, and past the
   fixed part.  */
static int
field_ok (const uint8_t *p, size_t msglen, size_t minoff, size_t *off,
          size_t *len)
{
  size_t l = get16 (p), o = get32 (p + 4);

  if (l == 0)
    {
      *off = 0;
      *len = 0;
      return 1;
    }
  if (o < minoff || o > msglen || l > msglen - o)
    return 0;
  *off = o;
  *len = l;
  return 1;
}

int
twist_ntlm_challenge_end (struct twist_ntlm *n)
{
  const uint8_t *m;
  size_t len, minoff, off, l, p;
  int have_time = 0;

  if (n == NULL || n->state != S_FED)
    return TWIST_ERR_INVAL;
  m = n->chal;
  len = n->chal_len;
  n->state = S_FAILED;
  if (len < 48 || memcmp (m, sig, 8) != 0 || get32 (m + 8) != 2)
    return TWIST_ERR_AUTH;
  n->flags = get32 (m + 20);
  if ((n->flags & F_REQUIRED) != F_REQUIRED)
    return TWIST_ERR_AUTH;
  minoff = (n->flags & F_VERSION) != 0 ? 56 : 48;
  if (len < minoff)
    return TWIST_ERR_AUTH;
  if (!field_ok (m + 12, len, minoff, &off, &l)
      || !field_ok (m + 40, len, minoff, &n->ti_off, &n->ti_len))
    return TWIST_ERR_AUTH;
  if (n->ti_len == 0 || n->ti_len > NTLM_TI_MAX)
    return TWIST_ERR_AUTH;
  memcpy (n->srv_chal, m + 24, 8);
  /* The target information is a list of pairs that ends with the end marker
     at the very end.  */
  p = n->ti_off;
  for (;;)
    {
      unsigned id, vl;

      if (n->ti_off + n->ti_len - p < 4)
        return TWIST_ERR_AUTH;
      id = get16 (m + p);
      vl = get16 (m + p + 2);
      p += 4;
      if (id == AV_EOL)
        {
          if (vl != 0 || p != n->ti_off + n->ti_len)
            return TWIST_ERR_AUTH;
          break;
        }
      if (vl > n->ti_off + n->ti_len - p)
        return TWIST_ERR_AUTH;
      if (id == AV_TIMESTAMP)
        {
          if (vl != 8)
            return TWIST_ERR_AUTH;
          if (!have_time)
            memcpy (n->timestamp, m + p, 8);
          have_time = 1;
        }
      else if (id == AV_FLAGS && vl != 4)
        return TWIST_ERR_AUTH;
      p += vl;
    }
  if (!have_time)
    return TWIST_ERR_AUTH;
  n->state = S_PARSED;
  return TWIST_OK;
}

int
twist_ntlm_challenge (struct twist_ntlm *n, const uint8_t *data, size_t len)
{
  int rc = twist_ntlm_feed (n, data, len);

  return rc != TWIST_OK ? rc : twist_ntlm_challenge_end (n);
}

/* The client challenge blob (MS-NLMP 2.2.2.7) around the server's pairs,
   changed as 2.2.2.1 asks: the flags pair says there is a MIC, the target
   name is ours, and a channel binding or target name the server sent is
   dropped.  */
static size_t
build_temp (const struct twist_ntlm *n, const uint8_t client_chal[8],
            uint8_t *t)
{
  const uint8_t *m = n->chal + n->ti_off;
  size_t end = n->ti_len, p = 0, o = 0;
  int flags_done = 0;

  t[o++] = 1;
  t[o++] = 1;
  memset (t + o, 0, 6);
  o += 6;
  memcpy (t + o, n->timestamp, 8);
  o += 8;
  memcpy (t + o, client_chal, 8);
  o += 8;
  memset (t + o, 0, 4);
  o += 4;
  while (p + 4 <= end)
    {
      unsigned id = get16 (m + p), vl = get16 (m + p + 2);

      if (id == AV_EOL)
        break;
      if (id == AV_FLAGS)
        {
          put16 (t + o, AV_FLAGS);
          put16 (t + o + 2, 4);
          put32 (t + o + 4, get32 (m + p + 4) | 2u);
          o += 8;
          flags_done = 1;
        }
      else if (id != AV_TARGET_NAME && id != AV_CHANNEL)
        {
          memcpy (t + o, m + p, 4 + (size_t) vl);
          o += 4 + (size_t) vl;
        }
      p += 4 + (size_t) vl;
    }
  if (!flags_done)
    {
      put16 (t + o, AV_FLAGS);
      put16 (t + o + 2, 4);
      put32 (t + o + 4, 2);
      o += 8;
    }
  put16 (t + o, AV_TARGET_NAME);
  put16 (t + o + 2, (unsigned) n->targetlen);
  memcpy (t + o + 4, n->target, n->targetlen);
  o += 4 + n->targetlen;
  memset (t + o, 0, 8);		/* The end marker, then the last four.  */
  o += 8;
  return o;
}

int
twist_ntlm_authenticate (struct twist_ntlm *n, uint8_t *out, size_t cap,
                         size_t *len)
{
  uint8_t cchal[8], proof[16], base[16], enc[16], mic[16];
  uint8_t temp[NTLM_TI_MAX + 1024];
  struct twist_rc4 rc4;
  uint8_t *cat;
  size_t templen, ntlen, pos, dom, usr, wks, lm, nt, key;
  uint32_t flags;
  int rc;

  if (n == NULL || out == NULL || len == NULL || n->state != S_PARSED)
    return TWIST_ERR_INVAL;
  templen = n->ti_len + 8 + n->targetlen + 4 + 28 + 4 + 8;
  if (templen > sizeof temp)
    return TWIST_ERR_AUTH;
  ntlen = 16 + templen;
  if (cap < NTLM_AUTH_HDR + n->domlen + n->userlen + 24 + ntlen + 16)
    return TWIST_ERR_INVAL;
  n->state = S_FAILED;
  if (random_bytes (n, cchal, 8) != TWIST_OK
      || random_bytes (n, n->session_key, 16) != TWIST_OK)
    return TWIST_ERR_AUTH;
  templen = build_temp (n, cchal, temp);
  ntlen = 16 + templen;
  if (twist_ntlm_v2_response (n->respkey, n->srv_chal, temp, templen, proof,
                              base) != TWIST_OK)
    return TWIST_ERR_AUTH;
  /* The key exchange key is the session base key; the exported session key is
     random and goes to the server under RC4.  */
  twist_rc4_init (&rc4, base, 16);
  twist_rc4_crypt (&rc4, n->session_key, enc, 16);
  twist_rc4_wipe (&rc4);

  flags = (n->flags & F_OFFERED) | F_VERSION;
  dom = NTLM_AUTH_HDR;
  usr = dom + n->domlen;
  wks = usr + n->userlen;
  lm = wks;
  nt = lm + 24;
  key = nt + ntlen;
  pos = key + 16;
  memset (out, 0, NTLM_AUTH_HDR);
  memcpy (out, sig, 8);
  put32 (out + 8, 3);
  put_field (out + 12, 24, lm);
  put_field (out + 20, ntlen, nt);
  put_field (out + 28, n->domlen, dom);
  put_field (out + 36, n->userlen, usr);
  put_field (out + 44, 0, wks);
  put_field (out + 52, 16, key);
  put32 (out + 60, flags);
  put_version (out + 64);
  memcpy (out + dom, n->domain, n->domlen);
  memcpy (out + usr, n->user, n->userlen);
  memset (out + lm, 0, 24);
  memcpy (out + nt, proof, 16);
  memcpy (out + nt + 16, temp, templen);
  memcpy (out + key, enc, 16);

  /* The MIC covers the three messages, with its own field zero.  */
  cat = malloc (NTLM_NEGOTIATE_LEN + n->chal_len + pos);
  if (cat == NULL)
    return TWIST_ERR_NOMEM;
  memcpy (cat, n->neg, NTLM_NEGOTIATE_LEN);
  memcpy (cat + NTLM_NEGOTIATE_LEN, n->chal, n->chal_len);
  memcpy (cat + NTLM_NEGOTIATE_LEN + n->chal_len, out, pos);
  rc = twist_hmac_md5 (n->session_key, 16, cat,
                       NTLM_NEGOTIATE_LEN + n->chal_len + pos, mic);
  free (cat);
  if (rc != TWIST_OK)
    return TWIST_ERR_AUTH;
  memcpy (out + 72, mic, 16);

  twist_ntlm_session_keys (n->session_key, n->sign_c, mic, n->sign_s, base);
  twist_rc4_init (&n->seal_c, mic, 16);
  twist_rc4_init (&n->seal_s, base, 16);
  gq_wipe (mic, sizeof mic);
  gq_wipe (base, sizeof base);
  gq_wipe (enc, sizeof enc);
  gq_wipe (proof, sizeof proof);
  gq_wipe (n->respkey, sizeof n->respkey);
  *len = pos;
  n->state = S_DONE;
  return TWIST_OK;
}

int
twist_ntlm_session_key (const struct twist_ntlm *n, uint8_t key[16])
{
  if (n == NULL || key == NULL || n->state != S_DONE)
    return TWIST_ERR_INVAL;
  memcpy (key, n->session_key, 16);
  return TWIST_OK;
}

/* The signature of MS-NLMP 3.4.4.2 for NTLMv2 with key exchange: a version, the
   first eight bytes of an HMAC-MD5 of the sequence number and the message
   under the signing key, sealed by the RC4 stream of that direction, and the
   sequence number.  */
static int
mac (const uint8_t signkey[16], struct twist_rc4 *seal, uint32_t seq,
     const void *msg, size_t len, uint8_t out[16])
{
  uint8_t s[4], h[16];

  put32 (s, seq);
  if (hmac2 (signkey, 16, s, 4, msg, len, h) != TWIST_OK)
    return TWIST_ERR_AUTH;
  put32 (out, 1);
  twist_rc4_crypt (seal, h, out + 4, 8);
  put32 (out + 12, seq);
  return TWIST_OK;
}

int
twist_ntlm_sign (struct twist_ntlm *n, const void *msg, size_t len,
                 uint8_t out[16])
{
  if (n == NULL || out == NULL || (msg == NULL && len > 0) || n->state != S_DONE
      || n->seq_c == 0xffffffffu)
    return TWIST_ERR_INVAL;
  if (mac (n->sign_c, &n->seal_c, n->seq_c, msg, len, out) != TWIST_OK)
    return TWIST_ERR_AUTH;
  n->seq_c++;
  return TWIST_OK;
}

int
twist_ntlm_verify (struct twist_ntlm *n, const void *msg, size_t len,
                   const uint8_t signature[16])
{
  uint8_t want[16];

  if (n == NULL || signature == NULL || (msg == NULL && len > 0)
      || n->state != S_DONE || n->seq_s == 0xffffffffu)
    return TWIST_ERR_INVAL;
  if (mac (n->sign_s, &n->seal_s, n->seq_s, msg, len, want) != TWIST_OK)
    return TWIST_ERR_AUTH;
  n->seq_s++;
  return gq_ct_equal (want, signature, 16) ? TWIST_OK : TWIST_ERR_AUTH;
}
