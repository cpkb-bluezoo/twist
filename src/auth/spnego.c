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

#include <stdlib.h>
#include <string.h>

/* A SPNEGO initiator (RFC 4178) for SMB2 SESSION_SETUP, with NTLMSSP as the
   only mechanism.  It owns the NTLM client (src/auth/ntlm.c).

     start     NegTokenInit: mechTypes holding NTLMSSP alone, and the NTLM
               NEGOTIATE as the mechToken.
     step 1    the server's NegTokenResp: accept-incomplete, the mechanism
               NTLMSSP and the CHALLENGE.  The reply is a NegTokenResp with
               the AUTHENTICATE as responseToken and, over the DER of the
               mechanism list, the NTLM message signature as mechListMIC.
     step 2    the server's last NegTokenResp: accept-completed and its
               mechListMIC, which is checked.  Nothing is sent.

   The server's tokens are read with the strict DER reader.  A reject, a
   mechanism other than NTLMSSP, a state out of its turn, a field repeated or
   out of order, anything else in a token, a missing or bad mechListMIC: all
   are refused with TWIST_ERR_AUTH.  A token is fed whole or in pieces.  */

#define NTLM_OID_BODY "\x2b\x06\x01\x04\x01\x82\x37\x02\x02\x0a"
#define SPNEGO_OID_BODY "\x2b\x06\x01\x05\x05\x02"

/* The DER of the mechanism list, which the mechListMIC is made over.  */
static const uint8_t mech_list[] = {
  0x30, 0x0c, 0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02,
  0x02, 0x0a
};

#define SPNEGO_TOKEN_MAX 4352		/* Over the NTLM CHALLENGE bound.  */

enum
{
  S_NEW,
  S_INIT_SENT,
  S_AUTH_SENT,
  S_DONE,
  S_FAILED
};

enum
{
  FIELD_NONE = -1,
  FIELD_STATE = 0,
  FIELD_MECH,
  FIELD_TOKEN,
  FIELD_MIC
};

struct twist_spnego
{
  struct twist_ntlm *ntlm;
  int state;
  struct twist_der_events ev;
  struct twist_der_reader rd;
  uint8_t scratch[SPNEGO_TOKEN_MAX];
  int reading;			/* A token is being fed.  */
  int bad;			/* The token broke a rule.  */
  int saw_resp, saw_seq;
  int field, last_field, field_got;
  int have[4];
  int neg_state;
  uint8_t mech[16];
  size_t mech_len;
  uint8_t mic[16];
  size_t mic_len;
};

static int
bad (struct twist_spnego *s)
{
  s->bad = 1;
  return TWIST_ERR_AUTH;
}

/* A constructed element of a NegTokenResp: the choice, its sequence, and the
   context-tagged fields in order, each at most once.  */
static int
on_start (void *user, uint8_t tag, size_t len)
{
  struct twist_spnego *s = user;
  int depth = s->rd.depth;

  (void) len;
  if (depth == 1)
    {
      if (tag != 0xa1 || s->saw_resp)
        return bad (s);
      s->saw_resp = 1;
    }
  else if (depth == 2)
    {
      if (tag != 0x30 || s->saw_seq)
        return bad (s);
      s->saw_seq = 1;
    }
  else if (depth == 3)
    {
      int f = (int) tag - 0xa0;

      if (f < 0 || f > FIELD_MIC || f <= s->last_field)
        return bad (s);
      s->field = f;
      s->last_field = f;
      s->field_got = 0;
    }
  else
    return bad (s);
  return TWIST_OK;
}

static int
on_end (void *user, uint8_t tag)
{
  struct twist_spnego *s = user;

  (void) tag;
  /* The end of a field, which held exactly one value.  */
  if (s->rd.depth == 2)
    {
      if (s->field_got != 1)
        return bad (s);
      s->field = FIELD_NONE;
    }
  return TWIST_OK;
}

static int
on_prim (void *user, uint8_t tag, const uint8_t *val, size_t len)
{
  struct twist_spnego *s = user;

  if (s->rd.depth != 3 || s->field == FIELD_NONE || s->field_got)
    return bad (s);
  s->field_got = 1;
  s->have[s->field] = 1;
  switch (s->field)
    {
    case FIELD_STATE:
      if (tag != 0x0a || len != 1 || val[0] > 3)
        return bad (s);
      s->neg_state = val[0];
      return TWIST_OK;
    case FIELD_MECH:
      if (tag != 0x06 || len > sizeof s->mech)
        return bad (s);
      memcpy (s->mech, val, len);
      s->mech_len = len;
      return TWIST_OK;
    case FIELD_TOKEN:
      /* The CHALLENGE is the only token a server sends, and only once.  */
      if (tag != 0x04 || s->state != S_INIT_SENT)
        return bad (s);
      if (twist_ntlm_feed (s->ntlm, val, len) != TWIST_OK)
        return bad (s);
      return TWIST_OK;
    default:			/* FIELD_MIC */
      if (tag != 0x04 || len != sizeof s->mic)
        return bad (s);
      memcpy (s->mic, val, len);
      s->mic_len = len;
      return TWIST_OK;
    }
}

static void
on_failure (void *user, int err)
{
  struct twist_spnego *s = user;

  (void) err;
  s->bad = 1;
}

struct twist_spnego *
twist_spnego_new (const char *domain, const char *user, const char *password,
                  const char *host, const struct twist_ntlm_rand *rnd)
{
  struct twist_spnego *s = calloc (1, sizeof *s);

  if (s == NULL)
    return NULL;
  s->ntlm = twist_ntlm_new (domain, user, password, host, rnd);
  if (s->ntlm == NULL)
    {
      free (s);
      return NULL;
    }
  s->ev.user = s;
  s->ev.start = on_start;
  s->ev.end = on_end;
  s->ev.prim = on_prim;
  s->ev.failure = on_failure;
  return s;
}

void
twist_spnego_free (struct twist_spnego *s)
{
  if (s == NULL)
    return;
  twist_ntlm_free (s->ntlm);
  gq_wipe (s, sizeof *s);
  free (s);
}

int
twist_spnego_start (struct twist_spnego *s, uint8_t *out, size_t cap,
                    size_t *len)
{
  uint8_t neg[64];
  size_t neglen, m0, m1, m2, m3, m4;
  struct twist_der_writer w;

  if (s == NULL || out == NULL || len == NULL || s->state != S_NEW)
    return TWIST_ERR_INVAL;
  if (twist_ntlm_negotiate (s->ntlm, neg, sizeof neg, &neglen) != TWIST_OK)
    return TWIST_ERR_AUTH;
  twist_der_writer_init (&w, out, cap, 1);
  m0 = twist_der_begin (&w, 0x60);
  twist_der_put (&w, 0x06, SPNEGO_OID_BODY, sizeof SPNEGO_OID_BODY - 1);
  m1 = twist_der_begin (&w, 0xa0);
  m2 = twist_der_begin (&w, 0x30);
  m3 = twist_der_begin (&w, 0xa0);
  m4 = twist_der_begin (&w, 0x30);
  twist_der_put (&w, 0x06, NTLM_OID_BODY, sizeof NTLM_OID_BODY - 1);
  twist_der_end (&w, m4);
  twist_der_end (&w, m3);
  m3 = twist_der_begin (&w, 0xa2);
  twist_der_put (&w, 0x04, neg, neglen);
  twist_der_end (&w, m3);
  twist_der_end (&w, m2);
  twist_der_end (&w, m1);
  twist_der_end (&w, m0);
  if (w.err)
    return TWIST_ERR_INVAL;
  *len = w.n;
  s->state = S_INIT_SENT;
  return TWIST_OK;
}

int
twist_spnego_feed (struct twist_spnego *s, const uint8_t *data, size_t len)
{
  if (s == NULL || (data == NULL && len > 0))
    return TWIST_ERR_INVAL;
  if (s->state != S_INIT_SENT && s->state != S_AUTH_SENT)
    return TWIST_ERR_INVAL;
  if (!s->reading)
    {
      s->reading = 1;
      s->bad = 0;
      s->saw_resp = s->saw_seq = 0;
      s->field = FIELD_NONE;
      s->last_field = FIELD_NONE;
      s->field_got = 0;
      memset (s->have, 0, sizeof s->have);
      s->mic_len = s->mech_len = 0;
      twist_der_reader_init (&s->rd, &s->ev, s->scratch, sizeof s->scratch, 1);
      s->rd.max_len = sizeof s->scratch + 64;
    }
  if (s->bad)
    return TWIST_ERR_AUTH;
  twist_der_receive (&s->rd, data, len);
  return s->bad ? TWIST_ERR_AUTH : TWIST_OK;
}

static int
fail (struct twist_spnego *s)
{
  s->state = S_FAILED;
  s->reading = 0;
  return TWIST_ERR_AUTH;
}

int
twist_spnego_finish (struct twist_spnego *s, uint8_t *out, size_t cap,
                     size_t *outlen, int *done)
{
  uint8_t auth[5000], sig[16];
  size_t alen, m1, m2, m3;
  struct twist_der_writer w;

  if (s == NULL || outlen == NULL || done == NULL || !s->reading
      || (s->state != S_INIT_SENT && s->state != S_AUTH_SENT))
    return TWIST_ERR_INVAL;
  *outlen = 0;
  *done = 0;
  s->reading = 0;
  if (s->bad || !twist_der_idle (&s->rd) || !s->saw_resp || !s->saw_seq)
    return fail (s);
  /* The server's state, which has to be one it has not rejected with, and
     the mechanism, if it names one, which has to be ours.  */
  if (!s->have[FIELD_STATE] || s->neg_state == 2 || s->neg_state == 3)
    return fail (s);
  if (s->have[FIELD_MECH]
      && (s->mech_len != sizeof NTLM_OID_BODY - 1
          || memcmp (s->mech, NTLM_OID_BODY, s->mech_len) != 0))
    return fail (s);
  if (s->state == S_INIT_SENT)
    {
      if (s->neg_state != 1 || !s->have[FIELD_MECH] || !s->have[FIELD_TOKEN]
          || s->have[FIELD_MIC])
        return fail (s);
      if (out == NULL
          || twist_ntlm_challenge_end (s->ntlm) != TWIST_OK
          || twist_ntlm_authenticate (s->ntlm, auth, sizeof auth, &alen)
             != TWIST_OK
          || twist_ntlm_sign (s->ntlm, mech_list, sizeof mech_list, sig)
             != TWIST_OK)
        return fail (s);
      twist_der_writer_init (&w, out, cap, 1);
      m1 = twist_der_begin (&w, 0xa1);
      m2 = twist_der_begin (&w, 0x30);
      m3 = twist_der_begin (&w, 0xa0);
      twist_der_put_int (&w, 0x0a, 1);
      twist_der_end (&w, m3);
      m3 = twist_der_begin (&w, 0xa2);
      twist_der_put (&w, 0x04, auth, alen);
      twist_der_end (&w, m3);
      m3 = twist_der_begin (&w, 0xa3);
      twist_der_put (&w, 0x04, sig, sizeof sig);
      twist_der_end (&w, m3);
      twist_der_end (&w, m2);
      twist_der_end (&w, m1);
      gq_wipe (auth, sizeof auth);
      if (w.err)
        return fail (s);
      *outlen = w.n;
      s->state = S_AUTH_SENT;
      return TWIST_OK;
    }
  /* The server is done: it says so, sends no token, and signs the list.  */
  if (s->neg_state != 0 || s->have[FIELD_TOKEN] || !s->have[FIELD_MIC]
      || twist_ntlm_verify (s->ntlm, mech_list, sizeof mech_list, s->mic)
         != TWIST_OK)
    return fail (s);
  s->state = S_DONE;
  *done = 1;
  return TWIST_OK;
}

int
twist_spnego_step (struct twist_spnego *s, const uint8_t *in, size_t inlen,
                   uint8_t *out, size_t cap, size_t *outlen, int *done)
{
  int rc = twist_spnego_feed (s, in, inlen);

  if (rc != TWIST_OK)
    {
      if (s != NULL && s->state != S_NEW && s->state != S_DONE)
        fail (s);
      return rc;
    }
  return twist_spnego_finish (s, out, cap, outlen, done);
}

int
twist_spnego_session_key (const struct twist_spnego *s, uint8_t key[16])
{
  if (s == NULL || (s->state != S_AUTH_SENT && s->state != S_DONE))
    return TWIST_ERR_INVAL;
  return twist_ntlm_session_key (s->ntlm, key);
}
