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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* The NTLMv2 client.  The values come from MS-NLMP 4.2.4 where it has them
   (the NT hash, the proof, the session base key, the encrypted session key
   and the signing and sealing keys) and, for whole messages, from a separate
   implementation of the same specification in Python.  The random values are
   fixed through the hook.  */

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

static int
is_hex (const uint8_t *b, size_t n, const char *want)
{
  uint8_t w[8192];

  return unhex (want, w) == n && memcmp (b, w, n) == 0;
}

static const char hex_neg[] =
    "4e544c4d53535000010000001502886200000000280000000000000028000000000000000000000f";
static const char hex_chal[] =
    "4e544c4d53535000020000000c000c003800000015028a620123456789abcdef"
    "000000000000000030003000440000000a00614a0000000f5300450052005600"
    "4500520002000c0044004f004d00410049004e0001000c005300450052005600"
    "4500520007000800001122334455667700000000";
static const char hex_auth[] =
    "4e544c4d5353500003000000180018006c00000092009200840000000c000c00"
    "580000000800080064000000000000006c000000100010001601000015028862"
    "000000000000000f6c6b23556cf5b10c5db06e0e39be147f44006f006d006100"
    "69006e0055007300650072000000000000000000000000000000000000000000"
    "00000000af266edc3a241ce8fc95c4d4bb78cf78010100000000000000112233"
    "44556677aaaaaaaaaaaaaaaa0000000002000c0044004f004d00410049004e00"
    "01000c0053004500520056004500520007000800001122334455667706000400"
    "020000000900260063006900660073002f007300650072007600650072002e00"
    "6500780061006d0070006c00650000000000000000006b5baf876b39edafc7e6"
    "588026d6d748";
static const char hex_chal2[] =
    "4e544c4d53535000020000000c000c003000000015028a600123456789abcdef"
    "0000000000000000420042003c00000053004500520056004500520002000c00"
    "44004f004d00410049004e000700080000112233445566770600040000000000"
    "0a0010000000000000000000000000000000000009000200780000000000";
static const char hex_auth2[] =
    "4e544c4d5353500003000000180018006c00000082008200840000000c000c00"
    "580000000800080064000000000000006c000000100010000601000015028862"
    "000000000000000f723fc62cc4a470ed96d2d781df92304944006f006d006100"
    "69006e0055007300650072000000000000000000000000000000000000000000"
    "000000005233ae52b9ad034d6117f88f0433c4cd010100000000000000112233"
    "44556677aaaaaaaaaaaaaaaa0000000002000c0044004f004d00410049004e00"
    "0700080000112233445566770600040002000000090026006300690066007300"
    "2f007300650072007600650072002e006500780061006d0070006c0065000000"
    "00000000000077d1b309b698e39552b32644d7792e6c";

/* The two values that are random, fixed: the client challenge, then the
   exported session key.  */
static int
fixed_fill (void *user, void *buf, size_t len)
{
  int *calls = user;

  (*calls)++;
  memset (buf, len == 8 ? 0xaa : 0x55, len);
  return 0;
}

static int
failing_fill (void *user, void *buf, size_t len)
{
  (void) user;
  (void) buf;
  (void) len;
  return -1;
}

static struct twist_ntlm *
make (int *calls)
{
  static struct twist_ntlm_rand rnd;

  rnd.fill = fixed_fill;
  rnd.user = calls;
  return twist_ntlm_new ("Domain", "User", "Password", "server.example", &rnd);
}

static void
test_ms_nlmp_examples (void)
{
  uint8_t key[16], proof[16], base[16], temp[256], sk[16], enc[16];
  uint8_t sc[16], ec[16], ss[16], es[16];
  static const uint8_t srv[8] = { 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef };
  struct twist_rc4 c;
  size_t n;

  check (twist_ntlm_ntowfv2 ("User", "Domain", "Password", key) == TWIST_OK
         && is_hex (key, 16, "0c868a403bfd7a93a3001ef22ef02e3f"),
         "ntlm: NTOWFv2 of MS-NLMP 4.2.4");
  n = unhex ("01010000000000000000000000000000aaaaaaaaaaaaaaaa0000000002000c0044006f006d00610069006e0001000c005300650072007600650072000000000000000000", temp);
  check (twist_ntlm_v2_response (key, srv, temp, n, proof, base) == TWIST_OK
         && is_hex (proof, 16, "68cd0ab851e51c96aabc927bebef6a1c"),
         "ntlm: NTProofStr of MS-NLMP 4.2.4");
  check (is_hex (base, 16, "8de40ccadbc14a82f15cb0ad0de95ca3"),
         "ntlm: SessionBaseKey of MS-NLMP 4.2.4");
  memset (sk, 0x55, 16);
  twist_rc4_init (&c, base, 16);
  twist_rc4_crypt (&c, sk, enc, 16);
  check (is_hex (enc, 16, "c5dad2544fc9799094ce1ce90bc9d03e"),
         "ntlm: EncryptedRandomSessionKey of MS-NLMP 4.2.4");
  check (twist_ntlm_session_keys (sk, sc, ec, ss, es) == TWIST_OK
         && is_hex (sc, 16, "4788dc861b4782f35d43fd98fe1a2d39")
         && is_hex (ec, 16, "59f600973cc4960a25480a7c196e4c58"),
         "ntlm: the client signing and sealing keys of MS-NLMP 4.2.4");
}

static void
test_text (void)
{
  uint8_t out[64];
  size_t n;

  check (twist_utf16le_from_utf8 ("aé€", 6, 0, out, sizeof out, &n) == TWIST_OK
         && n == 6 && is_hex (out, 6, "6100e900ac20"),
         "utf-16: ASCII, Latin-1 and the BMP");
  check (twist_utf16le_from_utf8 ("\xf0\x9f\x98\x80", 4, 0, out, sizeof out, &n)
         == TWIST_OK && n == 4 && is_hex (out, 4, "3dd800de"),
         "utf-16: a code point above the BMP is a surrogate pair");
  check (twist_utf16le_from_utf8 ("user\xc3\xa9\xd0\xb4", 8, 1, out, sizeof out, &n)
         == TWIST_OK && is_hex (out, n, "5500530045005200" "c900" "1404"),
         "utf-16: upper-casing Latin and Cyrillic");
  check (twist_utf16le_from_utf8 ("\xc0\xaf", 2, 0, out, sizeof out, &n)
         == TWIST_ERR_INVAL, "utf-16: an overlong form is refused");
  check (twist_utf16le_from_utf8 ("\xed\xa0\x80", 3, 0, out, sizeof out, &n)
         == TWIST_ERR_INVAL, "utf-16: a surrogate is refused");
  check (twist_utf16le_from_utf8 ("\xe2\x82", 2, 0, out, sizeof out, &n)
         == TWIST_ERR_INVAL, "utf-16: a cut-off sequence is refused");
  check (twist_utf16le_from_utf8 ("abcd", 4, 0, out, 7, &n) == TWIST_ERR_INVAL,
         "utf-16: output that does not fit is refused");
}

static void
test_flow (void)
{
  uint8_t neg[64], chal[1024], auth[1024], want[1024], sk[16], sig[16];
  size_t nl, cl, al, wl, i;
  int calls = 0;
  struct twist_ntlm *n = make (&calls);
  struct twist_ntlm *m;

  check (n != NULL, "ntlm: a client");
  check (twist_ntlm_negotiate (n, neg, sizeof neg, &nl) == TWIST_OK
         && nl == 40 && is_hex (neg, nl, hex_neg),
         "ntlm: NEGOTIATE with the flags that are asked for");
  cl = unhex (hex_chal, chal);
  check (twist_ntlm_challenge (n, chal, cl) == TWIST_OK,
         "ntlm: a CHALLENGE is taken");
  check (calls == 0, "ntlm: nothing random is drawn before AUTHENTICATE");
  check (twist_ntlm_authenticate (n, auth, sizeof auth, &al) == TWIST_OK,
         "ntlm: AUTHENTICATE");
  wl = unhex (hex_auth, want);
  check (al == wl && memcmp (auth, want, wl) == 0,
         "ntlm: AUTHENTICATE is the reference message, MIC included");
  check (calls == 2, "ntlm: two random values: the challenge and the key");
  check (twist_ntlm_session_key (n, sk) == TWIST_OK
         && is_hex (sk, 16, "55555555555555555555555555555555"),
         "ntlm: the exported session key");
  /* The LM response is all zeros, and the workstation and flags are as
     asked for.  */
  {
    static const uint8_t zeros[24];

    check (auth[12] == 24 && memcmp (auth + 88 + 12 + 8, zeros, 24) == 0,
           "ntlm: the LM response is 24 zero bytes");
  }
  /* Signatures: client to server, then server to client.  */
  check (twist_ntlm_sign (n, "hello", 5, sig) == TWIST_OK
         && is_hex (sig, 16, "01000000068e312923be79ab00000000"),
         "ntlm: signature, sequence 0");
  check (twist_ntlm_sign (n, "world!", 6, sig) == TWIST_OK
         && is_hex (sig, 16, "0100000058eb599430a9ea1d01000000"),
         "ntlm: signature, sequence 1");
  {
    uint8_t s0[16], s1[16];

    unhex ("0100000071b445bc23df24d600000000", s0);
    unhex ("0100000041a6b8d9bcc023ac01000000", s1);
    check (twist_ntlm_verify (n, "server says", 11, s0) == TWIST_OK,
           "ntlm: the server's signature, sequence 0, is accepted");
    s1[5] ^= 1;
    check (twist_ntlm_verify (n, "again", 5, s1) == TWIST_ERR_AUTH,
           "ntlm: a changed signature is refused");
  }
  m = make (&calls);
  twist_ntlm_negotiate (m, neg, sizeof neg, &nl);
  twist_ntlm_challenge (m, chal, cl);
  twist_ntlm_authenticate (m, auth, sizeof auth, &al);
  {
    uint8_t s0[16];

    unhex ("0100000071b445bc23df24d600000000", s0);
    check (twist_ntlm_verify (m, "server SAYS", 11, s0) == TWIST_ERR_AUTH,
           "ntlm: a changed message is refused");
  }
  twist_ntlm_free (m);
  twist_ntlm_free (n);

  /* The same CHALLENGE in pieces of one byte, and the same answer.  */
  n = make (&calls);
  twist_ntlm_negotiate (n, neg, sizeof neg, &nl);
  for (i = 0; i < cl; i++)
    check (twist_ntlm_feed (n, chal + i, 1) == TWIST_OK, "ntlm: one byte");
  check (twist_ntlm_challenge_end (n) == TWIST_OK
         && twist_ntlm_authenticate (n, auth, sizeof auth, &al) == TWIST_OK
         && al == wl && memcmp (auth, want, wl) == 0,
         "ntlm: a CHALLENGE in one-byte pieces gives the same AUTHENTICATE");
  twist_ntlm_free (n);

  /* A server's flags pair is raised, its channel bindings and target name are
     dropped, and a CHALLENGE without a version structure is laid out so.  */
  n = make (&calls);
  twist_ntlm_negotiate (n, neg, sizeof neg, &nl);
  cl = unhex (hex_chal2, chal);
  wl = unhex (hex_auth2, want);
  check (twist_ntlm_challenge (n, chal, cl) == TWIST_OK
         && twist_ntlm_authenticate (n, auth, sizeof auth, &al) == TWIST_OK
         && al == wl && memcmp (auth, want, wl) == 0,
         "ntlm: the pairs are rewritten for the MIC and the target name");
  twist_ntlm_free (n);
}

/* A CHALLENGE altered by CHANGE is refused.  */
static void
refused_after (const char *what, size_t at, uint8_t mask, int set)
{
  uint8_t neg[64], chal[1024];
  size_t nl, cl = unhex (hex_chal, chal);
  int calls = 0;
  struct twist_ntlm *n = make (&calls);

  twist_ntlm_negotiate (n, neg, sizeof neg, &nl);
  if (set)
    chal[at] |= mask;
  else
    chal[at] &= (uint8_t) ~mask;
  check (twist_ntlm_challenge (n, chal, cl) == TWIST_ERR_AUTH, what);
  twist_ntlm_free (n);
}

static void
test_refusals (void)
{
  uint8_t neg[64], chal[1024], auth[1024];
  size_t nl, cl, al, i, ti = 0;
  int calls = 0;
  struct twist_ntlm *n;

  /* The flags are at 20: 0x628a0215, little-endian.  */
  refused_after ("ntlm: a CHALLENGE without 128-bit keys is refused", 23, 0x20, 0);
  refused_after ("ntlm: a CHALLENGE without key exchange is refused", 23, 0x40, 0);
  refused_after ("ntlm: a CHALLENGE without extended session security is refused",
                 22, 0x08, 0);
  refused_after ("ntlm: a CHALLENGE without target info is refused", 22, 0x80, 0);
  refused_after ("ntlm: a CHALLENGE without signing is refused", 20, 0x10, 0);
  refused_after ("ntlm: a CHALLENGE without unicode is refused", 20, 0x01, 0);
  refused_after ("ntlm: a CHALLENGE of the wrong type is refused", 8, 0x01, 1);
  refused_after ("ntlm: a CHALLENGE with a bad signature is refused", 0, 0x01, 1);
  cl = unhex (hex_chal, chal);
  for (i = 0; i + 4 < cl; i++)
    if (chal[i] == 0x07 && chal[i + 1] == 0 && chal[i + 2] == 8)
      ti = i;
  check (ti > 0, "ntlm: the timestamp pair is found in the test CHALLENGE");

  /* No timestamp: the pair's id changed to one that is not a timestamp.  */
  n = make (&calls);
  twist_ntlm_negotiate (n, neg, sizeof neg, &nl);
  chal[ti] = 0x0b;
  check (twist_ntlm_challenge (n, chal, cl) == TWIST_ERR_AUTH,
         "ntlm: target info without a timestamp is refused");
  twist_ntlm_free (n);
  chal[ti] = 0x07;
  /* The target info does not end where the end marker is.  */
  n = make (&calls);
  twist_ntlm_negotiate (n, neg, sizeof neg, &nl);
  chal[cl - 4] = 0x0b;
  check (twist_ntlm_challenge (n, chal, cl) == TWIST_ERR_AUTH,
         "ntlm: target info with no end marker is refused");
  twist_ntlm_free (n);
  chal[cl - 4] = 0;
  /* An offset past the end.  */
  n = make (&calls);
  twist_ntlm_negotiate (n, neg, sizeof neg, &nl);
  chal[44] = 0xff;
  chal[45] = 0x7f;
  check (twist_ntlm_challenge (n, chal, cl) == TWIST_ERR_AUTH,
         "ntlm: a target info offset past the message is refused");
  twist_ntlm_free (n);
  chal[44] = 0x4a;		/* Back to what it was.  */
  chal[45] = 0;
  /* Every prefix of a good CHALLENGE is refused, fed whole and in pieces.  */
  for (i = 0; i < cl; i++)
    {
      int rc;

      n = make (&calls);
      twist_ntlm_negotiate (n, neg, sizeof neg, &nl);
      rc = twist_ntlm_challenge (n, chal, i);
      if (rc != TWIST_ERR_AUTH)
        break;
      twist_ntlm_free (n);
    }
  check (i == cl, "ntlm: no cut-off CHALLENGE is taken");

  /* Out of order, and too much.  */
  n = make (&calls);
  check (twist_ntlm_authenticate (n, auth, sizeof auth, &al) == TWIST_ERR_INVAL,
         "ntlm: AUTHENTICATE before NEGOTIATE is refused");
  check (twist_ntlm_challenge (n, chal, cl) == TWIST_ERR_INVAL,
         "ntlm: a CHALLENGE before NEGOTIATE is refused");
  twist_ntlm_negotiate (n, neg, sizeof neg, &nl);
  check (twist_ntlm_negotiate (n, neg, sizeof neg, &nl) == TWIST_ERR_INVAL,
         "ntlm: NEGOTIATE twice is refused");
  check (twist_ntlm_authenticate (n, auth, sizeof auth, &al) == TWIST_ERR_INVAL,
         "ntlm: AUTHENTICATE before a CHALLENGE is refused");
  check (twist_ntlm_sign (n, "x", 1, auth) == TWIST_ERR_INVAL,
         "ntlm: no signature before AUTHENTICATE");
  {
    static uint8_t big[2048];
    int rc = TWIST_OK, k;

    for (k = 0; k < 3 && rc == TWIST_OK; k++)
      rc = twist_ntlm_feed (n, big, sizeof big);
    check (rc == TWIST_ERR_AUTH, "ntlm: a CHALLENGE over the bound is refused");
  }
  twist_ntlm_free (n);

  /* Credentials.  */
  check (twist_ntlm_new ("D", "", "pw", "h", NULL) == NULL
         && twist_ntlm_new ("D", NULL, "pw", "h", NULL) == NULL,
         "ntlm: no user name is no login: never an anonymous session");
  check (twist_ntlm_new ("D", "u", "pw\xff", "h", NULL) == NULL,
         "ntlm: a password that is not UTF-8 is refused");
  {
    struct twist_ntlm_rand bad = { failing_fill, NULL };

    n = twist_ntlm_new ("Domain", "User", "Password", "h", &bad);
    twist_ntlm_negotiate (n, neg, sizeof neg, &nl);
    cl = unhex (hex_chal, chal);
    twist_ntlm_challenge (n, chal, cl);
    check (twist_ntlm_authenticate (n, auth, sizeof auth, &al) == TWIST_ERR_AUTH,
           "ntlm: a failing random source fails the login");
    twist_ntlm_free (n);
  }
  /* A buffer that is too small.  */
  n = make (&calls);
  twist_ntlm_negotiate (n, neg, sizeof neg, &nl);
  twist_ntlm_challenge (n, chal, cl);
  check (twist_ntlm_authenticate (n, auth, 100, &al) == TWIST_ERR_INVAL,
         "ntlm: a buffer too small for AUTHENTICATE is refused");
  check (twist_ntlm_authenticate (n, auth, sizeof auth, &al) == TWIST_OK,
         "ntlm: and the call can be made again with room");
  twist_ntlm_free (n);
}

int
main (void)
{
  test_ms_nlmp_examples ();
  test_text ();
  test_flow ();
  test_refusals ();
  return tests_finish ();
}
