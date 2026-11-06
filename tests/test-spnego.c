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

/* The SPNEGO initiator.  The tokens are made by a separate implementation of
   RFC 4178 and MS-NLMP in Python, over the same fixed NTLM values as
   test-ntlm; the server's replies are the exchange as a server sends it, and
   the mutations are the ways it can be wrong.  */

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

static const char hex_init[] =
    "604806062b0601050502a03e303ca00e300c060a2b06010401823702020aa22a"
    "04284e544c4d5353500001000000150288620000000028000000000000002800"
    "0000000000000000000f";
static const char hex_srv1[] =
    "a1818e30818ba0030a0101a10c060a2b06010401823702020aa27604744e544c"
    "4d53535000020000000c000c003800000015028a620123456789abcdef000000"
    "000000000030003000440000000a00614a0000000f5300450052005600450052"
    "0002000c0044004f004d00410049004e0001000c005300450052005600450052"
    "0007000800001122334455667700000000";
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
static const char hex_srv2[] =
    "a11b3019a0030a0100a3120410010000007dd6da05648a73ae00000000";
static const char hex_srv2m[] =
    "a1293027a0030a0100a10c060a2b06010401823702020aa3120410010000007d"
    "d6da05648a73ae00000000";
static const char hex_srv2bad[] =
    "a11b3019a0030a0100a3120410010000007dd7da05648a73ae00000000";
static const char hex_srv2nomic[] =
    "a1073005a0030a0100";
static const char hex_srv_reject[] =
    "a1073005a0030a0102";
static const char hex_srv1_krb[] =
    "a1818d30818aa0030a0101a10b06092a864886f712010202a27604744e544c4d"
    "53535000020000000c000c003800000015028a620123456789abcdef00000000"
    "0000000030003000440000000a00614a0000000f530045005200560045005200"
    "02000c0044004f004d00410049004e0001000c00530045005200560045005200"
    "07000800001122334455667700000000";
static const char hex_srv1_nostate[] =
    "a18189308186a10c060a2b06010401823702020aa27604744e544c4d53535000"
    "020000000c000c003800000015028a620123456789abcdef0000000000000000"
    "30003000440000000a00614a0000000f53004500520056004500520002000c00"
    "44004f004d00410049004e0001000c0053004500520056004500520007000800"
    "001122334455667700000000";
static const char hex_srv1_complete[] =
    "a1818e30818ba0030a0100a10c060a2b06010401823702020aa27604744e544c"
    "4d53535000020000000c000c003800000015028a620123456789abcdef000000"
    "000000000030003000440000000a00614a0000000f5300450052005600450052"
    "0002000c0044004f004d00410049004e0001000c005300450052005600450052"
    "0007000800001122334455667700000000";
static const char hex_srv1_outoforder[] =
    "a1818e30818ba10c060a2b06010401823702020aa0030a0101a27604744e544c"
    "4d53535000020000000c000c003800000015028a620123456789abcdef000000"
    "000000000030003000440000000a00614a0000000f5300450052005600450052"
    "0002000c0044004f004d00410049004e0001000c005300450052005600450052"
    "0007000800001122334455667700000000";
static const char hex_srv1_dup[] =
    "a18193308190a0030a0101a0030a0101a10c060a2b06010401823702020aa276"
    "04744e544c4d53535000020000000c000c003800000015028a620123456789ab"
    "cdef000000000000000030003000440000000a00614a0000000f530045005200"
    "56004500520002000c0044004f004d00410049004e0001000c00530045005200"
    "56004500520007000800001122334455667700000000";
static const char hex_srv1_wrapped[] =
    "60819906062b0601050502a1818e30818ba0030a0101a10c060a2b0601040182"
    "3702020aa27604744e544c4d53535000020000000c000c003800000015028a62"
    "0123456789abcdef000000000000000030003000440000000a00614a0000000f"
    "53004500520056004500520002000c0044004f004d00410049004e0001000c00"
    "53004500520056004500520007000800001122334455667700000000";
static const char hex_srv1_trailing[] =
    "a1818e30818ba0030a0101a10c060a2b06010401823702020aa27604744e544c"
    "4d53535000020000000c000c003800000015028a620123456789abcdef000000"
    "000000000030003000440000000a00614a0000000f5300450052005600450052"
    "0002000c0044004f004d00410049004e0001000c005300450052005600450052"
    "000700080000112233445566770000000000";
static const char hex_srv1_mic[] =
    "a181a230819fa0030a0101a10c060a2b06010401823702020aa27604744e544c"
    "4d53535000020000000c000c003800000015028a620123456789abcdef000000"
    "000000000030003000440000000a00614a0000000f5300450052005600450052"
    "0002000c0044004f004d00410049004e0001000c005300450052005600450052"
    "0007000800001122334455667700000000a3120410010000007dd6da05648a73"
    "ae00000000";

static int
fixed_fill (void *user, void *buf, size_t len)
{
  (void) user;
  memset (buf, len == 8 ? 0xaa : 0x55, len);
  return 0;
}

static struct twist_spnego *
make (void)
{
  static struct twist_ntlm_rand rnd = { fixed_fill, NULL };

  return twist_spnego_new ("Domain", "User", "Password", "server.example",
                           &rnd);
}

/* Compare a token with its expected hex.  */
static int
same (const uint8_t *got, size_t n, const char *hex)
{
  uint8_t w[8192];

  return unhex (hex, w) == n && memcmp (got, w, n) == 0;
}

/* A client that has sent its first token.  */
static struct twist_spnego *
started (void)
{
  struct twist_spnego *s = make ();
  uint8_t out[512];
  size_t n;

  twist_spnego_start (s, out, sizeof out, &n);
  return s;
}

/* One token from the server, taken whole.  */
static int
step (struct twist_spnego *s, const char *hex, uint8_t *out, size_t cap,
      size_t *n, int *done)
{
  uint8_t in[8192];
  size_t len = unhex (hex, in);

  return twist_spnego_step (s, in, len, out, cap, n, done);
}

static void
test_exchange (void)
{
  uint8_t out[8192], key[16];
  struct twist_spnego *s = make ();
  size_t n, i, inlen;
  int done = 0;
  uint8_t in[8192];

  check (s != NULL, "spnego: a client");
  check (twist_spnego_start (s, out, sizeof out, &n) == TWIST_OK
         && same (out, n, hex_init),
         "spnego: NegTokenInit holds NTLMSSP alone and the NEGOTIATE");
  check (twist_spnego_start (s, out, sizeof out, &n) == TWIST_ERR_INVAL,
         "spnego: starting twice is refused");
  check (twist_spnego_session_key (s, key) == TWIST_ERR_INVAL,
         "spnego: no session key before AUTHENTICATE");
  check (step (s, hex_srv1, out, sizeof out, &n, &done) == TWIST_OK
         && !done && same (out, n, hex_cli2),
         "spnego: the reply has the AUTHENTICATE and the mechListMIC");
  check (twist_spnego_session_key (s, key) == TWIST_OK && key[0] == 0x55
         && key[15] == 0x55, "spnego: the session key is there once it is sent");
  check (step (s, hex_srv2, out, sizeof out, &n, &done) == TWIST_OK
         && done && n == 0, "spnego: the server's last token ends it");
  check (step (s, hex_srv2, out, sizeof out, &n, &done) == TWIST_ERR_INVAL,
         "spnego: nothing is taken after the end");
  twist_spnego_free (s);

  /* The server's last token may name the mechanism.  */
  s = started ();
  step (s, hex_srv1, out, sizeof out, &n, &done);
  check (step (s, hex_srv2m, out, sizeof out, &n, &done) == TWIST_OK && done,
         "spnego: a last token that names NTLMSSP is taken");
  twist_spnego_free (s);

  /* Each token in pieces of one byte gives the same answer.  */
  s = started ();
  inlen = unhex (hex_srv1, in);
  for (i = 0; i < inlen; i++)
    if (twist_spnego_feed (s, in + i, 1) != TWIST_OK)
      break;
  check (i == inlen, "spnego: one-byte pieces are taken");
  check (twist_spnego_finish (s, out, sizeof out, &n, &done) == TWIST_OK
         && !done && same (out, n, hex_cli2),
         "spnego: and give the same reply");
  inlen = unhex (hex_srv2, in);
  for (i = 0; i < inlen; i++)
    twist_spnego_feed (s, in + i, 1);
  check (twist_spnego_finish (s, out, sizeof out, &n, &done) == TWIST_OK
         && done, "spnego: and the last token the same way");
  twist_spnego_free (s);
}

/* The first reply, mutated, is refused and ends the exchange.  */
static void
refused_first (const char *what, const char *hex)
{
  struct twist_spnego *s = started ();
  uint8_t out[8192];
  size_t n;
  int done = 0;

  check (step (s, hex, out, sizeof out, &n, &done) == TWIST_ERR_AUTH && !done,
         what);
  check (step (s, hex_srv1, out, sizeof out, &n, &done) == TWIST_ERR_INVAL,
         "spnego: and nothing more is taken after a refusal");
  twist_spnego_free (s);
}

static void
refused_last (const char *what, const char *hex)
{
  struct twist_spnego *s = started ();
  uint8_t out[8192];
  size_t n;
  int done = 0;

  step (s, hex_srv1, out, sizeof out, &n, &done);
  check (step (s, hex, out, sizeof out, &n, &done) == TWIST_ERR_AUTH && !done,
         what);
  twist_spnego_free (s);
}

static void
test_refusals (void)
{
  uint8_t in[8192], out[8192];
  size_t inlen, i, n;
  struct twist_spnego *s;
  int done, rc;

  refused_first ("spnego: a mechanism other than NTLMSSP is refused", hex_srv1_krb);
  refused_first ("spnego: a reject is refused", hex_srv_reject);
  refused_first ("spnego: a reply with no negState is refused", hex_srv1_nostate);
  refused_first ("spnego: accept-completed before the CHALLENGE is refused",
                 hex_srv1_complete);
  refused_first ("spnego: fields out of order are refused", hex_srv1_outoforder);
  refused_first ("spnego: a field twice is refused", hex_srv1_dup);
  refused_first ("spnego: the GSS wrapper on a NegTokenResp is refused",
                 hex_srv1_wrapped);
  refused_first ("spnego: bytes after the token are refused", hex_srv1_trailing);
  refused_first ("spnego: a mechListMIC before there is a session is refused",
                 hex_srv1_mic);
  refused_first ("spnego: the last token as the first is refused", hex_srv2);
  refused_last ("spnego: a bad mechListMIC is refused", hex_srv2bad);
  refused_last ("spnego: a missing mechListMIC is refused", hex_srv2nomic);
  refused_last ("spnego: a reject at the end is refused", hex_srv_reject);
  refused_last ("spnego: a CHALLENGE again is refused", hex_srv1);
  /* The client's own mechListMIC is not the server's.  */
  refused_last ("spnego: the client's token as the server's is refused",
                hex_cli2);

  /* Every cut-off first reply is refused, fed whole and by the byte.  */
  inlen = unhex (hex_srv1, in);
  for (i = 0; i < inlen; i++)
    {
      s = started ();
      rc = twist_spnego_step (s, in, i, out, sizeof out, &n, &done);
      if (rc != TWIST_ERR_AUTH)
        break;
      twist_spnego_free (s);
    }
  check (i == inlen, "spnego: no cut-off token is taken");
  for (i = 1; i < inlen; i++)
    {
      size_t k;

      s = started ();
      for (k = 0; k < i; k++)
        twist_spnego_feed (s, in + k, 1);
      rc = twist_spnego_finish (s, out, sizeof out, &n, &done);
      if (rc != TWIST_ERR_AUTH)
        break;
      twist_spnego_free (s);
    }
  check (i == inlen, "spnego: nor one fed by the byte and ended early");

  /* Calls out of turn.  */
  s = make ();
  check (twist_spnego_feed (s, in, 1) == TWIST_ERR_INVAL,
         "spnego: a token before the start is refused");
  check (twist_spnego_finish (s, out, sizeof out, &n, &done) == TWIST_ERR_INVAL,
         "spnego: finishing with nothing fed is refused");
  twist_spnego_free (s);
  check (twist_spnego_new ("D", "", "pw", "h", NULL) == NULL,
         "spnego: no user name is no client");
  /* An output buffer too small for the reply.  */
  s = started ();
  check (step (s, hex_srv1, out, 100, &n, &done) == TWIST_ERR_AUTH,
         "spnego: a reply that does not fit ends the exchange");
  twist_spnego_free (s);
}

int
main (void)
{
  test_exchange ();
  test_refusals ();
  return tests_finish ();
}
