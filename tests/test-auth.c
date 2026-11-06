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

static void
test_auth (void)
{
  uint8_t dig[16];
  char *hdr = NULL;
  static const char chal[] =
    "Digest realm=\"testrealm@host.com\", qop=\"auth\", "
    "nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\"";
  int use_get = 0;

  check (twist_md5 ("", 0, dig) == TWIST_OK, "md5");
  check (dig[0] == 0xd4 && dig[1] == 0x1d && dig[15] == 0x7e, "md5 empty");
  check (twist_auth_digest (chal, "GET", "/dir/index.html", "Mufasa",
                            "Circle Of Life", 1, "0a4f113b", &hdr) == TWIST_OK,
         "digest");
  check (hdr != NULL && strstr (hdr, "6629fae49393a05397450978507c4ef1") != NULL,
         "rfc2617");
  free (hdr);
  check (twist_auth_basic ("a", "b", &hdr) == TWIST_OK, "basic");
  check (hdr != NULL && strstr (hdr, "Basic YTpi") != NULL, "basic b64");
  free (hdr);
  check (twist_http_should_redirect (301, "POST", 1, 0, 5, &use_get) == 1
         && use_get == 1, "301");
  check (twist_http_should_redirect (307, "POST", 1, 0, 5, &use_get) == 1
         && use_get == 0, "307");
  /* At the limit a redirect is not followed and the transfer is told so (-1),
     which is not the same as a response that is not a redirect (0).  A limit
     below 0 is none.  */
  check (twist_http_should_redirect (302, "GET", 1, 5, 5, &use_get) == -1,
         "max");
  check (twist_http_should_redirect (302, "GET", 1, 0, 0, &use_get) == -1,
         "max 0");
  check (twist_http_should_redirect (200, "GET", 1, 5, 5, &use_get) == 0,
         "not a redirect at the limit");
  check (twist_http_should_redirect (302, "GET", 0, 5, 5, &use_get) == 0,
         "not following");
  check (twist_http_should_redirect (302, "GET", 1, 1000, -1, &use_get) == 1,
         "no limit");
  /* A redirect is followed by scheme alone: from http to http, https, ftp
     and ftps; from https to https and ftps; and from nothing else to anything.
     Every pair of the schemes there are is tried against that table.  */
  {
    static const char *const schemes[] = {
      "http", "https", "ws", "wss", "ftp", "ftps", "file", "sftp", "scp",
      "gopher", "gophers", "dict", "smtp", "smtps", "imap", "pop3", "ldap",
      "mqtt", "telnet", "tftp", "rtsp", "smb", "rtmp", ""
    };
    static const char *const allowed[][2] = {
      { "http", "http" }, { "http", "https" }, { "http", "ftp" },
      { "http", "ftps" }, { "https", "https" }, { "https", "ftps" }
    };
    size_t i, j, k;
    int wrong = 0;

    for (i = 0; i < sizeof schemes / sizeof schemes[0]; i++)
      for (j = 0; j < sizeof schemes / sizeof schemes[0]; j++)
        {
          int want = 0;

          for (k = 0; k < sizeof allowed / sizeof allowed[0]; k++)
            if (strcmp (schemes[i], allowed[k][0]) == 0
                && strcmp (schemes[j], allowed[k][1]) == 0)
              want = 1;
          if ((twist_http_redirect_ok (schemes[i], schemes[j]) != 0) != want)
            {
              fprintf (stderr, "redirect %s -> %s: wanted %d\n", schemes[i],
                       schemes[j], want);
              wrong++;
            }
        }
    check (wrong == 0, "redirects go only where the table says");
  }
  check (twist_http_redirect_ok ("HTTP", "Ftps") == 1
         && twist_http_redirect_ok ("Https", "HTTPS") == 1
         && twist_http_redirect_ok ("HTTPS", "FTP") == 0,
         "the case of a scheme does not matter");
  check (twist_http_redirect_ok (NULL, "http") == 0
         && twist_http_redirect_ok ("http", NULL) == 0
         && twist_http_redirect_ok (NULL, NULL) == 0,
         "and nothing is allowed from or to no scheme");
  check (twist_http_redirect_sensitive ("bank.example", 1, "bank.example", 1)
         == 0, "same origin");
  check (twist_http_redirect_sensitive ("Bank.Example", 1, "bank.example", 1)
         == 0, "host case");
  check (twist_http_redirect_sensitive ("bank.example", 1, "evil.example", 1)
         == 1, "cross host");
  check (twist_http_redirect_sensitive ("bank.example", 1, "bank.example", 0)
         == 1, "downgrade");
  check (twist_http_redirect_sensitive ("bank.example", 0, "bank.example", 1)
         == 0, "upgrade");
  check (twist_auth_digest (chal, "GET", "/a\rb", "Mufasa", "Circle Of Life",
                            1, "0a4f113b", &hdr) == TWIST_ERR_AUTH,
         "digest ctl");
  check (twist_auth_digest (chal, "GET", "/", "a\"b", "Circle Of Life",
                            1, "0a4f113b", &hdr) == TWIST_ERR_AUTH,
         "digest quote");
  check (twist_auth_digest ("Digest realm=\"r\", nonce=\"n\", qop=\"auth-int\"",
                            "GET", "/", "u", "p", 1, "c", &hdr)
         == TWIST_ERR_UNSUPPORTED, "auth-int");
}

/* The response of RFC 7616 without qop, MD5, worked out here from whole
   strings of any length: md5 (md5 (user:realm:pass) : nonce : md5 (method:uri))
   in hex.  The code under test must come to the same.  */
static void
hex_md5 (const char *s, char *out)
{
  uint8_t d[16];
  size_t i;

  twist_md5 (s, strlen (s), d);
  for (i = 0; i < 16; i++)
    sprintf (out + 2 * i, "%02x", d[i]);
}

static void
expected_response (const char *user, const char *realm, const char *pass,
                   const char *method, const char *uri, const char *nonce,
                   char *out)
{
  size_t n = strlen (user) + strlen (realm) + strlen (pass) + strlen (method)
             + strlen (uri) + strlen (nonce) + 128;
  char *t = malloc (n);
  char ha1[33], ha2[33];

  if (t == NULL)
    abort ();
  snprintf (t, n, "%s:%s:%s", user, realm, pass);
  hex_md5 (t, ha1);
  snprintf (t, n, "%s:%s", method, uri);
  hex_md5 (t, ha2);
  snprintf (t, n, "%s:%s:%s", ha1, nonce, ha2);
  hex_md5 (t, out);
  free (t);
}

/* A Digest header is built from what the challenge says and what the user
   gave, none of which has a length of its own.  A long password or URI was
   cut off in a fixed buffer, and the response then did not match the header
   or the credentials, so that the login failed with nothing said; the
   parameters were found by looking for their names anywhere in the
   challenge, in "cnonce" for "nonce" and in the middle of a quoted realm;
   and the server's opaque, which has to be sent back, was not.  */
static void
test_digest_lengths_and_params (void)
{
  char user[301];
  char pass[701];
  char uri[901];
  char want[33];
  char *hdr = NULL;
  char needle[96];
  size_t n;

  memset (user, 'u', sizeof user - 1);
  user[sizeof user - 1] = 0;
  memset (pass, 'p', sizeof pass - 1);
  pass[sizeof pass - 1] = 0;
  uri[0] = '/';
  memset (uri + 1, 'a', sizeof uri - 2);
  uri[sizeof uri - 1] = 0;

  /* Long credentials and a long URI: whole, and the response is of them.  */
  check (twist_auth_digest ("Digest realm=\"r\", nonce=\"n1\"", "GET", uri, user,
                            pass, 1, "c", &hdr) == TWIST_OK && hdr != NULL,
         "digest with long fields");
  expected_response (user, "r", pass, "GET", uri, "n1", want);
  snprintf (needle, sizeof needle, "response=\"%s\"", want);
  check (hdr != NULL && strstr (hdr, needle) != NULL,
         "its response is that of the whole credentials");
  check (hdr != NULL && strstr (hdr, user) != NULL && strstr (hdr, uri) != NULL,
         "and the user name and the URI are in it whole");
  n = hdr != NULL ? strlen (hdr) : 0;
  check (n > 0 && hdr[n - 1] == '"', "and it ends where it should");
  free (hdr);
  hdr = NULL;

  /* "nonce" is not "cnonce", and a name is not found in a quoted value.  */
  check (twist_auth_digest ("Digest realm=\"r\", cnonce=\"WRONG\", nonce=\"RIGHT\"",
                            "GET", "/", "u", "p", 1, "c", &hdr) == TWIST_OK,
         "challenge with a cnonce");
  check (hdr != NULL && strstr (hdr, "nonce=\"RIGHT\"") != NULL
         && strstr (hdr, "WRONG") == NULL, "the nonce is nonce, not cnonce");
  free (hdr);
  hdr = NULL;
  check (twist_auth_digest ("Digest realm=\"a qop=auth b\", nonce=\"n\"", "GET",
                            "/", "u", "p", 1, "c", &hdr) == TWIST_OK,
         "challenge with qop in the realm");
  check (hdr != NULL && strstr (hdr, "qop=auth,") == NULL
         && strstr (hdr, "realm=\"a qop=auth b\"") != NULL,
         "a name inside a quoted value is not a parameter");
  free (hdr);
  hdr = NULL;
  check (twist_auth_digest ("Digest REALM=\"r\", NONCE=\"n\", QOP=\"auth\"", "GET",
                            "/", "u", "p", 1, "c", &hdr) == TWIST_OK
         && hdr != NULL && strstr (hdr, "qop=auth") != NULL,
         "names are not case sensitive");
  free (hdr);
  hdr = NULL;

  /* The opaque is sent back as it came, and the algorithm named if it is
     not the default.  */
  check (twist_auth_digest ("Digest realm=\"r\", nonce=\"n\", opaque=\"5ccc069c\"",
                            "GET", "/", "u", "p", 1, "c", &hdr) == TWIST_OK
         && hdr != NULL && strstr (hdr, "opaque=\"5ccc069c\"") != NULL,
         "the opaque is sent back");
  free (hdr);
  hdr = NULL;
  check (twist_auth_digest ("Digest realm=\"r\", nonce=\"n\", algorithm=SHA-256",
                            "GET", "/", "u", "p", 1, "c", &hdr) == TWIST_OK
         && hdr != NULL && strstr (hdr, "algorithm=SHA-256") != NULL,
         "SHA-256 is named in the response");
  free (hdr);
  hdr = NULL;
  check (twist_auth_digest ("Digest realm=\"r\", nonce=\"n\"", "GET", "/", "u",
                            "p", 1, "c", &hdr) == TWIST_OK
         && hdr != NULL && strstr (hdr, "opaque") == NULL
         && strstr (hdr, "algorithm") == NULL,
         "neither when there is none, or for MD5");
  free (hdr);
  hdr = NULL;

  /* A nonce longer than the old buffer.  */
  {
    char chal[600];
    char nonce[301];

    memset (nonce, 'n', sizeof nonce - 1);
    nonce[sizeof nonce - 1] = 0;
    snprintf (chal, sizeof chal, "Digest realm=\"r\", nonce=\"%s\"", nonce);
    check (twist_auth_digest (chal, "GET", "/", "u", "p", 1, "c", &hdr)
           == TWIST_OK && hdr != NULL && strstr (hdr, nonce) != NULL,
           "a long nonce is taken");
    free (hdr);
  }
}

static void
test_sasl (void)
{
  struct twist_sasl_client *c;
  uint8_t *out = NULL;
  size_t n = 0;
  int done = 0;
  static const uint8_t plain[] = { 0, 'a', 0, 'b' };
  static const char xo[] = "user=alice\001auth=Bearer tok\001\001";

  check (twist_sasl_from_name ("plain") == TWIST_SASL_PLAIN, "plain name");
  check (twist_sasl_from_name ("GSSAPI") == 0, "no gssapi");
  c = twist_sasl_client_new (TWIST_SASL_PLAIN, "a", "b", NULL);
  check (c != NULL && twist_sasl_has_initial (c), "plain initial");
  check (twist_sasl_step (c, NULL, 0, &out, &n, &done) == TWIST_OK, "plain step");
  check (done && n == sizeof plain && memcmp (out, plain, n) == 0, "plain wire");
  free (out);
  check (twist_sasl_step (c, NULL, 0, &out, &n, &done) == TWIST_ERR_AUTH,
         "plain done");
  twist_sasl_client_free (c);

  c = twist_sasl_client_new (TWIST_SASL_LOGIN, "alice", "secret", NULL);
  check (c != NULL && !twist_sasl_has_initial (c), "login no initial");
  check (twist_sasl_step (c, NULL, 0, &out, &n, &done) == TWIST_OK && !done, "user");
  check (n == 5 && memcmp (out, "alice", 5) == 0, "login user");
  free (out);
  check (twist_sasl_step (c, NULL, 0, &out, &n, &done) == TWIST_OK && done, "pass");
  check (n == 6 && memcmp (out, "secret", 6) == 0, "login pass");
  free (out);
  twist_sasl_client_free (c);

  c = twist_sasl_client_new (TWIST_SASL_XOAUTH2, "alice", NULL, "tok");
  check (twist_sasl_step (c, NULL, 0, &out, &n, &done) == TWIST_OK && done, "xoauth2");
  check (n == sizeof xo - 1 && memcmp (out, xo, n) == 0, "xoauth2 wire");
  free (out);
  twist_sasl_client_free (c);
}

/* The primitives that SMB 3.1.1 and NTLMv2 need.  */

static void
hex (const uint8_t *b, size_t n, char *out)
{
  size_t i;

  for (i = 0; i < n; i++)
    snprintf (out + 2 * i, 3, "%02x", b[i]);
}

static int
is_hex (const uint8_t *b, size_t n, const char *want)
{
  char got[129];

  hex (b, n, got);
  return strcmp (got, want) == 0;
}

static void
test_md4 (void)
{
  /* RFC 1320 appendix A.5.  */
  static const struct
  {
    const char *in, *out;
  } v[] = {
    { "", "31d6cfe0d16ae931b73c59d7e0c089c0" },
    { "a", "bde52cb31de33e46245e05fbdbd6fb24" },
    { "abc", "a448017aaf21d8525fc10ae87aa6729d" },
    { "message digest", "d9130a8164549fe818874806e1c7014b" },
    { "abcdefghijklmnopqrstuvwxyz", "d79e1c308aa5bbcdeea8ed63df412da9" },
    { "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
      "043f8582f241db351ce627e153e7f0e4" },
    { "12345678901234567890123456789012345678901234567890"
      "123456789012345678901234567890",
      "e33b4ddc9c38f2199c3e7b164fcc0536" }
  };
  uint8_t out[16];
  size_t i;

  for (i = 0; i < sizeof v / sizeof v[0]; i++)
    {
      check (twist_md4 (v[i].in, strlen (v[i].in), out) == TWIST_OK
             && is_hex (out, 16, v[i].out), "md4: RFC 1320 vector");
    }
  check (twist_md4 ("a", 1, NULL) == TWIST_ERR_INVAL,
         "md4: a null output is refused");
}

static void
test_hmac_md5 (void)
{
  uint8_t out[16], key[80], data[50];
  static const char big[] =
    "Test Using Larger Than Block-Size Key - Hash Key First";

  /* RFC 2202 test cases 1, 2, 3 and 6.  */
  memset (key, 0x0b, 16);
  check (twist_hmac_md5 (key, 16, "Hi There", 8, out) == TWIST_OK
         && is_hex (out, 16, "9294727a3638bb1c13f48ef8158bfc9d"),
         "hmac-md5: case 1");
  check (twist_hmac_md5 ("Jefe", 4, "what do ya want for nothing?", 28, out)
         == TWIST_OK && is_hex (out, 16, "750c783e6ab0b503eaa86e310a5db738"),
         "hmac-md5: case 2");
  memset (key, 0xaa, 16);
  memset (data, 0xdd, 50);
  check (twist_hmac_md5 (key, 16, data, 50, out) == TWIST_OK
         && is_hex (out, 16, "56be34521d144c88dbb8c733f0e8b3f6"),
         "hmac-md5: case 3");
  memset (key, 0xaa, 80);
  check (twist_hmac_md5 (key, 80, big, strlen (big), out) == TWIST_OK
         && is_hex (out, 16, "6b1ab7fe4bd7bf8f0b62e6ce61b9d0cd"),
         "hmac-md5: case 6, a key longer than the block");
  check (twist_hmac_md5 ("k", 1, "x", 1, NULL) == TWIST_ERR_INVAL,
         "hmac-md5: a null output is refused");
}

static void
test_rc4 (void)
{
  /* RFC 6229: the keystream at offset 0 for a 40-bit and a 128-bit key.  */
  static const uint8_t k40[5] = { 1, 2, 3, 4, 5 };
  uint8_t k128[16], zero[16], out[16];
  struct twist_rc4 c;
  size_t i;

  memset (zero, 0, sizeof zero);
  check (twist_rc4_init (&c, k40, 5) == TWIST_OK, "rc4: a key");
  twist_rc4_crypt (&c, zero, out, 16);
  check (is_hex (out, 16, "b2396305f03dc027ccc3524a0a1118a8"),
         "rc4: RFC 6229, 40-bit key");
  for (i = 0; i < 16; i++)
    k128[i] = (uint8_t) (i + 1);
  twist_rc4_init (&c, k128, 16);
  twist_rc4_crypt (&c, zero, out, 16);
  check (is_hex (out, 16, "9ac7cc9a609d1ef7b2932899cde41b97"),
         "rc4: RFC 6229, 128-bit key");
  /* The stream goes on across calls, and the same key undoes it.  */
  twist_rc4_init (&c, k128, 16);
  twist_rc4_crypt (&c, (const uint8_t *) "abcdefgh", out, 8);
  twist_rc4_crypt (&c, (const uint8_t *) "ijklmnop", out + 8, 8);
  twist_rc4_init (&c, k128, 16);
  twist_rc4_crypt (&c, out, out, 16);
  check (memcmp (out, "abcdefghijklmnop", 16) == 0,
         "rc4: split calls are one stream, and it decrypts");
  twist_rc4_wipe (&c);
  check (c.s[0] == 0 && c.s[255] == 0, "rc4: wiped");
  check (twist_rc4_init (&c, k40, 0) == TWIST_ERR_INVAL,
         "rc4: an empty key is refused");
}

static void
test_sha512_cmac (void)
{
  uint8_t out[64];
  uint8_t key[16] = { 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
                      0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c };
  static const uint8_t m16[16] = { 0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f,
                                   0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93,
                                   0x17, 0x2a };

  check (twist_sha512 ("abc", 3, out) == TWIST_OK
         && is_hex (out, 64, "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea2"
                    "0a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423"
                    "643ce80e2a9ac94fa54ca49f"), "sha-512: FIPS 180 'abc'");
  check (twist_sha512 ("abc", 3, NULL) == TWIST_ERR_INVAL,
         "sha-512: a null output is refused");
  check (twist_sha512 (NULL, 3, out) == TWIST_ERR_INVAL,
         "sha-512: null data with a length is refused");
  /* RFC 4493 examples 1 and 2.  */
  check (twist_cmac_aes128 (key, NULL, 0, out) == TWIST_OK
         && is_hex (out, 16, "bb1d6929e95937287fa37d129b756746"),
         "cmac: RFC 4493, empty message");
  check (twist_cmac_aes128 (key, m16, 16, out) == TWIST_OK
         && is_hex (out, 16, "070a16b46b4d4144f79bdd9dd04a287c"),
         "cmac: RFC 4493, one block");
  check (twist_cmac_aes128 (key, m16, 16, NULL) == TWIST_ERR_INVAL,
         "cmac: a null output is refused");
  check (twist_cmac_aes128 (NULL, m16, 16, out) == TWIST_ERR_INVAL,
         "cmac: a null key is refused");
}

static void
test_smb_kdf (void)
{
  static const uint8_t sk[16] = { 0x7c, 0xd4, 0x51, 0x82, 0x5d, 0x04, 0x50,
                                  0xd2, 0x35, 0x42, 0x4e, 0x44, 0xba, 0x6e,
                                  0x78, 0xcc };
  uint8_t ph[64], out[32], again[32];
  size_t i;

  /* The signing key of Microsoft's SMB 3.0 example, with its label and
     context.  */
  check (twist_smb_kdf (sk, 16, "SMB2AESCMAC", 12, "SmbSign", 8, 128, out)
         == TWIST_OK && is_hex (out, 16, "0b7e9c5cac36c0f6ea9ab275298cedce"),
         "kdf: the published SMB 3.0 signing key");
  /* The 3.1.1 form: a label with its NUL, the pre-authentication hash as
     context, 128 and 256 bits.  The 256-bit key is two blocks and the 128-bit
     one is not a cut of it (L is part of every block).  */
  for (i = 0; i < 64; i++)
    ph[i] = (uint8_t) i;
  check (twist_smb_kdf (sk, 16, "SMBSigningKey", 14, ph, 64, 128, out)
         == TWIST_OK && is_hex (out, 16, "481642b8b0d9374628a7bc43f6def7b8"),
         "kdf: 128 bits with the pre-authentication hash");
  check (twist_smb_kdf (sk, 16, "SMBC2SCipherKey", 16, ph, 64, 256, out)
         == TWIST_OK
         && is_hex (out, 32, "52ab5b03168374c9894949043b3279c1"
                    "f4d30673196ef92ad52abe57b5539c8d"),
         "kdf: 256 bits");
  memset (again, 0, sizeof again);
  twist_smb_kdf (sk, 16, "SMBC2SCipherKey", 16, ph, 64, 256, again);
  check (memcmp (out, again, 32) == 0, "kdf: it is deterministic");
  check (twist_smb_kdf (sk, 16, "x", 2, ph, 64, 192, out) == TWIST_ERR_INVAL,
         "kdf: only 128 and 256 bits");
  check (twist_smb_kdf (sk, 16, "x", 2, ph, 64, 128, NULL) == TWIST_ERR_INVAL,
         "kdf: a null output is refused");
}

int
main (void)
{
  test_auth ();
  test_digest_lengths_and_params ();
  test_sasl ();
  test_md4 ();
  test_hmac_md5 ();
  test_rc4 ();
  test_sha512_cmac ();
  test_smb_kdf ();
  return tests_finish ();
}
