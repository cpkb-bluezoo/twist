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

int
main (void)
{
  test_auth ();
  test_digest_lengths_and_params ();
  test_sasl ();
  return tests_finish ();
}
