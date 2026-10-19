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
  check (twist_http_should_redirect (302, "GET", 1, 5, 5, &use_get) == 0,
         "max");
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
  test_sasl ();
  return tests_finish ();
}
