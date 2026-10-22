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

#include <stdlib.h>
#include <string.h>

/* The URI Template of a UDP proxy (RFC 9298, section 2): an https URI with
   the variables target_host and target_port, in the simple form {name} or the
   query form {?name,name} of RFC 6570.  */

static int
ok (const char *tmpl)
{
  char err[200];

  return twist_template_check (tmpl, err, sizeof err) == TWIST_OK;
}

static int
expands (const char *tmpl, const char *host, int port, const char *want)
{
  char *out = NULL;
  int r = twist_template_expand (tmpl, host, port, &out) == TWIST_OK
          && out != NULL && strcmp (out, want) == 0;

  free (out);
  return r;
}

static void
test_check (void)
{
  char err[200];

  check (ok ("https://p.example:4443/.well-known/masque/udp/{target_host}/{target_port}/"),
         "the default form");
  check (ok ("https://p.example/masque{?target_host,target_port}"),
         "the query form");
  check (ok ("https://p.example/m/{target_port}/{target_host}"),
         "in either order");
  check (ok ("https://p.example/m?h={target_host}&p={target_port}"),
         "in a query that is written out");
  check (ok ("https://p.example/{target_host}/{target_port}/{other}"),
         "another variable is allowed");
  check (ok ("HTTPS://p.example/{target_host}/{target_port}"), "any case");
  check (!ok ("http://p.example/{target_host}/{target_port}"),
         "http is not enough");
  check (!ok ("/{target_host}/{target_port}"), "a relative template");
  check (!ok ("https:///{target_host}/{target_port}"), "no host");
  check (!ok ("https://p.example/{target_host}/"), "no target_port");
  check (!ok ("https://p.example/{target_port}/"), "no target_host");
  check (!ok ("https://p.example/{target_host/{target_port}"), "an open brace");
  check (!ok ("https://p.example/target_host}/{target_port}"), "a stray close");
  check (!ok ("https://p.example/{+target_host}/{target_port}"),
         "an operator that is not supported");
  check (!ok ("https://p.example/{/target_host}/{target_port}"), "another");
  check (!ok ("https://p.example/{}/{target_host}/{target_port}"), "empty");
  check (!ok ("https://p.example/{target host}/{target_port}"),
         "a name with a space");
  check (!ok ("https://p{target_host}.example/{target_port}"),
         "the proxy's own host is not a variable");
  check (!ok ("https://p.example/{target_host}/{target_port}#frag"),
         "a fragment");
  check (!ok (""), "empty");
  check (twist_template_check ("https://p/{target_host}/", err, sizeof err)
         != TWIST_OK && strstr (err, "target_port") != NULL,
         "the reason names the variable");
}

static void
test_expand (void)
{
  const char *t = "https://p.example:4443/.well-known/masque/udp/{target_host}/{target_port}/";

  check (expands (t, "example.com", 443,
                  "https://p.example:4443/.well-known/masque/udp/example.com/443/"),
         "a name and a port");
  check (expands (t, "192.0.2.7", 53,
                  "https://p.example:4443/.well-known/masque/udp/192.0.2.7/53/"),
         "an IPv4 address");
  check (expands (t, "2001:db8::1", 443,
                  "https://p.example:4443/.well-known/masque/udp/2001%3Adb8%3A%3A1/443/"),
         "an IPv6 address has its colons encoded, and no brackets");
  check (expands (t, "a b/c", 1, "https://p.example:4443/.well-known/masque/udp/a%20b%2Fc/1/"),
         "what is not unreserved is percent-encoded");
  check (expands ("https://p.example/masque{?target_host,target_port}",
                  "example.com", 443,
                  "https://p.example/masque?target_host=example.com&target_port=443"),
         "the query form");
  check (expands ("https://p.example/m?h={target_host}&p={target_port}", "h", 9,
                  "https://p.example/m?h=h&p=9"), "a query written out");
  check (expands ("https://p.example/{target_port}-{target_host}", "h", 9,
                  "https://p.example/9-h"), "the other order");
  check (expands ("https://p.example/{target_host}/{target_port}/{other}x", "h", 9,
                  "https://p.example/h/9/x"), "an undefined variable is empty");
  check (expands ("https://p.example/{target_host}/{target_port}", "~a-b_c.d", 1,
                  "https://p.example/~a-b_c.d/1"), "unreserved characters stay");
}

static void
test_default (void)
{
  char *out = NULL;

  check (twist_template_default ("proxy.example", 443, &out) == TWIST_OK
         && strcmp (out, "https://proxy.example:443/.well-known/masque/udp/"
                    "{target_host}/{target_port}/") == 0,
         "the default template of a host and a port");
  free (out);
  check (twist_template_default ("::1", 8443, &out) == TWIST_OK
         && strcmp (out, "https://[::1]:8443/.well-known/masque/udp/"
                    "{target_host}/{target_port}/") == 0,
         "an IPv6 proxy is in brackets");
  free (out);
}

int
main (void)
{
  test_check ();
  test_expand ();
  test_default ();
  return tests_finish ();
}
