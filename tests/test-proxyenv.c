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

/* The proxy a transfer uses, from what it was given and from the
   environment; and the list of hosts that go direct.  */

static void
clear_env (void)
{
  static const char *const names[] = {
    "http_proxy", "HTTP_PROXY", "https_proxy", "HTTPS_PROXY", "ftp_proxy",
    "FTP_PROXY", "ws_proxy", "WS_PROXY", "wss_proxy", "WSS_PROXY",
    "sftp_proxy", "SFTP_PROXY", "imaps_proxy", "IMAPS_PROXY", "tftp_proxy",
    "all_proxy", "ALL_PROXY", "no_proxy", "NO_PROXY"
  };
  size_t i;

  for (i = 0; i < sizeof names / sizeof names[0]; i++)
    unsetenv (names[i]);
}

static int
m (const char *host, const char *list)
{
  return twist_noproxy_match (host, list);
}

static void
test_match (void)
{
  check (!m ("example.com", NULL) && !m ("example.com", ""), "no list");
  check (m ("example.com", "*") && m ("1.2.3.4", "*"), "* is all");
  check (!m ("example.com", "*.com"), "* is not a pattern");
  check (m ("example.com", "example.com"), "the name");
  check (m ("EXAMPLE.com", "example.COM"), "any case");
  check (m ("www.example.com", "example.com"), "a name under it");
  check (m ("a.b.example.com", "example.com"), "deeper");
  check (!m ("nonexample.com", "example.com"), "not a longer name");
  check (!m ("example.com", "www.example.com"), "not the parent");
  check (m ("www.example.com", ".example.com"), "a leading dot");
  check (m ("www.example.com", "example.com."), "a trailing dot");
  check (m ("www.example.com.", "example.com"), "and on the host");
  check (m ("example.com", "a.org,b.net,example.com,c.io"), "in a list");
  check (m ("example.com", "a.org, b.net ,example.com"), "blanks");
  check (m ("example.com", "a.org b.net example.com"), "blanks as commas");
  check (m ("example.com", ",,example.com,,"), "empty entries");
  check (!m ("example.com", "a.org,b.net"), "not in it");
  check (!m ("", "example.com") && !m (NULL, "example.com"), "no host");
  check (m ("localhost", "localhost"), "localhost");
  /* Addresses.  */
  check (m ("192.168.1.2", "192.168.1.2"), "an address");
  check (!m ("192.168.1.3", "192.168.1.2"), "not another");
  check (m ("192.168.1.3", "192.168.0.0/16"), "a /16");
  check (!m ("192.169.1.3", "192.168.0.0/16"), "not outside it");
  check (m ("10.0.0.1", "10.0.0.0/8"), "a /8");
  check (m ("10.1.2.3", "10.1.2.0/24"), "a /24");
  check (m ("10.1.2.200", "10.1.2.0/24"), "all of a /24");
  check (!m ("10.1.3.3", "10.1.2.0/24"), "not outside the /24");
  check (m ("10.1.2.129", "10.1.2.128/25"), "a /25");
  check (!m ("10.1.2.127", "10.1.2.128/25"), "not below it");
  check (m ("1.2.3.4", "1.2.3.4/32"), "a /32");
  check (!m ("1.2.3.5", "1.2.3.4/32"), "not another in the /32");
  check (!m ("1.2.3.4", "1.2.3.4/33"), "a /33 is nothing");
  check (!m ("1.2.3.4", "1.2.3.4/x"), "a bad number is nothing");
  check (!m ("1.2.3.4", "example.com"), "a name does not match an address");
  check (!m ("example.com", "1.2.3.4"), "nor an address a name");
  check (m ("::1", "::1"), "an IPv6 address");
  check (m ("[::1]", "::1"), "in brackets");
  check (m ("fe80::1%eth0", "fe80::1"), "with a zone");
  check (m ("2001:db8::5", "2001:db8::/32"), "an IPv6 network");
  check (!m ("2001:db9::5", "2001:db8::/32"), "not outside it");
  check (m ("2001:db8:0:ff::1", "2001:db8:0:f0::/60"), "bits in a byte");
  check (!m ("2001:db8:0:100::1", "2001:db8:0:f0::/60"), "not past them");
  check (!m ("::1", "127.0.0.1"), "IPv4 is not IPv6");
}

static struct twist_easy *
easy_for (const char *url)
{
  struct twist_easy *e = twist_easy_init ();

  twist_url_parse_int (url, &e->url);
  return e;
}

static int
is (const struct twist_easy *e, const char *want)
{
  const char *got = twist_easy_proxy (e);

  return want == NULL ? got == NULL : got != NULL && strcmp (got, want) == 0;
}

static void
test_proxy (void)
{
  struct twist_easy *e;

  clear_env ();
  e = easy_for ("http://example.com/");
  check (is (e, NULL), "no proxy without one");
  setenv ("http_proxy", "http://p1:3128", 1);
  check (is (e, "http://p1:3128"), "http_proxy");
  twist_easy_cleanup (e);

  e = easy_for ("https://example.com/");
  check (is (e, NULL), "http_proxy is not for https");
  setenv ("https_proxy", "http://p2:3128", 1);
  check (is (e, "http://p2:3128"), "https_proxy");
  setenv ("HTTPS_PROXY", "http://p3:3128", 1);
  check (is (e, "http://p2:3128"), "lower case first");
  unsetenv ("https_proxy");
  check (is (e, "http://p3:3128"), "HTTPS_PROXY");
  twist_easy_cleanup (e);

  /* HTTP_PROXY is never read: a web server can set it from a header.  */
  clear_env ();
  setenv ("HTTP_PROXY", "http://evil:1", 1);
  e = easy_for ("http://example.com/");
  check (is (e, NULL), "HTTP_PROXY is not used");
  twist_easy_cleanup (e);

  /* The scheme names the variable, for every scheme.  */
  clear_env ();
  setenv ("ftp_proxy", "http://pf:1", 1);
  setenv ("SFTP_PROXY", "http://ps:1", 1);
  setenv ("imaps_proxy", "http://pi:1", 1);
  e = easy_for ("ftp://example.com/f");
  check (is (e, "http://pf:1"), "ftp_proxy");
  twist_easy_cleanup (e);
  e = easy_for ("sftp://example.com/f");
  check (is (e, "http://ps:1"), "SFTP_PROXY");
  twist_easy_cleanup (e);
  e = easy_for ("imaps://example.com/");
  check (is (e, "http://pi:1"), "imaps_proxy");
  twist_easy_cleanup (e);
  e = easy_for ("smtp://example.com/");
  check (is (e, NULL), "no smtp_proxy, no proxy");
  twist_easy_cleanup (e);

  /* all_proxy for the rest.  */
  setenv ("ALL_PROXY", "socks5://pa:1080", 1);
  e = easy_for ("smtp://example.com/");
  check (is (e, "socks5://pa:1080"), "ALL_PROXY");
  setenv ("all_proxy", "socks5://pb:1080", 1);
  check (is (e, "socks5://pb:1080"), "all_proxy first");
  twist_easy_cleanup (e);
  e = easy_for ("ftp://example.com/f");
  check (is (e, "http://pf:1"), "the scheme's own before all_proxy");
  twist_easy_cleanup (e);

  /* An empty variable is set: it says none, and all_proxy is not asked.  */
  setenv ("ftp_proxy", "", 1);
  e = easy_for ("ftp://example.com/f");
  check (is (e, NULL), "an empty ftp_proxy is none");
  twist_easy_cleanup (e);

  /* A WebSocket goes through the proxy of HTTP when it has none of its own.  */
  clear_env ();
  setenv ("http_proxy", "http://ph:1", 1);
  setenv ("https_proxy", "http://pp:1", 1);
  e = easy_for ("ws://example.com/");
  check (is (e, "http://ph:1"), "ws uses http_proxy");
  twist_easy_cleanup (e);
  e = easy_for ("wss://example.com/");
  check (is (e, "http://pp:1"), "wss uses https_proxy");
  setenv ("ws_proxy", "http://pw:1", 1);
  twist_easy_cleanup (e);
  e = easy_for ("ws://example.com/");
  check (is (e, "http://pw:1"), "ws_proxy before it");
  twist_easy_cleanup (e);

  /* A scheme that does not use a proxy is not given one.  */
  clear_env ();
  setenv ("ALL_PROXY", "http://pa:1", 1);
  setenv ("tftp_proxy", "http://pt:1", 1);
  e = easy_for ("tftp://example.com/f");
  check (is (e, NULL), "tftp has none");
  twist_easy_cleanup (e);
  e = easy_for ("file:///etc/hostname");
  check (is (e, NULL), "nor file");
  twist_easy_cleanup (e);
}

static void
test_given (void)
{
  struct twist_easy *e;

  clear_env ();
  setenv ("http_proxy", "http://env:1", 1);
  e = easy_for ("http://example.com/");
  twist_easy_setopt (e, TWISTOPT_PROXY, "http://given:2");
  check (is (e, "http://given:2"), "given before the environment");
  twist_easy_setopt (e, TWISTOPT_PROXY, "");
  check (is (e, NULL), "\"\" is none, whatever the environment says");
  twist_easy_setopt (e, TWISTOPT_PROXY, NULL);
  check (is (e, "http://env:1"), "NULL goes back to the environment");
  twist_easy_cleanup (e);

  /* The proxy is looked at again when the URL changes, as with a redirect.  */
  clear_env ();
  setenv ("http_proxy", "http://env:1", 1);
  setenv ("no_proxy", "direct.example", 1);
  e = easy_for ("http://example.com/");
  check (is (e, "http://env:1"), "through the proxy");
  twist_url_free_int (e->url);
  e->url = NULL;
  twist_url_parse_int ("http://direct.example/x", &e->url);
  check (is (e, NULL), "and then not, for another host");
  twist_easy_cleanup (e);
}

static void
test_noproxy (void)
{
  struct twist_easy *e;

  clear_env ();
  setenv ("http_proxy", "http://env:1", 1);
  e = easy_for ("http://www.local.com/");
  setenv ("NO_PROXY", "local.com", 1);
  check (is (e, NULL), "NO_PROXY");
  unsetenv ("NO_PROXY");
  setenv ("no_proxy", "other.org", 1);
  check (is (e, "http://env:1"), "no_proxy that is not this host");
  setenv ("no_proxy", "local.com", 1);
  setenv ("NO_PROXY", "other.org", 1);
  check (is (e, NULL), "no_proxy before NO_PROXY");

  /* It disables a proxy that was given, too.  */
  twist_easy_setopt (e, TWISTOPT_PROXY, "http://given:2");
  check (is (e, NULL), "NO_PROXY with a proxy that was given");

  /* The application's list is used instead of the environment's, and "" is
     an empty one.  */
  twist_easy_setopt (e, TWISTOPT_NOPROXY, "other.org");
  check (is (e, "http://given:2"), "the given list instead of the environment's");
  twist_easy_setopt (e, TWISTOPT_NOPROXY, "www.local.com");
  check (is (e, NULL), "the given list");
  twist_easy_setopt (e, TWISTOPT_NOPROXY, "");
  check (is (e, "http://given:2"), "\"\" overrides the environment's list");
  twist_easy_setopt (e, TWISTOPT_NOPROXY, NULL);
  check (is (e, NULL), "NULL goes back to the environment's");
  twist_easy_setopt (e, TWISTOPT_NOPROXY, "*");
  twist_easy_setopt (e, TWISTOPT_PROXY, NULL);
  unsetenv ("no_proxy");
  unsetenv ("NO_PROXY");
  check (is (e, NULL), "* is every host");
  twist_easy_cleanup (e);

  /* An address in the list and a host that is one.  */
  clear_env ();
  setenv ("http_proxy", "http://env:1", 1);
  setenv ("no_proxy", "192.168.0.0/16,::1", 1);
  e = easy_for ("http://192.168.7.7:8080/");
  check (is (e, NULL), "a network in no_proxy");
  twist_easy_cleanup (e);
  e = easy_for ("http://[::1]:8080/");
  check (is (e, NULL), "an IPv6 address in no_proxy");
  twist_easy_cleanup (e);
  e = easy_for ("http://10.0.0.1/");
  check (is (e, "http://env:1"), "an address outside it");
  twist_easy_cleanup (e);
}

int
main (void)
{
  test_match ();
  test_proxy ();
  test_given ();
  test_noproxy ();
  clear_env ();
  return tests_finish ();
}
