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

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

/* The user name and password in a URL are percent-encoded, because they may
   hold the characters that end them (@ : /).  What the handlers use is the
   name and the password themselves, and what is written back is encoded
   again.  An encoded CR, LF or NUL is no better than a raw one: the name
   goes into FTP and SMTP commands.  */
/* BASE_TEXT resolved against REF is EXPECT, written as twist_url_format
   writes it (with the port).  */
static void
resolves (const char *base_text, const char *ref, const char *expect)
{
  struct twist_url *base = NULL;
  struct twist_url *out = NULL;
  char *text = NULL;
  int ok;

  ok = twist_url_parse_int (base_text, &base) == TWIST_OK
       && twist_url_resolve_int (base, ref, &out) == TWIST_OK
       && (text = twist_url_format (out)) != NULL
       && strcmp (text, expect) == 0;
  if (!ok)
    fprintf (stderr, "  %s + \"%s\" gave %s, wanted %s\n", base_text, ref,
             text != NULL ? text : "(nothing)", expect);
  check (ok, "a reference resolves as RFC 3986 says");
  free (text);
  twist_url_free_int (out);
  twist_url_free_int (base);
}

/* RFC 3986 section 5.4, the normal and the abnormal examples, with base
   http://a/b/c/d;p?q, and what a redirect really sends: an authority
   (//host/path), a query that holds a URL, an IPv6 origin, and a reference
   longer than any fixed buffer.  A relative Location from a server is
   hostile input, and these were resolved wrongly: //host stayed on the
   origin, a bracketed origin failed to resolve, ?y and #s lost the last path
   segment, a reference was cut off at 2 KiB, and .. stayed in the path.  */
static void
test_url_resolve (void)
{
  static const char base[] = "http://a/b/c/d;p?q";
  static const struct { const char *ref, *want; } v[] = {
    { "g", "/b/c/g" }, { "./g", "/b/c/g" }, { "g/", "/b/c/g/" },
    { "/g", "/g" }, { "?y", "/b/c/d;p?y" }, { "g?y", "/b/c/g?y" },
    { "#s", "/b/c/d;p?q" }, { "g#s", "/b/c/g" }, { "g?y#s", "/b/c/g?y" },
    { ";x", "/b/c/;x" }, { "g;x", "/b/c/g;x" }, { "g;x?y#s", "/b/c/g;x?y" },
    { "", "/b/c/d;p?q" }, { ".", "/b/c/" }, { "./", "/b/c/" },
    { "..", "/b/" }, { "../", "/b/" }, { "../g", "/b/g" }, { "../..", "/" },
    { "../../", "/" }, { "../../g", "/g" },
    { "../../../g", "/g" }, { "../../../../g", "/g" }, { "/./g", "/g" },
    { "/../g", "/g" }, { "g.", "/b/c/g." }, { ".g", "/b/c/.g" },
    { "g..", "/b/c/g.." }, { "..g", "/b/c/..g" }, { "./../g", "/b/g" },
    { "./g/.", "/b/c/g/" }, { "g/./h", "/b/c/g/h" }, { "g/../h", "/b/c/h" },
    { "g;x=1/./y", "/b/c/g;x=1/y" }, { "g;x=1/../y", "/b/c/y" },
    { "g?y/./x", "/b/c/g?y/./x" }, { "g?y/../x", "/b/c/g?y/../x" },
    { "g#s/./x", "/b/c/g" }, { "g#s/../x", "/b/c/g" }
  };
  struct twist_url *b = NULL;
  struct twist_url *out = NULL;
  char *long_ref;
  char want[64];
  size_t i;

  for (i = 0; i < sizeof v / sizeof v[0]; i++)
    {
      snprintf (want, sizeof want, "http://a:80%s", v[i].want);
      resolves (base, v[i].ref, want);
    }
  /* An authority, which is another host, and not a path on this one.  */
  resolves (base, "//g", "http://g:80/");
  resolves (base, "//g/p?x=1", "http://g:80/p?x=1");
  resolves (base, "//g:8080/p", "http://g:8080/p");
  resolves ("https://a/b", "//h/x", "https://h:443/x");
  /* Absolute.  */
  resolves (base, "https://x.example/y", "https://x.example:443/y");
  /* A query that has a URL in it is still a query.  */
  resolves (base, "/landed?next=http://other.example/",
            "http://a:80/landed?next=http://other.example/");
  resolves (base, "g?next=http://other.example/",
            "http://a:80/b/c/g?next=http://other.example/");
  /* An origin that is an IPv6 address, or has no path.  */
  resolves ("http://[::1]:8080/a/b", "/c", "http://[::1]:8080/c");
  resolves ("http://[::1]:8080/a/b", "d", "http://[::1]:8080/a/d");
  resolves ("http://[::1]:8080/a/b", "//[::2]/e", "http://[::2]:80/e");
  resolves ("http://h", "x", "http://h:80/x");
  resolves ("http://h?q=1", "?r=2", "http://h:80/?r=2");

  /* Longer than any buffer: whole, not cut off.  */
  long_ref = malloc (5001);
  check (long_ref != NULL, "long ref");
  memset (long_ref, 'p', 5000);
  long_ref[0] = '/';
  long_ref[5000] = 0;
  check (twist_url_parse_int (base, &b) == TWIST_OK
         && twist_url_resolve_int (b, long_ref, &out) == TWIST_OK
         && out->path != NULL && strlen (out->path) == 5000,
         "a long reference is resolved whole");
  twist_url_free_int (out);
  twist_url_free_int (b);
  free (long_ref);
}

/* A URL that names a host has one.  "http://" parsed, and the transfer then
   waited, resolving the empty name, until its timeout.  A file has none.  */
static void
test_url_empty_host (void)
{
  struct twist_url *u = NULL;

  check (twist_url_parse_int ("http://", &u) == TWIST_ERR_URL, "http://");
  check (twist_url_parse_int ("http:///x", &u) == TWIST_ERR_URL, "http:///x");
  check (twist_url_parse_int ("https://:8443/x", &u) == TWIST_ERR_URL,
         "no host before a port");
  check (twist_url_parse_int ("http://u@/x", &u) == TWIST_ERR_URL,
         "only a user name");
  check (twist_url_parse_int ("sftp://u@/x", &u) == TWIST_ERR_URL,
         "sftp too");
  check (twist_url_parse_int ("file:///tmp/x", &u) == TWIST_OK
         && u->host != NULL && u->host[0] == 0, "a file has no host");
  twist_url_free_int (u);
  u = NULL;
  check (twist_url_parse_int ("http://h/x", &u) == TWIST_OK, "a host is fine");
  twist_url_free_int (u);
}

/* What follows a host is a port of digits and then the end of the authority,
   and a host is made of characters that can be in one.  "http://h:80junk/x"
   was taken for port 80 and a path "junk/x", sent as "GET junk/x"; a port
   that started with a space, a tab, a newline or a sign was read by strtol;
   and "http://ho st/" was a host with a space in it.  curl takes none of
   these.  An empty port is the default one, as in curl.  */
static void
test_url_strict (void)
{
  static const char *const bad[] = {
    "http://h:80junk/x", "http://h:80 /x", "http://h: 80/", "http://h:\n80/",
    "http://h:\t80/", "http://h:+80/", "http://h:-1/", "http://h:99999/",
    "http://h:8x/", "http://h:0x50/", "http://[::1]junk/x", "http://[::1]:80junk/",
    "http://ho st/", "http://host\t/x", "http://a\\b/c", "http://a|b/",
    "http://h%41/", "http://h<b>/", "http://h\"x/", "http://h^x/",
    "http://h`x/", "http://h{x}/", "sftp://ho st/f", "ftp://a b/f"
  };
  struct twist_url *u = NULL;
  size_t i;

  for (i = 0; i < sizeof bad / sizeof bad[0]; i++)
    {
      int rc = twist_url_parse_int (bad[i], &u);

      if (rc == TWIST_OK)
        fprintf (stderr, "  parsed: %s\n", bad[i]);
      check (rc == TWIST_ERR_URL, "a URL with a bad port or host is refused");
      twist_url_free_int (u);
      u = NULL;
    }
  check (twist_url_parse_int ("http://h:/x", &u) == TWIST_OK && u->port == 80
         && strcmp (u->host, "h") == 0 && strcmp (u->path, "/x") == 0,
         "an empty port is the default");
  twist_url_free_int (u);
  check (twist_url_parse_int ("https://h:8443/x?a=b#f", &u) == TWIST_OK
         && u->port == 8443, "a port");
  twist_url_free_int (u);
  check (twist_url_parse_int ("http://under_score-1.example.com./", &u)
         == TWIST_OK, "a name with _ and - and a final dot");
  twist_url_free_int (u);
  check (twist_url_parse_int ("http://m\xc3\xbcnchen.example/", &u) == TWIST_OK,
         "a name in UTF-8 is not refused");
  twist_url_free_int (u);
  check (twist_url_parse_int ("http://h:80?q=1", &u) == TWIST_OK && u->port == 80,
         "a port, then a query");
  twist_url_free_int (u);
  check (twist_url_parse_int ("http://h:80#f", &u) == TWIST_OK, "then a fragment");
  twist_url_free_int (u);
  check (twist_url_parse_int ("http://[::1]:8080/p", &u) == TWIST_OK
         && u->port == 8080, "an IPv6 address and a port");
  twist_url_free_int (u);
}

static void
test_url_userinfo (void)
{
  struct twist_url *u = NULL, *again = NULL;
  char *text;

  check (twist_url_parse_int ("sftp://us%40er:p%3Ass%2Fw%25@host/x", &u)
         == TWIST_OK, "encoded userinfo parses");
  check (u != NULL && strcmp (u->user, "us@er") == 0
         && strcmp (u->password, "p:ss/w%") == 0, "userinfo is decoded");
  text = twist_url_format (u);
  check (text != NULL
         && strcmp (text, "sftp://us%40er:p%3Ass%2Fw%25@host:22/x") == 0,
         "and encoded again when written");
  if (text != NULL)
    {
      check (twist_url_parse_int (text, &again) == TWIST_OK
             && strcmp (again->user, u->user) == 0
             && strcmp (again->password, u->password) == 0,
             "it round-trips");
      twist_url_free_int (again);
    }
  free (text);
  twist_url_free_int (u);

  /* Not an escape: left as it is.  A plus is a plus.  UTF-8 is bytes.  */
  check (twist_url_parse_int ("ftp://a%zzb+c%4:d%C3%A9@host/", &u) == TWIST_OK
         && strcmp (u->user, "a%zzb+c%4") == 0
         && strcmp (u->password, "d\xc3\xa9") == 0, "what is not an escape");
  twist_url_free_int (u);

  /* A password that is empty is not one that is missing.  */
  check (twist_url_parse_int ("sftp://user:@host/", &u) == TWIST_OK
         && u->password != NULL && u->password[0] == 0, "an empty password");
  twist_url_free_int (u);
  check (twist_url_parse_int ("sftp://user@host/", &u) == TWIST_OK
         && u->password == NULL, "no password");
  twist_url_free_int (u);

  /* What would end a command, or the string.  */
  check (twist_url_parse_int ("ftp://a%0d%0aDELE%20x:pw@host/", &u)
         == TWIST_ERR_URL, "an encoded CRLF in the user");
  check (twist_url_parse_int ("ftp://a:b%0ac@host/", &u) == TWIST_ERR_URL,
         "an encoded LF in the password");
  check (twist_url_parse_int ("sftp://a%00b:pw@host/", &u) == TWIST_ERR_URL,
         "an encoded NUL in the user");
  check (twist_url_parse_int ("sftp://a:b%00c@host/", &u) == TWIST_ERR_URL,
         "an encoded NUL in the password");
  check (twist_url_parse_int ("ftp://a\r\nb:pw@host/", &u) == TWIST_ERR_URL,
         "a raw CRLF, as before");
}

/* An IPv6 address in a URL is in brackets, and the host is kept without
   them.  Written back it has them again, or the text would not parse.  A link
   local address may carry the name of the interface, which RFC 6874 writes
   after %25 (a percent sign, encoded); the host keeps it as ssh does
   (fe80::1%eth0), it is written back encoded, and it is not part of the
   authority a Host header names.  */
/* A connection that is not made in time is given up on: the default is five
   minutes, and 0 means that again.  */
static void
test_connect_timeout_default (void)
{
  twist_transfer *transfer = twist_transfer_new ();

  check (transfer != NULL && transfer->connect_timeout_ms == 300000,
         "a connect timeout by default");
  twist_transfer_setopt (transfer, TWISTOPT_CONNECTTIMEOUT_MS, 5000L);
  check (transfer->connect_timeout_ms == 5000, "set");
  twist_transfer_setopt (transfer, TWISTOPT_CONNECTTIMEOUT_MS, 0L);
  check (transfer->connect_timeout_ms == 300000, "0 is the default");
  twist_transfer_free (transfer);
}

static void
test_url_ipv6 (void)
{
  struct twist_url *u = NULL, *again = NULL;
  char *text;
  char buf[128];

  check (twist_url_parse_int ("sftp://u@[::1]:2222/p", &u) == TWIST_OK
         && strcmp (u->host, "::1") == 0 && u->port == 2222,
         "an IPv6 literal with a port");
  text = twist_url_format (u);
  check (text != NULL && strcmp (text, "sftp://u@[::1]:2222/p") == 0,
         "is written with its brackets");
  free (text);
  twist_url_free_int (u);

  check (twist_url_parse_int ("http://[2001:db8::7]/x?y=1", &u) == TWIST_OK
         && strcmp (u->host, "2001:db8::7") == 0 && u->port == 80,
         "and without one");
  text = twist_url_format (u);
  check (text != NULL && strcmp (text, "http://[2001:db8::7]:80/x?y=1") == 0,
         "the effective URL parses again");
  if (text != NULL)
    {
      check (twist_url_parse_int (text, &again) == TWIST_OK
             && strcmp (again->host, "2001:db8::7") == 0, "it round-trips");
      twist_url_free_int (again);
    }
  free (text);
  check (twist_url_host_text (u, 0, buf, sizeof buf) == TWIST_OK
         && strcmp (buf, "[2001:db8::7]") == 0, "the host as an authority");
  twist_url_free_int (u);

  check (twist_url_parse_int ("http://example.com/", &u) == TWIST_OK
         && twist_url_host_text (u, 0, buf, sizeof buf) == TWIST_OK
         && strcmp (buf, "example.com") == 0, "a name has no brackets");
  twist_url_free_int (u);

  /* The zone.  */
  check (twist_url_parse_int ("sftp://u@[fe80::1%25eth0]:22/p", &u) == TWIST_OK
         && strcmp (u->host, "fe80::1%eth0") == 0, "a zone is decoded");
  text = twist_url_format (u);
  check (text != NULL && strcmp (text, "sftp://u@[fe80::1%25eth0]:22/p") == 0,
         "and encoded again");
  free (text);
  check (twist_url_host_text (u, 1, buf, sizeof buf) == TWIST_OK
         && strcmp (buf, "[fe80::1%25eth0]") == 0, "with the zone");
  check (twist_url_host_text (u, 0, buf, sizeof buf) == TWIST_OK
         && strcmp (buf, "[fe80::1]") == 0, "and without it, for a Host header");
  twist_url_free_int (u);
  /* The URL reported back has no credentials in it.  */
  check (twist_url_parse_int ("http://alice:s3cret@h.example:8080/p?q=1", &u)
         == TWIST_OK, "a URL with credentials");
  text = twist_url_effective (u);
  check (text != NULL && strcmp (text, "http://h.example:8080/p?q=1") == 0,
         "the effective URL has neither user nor password");
  free (text);
  text = twist_url_format (u);
  check (text != NULL
         && strcmp (text, "http://alice:s3cret@h.example:8080/p?q=1") == 0,
         "and the full form still has both");
  free (text);
  twist_url_free_int (u);
  check (twist_url_parse_int ("sftp://u@[::1]:2222/p", &u) == TWIST_OK, "user");
  text = twist_url_effective (u);
  check (text != NULL && strcmp (text, "sftp://[::1]:2222/p") == 0,
         "a user name alone is left out too");
  free (text);
  twist_url_free_int (u);
  /* A URL with no port, such as a file, is written without one.  */
  check (twist_url_parse_int ("file:///tmp/x%20y", &u) == TWIST_OK, "file");
  text = twist_url_format (u);
  check (text != NULL && strcmp (text, "file:///tmp/x%20y") == 0,
         "a file URL has no :0");
  free (text);
  twist_url_free_int (u);

  check (twist_url_parse_int ("sftp://[fe80::1%253]/", &u) == TWIST_OK
         && strcmp (u->host, "fe80::1%3") == 0, "a zone that is a number");
  twist_url_free_int (u);
  check (twist_url_parse_int ("sftp://[fe80::1%eth0]/", &u) == TWIST_OK
         && strcmp (u->host, "fe80::1%eth0") == 0,
         "a zone with a bare percent sign");
  twist_url_free_int (u);
  check (twist_url_parse_int ("sftp://[fe80::1%25en%2Dp0]/", &u) == TWIST_OK
         && strcmp (u->host, "fe80::1%en-p0") == 0, "an encoded character");
  twist_url_free_int (u);

  /* What cannot be a zone is refused, since the text goes to the system and
     to known_hosts.  */
  check (twist_url_parse_int ("sftp://[fe80::1%25]/", &u) == TWIST_ERR_URL,
         "an empty zone");
  /* Brackets hold an IPv6 address and nothing else.  */
  check (twist_url_parse_int ("sftp://[::g]/", &u) == TWIST_ERR_URL,
         "text that is not an address");
  check (twist_url_parse_int ("sftp://[1:2:3]/", &u) == TWIST_ERR_URL,
         "too few groups");
  check (twist_url_parse_int ("sftp://[1.2.3.4]/", &u) == TWIST_ERR_URL,
         "an IPv4 address in brackets");
  check (twist_url_parse_int ("sftp://[example.com]/", &u) == TWIST_ERR_URL,
         "a name in brackets");
  check (twist_url_parse_int ("sftp://[::ffff:1.2.3.4]/", &u) == TWIST_OK
         && strcmp (u->host, "::ffff:1.2.3.4") == 0, "a mapped address");
  twist_url_free_int (u);
  check (twist_url_parse_int ("sftp://[fe80::1%25a%20b]/", &u)
         == TWIST_ERR_URL, "a space in a zone");
  check (twist_url_parse_int ("sftp://[fe80::1%25a%0ab]/", &u)
         == TWIST_ERR_URL, "a newline in a zone");
  check (twist_url_parse_int ("sftp://[fe80::1%25a%00b]/", &u)
         == TWIST_ERR_URL, "a NUL in a zone");
  check (twist_url_parse_int ("sftp://[fe80::1%25a%25b]/", &u)
         == TWIST_ERR_URL, "a percent sign in a zone");
  check (twist_url_parse_int ("sftp://[fe80::1%25a/b]/", &u) == TWIST_ERR_URL,
         "a slash in a zone");
  check (twist_url_parse_int ("sftp://[fe80::1%25aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa]/",
                              &u) == TWIST_ERR_URL, "a very long zone");
}

static void
test_url (void)
{
  struct twist_url *url = NULL;
  struct twist_url *rel = NULL;

  check (twist_url_parse_int ("http://user:secret@example.com:8080/a/b?x=1#f",
                              &url) == TWIST_OK, "parse");
  check (url != NULL && strcmp (url->scheme, "http") == 0, "scheme");
  check (strcmp (url->host, "example.com") == 0, "host");
  check (url->port == 8080, "port");
  check (strcmp (url->path, "/a/b") == 0, "path");
  check (strcmp (url->query, "x=1") == 0, "query");
  check (strcmp (url->user, "user") == 0, "user");
  check (twist_url_resolve_int (url, "/z", &rel) == TWIST_OK, "resolve");
  check (rel != NULL && strcmp (rel->path, "/z") == 0, "rel path");
  check (strcmp (rel->host, "example.com") == 0, "rel host");
  twist_url_free_int (rel);
  {
    char target[128];

    check (twist_url_proxy_target (url, target, sizeof target) == TWIST_OK,
           "proxy target");
    check (strcmp (target, "http://example.com:8080/a/b?x=1") == 0,
           "proxy no user");
  }
  twist_url_free_int (url);
  check (twist_url_parse_int ("http://example.com/a\r\nb", &url)
         == TWIST_ERR_URL, "crlf path");
  check (twist_url_parse_int ("http://ex\r\n.com/", &url) == TWIST_ERR_URL,
         "crlf host");
  check (twist_url_parse_int ("http://example.com/%0d%0a", &url) == TWIST_OK,
         "encoded crlf");
  twist_url_free_int (url);
}

static void
test_scheme (void)
{
  const struct twist_scheme *http = twist_scheme_by_name ("http");
  const struct twist_scheme *ftp = twist_scheme_by_name ("ftp");
  const struct twist_scheme *ftps = twist_scheme_by_name ("ftps");
  const struct twist_scheme *smtp = twist_scheme_by_name ("smtp");

  check (http != NULL && (http->flags & TWIST_SCHEME_READY) != 0, "http");
  check (ftp != NULL && (ftp->flags & TWIST_SCHEME_READY) != 0, "ftp");
  check (ftps != NULL && (ftps->flags & TWIST_SCHEME_READY) != 0, "ftps");
  check (smtp != NULL && (smtp->flags & TWIST_SCHEME_READY) != 0, "smtp");
  check (twist_scheme_by_name ("imap") != NULL
         && (twist_scheme_by_name ("imap")->flags & TWIST_SCHEME_READY) != 0,
         "imap");
  check (twist_scheme_by_name ("pop3s") != NULL
         && (twist_scheme_by_name ("pop3s")->flags & TWIST_SCHEME_READY) != 0,
         "pop3s");
  check (twist_scheme_by_name ("mqtt") != NULL
         && (twist_scheme_by_name ("mqtt")->flags & TWIST_SCHEME_READY) != 0,
         "mqtt");
  check (twist_scheme_by_name ("mqtts") != NULL
         && (twist_scheme_by_name ("mqtts")->flags & TWIST_SCHEME_TLS) != 0,
         "mqtts");
  check (twist_scheme_by_name ("ldaps") != NULL
         && (twist_scheme_by_name ("ldaps")->flags & TWIST_SCHEME_READY) != 0,
         "ldaps");
  check (twist_scheme_by_name ("no-such") == NULL, "missing");
  check (twist_scheme_by_name ("file") != NULL, "file");
  check (twist_scheme_by_name ("ws") != NULL
         && (twist_scheme_by_name ("ws")->flags & TWIST_SCHEME_READY) != 0,
         "ws");
  check (twist_scheme_by_name ("wss") != NULL
         && (twist_scheme_by_name ("wss")->flags & TWIST_SCHEME_TLS) != 0
         && (twist_scheme_by_name ("wss")->flags & TWIST_SCHEME_READY) != 0,
         "wss");
  check (twist_scheme_by_name ("gopher") != NULL
         && (twist_scheme_by_name ("gopher")->flags & TWIST_SCHEME_READY) != 0,
         "gopher");
  check (twist_scheme_by_name ("gophers") != NULL
         && (twist_scheme_by_name ("gophers")->flags & TWIST_SCHEME_TLS) != 0
         && (twist_scheme_by_name ("gophers")->flags & TWIST_SCHEME_READY) != 0,
         "gophers");
  check (twist_scheme_by_name ("dict") != NULL
         && (twist_scheme_by_name ("dict")->flags & TWIST_SCHEME_READY) != 0
         && twist_scheme_by_name ("dict")->default_port == 2628,
         "dict");
  check (twist_scheme_by_name ("tftp") != NULL
         && (twist_scheme_by_name ("tftp")->flags & TWIST_SCHEME_READY) != 0
         && (twist_scheme_by_name ("tftp")->flags & TWIST_SCHEME_DATAGRAM) != 0
         && twist_scheme_by_name ("tftp")->default_port == 69,
         "tftp");
}

/* What the proxy sends next, as a string of bytes; NULL if nothing.  */
static uint8_t *
px_next (struct twist_proxy *p, size_t *len)
{
  uint8_t *out = NULL;

  *len = 0;
  if (twist_proxy_opening (p, &out, len) != TWIST_OK)
    return NULL;
  return out;
}

static int
px_feed (struct twist_proxy *p, const void *data, size_t n, size_t *used,
         int *ready)
{
  *used = 0;
  *ready = 0;
  return twist_proxy_feed (p, data, n, used, ready);
}

static int
has (const uint8_t *buf, size_t len, const char *text)
{
  size_t n = strlen (text), i;

  for (i = 0; buf != NULL && i + n <= len; i++)
    if (memcmp (buf + i, text, n) == 0)
      return 1;
  return 0;
}

/* HTTP CONNECT.  An SSH server speaks first, so what follows the proxy's
   reply in the same read belongs to the tunnel: the proxy says how much of
   what it was given was its own.  */
static void
test_proxy_http (void)
{
  struct twist_proxy *p;
  uint8_t *out;
  size_t len, used;
  int ready, st = 0;
  static const char ok[] = "HTTP/1.1 200 Connection Established\r\n\r\n";
  char big[6000];
  size_t i;

  p = twist_proxy_new (TWIST_PROXY_HTTP, "127.0.0.1", 8080, NULL);
  twist_proxy_set_target (p, "example.com", 443);
  out = px_next (p, &len);
  check (out != NULL && has (out, len, "CONNECT example.com:443 HTTP/1.1\r\n")
         && has (out, len, "\r\nHost: example.com:443\r\n")
         && !has (out, len, "Proxy-Authorization"), "connect line, no auth");
  free (out);
  check (px_next (p, &len) == NULL, "nothing more to send while waiting");
  check (px_feed (p, ok, sizeof ok - 1, &used, &ready) == TWIST_OK
         && ready == 1 && used == sizeof ok - 1, "ready, all of it its own");
  twist_proxy_free (p);

  /* The server's banner in the same read.  */
  p = twist_proxy_new (TWIST_PROXY_HTTP, "127.0.0.1", 8080, NULL);
  twist_proxy_set_target (p, "h", 22);
  free (px_next (p, &len));
  {
    char both[256];

    snprintf (both, sizeof both, "%sSSH-2.0-OpenSSH_9\r\n", ok);
    check (px_feed (p, both, strlen (both), &used, &ready) == TWIST_OK
           && ready == 1 && used == sizeof ok - 1,
           "the banner after the reply is not the proxy's");
  }
  twist_proxy_free (p);

  /* The reply in pieces, a byte at a time: the count is of the last piece.  */
  p = twist_proxy_new (TWIST_PROXY_HTTP, "127.0.0.1", 8080, NULL);
  twist_proxy_set_target (p, "h", 22);
  free (px_next (p, &len));
  ready = 0;
  for (i = 0; i < sizeof ok - 1 && !ready; i++)
    {
      char two[2] = { ok[i], 'S' };

      /* One byte of the reply and one that is not: the second is the
         tunnel's if the reply is over with the first.  */
      check (px_feed (p, two, i + 1 < sizeof ok - 1 ? 1 : 2, &used, &ready)
             == TWIST_OK, "piece");
      if (ready)
        check (used == 1, "the last byte of the reply, and not the next");
    }
  check (ready == 1, "ready after the last piece");
  twist_proxy_free (p);

  /* A long reply: a proxy may say a good deal.  */
  p = twist_proxy_new (TWIST_PROXY_HTTP, "127.0.0.1", 8080, NULL);
  twist_proxy_set_target (p, "h", 22);
  free (px_next (p, &len));
  snprintf (big, sizeof big, "HTTP/1.1 200 OK\r\nX-Pad: ");
  len = strlen (big);
  memset (big + len, 'a', 5000);
  len += 5000;
  memcpy (big + len, "\r\n\r\n", 4);
  len += 4;
  check (px_feed (p, big, len, &used, &ready) == TWIST_OK && ready == 1
         && used == len, "a reply of five thousand bytes");
  twist_proxy_free (p);

  /* One that never ends is refused.  */
  p = twist_proxy_new (TWIST_PROXY_HTTP, "127.0.0.1", 8080, NULL);
  twist_proxy_set_target (p, "h", 22);
  free (px_next (p, &len));
  memset (big, 'a', sizeof big);
  memcpy (big, "HTTP/1.1 200 ", 13);
  for (i = 0; i < 4; i++)
    if (px_feed (p, big, sizeof big, &used, &ready) != TWIST_OK)
      break;
  check (i < 4 && ready == 0, "a reply with no end is refused");
  twist_proxy_free (p);

  /* Statuses.  Any 2xx is a tunnel.  */
  p = twist_proxy_new (TWIST_PROXY_HTTP, "127.0.0.1", 8080, NULL);
  twist_proxy_set_target (p, "h", 22);
  free (px_next (p, &len));
  check (px_feed (p, "HTTP/1.0 204 No Content\r\n\r\n", 27, &used, &ready)
         == TWIST_OK && ready == 1, "204 is a tunnel");
  twist_proxy_free (p);

  p = twist_proxy_new (TWIST_PROXY_HTTP, "127.0.0.1", 8080, NULL);
  twist_proxy_set_target (p, "h", 22);
  free (px_next (p, &len));
  check (px_feed (p, "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n", 45,
                  &used, &ready) == TWIST_ERR_PROXY && ready == 0,
         "403 is refused");
  {
    const char *msg = twist_proxy_error (p, &st);

    check (msg != NULL && strcmp (msg, "CONNECT tunnel failed, response 403")
           == 0 && st == 56, "with the words and status of a refusal");
  }
  check (px_feed (p, "x", 1, &used, &ready) == TWIST_ERR_PROXY,
         "and it stays failed");
  twist_proxy_free (p);

  p = twist_proxy_new (TWIST_PROXY_HTTP, "127.0.0.1", 8080, NULL);
  twist_proxy_set_target (p, "h", 22);
  free (px_next (p, &len));
  check (px_feed (p, "HTTP/1.1 407 Proxy Authentication Required\r\n\r\n", 46,
                  &used, &ready) == TWIST_ERR_PROXY
         && strstr (twist_proxy_error (p, &st), "response 407") != NULL,
         "407 is refused");
  twist_proxy_free (p);

  p = twist_proxy_new (TWIST_PROXY_HTTP, "127.0.0.1", 8080, NULL);
  twist_proxy_set_target (p, "h", 22);
  free (px_next (p, &len));
  check (px_feed (p, "SSH-2.0-nonsense\r\n\r\n", 20, &used, &ready)
         == TWIST_ERR_PROXY, "what is not HTTP at all");
  twist_proxy_free (p);

  /* An IPv6 target is in brackets, or the line names nothing.  */
  p = twist_proxy_new (TWIST_PROXY_HTTP, "127.0.0.1", 8080, NULL);
  twist_proxy_set_target (p, "2001:db8::7", 22);
  out = px_next (p, &len);
  check (out != NULL && has (out, len, "CONNECT [2001:db8::7]:22 HTTP/1.1")
         && has (out, len, "\r\nHost: [2001:db8::7]:22\r\n"),
         "an IPv6 target has brackets");
  free (out);
  twist_proxy_free (p);

  /* Credentials: Basic, of user:password.  */
  p = twist_proxy_new (TWIST_PROXY_HTTP, "127.0.0.1", 8080, NULL);
  twist_proxy_set_target (p, "h", 22);
  twist_proxy_set_credentials (p, "pxuser", "px:pass");
  out = px_next (p, &len);
  check (out != NULL
         && has (out, len, "\r\nProxy-Authorization: Basic "
                 "cHh1c2VyOnB4OnBhc3M=\r\n"), "Basic credentials");
  free (out);
  twist_proxy_free (p);
}

/* A long credential reaches the proxy whole, and the request that carries it
   still ends with its blank line.  The Proxy-Authorization line went into a
   buffer of 512 bytes, so a password over about 360 bytes was cut off, with
   the end of the line and of the request, and the proxy went on reading the
   TLS that followed as more headers.  And a status is three digits: "4  "
   was taken for 224 and a success.  */
static void
test_proxy_long_credentials (void)
{
  struct twist_proxy *p;
  uint8_t *out;
  size_t len;
  char pass[501];
  char cred[512];
  char *enc = NULL;
  char want[1024];
  size_t used;
  int ready;
  static const char *const bad[] = {
    "HTTP/1.1 4  \r\n\r\n", "HTTP/1.1 2x0 OK\r\n\r\n",
    "HTTP/1.1 2000 OK\r\n\r\n", "HTTP/1.1 20 OK\r\n\r\n",
    "HTTP/1.1 +20 OK\r\n\r\n", "HTTP/1.1 600 OK\r\n\r\n",
    "HTTP/1.1 000 OK\r\n\r\n"
  };
  size_t i;

  memset (pass, 'p', sizeof pass - 1);
  pass[sizeof pass - 1] = 0;
  p = twist_proxy_new (TWIST_PROXY_HTTP, "127.0.0.1", 8080, NULL);
  twist_proxy_set_target (p, "example.com", 443);
  twist_proxy_set_credentials (p, "user", pass);
  out = px_next (p, &len);
  snprintf (cred, sizeof cred, "user:%s", pass);
  check (twist_b64_encode ((const uint8_t *) cred, strlen (cred), &enc)
         == TWIST_OK, "encode");
  snprintf (want, sizeof want, "Proxy-Authorization: Basic %s\r\n", enc);
  check (out != NULL && has (out, len, want),
         "a long password is sent whole");
  check (out != NULL && len >= 4 && memcmp (out + len - 4, "\r\n\r\n", 4) == 0,
         "and the request ends with its blank line");
  free (enc);
  free (out);
  twist_proxy_free (p);

  for (i = 0; i < sizeof bad / sizeof bad[0]; i++)
    {
      p = twist_proxy_new (TWIST_PROXY_HTTP, "127.0.0.1", 8080, NULL);
      twist_proxy_set_target (p, "h", 22);
      free (px_next (p, &len));
      check (px_feed (p, bad[i], strlen (bad[i]), &used, &ready) != TWIST_OK
             || ready == 0, "a status that is not three digits is refused");
      twist_proxy_free (p);
    }
  check (twist_status_code ("200") == 200 && twist_status_code ("404") == 404
         && twist_status_code ("101") == 101 && twist_status_code ("599") == 599,
         "status digits");
  check (twist_status_code ("4  ") == -1 && twist_status_code ("2x0") == -1
         && twist_status_code ("+20") == -1 && twist_status_code ("600") == -1
         && twist_status_code ("099") == -1 && twist_status_code ("") == -1
         && twist_status_code ("20") == -1, "and what is not");
}

static void
test_proxy_socks (void)
{
  struct twist_proxy *p;
  uint8_t *out;
  size_t len, used;
  int ready, st = 0;
  static const uint8_t none[] = { 5, 0 };
  static const uint8_t pw[] = { 5, 2 };
  static const uint8_t refuse[] = { 5, 0xff };
  static const uint8_t okay[] = { 5, 0, 0, 1, 0, 0, 0, 0, 0, 0 };

  /* No credentials: only "no authentication" is offered.  */
  p = twist_proxy_new (TWIST_PROXY_SOCKS5H, "127.0.0.1", 1080, NULL);
  twist_proxy_set_target (p, "example.com", 80);
  out = px_next (p, &len);
  check (out != NULL && len == 3 && out[0] == 5 && out[1] == 1 && out[2] == 0,
         "greeting, no credentials");
  free (out);
  check (px_feed (p, none, 2, &used, &ready) == TWIST_OK && used == 2
         && !ready, "method accepted");
  out = px_next (p, &len);
  check (out != NULL && len == 7 + 11 && out[0] == 5 && out[1] == 1
         && out[3] == 3 && out[4] == 11 && memcmp (out + 5, "example.com", 11)
         == 0 && out[16] == 0 && out[17] == 80, "a name is a domain name");
  free (out);
  check (px_feed (p, okay, sizeof okay, &used, &ready) == TWIST_OK && ready
         && used == sizeof okay, "ready");
  twist_proxy_free (p);

  /* The reply and the server's banner in one read.  */
  p = twist_proxy_new (TWIST_PROXY_SOCKS5H, "127.0.0.1", 1080, NULL);
  twist_proxy_set_target (p, "h", 22);
  free (px_next (p, &len));
  px_feed (p, none, 2, &used, &ready);
  free (px_next (p, &len));
  {
    uint8_t both[64];

    memcpy (both, okay, sizeof okay);
    memcpy (both + sizeof okay, "SSH-2.0-x\r\n", 11);
    check (px_feed (p, both, sizeof okay + 11, &used, &ready) == TWIST_OK
           && ready && used == sizeof okay,
           "the banner after the reply is not the proxy's");
  }
  twist_proxy_free (p);

  /* A reply in pieces.  */
  p = twist_proxy_new (TWIST_PROXY_SOCKS5H, "127.0.0.1", 1080, NULL);
  twist_proxy_set_target (p, "h", 22);
  free (px_next (p, &len));
  px_feed (p, none, 2, &used, &ready);
  free (px_next (p, &len));
  check (px_feed (p, okay, 3, &used, &ready) == TWIST_OK && !ready
         && used == 3, "three bytes of the reply");
  check (px_feed (p, okay + 3, 4, &used, &ready) == TWIST_OK && !ready,
         "four more");
  {
    uint8_t tail[4] = { okay[7], okay[8], okay[9], 'S' };

    check (px_feed (p, tail, sizeof tail, &used, &ready) == TWIST_OK && ready
           && used == 3, "the end, and one that is not the proxy's");
  }
  twist_proxy_free (p);

  /* Address types: the target as it is.  */
  p = twist_proxy_new (TWIST_PROXY_SOCKS5H, "127.0.0.1", 1080, NULL);
  twist_proxy_set_target (p, "10.1.2.3", 22);
  free (px_next (p, &len));
  px_feed (p, none, 2, &used, &ready);
  out = px_next (p, &len);
  check (out != NULL && len == 10 && out[3] == 1 && out[4] == 10
         && out[5] == 1 && out[6] == 2 && out[7] == 3 && out[8] == 0
         && out[9] == 22, "an IPv4 address is one");
  free (out);
  twist_proxy_free (p);

  p = twist_proxy_new (TWIST_PROXY_SOCKS5H, "127.0.0.1", 1080, NULL);
  twist_proxy_set_target (p, "2001:db8::1", 2222);
  free (px_next (p, &len));
  px_feed (p, none, 2, &used, &ready);
  out = px_next (p, &len);
  check (out != NULL && len == 22 && out[3] == 4 && out[4] == 0x20
         && out[5] == 0x01 && out[19] == 1 && out[20] == 0x08
         && out[21] == 0xae, "and an IPv6 address");
  free (out);
  twist_proxy_free (p);

  /* A zone cannot be said to a proxy; the address is.  */
  p = twist_proxy_new (TWIST_PROXY_SOCKS5H, "127.0.0.1", 1080, NULL);
  twist_proxy_set_target (p, "fe80::1%eth0", 22);
  free (px_next (p, &len));
  px_feed (p, none, 2, &used, &ready);
  out = px_next (p, &len);
  check (out != NULL && len == 22 && out[3] == 4 && out[4] == 0xfe
         && out[19] == 1, "an address with a zone, without the zone");
  free (out);
  twist_proxy_free (p);

  /* Username and password (RFC 1929).  */
  p = twist_proxy_new (TWIST_PROXY_SOCKS5H, "127.0.0.1", 1080, NULL);
  twist_proxy_set_target (p, "h", 22);
  twist_proxy_set_credentials (p, "pxuser", "pxpass");
  out = px_next (p, &len);
  check (out != NULL && len == 4 && out[1] == 2 && out[2] == 0 && out[3] == 2,
         "greeting offers both with credentials");
  free (out);
  check (px_feed (p, pw, 2, &used, &ready) == TWIST_OK, "method 2");
  out = px_next (p, &len);
  check (out != NULL && len == 3 + 6 + 6 && out[0] == 1 && out[1] == 6
         && memcmp (out + 2, "pxuser", 6) == 0 && out[8] == 6
         && memcmp (out + 9, "pxpass", 6) == 0, "the credentials");
  free (out);
  check (px_next (p, &len) == NULL, "and nothing else while it waits");
  check (px_feed (p, "\x01\x00", 2, &used, &ready) == TWIST_OK && used == 2,
         "accepted");
  out = px_next (p, &len);
  check (out != NULL && len > 4 && out[1] == 1, "then the request");
  free (out);
  twist_proxy_free (p);

  p = twist_proxy_new (TWIST_PROXY_SOCKS5H, "127.0.0.1", 1080, NULL);
  twist_proxy_set_target (p, "h", 22);
  twist_proxy_set_credentials (p, "pxuser", "bad");
  free (px_next (p, &len));
  px_feed (p, pw, 2, &used, &ready);
  free (px_next (p, &len));
  check (px_feed (p, "\x01\x01", 2, &used, &ready) == TWIST_ERR_PROXY
         && strcmp (twist_proxy_error (p, &st),
                    "User was rejected by the SOCKS5 server (1 1).") == 0
         && st == 97, "credentials refused");
  twist_proxy_free (p);

  /* A server that wants credentials when there are none.  */
  p = twist_proxy_new (TWIST_PROXY_SOCKS5H, "127.0.0.1", 1080, NULL);
  twist_proxy_set_target (p, "h", 22);
  free (px_next (p, &len));
  check (px_feed (p, refuse, 2, &used, &ready) == TWIST_ERR_PROXY
         && strcmp (twist_proxy_error (p, &st),
                    "No authentication method was acceptable.") == 0
         && st == 97, "no method it will do");
  twist_proxy_free (p);

  p = twist_proxy_new (TWIST_PROXY_SOCKS5H, "127.0.0.1", 1080, NULL);
  twist_proxy_set_target (p, "h", 22);
  free (px_next (p, &len));
  check (px_feed (p, pw, 2, &used, &ready) == TWIST_ERR_PROXY,
         "a method that was not offered");
  twist_proxy_free (p);

  /* The request refused.  */
  p = twist_proxy_new (TWIST_PROXY_SOCKS5H, "127.0.0.1", 1080, NULL);
  twist_proxy_set_target (p, "10.9.9.9", 22);
  free (px_next (p, &len));
  px_feed (p, none, 2, &used, &ready);
  free (px_next (p, &len));
  check (px_feed (p, "\x05\x05\x00\x01\x00\x00\x00\x00\x00\x00", 10, &used,
                  &ready) == TWIST_ERR_PROXY
         && strcmp (twist_proxy_error (p, &st),
                    "Can't complete SOCKS5 connection to 10.9.9.9. (5)") == 0
         && st == 97, "refused with its reason");
  twist_proxy_free (p);

  /* Bound addresses of the three kinds are skipped by length.  */
  {
    static const uint8_t v6[] = { 5, 0, 0, 4, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
                                  11, 12, 13, 14, 15, 16, 0, 80, 'S' };
    static const uint8_t nm[] = { 5, 0, 0, 3, 3, 'a', 'b', 'c', 0, 80, 'S' };

    p = twist_proxy_new (TWIST_PROXY_SOCKS5H, "127.0.0.1", 1080, NULL);
    twist_proxy_set_target (p, "h", 22);
    free (px_next (p, &len));
    px_feed (p, none, 2, &used, &ready);
    free (px_next (p, &len));
    check (px_feed (p, v6, sizeof v6, &used, &ready) == TWIST_OK && ready
           && used == sizeof v6 - 1, "a bound IPv6 address");
    twist_proxy_free (p);
    p = twist_proxy_new (TWIST_PROXY_SOCKS5H, "127.0.0.1", 1080, NULL);
    twist_proxy_set_target (p, "h", 22);
    free (px_next (p, &len));
    px_feed (p, none, 2, &used, &ready);
    free (px_next (p, &len));
    check (px_feed (p, nm, sizeof nm, &used, &ready) == TWIST_OK && ready
           && used == sizeof nm - 1, "a bound name");
    twist_proxy_free (p);
  }
}

/* SOCKS4 and SOCKS4a: one request, one reply of eight bytes.  The user id is
   the proxy user, or empty.  An IPv4 address is the address; for 4a a name
   is sent after the user id, with 0.0.0.1 as the address; for 4 a name is
   looked up before the request, which the proxy asks for by saying it is not
   ready (TWIST_ERR_AGAIN).  */
static void
test_proxy_socks4 (void)
{
  struct twist_proxy *p;
  uint8_t *out;
  size_t len, used;
  int ready, st = 0;
  static const uint8_t granted[] = { 0, 90, 0, 0, 0, 0, 0, 0 };
  static const uint8_t rejected[] = { 0, 91, 0, 0, 0, 0, 0, 0 };

  p = twist_proxy_new (TWIST_PROXY_SOCKS4, "127.0.0.1", 1080, NULL);
  twist_proxy_set_target (p, "10.1.2.3", 22);
  out = px_next (p, &len);
  check (out != NULL && len == 9 && out[0] == 4 && out[1] == 1
         && out[2] == 0 && out[3] == 22 && out[4] == 10 && out[5] == 1
         && out[6] == 2 && out[7] == 3 && out[8] == 0,
         "an IPv4 address, no user");
  free (out);
  check (px_feed (p, granted, 5, &used, &ready) == TWIST_OK && !ready
         && used == 5, "a reply in pieces");
  check (px_feed (p, granted + 5, 3, &used, &ready) == TWIST_OK && ready
         && used == 3, "granted");
  twist_proxy_free (p);

  p = twist_proxy_new (TWIST_PROXY_SOCKS4, "127.0.0.1", 1080, NULL);
  twist_proxy_set_target (p, "10.1.2.3", 22);
  twist_proxy_set_credentials (p, "bob", "ignored");
  out = px_next (p, &len);
  check (out != NULL && len == 12 && memcmp (out + 8, "bob", 4) == 0,
         "the user id is the user");
  free (out);
  check (px_feed (p, rejected, 8, &used, &ready) == TWIST_ERR_PROXY
         && strcmp (twist_proxy_error (p, &st),
                    "Can't complete SOCKS4 connection to 10.1.2.3. (91)") == 0
         && st == 97, "rejected");
  twist_proxy_free (p);

  p = twist_proxy_new (TWIST_PROXY_SOCKS4, "127.0.0.1", 1080, NULL);
  twist_proxy_set_target (p, "example.com", 22);
  check (px_next (p, &len) == NULL, "a name is not sent to a socks4 proxy");
  twist_proxy_free (p);

  p = twist_proxy_new (TWIST_PROXY_SOCKS4A, "127.0.0.1", 1080, NULL);
  twist_proxy_set_target (p, "example.com", 80);
  out = px_next (p, &len);
  check (out != NULL && len == 9 + 12 && out[4] == 0 && out[5] == 0
         && out[6] == 0 && out[7] == 1 && out[8] == 0
         && memcmp (out + 9, "example.com", 12) == 0,
         "socks4a sends the name after the user");
  free (out);
  twist_proxy_free (p);

  p = twist_proxy_new (TWIST_PROXY_SOCKS4A, "127.0.0.1", 1080, NULL);
  twist_proxy_set_target (p, "2001:db8::1", 80);
  check (px_next (p, &len) == NULL
         && twist_proxy_feed (p, granted, 8, &used, &ready) == TWIST_ERR_PROXY
         && strstr (twist_proxy_error (p, &st), "IPv6") != NULL,
         "there is no IPv6 address in socks4");
  twist_proxy_free (p);

  /* socks5:// with an address in hand is the same request as socks5h://.  */
  p = twist_proxy_new (TWIST_PROXY_SOCKS5, "127.0.0.1", 1080, NULL);
  twist_proxy_set_target (p, "10.1.2.3", 22);
  free (px_next (p, &len));
  px_feed (p, "\x05\x00", 2, &used, &ready);
  out = px_next (p, &len);
  check (out != NULL && len == 10 && out[3] == 1, "socks5, an address");
  free (out);
  twist_proxy_free (p);

  p = twist_proxy_new (TWIST_PROXY_SOCKS5, "127.0.0.1", 1080, NULL);
  twist_proxy_set_target (p, "example.com", 22);
  free (px_next (p, &len));
  px_feed (p, "\x05\x00", 2, &used, &ready);
  check (px_next (p, &len) == NULL, "socks5 does not send a name");
  twist_proxy_free (p);
}

static void
test_proxy_parse (void)
{
  int kind = 0, port = 0;
  char *host = NULL, *user = NULL, *pass = NULL;

#define PARSE(s) (free (host), free (user), free (pass), host = user = pass = NULL, \
                  twist_proxy_parse ((s), &kind, &host, &port, &user, &pass))
  check (PARSE ("http://proxy.example:3128") == TWIST_OK
         && kind == TWIST_PROXY_HTTP && strcmp (host, "proxy.example") == 0
         && port == 3128 && user == NULL && pass == NULL, "http");
  check (PARSE ("proxy.example") == TWIST_OK && kind == TWIST_PROXY_HTTP
         && port == 8080, "no scheme: http, 8080");
  check (PARSE ("socks5://s:9050") == TWIST_OK && kind == TWIST_PROXY_SOCKS5
         && port == 9050, "socks5");
  check (PARSE ("socks5h://s") == TWIST_OK && kind == TWIST_PROXY_SOCKS5H
         && port == 1080, "socks5h, 1080");
  check (PARSE ("socks4://s:1081") == TWIST_OK && kind == TWIST_PROXY_SOCKS4
         && port == 1081, "socks4");
  check (PARSE ("socks4a://u@s") == TWIST_OK && kind == TWIST_PROXY_SOCKS4A
         && port == 1080 && strcmp (user, "u") == 0, "socks4a, a user");
  check (PARSE ("http://u:p%40w@h:3128/") == TWIST_OK
         && strcmp (user, "u") == 0 && strcmp (pass, "p@w") == 0
         && strcmp (host, "h") == 0 && port == 3128, "credentials, decoded");
  check (PARSE ("http://u@h") == TWIST_OK && strcmp (user, "u") == 0
         && pass != NULL && pass[0] == 0, "a user and no password");
  check (PARSE ("http://[::1]:3128") == TWIST_OK && strcmp (host, "::1") == 0
         && port == 3128, "an IPv6 proxy with a port");
  check (PARSE ("socks5://[fe80::1%25eth0]") == TWIST_OK
         && strcmp (host, "fe80::1%eth0") == 0 && port == 1080,
         "an IPv6 proxy without one");
  check (PARSE ("http://u:p@[::1]:80") == TWIST_OK && strcmp (host, "::1") == 0
         && strcmp (user, "u") == 0, "both");
  check (PARSE ("https://h") == TWIST_OK && kind == TWIST_PROXY_HTTPS
         && strcmp (host, "h") == 0 && port == 443, "https, 443");
  check (PARSE ("HTTPS://u:p@h:8443/") == TWIST_OK && kind == TWIST_PROXY_HTTPS
         && port == 8443 && strcmp (user, "u") == 0, "https, any case, with more");
  check (PARSE ("socks4x://h") == TWIST_ERR_UNSUPPORTED, "another scheme");
  check (PARSE ("ftp://h") == TWIST_ERR_UNSUPPORTED, "another scheme");
  check (PARSE ("http://") != TWIST_OK, "no host");
  check (PARSE ("http://h:99999") != TWIST_OK, "a port that is too big");
  check (PARSE ("http://h:abc") != TWIST_OK, "a port that is not one");
  free (host);
  free (user);
  free (pass);
#undef PARSE
}

static void
test_conn_pool (void)
{
  struct twist_loop *loop = twist_loop_new (1);
  struct twist_pool *pool = twist_pool_new ();
  struct twist_connection *got = NULL;
  int i;
  int n = 0;
  char key[16];

  check (loop != NULL && pool != NULL, "pool alloc");
  for (i = 0; i < 9; i++)
    {
      struct twist_connection *c = twist_connection_new (loop);

      check (c != NULL
             && twist_pool_put_idle (pool, "h", c, 1000) == TWIST_OK,
             "pool put");
    }
  while (twist_pool_take (pool, "h", &got) == TWIST_OK)
    {
      n++;
      twist_connection_free (got);
    }
  check (n == 8, "pool per-host cap");
  for (i = 0; i < 33; i++)
    {
      struct twist_connection *c = twist_connection_new (loop);

      snprintf (key, sizeof key, "k%d", i);
      check (c != NULL
             && twist_pool_put_idle (pool, key, c, 5000) == TWIST_OK,
             "pool many");
    }
  n = 0;
  for (i = 0; i < 33; i++)
    {
      snprintf (key, sizeof key, "k%d", i);
      if (twist_pool_take (pool, key, &got) == TWIST_OK)
        {
          n++;
          twist_connection_free (got);
        }
    }
  check (n == 32, "pool total cap");
  {
    struct twist_connection *c = twist_connection_new (loop);

    /* The idle timer is the loop's, as in real use; the loop is told the
       time, and the connection goes when its age is reached.  */
    check (twist_pool_put_idle (pool, "old", c, 0) == TWIST_OK, "pool age put");
    twist_loop_on_timer (loop, 117999);
    check (twist_pool_take (pool, "old", &got) == TWIST_OK, "pool not expired");
    twist_connection_free (got);
    c = twist_connection_new (loop);
    check (twist_pool_put_idle (pool, "old", c, 0) == TWIST_OK, "pool age put 2");
    twist_loop_on_timer (loop, 118000);
    check (twist_pool_take (pool, "old", &got) == TWIST_ERR_AGAIN, "pool expired");
  }
  twist_pool_free (pool);
  twist_loop_free (loop);
}

/* A parked connection that hears from its server (data, or its close) has its
   discard posted to the loop.  If the pool is freed before the loop runs it,
   the posted discard must not touch what the pool freed (a sanitizer build
   is what sees it).  */
static void
test_pool_free_with_post (void)
{
  struct twist_loop *loop = twist_loop_new (1);
  struct twist_pool *pool = twist_pool_new ();
  struct twist_connection *c = twist_connection_new (loop);
  int sv[2];

  check (loop != NULL && pool != NULL && c != NULL, "alloc");
  check (socketpair (AF_UNIX, SOCK_STREAM, 0, sv) == 0, "socketpair");
  fcntl (sv[0], F_SETFL, O_NONBLOCK);
  twist_connection_set_fd (c, sv[0]);
  check (twist_pool_put_idle (pool, "h", c, 0) == TWIST_OK, "parked");
  /* The server speaks: the connection is not one to keep.  */
  check (write (sv[1], "x", 1) == 1, "the server writes");
  /* Read at once, without running the loop: the discard is posted and waits.  */
  twist_connection_on_readable (c);
  twist_pool_free (pool);
  /* As a runtime does when it is freed: what was posted is delivered.  */
  twist_loop_drain (loop);
  twist_loop_free (loop);
  close (sv[1]);
}

/* What a runtime made for a program that polls tells it.  */
struct hooks
{
  twist_runtime *runtime;
  int watches;
  int removes;
  int last_fd;
  int last_what;
  int timers;
  long last_ms;
  int recursive_rc;
};

static void
hook_watch (int fd, int what, void *user)
{
  struct hooks *h = user;

  h->watches++;
  h->last_fd = fd;
  h->last_what = what;
  if (what == TWIST_POLL_REMOVE)
    h->removes++;
}

static void
hook_timer (long ms, void *user)
{
  struct hooks *h = user;

  h->timers++;
  h->last_ms = ms;
  h->recursive_rc = twist_runtime_on_timer (h->runtime);
}

static void
test_runtime_run_once (void)
{
  struct twist_runtime *runtime = twist_runtime_new ();
  struct twist_runtime *emb;
  struct hooks h;

  check (runtime != NULL, "runtime");
  check (twist_runtime_run_once (runtime, 0) == TWIST_OK,
         "run once with nothing to do");
  check (twist_runtime_on_ready (runtime, 0, TWIST_POLL_IN) == TWIST_ERR_INVAL
         && twist_runtime_on_timer (runtime) == TWIST_ERR_INVAL,
         "a handle with a poller is not driven by the program");
  twist_runtime_free (runtime);

  memset (&h, 0, sizeof h);
  emb = twist_runtime_new_embedded (hook_watch, hook_timer, &h);
  h.runtime = emb;
  check (emb != NULL, "embedded runtime");
  check (h.watches == 1 && h.last_what == TWIST_POLL_IN && h.last_fd >= 0,
         "an embedded handle tells the program of the descriptor that wakes it");
  check (twist_runtime_run_once (emb, 0) == TWIST_ERR_INVAL,
         "and has no loop of its own to run");
  check (twist_runtime_new_embedded (NULL, hook_timer, NULL) == NULL
         && twist_runtime_new_embedded (hook_watch, NULL, NULL) == NULL,
         "both hooks are required");
  twist_runtime_free (emb);
}

/* A TCP listener on the loopback that never answers.  A transfer to it
   ends by its own timeout with the connection still open.  */
static int
listen_loopback (int *port)
{
  struct sockaddr_in sin;
  socklen_t len = sizeof sin;
  int fd = socket (AF_INET, SOCK_STREAM, 0);

  if (fd < 0)
    return -1;
  memset (&sin, 0, sizeof sin);
  sin.sin_family = AF_INET;
  sin.sin_addr.s_addr = htonl (INADDR_LOOPBACK);
  if (bind (fd, (struct sockaddr *) &sin, sizeof sin) != 0
      || listen (fd, 4) != 0
      || getsockname (fd, (struct sockaddr *) &sin, &len) != 0)
    {
      close (fd);
      return -1;
    }
  fcntl (fd, F_SETFL, O_NONBLOCK);
  *port = ntohs (sin.sin_port);
  return fd;
}

static twist_transfer *
timeout_transfer (int port)
{
  twist_transfer *transfer = twist_transfer_new ();
  char url[64];

  snprintf (url, sizeof url, "mqtt://127.0.0.1:%d/x", port);
  twist_transfer_setopt (transfer, TWISTOPT_URL, url);
  twist_transfer_setopt (transfer, TWISTOPT_TIMEOUT_MS, 200L);
  return transfer;
}

/* The runtime called from a callback.  A write callback runs inside the
   delivery of the transfer's own data, so a handle freed there, or a loop run
   again there, is freed or entered under the code that called it.  Those are
   refused (the first with TWIST_ERR_RECURSIVE), and the transfer goes on and
   ends as it would have.  Starting another transfer touches only that one,
   and is allowed: a callback is where the next transfer is started.  */
static twist_runtime *cb_runtime;
static twist_transfer *cb_transfer;
static twist_transfer *cb_second;
static struct check_job cb_second_job;
static int cb_run_rc;
static int cb_start_rc;
static int cb_attached;
static int cb_calls;
static size_t cb_bytes;
static size_t cb_bytes2;

static size_t
call_runtime_in_callback (char *ptr, size_t size, size_t nmemb, void *user)
{
  (void) ptr;
  (void) user;
  cb_calls++;
  cb_bytes += size * nmemb;
  if (cb_calls == 1)
    {
      cb_run_rc = twist_runtime_run_once (cb_runtime, 0);
      /* Neither is done, since the call that is running needs both; this
         must not crash.  */
      twist_runtime_free (cb_runtime);
      twist_transfer_free (cb_transfer);
      cb_attached = cb_transfer->runtime == cb_runtime;
      cb_start_rc = twist_runtime_start (cb_runtime, cb_second, check_job_done,
                                         &cb_second_job);
    }
  return size * nmemb;
}

static size_t
second_body (char *ptr, size_t size, size_t nmemb, void *user)
{
  (void) ptr;
  (void) user;
  cb_bytes2 += size * nmemb;
  return size * nmemb;
}

static void
test_runtime_from_callback (void)
{
  char path[] = "/tmp/twist-recursive-XXXXXX";
  char url[128];
  char block[1024];
  int fd = mkstemp (path);
  int i;
  struct check_job job = { 0, 0, 0 };

  check (fd >= 0, "a file to read");
  if (fd < 0)
    return;
  memset (block, 'x', sizeof block);
  for (i = 0; i < 8; i++)
    if (write (fd, block, sizeof block) != (ssize_t) sizeof block)
      abort ();
  close (fd);
  snprintf (url, sizeof url, "file://%s", path);

  cb_runtime = twist_runtime_new ();
  cb_transfer = twist_transfer_new ();
  cb_second = twist_transfer_new ();
  memset (&cb_second_job, 0, sizeof cb_second_job);
  cb_run_rc = cb_start_rc = -99;
  cb_attached = 0;
  cb_calls = 0;
  cb_bytes = cb_bytes2 = 0;
  twist_transfer_setopt (cb_transfer, TWISTOPT_URL, url);
  twist_transfer_setopt (cb_transfer, TWISTOPT_WRITEFUNCTION,
                         call_runtime_in_callback);
  twist_transfer_setopt (cb_second, TWISTOPT_URL, url);
  twist_transfer_setopt (cb_second, TWISTOPT_WRITEFUNCTION, second_body);
  check (twist_runtime_start (cb_runtime, cb_transfer, check_job_done, &job)
         == TWIST_OK, "start");
  for (i = 0; i < 400 && !(job.done && cb_second_job.done); i++)
    twist_runtime_run_once (cb_runtime, 5);
  check (cb_calls > 0, "the write callback ran");
  check (cb_run_rc == TWIST_ERR_RECURSIVE,
         "running the loop from a callback is refused");
  check (cb_attached, "and so is freeing the handle: it is still in its runtime");
  check (job.done && job.calls == 1 && job.result == TWIST_OK
         && cb_bytes == 8 * sizeof block,
         "and the transfer ended with all its data, once reported");
  check (cb_start_rc == TWIST_OK, "starting another from a callback is not");
  check (cb_second_job.done && cb_second_job.result == TWIST_OK
         && cb_second_job.calls == 1 && cb_bytes2 == 8 * sizeof block,
         "and the other ran, and was reported");
  check (cb_transfer->runtime == NULL && cb_second->runtime == NULL,
         "a handle that has been reported is in no runtime");
  twist_transfer_free (cb_transfer);
  twist_transfer_free (cb_second);
  twist_runtime_free (cb_runtime);
  unlink (path);
}

/* A handle cleaned up while it is still in a runtime leaves it first, and is
   not reported.  It used to stay in the list as a pointer to freed memory,
   which twist_runtime_free then read.  */
static void
test_cleanup_handle_in_runtime (void)
{
  twist_runtime *runtime = twist_runtime_new ();
  twist_transfer *transfer = twist_transfer_new ();
  struct check_job job = { 0, 0, 0 };

  twist_transfer_setopt (transfer, TWISTOPT_URL, "file:///nonexistent/twist");
  check (twist_runtime_start (runtime, transfer, check_job_done,
                              &job) == TWIST_OK,
         "start");
  check (twist_runtime_start (runtime, transfer, NULL,
                              NULL) == TWIST_ERR_INVAL,
         "a handle in a runtime cannot be started again");
  twist_transfer_free (transfer);
  check (runtime->n_transfers == 0, "a cleaned up handle left its runtime");
  twist_runtime_run_once (runtime, 0);
  check (job.calls == 0, "and is not reported");
  twist_runtime_free (runtime);
}

/* A transfer that cannot begin is reported as any other is, from the loop and
   not from the call that started it, so that there is one place to learn how
   a transfer ended.  */
static void
test_start_failure (void)
{
  twist_runtime *runtime = twist_runtime_new ();
  twist_transfer *transfer = twist_transfer_new ();
  struct check_job job = { 0, 0, 0 };

  check (twist_runtime_start (runtime, transfer, check_job_done,
                              &job) == TWIST_OK,
         "a handle with no URL starts");
  check (job.calls == 0, "and is not reported by the call");
  check (check_pump (runtime, &job, 2000) && job.calls == 1
         && job.result == TWIST_ERR_URL, "but by the loop, once");
  check (twist_runtime_cancel (runtime, transfer) == TWIST_ERR_INVAL,
         "a handle that has been reported is not in the runtime");
  twist_transfer_free (transfer);
  twist_runtime_free (runtime);
}

/* The callback of a transfer that ends frees it and starts the next, which is
   what a program that runs a list of them does.  Each is reported after the
   one before has returned.  */
struct chain
{
  twist_runtime *runtime;
  twist_transfer *transfer[3];
  int next;
  int calls;
  int depth;
  int nested;
  int failed;
};

static void
chain_done (twist_transfer *transfer, int result, void *user)
{
  struct chain *c = user;

  if (c->depth++ > 0)
    c->nested++;
  c->calls++;
  if (result == TWIST_OK)
    c->failed++;
  twist_transfer_free (transfer);
  if (c->next < 3
      && twist_runtime_start (c->runtime, c->transfer[c->next++], chain_done,
                              c)
         != TWIST_OK)
    c->failed++;
  c->depth--;
}

static void
test_done_chain (void)
{
  struct chain c;
  int i;

  memset (&c, 0, sizeof c);
  c.runtime = twist_runtime_new ();
  for (i = 0; i < 3; i++)
    {
      c.transfer[i] = twist_transfer_new ();
      twist_transfer_setopt (c.transfer[i], TWISTOPT_URL,
                             "file:///nonexistent/twist");
    }
  c.next = 1;
  check (twist_runtime_start (c.runtime, c.transfer[0], chain_done,
                              &c) == TWIST_OK,
         "start the first");
  for (i = 0; i < 100 && c.calls < 3; i++)
    twist_runtime_run_once (c.runtime, 5);
  check (c.calls == 3 && c.failed == 0, "all three were reported, as failures");
  check (c.nested == 0, "each after the one before had returned");
  check (c.runtime->n_transfers == 0, "and the runtime holds none");
  twist_runtime_free (c.runtime);
}

/* The state of a transfer owns its connection, and the connection is
   released against the loop.  So the state must be released when the transfer
   handle leaves the loop, not later with the handle: by then the loop is
   gone and the release reads freed memory.  */
static void
test_release_transfer (void)
{
  int port = 0;
  int fd = listen_loopback (&port);
  int peer;
  twist_transfer *transfer;
  twist_runtime *runtime;
  struct check_job job = { 0, 0, 0 };
  struct timespec nap = { 0, 5000000 };
  int i;

  check (fd >= 0, "loopback listener");
  if (fd < 0)
    return;

  /* check_perform ends the transfer with the connection open.  */
  transfer = timeout_transfer (port);
  check (check_perform (transfer) != TWIST_OK, "perform times out");
  peer = accept (fd, NULL, NULL);
  check (peer >= 0, "the connection was open");
  if (peer >= 0)
    close (peer);
  check (transfer->state == NULL, "perform releases the transfer state");
  twist_transfer_free (transfer);

  /* The same through a runtime: by the time the loop reports the end,
     the handle has let go of its state and is in no runtime.  */
  runtime = twist_runtime_new ();
  transfer = timeout_transfer (port);
  check (twist_runtime_start (runtime, transfer, check_job_done,
                              &job) == TWIST_OK,
         "start");
  check (check_pump (runtime, &job, 3000) && job.calls == 1
         && job.result != TWIST_OK, "runtime transfer ended");
  check (transfer->state == NULL, "the loop releases the transfer state");
  check (transfer->runtime == NULL, "and the handle is in no runtime");
  twist_runtime_free (runtime);
  twist_transfer_free (transfer);

  /* A transfer still in the runtime when it is cleaned up is dropped.  */
  memset (&job, 0, sizeof job);
  runtime = twist_runtime_new ();
  transfer = timeout_transfer (port);
  check (twist_runtime_start (runtime, transfer, check_job_done,
                              &job) == TWIST_OK,
         "start 2");
  for (i = 0; i < 10; i++)
    {
      twist_runtime_run_once (runtime, 0);
      nanosleep (&nap, NULL);
    }
  twist_runtime_free (runtime);
  check (transfer->state == NULL,
         "runtime cleanup releases the transfer state");
  check (transfer->runtime == NULL && job.calls == 0,
         "and lets the handle go without reporting it");
  twist_transfer_free (transfer);
  close (fd);
}

/* A transfer that is cancelled closes its connection, and is reported, from
   the loop, with TWIST_ERR_ABORTED.  */
static void
test_cancel (void)
{
  int port = 0;
  int fd = listen_loopback (&port);
  int peer = -1;
  twist_runtime *runtime = twist_runtime_new ();
  twist_transfer *transfer = timeout_transfer (port);
  struct check_job job = { 0, 0, 0 };
  struct timespec nap = { 0, 5000000 };
  char buf[64];
  ssize_t n = -1;
  int i;

  check (fd >= 0 && runtime != NULL, "cancel setup");
  if (fd < 0)
    return;
  twist_transfer_setopt (transfer, TWISTOPT_TIMEOUT_MS, 30000L);
  check (twist_runtime_start (runtime, transfer, check_job_done,
                              &job) == TWIST_OK,
         "start");
  for (i = 0; i < 200 && peer < 0; i++)
    {
      twist_runtime_run_once (runtime, 0);
      peer = accept (fd, NULL, NULL);
      if (peer < 0)
        nanosleep (&nap, NULL);
    }
  check (peer >= 0, "the transfer connected");
  check (twist_runtime_cancel (runtime, transfer) == TWIST_OK, "cancel");
  check (!job.done, "it is reported by the loop, not by the call");
  check (check_pump (runtime, &job, 3000) && job.calls == 1
         && job.result == TWIST_ERR_ABORTED, "and reported once, as aborted");
  check (twist_runtime_cancel (runtime, transfer) == TWIST_ERR_INVAL,
         "a transfer that has ended cannot be cancelled");
  if (peer >= 0)
    {
      /* The descriptor is closed on a turn of the loop, which is given to it
         while the close is waited for: on a machine that is busy the turn
         that does it can be some time coming.  */
      fcntl (peer, F_SETFL, O_NONBLOCK);
      for (i = 0; i < 600 && n != 0; i++)
        {
          twist_runtime_run_once (runtime, 0);
          while ((n = recv (peer, buf, sizeof buf, 0)) > 0)
            ;
          if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK)
            break;
          if (n != 0)
            nanosleep (&nap, NULL);
        }
      check (n == 0, "the connection was closed");
      close (peer);
    }
  twist_transfer_free (transfer);
  twist_runtime_free (runtime);
  close (fd);
}

/* The connect timeout, as curl has it, covers the whole of making the
   connection: for smtp, imap, pop3 and ftp that is the lookup, the TCP connect
   and the greeting, and the login after it, so a server that takes the
   connection and then says nothing, or says its greeting and then nothing,
   ends the transfer at the connect timeout, and not at the transfer's.  The
   other protocols have no greeting to wait for, and have the connect timeout
   for the TCP connect only: a server that is silent is waited for until the
   transfer's own.  The server here accepts, may say GREETING, and keeps the
   connection open.  */
static void
connect_timeout_case (const char *scheme, const char *path,
                      const char *greeting, int covered)
{
  int port = 0;
  int fd = listen_loopback (&port);
  int peer = -1;
  twist_runtime *runtime = twist_runtime_new ();
  twist_transfer *transfer = twist_transfer_new ();
  struct check_job job = { 0, 0, 0 };
  struct timespec nap = { 0, 5000000 };
  char url[96];
  char what[160];
  int i;

  snprintf (url, sizeof url, "%s://127.0.0.1:%d%s", scheme, port, path);
  snprintf (what, sizeof what, "%s: %s, %s", scheme,
            greeting != NULL ? "greeting and then nothing" : "nothing",
            covered ? "ends at the connect timeout"
            : "waits for the transfer's timeout");
  check (fd >= 0 && runtime != NULL && transfer != NULL, "connect timeout setup");
  if (fd < 0)
    return;
  twist_transfer_setopt (transfer, TWISTOPT_URL, url);
  twist_transfer_setopt (transfer, TWISTOPT_CONNECTTIMEOUT_MS, 300L);
  twist_transfer_setopt (transfer, TWISTOPT_TIMEOUT_MS, 20000L);
  check (twist_runtime_start (runtime, transfer, check_job_done, &job)
         == TWIST_OK, "connect timeout start");
  for (i = 0; i < 200 && peer < 0; i++)
    {
      twist_runtime_run_once (runtime, 0);
      peer = accept (fd, NULL, NULL);
      if (peer < 0)
        nanosleep (&nap, NULL);
    }
  check (peer >= 0, "the transfer connected");
  if (peer >= 0 && greeting != NULL)
    {
      if (send (peer, greeting, strlen (greeting), 0) < 0)
        check (0, "the greeting was sent");
    }
  if (covered)
    check (check_pump (runtime, &job, 5000) && job.calls == 1
           && job.result == TWIST_ERR_TIMEOUT, what);
  else
    {
      /* Well past the connect timeout and well short of the transfer's.  */
      check (!check_pump (runtime, &job, 1500) && !job.done, what);
      twist_runtime_cancel (runtime, transfer);
      check_pump (runtime, &job, 3000);
    }
  if (peer >= 0)
    close (peer);
  twist_transfer_free (transfer);
  twist_runtime_free (runtime);
  close (fd);
}

static void
test_connect_timeout (void)
{
  connect_timeout_case ("smtp", "/", NULL, 1);
  connect_timeout_case ("smtp", "/", "220 hello\r\n", 1);
  connect_timeout_case ("imap", "/INBOX/", NULL, 1);
  connect_timeout_case ("imap", "/INBOX/", "* OK hello\r\n", 1);
  connect_timeout_case ("pop3", "/", NULL, 1);
  connect_timeout_case ("pop3", "/", "+OK hello\r\n", 1);
  connect_timeout_case ("ftp", "/f", NULL, 1);
  connect_timeout_case ("ftp", "/f", "220 hello\r\n", 1);
  connect_timeout_case ("dict", "/d:word", NULL, 0);
  connect_timeout_case ("gopher", "/1/", NULL, 0);
  connect_timeout_case ("http", "/", NULL, 0);
  connect_timeout_case ("mqtt", "/x", NULL, 0);
}

/* A Unix socket in place of the host and port of the URL (TWISTOPT_UNIX_SOCKET
   and the abstract form).  The data path is in integration/http-unix.sh; here,
   what is refused and what is not looked up.  */
static void
test_unix_socket_options (void)
{
  twist_transfer *transfer = twist_transfer_new ();
  char big[200];

  memset (big, 'a', sizeof big - 1);
  big[sizeof big - 1] = 0;
  check (twist_transfer_setopt (transfer, TWISTOPT_UNIX_SOCKET,
                                "/tmp/twist.sock")
         == TWIST_OK, "a socket path");
  check (twist_transfer_setopt (transfer, TWISTOPT_ABSTRACT_UNIX_SOCKET,
                                "twist")
         == TWIST_OK, "an abstract name");
  check (twist_transfer_setopt (transfer, TWISTOPT_UNIX_SOCKET, big) == TWIST_ERR_INVAL,
         "a path too long for the address is refused");
  check (twist_transfer_setopt (transfer, TWISTOPT_ABSTRACT_UNIX_SOCKET, big)
         == TWIST_ERR_INVAL, "and so is a name");
  check (twist_transfer_setopt (transfer, TWISTOPT_UNIX_SOCKET,
                                NULL) == TWIST_OK
         && twist_transfer_setopt (transfer, TWISTOPT_ABSTRACT_UNIX_SOCKET, "")
         == TWIST_OK, "NULL and an empty string clear it");
  twist_transfer_free (transfer);

  /* The URL's host is not looked up: a name that cannot be resolved fails to
     connect to the socket, which is not there.  */
  transfer = twist_transfer_new ();
  twist_transfer_setopt (transfer, TWISTOPT_URL,
                         "http://no-such-host.invalid/");
  twist_transfer_setopt (transfer, TWISTOPT_UNIX_SOCKET,
                         "/nonexistent/twist.sock");
  check (check_perform (transfer) == TWIST_ERR_CONNECT,
         "the host of the URL is not looked up");
  twist_transfer_free (transfer);

  /* Proxies are not used.  */
  transfer = twist_transfer_new ();
  twist_transfer_setopt (transfer, TWISTOPT_URL,
                         "http://no-such-host.invalid/");
  twist_transfer_setopt (transfer, TWISTOPT_PROXY, "http://no-such-proxy.invalid:3128");
  twist_transfer_setopt (transfer, TWISTOPT_UNIX_SOCKET,
                         "/nonexistent/twist.sock");
  check (check_perform (transfer) == TWIST_ERR_CONNECT,
         "nor is a proxy used or looked up");
  twist_transfer_free (transfer);

  /* Only the schemes of the HTTP handler.  */
  transfer = twist_transfer_new ();
  twist_transfer_setopt (transfer, TWISTOPT_URL,
                         "ftp://no-such-host.invalid/x");
  twist_transfer_setopt (transfer, TWISTOPT_UNIX_SOCKET,
                         "/nonexistent/twist.sock");
  check (check_perform (transfer) == TWIST_ERR_UNSUPPORTED,
         "another scheme is refused, not sent over TCP");
  twist_transfer_free (transfer);

  /* No QUIC over a Unix socket.  */
  transfer = twist_transfer_new ();
  twist_transfer_setopt (transfer, TWISTOPT_URL,
                         "https://no-such-host.invalid/");
  twist_transfer_setopt (transfer, TWISTOPT_HTTP_VERSION,
                         (long) TWIST_HTTP_VERSION_3ONLY);
  twist_transfer_setopt (transfer, TWISTOPT_UNIX_SOCKET,
                         "/nonexistent/twist.sock");
  check (check_perform (transfer) == TWIST_ERR_UNSUPPORTED,
         "HTTP/3 is refused");
  twist_transfer_free (transfer);
}

/* A person's home: $HOME if it says, else what the password file says.
   They differ when something sets $HOME to somewhere else, and lack of it
   (a cron job, a stripped environment) must not mean having no home.  */
static void
test_home_dir (void)
{
  char out[256], small[4];
  char *saved = getenv ("HOME") != NULL ? twist_strdup (getenv ("HOME")) : NULL;
  struct passwd pw, *res = NULL;
  char buf[4096];

  check (getpwuid_r (getuid (), &pw, buf, sizeof buf, &res) == 0 && res != NULL
         && res->pw_dir != NULL && res->pw_dir[0] != 0, "a password entry");
  if (res == NULL)
    return;
  setenv ("HOME", "/somewhere/else", 1);
  check (twist_home_dir (out, sizeof out) == 1
         && strcmp (out, "/somewhere/else") == 0, "HOME is used");
  unsetenv ("HOME");
  check (twist_home_dir (out, sizeof out) == 1 && strcmp (out, res->pw_dir) == 0,
         "no HOME: the password file's");
  setenv ("HOME", "", 1);
  check (twist_home_dir (out, sizeof out) == 1 && strcmp (out, res->pw_dir) == 0,
         "an empty HOME is no HOME");
  setenv ("HOME", "/somewhere/else", 1);
  check (twist_home_dir (small, sizeof small) == 0,
         "a home that does not fit is not cut short");
  unsetenv ("HOME");
  check (twist_home_dir (small, sizeof small) == 0 || strlen (res->pw_dir) < 4,
         "nor the password file's");
  if (saved != NULL)
    setenv ("HOME", saved, 1);
  free (saved);
}

static void
pool_work (void *arg)
{
  (void) arg;
}

static void
pool_done (void *user, int err)
{
  (void) err;
  ++*(int *) user;
}

/* A job on the runtime's storage pool whose completion is posted to its loop.
   If the runtime is cleaned up before the loop has run, the completion must
   still be delivered: it owns the job and whatever the job carries, and
   dropping it with the loop leaks both.  The pool's threads are joined
   first, so every job has run and posted by then.  */
static void
test_pool_completion_at_cleanup (void)
{
  struct twist_runtime *runtime = twist_runtime_new ();
  int done = 0, i;

  check (runtime != NULL, "runtime");
  for (i = 0; i < 5; i++)
    check (twist_storage_submit (runtime->storage, pool_work, NULL, pool_done,
                                 &done, runtime->loop) == TWIST_OK, "submit");
  twist_runtime_free (runtime);
  check (done == 5, "completions posted before cleanup are delivered");
}


/* A pool shared by several loops holds a few connections in all.  When it
   is full the oldest is dropped; that must be one of the loop that is
   parking a new one, because a loop's connections, its timers and its
   poller belong to the thread that runs it.  Another loop's are not ours
   to free.  */
static void
test_pool_eviction_stays_on_the_loop (void)
{
  struct twist_loop *a = twist_loop_new (1);
  struct twist_loop *b = twist_loop_new (1);
  struct twist_pool *pool = twist_pool_new ();
  struct twist_connection *got = NULL;
  char key[16];
  int i, kept = 0, left_of_b = 0;

  check (a != NULL && b != NULL && pool != NULL, "eviction setup");
  for (i = 0; i < 20; i++)
    {
      snprintf (key, sizeof key, "a%d", i);
      check (twist_pool_put_idle (pool, key, twist_connection_new (a), 1000)
             == TWIST_OK, "park on a");
    }
  /* b parks more than there is room for.  What it cannot make room for in
     its own connections is not parked.  */
  for (i = 0; i < 20; i++)
    {
      struct twist_connection *c = twist_connection_new (b);

      snprintf (key, sizeof key, "b%d", i);
      if (twist_pool_put_idle (pool, key, c, 2000) != TWIST_OK)
        twist_connection_free (c);
    }
  for (i = 0; i < 20; i++)
    {
      snprintf (key, sizeof key, "a%d", i);
      if (twist_pool_take (pool, key, &got) == TWIST_OK)
        {
          kept++;
          twist_connection_free (got);
        }
    }
  check (kept == 20, "another loop's parked connections are not evicted");
  for (i = 0; i < 20; i++)
    {
      snprintf (key, sizeof key, "b%d", i);
      if (twist_pool_take (pool, key, &got) == TWIST_OK)
        {
          left_of_b++;
          twist_connection_free (got);
        }
    }
  check (left_of_b > 0 && left_of_b <= 12, "b was held to the room there was");
  twist_pool_free (pool);
  twist_loop_free (a);
  twist_loop_free (b);
}

/* ---- a small HTTP/1.1 server that keeps connections open ---- */

#define KA_MAX 16

struct ka
{
  int listen_fd;
  int port;
  int conns[KA_MAX];
  int stop;
  pthread_t thread;
  char host[128];		/* The Host header of the last request.  */
  char cookie[128];		/* Its Cookie header, or nothing.  */
  int set_cookie;		/* Answer with a cookie, sid=abc.  */
};

/* The Host header of a request, for the test to read once the transfer is
   over.  */
static void
ka_note_host (struct ka *k, const char *request)
{
  const char *h = strstr (request, "\r\nHost: ");
  size_t n;

  if (h == NULL)
    return;
  h += 8;
  n = strcspn (h, "\r");
  if (n >= sizeof k->host)
    n = sizeof k->host - 1;
  memcpy (k->host, h, n);
  k->host[n] = 0;
  __atomic_thread_fence (__ATOMIC_RELEASE);
}

/* The Cookie header of a request, for the test to read once the transfer is
   over.  */
static void
ka_note_cookie (struct ka *k, const char *request)
{
  const char *h = strstr (request, "\r\nCookie: ");
  size_t n;

  k->cookie[0] = 0;
  if (h != NULL)
    {
      h += 10;
      n = strcspn (h, "\r");
      if (n >= sizeof k->cookie)
        n = sizeof k->cookie - 1;
      memcpy (k->cookie, h, n);
      k->cookie[n] = 0;
    }
  __atomic_thread_fence (__ATOMIC_RELEASE);
}

static void *
ka_serve (void *arg)
{
  struct ka *k = arg;
  static const char reply[] =
    "HTTP/1.1 200 OK\r\nContent-Length: 6\r\nContent-Type: text/plain\r\n\r\n"
    "hello\n";
  static const char cookie_reply[] =
    "HTTP/1.1 200 OK\r\nContent-Length: 6\r\nContent-Type: text/plain\r\n"
    "Set-Cookie: sid=abc\r\n\r\nhello\n";
  struct pollfd fds[KA_MAX + 1];
  int i, n;

  while (!__atomic_load_n (&k->stop, __ATOMIC_ACQUIRE))
    {
      n = 0;
      fds[n].fd = k->listen_fd;
      fds[n++].events = POLLIN;
      for (i = 0; i < KA_MAX; i++)
        if (k->conns[i] >= 0)
          {
            fds[n].fd = k->conns[i];
            fds[n++].events = POLLIN;
          }
      if (poll (fds, (nfds_t) n, 50) <= 0)
        continue;
      if (fds[0].revents & POLLIN)
        {
          int c = accept (k->listen_fd, NULL, NULL);

          for (i = 0; c >= 0 && i < KA_MAX; i++)
            if (k->conns[i] < 0)
              {
                k->conns[i] = c;
                c = -1;
              }
          if (c >= 0)
            close (c);
        }
      for (i = 0; i < KA_MAX; i++)
        {
          char buf[2048];
          ssize_t got;
          int j, hit = 0;

          if (k->conns[i] < 0)
            continue;
          for (j = 1; j < n; j++)
            if (fds[j].fd == k->conns[i] && (fds[j].revents & (POLLIN | POLLHUP)))
              hit = 1;
          if (!hit)
            continue;
          got = read (k->conns[i], buf, sizeof buf - 1);
          if (got <= 0)
            {
              close (k->conns[i]);
              k->conns[i] = -1;
            }
          else
            {
              buf[got] = 0;
              ka_note_host (k, buf);
              ka_note_cookie (k, buf);
              if (k->set_cookie
                  ? write (k->conns[i], cookie_reply, sizeof cookie_reply - 1) < 0
                  : write (k->conns[i], reply, sizeof reply - 1) < 0)
                {
                  close (k->conns[i]);
                  k->conns[i] = -1;
                }
            }
        }
    }
  for (i = 0; i < KA_MAX; i++)
    if (k->conns[i] >= 0)
      close (k->conns[i]);
  return NULL;
}

/* On 127.0.0.1, or on ::1 if V6.  */
static int
ka_start_on (struct ka *k, int v6)
{
  struct sockaddr_in sin;
  struct sockaddr_in6 sin6;
  struct sockaddr *sa = (struct sockaddr *) &sin;
  socklen_t len = sizeof sin;
  int i;

  memset (k, 0, sizeof *k);
  for (i = 0; i < KA_MAX; i++)
    k->conns[i] = -1;
  k->listen_fd = socket (v6 ? AF_INET6 : AF_INET, SOCK_STREAM, 0);
  if (k->listen_fd < 0)
    return -1;
  memset (&sin, 0, sizeof sin);
  sin.sin_family = AF_INET;
  sin.sin_addr.s_addr = htonl (INADDR_LOOPBACK);
  if (v6)
    {
      memset (&sin6, 0, sizeof sin6);
      sin6.sin6_family = AF_INET6;
      sin6.sin6_addr = in6addr_loopback;
      sa = (struct sockaddr *) &sin6;
      len = sizeof sin6;
    }
  if (bind (k->listen_fd, sa, len) != 0 || listen (k->listen_fd, 8) != 0
      || getsockname (k->listen_fd, sa, &len) != 0)
    {
      close (k->listen_fd);
      return -1;
    }
  k->port = ntohs (v6 ? sin6.sin6_port : sin.sin_port);
  return pthread_create (&k->thread, NULL, ka_serve, k);
}

static int
ka_start (struct ka *k)
{
  return ka_start_on (k, 0);
}

static void
ka_stop (struct ka *k)
{
  __atomic_store_n (&k->stop, 1, __ATOMIC_RELEASE);
  pthread_join (k->thread, NULL);
  close (k->listen_fd);
}

static size_t
ka_body (char *ptr, size_t size, size_t nmemb, void *user)
{
  size_t *total = user;

  (void) ptr;
  *total += size * nmemb;
  return size * nmemb;
}

/* A URL with an IPv6 address is written, and its Host header too, with the
   brackets: Host: [::1]:8080, and not ::1:8080, which names nothing.  */
static void
test_http_ipv6_host (void)
{
  struct ka k;
  twist_transfer *transfer;
  char url[128], want[64];
  size_t total = 0;
  char *eff = NULL;

  if (ka_start_on (&k, 1) != 0)
    {
      fputs ("test-engine: no IPv6 loopback; skipping the IPv6 Host test\n",
             stderr);
      return;
    }
  transfer = twist_transfer_new ();
  snprintf (url, sizeof url, "http://[::1]:%d/x", k.port);
  twist_transfer_setopt (transfer, TWISTOPT_URL, url);
  twist_transfer_setopt (transfer, TWISTOPT_WRITEFUNCTION, ka_body);
  twist_transfer_setopt (transfer, TWISTOPT_WRITEDATA, &total);
  check (check_perform (transfer) == TWIST_OK && total == 6,
         "a transfer from [::1]");
  __atomic_thread_fence (__ATOMIC_ACQUIRE);
  snprintf (want, sizeof want, "[::1]:%d", k.port);
  check (strcmp (k.host, want) == 0, "the Host header has the brackets");
  twist_transfer_getinfo (transfer, TWISTINFO_EFFECTIVE_URL, &eff);
  snprintf (want, sizeof want, "http://[::1]:%d/x", k.port);
  check (eff != NULL && strcmp (eff, want) == 0,
         "the effective URL has them too");
  twist_transfer_free (transfer);
  ka_stop (&k);
}

/* What a transfer says of the response: the status line as the server sent
   it, reason phrase and all, to the header callback, and the version of the
   response through TWISTINFO_HTTP_VERSION.  The curl tool writes the same.  */
static char status_seen[128];

static size_t
status_header (char *ptr, size_t size, size_t nmemb, void *user)
{
  size_t n = size * nmemb;

  (void) user;
  if (status_seen[0] == 0 && n < sizeof status_seen)
    {
      memcpy (status_seen, ptr, n);
      status_seen[n] = 0;
    }
  return n;
}

static void
test_http_status_line (void)
{
  struct ka k;
  char url[64];
  twist_transfer *transfer;
  size_t total = 0;
  long version = -1;

  check (ka_start (&k) == 0, "status line setup");
  snprintf (url, sizeof url, "http://127.0.0.1:%d/", k.port);
  transfer = twist_transfer_new ();
  status_seen[0] = 0;
  twist_transfer_setopt (transfer, TWISTOPT_URL, url);
  twist_transfer_setopt (transfer, TWISTOPT_WRITEFUNCTION, ka_body);
  twist_transfer_setopt (transfer, TWISTOPT_WRITEDATA, &total);
  twist_transfer_setopt (transfer, TWISTOPT_HEADERFUNCTION, status_header);
  check (twist_transfer_getinfo (transfer, TWISTINFO_HTTP_VERSION, &version)
         == TWIST_OK && version == TWIST_HTTP_VERSION_NONE,
         "no version before a response");
  check (check_perform (transfer) == TWIST_OK && total == 6, "a transfer");
  check (strcmp (status_seen, "HTTP/1.1 200 OK\r\n") == 0,
         "the status line has its reason phrase");
  version = -1;
  check (twist_transfer_getinfo (transfer, TWISTINFO_HTTP_VERSION, &version)
         == TWIST_OK && version == TWIST_HTTP_VERSION_1_1,
         "and the version is HTTP/1.1");
  twist_transfer_free (transfer);
  ka_stop (&k);
}

/* The cookie jar, the HSTS list and the Alt-Svc list are the runtime's,
   and a transfer uses them only when it asks to.  Two transfers in one runtime
   handle that ask share the jar: the cookie that the first was given is sent
   by the second.  A transfer that does not ask neither keeps nor sends one,
   and a second runtime has a jar of its own.  */
static void
test_runtime_stores (void)
{
  struct twist_runtime *runtime = twist_runtime_new ();
  struct twist_runtime *other = twist_runtime_new ();
  struct ka k;
  char url[64];
  twist_transfer *transfer;
  int i;

  check (runtime != NULL && other != NULL && ka_start (&k) == 0,
         "stores setup");
  k.set_cookie = 1;
  snprintf (url, sizeof url, "http://127.0.0.1:%d/", k.port);
  for (i = 0; i < 4; i++)
    {
      struct twist_runtime *m = i == 3 ? other : runtime;
      size_t total = 0;

      k.cookie[0] = 0;
      transfer = twist_transfer_new ();
      twist_transfer_setopt (transfer, TWISTOPT_URL, url);
      twist_transfer_setopt (transfer, TWISTOPT_WRITEFUNCTION, ka_body);
      twist_transfer_setopt (transfer, TWISTOPT_WRITEDATA, &total);
      /* The third transfer does not ask.  */
      twist_transfer_setopt (transfer, TWISTOPT_USE_COOKIES, i == 2 ? 0L : 1L);
      check (check_perform_in (m, transfer) == TWIST_OK && total == 6,
             "a transfer");
      twist_transfer_free (transfer);
      __atomic_thread_fence (__ATOMIC_ACQUIRE);
      if (i == 0)
        check (k.cookie[0] == 0, "the first has no cookie to send");
      else if (i == 1)
        check (strcmp (k.cookie, "sid=abc") == 0,
               "the second sends what the first was given");
      else if (i == 2)
        check (k.cookie[0] == 0, "one that does not ask sends none");
      else
        check (k.cookie[0] == 0, "another runtime has a jar of its own");
    }
  check (twist_jar_count (runtime->jar) == 1, "one cookie in the jar");
  twist_runtime_free (other);
  twist_runtime_free (runtime);
  ka_stop (&k);
}

/* The lists themselves, as a transfer that asks sees them.  */
static void
test_runtime_lists (void)
{
  struct twist_runtime *runtime = twist_runtime_new ();
  twist_transfer *transfer = twist_transfer_new ();
  char *hdr = NULL;
  char alt[32];

  check (runtime != NULL && transfer != NULL, "lists setup");
  check (twist_transfer_jar (transfer) == NULL
         && twist_transfer_hsts (transfer) == NULL
         && twist_transfer_altsvc (transfer) == NULL,
         "a transfer that is in no runtime has none");
  transfer->runtime = runtime;
  check (twist_transfer_jar (transfer) == NULL
         && twist_transfer_hsts (transfer) == NULL
         && twist_transfer_altsvc (transfer) == NULL,
         "and one that does not ask");
  twist_transfer_setopt (transfer, TWISTOPT_USE_COOKIES, 1L);
  twist_transfer_setopt (transfer, TWISTOPT_USE_HSTS, 1L);
  twist_transfer_setopt (transfer, TWISTOPT_USE_ALTSVC, 1L);
  check (twist_transfer_jar (transfer) == runtime->jar
         && twist_transfer_hsts (transfer) == runtime->hsts
         && twist_transfer_altsvc (transfer) == runtime->altsvc,
         "one that asks has the runtime's");
  check (twist_jar_store (runtime->jar, "a=b", "h.example", "/", 1) == TWIST_OK
         && twist_jar_header (runtime->jar, "h.example", "/", 1, &hdr)
         == TWIST_OK && hdr != NULL && strstr (hdr, "a=b") != NULL,
         "a cookie is kept and sent");
  free (hdr);
  check (twist_altsvc_note (runtime->altsvc, "h.example", "h3:443") == TWIST_OK
         && twist_altsvc_lookup (runtime->altsvc, "h.example", alt,
                                 sizeof alt) == 0
         && strcmp (alt, "h3:443") == 0
         && twist_altsvc_lookup (runtime->altsvc, "other.example", alt,
                                 sizeof alt) != 0,
         "an Alt-Svc entry is kept");
  check (!twist_hsts_upgrade (runtime->hsts, "h.example", 0), "HSTS has none");
  check (twist_hsts_note (runtime->hsts, "h.example", 100) == TWIST_OK
         && twist_hsts_upgrade (runtime->hsts, "h.example", 50)
         && !twist_hsts_upgrade (runtime->hsts, "h.example", 100),
         "an HSTS entry applies until it expires");
  transfer->runtime = NULL;
  twist_transfer_free (transfer);
  twist_runtime_free (runtime);
}

/* A runtime driven by a program that polls, as a transfer to a server on
   the loopback goes through.  The program polls what it was told to and
   hands back what is ready and the deadlines that pass; no loop of the
   library's is run.  */
#define EMB_FDS 16

struct emb
{
  twist_runtime *runtime;
  struct
  {
    int fd;
    int what;
  } w[EMB_FDS];
  int nw;
  int watches;
  int timers;
  long timer_ms;
  int recursive_rc;
};

static void
emb_watch (int fd, int what, void *user)
{
  struct emb *e = user;
  int i;

  e->watches++;
  for (i = 0; i < e->nw && e->w[i].fd != fd; i++)
    ;
  if (what == TWIST_POLL_REMOVE)
    {
      if (i < e->nw)
        e->w[i] = e->w[--e->nw];
      return;
    }
  if (i == e->nw)
    {
      if (e->nw == EMB_FDS)
        return;
      e->w[e->nw++].fd = fd;
    }
  e->w[i].what = what;
}

static void
emb_timer (long ms, void *user)
{
  struct emb *e = user;

  e->timers++;
  e->timer_ms = ms;
  e->recursive_rc = twist_runtime_on_timer (e->runtime);
}

static void
emb_run (struct emb *e, struct check_job *job, int rounds)
{
  struct pollfd pf[EMB_FDS];
  int i, n, nfds;

  while (!job->done && rounds-- > 0)
    {
      int wait_ms = e->timer_ms < 0 || e->timer_ms > 20 ? 20
                    : (int) e->timer_ms;

      nfds = e->nw;
      for (i = 0; i < nfds; i++)
        {
          pf[i].fd = e->w[i].fd;
          pf[i].events = (short) ((e->w[i].what & TWIST_POLL_IN ? POLLIN : 0)
                                  | (e->w[i].what & TWIST_POLL_OUT
                                     ? POLLOUT : 0));
          pf[i].revents = 0;
        }
      n = poll (pf, (nfds_t) nfds, wait_ms);
      for (i = 0; i < nfds && n > 0; i++)
        if (pf[i].revents != 0)
          twist_runtime_on_ready (e->runtime, pf[i].fd,
                                  (pf[i].revents & (POLLIN | POLLHUP | POLLERR)
                                   ? TWIST_POLL_IN : 0)
                                  | (pf[i].revents & POLLOUT
                                     ? TWIST_POLL_OUT : 0));
      if (n == 0 || e->timer_ms == 0)
        twist_runtime_on_timer (e->runtime);
    }
}

static void
test_runtime_embedded (void)
{
  struct emb e;
  struct ka k;
  struct check_job job = { 0, 0, 0 };
  char url[64];
  size_t total = 0;
  twist_transfer *transfer = twist_transfer_new ();
  int i;

  memset (&e, 0, sizeof e);
  e.timer_ms = -1;
  e.runtime = twist_runtime_new_embedded (emb_watch, emb_timer, &e);
  check (e.runtime != NULL && e.nw == 1, "told of the waker at once");
  check (ka_start (&k) == 0, "keep-alive server");
  snprintf (url, sizeof url, "http://127.0.0.1:%d/", k.port);
  for (i = 0; i < 2; i++)
    {
      total = 0;
      memset (&job, 0, sizeof job);
      twist_transfer_setopt (transfer, TWISTOPT_URL, url);
      twist_transfer_setopt (transfer, TWISTOPT_WRITEFUNCTION, ka_body);
      twist_transfer_setopt (transfer, TWISTOPT_WRITEDATA, &total);
      check (twist_runtime_start (e.runtime, transfer, check_job_done, &job)
             == TWIST_OK, "start");
      emb_run (&e, &job, 500);
      check (job.done && job.calls == 1 && job.result == TWIST_OK
             && total == 6, "a transfer is carried by the program's loop");
    }
  check (e.watches > 2 && e.nw >= 2,
         "it was told of the connection, which is kept");
  check (e.timers > 0, "and of the deadlines");
  check (e.recursive_rc == TWIST_ERR_RECURSIVE,
         "a call into the runtime from the timer hook is refused");
  twist_transfer_free (transfer);
  twist_runtime_free (e.runtime);
  ka_stop (&k);
}

int
main (void)
{
  test_url ();
  test_url_userinfo ();
  test_url_ipv6 ();
  test_url_resolve ();
  test_url_empty_host ();
  test_url_strict ();
  test_connect_timeout_default ();
  test_http_ipv6_host ();
  test_scheme ();
  test_proxy_http ();
  test_proxy_long_credentials ();
  test_proxy_socks ();
  test_proxy_socks4 ();
  test_proxy_parse ();
  test_conn_pool ();
  test_pool_free_with_post ();
  test_runtime_run_once ();
  test_release_transfer ();
  test_cancel ();
  test_connect_timeout ();
  test_runtime_from_callback ();
  test_start_failure ();
  test_done_chain ();
  test_runtime_lists ();
  test_runtime_stores ();
  test_http_status_line ();
  test_cleanup_handle_in_runtime ();
  test_runtime_embedded ();
  test_unix_socket_options ();
  test_home_dir ();
  test_pool_completion_at_cleanup ();
  test_pool_eviction_stays_on_the_loop ();
  return tests_finish ();
}
