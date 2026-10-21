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
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

/* The user name and password in a URL are percent-encoded, because they may
   hold the characters that end them (@ : /).  What the handlers use is the
   name and the password themselves, and what is written back is encoded
   again.  An encoded CR, LF or NUL is no better than a raw one: the name
   goes into FTP and SMTP commands.  */
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
   minutes, as in curl, and 0 means that again.  */
static void
test_connect_timeout_default (void)
{
  twist_easy *easy = twist_easy_init ();

  check (easy != NULL && easy->connect_timeout_ms == 300000,
         "a connect timeout by default");
  twist_easy_setopt (easy, TWISTOPT_CONNECTTIMEOUT_MS, 5000L);
  check (easy->connect_timeout_ms == 5000, "set");
  twist_easy_setopt (easy, TWISTOPT_CONNECTTIMEOUT_MS, 0L);
  check (easy->connect_timeout_ms == 300000, "0 is the default");
  twist_easy_cleanup (easy);
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
  check (twist_url_parse_int ("sftp://[fe80::1%253]/", &u) == TWIST_OK
         && strcmp (u->host, "fe80::1%3") == 0, "a zone that is a number");
  twist_url_free_int (u);
  check (twist_url_parse_int ("sftp://[fe80::1%eth0]/", &u) == TWIST_OK
         && strcmp (u->host, "fe80::1%eth0") == 0,
         "a zone with a bare percent sign, as curl takes it");
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
           == 0 && st == 56, "with curl's words and status");
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
  p = twist_proxy_new (TWIST_PROXY_SOCKS5, "127.0.0.1", 1080, NULL);
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
  p = twist_proxy_new (TWIST_PROXY_SOCKS5, "127.0.0.1", 1080, NULL);
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
  p = twist_proxy_new (TWIST_PROXY_SOCKS5, "127.0.0.1", 1080, NULL);
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
  p = twist_proxy_new (TWIST_PROXY_SOCKS5, "127.0.0.1", 1080, NULL);
  twist_proxy_set_target (p, "10.1.2.3", 22);
  free (px_next (p, &len));
  px_feed (p, none, 2, &used, &ready);
  out = px_next (p, &len);
  check (out != NULL && len == 10 && out[3] == 1 && out[4] == 10
         && out[5] == 1 && out[6] == 2 && out[7] == 3 && out[8] == 0
         && out[9] == 22, "an IPv4 address is one");
  free (out);
  twist_proxy_free (p);

  p = twist_proxy_new (TWIST_PROXY_SOCKS5, "127.0.0.1", 1080, NULL);
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
  p = twist_proxy_new (TWIST_PROXY_SOCKS5, "127.0.0.1", 1080, NULL);
  twist_proxy_set_target (p, "fe80::1%eth0", 22);
  free (px_next (p, &len));
  px_feed (p, none, 2, &used, &ready);
  out = px_next (p, &len);
  check (out != NULL && len == 22 && out[3] == 4 && out[4] == 0xfe
         && out[19] == 1, "an address with a zone, without the zone");
  free (out);
  twist_proxy_free (p);

  /* Username and password (RFC 1929).  */
  p = twist_proxy_new (TWIST_PROXY_SOCKS5, "127.0.0.1", 1080, NULL);
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

  p = twist_proxy_new (TWIST_PROXY_SOCKS5, "127.0.0.1", 1080, NULL);
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
  p = twist_proxy_new (TWIST_PROXY_SOCKS5, "127.0.0.1", 1080, NULL);
  twist_proxy_set_target (p, "h", 22);
  free (px_next (p, &len));
  check (px_feed (p, refuse, 2, &used, &ready) == TWIST_ERR_PROXY
         && strcmp (twist_proxy_error (p, &st),
                    "No authentication method was acceptable.") == 0
         && st == 97, "no method it will do");
  twist_proxy_free (p);

  p = twist_proxy_new (TWIST_PROXY_SOCKS5, "127.0.0.1", 1080, NULL);
  twist_proxy_set_target (p, "h", 22);
  free (px_next (p, &len));
  check (px_feed (p, pw, 2, &used, &ready) == TWIST_ERR_PROXY,
         "a method that was not offered");
  twist_proxy_free (p);

  /* The request refused.  */
  p = twist_proxy_new (TWIST_PROXY_SOCKS5, "127.0.0.1", 1080, NULL);
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

    p = twist_proxy_new (TWIST_PROXY_SOCKS5, "127.0.0.1", 1080, NULL);
    twist_proxy_set_target (p, "h", 22);
    free (px_next (p, &len));
    px_feed (p, none, 2, &used, &ready);
    free (px_next (p, &len));
    check (px_feed (p, v6, sizeof v6, &used, &ready) == TWIST_OK && ready
           && used == sizeof v6 - 1, "a bound IPv6 address");
    twist_proxy_free (p);
    p = twist_proxy_new (TWIST_PROXY_SOCKS5, "127.0.0.1", 1080, NULL);
    twist_proxy_set_target (p, "h", 22);
    free (px_next (p, &len));
    px_feed (p, none, 2, &used, &ready);
    free (px_next (p, &len));
    check (px_feed (p, nm, sizeof nm, &used, &ready) == TWIST_OK && ready
           && used == sizeof nm - 1, "a bound name");
    twist_proxy_free (p);
  }
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
  check (PARSE ("socks5h://s") == TWIST_OK && kind == TWIST_PROXY_SOCKS5
         && port == 1080, "socks5h, 1080");
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
  check (PARSE ("https://h") == TWIST_ERR_UNSUPPORTED,
         "an https proxy is not spoken to in the clear");
  check (PARSE ("socks4://h") == TWIST_ERR_UNSUPPORTED, "socks4");
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

    check (twist_pool_put_idle (pool, "old", c, 0) == TWIST_OK, "pool age put");
    twist_pool_expire (pool, 117999);
    check (twist_pool_take (pool, "old", &got) == TWIST_OK, "pool not expired");
    twist_connection_free (got);
    c = twist_connection_new (loop);
    check (twist_pool_put_idle (pool, "old", c, 0) == TWIST_OK, "pool age put 2");
    twist_pool_expire (pool, 118000);
    check (twist_pool_take (pool, "old", &got) == TWIST_ERR_AGAIN, "pool expired");
  }
  twist_pool_free (pool);
  twist_loop_free (loop);
}

static int
on_multi_socket (twist_easy *easy, int fd, int what, void *user, void *socketp)
{
  int *saw = user;

  (void) easy;
  (void) fd;
  (void) what;
  (void) socketp;
  if (saw != NULL)
    *saw = 1;
  return 0;
}

static void
test_multi_perform (void)
{
  struct twist_multi *multi = twist_multi_init ();
  int running = -1;
  int saw = 0;

  check (multi != NULL, "multi");
  check (twist_multi_perform (multi, &running) == TWIST_OK && running == 0,
         "multi perform");
  twist_multi_setopt (multi, TWISTMOPT_SOCKETDATA, &saw);
  twist_multi_setopt (multi, TWISTMOPT_SOCKETFUNCTION, on_multi_socket);
  check (saw == 1, "multi waker");
  twist_multi_cleanup (multi);
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

static twist_easy *
timeout_easy (int port)
{
  twist_easy *easy = twist_easy_init ();
  char url[64];

  snprintf (url, sizeof url, "mqtt://127.0.0.1:%d/x", port);
  twist_easy_setopt (easy, TWISTOPT_URL, url);
  twist_easy_setopt (easy, TWISTOPT_TIMEOUT_MS, 200L);
  return easy;
}

/* The state of a transfer owns its connection, and the connection is
   released against the loop.  So the state must be released when the easy
   handle leaves the loop, not later with the handle: by then the loop is
   gone and the release reads freed memory.  */
static void
test_release_transfer (void)
{
  int port = 0;
  int fd = listen_loopback (&port);
  int peer;
  twist_easy *easy;
  twist_multi *multi;
  struct timespec nap = { 0, 5000000 };
  int running = 1;
  int i;

  check (fd >= 0, "loopback listener");
  if (fd < 0)
    return;

  /* twist_easy_perform ends the transfer with the connection open.  */
  easy = timeout_easy (port);
  check (twist_easy_perform (easy) != TWIST_OK, "perform times out");
  peer = accept (fd, NULL, NULL);
  check (peer >= 0, "the connection was open");
  if (peer >= 0)
    close (peer);
  check (easy->xfer == NULL, "perform releases the transfer state");
  twist_easy_cleanup (easy);

  /* The same through a multi handle that is removed.  */
  multi = twist_multi_init ();
  easy = timeout_easy (port);
  check (twist_multi_add_handle (multi, easy) == TWIST_OK, "add handle");
  for (i = 0; i < 400 && running > 0; i++)
    {
      twist_multi_perform (multi, &running);
      nanosleep (&nap, NULL);
    }
  check (running == 0 && easy->done, "multi transfer ended");
  check (twist_multi_remove_handle (multi, easy) == TWIST_OK, "remove handle");
  check (easy->xfer == NULL, "remove releases the transfer state");
  twist_multi_cleanup (multi);
  twist_easy_cleanup (easy);

  /* Handles still in the multi when it is cleaned up.  */
  multi = twist_multi_init ();
  easy = timeout_easy (port);
  check (twist_multi_add_handle (multi, easy) == TWIST_OK, "add handle 2");
  for (i = 0; i < 400 && running > 0; i++)
    {
      twist_multi_perform (multi, &running);
      nanosleep (&nap, NULL);
    }
  twist_multi_cleanup (multi);
  check (easy->xfer == NULL, "multi cleanup releases the transfer state");
  twist_easy_cleanup (easy);
  close (fd);
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

/* A job on the multi's storage pool whose completion is posted to its loop.
   If the multi is cleaned up before the loop has run, the completion must
   still be delivered: it owns the job and whatever the job carries, and
   dropping it with the loop leaks both.  The pool's threads are joined
   first, so every job has run and posted by then.  */
static void
test_pool_completion_at_cleanup (void)
{
  struct twist_multi *multi = twist_multi_init ();
  int done = 0, i;

  check (multi != NULL, "multi");
  for (i = 0; i < 5; i++)
    check (twist_storage_submit (multi->storage, pool_work, NULL, pool_done,
                                 &done, multi->loop) == TWIST_OK, "submit");
  twist_multi_cleanup (multi);
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
  twist_pool_set_lock (pool, 1);
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

static void *
ka_serve (void *arg)
{
  struct ka *k = arg;
  static const char reply[] =
    "HTTP/1.1 200 OK\r\nContent-Length: 6\r\nContent-Type: text/plain\r\n\r\n"
    "hello\n";
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
              if (write (k->conns[i], reply, sizeof reply - 1) < 0)
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
  twist_easy *easy;
  char url[128], want[64];
  size_t total = 0;
  char *eff = NULL;

  if (ka_start_on (&k, 1) != 0)
    {
      fputs ("test-engine: no IPv6 loopback; skipping the IPv6 Host test\n",
             stderr);
      return;
    }
  easy = twist_easy_init ();
  snprintf (url, sizeof url, "http://[::1]:%d/x", k.port);
  twist_easy_setopt (easy, TWISTOPT_URL, url);
  twist_easy_setopt (easy, TWISTOPT_WRITEFUNCTION, ka_body);
  twist_easy_setopt (easy, TWISTOPT_WRITEDATA, &total);
  check (twist_easy_perform (easy) == TWIST_OK && total == 6,
         "a transfer from [::1]");
  __atomic_thread_fence (__ATOMIC_ACQUIRE);
  snprintf (want, sizeof want, "[::1]:%d", k.port);
  check (strcmp (k.host, want) == 0, "the Host header has the brackets");
  twist_easy_getinfo (easy, TWISTINFO_EFFECTIVE_URL, &eff);
  snprintf (want, sizeof want, "http://[::1]:%d/x", k.port);
  check (eff != NULL && strcmp (eff, want) == 0,
         "the effective URL has them too");
  twist_easy_cleanup (easy);
  ka_stop (&k);
}

/* A share keeps its connection pool for longer than any transfer, and each
   twist_easy_perform makes its own loop and frees it.  A connection parked
   by a transfer is bound to that loop; it cannot outlive it.  Left in the
   share's pool it is used by a later transfer, or freed by the share's
   cleanup, against memory that is gone.  So nothing may be left parked for a
   loop that is gone.  (valgrind shows the harm; this shows the cause.)  */
static void
test_share_pool_does_not_outlive_loops (void)
{
  struct ka k;
  twist_share *share = twist_share_init ();
  char url[64];
  int i;

  check (share != NULL && ka_start (&k) == 0, "keep-alive server");
  snprintf (url, sizeof url, "http://127.0.0.1:%d/", k.port);
  check (twist_share_setopt (share, TWIST_LOCK_DATA_CONNECT) == TWIST_OK,
         "share lock");
  for (i = 0; i < 3; i++)
    {
      twist_easy *easy = twist_easy_init ();
      size_t total = 0;

      twist_easy_setopt (easy, TWISTOPT_URL, url);
      twist_easy_setopt (easy, TWISTOPT_SHARE, share);
      twist_easy_setopt (easy, TWISTOPT_WRITEFUNCTION, ka_body);
      twist_easy_setopt (easy, TWISTOPT_WRITEDATA, &total);
      check (twist_easy_perform (easy) == TWIST_OK && total == 6,
             "a transfer on a share");
      twist_easy_cleanup (easy);
      check (twist_pool_count (share->pool) == 0,
             "nothing stays parked for a loop that has been freed");
    }
  twist_share_cleanup (share);
  ka_stop (&k);
}

int
main (void)
{
  test_url ();
  test_url_userinfo ();
  test_url_ipv6 ();
  test_connect_timeout_default ();
  test_http_ipv6_host ();
  test_scheme ();
  test_proxy_http ();
  test_proxy_socks ();
  test_proxy_parse ();
  test_conn_pool ();
  test_multi_perform ();
  test_release_transfer ();
  test_home_dir ();
  test_pool_completion_at_cleanup ();
  test_pool_eviction_stays_on_the_loop ();
  test_share_pool_does_not_outlive_loops ();
  return tests_finish ();
}
