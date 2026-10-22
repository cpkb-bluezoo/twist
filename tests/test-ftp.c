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

static int ftp_seen_n;
static int ftp_seen_code[8];
static int ftp_seen_final[8];
static char ftp_seen_text[8][32];
static char ftp_body[16];
static size_t ftp_body_len;

static void
ftp_on_line (void *user, int code, int final, const char *text, size_t len)
{
  (void) user;
  if (ftp_seen_n >= 8)
    return;
  ftp_seen_code[ftp_seen_n] = code;
  ftp_seen_final[ftp_seen_n] = final;
  if (len >= sizeof ftp_seen_text[0])
    len = sizeof ftp_seen_text[0] - 1;
  memcpy (ftp_seen_text[ftp_seen_n], text, len);
  ftp_seen_text[ftp_seen_n][len] = 0;
  ftp_seen_n++;
}

static void
feed_parser (struct twist_ftp_parser *p, const char *s, size_t split)
{
  const uint8_t *data = (const uint8_t *) s;
  size_t n = strlen (s);
  uint8_t window[8192];
  size_t held = 0;
  size_t off = 0;

  while (off < n)
    {
      size_t take = split;
      size_t got;
      size_t used;

      if (take > n - off)
        take = n - off;
      check (held + take <= sizeof window, "ftp window");
      memcpy (window + held, data + off, take);
      off += take;
      got = held + take;
      used = twist_ftp_parser_receive (p, window, got);
      if (used > got)
        used = got;
      held = got - used;
      if (held > 0)
        memmove (window, window + used, held);
    }
}

static void
test_ftp_parser (void)
{
  static const char banner[] = "220-hello\r\nwelcome\r\n220 ready\r\n";
  struct twist_ftp_events ev;
  size_t n = sizeof banner - 1;
  size_t split;
  uint8_t partial[16];
  size_t used;

  memset (&ev, 0, sizeof ev);
  ev.reply = ftp_on_line;
  for (split = 1; split <= n; split++)
    {
      struct twist_ftp_parser *p = twist_ftp_parser_new (&ev);

      ftp_seen_n = 0;
      feed_parser (p, banner, split);
      check (ftp_seen_n == 3, "ftp lines");
      check (ftp_seen_code[0] == 220 && ftp_seen_final[0] == 0, "ftp cont");
      check (strcmp (ftp_seen_text[0], "hello") == 0, "ftp hello");
      check (ftp_seen_final[1] == 0 && strcmp (ftp_seen_text[1], "welcome") == 0,
             "ftp mid");
      check (ftp_seen_code[2] == 220 && ftp_seen_final[2] == 1, "ftp final");
      check (strcmp (ftp_seen_text[2], "ready") == 0, "ftp ready");
      twist_ftp_parser_free (p);
    }
  {
    struct twist_ftp_parser *p = twist_ftp_parser_new (&ev);

    ftp_seen_n = 0;
    memcpy (partial, "220 hel", 7);
    used = twist_ftp_parser_receive (p, partial, 7);
    check (used == 0 && ftp_seen_n == 0, "ftp underflow");
    memcpy (partial + 7, "lo\r\n", 4);
    used = twist_ftp_parser_receive (p, partial, 11);
    check (used == 11 && ftp_seen_n == 1 && ftp_seen_final[0] == 1, "ftp resume");
    check (strcmp (ftp_seen_text[0], "hello") == 0, "ftp resumed text");
    twist_ftp_parser_free (p);
  }
  {
    char host[32];
    int port = 0;

    check (twist_ftp_pasv ("227 Entering Passive Mode (192,0,2,10,7,138).",
                           48, host, sizeof host, &port) == TWIST_OK, "pasv");
    check (strcmp (host, "192.0.2.10") == 0 && port == 1930, "pasv addr");
    check (twist_ftp_epsv ("229 Entering Extended Passive Mode (|||40000|)",
                           46, &port) == TWIST_OK && port == 40000, "epsv");
    {
      struct twist_dns_addr peer;
      struct twist_dns_addr out;

      memset (&peer, 0, sizeof peer);
      peer.family = 4;
      peer.addr[0] = 192;
      peer.addr[1] = 0;
      peer.addr[2] = 2;
      peer.addr[3] = 1;
      snprintf (peer.text, sizeof peer.text, "192.0.2.1");
      check (twist_ftp_data_addr (&peer, port, &out) == TWIST_OK, "data addr");
      check (memcmp (out.addr, peer.addr, 4) == 0
             && strcmp (out.text, "192.0.2.1") == 0, "data peer");
      check (twist_ftp_data_addr (&peer, 0, &out) == TWIST_ERR_INVAL,
             "data port");
    }
  }
}

static size_t
ftp_write (char *ptr, size_t size, size_t nmemb, void *user)
{
  size_t n = size * nmemb;

  (void) user;
  if (ftp_body_len + n < sizeof ftp_body)
    {
      memcpy (ftp_body + ftp_body_len, ptr, n);
      ftp_body_len += n;
    }
  return n;
}

static void
feed_session (struct twist_ftp *f, const char *s, size_t split)
{
  const uint8_t *data = (const uint8_t *) s;
  size_t n = strlen (s);
  uint8_t window[8192];
  size_t held = 0;
  size_t off = 0;

  while (off < n)
    {
      size_t take = split;
      size_t got;
      size_t used;

      if (take > n - off)
        take = n - off;
      check (held + take <= sizeof window, "session window");
      memcpy (window + held, data + off, take);
      off += take;
      got = held + take;
      used = twist_ftp_receive (f, window, got);
      if (used > got)
        used = got;
      held = got - used;
      if (held > 0)
        memmove (window, window + used, held);
    }
}

static void
test_ftp_session (void)
{
  static const char talk[] =
    "220-vsFTPd\r\n220 ready\r\n"
    "331 Password required.\r\n"
    "230 Logged in.\r\n"
    "200 Type set.\r\n"
    "229 Entering Extended Passive Mode (|||40000|)\r\n"
    "150 Opening BINARY mode data connection for file.txt (5 bytes).\r\n";
  size_t n = sizeof talk - 1;
  size_t split;

  for (split = 1; split <= n; split++)
    {
      twist_easy *easy = twist_easy_init ();
      struct twist_ftp *f;
      size_t i;

      ftp_body_len = 0;
      check (easy != NULL, "easy");
      check (twist_url_parse_int ("ftp://127.0.0.1/pub/file.txt", &easy->url)
             == TWIST_OK, "ftp url");
      easy->write_cb = ftp_write;
      f = twist_ftp_new (easy, 0);
      check (f != NULL, "ftp");
      feed_session (f, talk, split);
      check (strcmp (twist_ftp_command (f), "RETR pub/file.txt\r\n") == 0,
             "retr");
      check (twist_ftp_data_port (f) == 40000, "data port");
      for (i = 0; i < 5; i++)
        twist_ftp_data (f, (const uint8_t *) "hello" + i, 1);
      check (!easy->done, "waiting for 226");
      feed_session (f, "226 Transfer complete.\r\n", split > 24 ? 24 : split);
      check (!easy->done, "waiting for data eof");
      twist_ftp_data_eof (f);
      check (easy->done && easy->result == TWIST_OK, "ftp done");
      check (easy->http_code == 226, "ftp code");
      check (easy->size_download == 5 && ftp_body_len == 5, "ftp body");
      /* The progress: the size from the reply, and the bytes.  */
      check (easy->progress.dl_known && easy->progress.size_dl == 5
             && easy->progress.downloaded == 5, "ftp progress");
      check (memcmp (ftp_body, "hello", 5) == 0, "ftp bytes");
      twist_easy_cleanup (easy);
    }
  {
    twist_easy *easy = twist_easy_init ();
    struct twist_ftp *f;

    check (twist_url_parse_int ("ftp://alice:secret@127.0.0.1/pub/", &easy->url)
           == TWIST_OK, "auth url");
    f = twist_ftp_new (easy, 0);
    {
      struct twist_dns_addr peer;

      memset (&peer, 0, sizeof peer);
      peer.family = 4;
      peer.addr[0] = 127;
      peer.addr[3] = 1;
      snprintf (peer.text, sizeof peer.text, "127.0.0.1");
      twist_ftp_set_peer (f, &peer);
    }
    feed_session (f, "220 ready\r\n", 1);
    check (strcmp (twist_ftp_command (f), "USER alice\r\n") == 0, "user");
    feed_session (f, "331 need pass\r\n", 1);
    check (strcmp (twist_ftp_command (f), "PASS secret\r\n") == 0, "pass");
    feed_session (f, "230 ok\r\n200 Type set.\r\n500 no epsv\r\n", 1);
    check (strcmp (twist_ftp_command (f), "PASV\r\n") == 0, "pasv fallback");
    feed_session (f, "227 Entering Passive Mode (192,0,2,10,7,138).\r\n", 1);
    check (strcmp (twist_ftp_command (f), "LIST pub\r\n") == 0, "list");
    check (strcmp (twist_ftp_data_host (f), "127.0.0.1") == 0, "pasv host");
    check (twist_ftp_data_port (f) == 1930, "pasv port");
    /* A listing has no size, even when the server puts a number in its text.  */
    feed_session (f, "150 Here comes the directory listing (99 bytes).\r\n", 1);
    check (!easy->progress.dl_known, "a listing has no size");
    twist_easy_cleanup (easy);
  }
}

int
main (void)
{
  test_ftp_parser ();
  test_ftp_session ();
  return tests_finish ();
}
