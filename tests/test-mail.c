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
#include "feed.h"
#include "body.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct mail_cap
{
  uint8_t b[512];
  size_t n;
};

static int
mail_sink (void *user, const uint8_t *data, size_t len)
{
  struct mail_cap *c = user;

  if (c->n + len > sizeof c->b)
    return 1;
  memcpy (c->b + c->n, data, len);
  c->n += len;
  return 0;
}

static size_t
smtp_recv (void *obj, const uint8_t *data, size_t len)
{
  return twist_smtp_receive (obj, data, len);
}

static size_t
pop3_recv (void *obj, const uint8_t *data, size_t len)
{
  return twist_pop3_receive (obj, data, len);
}

static size_t
imap_recv (void *obj, const uint8_t *data, size_t len)
{
  return twist_imap_receive (obj, data, len);
}

static void
test_mail (void)
{
  static const char plain[] = "Hi\r\n.x\r\n";
  static const char stuffed[] = "Hi\r\n..x\r\n.\r\n";
  struct mail_cap cap;
  struct twist_dotout out;
  struct twist_dotin in;
  size_t i;
  int done = 0;
  int err = 0;
  struct twist_mime *mime;
  static const char expect_mime[] =
    "--twist-mime-1\r\n"
    "Content-Type: text/plain\r\n"
    "\r\n"
    "ab\r\n"
    "--twist-mime-1\r\n"
    "Content-Transfer-Encoding: base64\r\n"
    "\r\n"
    "aGk=\r\n"
    "--twist-mime-1--\r\n";

  memset (&cap, 0, sizeof cap);
  twist_dotout_init (&out);
  for (i = 0; i < sizeof plain - 1; i++)
    check (twist_dotout_write (&out, (const uint8_t *) plain + i, 1,
                               mail_sink, &cap) == TWIST_OK, "dotout");
  check (twist_dotout_finish (&out, mail_sink, &cap) == TWIST_OK, "dotend");
  check (cap.n == sizeof stuffed - 1
         && memcmp (cap.b, stuffed, cap.n) == 0, "stuffed");
  memset (&cap, 0, sizeof cap);
  twist_dotin_init (&in);
  for (i = 0; i < sizeof stuffed - 1; i++)
    {
      size_t used = twist_dotin_pull (&in, (const uint8_t *) stuffed + i, 1,
                                      mail_sink, &cap, &done, &err);

      check (used == 1 && err == TWIST_OK, "dotin byte");
    }
  check (done && cap.n == sizeof plain - 1
         && memcmp (cap.b, plain, cap.n) == 0, "unstuffed");

  memset (&cap, 0, sizeof cap);
  mime = twist_mime_new (mail_sink, &cap);
  check (mime != NULL && twist_mime_begin (mime, "mixed") == TWIST_OK, "mime");
  check (twist_mime_part (mime) == TWIST_OK, "part1");
  check (twist_mime_header (mime, "Content-Type", "text/plain") == TWIST_OK,
         "hdr");
  check (twist_mime_body (mime, (const uint8_t *) "a", 1) == TWIST_OK, "a");
  check (twist_mime_body (mime, (const uint8_t *) "b", 1) == TWIST_OK, "b");
  check (twist_mime_part (mime) == TWIST_OK, "part2");
  check (twist_mime_header (mime, "Content-Transfer-Encoding", "base64")
         == TWIST_OK, "cte");
  check (twist_mime_body_b64 (mime, (const uint8_t *) "hi", 2) == TWIST_OK,
         "b64");
  check (twist_mime_finish (mime) == TWIST_OK, "mime end");
  check (cap.n == sizeof expect_mime - 1
         && memcmp (cap.b, expect_mime, cap.n) == 0, "mime bytes");
  twist_mime_free (mime);

  {
    uint8_t raw[13] = { 0, 'a', 'l', 'i', 'c', 'e', 0,
                        's', 'e', 'c', 'r', 'e', 't' };
    char *b64 = NULL;
    char authcmd[128];
    twist_easy *easy = twist_easy_init ();
    struct twist_slist *rcpt = twist_slist_append (NULL, "c@d");
    struct twist_smtp *smtp;
    size_t split;

    check (twist_b64_encode (raw, sizeof raw, &b64) == TWIST_OK, "plain b64");
    snprintf (authcmd, sizeof authcmd, "AUTH PLAIN %s\r\n", b64);
    free (b64);
    for (split = 1; split <= 12; split++)
      {
        check (twist_url_parse_int ("smtp://alice:secret@127.0.0.1",
                                    &easy->url) == TWIST_OK, "smtp url");
        easy->mail_from = twist_strdup ("a@b");
        easy->mail_rcpt = rcpt;
        easy->postfields = (char[]) { 'H', 'i', '\r', '\n', '.', 'x', '\r', '\n', 0 };
        smtp = twist_smtp_new (easy, 0);
        feed_n (smtp_recv, smtp, "220 ready\r\n", split);
        check (strcmp (twist_smtp_command (smtp), "EHLO twist\r\n") == 0,
               "ehlo");
        feed_n (smtp_recv, smtp, "250-AUTH PLAIN\r\n250 hello\r\n", split);
        check (strcmp (twist_smtp_command (smtp), authcmd) == 0, "auth plain");
        feed_n (smtp_recv, smtp, "235 ok\r\n", split);
        check (strcmp (twist_smtp_command (smtp), "MAIL FROM:<a@b>\r\n") == 0,
               "mail from");
        feed_n (smtp_recv, smtp, "250 sender\r\n", split);
        check (strcmp (twist_smtp_command (smtp), "RCPT TO:<c@d>\r\n") == 0,
               "rcpt");
        feed_n (smtp_recv, smtp, "250 rcpt\r\n", split);
        check (strcmp (twist_smtp_command (smtp), "DATA\r\n") == 0, "data");
        feed_n (smtp_recv, smtp, "354 go\r\n", split);
        check (strcmp (twist_smtp_command (smtp), stuffed) == 0, "smtp body");
        feed_n (smtp_recv, smtp, "250 queued\r\n", split);
        check (easy->done && easy->result == TWIST_OK, "smtp done");
        check (strcmp (twist_smtp_command (smtp), "QUIT\r\n") == 0, "quit");
        twist_easy_cleanup (easy);
        easy = twist_easy_init ();
      }
    twist_slist_free_all (rcpt);
    twist_easy_cleanup (easy);
  }
  {
    twist_easy *easy = twist_easy_init ();
    struct twist_pop3 *pop;

    mail_body_len = 0;
    check (twist_url_parse_int ("pop3://alice:secret@127.0.0.1/1", &easy->url)
           == TWIST_OK, "pop url");
    easy->write_cb = mail_write;
    pop = twist_pop3_new (easy, 0);
    feed_n (pop3_recv, pop, "+OK pop\r\n", 1);
    check (strcmp (twist_pop3_command (pop), "CAPA\r\n") == 0, "capa");
    feed_n (pop3_recv, pop, "+OK\r\nUSER\r\n.\r\n", 1);
    check (strcmp (twist_pop3_command (pop), "USER alice\r\n") == 0, "user");
    feed_n (pop3_recv, pop, "+OK\r\n", 1);
    check (strcmp (twist_pop3_command (pop), "PASS secret\r\n") == 0, "pass");
    feed_n (pop3_recv, pop, "+OK\r\n+OK 5\r\nhello\r\n.\r\n+OK bye\r\n", 1);
    check (easy->done && easy->result == TWIST_OK, "pop done");
    check (mail_body_len == 7 && memcmp (mail_body, "hello\r\n", 7) == 0,
           "pop body");
    twist_easy_cleanup (easy);
  }
  {
    uint8_t raw[13] = { 0, 'a', 'l', 'i', 'c', 'e', 0,
                        's', 'e', 'c', 'r', 'e', 't' };
    char *b64 = NULL;
    char authcmd[160];
    twist_easy *easy = twist_easy_init ();
    struct twist_imap *imap;

    check (twist_b64_encode (raw, sizeof raw, &b64) == TWIST_OK, "imap b64");
    snprintf (authcmd, sizeof authcmd, "A2 AUTHENTICATE PLAIN %s\r\n", b64);
    free (b64);
    mail_body_len = 0;
    check (twist_url_parse_int ("imap://alice:secret@127.0.0.1/INBOX;UID=1",
                                &easy->url) == TWIST_OK, "imap url");
    easy->write_cb = mail_write;
    imap = twist_imap_new (easy, 0);
    feed_n (imap_recv, imap, "* OK ready\r\n", 1);
    check (strcmp (twist_imap_command (imap), "A1 CAPABILITY\r\n") == 0,
           "capability");
    feed_n (imap_recv, imap, "* CAPABILITY IMAP4rev1 AUTH=PLAIN\r\nA1 OK\r\n",
            1);
    check (strcmp (twist_imap_command (imap), authcmd) == 0, "authenticate");
    feed_n (imap_recv, imap, "A2 OK\r\n", 1);
    check (strcmp (twist_imap_command (imap), "A3 SELECT INBOX\r\n") == 0,
           "select");
    feed_n (imap_recv, imap, "* 1 EXISTS\r\nA3 OK [READ-WRITE]\r\n", 1);
    check (strcmp (twist_imap_command (imap), "A4 UID FETCH 1 BODY[]\r\n") == 0,
           "fetch");
    feed_n (imap_recv, imap, "* 1 FETCH (BODY[] {5}\r\nhello)\r\nA4 OK\r\n", 1);
    check (easy->done && easy->result == TWIST_OK, "imap done");
    check (mail_body_len == 5 && memcmp (mail_body, "hello", 5) == 0,
           "imap body");
    twist_easy_cleanup (easy);
  }
}

int
main (void)
{
  test_mail ();
  return tests_finish ();
}
