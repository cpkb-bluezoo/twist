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
test_imap_mailbox (void)
{
  char box[64];

  check (twist_imap_mailbox ("INBOX", box, sizeof box) == TWIST_OK
         && strcmp (box, "INBOX") == 0, "imap atom");
  check (twist_imap_mailbox ("INBOX{10}", box, sizeof box) == TWIST_OK
         && strcmp (box, "\"INBOX{10}\"") == 0, "imap literal");
  check (twist_imap_mailbox ("a\"b", box, sizeof box) == TWIST_ERR_URL,
         "imap quote");
  check (twist_imap_mailbox ("a\rb", box, sizeof box) == TWIST_ERR_URL,
         "imap cr");
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
  char expect_mime[256];

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
  snprintf (expect_mime, sizeof expect_mime,
            "--%s\r\nContent-Type: text/plain\r\n\r\nab\r\n"
            "--%s\r\nContent-Transfer-Encoding: base64\r\n\r\naGk=\r\n"
            "--%s--\r\n",
            twist_mime_boundary (mime), twist_mime_boundary (mime),
            twist_mime_boundary (mime));
  check (cap.n == strlen (expect_mime)
         && memcmp (cap.b, expect_mime, cap.n) == 0, "mime bytes");
  twist_mime_free (mime);

  /* The boundary is chosen for each message and cannot be guessed.  It was
     "twist-mime-1" every time, so a part that held "--twist-mime-1" and a
     line break ended its part and began another, with headers of its own.  */
  {
    struct twist_mime *a = twist_mime_new (mail_sink, &cap);
    struct twist_mime *b = twist_mime_new (mail_sink, &cap);
    const char *ba;
    const char *bb;
    size_t k;
    int hex = 1;

    check (twist_mime_boundary (a) == NULL, "no boundary before begin");
    check (twist_mime_begin (a, "mixed") == TWIST_OK
           && twist_mime_begin (b, "mixed") == TWIST_OK, "two messages");
    ba = twist_mime_boundary (a);
    bb = twist_mime_boundary (b);
    check (ba != NULL && bb != NULL && strcmp (ba, bb) != 0,
           "each message has its own boundary");
    check (ba != NULL && strlen (ba) >= 24 && strlen (ba) <= 70,
           "of a length that is hard to guess, and RFC 2046 allows");
    check (ba != NULL && strncmp (ba, "twist-", 6) == 0, "named for twist");
    for (k = 6; ba != NULL && ba[k] != 0; k++)
      if (!((ba[k] >= '0' && ba[k] <= '9') || (ba[k] >= 'a' && ba[k] <= 'f')))
        hex = 0;
    check (hex, "and made of characters that need no quoting");
    check (ba != NULL && strcmp (ba, "twist-mime-1") != 0,
           "and not the one that used to be");
    twist_mime_free (a);
    twist_mime_free (b);
  }

  {
    uint8_t raw[13] = { 0, 'a', 'l', 'i', 'c', 'e', 0,
                        's', 'e', 'c', 'r', 'e', 't' };
    char *b64 = NULL;
    char authcmd[128];
    twist_transfer *transfer = twist_transfer_new ();
    struct twist_slist *rcpt = twist_slist_append (NULL, "c@d");
    struct twist_smtp *smtp;
    size_t split;

    check (twist_b64_encode (raw, sizeof raw, &b64) == TWIST_OK, "plain b64");
    snprintf (authcmd, sizeof authcmd, "AUTH PLAIN %s\r\n", b64);
    free (b64);
    for (split = 1; split <= 12; split++)
      {
        check (twist_url_parse_int ("smtp://alice:secret@127.0.0.1",
                                    &transfer->url) == TWIST_OK, "smtp url");
        transfer->mail_from = twist_strdup ("a@b");
        transfer->mail_rcpt = rcpt;
        transfer->postfields = (char[]) { 'H', 'i', '\r', '\n', '.', 'x', '\r', '\n', 0 };
        smtp = twist_smtp_new (transfer, 0);
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
        check (transfer->done && transfer->result == TWIST_OK, "smtp done");
        check (transfer->progress.ul_known && transfer->progress.size_ul == 8
               && transfer->progress.uploaded == 8, "smtp progress");
        check (strcmp (twist_smtp_command (smtp), "QUIT\r\n") == 0, "quit");
        twist_transfer_free (transfer);
        transfer = twist_transfer_new ();
      }
    twist_slist_free_all (rcpt);
    twist_transfer_free (transfer);
  }
  {
    twist_transfer *transfer = twist_transfer_new ();
    struct twist_pop3 *pop;

    mail_body_len = 0;
    check (twist_url_parse_int ("pop3://alice:secret@127.0.0.1/1",
                                &transfer->url)
           == TWIST_OK, "pop url");
    transfer->write_cb = mail_write;
    pop = twist_pop3_new (transfer, 0);
    feed_n (pop3_recv, pop, "+OK pop\r\n", 1);
    check (strcmp (twist_pop3_command (pop), "CAPA\r\n") == 0, "capa");
    feed_n (pop3_recv, pop, "+OK\r\nUSER\r\n.\r\n", 1);
    check (strcmp (twist_pop3_command (pop), "USER alice\r\n") == 0, "user");
    feed_n (pop3_recv, pop, "+OK\r\n", 1);
    check (strcmp (twist_pop3_command (pop), "PASS secret\r\n") == 0, "pass");
    feed_n (pop3_recv, pop, "+OK\r\n+OK 5\r\nhello\r\n.\r\n+OK bye\r\n", 1);
    check (transfer->done && transfer->result == TWIST_OK, "pop done");
    check (mail_body_len == 7 && memcmp (mail_body, "hello\r\n", 7) == 0,
           "pop body");
    check (transfer->progress.downloaded == 7, "pop progress");
    twist_transfer_free (transfer);
  }
  {
    uint8_t raw[13] = { 0, 'a', 'l', 'i', 'c', 'e', 0,
                        's', 'e', 'c', 'r', 'e', 't' };
    char *b64 = NULL;
    char authcmd[160];
    twist_transfer *transfer = twist_transfer_new ();
    struct twist_imap *imap;

    check (twist_b64_encode (raw, sizeof raw, &b64) == TWIST_OK, "imap b64");
    snprintf (authcmd, sizeof authcmd, "A2 AUTHENTICATE PLAIN %s\r\n", b64);
    free (b64);
    mail_body_len = 0;
    check (twist_url_parse_int ("imap://alice:secret@127.0.0.1/INBOX;UID=1",
                                &transfer->url) == TWIST_OK, "imap url");
    transfer->write_cb = mail_write;
    imap = twist_imap_new (transfer, 0);
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
    check (transfer->done && transfer->result == TWIST_OK, "imap done");
    check (mail_body_len == 5 && memcmp (mail_body, "hello", 5) == 0,
           "imap body");
    /* The size is the literal's.  */
    check (transfer->progress.dl_known && transfer->progress.size_dl == 5
           && transfer->progress.downloaded == 5, "imap progress");
    twist_transfer_free (transfer);
  }
}

/* Explicit TLS (--ssl, --ssl-reqd): STARTTLS for smtp and imap, STLS for pop3.
   The upgrade is asked for only when the user asked for it and the server has
   said that it offers it, and the user name and password are not sent until
   the connection is encrypted.  Once it is, what the server said before is
   forgotten and asked again.  A server that cannot, or will not, is an error
   if TLS is required and is gone on without if it was only wanted.  Bytes that
   come in the clear behind the server's yes are not read as part of the
   encrypted session: they are an attack, and end the transfer.  */
static int
starts_with (const char *s, const char *prefix)
{
  return strncmp (s, prefix, strlen (prefix)) == 0;
}

static twist_transfer *
tls_transfer (const char *url, int use_ssl)
{
  twist_transfer *transfer = twist_transfer_new ();

  check (twist_url_parse_int (url, &transfer->url) == TWIST_OK,
         "starttls url");
  check (twist_transfer_setopt (transfer, TWISTOPT_USE_SSL, (long) use_ssl) == TWIST_OK,
         "use ssl");
  transfer->write_cb = mail_write;
  return transfer;
}

static void
test_smtp_starttls (void)
{
  static const char *const url = "smtp://alice:secret@127.0.0.1/";
  size_t splits[2] = { 1, 200 };
  size_t k;

  for (k = 0; k < 2; k++)
    {
      size_t split = splits[k];
      twist_transfer *transfer;
      struct twist_smtp *s;

      /* Wanted and required, offered: upgraded before anything is sent.  */
      transfer = tls_transfer (url, TWIST_USE_SSL_ALL);
      s = twist_smtp_new (transfer, 0);
      feed_n (smtp_recv, s, "220 ready\r\n", split);
      check (strcmp (twist_smtp_command (s), "EHLO twist\r\n") == 0, "ehlo");
      feed_n (smtp_recv, s, "250-mx\r\n250-STARTTLS\r\n250 AUTH PLAIN\r\n", split);
      check (strcmp (twist_smtp_command (s), "STARTTLS\r\n") == 0,
             "STARTTLS, not AUTH, when offered");
      feed_n (smtp_recv, s, "220 Ready to start TLS\r\n", split);
      check (strcmp (twist_smtp_command (s), "STARTTLS\r\n") == 0 && !transfer->done,
             "nothing is sent until the handshake is done");
      twist_smtp_tls_done (s);
      check (strcmp (twist_smtp_command (s), "EHLO twist\r\n") == 0,
             "EHLO again, encrypted");
      /* STARTTLS in the new answer does not start another upgrade.  */
      feed_n (smtp_recv, s, "250-mx\r\n250-STARTTLS\r\n250 AUTH PLAIN\r\n", split);
      check (starts_with (twist_smtp_command (s), "AUTH PLAIN ") && !transfer->done,
             "then the login");
      twist_transfer_free (transfer);

      /* Required, and not offered.  */
      transfer = tls_transfer (url, TWIST_USE_SSL_ALL);
      s = twist_smtp_new (transfer, 0);
      feed_n (smtp_recv, s, "220 ready\r\n250 AUTH PLAIN\r\n", split);
      check (transfer->done && transfer->result == TWIST_ERR_USE_SSL
             && !starts_with (twist_smtp_command (s), "AUTH"),
             "required and not offered is an error, and nothing is sent");
      twist_transfer_free (transfer);

      /* Wanted, and not offered: on in the clear.  */
      transfer = tls_transfer (url, TWIST_USE_SSL_TRY);
      s = twist_smtp_new (transfer, 0);
      feed_n (smtp_recv, s, "220 ready\r\n250 AUTH PLAIN\r\n", split);
      check (starts_with (twist_smtp_command (s), "AUTH PLAIN ") && !transfer->done,
             "wanted and not offered goes on");
      twist_transfer_free (transfer);

      /* Refused after it was asked.  */
      transfer = tls_transfer (url, TWIST_USE_SSL_ALL);
      s = twist_smtp_new (transfer, 0);
      feed_n (smtp_recv, s, "220 ready\r\n250-STARTTLS\r\n250 AUTH PLAIN\r\n",
              split);
      feed_n (smtp_recv, s, "454 TLS not available\r\n", split);
      check (transfer->done && transfer->result == TWIST_ERR_USE_SSL,
             "required and refused is an error");
      twist_transfer_free (transfer);
      transfer = tls_transfer (url, TWIST_USE_SSL_TRY);
      s = twist_smtp_new (transfer, 0);
      feed_n (smtp_recv, s, "220 ready\r\n250-STARTTLS\r\n250 AUTH PLAIN\r\n",
              split);
      feed_n (smtp_recv, s, "454 TLS not available\r\n", split);
      check (starts_with (twist_smtp_command (s), "AUTH PLAIN ") && !transfer->done,
             "wanted and refused goes on");
      twist_transfer_free (transfer);

      /* Not asked for: never upgraded, even if it is offered.  */
      transfer = tls_transfer (url, TWIST_USE_SSL_NONE);
      s = twist_smtp_new (transfer, 0);
      feed_n (smtp_recv, s, "220 ready\r\n250-STARTTLS\r\n250 AUTH PLAIN\r\n",
              split);
      check (starts_with (twist_smtp_command (s), "AUTH PLAIN "),
             "STARTTLS is not sent unless it is asked for");
      twist_transfer_free (transfer);
    }

  /* Bytes behind the 220 that are not encrypted.  */
  {
    twist_transfer *transfer = tls_transfer (url, TWIST_USE_SSL_ALL);
    struct twist_smtp *s = twist_smtp_new (transfer, 0);

    feed_n (smtp_recv, s, "220 ready\r\n250-STARTTLS\r\n250 AUTH PLAIN\r\n", 200);
    feed_n (smtp_recv, s, "220 go\r\n250 AUTH PLAIN\r\n", 200);
    check (transfer->done && transfer->result == TWIST_ERR_PROTOCOL,
           "bytes in the clear behind the reply to STARTTLS end the transfer");
    check (strcmp (twist_smtp_command (s), "STARTTLS\r\n") == 0,
           "and nothing is sent for them");
    twist_transfer_free (transfer);
  }
}

static void
test_imap_starttls (void)
{
  static const char *const url = "imap://alice:secret@127.0.0.1/INBOX;UID=1";
  size_t splits[2] = { 1, 200 };
  size_t k;

  for (k = 0; k < 2; k++)
    {
      size_t split = splits[k];
      twist_transfer *transfer;
      struct twist_imap *m;

      transfer = tls_transfer (url, TWIST_USE_SSL_ALL);
      m = twist_imap_new (transfer, 0);
      feed_n (imap_recv, m, "* OK ready\r\n", split);
      check (strcmp (twist_imap_command (m), "A1 CAPABILITY\r\n") == 0, "cap");
      feed_n (imap_recv, m,
              "* CAPABILITY IMAP4rev1 STARTTLS LOGINDISABLED\r\nA1 OK\r\n",
              split);
      check (strcmp (twist_imap_command (m), "A2 STARTTLS\r\n") == 0,
             "STARTTLS, not AUTHENTICATE, when offered");
      feed_n (imap_recv, m, "A2 OK Begin TLS negotiation now\r\n", split);
      check (strcmp (twist_imap_command (m), "A2 STARTTLS\r\n") == 0
             && !transfer->done,
             "nothing is sent until the handshake is done");
      twist_imap_tls_done (m);
      check (strcmp (twist_imap_command (m), "A3 CAPABILITY\r\n") == 0,
             "CAPABILITY again, encrypted");
      feed_n (imap_recv, m, "* CAPABILITY IMAP4rev1 AUTH=PLAIN\r\nA3 OK\r\n",
              split);
      check (starts_with (twist_imap_command (m), "A4 AUTHENTICATE PLAIN ")
             && !transfer->done, "then the login");
      twist_transfer_free (transfer);

      transfer = tls_transfer (url, TWIST_USE_SSL_ALL);
      m = twist_imap_new (transfer, 0);
      feed_n (imap_recv, m, "* OK ready\r\n", split);
      feed_n (imap_recv, m, "* CAPABILITY IMAP4rev1 AUTH=PLAIN\r\nA1 OK\r\n",
              split);
      check (transfer->done && transfer->result == TWIST_ERR_USE_SSL
             && !starts_with (twist_imap_command (m), "A2 AUTH"),
             "required and not offered is an error, and nothing is sent");
      twist_transfer_free (transfer);

      transfer = tls_transfer (url, TWIST_USE_SSL_TRY);
      m = twist_imap_new (transfer, 0);
      feed_n (imap_recv, m, "* OK ready\r\n", split);
      feed_n (imap_recv, m, "* CAPABILITY IMAP4rev1 AUTH=PLAIN\r\nA1 OK\r\n",
              split);
      check (starts_with (twist_imap_command (m), "A2 AUTHENTICATE PLAIN ")
             && !transfer->done, "wanted and not offered goes on");
      twist_transfer_free (transfer);

      transfer = tls_transfer (url, TWIST_USE_SSL_ALL);
      m = twist_imap_new (transfer, 0);
      feed_n (imap_recv, m, "* OK ready\r\n", split);
      feed_n (imap_recv, m, "* CAPABILITY IMAP4rev1 STARTTLS AUTH=PLAIN\r\nA1 OK\r\n",
              split);
      feed_n (imap_recv, m, "A2 NO TLS not available\r\n", split);
      check (transfer->done && transfer->result == TWIST_ERR_USE_SSL,
             "required and refused is an error");
      twist_transfer_free (transfer);
      transfer = tls_transfer (url, TWIST_USE_SSL_TRY);
      m = twist_imap_new (transfer, 0);
      feed_n (imap_recv, m, "* OK ready\r\n", split);
      feed_n (imap_recv, m, "* CAPABILITY IMAP4rev1 STARTTLS AUTH=PLAIN\r\nA1 OK\r\n",
              split);
      feed_n (imap_recv, m, "A2 NO TLS not available\r\n", split);
      check (starts_with (twist_imap_command (m), "A3 AUTHENTICATE PLAIN ")
             && !transfer->done, "wanted and refused goes on");
      twist_transfer_free (transfer);

      transfer = tls_transfer (url, TWIST_USE_SSL_NONE);
      m = twist_imap_new (transfer, 0);
      feed_n (imap_recv, m, "* OK ready\r\n", split);
      feed_n (imap_recv, m, "* CAPABILITY IMAP4rev1 STARTTLS AUTH=PLAIN\r\nA1 OK\r\n",
              split);
      check (starts_with (twist_imap_command (m), "A2 AUTHENTICATE PLAIN "),
             "STARTTLS is not sent unless it is asked for");
      twist_transfer_free (transfer);
    }
  {
    twist_transfer *transfer = tls_transfer (url, TWIST_USE_SSL_ALL);
    struct twist_imap *m = twist_imap_new (transfer, 0);

    feed_n (imap_recv, m, "* OK ready\r\n", 200);
    feed_n (imap_recv, m, "* CAPABILITY IMAP4rev1 STARTTLS\r\nA1 OK\r\n", 200);
    feed_n (imap_recv, m, "A2 OK go\r\n* CAPABILITY IMAP4rev1 AUTH=PLAIN\r\n", 200);
    check (transfer->done && transfer->result == TWIST_ERR_PROTOCOL,
           "bytes in the clear behind the reply to STARTTLS end the transfer");
    twist_transfer_free (transfer);
  }
}

static void
test_pop3_stls (void)
{
  static const char *const url = "pop3://alice:secret@127.0.0.1/1";
  size_t splits[2] = { 1, 200 };
  size_t k;

  for (k = 0; k < 2; k++)
    {
      size_t split = splits[k];
      twist_transfer *transfer;
      struct twist_pop3 *p;

      transfer = tls_transfer (url, TWIST_USE_SSL_ALL);
      p = twist_pop3_new (transfer, 0);
      feed_n (pop3_recv, p, "+OK pop\r\n", split);
      check (strcmp (twist_pop3_command (p), "CAPA\r\n") == 0, "capa");
      feed_n (pop3_recv, p, "+OK\r\nSTLS\r\nUSER\r\n.\r\n", split);
      check (strcmp (twist_pop3_command (p), "STLS\r\n") == 0,
             "STLS, not USER, when offered");
      feed_n (pop3_recv, p, "+OK Begin TLS negotiation\r\n", split);
      check (strcmp (twist_pop3_command (p), "STLS\r\n") == 0
             && !transfer->done,
             "nothing is sent until the handshake is done");
      twist_pop3_tls_done (p);
      check (strcmp (twist_pop3_command (p), "CAPA\r\n") == 0,
             "CAPA again, encrypted");
      feed_n (pop3_recv, p, "+OK\r\nSTLS\r\nUSER\r\n.\r\n", split);
      check (strcmp (twist_pop3_command (p), "USER alice\r\n") == 0
             && !transfer->done, "then the login");
      twist_transfer_free (transfer);

      transfer = tls_transfer (url, TWIST_USE_SSL_ALL);
      p = twist_pop3_new (transfer, 0);
      feed_n (pop3_recv, p, "+OK pop\r\n", split);
      feed_n (pop3_recv, p, "+OK\r\nUSER\r\n.\r\n", split);
      check (transfer->done && transfer->result == TWIST_ERR_USE_SSL
             && !starts_with (twist_pop3_command (p), "USER"),
             "required and not offered is an error, and nothing is sent");
      twist_transfer_free (transfer);

      transfer = tls_transfer (url, TWIST_USE_SSL_ALL);
      p = twist_pop3_new (transfer, 0);
      feed_n (pop3_recv, p, "+OK pop\r\n-ERR no CAPA\r\n", split);
      check (transfer->done && transfer->result == TWIST_ERR_USE_SSL,
             "required, and no way to ask what is offered, is an error");
      twist_transfer_free (transfer);

      transfer = tls_transfer (url, TWIST_USE_SSL_TRY);
      p = twist_pop3_new (transfer, 0);
      feed_n (pop3_recv, p, "+OK pop\r\n", split);
      feed_n (pop3_recv, p, "+OK\r\nUSER\r\n.\r\n", split);
      check (strcmp (twist_pop3_command (p), "USER alice\r\n") == 0
             && !transfer->done, "wanted and not offered goes on");
      twist_transfer_free (transfer);

      transfer = tls_transfer (url, TWIST_USE_SSL_ALL);
      p = twist_pop3_new (transfer, 0);
      feed_n (pop3_recv, p, "+OK pop\r\n", split);
      feed_n (pop3_recv, p, "+OK\r\nSTLS\r\n.\r\n", split);
      feed_n (pop3_recv, p, "-ERR not now\r\n", split);
      check (transfer->done && transfer->result == TWIST_ERR_USE_SSL,
             "required and refused is an error");
      twist_transfer_free (transfer);
      transfer = tls_transfer (url, TWIST_USE_SSL_TRY);
      p = twist_pop3_new (transfer, 0);
      feed_n (pop3_recv, p, "+OK pop\r\n", split);
      feed_n (pop3_recv, p, "+OK\r\nSTLS\r\n.\r\n", split);
      feed_n (pop3_recv, p, "-ERR not now\r\n", split);
      check (strcmp (twist_pop3_command (p), "USER alice\r\n") == 0
             && !transfer->done, "wanted and refused goes on");
      twist_transfer_free (transfer);

      transfer = tls_transfer (url, TWIST_USE_SSL_NONE);
      p = twist_pop3_new (transfer, 0);
      feed_n (pop3_recv, p, "+OK pop\r\n", split);
      feed_n (pop3_recv, p, "+OK\r\nSTLS\r\n.\r\n", split);
      check (strcmp (twist_pop3_command (p), "USER alice\r\n") == 0,
             "STLS is not sent unless it is asked for");
      twist_transfer_free (transfer);
    }
  {
    twist_transfer *transfer = tls_transfer (url, TWIST_USE_SSL_ALL);
    struct twist_pop3 *p = twist_pop3_new (transfer, 0);

    feed_n (pop3_recv, p, "+OK pop\r\n", 200);
    feed_n (pop3_recv, p, "+OK\r\nSTLS\r\n.\r\n", 200);
    feed_n (pop3_recv, p, "+OK go\r\nUSER\r\n.\r\n", 200);
    check (transfer->done && transfer->result == TWIST_ERR_PROTOCOL,
           "bytes in the clear behind the reply to STLS end the transfer");
    twist_transfer_free (transfer);
  }
}

/* The option takes the three values and no others.  */
static void
test_use_ssl_option (void)
{
  twist_transfer *transfer = twist_transfer_new ();

  check (twist_transfer_setopt (transfer, TWISTOPT_USE_SSL,
                                3L) == TWIST_ERR_INVAL
         && twist_transfer_setopt (transfer, TWISTOPT_USE_SSL,
                                   -1L) == TWIST_ERR_INVAL,
         "a value that is not one of the three is refused");
  check (twist_strerror (TWIST_ERR_USE_SSL)[0] != 0, "a sentence for the error");
  twist_transfer_free (transfer);
}

int
main (void)
{
  test_imap_mailbox ();
  test_mail ();
  test_use_ssl_option ();
  test_smtp_starttls ();
  test_imap_starttls ();
  test_pop3_stls ();
  return tests_finish ();
}
