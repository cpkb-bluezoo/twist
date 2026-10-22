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

#include "fuzz.h"

/* SMTP replies to a message being sent: greeting, EHLO and its extensions, AUTH, the envelope, DATA.  The first byte says how the input is cut up; the rest is what the
   server sends.  */

const char *const fuzz_tokens[] = {
  "220 ",
  "250-",
  "250 ",
  "334 ",
  "235 ",
  "354 ",
  "\r\n",
  "AUTH ",
  "PLAIN",
  "LOGIN",
  "CRAM-MD5",
  "STARTTLS",
  "421 ",
  "550 ",
  NULL
};

void
fuzz_seeds (void (*add) (const void *, size_t))
{
  static const char *seeds[] = {
    "\x00" "220 ready\r\n250-AUTH PLAIN LOGIN\r\n250-SIZE 100\r\n250 8BITMIME\r\n235 ok\r\n250 sender\r\n250 rcpt\r\n354 go\r\n250 queued\r\n221 bye\r\n",
    "\x00" "220 hi\r\n250 hello\r\n535 no\r\n",
    "\x00" "220-multi\r\n220 line\r\n334 dXNlcm5hbWU6\r\n"
  };
  size_t i;

  for (i = 0; i < sizeof seeds / sizeof seeds[0]; i++)
    add (seeds[i], strlen (seeds[i] + 1) + 1);
}


int
LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
  twist_easy *easy;
  void *obj;

  if (size == 0)
    return 0;
  easy = twist_easy_init ();
  if (easy == NULL)
    abort ();
  if (twist_url_parse_int ("smtp://alice:secret@127.0.0.1", &easy->url) != TWIST_OK)
    abort ();
  easy->write_cb = fuzz_sink;
  easy->mail_from = twist_strdup ("a@b");
  easy->mail_rcpt = twist_slist_append (NULL, "c@d");
  easy->postfields = (char[]) { 'H', 'i', '\r', '\n', '.', 'x', '\r', '\n', 0 };
  /* The top two bits say whether TLS is wanted, and the handshake of an
     upgrade, if there is one, finishes half way through.  */
  easy->use_ssl = (data[0] >> 6) % 3;
  obj = twist_smtp_new (easy, 0);
  if (obj == NULL)
    abort ();
  fuzz_feed ((fuzz_recv) twist_smtp_receive, obj, data + 1, (size - 1) / 2,
             fuzz_piece (data[0], size));
  twist_smtp_tls_done (obj);
  fuzz_feed ((fuzz_recv) twist_smtp_receive, obj, data + 1 + (size - 1) / 2,
             size - 1 - (size - 1) / 2, fuzz_piece (data[0], size));
  twist_slist_free_all (easy->mail_rcpt);
  easy->mail_rcpt = NULL;
  easy->postfields = NULL;
  twist_easy_cleanup (easy);
  return 0;
}
