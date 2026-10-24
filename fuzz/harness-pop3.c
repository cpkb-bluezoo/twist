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

/* POP3 replies: greeting, CAPA, USER and PASS, RETR with a dot-stuffed body.  The first byte says how the input is cut up; the rest is what the
   server sends.  */

const char *const fuzz_tokens[] = {
  "+OK",
  "-ERR",
  "\r\n",
  "\r\n.\r\n",
  "USER",
  "SASL ",
  "STLS",
  "PLAIN",
  "\r\n..",
  NULL
};

void
fuzz_seeds (void (*add) (const void *, size_t))
{
  static const char *seeds[] = {
    "\x00" "+OK pop\r\n+OK\r\nUSER\r\n.\r\n+OK\r\n+OK\r\n+OK 5 octets\r\nhello\r\n..dot\r\n.\r\n+OK bye\r\n",
    "\x00" "+OK\r\n-ERR no\r\n",
    "\x00" "+OK a <b@c>\r\n"
  };
  size_t i;

  for (i = 0; i < sizeof seeds / sizeof seeds[0]; i++)
    add (seeds[i], strlen (seeds[i] + 1) + 1);
}


int
LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
  twist_transfer *transfer;
  void *obj;

  if (size == 0)
    return 0;
  transfer = twist_transfer_new ();
  if (transfer == NULL)
    abort ();
  if (twist_url_parse_int ("pop3://alice:secret@127.0.0.1/1", &transfer->url) != TWIST_OK)
    abort ();
  transfer->write_cb = fuzz_sink;
  /* The top two bits say whether TLS is wanted, and the handshake of an
     upgrade, if there is one, finishes half way through.  */
  transfer->use_ssl = (data[0] >> 6) % 3;
  obj = twist_pop3_new (transfer, 0);
  if (obj == NULL)
    abort ();
  fuzz_feed ((fuzz_recv) twist_pop3_receive, obj, data + 1, (size - 1) / 2,
             fuzz_piece (data[0], size));
  twist_pop3_tls_done (obj);
  fuzz_feed ((fuzz_recv) twist_pop3_receive, obj, data + 1 + (size - 1) / 2,
             size - 1 - (size - 1) / 2, fuzz_piece (data[0], size));
  twist_transfer_free (transfer);
  return 0;
}
