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

/* IMAP responses: greeting, CAPABILITY, LOGIN, SELECT, FETCH with a literal.  The first byte says how the input is cut up; the rest is what the
   server sends.  */

const char *const fuzz_tokens[] = {
  "* OK",
  "* BYE",
  "* CAPABILITY ",
  "A001 ",
  "A002 ",
  "A003 ",
  " OK",
  " NO",
  " BAD",
  "{",
  "}\r\n",
  "FETCH (",
  "BODY[]",
  "+ ",
  "AUTH=PLAIN",
  "STARTTLS",
  NULL
};

void
fuzz_seeds (void (*add) (const void *, size_t))
{
  static const char *seeds[] = {
    "\x00" "* OK ready\r\n* CAPABILITY IMAP4rev1 AUTH=PLAIN\r\nA001 OK done\r\n* 1 EXISTS\r\nA002 OK [READ-ONLY] sel\r\n* 1 FETCH (UID 1 BODY[] {5}\r\nhello)\r\nA003 OK fetched\r\n",
    "\x00" "* PREAUTH hi\r\n",
    "\x00" "+ \r\nA001 NO bad\r\n",
    "\x00" "* BYE\r\n"
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
  if (twist_url_parse_int ("imap://alice:secret@127.0.0.1/INBOX;UID=1", &easy->url) != TWIST_OK)
    abort ();
  easy->write_cb = fuzz_sink;
  obj = twist_imap_new (easy, 0);
  if (obj == NULL)
    abort ();
  fuzz_feed ((fuzz_recv) twist_imap_receive, obj, data + 1, size - 1,
             fuzz_piece (data[0], size));
  twist_easy_cleanup (easy);
  return 0;
}
