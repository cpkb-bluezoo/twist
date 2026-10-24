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

/* What a telnet server sends: text with commands in it, the offers and
   requests of options, and sub-negotiations.  The first byte says how the
   input is cut up, and the second which options the session was given; the
   rest is what the server sends, and then what is to be sent to it.  */

const char *const fuzz_tokens[] = {
  "\xff\xfb",			/* IAC WILL */
  "\xff\xfc",			/* IAC WONT */
  "\xff\xfd",			/* IAC DO */
  "\xff\xfe",			/* IAC DONT */
  "\xff\xfa\x18\x01\xff\xf0",	/* IAC SB TTYPE SEND IAC SE */
  "\xff\xfa\x27\x01\xff\xf0",	/* IAC SB NEW-ENVIRON SEND IAC SE */
  "\xff\xff",
  "\xff\xf0",
  "\xff\xfa",
  "\r\0",
  "\r\n",
  "\x18",
  "\x1f",
  "\x23",
  "\x27",
  NULL
};

void
fuzz_seeds (void (*add) (const void *, size_t))
{
  static const char text[] = "\x00\x00" "hello\r\n\xff\xfb\x01" "x";
  static const char ask[] = "\x00\x3f" "\xff\xfd\x18\xff\xfd\x1f\xff\xfd\x27\xff\xfd\x23";
  static const char sub[] = "\x01\x3f" "\xff\xfa\x18\x01\xff\xf0\xff\xfa\x27\x01\xff\xf0";

  add (text, sizeof text - 1);
  add (ask, sizeof ask - 1);
  add (sub, sizeof sub - 1);
}

int
LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
  twist_easy *easy;
  struct twist_telnet *t;
  struct twist_slist *opts = NULL;

  if (size < 2)
    return 0;
  easy = twist_easy_init ();
  if (easy == NULL)
    abort ();
  if (twist_url_parse_int ("telnet://127.0.0.1/", &easy->url) != TWIST_OK)
    abort ();
  if (data[1] & 0x01)
    twist_easy_setopt (easy, TWISTOPT_USERNAME, "fuzz");
  if (data[1] & 0x02)
    opts = twist_slist_append (opts, "TTYPE=xterm");
  if (data[1] & 0x04)
    opts = twist_slist_append (opts, "XDISPLOC=host:0");
  if (data[1] & 0x08)
    opts = twist_slist_append (opts, "NEW_ENV=A,B");
  if (data[1] & 0x10)
    opts = twist_slist_append (opts, "WS=80x24");
  if (data[1] & 0x20)
    opts = twist_slist_append (opts, "BINARY=0");
  if (opts != NULL)
    twist_easy_setopt (easy, TWISTOPT_TELNETOPTIONS, opts);
  easy->write_cb = fuzz_sink;
  t = twist_telnet_new (easy, 0);
  if (t == NULL)
    abort ();
  fuzz_feed ((fuzz_recv) twist_telnet_receive, t, data + 2, size - 2,
             fuzz_piece (data[0], size));
  twist_telnet_input (t, data + 2, size - 2);
  twist_telnet_closed (t, TWIST_ERR_CLOSED);
  twist_easy_cleanup (easy);
  twist_slist_free_all (opts);
  return 0;
}
