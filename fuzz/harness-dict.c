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

/* DICT replies: banner, definitions, status lines and the end.  The first byte says how the input is cut up; the rest is what the
   server sends.  */

const char *const fuzz_tokens[] = {
  "220 ",
  "150 ",
  "151 ",
  "250 ",
  "221 ",
  "552 ",
  "550 ",
  "\r\n.\r\n",
  "\r\n..",
  NULL
};

void
fuzz_seeds (void (*add) (const void *, size_t))
{
  static const char *seeds[] = {
    "\x00" "220 dict ready\r\n150 1 definitions\r\n151 \"word\" db \"Db\"\r\nThe definition\r\n.\r\n250 ok\r\n221 bye\r\n",
    "\x00" "552 no match\r\n",
    "\x00" "220 x\r\n550 bad db\r\n"
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
  if (twist_url_parse_int ("dict://127.0.0.1/d:word", &easy->url) != TWIST_OK)
    abort ();
  easy->write_cb = fuzz_sink;
  obj = twist_dict_new (easy, 0);
  if (obj == NULL)
    abort ();
  fuzz_feed ((fuzz_recv) twist_dict_receive, obj, data + 1, size - 1,
             fuzz_piece (data[0], size));
  twist_easy_cleanup (easy);
  return 0;
}
