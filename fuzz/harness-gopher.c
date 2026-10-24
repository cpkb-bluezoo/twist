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

/* Gopher menus and documents: tab separated lines, the dot at the end.  The first byte says how the input is cut up; the rest is what the
   server sends.  */

const char *const fuzz_tokens[] = {
  "\t",
  "\r\n",
  "\r\n.\r\n",
  ".",
  "..",
  NULL
};

void
fuzz_seeds (void (*add) (const void *, size_t))
{
  static const char *seeds[] = {
    "\x00" "0A text\tpath\thost\t70\r\n.\r\n",
    "\x00" "plain document without an end",
    "\x00" "i\t\t\t\r\n..\r\n.\r\n"
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
  if (twist_url_parse_int ("gopher://127.0.0.1/1/hello", &transfer->url) != TWIST_OK)
    abort ();
  transfer->write_cb = fuzz_sink;
  obj = twist_gopher_new (transfer, 0);
  if (obj == NULL)
    abort ();
  fuzz_feed ((fuzz_recv) twist_gopher_receive, obj, data + 1, size - 1,
             fuzz_piece (data[0], size));
  twist_transfer_free (transfer);
  return 0;
}
