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

/* LDAP messages from a server (BER): bind response, search entries and the end.  The first byte says how the input is cut up; the rest is what the
   server sends.  */

const char *const fuzz_tokens[] = {
  "\x30", "\x02\x01", "\x61", "\x64", "\x65", "\x30\x84", "\x04\x00", "\x0a\x01\x00", "\x31", "\xa3", "\x83",
  NULL
};

void
fuzz_seeds (void (*add) (const void *, size_t))
{
  static const uint8_t s1[] = { 0x00, 0x30, 0x0c, 0x02, 0x01, 0x01, 0x61, 0x07, 0x0a, 0x01, 0x00, 0x04, 0x00, 0x04, 0x00,
                                0x30, 0x0c, 0x02, 0x01, 0x02, 0x65, 0x07, 0x0a, 0x01, 0x00, 0x04, 0x00, 0x04, 0x00 };
  static const uint8_t s2[] = { 0x00, 0x30, 0x1b, 0x02, 0x01, 0x02, 0x64, 0x16, 0x04, 0x07, 'd', 'c', '=', 'x', ',', 'd',
                                0x30, 0x0b, 0x30, 0x09, 0x04, 0x02, 'c', 'n', 0x31, 0x03, 0x04, 0x01, 'a' };

  add (s1, sizeof s1);
  add (s2, sizeof s2);
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
  if (twist_url_parse_int ("ldap://127.0.0.1/dc=example,dc=com", &easy->url) != TWIST_OK)
    abort ();
  easy->write_cb = fuzz_sink;
  obj = twist_ldap_new (easy, 0);
  if (obj == NULL)
    abort ();
  fuzz_feed ((fuzz_recv) twist_ldap_receive, obj, data + 1, size - 1,
             fuzz_piece (data[0], size));
  twist_easy_cleanup (easy);
  return 0;
}
