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

/* MQTT packets from a broker: CONNACK, SUBACK, PUBLISH, PINGRESP, DISCONNECT.  The first byte says how the input is cut up; the rest is what the
   server sends.  */

const char *const fuzz_tokens[] = {
  "\x20\x02\x00\x00", "\x90\x03", "\x30", "\xd0\x00", "\xe0\x00", "\x32", "\x40\x02",
  NULL
};

void
fuzz_seeds (void (*add) (const void *, size_t))
{
  static const uint8_t s1[] = { 0x00, 0x20, 0x02, 0x00, 0x00, 0x90, 0x03, 0x00, 0x01, 0x00,
                                0x30, 0x0d, 0x00, 0x07, 's', 'e', 'n', 's', 'o', 'r', 's', 'h', 'e', 'l', 'l', 'o', 0xe0, 0x00 };
  static const uint8_t s2[] = { 0x01, 0x20, 0x02, 0x00, 0x05, 0xd0, 0x00 };

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
  if (twist_url_parse_int ("mqtt://127.0.0.1/sensors/temp", &easy->url) != TWIST_OK)
    abort ();
  easy->write_cb = fuzz_sink;
  obj = twist_mqtt_new (easy, 0);
  if (obj == NULL)
    abort ();
  fuzz_feed ((fuzz_recv) twist_mqtt_receive, obj, data + 1, size - 1,
             fuzz_piece (data[0], size));
  twist_easy_cleanup (easy);
  return 0;
}
