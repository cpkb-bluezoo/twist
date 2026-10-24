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

/* TFTP datagrams: DATA, ACK, OACK and ERROR.  Each piece of the input is a datagram.  The first byte says how the input is cut up; the rest is what the
   server sends.  */

const char *const fuzz_tokens[] = {
  "\x00\x03", "\x00\x04", "\x00\x05", "\x00\x06", "blksize", "tsize", "timeout", "\x00",
  NULL
};

void
fuzz_seeds (void (*add) (const void *, size_t))
{
  static const uint8_t s1[] = { 0x00, 0x00, 0x03, 0x00, 0x01, 'h', 'e', 'l', 'l', 'o' };
  static const uint8_t s2[] = { 0x00, 0x00, 0x05, 0x00, 0x01, 'n', 'o', 0x00 };
  static const uint8_t s3[] = { 0x00, 0x00, 0x06, 'b', 'l', 'k', 's', 'i', 'z', 'e', 0x00, '5', '1', '2', 0x00 };

  add (s1, sizeof s1);
  add (s2, sizeof s2);
  add (s3, sizeof s3);
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
  if (twist_url_parse_int ("tftp://127.0.0.1/hello",
                           &transfer->url) != TWIST_OK)
    abort ();
  transfer->write_cb = fuzz_sink;
  obj = twist_tftp_new (transfer, 0);
  if (obj == NULL)
    abort ();
  fuzz_feed ((fuzz_recv) twist_tftp_receive, obj, data + 1, size - 1,
             fuzz_piece (data[0], size));
  twist_transfer_free (transfer);
  return 0;
}
