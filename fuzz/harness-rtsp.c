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

/* The reply of an RTSP server: a status line, headers, and a body as long as
   Content-Length says.  The first byte says how the input is cut up; the rest
   is what the server sends.  */

const char *const fuzz_tokens[] = {
  "RTSP/1.0 ",
  "200 OK",
  "\r\n",
  "\r\n\r\n",
  "CSeq: 1",
  "Content-Length: ",
  "Session: ",
  NULL
};

void
fuzz_seeds (void (*add) (const void *, size_t))
{
  static const char *seeds[] = {
    "\x00" "RTSP/1.0 200 OK\r\nCSeq: 1\r\nContent-Length: 5\r\n\r\nhello",
    "\x01" "RTSP/1.0 404 Not Found\r\nCSeq: 1\r\n\r\n",
    "\x02" "RTSP/1.0 200 OK\r\ncseq:1\r\nPublic: OPTIONS, DESCRIBE\r\n\r\n"
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
  if (twist_url_parse_int ("rtsp://127.0.0.1/stream", &transfer->url) != TWIST_OK)
    abort ();
  transfer->write_cb = fuzz_sink;
  transfer->header_cb = fuzz_sink;
  obj = twist_rtsp_new (transfer, 0);
  if (obj == NULL)
    abort ();
  fuzz_feed ((fuzz_recv) twist_rtsp_receive, obj, data + 1, size - 1,
             fuzz_piece (data[0], size));
  twist_transfer_free (transfer);
  return 0;
}
