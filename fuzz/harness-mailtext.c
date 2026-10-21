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

/* The pieces of the mail protocols that cut text: lines, the dot-stuffing
   of a message in both directions, and IMAP mailbox names.  */

static unsigned long events;

static int sink (void *u, const uint8_t *d, size_t n)
{
  (void) u;
  if (n > 0)
    events += d[n - 1];
  return 0;
}

const char *const fuzz_tokens[] = { "\r\n", "\r\n.\r\n", "\r\n..", ".", "\r", "\n", "\"", "{", "}", NULL };

void
fuzz_seeds (void (*add) (const void *, size_t))
{
  static const char *seeds[] = {
    "line one\r\nline two\r\n.\r\n", "..dotted\r\n.\r\n", "a\rb\nc\r\n", "INBOX{10}", "a\"b"
  };
  size_t i;

  for (i = 0; i < sizeof seeds / sizeof seeds[0]; i++)
    add (seeds[i], strlen (seeds[i]));
}

int
LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
  size_t off = 0;
  const uint8_t *line;
  size_t ln;
  int err = 0, done = 0;
  struct twist_dotin in;
  struct twist_dotout out;
  char box[512], *text = fuzz_string (data, size);

  while (off < size)
    {
      size_t used = twist_mail_line (data + off, size - off, &line, &ln, &err);

      if (err || used == 0)
        break;
      off += used;
    }
  twist_dotin_init (&in);
  off = 0;
  while (off < size && !done)
    {
      size_t used = twist_dotin_pull (&in, data + off, size - off, sink, NULL,
                                      &done, &err);

      if (used == 0 || err)
        break;
      off += used;
    }
  twist_dotout_init (&out);
  twist_dotout_write (&out, data, size, sink, NULL);
  twist_dotout_finish (&out, sink, NULL);
  twist_imap_mailbox (text, box, sizeof box);
  free (text);
  return 0;
}
