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
#include "ssh/ssh-int.h"

/* sftp quote commands, their dates, and the cleaning of a name that a server
   sent for the output.  */

const char *const fuzz_tokens[] = {
  "mkdir ", "rm ", "rmdir ", "rename ", "ln ", "symlink ", "chmod ", "chown ",
  "chgrp ", "mtime ", "atime ", "pwd", "*", "\"", "\\", " ", "GMT", "Jan",
  "Thu, ", "+0100", NULL
};

void
fuzz_seeds (void (*add) (const void *, size_t))
{
  static const char *seeds[] = {
    "mkdir /a/b", "*rm gone", "rename \"a b\" \"c d\"", "chmod 755 f",
    "chown 1000 f", "mtime \"Thu, 02 Jan 2020 10:00:00 GMT\" f", "pwd",
    "Thu, 02 Jan 2020 10:00:00 GMT", "Thu Jan  2 10:00:00 2020",
    "02 Jan 2020 10:00:00 +0100", "ln src dst"
  };
  size_t i;

  for (i = 0; i < sizeof seeds / sizeof seeds[0]; i++)
    add (seeds[i], strlen (seeds[i]));
}

int
LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
  char *s = fuzz_string (data, size), err[300];
  struct twist_quote q;
  int64_t t;
  uint8_t *clean = malloc (size + 1);

  if (twist_quote_parse (s, &q, err, sizeof err) == TWIST_OK)
    twist_quote_clear (&q);
  twist_quote_date (s, &t);
  if (clean != NULL)
    {
      twist_ssh_sanitize (clean, data, size);
      free (clean);
    }
  free (s);
  return 0;
}
