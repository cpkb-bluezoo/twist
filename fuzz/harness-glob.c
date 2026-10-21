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

/* URL globbing: the pattern, the first few hundred URLs it makes, the values,
   and an output name built from the pattern's own text.  */

const char *const fuzz_tokens[] = {
  "{", "}", "[", "]", ",", "-", ":", "\\", "[1-10]", "{a,b}", "[a-z]",
  "[01-10:3]", "#1", "#2", "http://[::1]/", NULL
};

void
fuzz_seeds (void (*add) (const void *, size_t))
{
  static const char *seeds[] = {
    "http://h/{a,b,c}", "http://h/[1-10]/{x,y}", "http://h/[01-10:3]",
    "http://h/[a-z]_[A-C]", "http://h/\\{a\\}", "http://[::1]/[1-3]",
    "http://h/{a\\,b,c}", "http://h/[3-1]", "http://h/{a,{b}}"
  };
  size_t i;

  for (i = 0; i < sizeof seeds / sizeof seeds[0]; i++)
    add (seeds[i], strlen (seeds[i]));
}

int
LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
  char *s = fuzz_string (data, size), err[600], *url, *name;
  struct twist_glob *g = NULL;
  int i;

  if (twist_glob_parse (s, &g, err, sizeof err) == TWIST_OK)
    {
      size_t n = twist_glob_count (g), k;

      for (i = 0; i < 300 && twist_glob_next (g, &url) == 1; i++)
        {
          for (k = 0; k <= n + 1; k++)
            (void) twist_glob_value (g, k);
          name = twist_glob_name (g, s);
          free (name);
          free (url);
        }
      twist_glob_free (g);
    }
  free (s);
  return 0;
}
