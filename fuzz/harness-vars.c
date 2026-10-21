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

/* Variables.  Every line but the last defines one (an @ becomes an =, so that
   no file is read); the last is expanded.  */

const char *const fuzz_tokens[] = {
  "{{", "}}", ":", ",", "trim", "json", "url", "b64", "64dec", "\\{{", "=",
  "%", "\n", NULL
};

void
fuzz_seeds (void (*add) (const void *, size_t))
{
  static const char *seeds[] = {
    "v=hello\n{{v}}", "v= pad \nw=aGVsbG8=\n{{v:trim:b64}}{{w:64dec}}",
    "v=a\"b\\c\n{{v:json}}", "v=a b/c\n{{v:url}}", "%HOME\n{{HOME}}",
    "%NOPE_FUZZ=dflt\n{{NOPE_FUZZ}}", "a=1\n\\{{a}}{{a}}{{b}}",
    "v=x\n{{v:nosuch}}", "v=x\n{{v:}}"
  };
  size_t i;

  for (i = 0; i < sizeof seeds / sizeof seeds[0]; i++)
    add (seeds[i], strlen (seeds[i]));
}

int
LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
  char *s = fuzz_string (data, size), *line = s, *nl, err[300], *out;
  struct twist_vars *v = twist_vars_new ();
  char *p;

  if (v == NULL)
    abort ();
  for (p = s; *p != 0; p++)
    if (*p == '@')
      *p = '=';
  while ((nl = strchr (line, '\n')) != NULL)
    {
      *nl = 0;
      twist_vars_define (v, line, err, sizeof err);
      line = nl + 1;
    }
  out = twist_vars_expand (v, line, err, sizeof err);
  free (out);
  twist_vars_free (v);
  free (s);
  return 0;
}
