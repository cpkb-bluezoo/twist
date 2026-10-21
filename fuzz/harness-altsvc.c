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

/* The Alt-Svc header: the value read for h3, and kept for an origin.  */

const char *const fuzz_tokens[] = {
  "h3=\":443\"", "h3-29=", "; ma=", "clear", ",", "\"", ":", "h2=", NULL
};

void
fuzz_seeds (void (*add) (const void *, size_t))
{
  static const char *seeds[] = {
    "h3=\":443\"; ma=86400", "h3-29=\":8443\", h2=\":443\"", "clear",
    "h3=\"alt.example.com:443\"; persist=1"
  };
  size_t i;

  for (i = 0; i < sizeof seeds / sizeof seeds[0]; i++)
    add (seeds[i], strlen (seeds[i]));
}

int
LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
  char *s = fuzz_string (data, size);
  struct twist_altsvc *a = twist_altsvc_new ();
  int port, clear;

  twist_alt_svc_h3 (s, size, &port, &clear);
  if (a != NULL)
    {
      twist_altsvc_note (a, "example.com", s);
      twist_altsvc_note (a, s, s);
      twist_altsvc_lookup (a, "example.com");
      twist_altsvc_lookup (a, s);
      twist_altsvc_free (a);
    }
  free (s);
  return 0;
}
