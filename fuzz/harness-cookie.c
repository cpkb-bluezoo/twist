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

/* Set-Cookie values, stored for a few hosts and paths and read back.  */

const char *const fuzz_tokens[] = {
  "; Path=/", "; Domain=", "; Secure", "; HttpOnly", "; Max-Age=", "; Expires=",
  "Thu, 01 Jan 1970 00:00:00 GMT", "; SameSite=", "example.com", ".com", "=", NULL
};

void
fuzz_seeds (void (*add) (const void *, size_t))
{
  static const char *seeds[] = {
    "a=b; Path=/", "id=1; Domain=example.com; Secure; HttpOnly",
    "x=y; Max-Age=0", "s=t; Expires=Thu, 01 Jan 2099 00:00:00 GMT",
    "a=b; Domain=.com", "=novalue", "a=b\r\nX: y"
  };
  size_t i;

  for (i = 0; i < sizeof seeds / sizeof seeds[0]; i++)
    add (seeds[i], strlen (seeds[i]));
}

int
LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
  static const char *const hosts[] = { "example.com", "www.example.com", "com",
                                       "127.0.0.1", "[::1]", "a.b.c.example.co.uk" };
  static const char *const paths[] = { "/", "/a/b", "/a/b/", "" };
  char *s = fuzz_string (data, size), *hdr;
  struct twist_jar *jar = twist_jar_new ();
  size_t i;

  if (jar == NULL)
    abort ();
  for (i = 0; i < 6; i++)
    twist_jar_store (jar, s, hosts[i], paths[i % 4], (int) (i & 1));
  for (i = 0; i < 6; i++)
    {
      hdr = NULL;
      if (twist_jar_header (jar, hosts[i], paths[(i + 1) % 4], (int) (i & 1),
                            &hdr) == TWIST_OK)
        free (hdr);
    }
  twist_jar_free (jar);
  free (s);
  return 0;
}
