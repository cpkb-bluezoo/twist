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

/* The URL parser, the writer, and resolving a reference against a base.  The
   input is a URL; if it has a newline, what follows is the reference.  */

const char *const fuzz_tokens[] = {
  "://", "[", "]", "%25", "%", "@", ":", "/", "?", "#", "..", "/./", "//",
  "http", "https", "sftp", "file", "ftp", "[::1]", "[fe80::1%25eth0]", NULL
};

void
fuzz_seeds (void (*add) (const void *, size_t))
{
  static const char *seeds[] = {
    "http://example.com/a/b?c=d#e", "sftp://user:pw@[::1]:2222/dir/f",
    "http://example.com/a/b\n../c?d", "file:///tmp/x%20y", "ftp://h/p;type=a",
    "sftp://u@[fe80::1%25eth0]/x", "HTTP://EXAMPLE.COM:80/", "http://a:b@c@d/",
    "http://h/a\n//other/x", "scheme://host:99999/", "http://[::1/x"
  };
  size_t i;

  for (i = 0; i < sizeof seeds / sizeof seeds[0]; i++)
    add (seeds[i], strlen (seeds[i]));
}

int
LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
  char *s = fuzz_string (data, size), *ref = strchr (s, '\n');
  struct twist_url *u = NULL, *r = NULL;
  char buf[256];

  if (ref != NULL)
    *ref++ = 0;
  if (twist_url_parse_int (s, &u) == TWIST_OK)
    {
      char *text = twist_url_format (u);

      free (text);
      twist_url_host_text (u, 0, buf, sizeof buf);
      twist_url_host_text (u, 1, buf, sizeof buf);
      twist_url_proxy_target (u, buf, sizeof buf);
      if (u->scheme != NULL)
        twist_url_default_port (u->scheme);
      if (ref != NULL && twist_url_resolve_int (u, ref, &r) == TWIST_OK)
        {
          text = twist_url_format (r);
          free (text);
          twist_url_free_int (r);
        }
      twist_url_free_int (u);
    }
  free (s);
  return 0;
}
