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

/* A proxy's side of the conversation.  The first byte says which proxy (HTTP
   or SOCKS5), whether there are credentials, which kind of target it is asked
   to reach, and how the reply is cut up; the rest is what the proxy sends.  A
   line of text is also a proxy URL.  */

static const char *const targets[] = {
  "example.com", "10.1.2.3", "2001:db8::7", "fe80::1%eth0", "a", ""
};

const char *const fuzz_tokens[] = {
  "HTTP/1.1 200 OK\r\n\r\n", "HTTP/1.0 407 ", "\r\n\r\n", "\x05\x00", "\x05\x02",
  "\x01\x00", "\x05\x00\x00\x01", "\x05\x00\x00\x03", "\x05\x00\x00\x04", NULL
};

void
fuzz_seeds (void (*add) (const void *, size_t))
{
  static const uint8_t s1[] = { 0x00, 'H', 'T', 'T', 'P', '/', '1', '.', '1', ' ',
                                '2', '0', '0', ' ', 'O', 'K', '\r', '\n',
                                '\r', '\n', 'S', 'S', 'H', '-' };
  static const uint8_t s2[] = { 0x01, 5, 0, 5, 0, 0, 1, 0, 0, 0, 0, 0, 0, 'S' };
  static const uint8_t s3[] = { 0x03, 5, 2, 1, 0, 5, 0, 0, 3, 3, 'a', 'b', 'c',
                                0, 80 };
  static const uint8_t s4[] = { 0x00, 'H', 'T', 'T', 'P', '/', '1', '.', '1',
                                ' ', '4', '0', '7', ' ', 'x', '\r', '\n', '\r',
                                '\n' };

  add (s1, sizeof s1);
  add (s2, sizeof s2);
  add (s3, sizeof s3);
  add (s4, sizeof s4);
  add ("http://u:p%40w@[::1]:3128/x", 27);
  add ("socks5://s:1080", 15);
}

static void
drive (struct twist_proxy *p, const uint8_t *reply, size_t n, size_t piece)
{
  size_t off = 0;
  int guard = 0;

  for (;;)
    {
      uint8_t *out = NULL;
      size_t len = 0, used = 0;
      int ready = 0;
      size_t take = piece < n - off ? piece : n - off;

      /* What the proxy has to say next: the request, the credentials.  */
      if (twist_proxy_opening (p, &out, &len) == TWIST_OK)
        free (out);
      if (take == 0 || ++guard > 20000)
        break;
      if (twist_proxy_feed (p, reply + off, take, &used, &ready) != TWIST_OK)
        break;
      if (used > take)
        abort ();
      off += used > 0 ? used : take;
      if (ready)
        break;
    }
}

int
LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
  struct twist_proxy *p;
  unsigned flags;
  char *text;
  int kind, port;
  char *host = NULL, *user = NULL, *pass = NULL;

  if (size == 0)
    return 0;
  flags = data[0];
  p = twist_proxy_new ((flags & 1) ? TWIST_PROXY_SOCKS5 : TWIST_PROXY_HTTP,
                       "proxy", 1080, NULL);
  twist_proxy_set_target (p, targets[(flags >> 2) % 6], 22);
  if (flags & 2)
    twist_proxy_set_credentials (p, "user", "pass");
  drive (p, data + 1, size - 1, fuzz_piece (flags >> 4, size));
  twist_proxy_error (p, &kind);
  twist_proxy_free (p);

  text = fuzz_string (data, size);
  if (twist_proxy_parse (text, &kind, &host, &port, &user, &pass) == TWIST_OK)
    {
      free (host);
      free (user);
      free (pass);
    }
  free (text);
  return 0;
}
