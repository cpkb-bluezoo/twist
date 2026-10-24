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

/* WebSocket frames from a server (including the control frames the client
   must answer), and the handshake checks.  The first byte says how the input
   is cut up.  */

static unsigned long events;

static int send_frame (void *u, const uint8_t *d, size_t n)
{
  (void) u;
  if (n > 0)
    events += d[n - 1];
  return 0;
}
static void finished (void *u, int err) { (void) u; (void) err; events++; }

const char *const fuzz_tokens[] = {
  "\x81", "\x82", "\x88\x00", "\x89\x00", "\x8a\x00", "\x01", "\x80", "\x7e", "\x7f",
  "dGhlIHNhbXBsZSBub25jZQ==", "websocket", "Upgrade", NULL
};

void
fuzz_seeds (void (*add) (const void *, size_t))
{
  static const uint8_t s1[] = { 0x00, 0x81, 0x05, 'H', 'e', 'l', 'l', 'o', 0x89, 0x01, 'p', 0x88, 0x00 };
  static const uint8_t s2[] = { 0x01, 0x01, 0x02, 'a', 'b', 0x80, 0x01, 'c', 0x81, 0x7e, 0x00, 0x03, 'x', 'y', 'z' };

  add (s1, sizeof s1);
  add (s2, sizeof s2);
}

int
LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
  twist_transfer *transfer;
  struct twist_ws *ws;
  char *text, *a, *b, *c, *nl;

  if (size == 0)
    return 0;
  transfer = twist_transfer_new ();
  if (transfer == NULL)
    abort ();
  transfer->write_cb = fuzz_sink;
  ws = twist_ws_new (transfer, send_frame, NULL, finished, NULL);
  if (ws == NULL)
    abort ();
  fuzz_feed ((fuzz_recv) twist_ws_receive, ws, data + 1, size - 1,
             fuzz_piece (data[0], size));
  twist_ws_send (ws, 1, 1, data, size < 200 ? size : 200);
  twist_ws_free (ws);
  twist_transfer_free (transfer);

  /* The handshake: four lines make the key, the upgrade header, the
     connection header and the accept value.  */
  text = fuzz_string (data, size);
  a = text;
  b = (nl = strchr (a, '\n')) != NULL ? (*nl = 0, nl + 1) : a + strlen (a);
  c = (nl = strchr (b, '\n')) != NULL ? (*nl = 0, nl + 1) : b + strlen (b);
  nl = strchr (c, '\n');
  if (nl != NULL)
    {
      *nl = 0;
      twist_ws_validate (a, b, c, nl + 1);
    }
  {
    char *accept = NULL;

    if (twist_ws_accept (a, &accept) == TWIST_OK)
      free (accept);
  }
  free (text);
  return 0;
}
