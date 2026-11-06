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

/* The SMB2 response parser.  The first byte picks the size of the pieces the
   input is fed in, whether the consumer takes only a few bytes of data at a
   time, and whether the input is one message with no framing; the rest is
   the stream.  */

const char *const fuzz_tokens[] = {
  "\\xfe" "SMB", "\\xfd" "SMB", "\\x40\\x00", "\\x41\\x00", "\\x09\\x00", "\\x11\\x00",
  "\\x03\\x11", "\\x01\\x00\\x00\\x00", "\\x00\\x00\\x00\\x00", NULL
};

static const char *const seeds[] = {
  "000000d4fe534d42400001000000000000001f0001000000000000000100000000000000000000000500000088776655443322115349474e41545552452d5349474e2d314100030011030300a0a1a2a3a4a5a6a7a8a9aaabacadaeaf2f000000000001000000010000000100010000000000000002000000000000008000040088000000414243440000000001002600000000000100200001005a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a000002000400000000000100020000000000080004000000000001000100",
  "00000064fe534d42400001000000000008001f0001000000000000000100000000000000000000000500000088776655443322115349474e41545552452d5349474e2d3111005000140000000000000000000000000102030405060708090a0b0c0d0e0f10111213",
  "00000070fe534d4240000100000000000e001f0001000000000000000100000000000000000000000500000088776655443322115349474e41545552452d5349474e2d31090048002800000018000000410000000000000000000000000000000000000000000000420000000000000000000000",
  "00000049fe534d4240000100060000800e001f0001000000000000000100000000000000000000000500000088776655443322115349474e41545552452d5349474e2d31090000000000000000",
  "00000074fd534d42545454545454545454545454545454544e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4000000000000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
};

void
fuzz_seeds (void (*add) (const void *, size_t))
{
  size_t k;

  for (k = 0; k < sizeof seeds / sizeof seeds[0]; k++)
    {
      uint8_t buf[600];
      size_t n = strlen (seeds[k]) / 2, i;

      if (n + 1 > sizeof buf)
        continue;
      buf[0] = 0;
      for (i = 0; i < n; i++)
        {
          unsigned v;

          sscanf (seeds[k] + 2 * i, "%2x", &v);
          buf[1 + i] = (uint8_t) v;
        }
      add (buf, n + 1);
    }
}

static unsigned take;

static size_t
on_data (void *u, enum twist_smb_data kind, const uint8_t *p, size_t n)
{
  size_t i;

  (void) u;
  (void) kind;
  if (take != 0 && n > take)
    n = take;
  for (i = 0; i < n; i++)
    fuzz_sunk += p[i];
  return n;
}

static int
on_entry (void *u, const uint8_t *p, size_t n)
{
  size_t i;

  (void) u;
  for (i = 0; i < n; i++)
    fuzz_sunk += p[i];
  return TWIST_OK;
}

static int
on_context (void *u, const struct twist_smb_context *c)
{
  size_t i;

  (void) u;
  for (i = 0; i < c->len; i++)
    fuzz_sunk += c->data[i];
  return TWIST_OK;
}

int
LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
  struct twist_smb_events ev;
  struct twist_smb_parser *p;
  size_t piece, off = 0, stuck = 0;

  if (size == 0)
    return 0;
  memset (&ev, 0, sizeof ev);
  ev.data = on_data;
  ev.entry = on_entry;
  ev.context = on_context;
  p = twist_smb_parser_new (&ev);
  if (p == NULL)
    abort ();
  piece = (size_t) (data[0] & 0x3f) + 1;
  take = (data[0] & 0x40) != 0 ? 3 : 0;
  twist_smb_parser_set_limit (p, 4096);
  if ((data[0] & 0x80) != 0)
    twist_smb_parser_message (p, data + 1, size - 1);
  else
    while (off + 1 < size && stuck < 4)
      {
        size_t c = size - 1 - off < piece ? size - 1 - off : piece;
        size_t used = twist_smb_parser_receive (p, data + 1 + off, c);

        off += used;
        stuck = used == 0 ? stuck + 1 : 0;
      }
  twist_smb_parser_free (p);
  return 0;
}
