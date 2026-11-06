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

/* The SMB 3.1.1 session layer fed as a server: after the client has started,
   the input is what the server sends.  The first byte picks the size of the
   pieces.  Nothing a fuzzer makes will have a good tag or signature, so this
   reaches the negotiate and session setup phases, the framing, the profile
   checks and the refusals.  */

const char *const fuzz_tokens[] = {
  "\\xfe" "SMB", "\\xfd" "SMB", "\\x00\\x00", "\\x11\\x03", "\\x01\\x00", "\\x02\\x00",
  "\\x16\\x00\\x00\\xc0", NULL
};

static const char *const seeds[] = {
  "000000d4fe534d42400001000000000000001f000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004100030011030300a0a1a2a3a4a5a6a7a8a9aaabacadaeaf44000000000001000000010000000100010000000000000002000000000000008000040088000000414243440000000001002600000000000100200001005a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a000002000400000000000100020000000000080004000000000001000100",
  "000000d4fe534d42400001000000000000001f000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004100030011030300a0a1a2a3a4a5a6a7a8a9aaabacadaeaf44000000000001000000010000000100010000000000000002000000000000008000040088000000414243440000000001002600000000000100200001005a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a0000020004000000000001000200000000000800040000000000010001000000004dfe534d4240000100160000c001001f000100000000000000010000000000000000000000000000008877665544332211000000000000000000000000000000000900000048000500544f4b454e",
};

void
fuzz_seeds (void (*add) (const void *, size_t))
{
  size_t k;

  for (k = 0; k < sizeof seeds / sizeof seeds[0]; k++)
    {
      uint8_t buf[800];
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

static int
fill (void *u, void *buf, size_t len)
{
  (void) u;
  memset (buf, 0x33, len);
  return 0;
}

static int
send_sink (void *u, const uint8_t *d, size_t n)
{
  size_t i;

  (void) u;
  for (i = 0; i < n; i++)
    fuzz_sunk += d[i];
  return TWIST_OK;
}

int
LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
  struct twist_smb_session_ops ops;
  struct twist_smb_session_config cfg;
  struct twist_ntlm_rand rnd = { fill, NULL };
  struct twist_smb_session *s;
  size_t piece, off = 0, stuck = 0;

  if (size == 0)
    return 0;
  memset (&ops, 0, sizeof ops);
  ops.send = send_sink;
  memset (&cfg, 0, sizeof cfg);
  cfg.domain = "D";
  cfg.user = "u";
  cfg.password = "p";
  cfg.host = "h";
  cfg.share = "s";
  cfg.rnd = &rnd;
  s = twist_smb_session_new (&cfg, &ops, NULL);
  if (s == NULL)
    abort ();
  twist_smb_session_start (s);
  piece = (size_t) (data[0] & 0x7f) + 1;
  while (off + 1 < size && stuck < 4)
    {
      size_t c = size - 1 - off < piece ? size - 1 - off : piece;
      size_t used = twist_smb_session_receive (s, data + 1 + off, c);

      off += used;
      stuck = used == 0 ? stuck + 1 : 0;
    }
  twist_smb_session_free (s);
  return 0;
}
