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

/* Content codings: gzip and deflate (and any other that is known), fed in
   pieces.  The first byte picks the coding and the size of the pieces.  */

static const char *const names[] = { "gzip", "deflate", "x-gzip", "identity" };

void
fuzz_seeds (void (*add) (const void *, size_t))
{
  uint8_t *gz = NULL, *df = NULL;
  size_t gn = 0, dn = 0;
  uint8_t *seed;

  if (twist_coding_encode ("gzip", (const uint8_t *) "hello hello hello", 17,
                           &gz, &gn) == TWIST_OK)
    {
      seed = malloc (gn + 1);
      seed[0] = 0x00;
      memcpy (seed + 1, gz, gn);
      add (seed, gn + 1);
      free (seed);
      free (gz);
    }
  if (twist_coding_encode ("deflate", (const uint8_t *) "abcabcabcabc", 12,
                           &df, &dn) == TWIST_OK)
    {
      seed = malloc (dn + 1);
      seed[0] = 0x05;
      memcpy (seed + 1, df, dn);
      add (seed, dn + 1);
      free (seed);
      free (df);
    }
}

/* The decoded data is dropped, but each piece is checked to be no larger than
   promised, and to be there.  */
static int
drop (void *user, const uint8_t *data, size_t len)
{
  (void) user;
  if (len == 0 || len > TWIST_CODING_PIECE || data == NULL)
    abort ();
  /* Read it all, so that the sanitizers see a piece that is not whole.  */
  return data[0] + data[len - 1] < 0;
}

int
LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
  struct twist_coding *c = NULL;
  size_t piece, off = 0;

  if (size == 0)
    return 0;
  if (twist_coding_open (&c, names[(data[0] >> 4) & 3]) != TWIST_OK)
    return 0;
  piece = fuzz_piece (data[0], size);
  data++;
  size--;
  while (off < size)
    {
      size_t take = piece < size - off ? piece : size - off;

      if (twist_coding_feed (c, data + off, take, drop, NULL) != TWIST_OK)
        break;
      off += take;
    }
  twist_coding_finish (c, drop, NULL);
  twist_coding_free (c);
  return 0;
}
