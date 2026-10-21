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

#ifndef TWIST_FUZZ_H
#define TWIST_FUZZ_H

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include "twist-int.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* What a harness defines: the function that takes an input, as for
   libFuzzer; and, if it likes, seeds and a dictionary of tokens.  */
int LLVMFuzzerTestOneInput (const uint8_t *data, size_t size);
void fuzz_seeds (void (*add) (const void *data, size_t n));
extern const char *const fuzz_tokens[];

typedef size_t (*fuzz_recv) (void *obj, const uint8_t *data, size_t len);

/* Where a transfer's body goes: nowhere, but every byte is read.  */
static unsigned long fuzz_sunk;

static inline size_t
fuzz_sink (char *ptr, size_t size, size_t nmemb, void *user)
{
  size_t n = size * nmemb, i;

  (void) user;
  for (i = 0; i < n; i++)
    fuzz_sunk += (unsigned char) ptr[i];
  return n;
}

/* A copy of DATA as a string.  */
static inline char *
fuzz_string (const uint8_t *data, size_t n)
{
  char *s = malloc (n + 1);

  if (s == NULL)
    abort ();
  if (n > 0)
    memcpy (s, data, n);
  s[n] = 0;
  return s;
}

/* The size of the pieces an input is offered in, from a byte of it: all at
   once, one byte at a time, or a few.  */
static inline size_t
fuzz_piece (unsigned b, size_t n)
{
  switch (b & 3)
    {
    case 0:
      return n > 0 ? n : 1;
    case 1:
      return 1;
    case 2:
      return 7;
    default:
      return (size_t) (b >> 2) + 1;
    }
}

/* Offer DATA to RECV as a connection does: in pieces, with what it did not
   take offered again with the next piece.  Each call gets a copy of exactly
   the bytes it is offered, so that a read past them is found.  */
static inline void
fuzz_feed (fuzz_recv recv, void *obj, const uint8_t *data, size_t n,
           size_t piece)
{
  uint8_t *window = malloc (n + 1);
  size_t have = 0, off = 0;

  if (window == NULL)
    abort ();
  for (;;)
    {
      size_t take = piece < n - off ? piece : n - off, used;
      uint8_t *copy;

      memcpy (window + have, data + off, take);
      have += take;
      off += take;
      if (have == 0)
        break;
      copy = malloc (have);
      if (copy == NULL)
        abort ();
      memcpy (copy, window, have);
      used = recv (obj, copy, have);
      free (copy);
      if (used > have)
        used = have;
      memmove (window, window + used, have - used);
      have -= used;
      if (used == 0 && off >= n)
        break;
    }
  free (window);
}

#endif
