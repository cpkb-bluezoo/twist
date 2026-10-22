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

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include "twist-int.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <zlib.h>

static int failed;

static void
check (int cond, const char *what)
{
  if (!cond)
    {
      fprintf (stderr, "FAIL %s\n", what);
      failed = 1;
    }
}

/* What a sink was given: the bytes, for those tests that want them, and the
   largest piece and the count, for the one that wants those.  */
struct got
{
  uint8_t *data;
  size_t n;
  size_t cap;
  size_t biggest;
  size_t total;
  int keep;
  int stop_after;
  int calls;
};

static int
collect (void *user, const uint8_t *data, size_t len)
{
  struct got *g = user;

  g->calls++;
  g->total += len;
  if (len > g->biggest)
    g->biggest = len;
  if (g->keep)
    {
      if (g->n + len > g->cap)
        {
          size_t cap = (g->n + len) * 2;
          uint8_t *grown = realloc (g->data, cap);

          if (grown == NULL)
            abort ();
          g->data = grown;
          g->cap = cap;
        }
      memcpy (g->data + g->n, data, len);
      g->n += len;
    }
  return g->stop_after > 0 && g->calls >= g->stop_after;
}

static void
round_trip (const char *name, const char *text)
{
  uint8_t *enc = NULL;
  size_t en = 0;
  struct twist_coding *c = NULL;
  struct got g;
  size_t i;

  memset (&g, 0, sizeof g);
  g.keep = 1;
  check (twist_coding_encode (name, (const uint8_t *) text, strlen (text),
                              &enc, &en) == TWIST_OK, "encode");
  check (enc != NULL && en > 0, "encoded bytes");
  check (twist_coding_open (&c, name) == TWIST_OK, "open");
  for (i = 0; enc != NULL && i < en; i++)
    check (twist_coding_feed (c, enc + i, 1, collect, &g) == TWIST_OK,
           "feed byte");
  check (twist_coding_finish (c, collect, &g) == TWIST_OK, "finish");
  check (g.n == strlen (text)
         && (g.n == 0 || (g.data != NULL && memcmp (g.data, text, g.n) == 0)),
         "round trip");
  free (g.data);
  free (enc);
  twist_coding_free (c);
}

static void
test_raw_deflate (void)
{
  z_stream strm;
  uint8_t raw[64];
  uint8_t text[] = "raw-deflate";
  struct twist_coding *c = NULL;
  struct got g;
  int z;

  memset (&g, 0, sizeof g);
  g.keep = 1;
  memset (&strm, 0, sizeof strm);
  z = deflateInit2 (&strm, Z_DEFAULT_COMPRESSION, Z_DEFLATED, -MAX_WBITS, 8,
                    Z_DEFAULT_STRATEGY);
  check (z == Z_OK, "raw init");
  strm.next_in = text;
  strm.avail_in = (uInt) (sizeof text - 1);
  strm.next_out = raw;
  strm.avail_out = sizeof raw;
  z = deflate (&strm, Z_FINISH);
  check (z == Z_STREAM_END, "raw finish");
  check (twist_coding_open (&c, "deflate") == TWIST_OK, "open deflate");
  check (twist_coding_feed (c, raw, (size_t) strm.total_out, collect, &g)
         == TWIST_OK, "feed raw");
  check (twist_coding_finish (c, collect, &g) == TWIST_OK, "finish raw");
  check (g.n == sizeof text - 1 && memcmp (g.data, text, g.n) == 0,
         "raw bytes");
  deflateEnd (&strm);
  free (g.data);
  twist_coding_free (c);
}

static void
test_truncated (void)
{
  uint8_t *enc = NULL;
  size_t en = 0;
  struct twist_coding *c = NULL;
  struct got g;
  const char *text = "truncated-gzip-body";

  memset (&g, 0, sizeof g);
  check (twist_coding_encode ("gzip", (const uint8_t *) text, strlen (text),
                              &enc, &en) == TWIST_OK, "gzip encode");
  check (en > 4, "gzip long enough");
  check (twist_coding_open (&c, "gzip") == TWIST_OK, "gzip open");
  check (twist_coding_feed (c, enc, en / 2, collect, &g) == TWIST_OK,
         "gzip prefix");
  check (twist_coding_finish (c, collect, &g) == TWIST_ERR_ENCODING,
         "truncated gzip");
  check (twist_coding_known ("gzip") && twist_coding_known ("deflate")
         && twist_coding_known ("x-gzip") && !twist_coding_known ("br"),
         "known codings");
  check (twist_strerror (TWIST_ERR_ENCODING)[0] != 0, "encoding string");
  free (enc);
  twist_coding_free (c);
}

/* A small input that inflates to a great deal (about 1000 to 1) must not
   make the decoder hold the great deal at once.  Memory is to be in
   proportion to what is in flight, not to what the peer's data expands to,
   so the output comes in pieces of a bounded size, as it is produced: here
   all 32 MiB of it, none of the pieces more than TWIST_CODING_PIECE.  It was
   one buffer of the whole expansion for each chunk received.  */
static void
test_coding_bomb (void)
{
  const size_t plain_n = 32u * 1024 * 1024;
  uint8_t *plain = calloc (1, plain_n);
  uint8_t *enc = NULL;
  size_t en = 0;
  struct twist_coding *c = NULL;
  struct got g;

  memset (&g, 0, sizeof g);
  check (plain != NULL, "bomb buffer");
  check (twist_coding_encode ("gzip", plain, plain_n, &enc, &en) == TWIST_OK
         && en < 200000, "a 32 MiB bomb of zeros is small");
  check (twist_coding_open (&c, "gzip") == TWIST_OK, "open");
  check (twist_coding_feed (c, enc, en, collect, &g) == TWIST_OK, "feed");
  check (g.biggest <= TWIST_CODING_PIECE,
         "no piece is larger than the bound");
  check (twist_coding_finish (c, collect, &g) == TWIST_OK, "finish");
  check (g.total == plain_n, "and all of it arrives");
  twist_coding_free (c);

  /* Fed in small pieces, the same.  */
  memset (&g, 0, sizeof g);
  check (twist_coding_open (&c, "gzip") == TWIST_OK, "open again");
  {
    size_t off = 0;

    while (off < en)
      {
        size_t take = en - off < 997 ? en - off : 997;

        if (twist_coding_feed (c, enc + off, take, collect, &g) != TWIST_OK)
          break;
        off += take;
      }
    check (off == en, "fed in pieces");
  }
  check (twist_coding_finish (c, collect, &g) == TWIST_OK
         && g.total == plain_n && g.biggest <= TWIST_CODING_PIECE,
         "bounded, and whole, in pieces too");
  twist_coding_free (c);

  /* A sink that says stop stops it.  */
  memset (&g, 0, sizeof g);
  g.stop_after = 3;
  check (twist_coding_open (&c, "gzip") == TWIST_OK, "open a third time");
  check (twist_coding_feed (c, enc, en, collect, &g) == TWIST_ERR_ABORTED
         && g.calls == 3, "a sink that stops it, stops it");
  twist_coding_free (c);
  free (enc);
  free (plain);
}

int
main (void)
{
  round_trip ("gzip", "hello");
  round_trip ("deflate", "hello deflate");
  round_trip ("x-gzip", "");
  test_raw_deflate ();
  test_truncated ();
  test_coding_bomb ();
  return failed ? 1 : 0;
}
