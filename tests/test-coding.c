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
         && twist_coding_known ("x-gzip"), "known codings");
#ifdef HAVE_BROTLI
  check (twist_coding_known ("br"), "br is known when libbrotli is built in");
#else
  check (!twist_coding_known ("br"), "and is not when it is not");
#endif
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

/* Brotli, when it is built in (libbrotli is optional).  The vectors were made
   by libbrotlienc on its own, so that the decoder is tried on bytes that did
   not come through twist's encoder.  */
static const uint8_t br_hello[] = {
  0x1b, 0x38, 0x00, 0x00, 0x44, 0x77, 0xf8, 0xf7, 0x5c, 0xf3, 0xf7, 0x5e,
  0x8b, 0x88, 0x32, 0x52, 0xb0, 0x01, 0x07, 0x0e, 0x59, 0xac, 0x99, 0x0c,
  0x3c, 0x4c, 0xe4, 0x30, 0xc0, 0xb6, 0xe0, 0x20, 0x67, 0xd3, 0x01, 0x36,
  0x57, 0xd7, 0xe5, 0x27, 0x18, 0x31, 0x1e, 0x62, 0x7f, 0x08, 0x25, 0xd8,
  0xa0, 0x01,
};
/* br_hello: 50 bytes */

static const uint8_t br_empty[] = {
  0x06,
};
/* br_empty: 1 bytes */

static const uint8_t br_zeros_64m[] = {
  0xcf, 0xff, 0xff, 0x7f, 0x00, 0x24, 0x00, 0xe2, 0xb1, 0x40, 0x72, 0xef,
  0xff, 0xf9, 0xff, 0xff, 0x0f, 0x80, 0x04, 0x40, 0x1c, 0x16, 0x80, 0xee,
  0xfd, 0x3f, 0xff, 0xff, 0xff, 0x01, 0x90, 0x00, 0x88, 0xc3, 0x02, 0xd0,
  0xbd, 0xff, 0xcf, 0xff, 0xff, 0x7f, 0x00, 0x12, 0x00, 0x71, 0x58, 0x00,
  0xba, 0xf7, 0xff,
};
/* br_zeros_64m: 51 bytes */

static const uint8_t br_large_window[] = {
  0x11, 0x5a, 0xe0, 0x00, 0x00, 0x10, 0xdd, 0xe1, 0xdf, 0x73, 0xcd, 0xdf,
  0x7b, 0x2d, 0x22, 0xca, 0x48, 0xc1, 0x06, 0x1c, 0x38, 0x64, 0xb1, 0x66,
  0x32, 0xf0, 0x30, 0x91, 0xc3, 0x00, 0xdb, 0x82, 0x83, 0x9c, 0x4d, 0x07,
  0xd8, 0x5c, 0x5d, 0x97, 0x9f, 0x60, 0xc4, 0x78, 0x88, 0xfd, 0x21, 0x94,
  0x60, 0x83, 0x06,
};
/* br_large_window: 51 bytes */


static const char br_hello_text[] =
  "hello hello hello hello brotli, the small crumb of bread\n";

static int
feed_all_in (const char *name, const uint8_t *enc, size_t en, size_t step,
             struct got *g, int *finished)
{
  struct twist_coding *c = NULL;
  size_t off = 0;
  int rc = TWIST_OK;

  if (twist_coding_open (&c, name) != TWIST_OK)
    return TWIST_ERR_ENCODING;
  while (off < en && rc == TWIST_OK)
    {
      size_t take = en - off < step ? en - off : step;

      rc = twist_coding_feed (c, enc + off, take, collect, g);
      off += take;
    }
  if (rc == TWIST_OK)
    rc = twist_coding_finish (c, collect, g);
  *finished = rc == TWIST_OK;
  twist_coding_free (c);
  return rc;
}

static void
test_brotli (void)
{
  const size_t hello_n = sizeof br_hello_text - 1;
  uint8_t *enc = NULL;
  size_t en = 0;
  struct got g;
  size_t step;
  int fin;
  int rc;

  if (!twist_coding_known ("br"))
    return;

  /* Bytes that came from elsewhere decode, in pieces of any size.  */
  for (step = 1; step <= sizeof br_hello + 1; step++)
    {
      memset (&g, 0, sizeof g);
      g.keep = 1;
      rc = feed_all_in ("br", br_hello, sizeof br_hello, step, &g, &fin);
      check (rc == TWIST_OK && g.n == hello_n
             && memcmp (g.data, br_hello_text, hello_n) == 0,
             "the stream of libbrotlienc decodes, whatever the pieces");
      free (g.data);
    }
  memset (&g, 0, sizeof g);
  rc = feed_all_in ("br", br_empty, sizeof br_empty, 1, &g, &fin);
  check (rc == TWIST_OK && g.total == 0, "an empty stream is empty");

  /* The coding is case-insensitive in its name, as the others are.  */
  check (twist_coding_known ("BR"), "BR is br");

  /* Our own encoder's output decodes: text, nothing, and a lot of it.  */
  round_trip ("br", "hello brotli");
  round_trip ("br", "");
  {
    size_t n = 300000;
    uint8_t *plain = malloc (n);
    uint32_t x = 12345;
    size_t i;

    check (plain != NULL, "a body");
    for (i = 0; i < n; i++)
      {
        /* Words, so that the static dictionary and copies are both used,
           with some noise.  */
        x = x * 1103515245u + 12345u;
        plain[i] = (i % 7 < 5) ? (uint8_t) "the quick brown fox jumps over"[i % 30]
                               : (uint8_t) (x >> 16);
      }
    check (twist_coding_encode ("br", plain, n, &enc, &en) == TWIST_OK
           && en > 0 && en < n, "encode a body");
    for (step = 1; step <= 4099; step = step * 3 + 1)
      {
        memset (&g, 0, sizeof g);
        g.keep = 1;
        rc = feed_all_in ("br", enc, en, step, &g, &fin);
        check (rc == TWIST_OK && g.n == n && memcmp (g.data, plain, n) == 0,
               "a body in pieces of one size is the body");
        free (g.data);
      }
    free (enc);
    free (plain);
  }

  /* What is not a whole stream.  */
  memset (&g, 0, sizeof g);
  rc = feed_all_in ("br", br_hello, sizeof br_hello / 2, 5, &g, &fin);
  check (rc == TWIST_ERR_ENCODING, "a stream cut short is an encoding error");
  {
    uint8_t junk[sizeof br_hello + 3];

    memcpy (junk, br_hello, sizeof br_hello);
    memcpy (junk + sizeof br_hello, "xyz", 3);
    memset (&g, 0, sizeof g);
    rc = feed_all_in ("br", junk, sizeof junk, sizeof junk, &g, &fin);
    check (rc == TWIST_ERR_ENCODING, "bytes after the end are an error");
    memset (&g, 0, sizeof g);
    rc = feed_all_in ("br", junk, sizeof junk, 1, &g, &fin);
    check (rc == TWIST_ERR_ENCODING, "also when they come after it is over");
  }
  {
    uint8_t bad[sizeof br_hello];

    memcpy (bad, br_hello, sizeof bad);
    memset (bad + 2, 0xff, sizeof bad - 2);
    memset (&g, 0, sizeof g);
    rc = feed_all_in ("br", bad, sizeof bad, 7, &g, &fin);
    check (rc == TWIST_ERR_ENCODING, "a corrupt stream is an encoding error");
  }
  /* The window of large-window Brotli (a window above 16 MiB) is not HTTP's
     br, and would let a peer ask for a gigabyte.  */
  memset (&g, 0, sizeof g);
  rc = feed_all_in ("br", br_large_window, sizeof br_large_window, 3, &g, &fin);
  check (rc == TWIST_ERR_ENCODING, "a large-window stream is refused");

  /* 64 MiB from 51 bytes: the output is passed on in bounded pieces and is not
     held.  */
  memset (&g, 0, sizeof g);
  rc = feed_all_in ("br", br_zeros_64m, sizeof br_zeros_64m, 11, &g, &fin);
  check (rc == TWIST_OK && g.total == 64u * 1024 * 1024
         && g.biggest <= TWIST_CODING_PIECE,
         "a 64 MiB bomb arrives whole, in pieces of a bounded size");
  {
    struct twist_coding *c = NULL;

    memset (&g, 0, sizeof g);
    g.stop_after = 3;
    check (twist_coding_open (&c, "br") == TWIST_OK, "open br");
    check (twist_coding_feed (c, br_zeros_64m, sizeof br_zeros_64m, collect,
                              &g) == TWIST_ERR_ABORTED && g.calls == 3,
           "a sink that stops it, stops it");
    twist_coding_free (c);
  }
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
  test_brotli ();
  return failed ? 1 : 0;
}
