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

static void
round_trip (const char *name, const char *text)
{
  uint8_t *enc = NULL;
  size_t en = 0;
  struct twist_coding *c = NULL;
  uint8_t *plain = NULL;
  size_t pn = 0;
  uint8_t *tail = NULL;
  size_t tn = 0;
  size_t i;

  check (twist_coding_encode (name, (const uint8_t *) text, strlen (text),
                              &enc, &en) == TWIST_OK, "encode");
  check (enc != NULL && en > 0, "encoded bytes");
  check (twist_coding_open (&c, name) == TWIST_OK, "open");
  for (i = 0; enc != NULL && i < en; i++)
    {
      uint8_t *part = NULL;
      size_t part_n = 0;

      check (twist_coding_feed (c, enc + i, 1, &part, &part_n) == TWIST_OK,
             "feed byte");
      if (part_n > 0)
        {
          uint8_t *grown = realloc (plain, pn + part_n);

          check (grown != NULL, "grow plain");
          if (grown != NULL)
            {
              memcpy (grown + pn, part, part_n);
              plain = grown;
              pn += part_n;
            }
        }
      free (part);
    }
  check (twist_coding_finish (c, &tail, &tn) == TWIST_OK, "finish");
  if (tn > 0)
    {
      uint8_t *grown = realloc (plain, pn + tn);

      check (grown != NULL, "grow tail");
      if (grown != NULL)
        {
          memcpy (grown + pn, tail, tn);
          plain = grown;
          pn += tn;
        }
    }
  check (pn == strlen (text)
         && (pn == 0 || (plain != NULL && memcmp (plain, text, pn) == 0)),
         "round trip");
  free (tail);
  free (plain);
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
  uint8_t *plain = NULL;
  size_t pn = 0;
  uint8_t *tail = NULL;
  size_t tn = 0;
  int z;

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
  check (twist_coding_feed (c, raw, (size_t) strm.total_out, &plain, &pn)
         == TWIST_OK, "feed raw");
  check (twist_coding_finish (c, &tail, &tn) == TWIST_OK, "finish raw");
  check (pn + tn == sizeof text - 1, "raw length");
  check ((pn == 0 || memcmp (plain, text, pn) == 0)
         && (tn == 0 || memcmp (tail, text + pn, tn) == 0), "raw bytes");
  deflateEnd (&strm);
  free (plain);
  free (tail);
  twist_coding_free (c);
}

static void
test_truncated (void)
{
  uint8_t *enc = NULL;
  size_t en = 0;
  struct twist_coding *c = NULL;
  uint8_t *plain = NULL;
  size_t pn = 0;
  uint8_t *tail = NULL;
  size_t tn = 0;
  const char *text = "truncated-gzip-body";

  check (twist_coding_encode ("gzip", (const uint8_t *) text, strlen (text),
                              &enc, &en) == TWIST_OK, "gzip encode");
  check (en > 4, "gzip long enough");
  check (twist_coding_open (&c, "gzip") == TWIST_OK, "gzip open");
  check (twist_coding_feed (c, enc, en / 2, &plain, &pn) == TWIST_OK,
         "gzip prefix");
  check (twist_coding_finish (c, &tail, &tn) == TWIST_ERR_ENCODING,
         "truncated gzip");
  check (twist_coding_known ("gzip") && twist_coding_known ("deflate")
         && twist_coding_known ("x-gzip") && !twist_coding_known ("br"),
         "known codings");
  check (twist_strerror (TWIST_ERR_ENCODING)[0] != 0, "encoding string");
  free (plain);
  free (tail);
  free (enc);
  twist_coding_free (c);
}

int
main (void)
{
  round_trip ("gzip", "hello");
  round_trip ("deflate", "hello deflate");
  round_trip ("x-gzip", "");
  test_raw_deflate ();
  test_truncated ();
  return failed ? 1 : 0;
}
