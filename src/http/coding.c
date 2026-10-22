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

#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <zlib.h>

#ifdef HAVE_BROTLI
# include <brotli/decode.h>
# include <brotli/encode.h>
#endif

/* gzip and deflate, and br when libbrotli is built in (it is optional).  A
   coding is a name in coding_kind and does not change the HTTP caller.  */

#define KIND_GZIP 1
#define KIND_DEFLATE 2
#define KIND_BROTLI 3

/* What a request body is coded with when it is: the quality and window of the
   encoder.  Quality 11 is for files that are compressed once and sent many
   times, and is too slow here; 5 is the balance for a reactor.  The window is
   4 MiB, well within the 16 MiB that br allows a decoder to be asked for.  */
#define BROTLI_QUALITY 5
#define BROTLI_LGWIN 22

struct twist_coding
{
  z_stream strm;
  int inited;
  int kind;
  int raw;
  int started;
  int ended;
#ifdef HAVE_BROTLI
  BrotliDecoderState *br;
#endif
};

static int
coding_kind (const char *name)
{
  if (name == NULL)
    return 0;
  if (strcasecmp (name, "gzip") == 0 || strcasecmp (name, "x-gzip") == 0)
    return KIND_GZIP;
  if (strcasecmp (name, "deflate") == 0)
    return KIND_DEFLATE;
#ifdef HAVE_BROTLI
  if (strcasecmp (name, "br") == 0)
    return KIND_BROTLI;
#endif
  return 0;
}

int
twist_coding_known (const char *name)
{
  return coding_kind (name) != 0;
}

static int
decoder_init (struct twist_coding *c, int window)
{
  int z;

  memset (&c->strm, 0, sizeof c->strm);
  z = inflateInit2 (&c->strm, window);
  if (z != Z_OK)
    return z == Z_MEM_ERROR ? TWIST_ERR_NOMEM : TWIST_ERR_ENCODING;
  c->inited = 1;
  return TWIST_OK;
}

int
twist_coding_open (struct twist_coding **out, const char *name)
{
  struct twist_coding *c;
  int kind;
  int window;
  int rc;

  if (out == NULL)
    return TWIST_ERR_INVAL;
  *out = NULL;
  kind = coding_kind (name);
  if (kind == 0)
    return TWIST_ERR_ENCODING;
  c = calloc (1, sizeof *c);
  if (c == NULL)
    return TWIST_ERR_NOMEM;
  c->kind = kind;
#ifdef HAVE_BROTLI
  if (kind == KIND_BROTLI)
    {
      /* The large-window extension is not set, so a stream that asks for a
         window above 16 MiB is refused.  */
      c->br = BrotliDecoderCreateInstance (NULL, NULL, NULL);
      if (c->br == NULL)
        {
          free (c);
          return TWIST_ERR_NOMEM;
        }
      c->inited = 1;
      *out = c;
      return TWIST_OK;
    }
#endif
  window = kind == KIND_GZIP ? 16 + MAX_WBITS : MAX_WBITS;
  rc = decoder_init (c, window);
  if (rc != TWIST_OK)
    {
      free (c);
      return rc;
    }
  *out = c;
  return TWIST_OK;
}

/* Hand one piece of decoded output to the sink.  */
static int
emit (twist_coding_sink sink, void *user, const uint8_t *buf, size_t n)
{
  if (n == 0)
    return TWIST_OK;
  return sink (user, buf, n) != 0 ? TWIST_ERR_ABORTED : TWIST_OK;
}

/* Inflate IN, N bytes, handing the output on in pieces of no more than
   TWIST_CODING_PIECE as it is produced.  Nothing is accumulated: what a
   small input expands to (a thousand to one) is never held, only passed on,
   so memory does not depend on what the peer sends.  */
static int
inflate_chunk (struct twist_coding *c, const uint8_t *in, size_t n,
               twist_coding_sink sink, void *user)
{
  uint8_t buf[TWIST_CODING_PIECE];
  size_t delivered = 0;
  /* zlib reads its input and does not write it, but takes it as non-const.  */
  union { const uint8_t *in; Bytef *zin; } src;

  src.in = in;
  c->strm.next_in = src.zin;
  c->strm.avail_in = (uInt) n;
  for (;;)
    {
      size_t produced;
      int z;
      int rc;

      c->strm.next_out = buf;
      c->strm.avail_out = sizeof buf;
      z = inflate (&c->strm, Z_NO_FLUSH);
      produced = sizeof buf - c->strm.avail_out;
      if (z == Z_DATA_ERROR && c->kind == 2 && !c->raw && !c->started
          && delivered == 0 && produced == 0)
        {
          /* deflate that has no zlib header is raw: once, from the start.  */
          inflateEnd (&c->strm);
          c->inited = 0;
          if (decoder_init (c, -MAX_WBITS) != TWIST_OK)
            return TWIST_ERR_ENCODING;
          c->raw = 1;
          c->strm.next_in = src.zin;
          c->strm.avail_in = (uInt) n;
          continue;
        }
      rc = emit (sink, user, buf, produced);
      if (rc != TWIST_OK)
        return rc;
      delivered += produced;
      if (z == Z_STREAM_END)
        {
          c->ended = 1;
          break;
        }
      if (z == Z_OK)
        {
          /* Output that filled the piece exactly may leave more behind.  */
          if (c->strm.avail_in == 0 && c->strm.avail_out != 0)
            break;
          continue;
        }
      if (z == Z_BUF_ERROR && c->strm.avail_in == 0)
        break;
      return z == Z_MEM_ERROR ? TWIST_ERR_NOMEM : TWIST_ERR_ENCODING;
    }
  c->started = 1;
  return TWIST_OK;
}

#ifdef HAVE_BROTLI
/* The error of a Brotli decoder that stopped: out of memory is that, and the
   rest is a stream that is not Brotli.  */
static int
brotli_error (const BrotliDecoderState *st)
{
  switch (BrotliDecoderGetErrorCode (st))
    {
    case BROTLI_DECODER_ERROR_ALLOC_CONTEXT_MODES:
    case BROTLI_DECODER_ERROR_ALLOC_TREE_GROUPS:
    case BROTLI_DECODER_ERROR_ALLOC_CONTEXT_MAP:
    case BROTLI_DECODER_ERROR_ALLOC_RING_BUFFER_1:
    case BROTLI_DECODER_ERROR_ALLOC_RING_BUFFER_2:
    case BROTLI_DECODER_ERROR_ALLOC_BLOCK_TYPE_TREES:
      return TWIST_ERR_NOMEM;
    default:
      return TWIST_ERR_ENCODING;
    }
}

/* Decode IN, N bytes, as inflate_chunk does: the output goes on in pieces of
   no more than TWIST_CODING_PIECE as it is produced, and nothing is held.
   The decoder resumes inside a symbol, so the input can be cut anywhere.  It
   is not finished until it says so; bytes after its end are an error.  */
static int
brotli_chunk (struct twist_coding *c, const uint8_t *in, size_t n,
              twist_coding_sink sink, void *user)
{
  uint8_t buf[TWIST_CODING_PIECE];
  const uint8_t *next_in = in;
  size_t avail_in = n;

  for (;;)
    {
      uint8_t *next_out = buf;
      size_t avail_out = sizeof buf;
      BrotliDecoderResult r;
      int rc;

      r = BrotliDecoderDecompressStream (c->br, &avail_in, &next_in,
                                         &avail_out, &next_out, NULL);
      rc = emit (sink, user, buf, sizeof buf - avail_out);
      if (rc != TWIST_OK)
        return rc;
      switch (r)
        {
        case BROTLI_DECODER_RESULT_SUCCESS:
          c->ended = 1;
          return avail_in == 0 ? TWIST_OK : TWIST_ERR_ENCODING;
        case BROTLI_DECODER_RESULT_NEEDS_MORE_INPUT:
          c->started = 1;
          return TWIST_OK;
        case BROTLI_DECODER_RESULT_NEEDS_MORE_OUTPUT:
          break;
        default:
          return brotli_error (c->br);
        }
    }
}
#endif

int
twist_coding_feed (struct twist_coding *c, const uint8_t *data, size_t len,
                   twist_coding_sink sink, void *user)
{
  if (c == NULL || sink == NULL)
    return TWIST_ERR_INVAL;
  if (!c->inited)
    return TWIST_ERR_ENCODING;
  if (c->ended)
    return len == 0 ? TWIST_OK : TWIST_ERR_ENCODING;
  if (len > (size_t) ~0u)
    return TWIST_ERR_ENCODING;
  if (len == 0)
    return TWIST_OK;
#ifdef HAVE_BROTLI
  if (c->kind == KIND_BROTLI)
    return brotli_chunk (c, data, len, sink, user);
#endif
  return inflate_chunk (c, data, len, sink, user);
}

int
twist_coding_finish (struct twist_coding *c, twist_coding_sink sink,
                     void *user)
{
  uint8_t buf[TWIST_CODING_PIECE];
  uint8_t empty;

  if (c == NULL || sink == NULL)
    return TWIST_ERR_INVAL;
  if (!c->inited)
    return TWIST_ERR_ENCODING;
  if (c->ended)
    return TWIST_OK;
  /* Whatever the decoder had was delivered when it asked for more input, so
     what is not ended now is a stream cut short.  */
  if (c->kind == KIND_BROTLI)
    return TWIST_ERR_ENCODING;
  c->strm.next_in = &empty;
  c->strm.avail_in = 0;
  for (;;)
    {
      size_t produced;
      int z;
      int rc;

      c->strm.next_out = buf;
      c->strm.avail_out = sizeof buf;
      z = inflate (&c->strm, Z_FINISH);
      produced = sizeof buf - c->strm.avail_out;
      rc = emit (sink, user, buf, produced);
      if (rc != TWIST_OK)
        return rc;
      if (z == Z_STREAM_END)
        {
          c->ended = 1;
          return TWIST_OK;
        }
      /* Output that filled the piece may leave more.  Otherwise, with no
         input left and no end, the body was cut short.  */
      if (z == Z_OK || (z == Z_BUF_ERROR && c->strm.avail_out == 0))
        continue;
      return z == Z_MEM_ERROR ? TWIST_ERR_NOMEM : TWIST_ERR_ENCODING;
    }
}

void
twist_coding_free (struct twist_coding *c)
{
  if (c == NULL)
    return;
#ifdef HAVE_BROTLI
  if (c->kind == KIND_BROTLI)
    BrotliDecoderDestroyInstance (c->br);
  else
#endif
  if (c->inited)
    inflateEnd (&c->strm);
  free (c);
}

int
twist_coding_encode (const char *name, const uint8_t *data, size_t len,
                     uint8_t **out, size_t *out_n)
{
  z_stream strm;
  int kind;
  int window;
  int z;
  uLong bound;
  uint8_t *buf;
  uint8_t *copy = NULL;
  uint8_t empty_in = 0;

  if (out == NULL || out_n == NULL)
    return TWIST_ERR_INVAL;
  *out = NULL;
  *out_n = 0;
  kind = coding_kind (name);
  if (kind == 0)
    return TWIST_ERR_UNSUPPORTED;
#ifdef HAVE_BROTLI
  if (kind == KIND_BROTLI)
    {
      /* One call: a request body is in memory, and is coded as a whole.  */
      size_t cap = BrotliEncoderMaxCompressedSize (len);
      size_t got;
      uint8_t empty_br = 0;
      uint8_t *obuf;

      if (cap == 0)
        return TWIST_ERR_ENCODING;
      obuf = twist_xmalloc (cap);
      if (obuf == NULL)
        return TWIST_ERR_NOMEM;
      got = cap;
      if (!BrotliEncoderCompress (BROTLI_QUALITY, BROTLI_LGWIN,
                                  BROTLI_MODE_GENERIC, len,
                                  len > 0 ? data : &empty_br, &got, obuf))
        {
          free (obuf);
          return TWIST_ERR_ENCODING;
        }
      *out = obuf;
      *out_n = got;
      return TWIST_OK;
    }
#endif
  if (len > (size_t) ~0u)
    return TWIST_ERR_ENCODING;
  window = kind == KIND_GZIP ? 16 + MAX_WBITS : MAX_WBITS;
  memset (&strm, 0, sizeof strm);
  z = deflateInit2 (&strm, Z_DEFAULT_COMPRESSION, Z_DEFLATED, window, 8,
                    Z_DEFAULT_STRATEGY);
  if (z != Z_OK)
    return z == Z_MEM_ERROR ? TWIST_ERR_NOMEM : TWIST_ERR_ENCODING;
  bound = deflateBound (&strm, (uLong) len);
  if (bound > (uLong) ~0u)
    {
      deflateEnd (&strm);
      return TWIST_ERR_ENCODING;
    }
  buf = twist_xmalloc (bound > 0 ? (size_t) bound : 1);
  if (buf == NULL)
    {
      deflateEnd (&strm);
      return TWIST_ERR_NOMEM;
    }
  if (len > 0)
    {
      copy = twist_xmalloc (len);
      if (copy == NULL)
        {
          free (buf);
          deflateEnd (&strm);
          return TWIST_ERR_NOMEM;
        }
      memcpy (copy, data, len);
    }
  strm.next_in = copy != NULL ? copy : &empty_in;
  strm.avail_in = (uInt) len;
  strm.next_out = buf;
  strm.avail_out = (uInt) bound;
  z = deflate (&strm, Z_FINISH);
  *out_n = (size_t) strm.total_out;
  deflateEnd (&strm);
  free (copy);
  if (z != Z_STREAM_END)
    {
      free (buf);
      return z == Z_MEM_ERROR ? TWIST_ERR_NOMEM : TWIST_ERR_ENCODING;
    }
  *out = buf;
  return TWIST_OK;
}
