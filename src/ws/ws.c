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
#include <sys/random.h>
#include <sys/types.h>

/* Client WebSocket session after the HTTP opening.  Data payload is
   delivered as it arrives.  Control frames stay in a 125-byte buffer.
   Outbound frames are masked, which is what a client must do.  SHA-1
   exists here only for Sec-WebSocket-Accept.  */

#define WS_GUID "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
#define WS_CTRL 125
#define WS_MAX ((size_t) 8 * 1024 * 1024)

enum
{
  WS_B0 = 0,
  WS_B1,
  WS_LEN,
  WS_PAY
};

struct twist_ws
{
  struct twist_easy *easy;
  int (*send) (void *user, const uint8_t *data, size_t len);
  void *send_user;
  void (*done) (void *user, int err);
  void *done_user;
  int step;
  int fin;
  int opcode;
  unsigned len_bits;
  size_t pay_len;
  size_t pay_got;
  int len_left;
  uint8_t ctrl[WS_CTRL];
  int failed;
};

static uint32_t
rol (uint32_t v, int n)
{
  return (v << n) | (v >> (32 - n));
}

static void
sha1_block (uint32_t h[5], const uint8_t block[64])
{
  uint32_t w[80];
  uint32_t a, b, c, d, e;
  int i;

  for (i = 0; i < 16; i++)
    w[i] = ((uint32_t) block[i * 4] << 24)
      | ((uint32_t) block[i * 4 + 1] << 16)
      | ((uint32_t) block[i * 4 + 2] << 8)
      | block[i * 4 + 3];
  for (i = 16; i < 80; i++)
    w[i] = rol (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
  a = h[0];
  b = h[1];
  c = h[2];
  d = h[3];
  e = h[4];
  for (i = 0; i < 80; i++)
    {
      uint32_t f, k, t;

      if (i < 20)
        {
          f = (b & c) | ((~b) & d);
          k = 0x5a827999u;
        }
      else if (i < 40)
        {
          f = b ^ c ^ d;
          k = 0x6ed9eba1u;
        }
      else if (i < 60)
        {
          f = (b & c) | (b & d) | (c & d);
          k = 0x8f1bbcdcu;
        }
      else
        {
          f = b ^ c ^ d;
          k = 0xca62c1d6u;
        }
      t = rol (a, 5) + f + e + k + w[i];
      e = d;
      d = c;
      c = rol (b, 30);
      b = a;
      a = t;
    }
  h[0] += a;
  h[1] += b;
  h[2] += c;
  h[3] += d;
  h[4] += e;
}

static void
sha1 (const uint8_t *msg, size_t len, uint8_t out[20])
{
  uint32_t h[5] = {
    0x67452301u, 0xefcdab89u, 0x98badcfeu, 0x10325476u, 0xc3d2e1f0u
  };
  uint8_t block[64];
  size_t off = 0;
  uint64_t bits = (uint64_t) len * 8;
  int i;

  while (len - off >= 64)
    {
      sha1_block (h, msg + off);
      off += 64;
    }
  memset (block, 0, sizeof block);
  if (len > off)
    memcpy (block, msg + off, len - off);
  block[len - off] = 0x80;
  if (len - off >= 56)
    {
      sha1_block (h, block);
      memset (block, 0, sizeof block);
    }
  for (i = 0; i < 8; i++)
    block[63 - i] = (uint8_t) (bits >> (8 * i));
  sha1_block (h, block);
  for (i = 0; i < 5; i++)
    {
      out[i * 4] = (uint8_t) (h[i] >> 24);
      out[i * 4 + 1] = (uint8_t) (h[i] >> 16);
      out[i * 4 + 2] = (uint8_t) (h[i] >> 8);
      out[i * 4 + 3] = (uint8_t) h[i];
    }
}

int
twist_ws_accept (const char *key, char **out)
{
  char raw[80];
  uint8_t dig[20];
  size_t n;

  if (key == NULL || out == NULL)
    return TWIST_ERR_INVAL;
  n = strlen (key);
  if (n + sizeof WS_GUID > sizeof raw)
    return TWIST_ERR_PROTOCOL;
  memcpy (raw, key, n);
  memcpy (raw + n, WS_GUID, sizeof WS_GUID - 1);
  sha1 ((const uint8_t *) raw, n + sizeof WS_GUID - 1, dig);
  return twist_b64_encode (dig, sizeof dig, out);
}

int
twist_ws_key (char key[25])
{
  uint8_t raw[16];
  char *b64 = NULL;
  ssize_t n;

  if (key == NULL)
    return TWIST_ERR_INVAL;
  n = getrandom (raw, sizeof raw, 0);
  if (n != (ssize_t) sizeof raw)
    return TWIST_ERR_PROTOCOL;
  if (twist_b64_encode (raw, sizeof raw, &b64) != TWIST_OK)
    return TWIST_ERR_NOMEM;
  if (strlen (b64) != 24)
    {
      free (b64);
      return TWIST_ERR_PROTOCOL;
    }
  memcpy (key, b64, 25);
  free (b64);
  return TWIST_OK;
}

static int
token_has (const char *list, const char *token)
{
  size_t n;

  if (list == NULL)
    return 0;
  n = strlen (token);
  while (*list != 0)
    {
      while (*list == ' ' || *list == '\t' || *list == ',')
        list++;
      if (strncasecmp (list, token, n) == 0
          && (list[n] == 0 || list[n] == ',' || list[n] == ' '
              || list[n] == '\t'))
        return 1;
      while (*list != 0 && *list != ',')
        list++;
    }
  return 0;
}

int
twist_ws_validate (const char *key, const char *upgrade,
                   const char *connection, const char *accept)
{
  char *expect = NULL;
  int rc;

  if (!token_has (upgrade, "websocket") || !token_has (connection, "upgrade"))
    return TWIST_ERR_PROTOCOL;
  rc = twist_ws_accept (key, &expect);
  if (rc != TWIST_OK)
    return rc;
  rc = accept != NULL && strcmp (accept, expect) == 0
       ? TWIST_OK : TWIST_ERR_PROTOCOL;
  free (expect);
  return rc;
}

static int
deliver (struct twist_ws *w, const uint8_t *data, size_t len)
{
  struct twist_easy *easy = w->easy;
  size_t off = 0;

  if (easy == NULL || len == 0)
    {
      if (easy != NULL)
        easy->size_download += len;
      return TWIST_OK;
    }
  if (easy->write_cb == NULL)
    {
      easy->size_download += len;
      return TWIST_OK;
    }
  while (off < len)
    {
      char buf[512];
      size_t chunk = len - off;
      size_t n;

      if (chunk > sizeof buf)
        chunk = sizeof buf;
      memcpy (buf, data + off, chunk);
      n = easy->write_cb (buf, 1, chunk, easy->write_data);
      if (n < chunk)
        return TWIST_ERR_ABORTED;
      off += chunk;
    }
  easy->size_download += len;
  return TWIST_OK;
}

int
twist_ws_send (struct twist_ws *w, int opcode, int fin,
               const uint8_t *data, size_t len)
{
  uint8_t hdr[14];
  size_t n = 0;
  uint8_t mask[4];
  size_t off = 0;
  ssize_t got;

  if (w == NULL || w->send == NULL || opcode < 0 || opcode > 15)
    return TWIST_ERR_INVAL;
  if (len > WS_MAX)
    return TWIST_ERR_PROTOCOL;
  if ((opcode & 0x8) != 0 && len > WS_CTRL)
    return TWIST_ERR_PROTOCOL;
  got = getrandom (mask, sizeof mask, 0);
  if (got != (ssize_t) sizeof mask)
    return TWIST_ERR_PROTOCOL;
  hdr[n++] = (uint8_t) ((fin ? 0x80 : 0) | opcode);
  if (len < 126)
    hdr[n++] = (uint8_t) (0x80 | len);
  else if (len <= 65535)
    {
      hdr[n++] = 0x80 | 126;
      hdr[n++] = (uint8_t) (len >> 8);
      hdr[n++] = (uint8_t) len;
    }
  else
    {
      int i;

      hdr[n++] = 0x80 | 127;
      for (i = 7; i >= 0; i--)
        hdr[n++] = (uint8_t) (len >> (8 * i));
    }
  memcpy (hdr + n, mask, 4);
  n += 4;
  if (w->send (w->send_user, hdr, n) != 0)
    return TWIST_ERR_ABORTED;
  while (off < len)
    {
      uint8_t buf[512];
      size_t chunk = len - off;
      size_t i;

      if (chunk > sizeof buf)
        chunk = sizeof buf;
      for (i = 0; i < chunk; i++)
        buf[i] = data[off + i] ^ mask[(off + i) & 3];
      if (w->send (w->send_user, buf, chunk) != 0)
        return TWIST_ERR_ABORTED;
      off += chunk;
    }
  return TWIST_OK;
}

static int
finish_frame (struct twist_ws *w)
{
  int rc = TWIST_OK;

  if ((w->opcode & 0x8) != 0 && (!w->fin || w->pay_len > WS_CTRL))
    return TWIST_ERR_PROTOCOL;
  if (w->opcode == 0x9)
    rc = twist_ws_send (w, 0xa, 1, w->ctrl, w->pay_len);
  else if (w->opcode == 0x8)
    {
      rc = twist_ws_send (w, 0x8, 1, w->ctrl, w->pay_len);
      w->failed = 1;
      if (w->done != NULL)
        w->done (w->done_user, rc == TWIST_OK ? TWIST_OK : rc);
      rc = TWIST_OK;
    }
  w->step = WS_B0;
  w->pay_got = 0;
  w->pay_len = 0;
  return rc;
}

static int
hdr_byte (struct twist_ws *w, uint8_t c)
{
  if (w->step == WS_B0)
    {
      if ((c & 0x70) != 0)
        return TWIST_ERR_PROTOCOL;
      w->fin = (c & 0x80) != 0;
      w->opcode = c & 0x0f;
      if (w->opcode > 2 && w->opcode < 8)
        return TWIST_ERR_PROTOCOL;
      if (w->opcode > 10)
        return TWIST_ERR_PROTOCOL;
      w->step = WS_B1;
      return TWIST_OK;
    }
  if (w->step == WS_B1)
    {
      if ((c & 0x80) != 0)
        return TWIST_ERR_PROTOCOL;
      w->len_bits = c & 0x7f;
      if ((w->opcode & 0x8) != 0
          && (w->len_bits > WS_CTRL || !w->fin))
        return TWIST_ERR_PROTOCOL;
      if (w->len_bits == 126)
        {
          w->len_left = 2;
          w->pay_len = 0;
          w->step = WS_LEN;
        }
      else if (w->len_bits == 127)
        {
          w->len_left = 8;
          w->pay_len = 0;
          w->step = WS_LEN;
        }
      else
        {
          w->pay_len = w->len_bits;
          w->pay_got = 0;
          if (w->pay_len == 0)
            return finish_frame (w);
          w->step = WS_PAY;
        }
      return TWIST_OK;
    }
  w->pay_len = (w->pay_len << 8) | c;
  w->len_left--;
  if (w->len_left > 0)
    return TWIST_OK;
  if (w->len_bits == 127 && (w->pay_len >> 63) != 0)
    return TWIST_ERR_PROTOCOL;
  if (w->pay_len > WS_MAX || ((w->opcode & 0x8) != 0 && w->pay_len > WS_CTRL))
    return TWIST_ERR_PROTOCOL;
  w->pay_got = 0;
  if (w->pay_len == 0)
    return finish_frame (w);
  w->step = WS_PAY;
  return TWIST_OK;
}

size_t
twist_ws_receive (struct twist_ws *w, const uint8_t *data, size_t len)
{
  size_t off = 0;

  if (w == NULL)
    return 0;
  if (w->failed)
    return len;
  while (off < len && !w->failed)
    {
      if (w->step == WS_PAY)
        {
          size_t n = len - off;
          int rc = TWIST_OK;

          if (n > w->pay_len - w->pay_got)
            n = w->pay_len - w->pay_got;
          if ((w->opcode & 0x8) != 0)
            memcpy (w->ctrl + w->pay_got, data + off, n);
          else
            rc = deliver (w, data + off, n);
          if (rc != TWIST_OK)
            {
              w->failed = 1;
              if (w->done != NULL)
                w->done (w->done_user, rc);
              return len;
            }
          off += n;
          w->pay_got += n;
          if (w->pay_got == w->pay_len)
            {
              rc = finish_frame (w);
              if (rc != TWIST_OK)
                {
                  w->failed = 1;
                  if (w->done != NULL)
                    w->done (w->done_user, rc);
                  return len;
                }
            }
          continue;
        }
      if (hdr_byte (w, data[off]) != TWIST_OK)
        {
          w->failed = 1;
          if (w->done != NULL)
            w->done (w->done_user, TWIST_ERR_PROTOCOL);
          return len;
        }
      off++;
    }
  return off;
}

struct twist_ws *
twist_ws_new (struct twist_easy *easy,
              int (*send) (void *user, const uint8_t *data, size_t len),
              void *send_user, void (*done) (void *user, int err),
              void *done_user)
{
  struct twist_ws *w = calloc (1, sizeof *w);

  if (w == NULL)
    return NULL;
  w->easy = easy;
  w->send = send;
  w->send_user = send_user;
  w->done = done;
  w->done_user = done_user;
  return w;
}

void
twist_ws_free (struct twist_ws *w)
{
  free (w);
}
