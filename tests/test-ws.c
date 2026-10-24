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

#include "check.h"
#include "twist-int.h"
#include "http-ev.h"
#include "feed.h"
#include "body.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static uint8_t ws_out[64];
static size_t ws_out_n;
static int ws_done_err;
static int ws_done_n;

static int
ws_sink (void *user, const uint8_t *data, size_t len)
{
  (void) user;
  if (ws_out_n + len > sizeof ws_out)
    return 1;
  memcpy (ws_out + ws_out_n, data, len);
  ws_out_n += len;
  return 0;
}

static void
ws_finished (void *user, int err)
{
  (void) user;
  ws_done_err = err;
  ws_done_n++;
}

static size_t
ws_recv (void *obj, const uint8_t *data, size_t len)
{
  return twist_ws_receive (obj, data, len);
}

static int opened_switch (void *user);

static char h3_names[8][32];
static char h3_values[8][64];
static int h3_seen;

static void
h3_collect (void *user, const char *name, size_t nn, const char *value,
            size_t vn)
{
  (void) user;
  if (h3_seen < 8)
    {
      snprintf (h3_names[h3_seen], sizeof h3_names[0], "%.*s", (int) nn, name);
      snprintf (h3_values[h3_seen], sizeof h3_values[0], "%.*s", (int) vn,
                value);
      h3_seen++;
    }
}

static int
h3_has (const char *name, const char *value)
{
  int i;

  for (i = 0; i < h3_seen; i++)
    if (strcmp (h3_names[i], name) == 0 && strcmp (h3_values[i], value) == 0)
      return 1;
  return 0;
}

static void
test_ws (void)
{
  char *accept = NULL;
  struct twist_ws *ws;
  struct twist_transfer *transfer;
  static const uint8_t hello[] = {
    0x81, 0x05, 'H', 'e', 'l', 'l', 'o'
  };
  static const uint8_t ping[] = { 0x89, 0x01, 'z' };
  static const uint8_t close_frame[] = { 0x88, 0x00 };

  check (twist_ws_accept ("dGhlIHNhbXBsZSBub25jZQ==", &accept) == TWIST_OK,
         "ws accept rc");
  check (accept != NULL
         && strcmp (accept, "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=") == 0,
         "ws accept");
  free (accept);
  check (twist_ws_validate ("dGhlIHNhbXBsZSBub25jZQ==", "websocket",
                            "Upgrade", "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=")
         == TWIST_OK, "ws validate");
  check (twist_ws_validate ("dGhlIHNhbXBsZSBub25jZQ==", "websocket",
                            "Upgrade", "nope") == TWIST_ERR_PROTOCOL,
         "ws bad accept");
  transfer = twist_transfer_new ();
  transfer->write_cb = mail_write;
  mail_body_len = 0;
  ws_out_n = 0;
  ws_done_n = 0;
  ws = twist_ws_new (transfer, ws_sink, NULL, ws_finished, NULL);
  feed_bin (ws_recv, ws, hello, sizeof hello, 1);
  check (mail_body_len == 5 && memcmp (mail_body, "Hello", 5) == 0,
         "ws text");
  check (transfer->progress.downloaded == 5, "ws progress");
  feed_bin (ws_recv, ws, ping, sizeof ping, 1);
  check (ws_out_n == 7 && (ws_out[0] & 0x0f) == 0x0a
         && (ws_out[1] & 0x80) != 0
         && (ws_out[6] ^ ws_out[2]) == 'z', "ws pong");
  check (ws_done_n == 0, "ws ping open");
  ws_out_n = 0;
  feed_bin (ws_recv, ws, close_frame, sizeof close_frame, 1);
  check (ws_done_n == 1 && ws_done_err == TWIST_OK, "ws close");
  check (ws_out_n == 6 && (ws_out[0] & 0x0f) == 0x08
         && (ws_out[1] & 0x80) != 0, "ws close frame");
  twist_ws_free (ws);
  twist_transfer_free (transfer);
  {
    struct twist_slist *extra = NULL;
    struct twist_h1_events ev;
    struct twist_h3 *h3;
    uint8_t *out = NULL;
    size_t n = 0;
    static const uint8_t resp[] = {
      0x01, 0x03, 0x00, 0x00, 0xd9,
      0x00, 0x07, 0x81, 0x05, 'H', 'e', 'l', 'l', 'o',
      0x04, 0x00
    };
    static int opened;

    extra = twist_slist_append (NULL, ":protocol: websocket");
    check (twist_h3_request (NULL, "CONNECT", "https", "example", "/chat",
                             extra, NULL, 0, &out, &n) == TWIST_OK,
           "h3 connect rc");
    check (out != NULL && out[0] == 0x01, "h3 headers");
    /* The fields as a decoder reads them: the table's for the method and the
       scheme, literals for the rest.  out[1] is the length, a byte.  */
    {
      struct twist_h1_events cev;

      memset (&cev, 0, sizeof cev);
      cev.header = h3_collect;
      h3_seen = 0;
      check (n > 2 && twist_qpack_decode (out + 2, n - 2, &cev) == TWIST_OK,
             "h3 fields decode");
      check (h3_seen == 5 && h3_has (":method", "CONNECT")
             && h3_has (":scheme", "https") && h3_has (":authority", "example")
             && h3_has (":path", "/chat") && h3_has (":protocol", "websocket"),
             "h3 connect fields");
    }
    free (out);
    twist_slist_free_all (extra);
    ev = test_events ();
    opened = 0;
    ev.switching = opened_switch;
    ev.user = &opened;
    h3 = twist_h3_new (&ev);
    reset_ev ();
    feed_remain (h3_recv, h3, resp, sizeof resp, 1);
    check (opened == 1, "h3 opened");
    check (body_len == 7 && memcmp (body, "\x81\x05Hello", 7) == 0,
           "h3 ws data");
    check (saw_done == 1, "h3 ws done");
    twist_h3_free (h3);
  }
}

static int
opened_switch (void *user)
{
  int *opened = user;

  (*opened)++;
  return 1;
}

int
main (void)
{
  test_ws ();
  return tests_finish ();
}
