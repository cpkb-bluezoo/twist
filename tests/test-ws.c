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

static void
test_ws (void)
{
  char *accept = NULL;
  struct twist_ws *ws;
  struct twist_easy *easy;
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
  easy = twist_easy_init ();
  easy->write_cb = mail_write;
  mail_body_len = 0;
  ws_out_n = 0;
  ws_done_n = 0;
  ws = twist_ws_new (easy, ws_sink, NULL, ws_finished, NULL);
  feed_bin (ws_recv, ws, hello, sizeof hello, 1);
  check (mail_body_len == 5 && memcmp (mail_body, "Hello", 5) == 0,
         "ws text");
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
  twist_easy_cleanup (easy);
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
    check (has_bytes (out, n, "CONNECT", 7)
           && has_bytes (out, n, ":protocol", 9)
           && has_bytes (out, n, "websocket", 9)
           && has_bytes (out, n, "https", 5), "h3 connect fields");
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
