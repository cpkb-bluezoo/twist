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
#include "feed.h"
#include "body.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static size_t
mqtt_recv (void *obj, const uint8_t *data, size_t len)
{
  return twist_mqtt_receive (obj, data, len);
}

static void
test_mqtt (void)
{
  static const uint8_t connect[] = {
    0x10, 0x11, 0x00, 0x04, 'M', 'Q', 'T', 'T', 0x04, 0x02, 0x00, 0x3c,
    0x00, 0x05, 't', 'w', 'i', 's', 't'
  };
  static const uint8_t connack[] = { 0x20, 0x02, 0x00, 0x00 };
  static const uint8_t refused[] = { 0x20, 0x02, 0x00, 0x05 };
  static const uint8_t suback[] = { 0x90, 0x03, 0x00, 0x01, 0x00 };
  static const uint8_t publish[] = {
    0x30, 19, 0x00, 12, 's', 'e', 'n', 's', 'o', 'r', 's', '/', 't', 'e',
    'm', 'p', 'h', 'e', 'l', 'l', 'o'
  };
  static const uint8_t disc[] = { 0xe0, 0x00 };

  twist_easy *easy = twist_easy_init ();
  struct twist_mqtt *mqtt;
  const uint8_t *cmd;
  size_t n = 0;
  char ping[] = "ping";

  check (twist_url_parse_int ("mqtt://127.0.0.1/sensors/temp", &easy->url)
         == TWIST_OK, "mqtt url");
  mqtt = twist_mqtt_new (easy, 0);
  cmd = twist_mqtt_command (mqtt, &n);
  check (n == sizeof connect && memcmp (cmd, connect, n) == 0, "connect");
  feed_bin (mqtt_recv, mqtt, connack, sizeof connack, 1);
  cmd = twist_mqtt_command (mqtt, &n);
  check (has_bytes (cmd, n, "sensors/temp", 12), "subscribe");
  feed_bin (mqtt_recv, mqtt, suback, sizeof suback, 1);
  mail_body_len = 0;
  easy->write_cb = mail_write;
  feed_bin (mqtt_recv, mqtt, publish, sizeof publish, 1);
  check (mail_body_len == 5 && memcmp (mail_body, "hello", 5) == 0,
         "mqtt payload");
  feed_bin (mqtt_recv, mqtt, disc, sizeof disc, 1);
  check (easy->done && easy->result == TWIST_OK, "mqtt done");
  twist_easy_cleanup (easy);

  easy = twist_easy_init ();
  check (twist_url_parse_int ("mqtt://127.0.0.1/a", &easy->url) == TWIST_OK,
         "pub url");
  easy->postfields = ping;
  mqtt = twist_mqtt_new (easy, 0);
  feed_bin (mqtt_recv, mqtt, connack, sizeof connack, 1);
  cmd = twist_mqtt_command (mqtt, &n);
  check (easy->done && easy->result == TWIST_OK, "published");
  check (has_bytes (cmd, n, "ping", 4)
         && n >= 2 && cmd[n - 2] == 0xe0 && cmd[n - 1] == 0x00, "pub bytes");
  twist_easy_cleanup (easy);

  easy = twist_easy_init ();
  check (twist_url_parse_int ("mqtt://127.0.0.1/a", &easy->url) == TWIST_OK,
         "refuse url");
  mqtt = twist_mqtt_new (easy, 0);
  feed_bin (mqtt_recv, mqtt, refused, sizeof refused, 1);
  check (easy->done && easy->result == TWIST_ERR_AUTH, "connack auth");
  twist_easy_cleanup (easy);

  easy = twist_easy_init ();
  check (twist_url_parse_int ("mqtt://alice:secret@127.0.0.1/a", &easy->url)
         == TWIST_OK, "mqtt user");
  mqtt = twist_mqtt_new (easy, 0);
  cmd = twist_mqtt_command (mqtt, &n);
  check (has_bytes (cmd, n, "alice", 5) && has_bytes (cmd, n, "secret", 6),
         "mqtt credentials");
  twist_easy_cleanup (easy);
}

int
main (void)
{
  test_mqtt ();
  return tests_finish ();
}
