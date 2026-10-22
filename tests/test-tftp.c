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
#include "body.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static size_t
tftp_read (char *ptr, size_t size, size_t nmemb, void *user)
{
  static const char chunk[] = "xy";
  static size_t off;
  size_t want = size * nmemb;
  size_t left;

  (void) user;
  if (ptr == NULL)
    {
      off = 0;
      return 0;
    }
  left = sizeof chunk - 1 - off;
  if (left > want)
    left = want;
  if (left == 0)
    return 0;
  memcpy (ptr, chunk + off, left);
  off += left;
  return left;
}

static void
test_tftp_is (struct twist_tftp *t, const uint8_t *expect, size_t n,
              const char *what)
{
  const uint8_t *pkt;
  size_t got = 0;

  pkt = twist_tftp_packet (t, &got);
  check (pkt != NULL && got == n && memcmp (pkt, expect, n) == 0, what);
}

static void
test_tftp (void)
{
  struct twist_easy *easy;
  struct twist_tftp *t;
  uint8_t block[4 + 512];
  static const uint8_t rrq[] = {
    0, 1,
    'h', 'e', 'l', 'l', 'o', 0,
    'o', 'c', 't', 'e', 't', 0,
    't', 's', 'i', 'z', 'e', 0,
    '0', 0,
    'b', 'l', 'k', 's', 'i', 'z', 'e', 0,
    '5', '1', '2', 0,
    't', 'i', 'm', 'e', 'o', 'u', 't', 0,
    '5', 0
  };
  static const uint8_t wrq[] = {
    0, 2,
    'u', 'p', 0,
    'o', 'c', 't', 'e', 't', 0,
    't', 's', 'i', 'z', 'e', 0,
    '3', 0,
    'b', 'l', 'k', 's', 'i', 'z', 'e', 0,
    '5', '1', '2', 0,
    't', 'i', 'm', 'e', 'o', 'u', 't', 0,
    '5', 0
  };
  static const uint8_t wrq_cb[] = {
    0, 2,
    'c', 'b', 0,
    'o', 'c', 't', 'e', 't', 0,
    't', 's', 'i', 'z', 'e', 0,
    '0', 0,
    'b', 'l', 'k', 's', 'i', 'z', 'e', 0,
    '5', '1', '2', 0,
    't', 'i', 'm', 'e', 'o', 'u', 't', 0,
    '5', 0
  };
  static const uint8_t data_abc[] = { 0, 3, 0, 1, 'a', 'b', 'c' };
  static const uint8_t data_xy[] = { 0, 3, 0, 1, 'x', 'y' };
  static const uint8_t ack0[] = { 0, 4, 0, 0 };
  static const uint8_t ack1[] = { 0, 4, 0, 1 };
  static const uint8_t ack2[] = { 0, 4, 0, 2 };
  static const uint8_t oack[] = {
    0, 6,
    'B', 'L', 'K', 'S', 'I', 'Z', 'E', 0,
    '5', '1', '2', 0
  };
  static const uint8_t oack_big[] = {
    0, 6,
    'b', 'l', 'k', 's', 'i', 'z', 'e', 0,
    '4', '0', '9', '6', 0
  };
  static const uint8_t oack_bad[] = { 0, 6, 'b', 'l', 'k' };
  static const uint8_t err_pkt[] = { 0, 5, 0, 1, 'n', 'o', 0 };
  static const uint8_t data_hi[] = { 0, 3, 0, 1, 'h', 'i' };
  int i;

  easy = twist_easy_init ();
  check (twist_url_parse_int ("tftp://127.0.0.1/hello", &easy->url) == TWIST_OK,
         "tftp url");
  check (easy->url->port == 69, "tftp port");
  t = twist_tftp_new (easy, 0);
  test_tftp_is (t, rrq, sizeof rrq, "tftp rrq");
  check (!easy->done, "tftp rrq open");
  twist_easy_cleanup (easy);

  easy = twist_easy_init ();
  check (twist_url_parse_int ("tftp://127.0.0.1/hello?x=1", &easy->url)
         == TWIST_OK, "tftp query url");
  t = twist_tftp_new (easy, 0);
  test_tftp_is (t, rrq, sizeof rrq, "tftp query");
  twist_easy_cleanup (easy);

  easy = twist_easy_init ();
  check (twist_url_parse_int ("tftp://127.0.0.1/", &easy->url) == TWIST_OK,
         "tftp empty url");
  t = twist_tftp_new (easy, 0);
  check (t != NULL && easy->done && easy->result == TWIST_ERR_URL,
         "tftp empty");
  twist_easy_cleanup (easy);

  easy = twist_easy_init ();
  check (twist_url_parse_int ("tftp://127.0.0.1/a%00", &easy->url) == TWIST_OK,
         "tftp nul url");
  t = twist_tftp_new (easy, 0);
  check (t != NULL && easy->done && easy->result == TWIST_ERR_URL, "tftp nul");
  twist_easy_cleanup (easy);

  static char upload[] = "abc";

  easy = twist_easy_init ();
  check (twist_url_parse_int ("tftp://127.0.0.1/up", &easy->url) == TWIST_OK,
         "tftp put url");
  easy->postfields = upload;
  easy->postfieldsize = 3;
  easy->postfieldsize_set = 1;
  t = twist_tftp_new (easy, 0);
  test_tftp_is (t, wrq, sizeof wrq, "tftp wrq");
  twist_tftp_receive (t, ack0, sizeof ack0);
  test_tftp_is (t, data_abc, sizeof data_abc, "tftp data");
  check (!easy->done, "tftp put open");
  twist_tftp_receive (t, ack1, sizeof ack1);
  check (easy->done && easy->result == TWIST_OK, "tftp put done");
  check (easy->progress.ul_known && easy->progress.size_ul == 3
         && easy->progress.uploaded == 3, "tftp upload progress");
  easy->postfields = NULL;
  twist_easy_cleanup (easy);

  easy = twist_easy_init ();
  check (twist_url_parse_int ("tftp://127.0.0.1/cb", &easy->url) == TWIST_OK,
         "tftp read url");
  tftp_read (NULL, 0, 0, NULL);
  easy->read_cb = tftp_read;
  t = twist_tftp_new (easy, 0);
  test_tftp_is (t, wrq_cb, sizeof wrq_cb, "tftp wrq cb");
  twist_tftp_receive (t, ack0, sizeof ack0);
  test_tftp_is (t, data_xy, sizeof data_xy, "tftp data cb");
  twist_tftp_receive (t, ack1, sizeof ack1);
  check (easy->done && easy->result == TWIST_OK, "tftp read done");
  twist_easy_cleanup (easy);

  easy = twist_easy_init ();
  check (twist_url_parse_int ("tftp://127.0.0.1/hello", &easy->url) == TWIST_OK,
         "tftp get url");
  easy->write_cb = mail_write;
  mail_body_len = 0;
  t = twist_tftp_new (easy, 0);
  twist_tftp_receive (t, oack, sizeof oack);
  test_tftp_is (t, ack0, sizeof ack0, "tftp oack");
  check (!easy->done, "tftp oack open");
  twist_tftp_receive (t, data_hi, sizeof data_hi);
  test_tftp_is (t, ack1, sizeof ack1, "tftp ack hi");
  check (mail_body_len == 2 && memcmp (mail_body, "hi", 2) == 0, "tftp body");
  check (easy->progress.downloaded == 2, "tftp download progress");
  check (easy->done && easy->result == TWIST_OK, "tftp get done");
  twist_easy_cleanup (easy);

  easy = twist_easy_init ();
  check (twist_url_parse_int ("tftp://127.0.0.1/hello", &easy->url) == TWIST_OK,
         "tftp blocks url");
  t = twist_tftp_new (easy, 0);
  memset (block, 'a', sizeof block);
  block[0] = 0;
  block[1] = 3;
  block[2] = 0;
  block[3] = 1;
  twist_tftp_receive (t, block, sizeof block);
  check (!easy->done && easy->size_download == 512, "tftp full");
  test_tftp_is (t, ack1, sizeof ack1, "tftp ack full");
  twist_tftp_receive (t, block, sizeof block);
  check (!easy->done && easy->size_download == 512, "tftp dup");
  block[3] = 3;
  twist_tftp_receive (t, block, 4 + 8);
  check (!easy->done && easy->size_download == 512, "tftp skip");
  test_tftp_is (t, ack1, sizeof ack1, "tftp ack held");
  block[3] = 2;
  twist_tftp_receive (t, block, 4);
  test_tftp_is (t, ack2, sizeof ack2, "tftp ack end");
  check (easy->done && easy->result == TWIST_OK
         && easy->size_download == 512, "tftp end");
  twist_easy_cleanup (easy);

  easy = twist_easy_init ();
  check (twist_url_parse_int ("tftp://127.0.0.1/hello", &easy->url) == TWIST_OK,
         "tftp err url");
  t = twist_tftp_new (easy, 0);
  twist_tftp_receive (t, err_pkt, sizeof err_pkt);
  check (easy->done && easy->result == TWIST_ERR_FILE, "tftp missing");
  twist_easy_cleanup (easy);

  easy = twist_easy_init ();
  check (twist_url_parse_int ("tftp://127.0.0.1/hello", &easy->url) == TWIST_OK,
         "tftp big url");
  t = twist_tftp_new (easy, 0);
  twist_tftp_receive (t, oack_big, sizeof oack_big);
  check (easy->done && easy->result == TWIST_ERR_PROTOCOL, "tftp big blk");
  check (t != NULL && twist_tftp_packet (t, NULL)[1] == 5, "tftp error op");
  twist_easy_cleanup (easy);

  easy = twist_easy_init ();
  check (twist_url_parse_int ("tftp://127.0.0.1/hello", &easy->url) == TWIST_OK,
         "tftp bad url");
  t = twist_tftp_new (easy, 0);
  twist_tftp_receive (t, oack_bad, sizeof oack_bad);
  check (easy->done && easy->result == TWIST_ERR_PROTOCOL, "tftp bad oack");
  twist_easy_cleanup (easy);

  easy = twist_easy_init ();
  check (twist_url_parse_int ("tftp://127.0.0.1/hello", &easy->url) == TWIST_OK,
         "tftp time url");
  t = twist_tftp_new (easy, 0);
  for (i = 0; i < 8 && !easy->done; i++)
    twist_tftp_timeout (t);
  check (easy->done && easy->result == TWIST_ERR_CONNECT && i == 6,
         "tftp timeout");
  twist_easy_cleanup (easy);

  easy = twist_easy_init ();
  check (twist_url_parse_int ("tftp://127.0.0.1/hello", &easy->url) == TWIST_OK,
         "tftp proxy url");
  check (twist_easy_setopt (easy, TWISTOPT_PROXY, "http://127.0.0.1:9")
         == TWIST_OK, "tftp proxy set");
  t = twist_tftp_new (easy, 0);
  check (t != NULL && easy->done && easy->result == TWIST_ERR_UNSUPPORTED,
         "tftp proxy");
  twist_easy_cleanup (easy);
}

int
main (void)
{
  test_tftp ();
  return tests_finish ();
}
