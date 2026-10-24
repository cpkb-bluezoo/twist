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
gopher_recv (void *obj, const uint8_t *data, size_t len)
{
  return twist_gopher_receive (obj, data, len);
}

static void
test_gopher_one (const char *url, const void *expect, size_t expect_n,
                 const char *what)
{
  struct twist_transfer *transfer = twist_transfer_new ();
  struct twist_gopher *g;
  const uint8_t *req;
  size_t n = 0;

  check (twist_url_parse_int (url, &transfer->url) == TWIST_OK, what);
  g = twist_gopher_new (transfer, 0);
  req = twist_gopher_request (g, &n);
  check (g != NULL && !transfer->done && n == expect_n
         && memcmp (req, expect, expect_n) == 0, what);
  twist_transfer_free (transfer);
}

static void
test_gopher (void)
{
  struct twist_transfer *transfer;
  struct twist_gopher *g;
  static const uint8_t menu[] = {
    '1', 'H', 'e', 'l', 'l', 'o', '\t', 's', '\t', 'h', '\t', '7', '0',
    '\r', '\n', '.', '\r', '\n'
  };
  static const uint8_t tabbed[] = { '/', 'a', '\t', 'b', '\r', '\n' };

  test_gopher_one ("gopher://127.0.0.1/1/foo", "/foo\r\n", 6, "gopher sel");
  test_gopher_one ("gopher://127.0.0.1/", "\r\n", 2, "gopher root");
  test_gopher_one ("gopher://127.0.0.1/1", "\r\n", 2, "gopher type");
  test_gopher_one ("gopher://127.0.0.1/0file%20name", "file name\r\n", 11,
                   "gopher decode");
  test_gopher_one ("gopher://127.0.0.1/1/a%09b", tabbed, sizeof tabbed,
                   "gopher tab");
  test_gopher_one ("gopher://127.0.0.1/7/q?find", "/q?find\r\n", 9,
                   "gopher search");
  transfer = twist_transfer_new ();
  check (twist_url_parse_int ("gopher://127.0.0.1/1/%00", &transfer->url)
         == TWIST_OK, "gopher nul url");
  g = twist_gopher_new (transfer, 0);
  check (g != NULL && transfer->done && transfer->result == TWIST_ERR_URL,
         "gopher nul");
  twist_transfer_free (transfer);
  transfer = twist_transfer_new ();
  check (twist_url_parse_int ("gopher://127.0.0.1/1/hello", &transfer->url)
         == TWIST_OK, "gopher body url");
  transfer->write_cb = mail_write;
  mail_body_len = 0;
  g = twist_gopher_new (transfer, 0);
  feed_bin (gopher_recv, g, menu, sizeof menu, 1);
  check (mail_body_len == sizeof menu
         && memcmp (mail_body, menu, sizeof menu) == 0, "gopher body");
  check (transfer->progress.downloaded == (long long) sizeof menu,
         "gopher progress");
  check (!transfer->done, "gopher still open");
  twist_gopher_closed (g, TWIST_ERR_CLOSED);
  check (transfer->done && transfer->result == TWIST_OK, "gopher close");
  twist_transfer_free (transfer);
}

int
main (void)
{
  test_gopher ();
  return tests_finish ();
}
