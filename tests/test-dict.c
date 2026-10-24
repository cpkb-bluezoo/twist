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
dict_recv (void *obj, const uint8_t *data, size_t len)
{
  return twist_dict_receive (obj, data, len);
}

static void
test_dict_one (const char *url, const char *expect, const char *what)
{
  struct twist_transfer *transfer = twist_transfer_new ();
  struct twist_dict *d;
  const uint8_t *req;
  size_t n = 0;
  size_t en = strlen (expect);

  check (twist_url_parse_int (url, &transfer->url) == TWIST_OK, what);
  check (transfer->url->port == 2628, what);
  d = twist_dict_new (transfer, 0);
  req = twist_dict_request (d, &n);
  check (d != NULL && !transfer->done && n == en
         && memcmp (req, expect, en) == 0, what);
  twist_transfer_free (transfer);
}

static void
test_dict (void)
{
  struct twist_transfer *transfer;
  struct twist_dict *d;
  static const uint8_t reply[] =
    "150 1 definitions retrieved\r\nhello\r\n250 ok\r\n";

  test_dict_one ("dict://127.0.0.1/d:hello:wn",
                 "CLIENT twist 0.1\r\nDEFINE wn hello\r\nQUIT\r\n",
                 "dict define");
  test_dict_one ("dict://127.0.0.1/m:hello",
                 "CLIENT twist 0.1\r\nMATCH ! . hello\r\nQUIT\r\n",
                 "dict match");
  test_dict_one ("dict://127.0.0.1/MATCH:foo:foldoc:exact:9",
                 "CLIENT twist 0.1\r\nMATCH foldoc exact foo\r\nQUIT\r\n",
                 "dict nth");
  test_dict_one ("dict://127.0.0.1/SHOW:DB",
                 "CLIENT twist 0.1\r\nSHOW DB\r\nQUIT\r\n",
                 "dict show");
  test_dict_one ("dict://127.0.0.1/d:hello%20world",
                 "CLIENT twist 0.1\r\nDEFINE ! hello\\ world\r\nQUIT\r\n",
                 "dict space");
  test_dict_one ("dict://127.0.0.1/d:a%22b%5Cc",
                 "CLIENT twist 0.1\r\nDEFINE ! a\\\"b\\\\c\r\nQUIT\r\n",
                 "dict escape");
  test_dict_one ("dict://127.0.0.1/d:word:db?x=1",
                 "CLIENT twist 0.1\r\nDEFINE db word\r\nQUIT\r\n",
                 "dict query");
  test_dict_one ("dict://127.0.0.1/",
                 "CLIENT twist 0.1\r\n\r\nQUIT\r\n",
                 "dict root");
  test_dict_one ("dict://127.0.0.1/d:",
                 "CLIENT twist 0.1\r\nDEFINE ! default\r\nQUIT\r\n",
                 "dict default");
  test_dict_one ("dict://127.0.0.1/FIND:bar:!:prefix",
                 "CLIENT twist 0.1\r\nMATCH ! prefix bar\r\nQUIT\r\n",
                 "dict find");
  test_dict_one ("dict://127.0.0.1/LOOKUP:Bar",
                 "CLIENT twist 0.1\r\nDEFINE ! Bar\r\nQUIT\r\n",
                 "dict lookup");
  test_dict_one ("dict://127.0.0.1/DeFiNe:Foo:*",
                 "CLIENT twist 0.1\r\nDEFINE * Foo\r\nQUIT\r\n",
                 "dict case");
  transfer = twist_transfer_new ();
  check (twist_url_parse_int ("dict://127.0.0.1/d:a%00", &transfer->url)
         == TWIST_OK, "dict nul url");
  d = twist_dict_new (transfer, 0);
  check (d != NULL && transfer->done && transfer->result == TWIST_ERR_URL,
         "dict nul");
  twist_transfer_free (transfer);
  transfer = twist_transfer_new ();
  check (twist_url_parse_int ("dict://127.0.0.1/d:a%0a", &transfer->url)
         == TWIST_OK, "dict lf url");
  d = twist_dict_new (transfer, 0);
  check (d != NULL && transfer->done && transfer->result == TWIST_ERR_URL,
         "dict lf");
  twist_transfer_free (transfer);
  transfer = twist_transfer_new ();
  /* A URL with no host is refused when it is parsed, so the handler is
     never given one.  */
  check (twist_url_parse_int ("dict:///d:word",
                              &transfer->url) == TWIST_ERR_URL
         && transfer->url == NULL, "dict host url");
  d = twist_dict_new (transfer, 0);
  check (d == NULL, "dict host");
  twist_transfer_free (transfer);
  transfer = twist_transfer_new ();
  check (twist_url_parse_int ("dict://127.0.0.1/d:hello", &transfer->url)
         == TWIST_OK, "dict body url");
  transfer->write_cb = mail_write;
  mail_body_len = 0;
  d = twist_dict_new (transfer, 0);
  feed_bin (dict_recv, d, reply, sizeof reply - 1, 1);
  check (mail_body_len == sizeof reply - 1
         && memcmp (mail_body, reply, mail_body_len) == 0, "dict body");
  check (transfer->progress.downloaded == (long long) mail_body_len,
         "dict progress");
  check (!transfer->done, "dict still open");
  twist_dict_closed (d, TWIST_ERR_CLOSED);
  check (transfer->done && transfer->result == TWIST_OK, "dict close");
  twist_transfer_free (transfer);
  transfer = twist_transfer_new ();
  check (twist_url_parse_int ("dict://127.0.0.1/d:hello", &transfer->url)
         == TWIST_OK, "dict early url");
  d = twist_dict_new (transfer, 0);
  twist_dict_closed (d, TWIST_ERR_CLOSED);
  check (transfer->done && transfer->result == TWIST_ERR_CLOSED,
         "dict early close");
  twist_transfer_free (transfer);
}

int
main (void)
{
  test_dict ();
  return tests_finish ();
}
