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
ldap_recv (void *obj, const uint8_t *data, size_t len)
{
  return twist_ldap_receive (obj, data, len);
}

static void
test_ldap (void)
{
  static const uint8_t bind_ok[] = {
    0x30, 0x0c, 0x02, 0x01, 0x01, 0x61, 0x07, 0x0a, 0x01, 0x00, 0x04, 0x00,
    0x04, 0x00
  };
  static const uint8_t bind_no[] = {
    0x30, 0x0c, 0x02, 0x01, 0x01, 0x61, 0x07, 0x0a, 0x01, 0x31, 0x04, 0x00,
    0x04, 0x00
  };
  static const uint8_t entry[] = {
    0x30, 0x27, 0x02, 0x01, 0x02, 0x64, 0x22, 0x04, 0x11, 'd', 'c', '=',
    'e', 'x', 'a', 'm', 'p', 'l', 'e', ',', 'd', 'c', '=', 'c', 'o', 'm',
    0x30, 0x0d, 0x30, 0x0b, 0x04, 0x02, 'c', 'n', 0x31, 0x05, 0x04, 0x03,
    'b', 'o', 'b'
  };
  static const uint8_t search_done[] = {
    0x30, 0x0c, 0x02, 0x01, 0x02, 0x65, 0x07, 0x0a, 0x01, 0x00, 0x04, 0x00,
    0x04, 0x00
  };
  static const char ldif[] = "dn: dc=example,dc=com\ncn: bob\n\n";

  twist_easy *easy;
  struct twist_ldap *ldap;
  const uint8_t *cmd;
  size_t n = 0;

  easy = twist_easy_init ();
  check (twist_url_parse_int
         ("ldap://cn=alice:secret@127.0.0.1/dc=example,dc=com?cn?sub?(uid=alice)",
          &easy->url) == TWIST_OK, "ldap url");
  ldap = twist_ldap_new (easy, 0);
  cmd = twist_ldap_command (ldap, &n);
  check (has_bytes (cmd, n, "cn=alice", 8) && has_bytes (cmd, n, "secret", 6),
         "simple bind");
  feed_bin (ldap_recv, ldap, bind_ok, sizeof bind_ok, 1);
  cmd = twist_ldap_command (ldap, &n);
  check (has_bytes (cmd, n, "dc=example,dc=com", 17)
         && has_bytes (cmd, n, "uid", 3) && has_bytes (cmd, n, "alice", 5)
         && has_bytes (cmd, n, "cn", 2), "search");
  mail_body_len = 0;
  easy->write_cb = mail_write;
  feed_bin (ldap_recv, ldap, entry, sizeof entry, 1);
  feed_bin (ldap_recv, ldap, search_done, sizeof search_done, 1);
  check (easy->done && easy->result == TWIST_OK, "ldap done");
  check (mail_body_len == sizeof ldif - 1
         && memcmp (mail_body, ldif, mail_body_len) == 0, "ldif");
  check (easy->progress.downloaded == (long long) mail_body_len,
         "ldap progress");
  cmd = twist_ldap_command (ldap, &n);
  check (has_bytes (cmd, n, "\x42", 1), "unbind");
  twist_easy_cleanup (easy);

  easy = twist_easy_init ();
  check (twist_url_parse_int ("ldap://cn=alice:no@127.0.0.1/dc=x", &easy->url)
         == TWIST_OK, "ldap bad url");
  ldap = twist_ldap_new (easy, 0);
  feed_bin (ldap_recv, ldap, bind_no, sizeof bind_no, 1);
  check (easy->done && easy->result == TWIST_ERR_AUTH, "bind refused");
  twist_easy_cleanup (easy);

  {
    static const uint8_t bind_long[] = {
      0x30, 0x82, 0x00, 0x0e, 0x02, 0x01, 0x01, 0x61, 0x82, 0x00, 0x07,
      0x0a, 0x01, 0x00, 0x04, 0x00, 0x04, 0x00
    };

    easy = twist_easy_init ();
    check (twist_url_parse_int ("ldap://127.0.0.1/dc=example,dc=com",
                                &easy->url) == TWIST_OK, "long url");
    ldap = twist_ldap_new (easy, 0);
    feed_bin (ldap_recv, ldap, bind_long, sizeof bind_long, 1);
    cmd = twist_ldap_command (ldap, &n);
    check (has_bytes (cmd, n, "dc=example,dc=com", 17)
           && has_bytes (cmd, n, "objectClass", 11), "long bind");
    twist_easy_cleanup (easy);
  }

  easy = twist_easy_init ();
  check (twist_url_parse_int ("ldap://alice:x@127.0.0.1/dc=example,dc=com",
                              &easy->url) == TWIST_OK, "sasl url");
  easy->bearer = twist_strdup ("tok");
  ldap = twist_ldap_new (easy, 0);
  cmd = twist_ldap_command (ldap, &n);
  check (has_bytes (cmd, n, "XOAUTH2", 7)
         && has_bytes (cmd, n, "auth=Bearer tok", 15), "sasl bind");
  twist_easy_cleanup (easy);
  easy = NULL;
}

int
main (void)
{
  test_ldap ();
  return tests_finish ();
}
