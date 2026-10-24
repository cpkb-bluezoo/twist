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

  twist_transfer *transfer;
  struct twist_ldap *ldap;
  const uint8_t *cmd;
  size_t n = 0;

  transfer = twist_transfer_new ();
  check (twist_url_parse_int
         ("ldap://cn=alice:secret@127.0.0.1/dc=example,dc=com?cn?sub?(uid=alice)",
          &transfer->url) == TWIST_OK, "ldap url");
  ldap = twist_ldap_new (transfer, 0);
  cmd = twist_ldap_command (ldap, &n);
  check (has_bytes (cmd, n, "cn=alice", 8) && has_bytes (cmd, n, "secret", 6),
         "simple bind");
  feed_bin (ldap_recv, ldap, bind_ok, sizeof bind_ok, 1);
  cmd = twist_ldap_command (ldap, &n);
  check (has_bytes (cmd, n, "dc=example,dc=com", 17)
         && has_bytes (cmd, n, "uid", 3) && has_bytes (cmd, n, "alice", 5)
         && has_bytes (cmd, n, "cn", 2), "search");
  mail_body_len = 0;
  transfer->write_cb = mail_write;
  feed_bin (ldap_recv, ldap, entry, sizeof entry, 1);
  feed_bin (ldap_recv, ldap, search_done, sizeof search_done, 1);
  check (transfer->done && transfer->result == TWIST_OK, "ldap done");
  check (mail_body_len == sizeof ldif - 1
         && memcmp (mail_body, ldif, mail_body_len) == 0, "ldif");
  check (transfer->progress.downloaded == (long long) mail_body_len,
         "ldap progress");
  cmd = twist_ldap_command (ldap, &n);
  check (has_bytes (cmd, n, "\x42", 1), "unbind");
  twist_transfer_free (transfer);

  transfer = twist_transfer_new ();
  check (twist_url_parse_int ("ldap://cn=alice:no@127.0.0.1/dc=x",
                              &transfer->url)
         == TWIST_OK, "ldap bad url");
  ldap = twist_ldap_new (transfer, 0);
  feed_bin (ldap_recv, ldap, bind_no, sizeof bind_no, 1);
  check (transfer->done && transfer->result == TWIST_ERR_AUTH, "bind refused");
  twist_transfer_free (transfer);

  {
    static const uint8_t bind_long[] = {
      0x30, 0x82, 0x00, 0x0e, 0x02, 0x01, 0x01, 0x61, 0x82, 0x00, 0x07,
      0x0a, 0x01, 0x00, 0x04, 0x00, 0x04, 0x00
    };

    transfer = twist_transfer_new ();
    check (twist_url_parse_int ("ldap://127.0.0.1/dc=example,dc=com",
                                &transfer->url) == TWIST_OK, "long url");
    ldap = twist_ldap_new (transfer, 0);
    feed_bin (ldap_recv, ldap, bind_long, sizeof bind_long, 1);
    cmd = twist_ldap_command (ldap, &n);
    check (has_bytes (cmd, n, "dc=example,dc=com", 17)
           && has_bytes (cmd, n, "objectClass", 11), "long bind");
    twist_transfer_free (transfer);
  }

  transfer = twist_transfer_new ();
  check (twist_url_parse_int ("ldap://alice:x@127.0.0.1/dc=example,dc=com",
                              &transfer->url) == TWIST_OK, "sasl url");
  transfer->bearer = twist_strdup ("tok");
  ldap = twist_ldap_new (transfer, 0);
  cmd = twist_ldap_command (ldap, &n);
  check (has_bytes (cmd, n, "XOAUTH2", 7)
         && has_bytes (cmd, n, "auth=Bearer tok", 15), "sasl bind");
  twist_transfer_free (transfer);
  transfer = NULL;
}

/* A SearchResultEntry for dc=x with one attribute, ATTR, of the one value
   VAL, in BER (all the lengths here are short).  */
static size_t
build_entry (uint8_t *out, const char *attr, const char *val)
{
  size_t al = strlen (attr);
  size_t vl = strlen (val);
  size_t pa = (2 + al) + (4 + vl);
  size_t entry = (2 + 4) + (2 + 2 + pa);
  size_t n = 0;

  out[n++] = 0x30;
  out[n++] = (uint8_t) (3 + 2 + entry);
  out[n++] = 0x02; out[n++] = 0x01; out[n++] = 0x02;
  out[n++] = 0x64;
  out[n++] = (uint8_t) entry;
  out[n++] = 0x04; out[n++] = 4;
  memcpy (out + n, "dc=x", 4);
  n += 4;
  out[n++] = 0x30;
  out[n++] = (uint8_t) (2 + pa);
  out[n++] = 0x30;
  out[n++] = (uint8_t) pa;
  out[n++] = 0x04;
  out[n++] = (uint8_t) al;
  memcpy (out + n, attr, al);
  n += al;
  out[n++] = 0x31;
  out[n++] = (uint8_t) (2 + vl);
  out[n++] = 0x04;
  out[n++] = (uint8_t) vl;
  memcpy (out + n, val, vl);
  n += vl;
  return n;
}

/* The attribute names are the server's, and are written into the output as
   they come.  A name that holds a line break writes a second line, an
   attribute the server did not send as one (userPassword: x) for whatever
   reads the output.  A name is letters, digits, dots, semicolons and hyphens
   (RFC 4512: a keyword or an OID, with options).  Values are another thing
   and are encoded (base64) where they need it.  */
static void
test_ldap_names (void)
{
  static const uint8_t bind_ok[] = {
    0x30, 0x0c, 0x02, 0x01, 0x01, 0x61, 0x07, 0x0a, 0x01, 0x00, 0x04, 0x00,
    0x04, 0x00
  };
  static const char *const bad[] = {
    "cn\nuserPassword", "cn\r\nx", "cn: x", "c n", "cn:", "cn\t", "cn=1",
    "c\x80n", "cn,sn", "cn/x", "<cn>"
  };
  static const char *const good[] = { "cn", "cn;lang-en", "2.5.4.3",
                                      "userCertificate;binary", "mail-x1" };
  uint8_t buf[256];
  size_t i;

  for (i = 0; i < sizeof bad / sizeof bad[0]; i++)
    {
      twist_transfer *transfer = twist_transfer_new ();
      struct twist_ldap *ldap;
      size_t n;

      check (twist_url_parse_int ("ldap://127.0.0.1/dc=x", &transfer->url)
             == TWIST_OK, "url");
      ldap = twist_ldap_new (transfer, 0);
      feed_bin (ldap_recv, ldap, bind_ok, sizeof bind_ok, 1);
      mail_body_len = 0;
      transfer->write_cb = mail_write;
      n = build_entry (buf, bad[i], "bob");
      feed_bin (ldap_recv, ldap, buf, n, 1);
      check (transfer->done && transfer->result == TWIST_ERR_PROTOCOL,
             "a hostile attribute name ends the transfer");
      check (mail_body_len == 0
             || (mail_body_len == 9 && memcmp (mail_body, "dn: dc=x\n", 9) == 0),
             "and writes no line of the server's making");
      check (!has_bytes ((const uint8_t *) mail_body, mail_body_len, "userPassword", 12),
             "nor the forged one");
      twist_transfer_free (transfer);
    }
  for (i = 0; i < sizeof good / sizeof good[0]; i++)
    {
      twist_transfer *transfer = twist_transfer_new ();
      struct twist_ldap *ldap;
      size_t n;
      char want[64];

      check (twist_url_parse_int ("ldap://127.0.0.1/dc=x", &transfer->url)
             == TWIST_OK, "url");
      ldap = twist_ldap_new (transfer, 0);
      feed_bin (ldap_recv, ldap, bind_ok, sizeof bind_ok, 1);
      mail_body_len = 0;
      transfer->write_cb = mail_write;
      n = build_entry (buf, good[i], "bob");
      feed_bin (ldap_recv, ldap, buf, n, 1);
      snprintf (want, sizeof want, "%s: bob\n", good[i]);
      check (!transfer->done
             && has_bytes ((const uint8_t *) mail_body, mail_body_len, want, strlen (want)),
             "an ordinary attribute name is written");
      twist_transfer_free (transfer);
    }
  /* A value with trailing space is base64, as LDIF readers expect.  */
  {
    twist_transfer *transfer = twist_transfer_new ();
    struct twist_ldap *ldap;
    size_t n;

    check (twist_url_parse_int ("ldap://127.0.0.1/dc=x", &transfer->url)
           == TWIST_OK, "url");
    ldap = twist_ldap_new (transfer, 0);
    feed_bin (ldap_recv, ldap, bind_ok, sizeof bind_ok, 1);
    mail_body_len = 0;
    transfer->write_cb = mail_write;
    n = build_entry (buf, "cn", "bob ");
    feed_bin (ldap_recv, ldap, buf, n, 1);
    check (has_bytes ((const uint8_t *) mail_body, mail_body_len, "cn:: Ym9iIA==\n", 14),
           "a value with a trailing space is base64");
    twist_transfer_free (transfer);
  }
}

int
main (void)
{
  test_ldap ();
  test_ldap_names ();
  return tests_finish ();
}
