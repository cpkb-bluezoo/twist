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

/* STARTTLS (RFC 4511 section 4.14): --ssl and --ssl-reqd send the extended
   operation first, and a name and a password, or a bearer token, are not
   written until the handshake is done.  The peer here is the bytes it would
   send; the command is what the client has written.  */
static const uint8_t starttls_ok[] = {
  0x30, 0x0c, 0x02, 0x01, 0x01, 0x78, 0x07, 0x0a, 0x01, 0x00, 0x04, 0x00,
  0x04, 0x00
};
static const uint8_t starttls_no[] = {	/* protocolError */
  0x30, 0x0c, 0x02, 0x01, 0x01, 0x78, 0x07, 0x0a, 0x01, 0x02, 0x04, 0x00,
  0x04, 0x00
};
static const uint8_t bind_ok2[] = {
  0x30, 0x0c, 0x02, 0x01, 0x02, 0x61, 0x07, 0x0a, 0x01, 0x00, 0x04, 0x00,
  0x04, 0x00
};
#define STARTTLS_OID "1.3.6.1.4.1.1466.20037"

static twist_transfer *
starttls_transfer (const char *url, int use_ssl)
{
  twist_transfer *t = twist_transfer_new ();

  check (twist_url_parse_int (url, &t->url) == TWIST_OK, "starttls url");
  t->use_ssl = use_ssl;
  return t;
}

static int
sent (struct twist_ldap *l, const char *what)
{
  size_t n = 0;
  const uint8_t *cmd = twist_ldap_command (l, &n);

  return has_bytes (cmd, n, what, strlen (what));
}

static void
test_ldap_starttls (void)
{
  twist_transfer *t;
  struct twist_ldap *l;
  uint8_t both[sizeof starttls_ok + sizeof bind_ok2];

  /* Offered: the extended operation first, and nothing of the login.  */
  t = starttls_transfer ("ldap://cn=alice:secret@127.0.0.1/dc=x", TWIST_USE_SSL_ALL);
  l = twist_ldap_new (t, 0);
  check (sent (l, STARTTLS_OID), "starttls: the first thing written is STARTTLS");
  check (!sent (l, "secret") && !sent (l, "cn=alice"),
         "starttls: and holds no name or password");
  feed_bin (ldap_recv, l, starttls_ok, sizeof starttls_ok, 1);
  check (!t->done, "starttls: a yes waits for the handshake");
  check (!sent (l, "secret") && !sent (l, "cn=alice"),
         "starttls: and the login is not written before it");
  twist_ldap_tls_done (l);
  check (sent (l, "cn=alice") && sent (l, "secret") && !sent (l, STARTTLS_OID),
         "starttls: the bind is written when the handshake is done");
  feed_bin (ldap_recv, l, bind_ok2, sizeof bind_ok2, 1);
  check (!t->done && sent (l, "objectClass"), "starttls: and the search follows");
  twist_transfer_free (t);

  /* Bytes behind the yes came in the clear.  */
  t = starttls_transfer ("ldap://cn=alice:secret@127.0.0.1/dc=x", TWIST_USE_SSL_TRY);
  l = twist_ldap_new (t, 0);
  memcpy (both, starttls_ok, sizeof starttls_ok);
  memcpy (both + sizeof starttls_ok, bind_ok2, sizeof bind_ok2);
  feed_bin (ldap_recv, l, both, sizeof both, sizeof both);
  check (t->done && t->result == TWIST_ERR_PROTOCOL && !sent (l, "secret"),
         "starttls: bytes in the clear behind the yes end the transfer");
  twist_transfer_free (t);

  /* Refused, with a password: it is not sent, whether TLS was wanted or
     required.  */
  t = starttls_transfer ("ldap://cn=alice:secret@127.0.0.1/dc=x", TWIST_USE_SSL_TRY);
  l = twist_ldap_new (t, 0);
  feed_bin (ldap_recv, l, starttls_no, sizeof starttls_no, 1);
  check (t->done && t->result == TWIST_ERR_USE_SSL && !sent (l, "secret"),
         "starttls: a refusal with a password fails, though only --ssl was given");
  twist_transfer_free (t);
  t = starttls_transfer ("ldap://cn=alice:secret@127.0.0.1/dc=x", TWIST_USE_SSL_ALL);
  l = twist_ldap_new (t, 0);
  feed_bin (ldap_recv, l, starttls_no, sizeof starttls_no, 1);
  check (t->done && t->result == TWIST_ERR_USE_SSL && !sent (l, "secret"),
         "starttls: and so does --ssl-reqd");
  twist_transfer_free (t);

  /* A bearer token is a secret as a password is.  */
  t = starttls_transfer ("ldap://alice@127.0.0.1/dc=x", TWIST_USE_SSL_TRY);
  t->bearer = twist_strdup ("tok");
  l = twist_ldap_new (t, 0);
  check (!sent (l, "tok") && !sent (l, "XOAUTH2"),
         "starttls: a bearer token is not written before the handshake");
  feed_bin (ldap_recv, l, starttls_no, sizeof starttls_no, 1);
  check (t->done && t->result == TWIST_ERR_USE_SSL && !sent (l, "tok"),
         "starttls: and a refusal fails the transfer");
  twist_transfer_free (t);

  /* No credentials: --ssl goes on in the clear, --ssl-reqd does not.  */
  t = starttls_transfer ("ldap://127.0.0.1/dc=x", TWIST_USE_SSL_TRY);
  l = twist_ldap_new (t, 0);
  feed_bin (ldap_recv, l, starttls_no, sizeof starttls_no, 1);
  check (!t->done && !sent (l, STARTTLS_OID) && sent (l, "\x60"),
         "starttls: with no credentials a refusal goes on in the clear");
  feed_bin (ldap_recv, l, bind_ok2, sizeof bind_ok2, 1);
  check (!t->done && sent (l, "objectClass"), "starttls: and searches");
  twist_transfer_free (t);
  t = starttls_transfer ("ldap://127.0.0.1/dc=x", TWIST_USE_SSL_ALL);
  l = twist_ldap_new (t, 0);
  feed_bin (ldap_recv, l, starttls_no, sizeof starttls_no, 1);
  check (t->done && t->result == TWIST_ERR_USE_SSL,
         "starttls: --ssl-reqd with no credentials does not");
  twist_transfer_free (t);

  /* Not asked for: the bind is written at once, as it was.  */
  t = starttls_transfer ("ldap://cn=alice:secret@127.0.0.1/dc=x", TWIST_USE_SSL_NONE);
  l = twist_ldap_new (t, 0);
  check (sent (l, "secret") && !sent (l, STARTTLS_OID),
         "starttls: without --ssl nothing is asked for");
  twist_transfer_free (t);
}

int
main (void)
{
  test_ldap ();
  test_ldap_names ();
  test_ldap_starttls ();
  return tests_finish ();
}
