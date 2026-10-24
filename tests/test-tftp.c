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

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

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
  struct twist_transfer *transfer;
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

  transfer = twist_transfer_new ();
  check (twist_url_parse_int ("tftp://127.0.0.1/hello", &transfer->url) == TWIST_OK,
         "tftp url");
  check (transfer->url->port == 69, "tftp port");
  t = twist_tftp_new (transfer, 0);
  test_tftp_is (t, rrq, sizeof rrq, "tftp rrq");
  check (!transfer->done, "tftp rrq open");
  twist_transfer_free (transfer);

  transfer = twist_transfer_new ();
  check (twist_url_parse_int ("tftp://127.0.0.1/hello?x=1", &transfer->url)
         == TWIST_OK, "tftp query url");
  t = twist_tftp_new (transfer, 0);
  test_tftp_is (t, rrq, sizeof rrq, "tftp query");
  twist_transfer_free (transfer);

  transfer = twist_transfer_new ();
  check (twist_url_parse_int ("tftp://127.0.0.1/", &transfer->url) == TWIST_OK,
         "tftp empty url");
  t = twist_tftp_new (transfer, 0);
  check (t != NULL && transfer->done && transfer->result == TWIST_ERR_URL,
         "tftp empty");
  twist_transfer_free (transfer);

  transfer = twist_transfer_new ();
  check (twist_url_parse_int ("tftp://127.0.0.1/a%00",
                              &transfer->url) == TWIST_OK,
         "tftp nul url");
  t = twist_tftp_new (transfer, 0);
  check (t != NULL && transfer->done && transfer->result == TWIST_ERR_URL,
         "tftp nul");
  twist_transfer_free (transfer);

  static char upload[] = "abc";

  transfer = twist_transfer_new ();
  check (twist_url_parse_int ("tftp://127.0.0.1/up",
                              &transfer->url) == TWIST_OK,
         "tftp put url");
  transfer->postfields = upload;
  transfer->postfieldsize = 3;
  transfer->postfieldsize_set = 1;
  t = twist_tftp_new (transfer, 0);
  test_tftp_is (t, wrq, sizeof wrq, "tftp wrq");
  twist_tftp_receive (t, ack0, sizeof ack0);
  test_tftp_is (t, data_abc, sizeof data_abc, "tftp data");
  check (!transfer->done, "tftp put open");
  twist_tftp_receive (t, ack1, sizeof ack1);
  check (transfer->done && transfer->result == TWIST_OK, "tftp put done");
  check (transfer->progress.ul_known && transfer->progress.size_ul == 3
         && transfer->progress.uploaded == 3, "tftp upload progress");
  transfer->postfields = NULL;
  twist_transfer_free (transfer);

  transfer = twist_transfer_new ();
  check (twist_url_parse_int ("tftp://127.0.0.1/cb",
                              &transfer->url) == TWIST_OK,
         "tftp read url");
  tftp_read (NULL, 0, 0, NULL);
  transfer->read_cb = tftp_read;
  t = twist_tftp_new (transfer, 0);
  test_tftp_is (t, wrq_cb, sizeof wrq_cb, "tftp wrq cb");
  twist_tftp_receive (t, ack0, sizeof ack0);
  test_tftp_is (t, data_xy, sizeof data_xy, "tftp data cb");
  twist_tftp_receive (t, ack1, sizeof ack1);
  check (transfer->done && transfer->result == TWIST_OK, "tftp read done");
  twist_transfer_free (transfer);

  transfer = twist_transfer_new ();
  check (twist_url_parse_int ("tftp://127.0.0.1/hello", &transfer->url) == TWIST_OK,
         "tftp get url");
  transfer->write_cb = mail_write;
  mail_body_len = 0;
  t = twist_tftp_new (transfer, 0);
  twist_tftp_receive (t, oack, sizeof oack);
  test_tftp_is (t, ack0, sizeof ack0, "tftp oack");
  check (!transfer->done, "tftp oack open");
  twist_tftp_receive (t, data_hi, sizeof data_hi);
  test_tftp_is (t, ack1, sizeof ack1, "tftp ack hi");
  check (mail_body_len == 2 && memcmp (mail_body, "hi", 2) == 0, "tftp body");
  check (transfer->progress.downloaded == 2, "tftp download progress");
  check (transfer->done && transfer->result == TWIST_OK, "tftp get done");
  twist_transfer_free (transfer);

  transfer = twist_transfer_new ();
  check (twist_url_parse_int ("tftp://127.0.0.1/hello", &transfer->url) == TWIST_OK,
         "tftp blocks url");
  t = twist_tftp_new (transfer, 0);
  memset (block, 'a', sizeof block);
  block[0] = 0;
  block[1] = 3;
  block[2] = 0;
  block[3] = 1;
  twist_tftp_receive (t, block, sizeof block);
  check (!transfer->done && transfer->size_download == 512, "tftp full");
  test_tftp_is (t, ack1, sizeof ack1, "tftp ack full");
  twist_tftp_receive (t, block, sizeof block);
  check (!transfer->done && transfer->size_download == 512, "tftp dup");
  block[3] = 3;
  twist_tftp_receive (t, block, 4 + 8);
  check (!transfer->done && transfer->size_download == 512, "tftp skip");
  test_tftp_is (t, ack1, sizeof ack1, "tftp ack held");
  block[3] = 2;
  twist_tftp_receive (t, block, 4);
  test_tftp_is (t, ack2, sizeof ack2, "tftp ack end");
  check (transfer->done && transfer->result == TWIST_OK
         && transfer->size_download == 512, "tftp end");
  twist_transfer_free (transfer);

  transfer = twist_transfer_new ();
  check (twist_url_parse_int ("tftp://127.0.0.1/hello", &transfer->url) == TWIST_OK,
         "tftp err url");
  t = twist_tftp_new (transfer, 0);
  twist_tftp_receive (t, err_pkt, sizeof err_pkt);
  check (transfer->done && transfer->result == TWIST_ERR_FILE, "tftp missing");
  twist_transfer_free (transfer);

  transfer = twist_transfer_new ();
  check (twist_url_parse_int ("tftp://127.0.0.1/hello", &transfer->url) == TWIST_OK,
         "tftp big url");
  t = twist_tftp_new (transfer, 0);
  twist_tftp_receive (t, oack_big, sizeof oack_big);
  check (transfer->done && transfer->result == TWIST_ERR_PROTOCOL,
         "tftp big blk");
  check (t != NULL && twist_tftp_packet (t, NULL)[1] == 5, "tftp error op");
  twist_transfer_free (transfer);

  transfer = twist_transfer_new ();
  check (twist_url_parse_int ("tftp://127.0.0.1/hello", &transfer->url) == TWIST_OK,
         "tftp bad url");
  t = twist_tftp_new (transfer, 0);
  twist_tftp_receive (t, oack_bad, sizeof oack_bad);
  check (transfer->done && transfer->result == TWIST_ERR_PROTOCOL,
         "tftp bad oack");
  twist_transfer_free (transfer);

  transfer = twist_transfer_new ();
  check (twist_url_parse_int ("tftp://127.0.0.1/hello", &transfer->url) == TWIST_OK,
         "tftp time url");
  t = twist_tftp_new (transfer, 0);
  for (i = 0; i < 8 && !transfer->done; i++)
    twist_tftp_timeout (t);
  check (transfer->done && transfer->result == TWIST_ERR_CONNECT && i == 6,
         "tftp timeout");
  twist_transfer_free (transfer);

  transfer = twist_transfer_new ();
  check (twist_url_parse_int ("tftp://127.0.0.1/hello", &transfer->url) == TWIST_OK,
         "tftp proxy url");
  check (twist_transfer_setopt (transfer, TWISTOPT_PROXY, "http://127.0.0.1:9")
         == TWIST_OK, "tftp proxy set");
  t = twist_tftp_new (transfer, 0);
  check (t != NULL && transfer->done
         && transfer->result == TWIST_ERR_UNSUPPORTED,
         "tftp proxy");
  twist_transfer_free (transfer);
}

static struct sockaddr_in
from4 (const char *ip, int port)
{
  struct sockaddr_in sin;

  memset (&sin, 0, sizeof sin);
  sin.sin_family = AF_INET;
  sin.sin_port = htons ((uint16_t) port);
  inet_pton (AF_INET, ip, &sin.sin_addr);
  return sin;
}

static struct sockaddr_in6
from6 (const char *ip, int port)
{
  struct sockaddr_in6 sin;

  memset (&sin, 0, sizeof sin);
  sin.sin6_family = AF_INET6;
  sin.sin6_port = htons ((uint16_t) port);
  inet_pton (AF_INET6, ip, &sin.sin6_addr);
  return sin;
}

static int
accepts4 (struct twist_tftp *t, const char *ip, int port)
{
  struct sockaddr_in sin = from4 (ip, port);

  return twist_tftp_accept_source (t, (struct sockaddr *) &sin, sizeof sin);
}

static int
accepts6 (struct twist_tftp *t, const char *ip, int port)
{
  struct sockaddr_in6 sin = from6 (ip, port);

  return twist_tftp_accept_source (t, (struct sockaddr *) &sin, sizeof sin);
}

/* RFC 1350 section 4: the server answers from a port of its own, and the
   client goes on with that port only.  A datagram from anywhere else is not
   the transfer's, whatever it says.  It used to be taken, and the rest of the
   transfer was then sent to whoever sent it.  */
static void
test_tftp_source (void)
{
  struct twist_transfer *transfer = twist_transfer_new ();
  struct twist_tftp *t;
  struct twist_dns_addr a4;
  struct twist_dns_addr a6;

  memset (&a4, 0, sizeof a4);
  a4.family = 4;
  inet_pton (AF_INET, "192.0.2.1", a4.addr);
  memset (&a6, 0, sizeof a6);
  a6.family = 6;
  inet_pton (AF_INET6, "2001:db8::1", a6.addr);

  check (twist_url_parse_int ("tftp://192.0.2.1/hello", &transfer->url)
         == TWIST_OK, "source url");
  t = twist_tftp_new (transfer, 0);
  twist_tftp_set_dest (t, &a4, 69);
  check (!accepts4 (t, "198.51.100.7", 5000),
         "a stranger before the first reply is not taken");
  check (!accepts4 (t, "192.0.2.2", 5000),
         "a neighbour of the server is not taken");
  check (accepts4 (t, "192.0.2.1", 5000),
         "the server's first reply is taken");
  check (accepts4 (t, "192.0.2.1", 5000), "and the ones after it");
  check (!accepts4 (t, "192.0.2.1", 5001),
         "the server's address on another port is not taken");
  check (!accepts4 (t, "198.51.100.7", 5000),
         "a stranger on the same port is not taken");
  check (!accepts4 (t, "198.51.100.7", 69), "nor from port 69");
  check (accepts4 (t, "192.0.2.1", 5000), "the server is still heard");
  twist_transfer_free (transfer);

  transfer = twist_transfer_new ();
  check (twist_url_parse_int ("tftp://[2001:db8::1]/hello", &transfer->url)
         == TWIST_OK, "v6 source url");
  t = twist_tftp_new (transfer, 0);
  twist_tftp_set_dest (t, &a6, 69);
  check (!accepts6 (t, "2001:db8::2", 5000), "v6: a stranger is not taken");
  check (!accepts4 (t, "192.0.2.1", 5000), "v6: another family is not taken");
  check (accepts6 (t, "2001:db8::1", 5000), "v6: the server's reply is taken");
  check (!accepts6 (t, "2001:db8::1", 5001), "v6: another port is not taken");
  check (!accepts6 (t, "2001:db8::2", 5000), "v6: a stranger is still not");
  twist_transfer_free (transfer);
}

int
main (void)
{
  test_tftp ();
  test_tftp_source ();
  return tests_finish ();
}
