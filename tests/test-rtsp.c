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

/* RTSP as the curl tool does it: one OPTIONS request, whatever the URL's
   path, and the reply written as the server sent it.  */

static char hdrs[1024];
static size_t hdrs_len;

static size_t
hdr_write (char *ptr, size_t size, size_t nmemb, void *user)
{
  size_t n = size * nmemb;

  (void) user;
  if (hdrs_len + n < sizeof hdrs)
    {
      memcpy (hdrs + hdrs_len, ptr, n);
      hdrs_len += n;
      hdrs[hdrs_len] = 0;
    }
  return n;
}

static size_t
rtsp_recv (void *obj, const uint8_t *data, size_t len)
{
  return twist_rtsp_receive (obj, data, len);
}

static struct twist_transfer *
make (const char *url)
{
  struct twist_transfer *transfer = twist_transfer_new ();

  check (twist_url_parse_int (url, &transfer->url) == TWIST_OK, url);
  transfer->write_cb = mail_write;
  transfer->header_cb = hdr_write;
  mail_body_len = 0;
  hdrs_len = 0;
  hdrs[0] = 0;
  return transfer;
}

static void
request_is (struct twist_transfer *transfer, const char *expect,
            const char *what)
{
  struct twist_rtsp *r = twist_rtsp_new (transfer, 0);
  size_t n = 0;
  const uint8_t *req = twist_rtsp_request (r, &n);

  check (r != NULL && !transfer->done && n == strlen (expect)
         && req != NULL && memcmp (req, expect, n) == 0, what);
  twist_transfer_free (transfer);
}

static void
test_request (void)
{
  struct twist_transfer *transfer;
  struct twist_slist *list;

  request_is (make ("rtsp://127.0.0.1/stream"),
              "OPTIONS * RTSP/1.0\r\nCSeq: 1\r\n"
              "User-Agent: twist/0.1\r\n\r\n", "rtsp request");
  request_is (make ("rtsp://127.0.0.1"),
              "OPTIONS * RTSP/1.0\r\nCSeq: 1\r\n"
              "User-Agent: twist/0.1\r\n\r\n", "rtsp no path");
  request_is (make ("rtsp://127.0.0.1/a/b?x=1"),
              "OPTIONS * RTSP/1.0\r\nCSeq: 1\r\n"
              "User-Agent: twist/0.1\r\n\r\n", "rtsp query");
  transfer = make ("rtsp://127.0.0.1/s");
  transfer->method = twist_strdup ("DESCRIBE");
  transfer->nobody = 1;
  transfer->postfields = twist_strdup ("body");
  request_is (transfer,
              "OPTIONS * RTSP/1.0\r\nCSeq: 1\r\n"
              "User-Agent: twist/0.1\r\n\r\n", "rtsp ignores -X -I -d");
  transfer = make ("rtsp://127.0.0.1/s");
  transfer->useragent = twist_strdup ("foo/1");
  list = twist_slist_append (NULL, "X-A: b");
  list = twist_slist_append (list, "X-B: c");
  transfer->headers = list;
  transfer->username = twist_strdup ("u");
  transfer->password = twist_strdup ("p");
  request_is (transfer,
              "OPTIONS * RTSP/1.0\r\nCSeq: 1\r\nUser-Agent: foo/1\r\n"
              "Authorization: Basic dTpw\r\nX-A: b\r\nX-B: c\r\n\r\n",
              "rtsp agent, auth, headers");
  twist_slist_free_all (list);
}

static void
refused (const char *header, int err, const char *what)
{
  struct twist_transfer *transfer = make ("rtsp://127.0.0.1/s");
  struct twist_slist *list = twist_slist_append (NULL, header);
  struct twist_rtsp *r;

  transfer->headers = list;
  r = twist_rtsp_new (transfer, 0);
  check (r != NULL && transfer->done && transfer->result == err, what);
  twist_transfer_free (transfer);
  twist_slist_free_all (list);
}

/* Feed REPLY in pieces of SPLIT bytes and say how it ended.  */
static int
reply (const char *text, size_t split, struct twist_transfer *transfer,
       int close_after)
{
  struct twist_rtsp *r = twist_rtsp_new (transfer, 0);

  feed_n (rtsp_recv, r, text, split);
  if (close_after && !transfer->done)
    twist_rtsp_closed (r, TWIST_ERR_CLOSED);
  return transfer->done ? transfer->result : -1;
}

static void
test_reply (void)
{
  static const size_t splits[] = { 1, 2, 3, 7, 1000 };
  struct twist_transfer *transfer;
  size_t i;

  for (i = 0; i < sizeof splits / sizeof splits[0]; i++)
    {
      transfer = make ("rtsp://127.0.0.1/s");
      check (reply ("RTSP/1.0 200 Fine  Thing\r\ncseq:   1\r\n"
                    "Content-Length: 5\r\nx-odd:v\r\n\r\nhello",
                    splits[i], transfer, 0) == TWIST_OK, "rtsp ok, no close");
      check (transfer->http_code == 200, "rtsp code");
      check (strcmp (hdrs, "RTSP/1.0 200 Fine  Thing\r\ncseq:   1\r\n"
                           "Content-Length: 5\r\nx-odd:v\r\n") == 0,
             "rtsp headers");
      check (mail_body_len == 5 && memcmp (mail_body, "hello", 5) == 0,
             "rtsp body");
      check (transfer->progress.downloaded == 5, "rtsp progress");
      twist_transfer_free (transfer);
    }
  transfer = make ("rtsp://127.0.0.1/s");
  check (reply ("RTSP/1.0 200 OK\r\nCSeq: 1\r\nContent-Length: 0\r\n\r\n",
                4, transfer, 0) == TWIST_OK, "rtsp empty body ends at once");
  twist_transfer_free (transfer);
  transfer = make ("rtsp://127.0.0.1/s");
  check (reply ("RTSP/1.0 200 OK\r\nCSeq: 1\r\n\r\nxx", 3, transfer, 0)
         == TWIST_OK && mail_body_len == 0,
         "rtsp no length, no body");
  twist_transfer_free (transfer);
  transfer = make ("rtsp://127.0.0.1/s");
  transfer->nobody = 1;
  check (reply ("RTSP/1.0 200 OK\r\nCSeq: 1\r\nContent-Length: 4\r\n\r\nabcd",
                5, transfer, 0) == TWIST_OK && mail_body_len == 0
         && strstr (hdrs, "Content-Length: 4") != NULL, "rtsp -I");
  twist_transfer_free (transfer);
}

static void
test_cseq (void)
{
  struct twist_transfer *transfer;

  transfer = make ("rtsp://127.0.0.1/s");
  check (reply ("RTSP/1.0 200 OK\r\nCSeq: 2\r\nContent-Length: 0\r\n\r\n", 6,
                transfer, 0) == TWIST_ERR_RTSP_CSEQ, "rtsp cseq mismatch");
  twist_transfer_free (transfer);
  transfer = make ("rtsp://127.0.0.1/s");
  check (reply ("RTSP/1.0 200 OK\r\nContent-Length: 0\r\n\r\n", 6, transfer, 0)
         == TWIST_ERR_RTSP_CSEQ, "rtsp cseq missing");
  twist_transfer_free (transfer);
  refused ("CSeq: 9", TWIST_ERR_RTSP_CSEQ, "rtsp cseq header");
  refused ("cseq:9", TWIST_ERR_RTSP_CSEQ, "rtsp cseq header, lower case");
  refused ("Session: abc", TWIST_ERR_INVAL, "rtsp session header");
  refused ("session:abc", TWIST_ERR_INVAL, "rtsp session header, lower case");
}

static void
test_status (void)
{
  struct twist_transfer *transfer;

  transfer = make ("rtsp://127.0.0.1/s");
  check (reply ("RTSP/1.0 404 Not Found\r\nCSeq: 1\r\nContent-Length: 0\r\n\r\n",
                9, transfer, 0) == TWIST_OK && transfer->http_code == 404,
         "rtsp 404 is not an error");
  twist_transfer_free (transfer);
  transfer = make ("rtsp://127.0.0.1/s");
  transfer->failonerror = 1;
  check (reply ("RTSP/1.0 404 Not Found\r\nCSeq: 1\r\nContent-Length: 0\r\n\r\n",
                9, transfer, 0) == TWIST_ERR_HTTP && transfer->http_code == 404,
         "rtsp -f");
  twist_transfer_free (transfer);
  transfer = make ("rtsp://127.0.0.1/s");
  transfer->failonerror = 1;
  check (reply ("RTSP/1.0 302 Found\r\nCSeq: 1\r\nContent-Length: 0\r\n\r\n",
                9, transfer, 0) == TWIST_OK, "rtsp -f, 302");
  twist_transfer_free (transfer);
  transfer = make ("rtsp://127.0.0.1/s");
  transfer->follow = 1;
  check (reply ("RTSP/1.0 302 Found\r\nCSeq: 1\r\nLocation: rtsp://x/y\r\n"
                "Content-Length: 0\r\n\r\n", 9, transfer, 0) == TWIST_OK
         && transfer->redirs == 0, "rtsp -L does not follow");
  twist_transfer_free (transfer);
}

static void
test_broken (void)
{
  struct twist_transfer *transfer;

  transfer = make ("rtsp://127.0.0.1/s");
  check (reply ("RTSP/1.1 200 OK\r\nCSeq: 1\r\n\r\n", 5, transfer, 0)
         == TWIST_ERR_PROTOCOL, "rtsp other version");
  twist_transfer_free (transfer);
  transfer = make ("rtsp://127.0.0.1/s");
  check (reply ("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n", 5, transfer, 1)
         == TWIST_ERR_CLOSED, "rtsp a reply that is not rtsp");
  twist_transfer_free (transfer);
  transfer = make ("rtsp://127.0.0.1/s");
  check (reply ("", 1, transfer, 1) == TWIST_ERR_CLOSED, "rtsp no reply");
  twist_transfer_free (transfer);
  transfer = make ("rtsp://127.0.0.1/s");
  check (reply ("RTSP/1.0 200 OK\r\nCSeq: 1\r\nContent-Length: 10\r\n\r\nabc",
                2, transfer, 1) == TWIST_ERR_PARTIAL && mail_body_len == 3,
         "rtsp short body");
  twist_transfer_free (transfer);
  transfer = make ("rtsp://127.0.0.1/s");
  check (reply ("RTSP/1.0 200 OK\r\nCSeq: 1\r\nCont", 2, transfer, 1)
         == TWIST_ERR_CLOSED, "rtsp closed in the headers");
  twist_transfer_free (transfer);
  transfer = make ("rtsp://127.0.0.1/s");
  check (reply ("RTSP/1.0 200 OK\r\nCSeq: 1\r\nContent-Length: x\r\n\r\n", 5,
                transfer, 1) == TWIST_ERR_PROTOCOL, "rtsp bad length");
  twist_transfer_free (transfer);
}

int
main (void)
{
  test_request ();
  test_reply ();
  test_cseq ();
  test_status ();
  test_broken ();
  return tests_finish ();
}
