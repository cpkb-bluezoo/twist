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

#include "fuzz.h"

/* FTP: the reply parser, the passive-mode addresses in 227 and 229 replies,
   and a whole transfer driven by replies, with data and its end.  The first
   byte says which URL (a file or a listing), how the replies are cut up, and
   whether to give the data; the rest is the replies, and after a 0xff byte
   the data.  */

static unsigned long events;

static void reply (void *u, int code, int final, const char *text, size_t n)
{
  (void) u; (void) code; (void) final;
  if (n > 0)
    events += (unsigned char) text[n - 1];
}
static void failure (void *u, int e) { (void) u; (void) e; events++; }

const char *const fuzz_tokens[] = {
  "220 ", "230 ", "331 ", "227 Entering Passive Mode (", "229 Entering Extended Passive Mode (|||",
  "|)", ")", "150 ", "226 ", "250 ", "257 ", "213 ", "200 ", "500 ", "530 ", "550 ", "\r\n", "211-", NULL
};

void
fuzz_seeds (void (*add) (const void *, size_t))
{
  static const char *seeds[] = {
    "\x00" "220 ready\r\n331 pass\r\n230 ok\r\n200 type\r\n229 Entering Extended Passive Mode (|||2000|)\r\n150 opening\r\n226 done\r\n",
    "\x01" "220-multi\r\n220 line\r\n230 ok\r\n200 t\r\n500 no epsv\r\n227 Entering Passive Mode (192,0,2,10,7,138).\r\n150 x\r\n226 y\r\n",
    "\x02" "220 x\r\n421 closing\r\n"
  };
  size_t i;

  for (i = 0; i < sizeof seeds / sizeof seeds[0]; i++)
    add (seeds[i], strlen (seeds[i] + 1) + 1);
}

int
LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
  struct twist_ftp_events ev;
  struct twist_ftp_parser *p;
  struct twist_dns_addr peer;
  twist_easy *easy;
  struct twist_ftp *f;
  char host[64], *text;
  int port;
  const uint8_t *cut, *rest = NULL;
  size_t n, restn = 0;

  if (size == 0)
    return 0;
  text = fuzz_string (data + 1, size - 1);
  twist_ftp_pasv (text, size - 1, host, sizeof host, &port);
  twist_ftp_epsv (text, size - 1, &port);
  free (text);

  memset (&ev, 0, sizeof ev);
  ev.reply = reply;
  ev.failure = failure;
  p = twist_ftp_parser_new (&ev);
  if (p == NULL)
    abort ();
  fuzz_feed ((fuzz_recv) twist_ftp_parser_receive, p, data + 1, size - 1,
             fuzz_piece (data[0] >> 2, size));
  twist_ftp_parser_free (p);

  /* The replies and the data are told apart by a 0xff.  */
  cut = memchr (data + 1, 0xff, size - 1);
  n = cut != NULL ? (size_t) (cut - (data + 1)) : size - 1;
  if (cut != NULL)
    {
      rest = cut + 1;
      restn = size - 1 - n - 1;
    }
  easy = twist_easy_init ();
  if (easy == NULL
      || twist_url_parse_int ((data[0] & 3) == 0 ? "ftp://127.0.0.1/pub/file.txt"
                              : (data[0] & 3) == 1 ? "ftp://alice:secret@127.0.0.1/pub/"
                              : "ftp://alice:secret@127.0.0.1/pub/f;type=a",
                              &easy->url) != TWIST_OK)
    abort ();
  easy->write_cb = fuzz_sink;
  /* The top two bits say whether TLS is wanted, and the handshake of an
     upgrade, if there is one, finishes half way through the replies.  */
  easy->use_ssl = (data[0] >> 6) % 3;
  f = twist_ftp_new (easy, 0);
  if (f == NULL)
    abort ();
  memset (&peer, 0, sizeof peer);
  peer.family = 4;
  peer.addr[0] = 127;
  peer.addr[3] = 1;
  snprintf (peer.text, sizeof peer.text, "127.0.0.1");
  twist_ftp_set_peer (f, &peer);
  fuzz_feed ((fuzz_recv) twist_ftp_receive, f, data + 1, n / 2,
             fuzz_piece (data[0] >> 2, size));
  twist_ftp_tls_done (f);
  fuzz_feed ((fuzz_recv) twist_ftp_receive, f, data + 1 + n / 2, n - n / 2,
             fuzz_piece (data[0] >> 2, size));
  twist_ftp_command (f);
  twist_ftp_data_port (f);
  twist_ftp_data_host (f);
  if (rest != NULL)
    {
      fuzz_feed ((fuzz_recv) twist_ftp_data, f, rest, restn,
                 fuzz_piece (data[0] >> 4, size));
      twist_ftp_data_eof (f);
    }
  twist_easy_cleanup (easy);
  return 0;
}
