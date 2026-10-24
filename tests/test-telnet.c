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

#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

static uint8_t text[8192];
static size_t text_len;

static size_t
collect (char *ptr, size_t size, size_t nmemb, void *user)
{
  size_t n = size * nmemb;

  (void) user;
  if (text_len + n > sizeof text)
    n = sizeof text - text_len;
  memcpy (text + text_len, ptr, n);
  text_len += n;
  return size * nmemb;
}

static size_t
telnet_recv (void *obj, const uint8_t *data, size_t len)
{
  return twist_telnet_receive (obj, data, len);
}

static size_t
unhex (const char *h, uint8_t *out)
{
  size_t n = 0;

  for (; h[0] != 0 && h[1] != 0; h += 2)
    {
      unsigned v;

      sscanf (h, "%2x", &v);
      out[n++] = (uint8_t) v;
    }
  return n;
}

/* Whether N bytes at P are what the hex string says.  */
static int
is_hex (const uint8_t *p, size_t n, const char *hex)
{
  uint8_t want[2048];
  size_t m = unhex (hex, want);

  return m == n && (n == 0 || memcmp (p, want, n) == 0);
}

static struct twist_telnet *
session (twist_transfer **out, const char *const *opts, const char *user)
{
  twist_transfer *transfer = twist_transfer_new ();
  struct twist_slist *list = NULL;

  check (twist_url_parse_int ("telnet://127.0.0.1/",
                              &transfer->url) == TWIST_OK,
         "telnet url");
  for (; opts != NULL && *opts != NULL; opts++)
    list = twist_slist_append (list, *opts);
  if (list != NULL)
    {
      /* The list is the caller's; it is kept for as long as the handle.  */
      twist_transfer_setopt (transfer, TWISTOPT_TELNETOPTIONS, list);
    }
  if (user != NULL)
    twist_transfer_setopt (transfer, TWISTOPT_USERNAME, user);
  transfer->write_cb = collect;
  text_len = 0;
  *out = transfer;
  return twist_telnet_new (transfer, 0);
}

static void
session_end (twist_transfer *transfer)
{
  struct twist_slist *list = transfer->telnet_options;

  twist_transfer_free (transfer);
  twist_slist_free_all (list);
}

/* What curl 8.5.0 sent and wrote for the same server, taken from a real run
   against a scripted peer.  Each CHUNK is one read of the server's bytes,
   which matters: the options that are wanted are asked for after the chunk
   with the server's first command in it.  */
#define ONE_BYTE_B "ff","fb","01","ff","fd","03","ff","fb","03","ff","fd","00","ff","fd","18","ff","fd","1f","ff","fd","27","ff","fd","23"

struct oracle
{
  const char *name;
  const char *opts[8];
  const char *user;
  const char *chunks[40];
  const char *text;
  const char *sent;
};

static const struct oracle oracles[] = {
  { "A",
    { NULL }, NULL,
    { "68656c6c6f0d0a", "610d00620d0a", "41ff4142", "fffb01", "4344", NULL },
    "68656c6c6f0d0a610d620d0a41424344",
    "fffd01fffb00fffd00fffb03fffd03" },
  { "B",
    { NULL }, NULL,
    { "fffb01fffd03fffb03fffd00fffd18fffd1ffffd27fffd23", "fffa1801fff0", NULL },
    "",
    "fffd01fffb03fffd03fffb00fffc18fffb1ffffa1f00000000fff0fffc27"
    "fffc23fffd00fffa1800fff0" },
  { "B1",
    { NULL }, NULL,
    { "ff","fb","01","ff","fd","03","ff","fb","03","ff","fd","00","ff","fd","18","ff","fd","1f","ff","fd","27","ff","fd","23", "fffa1801fff0", NULL },
    "",
    "fffd01fffb00fffd00fffb03fffd03fffc18fffb1ffffa1f00000000fff0"
    "fffc27fffc23fffa1800fff0" },
  { "D",
    { "TTYPE=vt100", "XDISPLOC=host:0", "NEW_ENV=A,B", "NEW_ENV=C", "WS=80x24", "BINARY=0", NULL }, NULL,
    { "fffd18fffd23fffd27fffd1ffffd00", "fffa1801fff0fffa2301fff0fffa2701fff0", NULL },
    "",
    "fffb18fffb23fffb27fffb1ffffa1f00500018fff0fffc00fffb03fffd03"
    "fffa18007674313030fff0fffa2300686f73743a30fff0fffa2700004101"
    "420043fff0" },
  { "D2",
    { NULL }, "bob",
    { "fffd18fffd23fffd27fffd1ffffd00", "fffa1801fff0fffa2301fff0fffa2701fff0", NULL },
    "",
    "fffc18fffc23fffb27fffb1ffffa1f00000000fff0fffb00fffd00fffb03"
    "fffd03fffa1800fff0fffa2300fff0fffa2700005553455201626f62fff0" },
  { "D3",
    { "WS=255x300", NULL }, NULL,
    { "fffd1f", NULL },
    "",
    "fffb1ffffa1f00ffff012cfff0fffb00fffd00fffb03fffd03" },
  { "K6",
    { "ws=10X20", "ttype=abc", NULL }, NULL,
    { "fffd18", "fffd1f", NULL },
    "",
    "fffb18fffb00fffd00fffb03fffd03fffb1ffffa1f000a0014fff0" },
  { "K7",
    { "TTYPE=caf\303\251", NULL }, NULL,
    { "fffd18", NULL },
    "",
    "fffc18fffb00fffd00fffb03fffd03" },
  { "SB1",
    { "TTYPE=xterm", NULL }, NULL,
    { "fffd18", "fffa1801fffd03", NULL },
    "",
    "fffb18fffb00fffd00fffb03fffd03fffa1800787465726dfff0" },
  { "SB2",
    { "TTYPE=xterm", NULL }, NULL,
    { "fffd18", "fffa18ffff01fff0", NULL },
    "",
    "fffb18fffb00fffd00fffb03fffd03fffa1800787465726dfff0" },
  { "SB3",
    { NULL }, "bob",
    { "fffd27", "fffaFFF0fffa2701fff0", NULL },
    "",
    "fffb27fffb00fffd00fffb03fffd03fffa2700005553455201626f62fff0" },
  { "WD",
    { NULL }, NULL,
    { "fffb01", "fffc01", "fffd03", "fffe03", NULL },
    "",
    "fffd01fffb00fffd00fffb03fffd03fffe01fffc03" },
  { "NOIAC",
    { NULL }, NULL,
    { "323230206869210d0a", NULL },
    "323230206869210d0a",
    "" },
  { "CMDS",
    { NULL }, NULL,
    { "61fff1fff2fff562", NULL },
    "6162",
    "" },
  { "UNK",
    { NULL }, NULL,
    { "fffb", "c8", NULL },
    "",
    "fffec8fffb00fffd00fffb03fffd03" },
  { "UNK2",
    { NULL }, NULL,
    { "fffbc8fffdc8fffcc9fffec9", NULL },
    "",
    "fffec8fffcc8fffb00fffd00fffb03fffd03" },
  { "BIN1",
    { "BINARY=1", "binary=2", NULL }, NULL,
    { "fffd00fffb00", NULL },
    "",
    "fffc00fffe00fffb03fffd03" },
  { "LONG",
    { "TTYPE=0123456789012345678901234567890123456789", NULL }, NULL,
    { "fffd18", "fffa1801fff0", NULL },
    "",
    "fffb18fffb00fffd00fffb03fffd03fffa18003031323334353637383930"
    "3132333435363738393031323334353637383930fff0" },
  { "ENV",
    { "NEW_ENV=ONLY", "NEW_ENV=K,V,W", "new_env=X,", NULL }, NULL,
    { "fffd27", "fffa2701fff0", NULL },
    "",
    "fffb27fffb00fffd00fffb03fffd03fffa2700004f4e4c59004b01562c57"
    "005801fff0" },
  { "XD",
    { "XDISPLOC=:0.0", NULL }, NULL,
    { "fffd23", "fffa2301fff0", NULL },
    "",
    "fffb23fffb00fffd00fffb03fffd03fffa23003a302e30fff0" },
  { "WS1",
    { "WS=1x1", NULL }, NULL,
    { "fffd1f", NULL },
    "",
    "fffb1ffffa1f00010001fff0fffb00fffd00fffb03fffd03" },
  { "WS2",
    { "WS=65535x65535", NULL }, NULL,
    { "fffd1f", NULL },
    "",
    "fffb1ffffa1ffffffffffffffffffff0fffb00fffd00fffb03fffd03" },
  { "WS4",
    { "WS=5x65536", NULL }, NULL,
    { "fffd1f", NULL },
    "",
    "fffb1ffffa1f00000000fff0fffb00fffd00fffb03fffd03" },
  { "EMPTY",
    { "TTYPE=", NULL }, NULL,
    { "fffd18", "fffa1801fff0", NULL },
    "",
    "fffb18fffb00fffd00fffb03fffd03fffa1800fff0" },
  { "BIGSB",
    { "TTYPE=t", NULL }, NULL,
    { "fffd18", "fffa18414141414141414141414141414141414141414141414141414141"
        "414141414141414141414141414141414141414141414141414141414141"
        "414141414141414141414141414141414141414141414141414141414141"
        "414141414141414141414141414141414141414141414141414141414141"
        "414141414141414141414141414141414141414141414141414141414141"
        "414141414141414141414141414141414141414141414141414141414141"
        "414141414141414141414141414141414141414141414141414141414141"
        "414141414141414141414141414141414141414141414141414141414141"
        "414141414141414141414141414141414141414141414141414141414141"
        "414141414141414141414141414141414141414141414141414141414141"
        "414141414141414141414141414141414141414141414141414141414141"
        "414141414141414141414141414141414141414141414141414141414141"
        "414141414141414141414141414141414141414141414141414141414141"
        "414141414141414141414141414141414141414141414141414141414141"
        "414141414141414141414141414141414141414141414141414141414141"
        "414141414141414141414141414141414141414141414141414141414141"
        "414141414141414141414141414141414141414141414141414141414141"
        "414141414141414141414141414141414141414141414141414141414141"
        "414141414141414141414141414141414141414141414141414141414141"
        "414141414141414141414141414141414141414141414141414141414141"
        "414141fff0", NULL },
    "",
    "fffb18fffb00fffd00fffb03fffd03fffa180074fff0" },
};

static void
run_oracle (const struct oracle *o)
{
  twist_transfer *transfer;
  struct twist_telnet *t = session (&transfer, o->opts, o->user);
  uint8_t chunk[1024];
  const uint8_t *sent;
  size_t sent_n = 0;
  size_t i;

  check (t != NULL && !transfer->done, o->name);
  for (i = 0; o->chunks[i] != NULL; i++)
    {
      size_t n = unhex (o->chunks[i], chunk);

      check (twist_telnet_receive (t, chunk, n) == n, o->name);
    }
  sent = twist_telnet_sent (t, &sent_n);
  check (is_hex (sent, sent_n, o->sent), o->name);
  check (is_hex (text, text_len, o->text), o->name);
  check (!transfer->done, o->name);
  session_end (transfer);
}

/* The text is the same however the server's bytes are cut up.  What is sent
   in answer may not be, since the options we want are asked for after the
   chunk that held the first command.  */
static void
run_split (const struct oracle *o, size_t split)
{
  twist_transfer *transfer;
  struct twist_telnet *t = session (&transfer, o->opts, o->user);
  uint8_t all[2048];
  size_t n = 0;
  size_t i;

  for (i = 0; o->chunks[i] != NULL; i++)
    n += unhex (o->chunks[i], all + n);
  feed_bin (telnet_recv, t, all, n, split);
  check (is_hex (text, text_len, o->text), o->name);
  check (!transfer->done, o->name);
  session_end (transfer);
}

static void
test_oracles (void)
{
  static const size_t splits[] = { 1, 2, 3, 5, 64 };
  size_t i, j;

  for (i = 0; i < sizeof oracles / sizeof oracles[0]; i++)
    {
      run_oracle (&oracles[i]);
      for (j = 0; j < sizeof splits / sizeof splits[0]; j++)
        run_split (&oracles[i], splits[j]);
    }
}

static void
test_input_escape (void)
{
  twist_transfer *transfer;
  struct twist_telnet *t = session (&transfer, NULL, NULL);
  static const uint8_t in[] = { 'a', 0xff, 'b' };
  uint8_t *big = malloc (10000);
  const uint8_t *sent;
  size_t n = 0;
  size_t i;

  twist_telnet_input (t, in, sizeof in);
  sent = twist_telnet_sent (t, &n);
  check (is_hex (sent, n, "61ffff62"), "a 255 in the input is doubled");
  check (transfer->progress.uploaded == 3, "the input counts as it was read");
  twist_telnet_sent_clear (t);
  twist_telnet_input (t, in, 0);
  sent = twist_telnet_sent (t, &n);
  check (n == 0, "no input, nothing sent");
  /* More than is escaped at once.  */
  memset (big, 0xff, 10000);
  twist_telnet_input (t, big, 10000);
  sent = twist_telnet_sent (t, &n);
  check (n == 20000, "ten thousand 255s are twenty thousand");
  for (i = 0; i < n; i++)
    if (sent[i] != 0xff)
      {
        check (0, "every byte of them is 255");
        break;
      }
  free (big);
  session_end (transfer);
}

/* A carriage return is followed by a NUL or a line feed, but curl takes the
   next byte as text even if it is IAC, so that a command there is written to
   the output.  Here it is a command.  */
static void
test_cr_then_command (void)
{
  twist_transfer *transfer;
  struct twist_telnet *t = session (&transfer, NULL, NULL);
  static const uint8_t in[] = { 'a', '\r', 0xff, 0xfd, 0x03, 'b' };
  const uint8_t *sent;
  size_t n = 0;

  twist_telnet_receive (t, in, sizeof in);
  sent = twist_telnet_sent (t, &n);
  check (is_hex (text, text_len, "610d62"), "text around a command after a CR");
  check (is_hex (sent, n, "fffb03fffb00fffd00fffd03"),
         "and the command is answered");
  session_end (transfer);
}

static void
test_asks_once (void)
{
  twist_transfer *transfer;
  struct twist_telnet *t = session (&transfer, NULL, NULL);
  static const uint8_t will_echo[] = { 0xff, 0xfb, 0x01 };
  size_t n1 = 0, n2 = 0;

  twist_telnet_receive (t, will_echo, sizeof will_echo);
  twist_telnet_sent (t, &n1);
  check (n1 == 3 + 12, "the DO ECHO and the options we want");
  twist_telnet_receive (t, will_echo, sizeof will_echo);
  twist_telnet_sent (t, &n2);
  check (n2 == n1, "a command again asks for nothing more");
  session_end (transfer);
}

static void
test_counts_text (void)
{
  twist_transfer *transfer;
  struct twist_telnet *t = session (&transfer, NULL, NULL);
  static const uint8_t in[] = { 'a', 'b', 0xff, 0xfb, 0x01, 'c' };

  twist_telnet_receive (t, in, sizeof in);
  check (transfer->size_download == 3 && transfer->progress.downloaded == 3,
         "what is downloaded is the text, not the commands");
  session_end (transfer);
}

static void
option_error (const char *opt, int code, const char *words)
{
  twist_transfer *transfer;
  const char *list[2];
  struct twist_telnet *t;
  const char *err;

  list[0] = opt;
  list[1] = NULL;
  t = session (&transfer, list, NULL);
  err = twist_transfer_error (transfer);
  check (t != NULL && transfer->done && transfer->result == code, opt);
  check (err != NULL && strstr (err, words) != NULL, opt);
  session_end (transfer);
}

static void
test_option_errors (void)
{
  twist_transfer *transfer;
  struct twist_telnet *t;

  option_error ("foo", TWIST_ERR_OPTION_SYNTAX, "syntax error in telnet option: foo");
  option_error ("TTYPE", TWIST_ERR_OPTION_SYNTAX, "TTYPE");
  option_error ("WS=bad", TWIST_ERR_OPTION_SYNTAX, "WS=bad");
  option_error ("WS=0x5", TWIST_ERR_OPTION_SYNTAX, "WS=0x5");
  option_error ("WS=65536x5", TWIST_ERR_OPTION_SYNTAX, "WS=65536x5");
  option_error ("WS=5x", TWIST_ERR_OPTION_SYNTAX, "WS=5x");
  option_error ("FOO=bar", TWIST_ERR_UNKNOWN_OPTION, "unknown telnet option FOO=bar");
  option_error ("TTYPEX=bar", TWIST_ERR_UNKNOWN_OPTION, "TTYPEX=bar");
  option_error ("NEW_ENVS=a", TWIST_ERR_UNKNOWN_OPTION, "NEW_ENVS=a");
  /* A user name that is not ASCII cannot be an environment variable here.  */
  t = session (&transfer, NULL, "caf\303\251");
  check (t != NULL && transfer->done && transfer->result == TWIST_ERR_INVAL,
         "a user name with a byte above 127");
  session_end (transfer);
  /* The user name of the URL is the same as one given.  */
  transfer = twist_transfer_new ();
  check (twist_url_parse_int ("telnet://bob@127.0.0.1/", &transfer->url) == TWIST_OK,
         "url with a user");
  transfer->write_cb = collect;
  t = twist_telnet_new (transfer, 0);
  {
    static const uint8_t ask[] = { 0xff, 0xfd, 0x27 };
    static const uint8_t send[] = { 0xff, 0xfa, 0x27, 0x01, 0xff, 0xf0 };
    static const uint8_t reply[] = { 0xff, 0xfa, 0x27, 0x00, 0x00, 'U', 'S',
                                     'E', 'R', 0x01, 'b', 'o', 'b', 0xff,
                                     0xf0 };
    const uint8_t *sent;
    size_t n = 0;

    twist_telnet_receive (t, ask, sizeof ask);
    twist_telnet_receive (t, send, sizeof send);
    sent = twist_telnet_sent (t, &n);
    check (n > sizeof reply && memcmp (sent, "\xff\xfb\x27", 3) == 0
           && memcmp (sent + n - sizeof reply, reply, sizeof reply) == 0,
           "the user in the URL is the USER variable");
  }
  twist_transfer_free (transfer);
}

static void
test_closed (void)
{
  twist_transfer *transfer;
  struct twist_telnet *t = session (&transfer, NULL, NULL);

  twist_telnet_closed (t, TWIST_ERR_CLOSED);
  check (transfer->done && transfer->result == TWIST_OK,
         "the server closing ends the session");
  twist_telnet_closed (t, TWIST_ERR_CONNECT);
  check (transfer->result == TWIST_OK, "and only once");
  session_end (transfer);
  t = session (&transfer, NULL, NULL);
  twist_telnet_closed (t, TWIST_ERR_CONNECT);
  check (transfer->done && transfer->result == TWIST_ERR_CONNECT,
         "any other end is an error");
  session_end (transfer);
}

static size_t
refuse (char *ptr, size_t size, size_t nmemb, void *user)
{
  (void) ptr;
  (void) size;
  (void) nmemb;
  (void) user;
  return 0;
}

static void
test_write_refused (void)
{
  twist_transfer *transfer;
  struct twist_telnet *t = session (&transfer, NULL, NULL);

  transfer->write_cb = refuse;
  twist_telnet_receive (t, (const uint8_t *) "x", 1);
  check (transfer->done && transfer->result == TWIST_ERR_ABORTED,
         "a write callback that takes nothing ends the transfer");
  session_end (transfer);
}

/* ---- a server on the loopback ---- */

struct peer
{
  int listen_fd;
  int port;
  pthread_t thread;
  /* Sent as soon as it is connected to.  */
  const uint8_t *script;
  size_t script_len;
  /* The connection is closed once this many bytes have come, or this long
     after it began, whichever is first; and a nap after each read.  */
  size_t until;
  unsigned linger_ms;
  unsigned nap_us;
  int rcvbuf;
  uint8_t *got;
  size_t got_len;
  size_t got_cap;
};

static void *
peer_run (void *arg)
{
  struct peer *p = arg;
  struct pollfd fd;
  struct timespec t0, now;
  int c;

  fd.fd = p->listen_fd;
  fd.events = POLLIN;
  if (poll (&fd, 1, 10000) <= 0)
    return NULL;
  c = accept (p->listen_fd, NULL, NULL);
  if (c < 0)
    return NULL;
  clock_gettime (CLOCK_MONOTONIC, &t0);
  if (p->script_len > 0 && write (c, p->script, p->script_len) < 0)
    {
      close (c);
      return NULL;
    }
  for (;;)
    {
      uint8_t buf[16384];
      long waited;
      ssize_t n;

      if (p->until != 0 && p->got_len >= p->until)
        break;
      clock_gettime (CLOCK_MONOTONIC, &now);
      waited = (now.tv_sec - t0.tv_sec) * 1000
               + (now.tv_nsec - t0.tv_nsec) / 1000000;
      if (waited > 20000 || (p->linger_ms != 0 && waited >= p->linger_ms))
        break;
      fd.fd = c;
      if (poll (&fd, 1, 20) <= 0)
        continue;
      n = read (c, buf, p->nap_us != 0 ? 8192 : sizeof buf);
      if (n <= 0)
        break;
      if (p->got_len + (size_t) n > p->got_cap)
        {
          p->got_cap = (p->got_len + (size_t) n) * 2;
          p->got = realloc (p->got, p->got_cap);
        }
      memcpy (p->got + p->got_len, buf, (size_t) n);
      p->got_len += (size_t) n;
      if (p->nap_us != 0)
        usleep (p->nap_us);
    }
  close (c);
  return NULL;
}

static int
peer_start (struct peer *p)
{
  struct sockaddr_in sin;
  socklen_t len = sizeof sin;

  p->listen_fd = socket (AF_INET, SOCK_STREAM, 0);
  if (p->listen_fd < 0)
    return -1;
  if (p->rcvbuf != 0)
    setsockopt (p->listen_fd, SOL_SOCKET, SO_RCVBUF, &p->rcvbuf,
                sizeof p->rcvbuf);
  memset (&sin, 0, sizeof sin);
  sin.sin_family = AF_INET;
  sin.sin_addr.s_addr = htonl (INADDR_LOOPBACK);
  if (bind (p->listen_fd, (struct sockaddr *) &sin, sizeof sin) != 0
      || listen (p->listen_fd, 2) != 0
      || getsockname (p->listen_fd, (struct sockaddr *) &sin, &len) != 0)
    {
      close (p->listen_fd);
      return -1;
    }
  p->port = ntohs (sin.sin_port);
  return pthread_create (&p->thread, NULL, peer_run, p);
}

static void
peer_stop (struct peer *p)
{
  pthread_join (p->thread, NULL);
  close (p->listen_fd);
}

/* For a test where nothing is to connect: do not wait for it to.  */
static void
peer_cancel (struct peer *p)
{
  shutdown (p->listen_fd, SHUT_RDWR);
  peer_stop (p);
}

static void
peer_free (struct peer *p)
{
  free (p->got);
  p->got = NULL;
}

static twist_transfer *
live_transfer (const struct peer *p)
{
  twist_transfer *transfer = twist_transfer_new ();
  char url[64];

  snprintf (url, sizeof url, "telnet://127.0.0.1:%d/ignored?x", p->port);
  twist_transfer_setopt (transfer, TWISTOPT_URL, url);
  twist_transfer_setopt (transfer, TWISTOPT_WRITEFUNCTION, collect);
  twist_transfer_setopt (transfer, TWISTOPT_TIMEOUT_MS, 30000L);
  text_len = 0;
  return transfer;
}

/* A read callback that gives STEP bytes at a time.  */
struct source
{
  const uint8_t *data;
  size_t len;
  size_t off;
  size_t step;
};

static size_t
source_read (char *ptr, size_t size, size_t nmemb, void *user)
{
  struct source *s = user;
  size_t n = s->len - s->off;

  if (n > s->step)
    n = s->step;
  if (n > size * nmemb)
    n = size * nmemb;
  memcpy (ptr, s->data + s->off, n);
  s->off += n;
  return n;
}

static size_t
source_abort (char *ptr, size_t size, size_t nmemb, void *user)
{
  (void) ptr;
  (void) size;
  (void) nmemb;
  (void) user;
  return TWIST_READFUNC_ABORT;
}

/* What a server sends comes out, the commands are not, and the server's
   close ends the session.  */
static void
test_live_text (void)
{
  static const uint8_t script[] = { 'h', 'i', '\r', '\n', 0xff, 0xfb, 0x01,
                                    'x' };
  struct peer p;
  twist_transfer *transfer;
  int rc;

  memset (&p, 0, sizeof p);
  p.script = script;
  p.script_len = sizeof script;
  /* The answers to the command: DO ECHO and the options we want.  */
  p.until = 15;
  if (peer_start (&p) != 0)
    {
      fputs ("test-telnet: no loopback; skipping the live tests\n", stderr);
      return;
    }
  transfer = live_transfer (&p);
  /* Nothing to send: an empty source, as /dev/null would be.  */
  {
    struct source none = { NULL, 0, 0, 1 };

    twist_transfer_setopt (transfer, TWISTOPT_READFUNCTION, source_read);
    twist_transfer_setopt (transfer, TWISTOPT_READDATA, &none);
    rc = check_perform (transfer);
  }
  peer_stop (&p);
  check (rc == TWIST_OK, "a session ends when the server closes");
  check (is_hex (text, text_len, "68690d0a78"), "its text, without commands");
  check (transfer->size_download == 5, "and counts it");
  peer_free (&p);
  twist_transfer_free (transfer);
}

static void
test_live_read_callback (void)
{
  static const uint8_t data[] = { 'o', 'n', 'e', 0xff, 't', 'w', 'o', '\n' };
  struct peer p;
  struct source src = { data, sizeof data, 0, 3 };
  twist_transfer *transfer;
  int rc;

  memset (&p, 0, sizeof p);
  p.until = sizeof data + 1;
  if (peer_start (&p) != 0)
    return;
  transfer = live_transfer (&p);
  twist_transfer_setopt (transfer, TWISTOPT_READFUNCTION, source_read);
  twist_transfer_setopt (transfer, TWISTOPT_READDATA, &src);
  rc = check_perform (transfer);
  peer_stop (&p);
  check (rc == TWIST_OK, "read callback: the transfer ends");
  check (p.got_len == sizeof data + 1
         && is_hex (p.got, p.got_len, "6f6e65ffff74776f0a"),
         "read callback: what it gave is sent, a 255 doubled");
  peer_free (&p);
  check (transfer->progress.uploaded == (long long) sizeof data,
         "read callback: and counted");
  twist_transfer_free (transfer);

  /* One that cannot read.  */
  memset (&p, 0, sizeof p);
  p.linger_ms = 5000;
  if (peer_start (&p) != 0)
    return;
  transfer = live_transfer (&p);
  twist_transfer_setopt (transfer, TWISTOPT_READFUNCTION, source_abort);
  rc = check_perform (transfer);
  peer_stop (&p);
  check (rc == TWIST_ERR_ABORTED, "a read callback that cannot read");
  peer_free (&p);
  twist_transfer_free (transfer);
}

struct late
{
  int fd;
  const char *text;
};

static void *
write_late (void *arg)
{
  struct late *l = arg;

  usleep (150000);
  if (write (l->fd, l->text, strlen (l->text)) < 0)
    return NULL;
  return NULL;
}

/* Standard input is watched: what is in the pipe at the start is sent, what
   is put in it later is sent too, and the pipe being open does not hold up
   the end of the session.  */
static void
test_live_pipe (void)
{
  struct peer p;
  twist_transfer *transfer;
  int pfd[2];
  pthread_t th;
  struct late late;
  int rc;

  memset (&p, 0, sizeof p);
  p.until = 5 + 5;
  if (pipe (pfd) != 0 || peer_start (&p) != 0)
    return;
  if (write (pfd[1], "first", 5) < 0)
    return;
  late.fd = pfd[1];
  late.text = "later";
  pthread_create (&th, NULL, write_late, &late);
  transfer = live_transfer (&p);
  twist_transfer_setopt (transfer, TWISTOPT_TELNET_INPUT_FD, (long) pfd[0]);
  rc = check_perform (transfer);
  pthread_join (th, NULL);
  peer_stop (&p);
  close (pfd[0]);
  close (pfd[1]);
  check (rc == TWIST_OK, "input pipe: the transfer ends");
  check (p.got_len == 10 && memcmp (p.got, "firstlater", 10) == 0,
         "input pipe: what was there and what came later");
  peer_free (&p);
  twist_transfer_free (transfer);
}

/* A descriptor that cannot be polled is read in steps: a file, and the null
   device.  */
static void
test_live_unpollable (void)
{
  struct peer p;
  twist_transfer *transfer;
  char path[] = "/tmp/twist-telnet-XXXXXX";
  int fd = mkstemp (path);
  int rc;

  if (fd < 0)
    return;
  if (write (fd, "from a file\n", 12) < 0)
    return;
  lseek (fd, 0, SEEK_SET);
  memset (&p, 0, sizeof p);
  p.until = 12;
  if (peer_start (&p) != 0)
    return;
  transfer = live_transfer (&p);
  twist_transfer_setopt (transfer, TWISTOPT_TELNET_INPUT_FD, (long) fd);
  rc = check_perform (transfer);
  peer_stop (&p);
  close (fd);
  unlink (path);
  check (rc == TWIST_OK, "input file: the transfer ends");
  check (p.got_len == 12 && memcmp (p.got, "from a file\n", 12) == 0,
         "input file: sent");
  peer_free (&p);
  twist_transfer_free (transfer);

  fd = open ("/dev/null", O_RDONLY);
  if (fd < 0)
    return;
  memset (&p, 0, sizeof p);
  p.linger_ms = 200;
  if (peer_start (&p) != 0)
    return;
  transfer = live_transfer (&p);
  twist_transfer_setopt (transfer, TWISTOPT_TELNET_INPUT_FD, (long) fd);
  rc = check_perform (transfer);
  peer_stop (&p);
  close (fd);
  check (rc == TWIST_OK && p.got_len == 0,
         "the null device: nothing to send, and the session goes on");
  peer_free (&p);
  twist_transfer_free (transfer);
}

/* The library takes no descriptor for granted.  With no read callback and no
   TWISTOPT_TELNET_INPUT_FD nothing is sent and the session is the server's,
   though the process's standard input has something in it, and that is left
   where it is.  A descriptor that is given is the caller's: it is open and
   unread past what was sent when the session is over.  */
static void
test_live_input_descriptor (void)
{
  struct peer p;
  twist_transfer *transfer;
  struct pollfd pf;
  int pfd[2];
  int saved;
  int rc;
  char buf[16];
  ssize_t n = 0;

  memset (&p, 0, sizeof p);
  p.linger_ms = 200;
  if (pipe (pfd) != 0 || peer_start (&p) != 0)
    return;
  if (write (pfd[1], "unread", 6) < 0)
    return;
  saved = dup (STDIN_FILENO);
  dup2 (pfd[0], STDIN_FILENO);
  transfer = live_transfer (&p);
  rc = check_perform (transfer);
  dup2 (saved, STDIN_FILENO);
  close (saved);
  peer_stop (&p);
  check (rc == TWIST_OK && p.got_len == 0, "no input: nothing is sent");
  pf.fd = pfd[0];
  pf.events = POLLIN;
  if (poll (&pf, 1, 0) == 1)
    n = read (pfd[0], buf, sizeof buf);
  check (n == 6 && memcmp (buf, "unread", 6) == 0,
         "and standard input was not read");
  peer_free (&p);
  check (twist_transfer_setopt (transfer, TWISTOPT_TELNET_INPUT_FD, -2L)
         == TWIST_ERR_INVAL, "a descriptor below -1 is refused");
  twist_transfer_free (transfer);

  memset (&p, 0, sizeof p);
  p.until = 3;
  if (peer_start (&p) != 0)
    return;
  if (write (pfd[1], "abc", 3) < 0)
    return;
  transfer = live_transfer (&p);
  twist_transfer_setopt (transfer, TWISTOPT_TELNET_INPUT_FD, (long) pfd[0]);
  rc = check_perform (transfer);
  peer_stop (&p);
  check (rc == TWIST_OK && p.got_len == 3 && memcmp (p.got, "abc", 3) == 0,
         "a descriptor that is given is read");
  check (fcntl (pfd[0], F_GETFD) != -1 && fcntl (pfd[1], F_GETFD) != -1,
         "and is still open afterwards");
  peer_free (&p);
  twist_transfer_free (transfer);
  close (pfd[0]);
  close (pfd[1]);
}

struct feed_pipe
{
  int fd;
  const uint8_t *data;
  size_t len;
};

static void *
feed_pipe_run (void *arg)
{
  struct feed_pipe *f = arg;
  size_t off = 0;

  while (off < f->len)
    {
      ssize_t n = write (f->fd, f->data + off, f->len - off);

      if (n <= 0)
        break;
      off += (size_t) n;
    }
  return NULL;
}

/* More than the connection takes is held until it can: all of it arrives,
   in order, and the end of the input is not the end of the session.  The
   input is the read callback, or a descriptor, which are held in different
   ways.  */
static void
backpressure (int from_pipe, const char *what)
{
  enum { SIZE = 4 * 1024 * 1024 };
  uint8_t *data = malloc (SIZE);
  struct peer p;
  struct source src;
  struct feed_pipe feed;
  pthread_t th;
  int pfd[2] = { -1, -1 };
  twist_transfer *transfer;
  size_t escapes = 0;
  size_t i;
  int rc;

  if (data == NULL)
    return;
  for (i = 0; i < SIZE; i++)
    {
      data[i] = (uint8_t) (i % 251);
      if (i % 4096 == 0)
        data[i] = 0xff;
      if (data[i] == 0xff)
        escapes++;
    }
  src.data = data;
  src.len = SIZE;
  src.off = 0;
  src.step = 16384;
  memset (&p, 0, sizeof p);
  p.until = SIZE + escapes;
  p.nap_us = 1000;
  p.rcvbuf = 4096;
  if ((from_pipe && pipe (pfd) != 0) || peer_start (&p) != 0)
    {
      free (data);
      return;
    }
  transfer = live_transfer (&p);
  if (from_pipe)
    {
      feed.fd = pfd[1];
      feed.data = data;
      feed.len = SIZE;
      pthread_create (&th, NULL, feed_pipe_run, &feed);
      twist_transfer_setopt (transfer, TWISTOPT_TELNET_INPUT_FD,
                             (long) pfd[0]);
    }
  else
    {
      twist_transfer_setopt (transfer, TWISTOPT_READFUNCTION, source_read);
      twist_transfer_setopt (transfer, TWISTOPT_READDATA, &src);
    }
  rc = check_perform (transfer);
  if (from_pipe)
    {
          pthread_join (th, NULL);
      close (pfd[0]);
      close (pfd[1]);
    }
  peer_stop (&p);
  check (rc == TWIST_OK, what);
  {
    size_t o = 0;
    int same = p.got_len == SIZE + escapes;

    for (i = 0; same && i < SIZE; i++)
      {
        if (p.got[o++] != data[i])
          same = 0;
        else if (data[i] == 0xff && p.got[o++] != 0xff)
          same = 0;
      }
    check (same, what);
  }
  peer_free (&p);
  twist_transfer_free (transfer);
  free (data);
}

static void
test_live_backpressure (void)
{
  backpressure (0, "a large upload from the read callback");
  backpressure (1, "a large upload from a descriptor");
}

/* Once the session is over nothing more is read from the input descriptor: it
   is wanted by whoever reads it next.  The loop goes on running.  */
static void
test_live_input_stops (void)
{
  struct peer p;
  twist_runtime *runtime;
  twist_transfer *transfer;
  struct timespec nap = { 0, 2000000 };
  int pfd[2];
  struct check_job job = { 0, 0, 0 };
  int i;
  char buf[16];
  ssize_t n = 0;
  struct pollfd pf;

  memset (&p, 0, sizeof p);
  p.linger_ms = 150;
  if (pipe (pfd) != 0 || peer_start (&p) != 0)
    return;
  runtime = twist_runtime_new ();
  transfer = live_transfer (&p);
  twist_transfer_setopt (transfer, TWISTOPT_TELNET_INPUT_FD, (long) pfd[0]);
  twist_runtime_start (runtime, transfer, check_job_done, &job);
  for (i = 0; i < 5000 && !job.done; i++)
    {
      twist_runtime_run_once (runtime, 0);
      nanosleep (&nap, NULL);
    }
  check (job.done, "input stops: the session ends");
  if (write (pfd[1], "late", 4) < 0)
    return;
  for (i = 0; i < 50; i++)
    {
      twist_runtime_run_once (runtime, 0);
      nanosleep (&nap, NULL);
    }
  pf.fd = pfd[0];
  pf.events = POLLIN;
  if (poll (&pf, 1, 0) == 1)
    n = read (pfd[0], buf, sizeof buf);
  check (n == 4 && memcmp (buf, "late", 4) == 0,
         "input stops: what came after the end is still there to be read");
  peer_stop (&p);
  peer_free (&p);
  twist_transfer_free (transfer);
  twist_runtime_free (runtime);
  close (pfd[0]);
  close (pfd[1]);
}

static void
test_live_failures (void)
{
  struct peer p;
  twist_transfer *transfer;
  struct twist_slist *opts;
  int rc;

  /* A bad option is found before there is a connection.  */
  memset (&p, 0, sizeof p);
  p.linger_ms = 100;
  if (peer_start (&p) != 0)
    return;
  transfer = live_transfer (&p);
  opts = twist_slist_append (NULL, "WS=bad");
  twist_transfer_setopt (transfer, TWISTOPT_TELNETOPTIONS, opts);
  rc = check_perform (transfer);
  peer_cancel (&p);
  check (rc == TWIST_ERR_OPTION_SYNTAX, "a bad option ends the transfer");
  check (twist_transfer_error (transfer) != NULL
         && strstr (twist_transfer_error (transfer), "WS=bad") != NULL,
         "and says which");
  check (p.got_len == 0, "before it connects");
  twist_transfer_free (transfer);
  twist_slist_free_all (opts);

  /* Nobody is there.  */
  memset (&p, 0, sizeof p);
  p.linger_ms = 1;
  if (peer_start (&p) != 0)
    return;
  peer_cancel (&p);
  transfer = live_transfer (&p);
  rc = check_perform (transfer);
  check (rc == TWIST_ERR_CONNECT, "a refused connection");
  twist_transfer_free (transfer);
}

int
main (void)
{
  /* A stuck session fails the test, and does not hold up the others.  */
  alarm (120);
  test_oracles ();
  test_input_escape ();
  test_cr_then_command ();
  test_asks_once ();
  test_counts_text ();
  test_option_errors ();
  test_closed ();
  test_write_refused ();
  test_live_text ();
  test_live_read_callback ();
  test_live_pipe ();
  test_live_unpollable ();
  test_live_input_descriptor ();
  test_live_backpressure ();
  test_live_input_stops ();
  test_live_failures ();
  return tests_finish ();
}
