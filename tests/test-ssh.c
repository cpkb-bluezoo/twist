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

#include <foxtrot/conn.h>
#include <foxtrot/crypto.h>
#include <foxtrot/key.h>
#include <foxtrot/status.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* The twist handler is the client; a foxtrot transport is the server, in
   the same process.  Each side's output is collected and handed to the
   other, so the exchange can be cut into pieces of any size.  */

#define PIPE_MAX 65536

struct pipe
{
  uint8_t data[PIPE_MAX];
  size_t len;
};

struct peer
{
  struct pipe out;
  gf_conn *conn;
  int established;
  int closed;
  uint32_t reason;
};

static uint64_t now_us = 1000000;

static int
pipe_write (struct pipe *p, const uint8_t *data, size_t len)
{
  if (p->len + len > sizeof p->data)
    return -1;
  memcpy (p->data + p->len, data, len);
  p->len += len;
  return 0;
}

static int
client_sink (void *user, const uint8_t *data, size_t len)
{
  return pipe_write (user, data, len);
}

static int
server_write (void *user, const uint8_t *data, size_t len)
{
  struct peer *p = user;

  return pipe_write (&p->out, data, len);
}

static int
server_message (void *user, const uint8_t *payload, size_t len)
{
  (void) user;
  (void) payload;
  (void) len;
  return 0;
}

static int
server_established (void *user, const gf_conn_info *info)
{
  struct peer *p = user;

  (void) info;
  p->established = 1;
  return 0;
}

static void
server_closed (void *user, int error, uint32_t reason, gf_slice text)
{
  struct peer *p = user;

  (void) error;
  (void) text;
  p->closed = 1;
  p->reason = reason;
}

static int
server_new (struct peer *p, gf_key **host)
{
  gf_conn_config cfg;
  gf_conn_events ev;

  memset (p, 0, sizeof *p);
  memset (&cfg, 0, sizeof cfg);
  memset (&ev, 0, sizeof ev);
  if (gf_key_generate (host, GF_KEY_ED25519, 0) != GF_OK)
    return -1;
  cfg.software = "testd_1";
  cfg.host_keys = host;
  cfg.nhost_keys = 1;
  ev.user = p;
  ev.write = server_write;
  ev.message = server_message;
  ev.established = server_established;
  ev.closed = server_closed;
  if (gf_conn_server_new (&p->conn, &cfg, &ev) != GF_OK)
    return -1;
  return gf_conn_start (p->conn, now_us) == GF_OK ? 0 : -1;
}

/* Take everything out of PIPE and give it to FN in pieces of CHUNK.  */
static size_t
drain (struct pipe *p, size_t chunk, void (*fn) (void *, const uint8_t *,
                                                 size_t), void *obj)
{
  size_t off = 0;
  size_t total = p->len;

  while (off < p->len)
    {
      size_t n = p->len - off;

      if (n > chunk)
        n = chunk;
      fn (obj, p->data + off, n);
      off += n;
    }
  p->len = 0;
  return total;
}

struct pair
{
  struct twist_ssh *ssh;
  struct peer *server;
  struct pipe c2s;
};

static void
to_client (void *obj, const uint8_t *data, size_t len)
{
  struct pair *pr = obj;

  twist_ssh_receive (pr->ssh, data, len);
}

static void
to_server (void *obj, const uint8_t *data, size_t len)
{
  struct pair *pr = obj;

  if (pr->server->conn != NULL)
    gf_conn_receive (pr->server->conn, now_us, data, len);
}

/* Run the exchange until nothing moves or the transfer ends.  */
static void
pump (struct pair *pr, struct twist_easy *easy, size_t chunk)
{
  int i;

  for (i = 0; i < 200 && !easy->done; i++)
    {
      size_t moved = 0;

      moved += drain (&pr->c2s, chunk, to_server, pr);
      moved += drain (&pr->server->out, chunk, to_client, pr);
      if (moved == 0)
        break;
    }
}

static struct twist_easy *
new_easy (struct twist_ssh **ssh, struct pair *pr, int verify)
{
  struct twist_easy *easy = twist_easy_init ();

  check (twist_url_parse_int ("sftp://alice@127.0.0.1/file", &easy->url)
         == TWIST_OK, "url");
  easy->verifypeer = verify;
  *ssh = twist_ssh_new (easy, 0);
  check (*ssh != NULL, "ssh new");
  pr->ssh = *ssh;
  memset (&pr->c2s, 0, sizeof pr->c2s);
  twist_ssh_set_sink (*ssh, client_sink, &pr->c2s);
  twist_ssh_set_time (*ssh, now_us);
  return easy;
}

/* Key exchange completes, and with verification off the transfer then
   stops because authentication is not written.  Run at several chunk
   sizes, down to one byte at a time.  */
static void
test_kex (size_t chunk)
{
  struct twist_easy *easy;
  struct twist_ssh *ssh;
  struct peer server;
  struct pair pr;
  gf_key *host = NULL;
  const char *detail;

  check (server_new (&server, &host) == 0, "server");
  pr.server = &server;
  easy = new_easy (&ssh, &pr, 0);
  check (twist_ssh_start (ssh) == TWIST_OK, "start");
  check (pr.c2s.len > 0, "identification sent");
  check (memcmp (pr.c2s.data, "SSH-2.0-twist_", 14) == 0, "ident text");
  pump (&pr, easy, chunk);
  /* The client finished as soon as its keys were in use; the server gets
     the rest of what it sent, its NEWKEYS and the disconnect.  */
  drain (&pr.c2s, chunk, to_server, &pr);
  check (server.established, "server established");
  check (server.closed && server.reason == GF_DISCONNECT_BY_APPLICATION,
         "server told goodbye");
  check (easy->done, "transfer ended");
  check (easy->result == TWIST_ERR_UNSUPPORTED, "unsupported after kex");
  detail = twist_easy_error (easy);
  check (detail != NULL && strstr (detail, "testd_1") != NULL
         && strstr (detail, "authentication") != NULL, "detail names peer");
  twist_easy_cleanup (easy);
  gf_conn_free (server.conn);
  gf_key_free (host);
}

/* Verification is on by default and known_hosts is not read yet, so the
   host key is refused, with an error of its own.  */
static void
test_hostkey_refused (void)
{
  struct twist_easy *easy;
  struct twist_ssh *ssh;
  struct peer server;
  struct pair pr;
  gf_key *host = NULL;
  const char *detail;

  check (server_new (&server, &host) == 0, "server");
  pr.server = &server;
  easy = new_easy (&ssh, &pr, 1);
  check (twist_ssh_start (ssh) == TWIST_OK, "start");
  pump (&pr, easy, 4096);
  check (easy->done && easy->result == TWIST_ERR_HOSTKEY, "host key refused");
  detail = twist_easy_error (easy);
  check (detail != NULL && strstr (detail, "known_hosts") != NULL,
         "detail names known_hosts");
  twist_easy_cleanup (easy);
  gf_conn_free (server.conn);
  gf_key_free (host);
}

/* A peer that is not SSH-2.  */
static void
test_bad_peer (void)
{
  static const char old[] = "SSH-1.5-ancient\r\n";
  struct twist_easy *easy;
  struct twist_ssh *ssh;
  struct pair pr;

  easy = new_easy (&ssh, &pr, 0);
  check (twist_ssh_start (ssh) == TWIST_OK, "start");
  twist_ssh_receive (ssh, (const uint8_t *) old, sizeof old - 1);
  check (easy->done && easy->result == TWIST_ERR_PROTOCOL, "SSH-1 refused");
  twist_easy_cleanup (easy);
}

/* A server that never answers: the key exchange has a deadline, and the
   timeout is reported as one.  */
static void
test_timeout (void)
{
  struct twist_easy *easy;
  struct twist_ssh *ssh;
  struct pair pr;
  uint64_t due;

  easy = new_easy (&ssh, &pr, 0);
  check (twist_ssh_start (ssh) == TWIST_OK, "start");
  due = twist_ssh_deadline (ssh);
  check (due != UINT64_MAX && due > now_us, "deadline set");
  twist_ssh_set_time (ssh, due);
  twist_ssh_timeout (ssh);
  check (easy->done && easy->result == TWIST_ERR_TIMEOUT, "timeout");
  twist_easy_cleanup (easy);
}

int
main (void)
{
  /* foxtrot refuses a libgcrypt older than the version it was written
     against, and then nothing here can run.  Say so, and skip.  */
  if (gf_crypto_init () != GF_OK)
    {
      fputs ("test-ssh: libgcrypt is older than foxtrot requires "
             "(1.12.4); skipping\n", stderr);
      return 77;
    }
  test_kex (65536);
  test_kex (64);
  test_kex (1);
  test_hostkey_refused ();
  test_bad_peer ();
  test_timeout ();
  return tests_finish ();
}
