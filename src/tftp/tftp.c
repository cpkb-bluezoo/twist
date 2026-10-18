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

#include "twist-int.h"

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

/* TFTP (RFC 1350) with the blksize, tsize and timeout options (RFC
   2347, 2348, 2349).  The request goes to port 69.  Every later packet
   goes to the source address of the first reply, so the socket is not
   connected.  A packet is one datagram: receive consumes the whole
   buffer, because there is no length field that would let a tail wait
   for the next read.  The body is one block at a time.  The last packet
   sent is kept so a timer can retransmit it.  */

#define OP_RRQ 1
#define OP_WRQ 2
#define OP_DATA 3
#define OP_ACK 4
#define OP_ERROR 5
#define OP_OACK 6

#define TFTP_BLKSIZE 512
#define TFTP_REQ_MAX 512
#define TFTP_PKT_MAX (4 + TFTP_BLKSIZE)
#define TFTP_RETRY_MAX 5
#define TFTP_RETRY_MS 5000u

#define ST_START 0
#define ST_RX 1
#define ST_TX 2

struct twist_tftp
{
  struct twist_easy *easy;
  struct twist_connection *conn;
  struct twist_timer *timer;
  struct twist_timer *deadline;
  int fd;
  int upload;
  int state;
  int finished;
  int retries;
  int blksize;
  unsigned block;
  size_t payload;
  int kind;
  union
  {
    struct sockaddr sa;
    struct sockaddr_in in;
    struct sockaddr_in6 in6;
  } peer;
  socklen_t peer_len;
  const char *upload_data;
  size_t upload_len;
  size_t upload_off;
  uint8_t pkt[TFTP_PKT_MAX];
  size_t pkt_len;
  uint64_t retry_ms;
};

static void
tftp_finish (struct twist_tftp *t, int err)
{
  if (t == NULL || t->finished)
    return;
  t->finished = 1;
  if (t->timer != NULL)
    {
      twist_timer_cancel (t->timer);
      t->timer = NULL;
    }
  if (t->deadline != NULL)
    {
      twist_timer_cancel (t->deadline);
      t->deadline = NULL;
    }
  twist_easy_finish (t->easy, err);
}

static int
transmit (struct twist_tftp *t)
{
  ssize_t n;

  if (t->fd < 0 || t->pkt_len == 0 || t->peer_len == 0)
    return TWIST_OK;
  n = sendto (t->fd, t->pkt, t->pkt_len, 0, &t->peer.sa, t->peer_len);
  if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
    return TWIST_OK;
  if (n < 0 || (size_t) n != t->pkt_len)
    return TWIST_ERR_CONNECT;
  return TWIST_OK;
}

static void
arm_timer (struct twist_tftp *t);

static void
on_retry (void *user)
{
  struct twist_tftp *t = user;
  int err;

  t->timer = NULL;
  if (t->finished)
    return;
  t->retries++;
  if (t->retries > TFTP_RETRY_MAX)
    {
      err = t->state == ST_START ? TWIST_ERR_CONNECT : TWIST_ERR_TIMEOUT;
      tftp_finish (t, err);
      return;
    }
  if (transmit (t) != TWIST_OK)
    {
      tftp_finish (t, TWIST_ERR_CONNECT);
      return;
    }
  arm_timer (t);
}

static void
arm_timer (struct twist_tftp *t)
{
  if (t->finished || t->easy == NULL || t->easy->loop == NULL)
    return;
  if (t->timer != NULL)
    twist_timer_cancel (t->timer);
  t->timer = NULL;
  if (twist_loop_schedule (t->easy->loop,
                           twist_loop_now (t->easy->loop) + t->retry_ms,
                           on_retry, t, &t->timer) != TWIST_OK)
    tftp_finish (t, TWIST_ERR_NOMEM);
}

static void
on_deadline (void *user)
{
  struct twist_tftp *t = user;

  t->deadline = NULL;
  tftp_finish (t, TWIST_ERR_TIMEOUT);
}

static int
add_z (struct twist_tftp *t, const char *s)
{
  size_t n = strlen (s);

  if (t->pkt_len + n + 1 > TFTP_REQ_MAX)
    return TWIST_ERR_URL;
  memcpy (t->pkt + t->pkt_len, s, n + 1);
  t->pkt_len += n + 1;
  return TWIST_OK;
}

static int
hex_nibble (int c)
{
  if (c >= '0' && c <= '9')
    return c - '0';
  if (c >= 'a' && c <= 'f')
    return c - 'a' + 10;
  if (c >= 'A' && c <= 'F')
    return c - 'A' + 10;
  return -1;
}

static int
decode_name (const char *in, char *out, size_t cap, size_t *out_n)
{
  size_t i = 0;
  size_t o = 0;
  size_t n = strlen (in);

  while (i < n)
    {
      unsigned char c = (unsigned char) in[i];

      if (c == '%')
        {
          int hi;
          int lo;

          if (i + 2 >= n)
            return TWIST_ERR_URL;
          hi = hex_nibble ((unsigned char) in[i + 1]);
          lo = hex_nibble ((unsigned char) in[i + 2]);
          if (hi < 0 || lo < 0)
            return TWIST_ERR_URL;
          c = (unsigned char) ((hi << 4) | lo);
          i += 3;
        }
      else
        i++;
      if (c < 32 || c == 127)
        return TWIST_ERR_URL;
      if (o >= cap)
        return TWIST_ERR_URL;
      out[o++] = (char) c;
    }
  out[o] = 0;
  *out_n = o;
  return TWIST_OK;
}

static int
build_request (struct twist_tftp *t)
{
  struct twist_url *url = t->easy->url;
  const char *path = url->path != NULL ? url->path : "/";
  char name[TFTP_REQ_MAX];
  size_t name_n = 0;
  char tsize[32];
  int rc;

  if (url->host == NULL || url->host[0] == 0)
    return TWIST_ERR_URL;
  if (path[0] == '/')
    path++;
  rc = decode_name (path, name, sizeof name - 1, &name_n);
  if (rc != TWIST_OK)
    return rc;
  if (name_n == 0)
    return TWIST_ERR_URL;
  t->upload = t->easy->postfields != NULL || t->easy->read_cb != NULL;
  if (t->easy->postfields != NULL)
    {
      t->upload_data = t->easy->postfields;
      t->upload_len = t->easy->postfieldsize_set && t->easy->postfieldsize >= 0
                      ? (size_t) t->easy->postfieldsize
                      : strlen (t->easy->postfields);
    }
  t->kind = t->upload ? OP_WRQ : OP_RRQ;
  t->pkt[0] = 0;
  t->pkt[1] = (uint8_t) t->kind;
  t->pkt_len = 2;
  rc = add_z (t, name);
  if (rc != TWIST_OK)
    return rc;
  rc = add_z (t, "octet");
  if (rc != TWIST_OK)
    return rc;
  rc = add_z (t, "tsize");
  if (rc != TWIST_OK)
    return rc;
  if (t->upload && t->upload_data != NULL)
    snprintf (tsize, sizeof tsize, "%lu", (unsigned long) t->upload_len);
  else
    memcpy (tsize, "0", 2);
  rc = add_z (t, tsize);
  if (rc != TWIST_OK)
    return rc;
  rc = add_z (t, "blksize");
  if (rc != TWIST_OK)
    return rc;
  rc = add_z (t, "512");
  if (rc != TWIST_OK)
    return rc;
  rc = add_z (t, "timeout");
  if (rc != TWIST_OK)
    return rc;
  return add_z (t, "5");
}

static int
deliver (struct twist_tftp *t, const uint8_t *data, size_t len)
{
  struct twist_easy *easy = t->easy;
  size_t off = 0;

  if (easy->write_cb == NULL || len == 0)
    {
      easy->size_download += len;
      return TWIST_OK;
    }
  while (off < len)
    {
      char buf[512];
      size_t chunk = len - off;
      size_t n;

      if (chunk > sizeof buf)
        chunk = sizeof buf;
      memcpy (buf, data + off, chunk);
      n = easy->write_cb (buf, 1, chunk, easy->write_data);
      if (n < chunk)
        return TWIST_ERR_ABORTED;
      off += chunk;
    }
  easy->size_download += len;
  return TWIST_OK;
}

static int
fill_data (struct twist_tftp *t)
{
  size_t n = 0;

  t->pkt[0] = 0;
  t->pkt[1] = OP_DATA;
  t->pkt[2] = (uint8_t) (t->block >> 8);
  t->pkt[3] = (uint8_t) t->block;
  if (t->upload_data != NULL)
    {
      size_t left = t->upload_len - t->upload_off;

      if (left > (size_t) t->blksize)
        left = (size_t) t->blksize;
      memcpy (t->pkt + 4, t->upload_data + t->upload_off, left);
      t->upload_off += left;
      n = left;
    }
  else if (t->easy->read_cb != NULL)
    {
      while (n < (size_t) t->blksize)
        {
          char buf[512];
          size_t want = (size_t) t->blksize - n;
          size_t got;

          if (want > sizeof buf)
            want = sizeof buf;
          got = t->easy->read_cb (buf, 1, want, t->easy->read_data);
          if (got == 0)
            break;
          if (got > want)
            got = want;
          memcpy (t->pkt + 4 + n, buf, got);
          n += got;
        }
    }
  t->payload = n;
  t->pkt_len = 4 + n;
  t->kind = OP_DATA;
  return TWIST_OK;
}

static int
send_ack (struct twist_tftp *t, unsigned block)
{
  t->pkt[0] = 0;
  t->pkt[1] = OP_ACK;
  t->pkt[2] = (uint8_t) (block >> 8);
  t->pkt[3] = (uint8_t) block;
  t->pkt_len = 4;
  t->kind = OP_ACK;
  return transmit (t);
}

static int
send_error (struct twist_tftp *t, unsigned code)
{
  static const char msg[] = "illegal";

  t->pkt[0] = 0;
  t->pkt[1] = OP_ERROR;
  t->pkt[2] = 0;
  t->pkt[3] = (uint8_t) code;
  memcpy (t->pkt + 4, msg, sizeof msg);
  t->pkt_len = 4 + sizeof msg;
  t->kind = OP_ERROR;
  return transmit (t);
}

static int
opt_eq (const char *a, const char *b)
{
  size_t i;

  for (i = 0; a[i] != 0 || b[i] != 0; i++)
    if (tolower ((unsigned char) a[i]) != tolower ((unsigned char) b[i]))
      return 0;
  return 1;
}

static int
parse_num (const char *s, long max, long *out)
{
  char *end = NULL;
  unsigned long v;

  if (s == NULL || s[0] == 0)
    return -1;
  errno = 0;
  v = strtoul (s, &end, 10);
  if (end == s || *end != 0 || errno == ERANGE || v > (unsigned long) max)
    return -1;
  *out = (long) v;
  return 0;
}

static int
parse_oack (struct twist_tftp *t, const uint8_t *p, size_t n)
{
  size_t i = 0;

  t->blksize = TFTP_BLKSIZE;
  while (i < n)
    {
      const char *opt;
      const char *val;
      long num;

      if (memchr (p + i, 0, n - i) == NULL)
        return TWIST_ERR_PROTOCOL;
      opt = (const char *) (p + i);
      i += strlen (opt) + 1;
      if (i >= n || memchr (p + i, 0, n - i) == NULL)
        return TWIST_ERR_PROTOCOL;
      val = (const char *) (p + i);
      i += strlen (val) + 1;
      if (opt_eq (opt, "blksize"))
        {
          if (parse_num (val, TFTP_BLKSIZE, &num) != 0 || num < 8)
            return TWIST_ERR_PROTOCOL;
          t->blksize = (int) num;
        }
      else if (opt_eq (opt, "timeout"))
        {
          if (parse_num (val, 255, &num) != 0 || num < 1)
            return TWIST_ERR_PROTOCOL;
          t->retry_ms = (uint64_t) num * 1000u;
        }
    }
  return TWIST_OK;
}

static int
map_error (unsigned code)
{
  if (code == 1 || code == 2 || code == 3 || code == 6 || code == 7)
    return TWIST_ERR_FILE;
  return TWIST_ERR_PROTOCOL;
}

static int
handle_data (struct twist_tftp *t, const uint8_t *data, size_t len)
{
  unsigned block = ((unsigned) data[2] << 8) | data[3];
  unsigned expect = (t->block + 1u) & 0xffffu;
  size_t payload = len - 4;
  int rc;

  if (block == t->block)
    return send_ack (t, block);
  if (block != expect)
    return TWIST_OK;
  if (payload > (size_t) t->blksize)
    return TWIST_ERR_PROTOCOL;
  rc = deliver (t, data + 4, payload);
  if (rc != TWIST_OK)
    return rc;
  t->block = block;
  t->retries = 0;
  rc = send_ack (t, block);
  if (rc != TWIST_OK)
    return rc;
  if (payload < (size_t) t->blksize)
    tftp_finish (t, TWIST_OK);
  else
    arm_timer (t);
  return TWIST_OK;
}

static int
handle_ack (struct twist_tftp *t, unsigned block)
{
  int rc;

  if (t->block == 0 && block == 65535 && t->kind == OP_DATA)
    block = 0;
  if (block != t->block)
    {
      t->retries++;
      if (t->retries > TFTP_RETRY_MAX)
        return TWIST_ERR_TIMEOUT;
      rc = transmit (t);
      if (rc != TWIST_OK)
        return rc;
      arm_timer (t);
      return TWIST_OK;
    }
  t->retries = 0;
  if (t->block > 0 && t->payload < (size_t) t->blksize)
    {
      tftp_finish (t, TWIST_OK);
      return TWIST_OK;
    }
  t->block = (t->block + 1u) & 0xffffu;
  fill_data (t);
  rc = transmit (t);
  if (rc != TWIST_OK)
    return rc;
  arm_timer (t);
  return TWIST_OK;
}

static int
take_oack (struct twist_tftp *t, const uint8_t *data, size_t len)
{
  int rc;

  rc = parse_oack (t, data + 2, len - 2);
  if (rc != TWIST_OK)
    {
      send_error (t, 4);
      return rc;
    }
  t->retries = 0;
  if (t->upload)
    {
      t->state = ST_TX;
      t->block = 0;
      t->payload = (size_t) t->blksize;
      return handle_ack (t, 0);
    }
  t->state = ST_RX;
  t->block = 0;
  rc = send_ack (t, 0);
  if (rc != TWIST_OK)
    return rc;
  arm_timer (t);
  return TWIST_OK;
}

const uint8_t *
twist_tftp_packet (const struct twist_tftp *t, size_t *len)
{
  if (t == NULL)
    {
      if (len != NULL)
        *len = 0;
      return NULL;
    }
  if (len != NULL)
    *len = t->pkt_len;
  return t->pkt;
}

size_t
twist_tftp_receive (struct twist_tftp *t, const uint8_t *data, size_t len)
{
  unsigned opcode;
  unsigned block;
  int rc = TWIST_OK;

  if (t == NULL || t->finished)
    return len;
  if (len < 2)
    return len;
  opcode = ((unsigned) data[0] << 8) | data[1];
  if (opcode != OP_OACK && len < 4)
    return len;
  block = len >= 4 ? (((unsigned) data[2] << 8) | data[3]) : 0;
  if (opcode == OP_ERROR)
    {
      tftp_finish (t, map_error (block));
      return len;
    }
  if (opcode == OP_OACK)
    rc = take_oack (t, data, len);
  else if (opcode == OP_DATA && !t->upload)
    {
      t->state = ST_RX;
      rc = handle_data (t, data, len);
    }
  else if (opcode == OP_ACK && t->upload)
    {
      t->state = ST_TX;
      rc = handle_ack (t, block);
    }
  if (rc != TWIST_OK)
    tftp_finish (t, rc);
  return len;
}

void
twist_tftp_timeout (struct twist_tftp *t)
{
  if (t == NULL || t->finished)
    return;
  on_retry (t);
}

static ssize_t
udp_read (void *user, uint8_t *buf, size_t len)
{
  struct twist_tftp *t = user;
  struct sockaddr_storage from;
  socklen_t flen = sizeof from;
  ssize_t n;

  n = recvfrom (t->fd, buf, len, 0, (struct sockaddr *) &from, &flen);
  if (n >= 0 && flen > 0 && (size_t) flen <= sizeof t->peer)
    {
      memcpy (&t->peer, &from, (size_t) flen);
      t->peer_len = flen;
    }
  return n;
}

static ssize_t
udp_write (void *user, const uint8_t *buf, size_t len)
{
  struct twist_tftp *t = user;
  ssize_t n;

  if (t->peer_len == 0)
    {
      errno = EDESTADDRREQ;
      return -1;
    }
  n = sendto (t->fd, buf, len, 0, &t->peer.sa, t->peer_len);
  if (n < 0)
    return -1;
  if ((size_t) n != len)
    {
      errno = EIO;
      return -1;
    }
  return n;
}

static void
tftp_connected (struct twist_endpoint *ep)
{
  struct twist_tftp *t = ep->user_data;

  if (t->finished)
    return;
  if (transmit (t) != TWIST_OK)
    tftp_finish (t, TWIST_ERR_CONNECT);
  else
    arm_timer (t);
}

static size_t
tftp_on_recv (struct twist_endpoint *ep, const uint8_t *data, size_t len)
{
  return twist_tftp_receive (ep->user_data, data, len);
}

static void
tftp_stopped (struct twist_endpoint *ep, int error)
{
  struct twist_tftp *t = ep->user_data;

  if (t == NULL || t->finished)
    return;
  tftp_finish (t, error != TWIST_OK ? error : TWIST_ERR_CONNECT);
}

static const struct twist_protocol_handler tftp_handler = {
  tftp_connected,
  tftp_on_recv,
  tftp_stopped,
  NULL,
  tftp_stopped,
  NULL,
  NULL
};

static int
dial_udp (struct twist_tftp *t, const struct twist_dns_addr *addr)
{
  struct twist_connection *c;
  struct twist_endpoint *ep;
  int fd;
  int port = t->easy->url->port > 0 ? t->easy->url->port : 69;

  fd = socket (addr->family == 6 ? AF_INET6 : AF_INET, SOCK_DGRAM, 0);
  if (fd < 0 || fcntl (fd, F_SETFL, O_NONBLOCK) < 0
      || fcntl (fd, F_SETFD, FD_CLOEXEC) < 0)
    {
      if (fd >= 0)
        close (fd);
      return TWIST_ERR_CONNECT;
    }
  if (addr->family == 6)
    {
      struct sockaddr_in6 local;

      memset (&local, 0, sizeof local);
      local.sin6_family = AF_INET6;
      local.sin6_addr = in6addr_any;
      if (bind (fd, (struct sockaddr *) &local, sizeof local) < 0)
        {
          close (fd);
          return TWIST_ERR_CONNECT;
        }
      memset (&t->peer, 0, sizeof t->peer);
      t->peer.in6.sin6_family = AF_INET6;
      t->peer.in6.sin6_port = htons ((uint16_t) port);
      memcpy (&t->peer.in6.sin6_addr, addr->addr, 16);
      t->peer_len = sizeof t->peer.in6;
    }
  else
    {
      struct sockaddr_in local;

      memset (&local, 0, sizeof local);
      local.sin_family = AF_INET;
      local.sin_addr.s_addr = htonl (INADDR_ANY);
      if (bind (fd, (struct sockaddr *) &local, sizeof local) < 0)
        {
          close (fd);
          return TWIST_ERR_CONNECT;
        }
      memset (&t->peer, 0, sizeof t->peer);
      t->peer.in.sin_family = AF_INET;
      t->peer.in.sin_port = htons ((uint16_t) port);
      memcpy (&t->peer.in.sin_addr, addr->addr, 4);
      t->peer_len = sizeof t->peer.in;
    }
  c = twist_connection_new (t->easy->loop);
  if (c == NULL)
    {
      close (fd);
      return TWIST_ERR_NOMEM;
    }
  t->conn = c;
  t->fd = fd;
  ep = twist_connection_endpoint (c);
  ep->user_data = t;
  twist_connection_set_handler (c, &tftp_handler);
  twist_connection_set_io (c, udp_read, udp_write, t);
  twist_connection_set_fd (c, fd);
  twist_connection_connected (c);
  return TWIST_OK;
}

static void
on_resolved (void *user, int err, const struct twist_dns_addr *addr)
{
  struct twist_tftp *t = user;
  int rc;

  if (t->finished)
    return;
  if (err != TWIST_OK || addr == NULL)
    {
      tftp_finish (t, err != TWIST_OK ? err : TWIST_ERR_RESOLVE);
      return;
    }
  rc = dial_udp (t, addr);
  if (rc != TWIST_OK)
    tftp_finish (t, rc);
}

void
twist_tftp_free (void *p)
{
  struct twist_tftp *t = p;

  if (t == NULL)
    return;
  if (t->timer != NULL)
    twist_timer_cancel (t->timer);
  if (t->deadline != NULL)
    twist_timer_cancel (t->deadline);
  t->timer = NULL;
  t->deadline = NULL;
  t->fd = -1;
  twist_connection_free (t->conn);
  free (t);
}

struct twist_tftp *
twist_tftp_new (struct twist_easy *easy, int live)
{
  struct twist_tftp *t;
  int rc;

  (void) live;
  if (easy == NULL || easy->url == NULL)
    return NULL;
  t = calloc (1, sizeof *t);
  if (t == NULL)
    return NULL;
  t->easy = easy;
  t->fd = -1;
  t->blksize = TFTP_BLKSIZE;
  t->payload = TFTP_BLKSIZE;
  t->retry_ms = TFTP_RETRY_MS;
  easy->xfer = t;
  easy->xfer_free = twist_tftp_free;
  if (easy->proxy != NULL && easy->proxy[0] != 0)
    {
      tftp_finish (t, TWIST_ERR_UNSUPPORTED);
      return t;
    }
  rc = build_request (t);
  if (rc != TWIST_OK)
    tftp_finish (t, rc);
  return t;
}

int
twist_tftp_attach (struct twist_easy *easy)
{
  struct twist_tftp *t;
  int rc;

  if (easy == NULL || easy->loop == NULL)
    return TWIST_ERR_INVAL;
  t = twist_tftp_new (easy, 1);
  if (t == NULL)
    return TWIST_ERR_NOMEM;
  if (t->finished)
    return easy->result;
  if (easy->timeout_ms > 0)
    twist_loop_schedule (easy->loop,
                         twist_loop_now (easy->loop)
                         + (uint64_t) easy->timeout_ms,
                         on_deadline, t, &t->deadline);
  rc = twist_dns_resolve_easy (easy, easy->url->host, on_resolved, t);
  if (rc != TWIST_OK)
    tftp_finish (t, rc);
  return easy->done ? easy->result : TWIST_OK;
}
