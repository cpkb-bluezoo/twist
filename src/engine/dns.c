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

#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static void
put16 (uint8_t *p, uint16_t v)
{
  p[0] = (uint8_t) (v >> 8);
  p[1] = (uint8_t) v;
}

static int
encode_name (uint8_t *out, size_t cap, size_t *n, const char *name)
{
  const char *p = name;

  while (*p != 0)
    {
      const char *dot = strchr (p, '.');
      size_t lab = dot != NULL ? (size_t) (dot - p) : strlen (p);
      if (lab == 0 || lab > 63 || *n + lab + 1 >= cap)
        return TWIST_ERR_RESOLVE;
      out[(*n)++] = (uint8_t) lab;
      memcpy (out + *n, p, lab);
      *n += lab;
      if (dot == NULL)
        break;
      p = dot + 1;
    }
  if (*n >= cap)
    return TWIST_ERR_RESOLVE;
  out[(*n)++] = 0;
  return TWIST_OK;
}

int
twist_dns_encode_query (const char *name, int qtype, uint16_t id,
                        uint8_t **out, size_t *len)
{
  uint8_t buf[512];
  size_t n = 12;
  int rc;

  memset (buf, 0, sizeof buf);
  put16 (buf, id);
  put16 (buf + 2, 0x0100);
  put16 (buf + 4, 1);
  rc = encode_name (buf, sizeof buf, &n, name);
  if (rc != TWIST_OK)
    return rc;
  if (n + 4 > sizeof buf)
    return TWIST_ERR_RESOLVE;
  put16 (buf + n, (uint16_t) qtype);
  put16 (buf + n + 2, 1);
  n += 4;
  *out = twist_xmalloc (n);
  if (*out == NULL)
    return TWIST_ERR_NOMEM;
  memcpy (*out, buf, n);
  *len = n;
  return TWIST_OK;
}

static int
skip_name (const uint8_t *msg, size_t len, size_t *off)
{
  size_t jumps = 0;

  while (*off < len)
    {
      uint8_t lab = msg[*off];
      if (lab == 0)
        {
          (*off)++;
          return TWIST_OK;
        }
      if ((lab & 0xc0) == 0xc0)
        {
          if (*off + 1 >= len)
            return TWIST_ERR_PROTOCOL;
          *off += 2;
          return TWIST_OK;
        }
      if (*off + 1 + lab > len || ++jumps > 64)
        return TWIST_ERR_PROTOCOL;
      *off += 1 + lab;
    }
  return TWIST_ERR_PROTOCOL;
}

static uint16_t
rd16 (const uint8_t *p)
{
  return (uint16_t) ((p[0] << 8) | p[1]);
}

int
twist_dns_decode (const uint8_t *msg, size_t len, int qtype,
                  struct twist_dns_addr **out, size_t *n_out)
{
  size_t off = 12;
  uint16_t qd;
  uint16_t an;
  uint16_t i;
  struct twist_dns_addr *list = NULL;
  size_t n = 0;

  if (len < 12)
    return TWIST_ERR_PROTOCOL;
  qd = rd16 (msg + 4);
  an = rd16 (msg + 6);
  for (i = 0; i < qd; i++)
    {
      if (skip_name (msg, len, &off) != TWIST_OK || off + 4 > len)
        return TWIST_ERR_PROTOCOL;
      off += 4;
    }
  for (i = 0; i < an; i++)
    {
      uint16_t typ;
      uint16_t rdlen;
      if (skip_name (msg, len, &off) != TWIST_OK || off + 10 > len)
        {
          free (list);
          return TWIST_ERR_PROTOCOL;
        }
      typ = rd16 (msg + off);
      rdlen = rd16 (msg + off + 8);
      off += 10;
      if (off + rdlen > len)
        {
          free (list);
          return TWIST_ERR_PROTOCOL;
        }
      if (typ == qtype && (rdlen == 4 || rdlen == 16))
        {
          struct twist_dns_addr *grown = realloc (list, (n + 1) * sizeof *list);
          if (grown == NULL)
            {
              free (list);
              return TWIST_ERR_NOMEM;
            }
          list = grown;
          memset (&list[n], 0, sizeof list[n]);
          list[n].family = rdlen == 4 ? 4 : 6;
          memcpy (list[n].addr, msg + off, rdlen);
          if (rdlen == 4)
            snprintf (list[n].text, sizeof list[n].text, "%u.%u.%u.%u",
                      msg[off], msg[off + 1], msg[off + 2], msg[off + 3]);
          else
            inet_ntop (AF_INET6, msg + off, list[n].text, sizeof list[n].text);
          n++;
        }
      off += rdlen;
    }
  *out = list;
  *n_out = n;
  return n > 0 ? TWIST_OK : TWIST_ERR_RESOLVE;
}

struct dns_query
{
  struct twist_loop *loop;
  char *host;
  void (*cb) (void *, int, const struct twist_dns_addr *);
  void *user;
  struct twist_connection *conn;
  int done;
  int sent;
};

static void dns_reap (void *user);

static void
dns_finish (struct dns_query *q, int err, const struct twist_dns_addr *addr)
{
  struct twist_loop *loop;

  if (q->done)
    return;
  q->done = 1;
  loop = q->loop;
  q->cb (q->user, err, addr);
  if (loop != NULL)
    twist_loop_post (loop, dns_reap, q);
  else
    dns_reap (q);
}

static void
dns_reap (void *user)
{
  struct dns_query *q = user;

  if (q->conn != NULL)
    {
      struct twist_connection *c = q->conn;
      q->conn = NULL;
      twist_connection_free (c);
    }
  free (q->host);
  free (q);
}

static void
dns_send (struct twist_endpoint *ep)
{
  struct dns_query *q = ep->user_data;
  uint8_t *pkt = NULL;
  size_t len = 0;

  if (q->sent)
    return;
  if (twist_dns_encode_query (q->host, 1, 1, &pkt, &len) != TWIST_OK)
    {
      dns_finish (q, TWIST_ERR_RESOLVE, NULL);
      return;
    }
  q->sent = 1;
  if (twist_endpoint_send (ep, pkt, len) != TWIST_OK)
    dns_finish (q, TWIST_ERR_RESOLVE, NULL);
  free (pkt);
}

static size_t
dns_receive (struct twist_endpoint *ep, const uint8_t *data, size_t len)
{
  struct dns_query *q = ep->user_data;
  struct twist_dns_addr *list = NULL;
  size_t n = 0;
  int rc;

  rc = twist_dns_decode (data, len, 1, &list, &n);
  if (rc == TWIST_OK && n > 0)
    dns_finish (q, TWIST_OK, &list[0]);
  else
    dns_finish (q, rc != TWIST_OK ? rc : TWIST_ERR_RESOLVE, NULL);
  free (list);
  return len;
}

static void
dns_disconnected (struct twist_endpoint *ep, int error)
{
  struct dns_query *q = ep->user_data;

  if (!q->done)
    dns_finish (q, error != TWIST_OK ? error : TWIST_ERR_RESOLVE, NULL);
}

static const struct twist_protocol_handler dns_handler = {
  dns_send,
  dns_receive,
  dns_disconnected,
  NULL,
  NULL,
  NULL,
  NULL
};

static int
nameserver (struct sockaddr_in *sin)
{
  FILE *fp;
  char line[256];

  memset (sin, 0, sizeof *sin);
  sin->sin_family = AF_INET;
  sin->sin_port = htons (53);
  fp = fopen ("/etc/resolv.conf", "r");
  if (fp != NULL)
    {
      while (fgets (line, sizeof line, fp) != NULL)
        {
          char ip[64];
          if (sscanf (line, "nameserver %63s", ip) == 1
              && inet_pton (AF_INET, ip, &sin->sin_addr) == 1)
            {
              fclose (fp);
              return TWIST_OK;
            }
        }
      fclose (fp);
    }
  inet_pton (AF_INET, "127.0.0.1", &sin->sin_addr);
  return TWIST_OK;
}

static int
dns_udp (struct twist_loop *loop, const char *host,
         void (*cb) (void *, int, const struct twist_dns_addr *), void *user)
{
  struct dns_query *q;
  struct sockaddr_in sin;
  struct twist_endpoint *ep;
  int fd;

  q = calloc (1, sizeof *q);
  if (q == NULL)
    return TWIST_ERR_NOMEM;
  q->loop = loop;
  q->host = twist_strdup (host);
  q->cb = cb;
  q->user = user;
  if (q->host == NULL)
    {
      free (q);
      return TWIST_ERR_NOMEM;
    }
  nameserver (&sin);
  fd = socket (AF_INET, SOCK_DGRAM, 0);
  if (fd < 0 || fcntl (fd, F_SETFL, O_NONBLOCK) < 0
      || fcntl (fd, F_SETFD, FD_CLOEXEC) < 0
      || connect (fd, (struct sockaddr *) &sin, sizeof sin) < 0)
    {
      if (fd >= 0)
        close (fd);
      free (q->host);
      free (q);
      return TWIST_ERR_RESOLVE;
    }
  q->conn = twist_connection_new (loop);
  if (q->conn == NULL)
    {
      close (fd);
      free (q->host);
      free (q);
      return TWIST_ERR_NOMEM;
    }
  ep = twist_connection_endpoint (q->conn);
  ep->user_data = q;
  twist_connection_set_handler (q->conn, &dns_handler);
  twist_connection_set_fd (q->conn, fd);
  twist_connection_connected (q->conn);
  return TWIST_OK;
}

int
twist_dns_resolve (struct twist_loop *loop, const char *host,
                   void (*cb) (void *, int, const struct twist_dns_addr *),
                   void *user)
{
  struct twist_dns_addr addr;
  struct in_addr a4;
  struct in6_addr a6;

  if (host == NULL || cb == NULL)
    return TWIST_ERR_INVAL;
  memset (&addr, 0, sizeof addr);
  if (inet_pton (AF_INET, host, &a4) == 1)
    {
      addr.family = 4;
      memcpy (addr.addr, &a4, 4);
      snprintf (addr.text, sizeof addr.text, "%s", host);
      cb (user, TWIST_OK, &addr);
      return TWIST_OK;
    }
  if (inet_pton (AF_INET6, host, &a6) == 1)
    {
      addr.family = 6;
      memcpy (addr.addr, &a6, 16);
      snprintf (addr.text, sizeof addr.text, "%s", host);
      cb (user, TWIST_OK, &addr);
      return TWIST_OK;
    }
  if (loop == NULL)
    return TWIST_ERR_INVAL;
  return dns_udp (loop, host, cb, user);
}
