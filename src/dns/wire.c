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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* DNS is one client protocol.  UDP, TCP, DoT, DoQ, and DoH only
   differ in how a message is framed.  The message itself is parsed
   here, in place, once the frame is complete.  Compression pointers
   refer back into that message, so the bytes have to be present
   together; the caller keeps any short tail and presents it again.  */

static void
put16 (uint8_t *p, uint16_t v)
{
  p[0] = (uint8_t) (v >> 8);
  p[1] = (uint8_t) v;
}

static uint16_t
rd16 (const uint8_t *p)
{
  return (uint16_t) ((p[0] << 8) | p[1]);
}

static void
fail (const struct twist_dns_events *ev, int err)
{
  if (ev != NULL && ev->failure != NULL)
    ev->failure (ev->user, err);
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

static void
emit_addr (const struct twist_dns_events *ev, int family,
           const uint8_t *addr)
{
  struct twist_dns_addr a;

  if (ev == NULL || ev->address == NULL)
    return;
  memset (&a, 0, sizeof a);
  a.family = family;
  memcpy (a.addr, addr, family == 4 ? 4 : 16);
  if (family == 4)
    snprintf (a.text, sizeof a.text, "%u.%u.%u.%u",
              addr[0], addr[1], addr[2], addr[3]);
  else
    inet_ntop (AF_INET6, addr, a.text, sizeof a.text);
  ev->address (ev->user, &a);
}

/* RFC 9460 HTTPS/SVCB rdata.  Priority 0 is an alias and carries no
   parameters.  "alpn" is key 1, "port" is key 3.  */

static void
parse_https (const uint8_t *msg, size_t len, size_t off, size_t rdlen,
             const struct twist_dns_events *ev)
{
  size_t end;
  uint16_t prio;

  if (rdlen < 3 || off + rdlen > len)
    return;
  end = off + rdlen;
  prio = rd16 (msg + off);
  off += 2;
  if (skip_name (msg, len, &off) != TWIST_OK || off > end)
    return;
  if (prio == 0)
    return;
  while (off + 4 <= end)
    {
      uint16_t key = rd16 (msg + off);
      uint16_t vl = rd16 (msg + off + 2);
      const uint8_t *val;
      size_t i;

      off += 4;
      if (off + vl > end)
        return;
      val = msg + off;
      off += vl;
      if (key == 1 && ev->https_alpn != NULL)
        {
          i = 0;
          while (i < vl)
            {
              size_t n = val[i++];
              if (i + n > vl)
                return;
              ev->https_alpn (ev->user, (const char *) (val + i), n);
              i += n;
            }
        }
      else if (key == 3 && vl == 2 && ev->https_port != NULL)
        ev->https_port (ev->user, rd16 (val));
    }
}

static int
parse_message (const uint8_t *msg, size_t len, const struct twist_dns_events *ev)
{
  size_t off = 12;
  uint16_t flags;
  uint16_t qd;
  uint16_t an;
  uint16_t i;

  if (len < 12)
    {
      fail (ev, TWIST_ERR_PROTOCOL);
      return TWIST_ERR_PROTOCOL;
    }
  flags = rd16 (msg + 2);
  qd = rd16 (msg + 4);
  an = rd16 (msg + 6);
  for (i = 0; i < qd; i++)
    {
      if (skip_name (msg, len, &off) != TWIST_OK || off + 4 > len)
        {
          fail (ev, TWIST_ERR_PROTOCOL);
          return TWIST_ERR_PROTOCOL;
        }
      off += 4;
    }
  for (i = 0; i < an; i++)
    {
      uint16_t typ;
      uint16_t rdlen;
      if (skip_name (msg, len, &off) != TWIST_OK || off + 10 > len)
        {
          fail (ev, TWIST_ERR_PROTOCOL);
          return TWIST_ERR_PROTOCOL;
        }
      typ = rd16 (msg + off);
      rdlen = rd16 (msg + off + 8);
      off += 10;
      if (off + rdlen > len)
        {
          fail (ev, TWIST_ERR_PROTOCOL);
          return TWIST_ERR_PROTOCOL;
        }
      if (typ == 1 && rdlen == 4)
        emit_addr (ev, 4, msg + off);
      else if (typ == 28 && rdlen == 16)
        emit_addr (ev, 6, msg + off);
      else if (typ == 65 || typ == 64)
        {
          if (ev->https_rr != NULL)
            ev->https_rr (ev->user);
          parse_https (msg, len, off, rdlen, ev);
        }
      off += rdlen;
    }
  if ((flags & 0x0200) != 0 && ev->truncated != NULL)
    ev->truncated (ev->user);
  return TWIST_OK;
}

size_t
twist_dns_stream_receive (const uint8_t *data, size_t len,
                          const struct twist_dns_events *ev)
{
  size_t need;

  if (data == NULL || ev == NULL)
    return 0;
  if (len < 2)
    return 0;
  need = rd16 (data);
  if (len < 2 + need)
    return 0;
  if (need < 12)
    {
      fail (ev, TWIST_ERR_PROTOCOL);
      return 2 + need;
    }
  parse_message (data + 2, need, ev);
  return 2 + need;
}

size_t
twist_dns_datagram_receive (const uint8_t *data, size_t len,
                            const struct twist_dns_events *ev)
{
  if (data == NULL || ev == NULL || len == 0)
    return 0;
  if (len < 12)
    {
      fail (ev, TWIST_ERR_PROTOCOL);
      return len;
    }
  parse_message (data, len, ev);
  return len;
}

struct decode_box
{
  int qtype;
  struct twist_dns_addr *list;
  size_t n;
};

static void
decode_addr (void *user, const struct twist_dns_addr *addr)
{
  struct decode_box *b = user;
  struct twist_dns_addr *grown;
  int want = b->qtype == 28 ? 6 : 4;

  if (addr->family != want || b->n >= 16)
    return;
  grown = realloc (b->list, (b->n + 1) * sizeof *grown);
  if (grown == NULL)
    return;
  b->list = grown;
  b->list[b->n++] = *addr;
}

int
twist_dns_decode (const uint8_t *msg, size_t len, int qtype,
                  struct twist_dns_addr **out, size_t *n_out)
{
  struct decode_box box;
  struct twist_dns_events ev;
  int rc;

  memset (&box, 0, sizeof box);
  memset (&ev, 0, sizeof ev);
  box.qtype = qtype;
  ev.user = &box;
  ev.address = decode_addr;
  rc = len < 12 ? TWIST_ERR_PROTOCOL : parse_message (msg, len, &ev);
  if (rc != TWIST_OK)
    {
      free (box.list);
      return rc;
    }
  *out = box.list;
  *n_out = box.n;
  return box.n > 0 ? TWIST_OK : TWIST_ERR_RESOLVE;
}
