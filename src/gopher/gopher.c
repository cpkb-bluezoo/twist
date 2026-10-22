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

#include <stdlib.h>
#include <string.h>

/* Gopher (RFC 1436) and its URL form.  The request is one
   selector line.  The first character of the path, after the leading
   slash, is the item type and is not sent.  The rest is percent-decoded
   and sent, with a '?' query kept as part of that line.  The reply is
   an undifferentiated byte stream ended by the peer closing.  */

#define GOPHER_MAX 2048

struct twist_gopher
{
  struct twist_easy *easy;
  struct twist_endpoint *ep;
  struct twist_mail_link link;
  int implicit_tls;
  int sent;
  int saw;
  int finished;
  uint8_t req[GOPHER_MAX];
  size_t req_len;
};

static void
gopher_complete (struct twist_gopher *g, int err)
{
  if (g == NULL || g->finished)
    return;
  g->finished = 1;
  twist_easy_finish (g->easy, err);
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
decode (const char *in, size_t n, uint8_t *out, size_t cap, size_t *out_n)
{
  size_t i = 0;
  size_t o = 0;

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
          if (c == 0)
            return TWIST_ERR_URL;
          i += 3;
        }
      else
        i++;
      if (o >= cap)
        return TWIST_ERR_URL;
      out[o++] = c;
    }
  *out_n = o;
  return TWIST_OK;
}

static int
build_request (struct twist_gopher *g)
{
  struct twist_url *url = g->easy->url;
  const char *path = url->path != NULL && url->path[0] != 0 ? url->path : "/";
  char joined[GOPHER_MAX];
  size_t n = 0;
  size_t pn = strlen (path);
  size_t qn = url->query != NULL ? strlen (url->query) : 0;
  int rc;

  if (url->host == NULL || url->host[0] == 0)
    return TWIST_ERR_URL;
  if (pn + (qn > 0 ? qn + 1 : 0) >= sizeof joined)
    return TWIST_ERR_URL;
  memcpy (joined, path, pn);
  n = pn;
  if (qn > 0)
    {
      joined[n++] = '?';
      memcpy (joined + n, url->query, qn);
      n += qn;
    }
  joined[n] = 0;
  if (n <= 2)
    {
      g->req[0] = '\r';
      g->req[1] = '\n';
      g->req_len = 2;
      return TWIST_OK;
    }
  rc = decode (joined + 2, n - 2, g->req, sizeof g->req - 2, &g->req_len);
  if (rc != TWIST_OK)
    return rc;
  g->req[g->req_len++] = '\r';
  g->req[g->req_len++] = '\n';
  return TWIST_OK;
}

static int
flush_request (struct twist_gopher *g)
{
  int rc;

  if (g->ep == NULL || g->sent)
    return TWIST_OK;
  rc = twist_endpoint_send (g->ep, g->req, g->req_len);
  if (rc != TWIST_OK)
    return rc;
  g->sent = 1;
  return TWIST_OK;
}

static int
deliver (struct twist_gopher *g, const uint8_t *data, size_t len)
{
  struct twist_easy *easy = g->easy;
  size_t off = 0;

  if (len > 0)
    g->saw = 1;
  if (easy->write_cb == NULL || len == 0)
    {
      twist_easy_downloaded (easy, len);
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
  twist_easy_downloaded (easy, len);
  return TWIST_OK;
}

const uint8_t *
twist_gopher_request (const struct twist_gopher *g, size_t *len)
{
  if (g == NULL)
    {
      if (len != NULL)
        *len = 0;
      return NULL;
    }
  if (len != NULL)
    *len = g->req_len;
  return g->req;
}

size_t
twist_gopher_receive (struct twist_gopher *g, const uint8_t *data, size_t len)
{
  int rc;

  if (g == NULL || g->finished)
    return len;
  rc = deliver (g, data, len);
  if (rc != TWIST_OK)
    {
      gopher_complete (g, rc);
      return len;
    }
  return len;
}

void
twist_gopher_closed (struct twist_gopher *g, int err)
{
  if (g == NULL || g->finished)
    return;
  if ((g->sent || g->saw) && (err == TWIST_OK || err == TWIST_ERR_CLOSED))
    gopher_complete (g, TWIST_OK);
  else
    gopher_complete (g, err != TWIST_OK ? err : TWIST_ERR_CLOSED);
}

static void
gopher_connected (struct twist_endpoint *ep)
{
  struct twist_gopher *g = ep->user_data;
  int rc;

  g->ep = ep;
  if (g->implicit_tls)
    {
      rc = twist_connection_start_tls (ep->conn, g->easy->url->host,
                                       g->easy->verifypeer, NULL, 0,
                                       g->easy->cainfo, g->easy->capath, g->easy->sslcert,
                                       g->easy->sslkey);
      if (rc != TWIST_OK)
        gopher_complete (g, rc);
      return;
    }
  rc = flush_request (g);
  if (rc != TWIST_OK)
    gopher_complete (g, rc);
}

static void
gopher_secure (struct twist_endpoint *ep, const char *alpn, size_t alpn_len)
{
  struct twist_gopher *g = ep->user_data;
  int rc;

  (void) alpn;
  (void) alpn_len;
  g->ep = ep;
  rc = flush_request (g);
  if (rc != TWIST_OK)
    gopher_complete (g, rc);
}

static size_t
gopher_on_recv (struct twist_endpoint *ep, const uint8_t *data, size_t len)
{
  struct twist_gopher *g = ep->user_data;

  g->ep = ep;
  return twist_gopher_receive (g, data, len);
}

static void
gopher_disconnected (struct twist_endpoint *ep, int error)
{
  twist_gopher_closed (ep->user_data, error);
}

static void
gopher_error (struct twist_endpoint *ep, int error)
{
  twist_gopher_closed (ep->user_data, error);
}

static void
gopher_fail (void *user, int err)
{
  gopher_complete (user, err);
}

static const struct twist_protocol_handler gopher_handler = {
  gopher_connected,
  gopher_on_recv,
  gopher_disconnected,
  gopher_secure,
  gopher_error,
  NULL,
  NULL
};

void
twist_gopher_free (void *p)
{
  struct twist_gopher *g = p;

  if (g == NULL)
    return;
  twist_mail_link_close (&g->link);
  free (g);
}

struct twist_gopher *
twist_gopher_new (struct twist_easy *easy, int live)
{
  struct twist_gopher *g;
  int rc;

  (void) live;
  if (easy == NULL || easy->url == NULL)
    return NULL;
  g = calloc (1, sizeof *g);
  if (g == NULL)
    return NULL;
  g->easy = easy;
  g->implicit_tls = easy->url->scheme != NULL
                    && strcmp (easy->url->scheme, "gophers") == 0;
  easy->xfer = g;
  easy->xfer_free = twist_gopher_free;
  rc = build_request (g);
  if (rc != TWIST_OK)
    gopher_complete (g, rc);
  return g;
}

int
twist_gopher_attach (struct twist_easy *easy)
{
  struct twist_gopher *g;
  int rc;

  g = twist_gopher_new (easy, 1);
  if (g == NULL)
    return TWIST_ERR_NOMEM;
  if (g->finished)
    return easy->result;
  rc = twist_mail_link_open (&g->link, easy, &gopher_handler, g, gopher_fail);
  if (rc != TWIST_OK)
    gopher_complete (g, rc);
  return easy->done ? easy->result : TWIST_OK;
}
