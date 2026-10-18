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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

enum
{
  PX_START = 0,
  PX_HTTP,
  PX_SOCKS_GREET,
  PX_SOCKS_ASK,
  PX_SOCKS_CONNECT,
  PX_READY
};

struct twist_proxy
{
  int kind;
  int state;
  char *host;
  int port;
  char *target_host;
  int target_port;
  void *inner_user;
  const struct twist_protocol_handler *inner;
  struct twist_endpoint *ep;
  uint8_t acc[512];
  size_t acc_len;
  struct twist_protocol_handler handler;
};

static void
swap_user (struct twist_proxy *p, int to_inner)
{
  if (p->ep == NULL)
    return;
  p->ep->user_data = to_inner ? p->inner_user : p;
}

static void
proxy_connected (struct twist_endpoint *ep)
{
  struct twist_proxy *p = ep->user_data;
  uint8_t *out = NULL;
  size_t len = 0;

  p->ep = ep;
  if (twist_proxy_opening (p, &out, &len) == TWIST_OK && out != NULL)
    {
      twist_endpoint_send (ep, out, len);
      free (out);
    }
}

static size_t
proxy_receive (struct twist_endpoint *ep, const uint8_t *data, size_t len)
{
  struct twist_proxy *p = ep->user_data;

  p->ep = ep;
  int ready = 0;
  size_t n;

  p->ep = ep;

  if (p->state == PX_READY && p->inner != NULL && p->inner->receive != NULL)
    {
      swap_user (p, 1);
      n = p->inner->receive (ep, data, len);
      swap_user (p, 0);
      return n;
    }
  if (twist_proxy_feed (p, data, len, &ready) != TWIST_OK)
    return 0;
  if (p->state == PX_SOCKS_ASK)
    {
      uint8_t *out = NULL;
      size_t out_len = 0;
      if (twist_proxy_opening (p, &out, &out_len) == TWIST_OK && out != NULL)
        {
          twist_endpoint_send (ep, out, out_len);
          free (out);
        }
    }
  if (ready && p->inner != NULL && p->inner->connected != NULL)
    {
      swap_user (p, 1);
      p->inner->connected (ep);
      swap_user (p, 0);
    }
  return len;
}

static void
proxy_forward_disc (struct twist_endpoint *ep, int error)
{
  struct twist_proxy *p = ep->user_data;

  p->ep = ep;

  if (p->inner != NULL && p->inner->disconnected != NULL)
    {
      swap_user (p, 1);
      p->inner->disconnected (ep, error);
      swap_user (p, 0);
    }
}

static void
proxy_forward_sec (struct twist_endpoint *ep, const char *alpn, size_t n)
{
  struct twist_proxy *p = ep->user_data;

  p->ep = ep;

  if (p->inner != NULL && p->inner->security_established != NULL)
    {
      swap_user (p, 1);
      p->inner->security_established (ep, alpn, n);
      swap_user (p, 0);
    }
}

static void
proxy_forward_err (struct twist_endpoint *ep, int error)
{
  struct twist_proxy *p = ep->user_data;

  p->ep = ep;

  if (p->inner != NULL && p->inner->error != NULL)
    {
      swap_user (p, 1);
      p->inner->error (ep, error);
      swap_user (p, 0);
    }
}

int
twist_proxy_parse (const char *s, int *kind, char **host, int *port)
{
  const char *p = s;
  const char *colon;
  int k = TWIST_PROXY_HTTP;
  int def = 8080;

  if (s == NULL || kind == NULL || host == NULL || port == NULL)
    return TWIST_ERR_INVAL;
  if (strncmp (p, "socks5://", 9) == 0 || strncmp (p, "socks5h://", 10) == 0)
    {
      k = TWIST_PROXY_SOCKS5;
      def = 1080;
      p += p[6] == 'h' ? 10 : 9;
    }
  else if (strncmp (p, "http://", 7) == 0)
    p += 7;
  else if (strncmp (p, "https://", 8) == 0)
    p += 8;
  colon = strrchr (p, ':');
  if (colon != NULL && colon != p)
    {
      char *end = NULL;
      long v = strtol (colon + 1, &end, 10);
      *host = twist_xmalloc ((size_t) (colon - p) + 1);
      if (*host == NULL)
        return TWIST_ERR_NOMEM;
      memcpy (*host, p, (size_t) (colon - p));
      (*host)[colon - p] = 0;
      *port = (end != NULL && *end == 0 && v > 0 && v < 65536) ? (int) v : def;
    }
  else
    {
      *host = twist_strdup (p);
      if (*host == NULL)
        return TWIST_ERR_NOMEM;
      *port = def;
    }
  *kind = k;
  return TWIST_OK;
}

struct twist_proxy *
twist_proxy_new (int kind, const char *host, int port,
                 const struct twist_protocol_handler *inner)
{
  struct twist_proxy *p = calloc (1, sizeof *p);

  if (p == NULL)
    return NULL;
  p->kind = kind;
  p->port = port;
  p->host = twist_strdup (host != NULL ? host : "");
  p->inner = inner;
  if (p->host == NULL)
    {
      free (p);
      return NULL;
    }
  p->handler.connected = proxy_connected;
  p->handler.receive = proxy_receive;
  p->handler.disconnected = proxy_forward_disc;
  p->handler.security_established = proxy_forward_sec;
  p->handler.error = proxy_forward_err;
  return p;
}

void
twist_proxy_free (struct twist_proxy *proxy)
{
  if (proxy == NULL)
    return;
  free (proxy->host);
  free (proxy->target_host);
  free (proxy);
}

void
twist_proxy_set_target (struct twist_proxy *proxy, const char *host, int port)
{
  if (proxy == NULL)
    return;
  free (proxy->target_host);
  proxy->target_host = twist_strdup (host != NULL ? host : "");
  proxy->target_port = port;
}

void
twist_proxy_set_user (struct twist_proxy *proxy, void *user)
{
  if (proxy != NULL)
    proxy->inner_user = user;
}

int
twist_proxy_opening (struct twist_proxy *proxy, uint8_t **out, size_t *len)
{
  char line[512];
  int n;

  if (proxy == NULL || out == NULL || len == NULL)
    return TWIST_ERR_INVAL;
  *out = NULL;
  *len = 0;
  if (proxy->kind == TWIST_PROXY_HTTP && proxy->state == PX_START)
    {
      n = snprintf (line, sizeof line,
                    "CONNECT %s:%d HTTP/1.1\r\nHost: %s:%d\r\n\r\n",
                    proxy->target_host != NULL ? proxy->target_host : "",
                    proxy->target_port,
                    proxy->target_host != NULL ? proxy->target_host : "",
                    proxy->target_port);
      if (n < 0 || (size_t) n >= sizeof line)
        return TWIST_ERR_CONNECT;
      *out = (uint8_t *) twist_strdup (line);
      if (*out == NULL)
        return TWIST_ERR_NOMEM;
      *len = (size_t) n;
      proxy->state = PX_HTTP;
      return TWIST_OK;
    }
  if (proxy->kind == TWIST_PROXY_SOCKS5 && proxy->state == PX_START)
    {
      *out = twist_xmalloc (3);
      if (*out == NULL)
        return TWIST_ERR_NOMEM;
      (*out)[0] = 5;
      (*out)[1] = 1;
      (*out)[2] = 0;
      *len = 3;
      proxy->state = PX_SOCKS_GREET;
      return TWIST_OK;
    }
  if (proxy->kind == TWIST_PROXY_SOCKS5 && proxy->state == PX_SOCKS_ASK)
    {
      const char *host = proxy->target_host != NULL ? proxy->target_host : "";
      size_t hl = strlen (host);
      uint8_t *buf;

      if (hl > 255)
        return TWIST_ERR_CONNECT;
      buf = twist_xmalloc (7 + hl);
      if (buf == NULL)
        return TWIST_ERR_NOMEM;
      buf[0] = 5;
      buf[1] = 1;
      buf[2] = 0;
      buf[3] = 3;
      buf[4] = (uint8_t) hl;
      memcpy (buf + 5, host, hl);
      buf[5 + hl] = (uint8_t) (proxy->target_port >> 8);
      buf[6 + hl] = (uint8_t) proxy->target_port;
      *out = buf;
      *len = 7 + hl;
      proxy->state = PX_SOCKS_CONNECT;
      return TWIST_OK;
    }
  return TWIST_ERR_AGAIN;
}

static int
http_status (const uint8_t *buf, size_t len)
{
  const char *p = (const char *) buf;
  const char *sp;

  if (len < 12 || strncmp (p, "HTTP/", 5) != 0)
    return -1;
  sp = memchr (p, ' ', len);
  if (sp == NULL || sp + 4 > p + len)
    return -1;
  if (sp[1] < '0' || sp[1] > '9')
    return -1;
  return (sp[1] - '0') * 100 + (sp[2] - '0') * 10 + (sp[3] - '0');
}

int
twist_proxy_feed (struct twist_proxy *proxy, const uint8_t *data, size_t len,
                  int *ready)
{
  size_t room;

  if (ready != NULL)
    *ready = 0;
  if (proxy == NULL)
    return TWIST_ERR_INVAL;
  if (proxy->state == PX_READY)
    {
      if (ready != NULL)
        *ready = 1;
      return TWIST_OK;
    }
  room = sizeof proxy->acc - proxy->acc_len;
  if (len > room)
    len = room;
  if (len > 0 && data != NULL)
    {
      memcpy (proxy->acc + proxy->acc_len, data, len);
      proxy->acc_len += len;
    }
  if (proxy->state == PX_HTTP)
    {
      size_t i;
      int status;
      for (i = 0; i + 3 < proxy->acc_len; i++)
        if (proxy->acc[i] == '\r' && proxy->acc[i + 1] == '\n'
            && proxy->acc[i + 2] == '\r' && proxy->acc[i + 3] == '\n')
          {
            status = http_status (proxy->acc, i);
            if (status != 200)
              return TWIST_ERR_CONNECT;
            proxy->state = PX_READY;
            if (ready != NULL)
              *ready = 1;
            return TWIST_OK;
          }
      return TWIST_OK;
    }
  if (proxy->state == PX_SOCKS_GREET)
    {
      if (proxy->acc_len < 2)
        return TWIST_OK;
      if (proxy->acc[0] != 5 || proxy->acc[1] != 0)
        return TWIST_ERR_CONNECT;
      proxy->acc_len = 0;
      proxy->state = PX_SOCKS_ASK;
      return TWIST_OK;
    }
  if (proxy->state == PX_SOCKS_CONNECT)
    {
      size_t need;
      if (proxy->acc_len < 5)
        return TWIST_OK;
      if (proxy->acc[0] != 5 || proxy->acc[1] != 0)
        return TWIST_ERR_CONNECT;
      if (proxy->acc[3] == 1)
        need = 4 + 4 + 2;
      else if (proxy->acc[3] == 4)
        need = 4 + 16 + 2;
      else if (proxy->acc[3] == 3)
        need = 4 + 1 + proxy->acc[4] + 2;
      else
        return TWIST_ERR_CONNECT;
      if (proxy->acc_len < need)
        return TWIST_OK;
      proxy->state = PX_READY;
      if (ready != NULL)
        *ready = 1;
      return TWIST_OK;
    }
  return TWIST_OK;
}

int
twist_proxy_is_ready (const struct twist_proxy *proxy)
{
  return proxy != NULL && proxy->state == PX_READY;
}

const struct twist_protocol_handler *
twist_proxy_handler (struct twist_proxy *p)
{
  if (p == NULL)
    return NULL;
  return &p->handler;
}
