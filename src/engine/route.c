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

#include "gettext.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* An http:// target, and a WebSocket's, is what a proxy can forward.  */
static int
forwardable (const char *scheme)
{
  return scheme != NULL
         && (strcmp (scheme, "http") == 0 || strcmp (scheme, "ws") == 0);
}

static void
route_key (const struct twist_route *r, char *buf, size_t cap)
{
  snprintf (buf, cap, "%s|%d|%d", r->host != NULL ? r->host : "", r->port,
            r->hop);
}

static struct twist_origintab *
tab_of (const struct twist_transfer *transfer)
{
  return transfer != NULL && transfer->runtime != NULL
         ? transfer->runtime->origintab : NULL;
}

void
twist_route_free (struct twist_route *route)
{
  if (route == NULL)
    return;
  free (route->host);
  free (route->user);
  if (route->pass != NULL)
    {
      memset (route->pass, 0, strlen (route->pass));
      free (route->pass);
    }
  memset (route, 0, sizeof *route);
}

int
twist_route_plan (struct twist_transfer *transfer, const char *scheme, int udp,
                  struct twist_route *out)
{
  const char *px;
  int kind = TWIST_PROXY_NONE;
  int rc;

  memset (out, 0, sizeof *out);
  if (transfer == NULL)
    return TWIST_ERR_INVAL;
  px = twist_transfer_proxy (transfer);
  if (px == NULL || transfer->unix_path != NULL)
    return TWIST_OK;
  rc = twist_proxy_parse (px, &kind, &out->host, &out->port, &out->user,
                          &out->pass);
  if (rc != TWIST_OK)
    {
      twist_route_free (out);
      return rc == TWIST_ERR_UNSUPPORTED ? rc : TWIST_ERR_URL;
    }
  out->kind = kind;
  switch (kind)
    {
    case TWIST_PROXY_SOCKS5:
      out->neg = TWIST_NEG_SOCKS5;
      break;
    case TWIST_PROXY_SOCKS5H:
      out->neg = TWIST_NEG_SOCKS5H;
      break;
    case TWIST_PROXY_SOCKS4:
      out->neg = TWIST_NEG_SOCKS4;
      break;
    case TWIST_PROXY_SOCKS4A:
      out->neg = TWIST_NEG_SOCKS4A;
      break;
    default:
      break;
    }
  if (TWIST_PROXY_IS_SOCKS (kind))
    {
      if (udp)
        {
          twist_transfer_set_error (transfer,
                                    twist_strdup (_("HTTP/3 through a proxy "
                                                    "needs an https:// "
                                                    "proxy (CONNECT-UDP)")));
          twist_route_free (out);
          return TWIST_ERR_UNSUPPORTED;
        }
      out->role = TWIST_ROUTE_TCP_TUNNEL;
      out->hop = TWIST_HOP_TCP;
      return TWIST_OK;
    }
  out->hop = kind == TWIST_PROXY_HTTPS ? TWIST_HOP_TLS : TWIST_HOP_TCP;
  if (udp)
    {
      if (kind != TWIST_PROXY_HTTPS)
        {
          twist_transfer_set_error (transfer,
                                    twist_strdup (_("HTTP/3 through a proxy "
                                                    "needs an https:// "
                                                    "proxy (CONNECT-UDP)")));
          twist_route_free (out);
          return TWIST_ERR_UNSUPPORTED;
        }
      out->role = TWIST_ROUTE_UDP_TUNNEL;
      out->neg = TWIST_NEG_CONNECT_UDP;
      return TWIST_OK;
    }
  if (forwardable (scheme) && !transfer->proxy_tunnel)
    {
      char key[400];

      route_key (out, key, sizeof key);
      if (!twist_origintab_noforward (tab_of (transfer), key))
        {
          out->role = TWIST_ROUTE_FORWARD;
          out->neg = TWIST_NEG_NONE;
          return TWIST_OK;
        }
    }
  out->role = TWIST_ROUTE_TCP_TUNNEL;
  out->neg = TWIST_NEG_CONNECT;
  return TWIST_OK;
}

int
twist_route_role (struct twist_transfer *transfer, const char *scheme, int udp)
{
  struct twist_route r;
  int rc = twist_route_plan (transfer, scheme, udp, &r);
  int role = rc == TWIST_OK ? r.role : -1;

  twist_route_free (&r);
  return role;
}

void
twist_route_remember_no_forward (struct twist_transfer *transfer,
                                 const struct twist_route *route)
{
  char key[400];

  if (route == NULL || route->host == NULL || tab_of (transfer) == NULL)
    return;
  route_key (route, key, sizeof key);
  twist_origintab_note_noforward (tab_of (transfer), key);
}
