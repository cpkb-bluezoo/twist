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

#include "gettext.h"
#include "twist-int.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

/* One TCP dial shared by SMTP, POP3 and IMAP.  The protocol handler
   owns the greeting; this only resolves and connects.  */

static void
on_timeout (void *user)
{
  struct twist_mail_link *link = user;

  link->timer = NULL;
  if (link->fail != NULL)
    link->fail (link->user, TWIST_ERR_TIMEOUT);
}

static void
on_phase_timeout (void *user)
{
  struct twist_mail_link *link = user;
  char msg[128];

  link->phase_timer = NULL;
  if (twist_transfer_error (link->transfer) == NULL)
    {
      snprintf (msg, sizeof msg, _("timed out after %ld ms making the "
                                   "connection"), link->transfer->connect_timeout_ms);
      twist_transfer_set_error (link->transfer, twist_strdup (msg));
    }
  if (link->fail != NULL)
    link->fail (link->user, TWIST_ERR_TIMEOUT);
}

void
twist_mail_link_phase_begin (struct twist_mail_link *link)
{
  if (link->phase_timer == NULL && link->transfer->connect_timeout_ms > 0
      && link->transfer->loop != NULL)
    twist_loop_schedule (link->transfer->loop,
                         twist_loop_now (link->transfer->loop)
                         + (uint64_t) link->transfer->connect_timeout_ms,
                         on_phase_timeout, link, &link->phase_timer);
}

void
twist_mail_link_phase_end (struct twist_mail_link *link)
{
  if (link->phase_timer != NULL)
    {
      twist_timer_cancel (link->phase_timer);
      link->phase_timer = NULL;
    }
}

static void
arm_timeout (struct twist_mail_link *link)
{
  if (link->transfer->timeout_ms > 0)
    twist_loop_schedule (link->transfer->loop,
                         twist_loop_now (link->transfer->loop)
                         + (uint64_t) link->transfer->timeout_ms,
                         on_timeout, link, &link->timer);
}

static int
dial_tcp (struct twist_mail_link *link, const struct twist_dns_addr *addr)
{
  struct twist_connection *c;
  struct sockaddr_in sin;
  struct sockaddr_in6 sin6;
  const void *sa;
  size_t salen;
  void *user = link->user;
  const struct twist_protocol_handler *handler = link->handler;

  if (link->tls_tunnel)
    {
      struct twist_tunnel_spec spec;
      int rc;

      memset (&spec, 0, sizeof spec);
      spec.proxy_host = link->dial_host;
      spec.proxy_port = link->dial_port;
      spec.user = link->tun_user;
      spec.pass = link->tun_pass;
      spec.host = link->transfer->url->host;
      spec.port = link->transfer->url->port > 0
        ? link->transfer->url->port
        : twist_url_default_port (link->transfer->url->scheme);
      rc = twist_tunnel_connect (link->transfer, &spec, addr, handler, user,
                                 &c);
      link->conn = c;
      return rc;
    }
  c = twist_connection_new (link->transfer->loop);
  if (c == NULL)
    return TWIST_ERR_NOMEM;
  link->conn = c;
  if (link->proxy != NULL)
    {
      user = link->proxy;
      handler = twist_proxy_handler (link->proxy);
      twist_proxy_set_user (link->proxy, link->user);
    }
  twist_connection_endpoint (c)->user_data = user;
  twist_connection_set_handler (c, handler);
  if (addr->family == 6)
    {
      memset (&sin6, 0, sizeof sin6);
      sin6.sin6_family = AF_INET6;
      memcpy (&sin6.sin6_addr, addr->addr, 16);
      sin6.sin6_scope_id = addr->scope_id;
      sin6.sin6_port = htons ((uint16_t) link->dial_port);
      sa = &sin6;
      salen = sizeof sin6;
    }
  else
    {
      memset (&sin, 0, sizeof sin);
      sin.sin_family = AF_INET;
      memcpy (&sin.sin_addr, addr->addr, 4);
      sin.sin_port = htons ((uint16_t) link->dial_port);
      sa = &sin;
      salen = sizeof sin;
    }
  return twist_connection_connect
    (c, sa, salen, (uint64_t) link->transfer->connect_timeout_ms);
}

static void
on_resolved (void *user, int err, const struct twist_dns_addr *addr)
{
  struct twist_mail_link *link = user;
  int rc;

  if (err != TWIST_OK || addr == NULL)
    {
      if (link->fail != NULL)
        link->fail (link->user, err != TWIST_OK ? err : TWIST_ERR_RESOLVE);
      return;
    }
  rc = dial_tcp (link, addr);
  if (rc != TWIST_OK && link->fail != NULL)
    link->fail (link->user, rc);
}

int
twist_mail_link_open (struct twist_mail_link *link,
                      struct twist_transfer *transfer,
                      const struct twist_protocol_handler *handler,
                      void *user, void (*fail) (void *user, int err))
{
  struct twist_url *url;
  const char *dial;
  int kind = TWIST_PROXY_NONE;
  char *phost = NULL, *puser = NULL, *ppass = NULL;
  int pport = 0;

  if (link == NULL || transfer == NULL || transfer->url == NULL
      || transfer->loop == NULL
      || handler == NULL)
    return TWIST_ERR_INVAL;
  memset (link, 0, sizeof *link);
  link->transfer = transfer;
  link->handler = handler;
  link->user = user;
  link->fail = fail;
  url = transfer->url;
  link->dial_port = url->port;
  dial = url->host;
  if (twist_transfer_proxy (transfer) != NULL)
    {
      int rc = twist_proxy_parse (twist_transfer_proxy (transfer), &kind, &phost, &pport, &puser,
                                  &ppass);

      if (rc == TWIST_ERR_UNSUPPORTED)
        {
          twist_transfer_set_error (transfer,
                                    twist_strdup (_("this kind of proxy is "
                                                    "not supported; use "
                                                    "http://, https:// or "
                                                    "socks5://")));
          return rc;
        }
      if (rc != TWIST_OK)
        return TWIST_ERR_URL;
      if (kind == TWIST_PROXY_HTTPS)
        {
          /* TLS to the proxy and CONNECT in it (tunnel.c).  */
          link->tls_tunnel = 1;
          link->tun_user = puser;
          link->tun_pass = ppass;
          puser = ppass = NULL;
          dial = phost;
          link->dial_port = pport;
        }
      else
        {
          link->proxy = twist_proxy_new (kind, phost, pport, handler);
          if (link->proxy == NULL)
            {
              free (phost);
              free (puser);
              free (ppass);
              return TWIST_ERR_NOMEM;
            }
          twist_proxy_set_target (link->proxy, url->host, url->port);
          twist_proxy_configure (link->proxy, transfer, puser, ppass);
          dial = phost;
          link->dial_port = pport;
        }
    }
  link->dial_host = twist_strdup (dial != NULL ? dial : "");
  free (phost);
  free (puser);
  if (ppass != NULL)
    {
      memset (ppass, 0, strlen (ppass));
      free (ppass);
    }
  if (link->dial_host == NULL)
    return TWIST_ERR_NOMEM;
  arm_timeout (link);
  {
    int rc = twist_dns_resolve_transfer (transfer, link->dial_host,
                                         on_resolved, link);

    if (rc != TWIST_OK)
      return rc;
  }
  return TWIST_OK;
}

struct twist_connection *
twist_mail_link_detach (struct twist_mail_link *link)
{
  struct twist_connection *c = link->conn;

  if (link->timer != NULL)
    {
      twist_timer_cancel (link->timer);
      link->timer = NULL;
    }
  twist_mail_link_phase_end (link);
  link->conn = NULL;
  return c;
}

void
twist_mail_link_attach (struct twist_mail_link *link,
                        struct twist_transfer *transfer,
                        struct twist_connection *conn)
{
  link->transfer = transfer;
  link->conn = conn;
  twist_connection_endpoint (conn)->user_data = link->user;
  twist_connection_set_handler (conn, link->handler);
  arm_timeout (link);
}

void
twist_mail_link_close (struct twist_mail_link *link)
{
  if (link == NULL)
    return;
  if (link->timer != NULL)
    twist_timer_cancel (link->timer);
  twist_mail_link_phase_end (link);
  twist_connection_free (link->conn);
  twist_proxy_free (link->proxy);
  free (link->dial_host);
  free (link->tun_user);
  if (link->tun_pass != NULL)
    {
      memset (link->tun_pass, 0, strlen (link->tun_pass));
      free (link->tun_pass);
    }
  memset (link, 0, sizeof *link);
}
