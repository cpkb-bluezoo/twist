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
#include <netinet/in.h>
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

  c = twist_connection_new (link->easy->loop);
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
  return twist_connection_connect (c, sa, salen,
                                   (uint64_t) link->easy->connect_timeout_ms);
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
twist_mail_link_open (struct twist_mail_link *link, struct twist_easy *easy,
                      const struct twist_protocol_handler *handler,
                      void *user, void (*fail) (void *user, int err))
{
  struct twist_url *url;
  const char *dial;
  int kind = TWIST_PROXY_NONE;
  char *phost = NULL;
  int pport = 0;

  if (link == NULL || easy == NULL || easy->url == NULL || easy->loop == NULL
      || handler == NULL)
    return TWIST_ERR_INVAL;
  memset (link, 0, sizeof *link);
  link->easy = easy;
  link->handler = handler;
  link->user = user;
  link->fail = fail;
  url = easy->url;
  link->dial_port = url->port;
  dial = url->host;
  if (easy->proxy != NULL)
    {
      if (twist_proxy_parse (easy->proxy, &kind, &phost, &pport) != TWIST_OK)
        return TWIST_ERR_URL;
      link->proxy = twist_proxy_new (kind, phost, pport, handler);
      if (link->proxy == NULL)
        {
          free (phost);
          return TWIST_ERR_NOMEM;
        }
      twist_proxy_set_target (link->proxy, url->host, url->port);
      dial = phost;
      link->dial_port = pport;
    }
  link->dial_host = twist_strdup (dial != NULL ? dial : "");
  free (phost);
  if (link->dial_host == NULL)
    return TWIST_ERR_NOMEM;
  if (easy->timeout_ms > 0)
    twist_loop_schedule (easy->loop,
                         twist_loop_now (easy->loop) + (uint64_t) easy->timeout_ms,
                         on_timeout, link, &link->timer);
  {
    int rc = twist_dns_resolve_easy (easy, link->dial_host, on_resolved, link);

    if (rc != TWIST_OK)
      return rc;
  }
  return TWIST_OK;
}

void
twist_mail_link_close (struct twist_mail_link *link)
{
  if (link == NULL)
    return;
  if (link->timer != NULL)
    twist_timer_cancel (link->timer);
  twist_connection_free (link->conn);
  twist_proxy_free (link->proxy);
  free (link->dial_host);
  memset (link, 0, sizeof *link);
}
