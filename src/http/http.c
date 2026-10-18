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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>

enum
{
  HTTP_H1 = 1,
  HTTP_H2,
  HTTP_H3
};

struct twist_http
{
  struct twist_easy *easy;
  struct twist_connection *conn;
  struct twist_proxy *proxy;
  struct twist_h1 *h1;
  struct twist_h2 *h2;
  struct twist_h3 *h3;
  struct twist_timer *timer;
  struct twist_protocol_handler handler;
  int https;
  int tunnel;
  int tls_on;
  int sent;
  int finished;
  int mode;
  int status;
  int auth_tries;
  int suppress_body;
  char *location;
  char *challenge;
  char *auth_line;
  char *dial_host;
  int dial_port;
};

static void http_begin (struct twist_http *h);
static void http_free_parsers (struct twist_http *h);

static struct twist_http *
http_of (struct twist_endpoint *ep)
{
  return ep->user_data;
}

static char *
ncopy (const char *s, size_t n)
{
  char *p = twist_xmalloc (n + 1);

  if (p == NULL)
    return NULL;
  if (n > 0)
    memcpy (p, s, n);
  p[n] = 0;
  return p;
}

static void
http_complete (struct twist_http *h, int err)
{
  if (h->finished)
    return;
  h->finished = 1;
  if (h->timer != NULL)
    {
      twist_timer_cancel (h->timer);
      h->timer = NULL;
    }
  if (err == TWIST_OK && h->easy->failonerror && h->status >= 400)
    err = TWIST_ERR_PROTOCOL;
  twist_easy_finish (h->easy, err);
}

static void
on_status (void *user, int code, const char *reason, size_t n)
{
  struct twist_http *h = user;
  char line[64];
  int wr;

  (void) reason;
  (void) n;
  h->status = code;
  h->easy->http_code = code;
  if (h->easy->header_cb == NULL)
    return;
  wr = snprintf (line, sizeof line, "HTTP/1.1 %d\r\n", code);
  if (wr > 0)
    h->easy->header_cb (line, 1, (size_t) wr, h->easy->header_data);
}

static void
on_header (void *user, const char *name, size_t name_len, const char *value,
           size_t value_len)
{
  struct twist_http *h = user;
  char *line;
  size_t n;

  if (name_len == 8 && strncasecmp (name, "location", 8) == 0)
    {
      free (h->location);
      h->location = ncopy (value, value_len);
    }
  else if (name_len == 16 && strncasecmp (name, "www-authenticate", 16) == 0)
    {
      free (h->challenge);
      h->challenge = ncopy (value, value_len);
    }
  else if (name_len == 12 && strncasecmp (name, "content-type", 12) == 0)
    {
      free (h->easy->content_type);
      h->easy->content_type = ncopy (value, value_len);
    }
  else if (name_len == 10 && strncasecmp (name, "set-cookie", 10) == 0
           && h->easy->share != NULL && h->easy->share->jar != NULL)
    {
      char *cookie = ncopy (value, value_len);
      if (cookie != NULL)
        {
          twist_jar_store (h->easy->share->jar, cookie, h->easy->url->host,
                           h->easy->url->path, h->https);
          free (cookie);
        }
    }
  if (h->easy->header_cb == NULL)
    return;
  line = twist_xmalloc (name_len + value_len + 5);
  if (line == NULL)
    return;
  memcpy (line, name, name_len);
  n = name_len;
  line[n++] = ':';
  line[n++] = ' ';
  memcpy (line + n, value, value_len);
  n += value_len;
  line[n++] = '\r';
  line[n++] = '\n';
  line[n] = 0;
  h->easy->header_cb (line, 1, n, h->easy->header_data);
  free (line);
}

static void
on_body (void *user, const uint8_t *data, size_t len)
{
  struct twist_http *h = user;

  h->easy->size_download += len;
  if (h->easy->write_cb != NULL && len > 0)
    h->easy->write_cb ((char *) data, 1, len, h->easy->write_data);
}

static void http_message_done (void *user);

static int
arm_parsers (struct twist_http *h)
{
  struct twist_h1_events ev;

  memset (&ev, 0, sizeof ev);
  ev.user = h;
  ev.status_line = on_status;
  ev.header = on_header;
  ev.body = on_body;
  ev.message_done = http_message_done;
  http_free_parsers (h);
  h->h1 = twist_h1_new (&ev);
  h->h2 = twist_h2_new (&ev);
  h->h3 = twist_h3_new (&ev);
  if (h->h1 == NULL || h->h2 == NULL || h->h3 == NULL)
    return TWIST_ERR_NOMEM;
  return TWIST_OK;
}

static struct twist_slist *
request_headers (struct twist_http *h)
{
  struct twist_easy *easy = h->easy;
  struct twist_slist *list = NULL;
  struct twist_slist *scan;
  char buf[512];
  const char *ua = easy->useragent != NULL ? easy->useragent : "twist/0.1";

  snprintf (buf, sizeof buf, "User-Agent: %s", ua);
  list = twist_slist_append (list, buf);
  if (h->auth_line != NULL)
    list = twist_slist_append (list, h->auth_line);
  else if (easy->bearer != NULL)
    {
      snprintf (buf, sizeof buf, "Authorization: Bearer %s", easy->bearer);
      list = twist_slist_append (list, buf);
    }
  else if (easy->username != NULL
           && (easy->auth == 0 || (easy->auth & TWISTAUTH_BASIC) != 0)
           && (easy->auth & TWISTAUTH_DIGEST) == 0)
    {
      char *basic = NULL;
      if (twist_auth_basic (easy->username, easy->password, &basic) == TWIST_OK)
        {
          list = twist_slist_append (list, basic);
          free (basic);
        }
    }
  if (easy->cookie != NULL)
    {
      snprintf (buf, sizeof buf, "Cookie: %s", easy->cookie);
      list = twist_slist_append (list, buf);
    }
  else if (easy->share != NULL && easy->share->jar != NULL)
    {
      char *cookie = NULL;
      if (twist_jar_header (easy->share->jar, easy->url->host, easy->url->path,
                            h->https, &cookie) == TWIST_OK
          && cookie != NULL)
        {
          list = twist_slist_append (list, cookie);
          free (cookie);
        }
    }
  if (easy->range != NULL)
    {
      snprintf (buf, sizeof buf, "Range: bytes=%s", easy->range);
      list = twist_slist_append (list, buf);
    }
  if (easy->referer != NULL)
    {
      snprintf (buf, sizeof buf, "Referer: %s", easy->referer);
      list = twist_slist_append (list, buf);
    }
  for (scan = easy->headers; scan != NULL; scan = scan->next)
    list = twist_slist_append (list, scan->data);
  return list;
}

static int
send_request (struct twist_http *h)
{
  struct twist_easy *easy = h->easy;
  struct twist_url *url = easy->url;
  const char *method;
  const char *path;
  char target[2048];
  char authority[512];
  struct twist_slist *extra;
  const uint8_t *body = NULL;
  size_t body_len = 0;
  uint8_t *out = NULL;
  size_t out_len = 0;
  int rc;
  int http10;

  if (h->sent || h->conn == NULL)
    return TWIST_OK;
  method = "GET";
  if (easy->nobody)
    method = "HEAD";
  else if (easy->method != NULL)
    method = easy->method;
  else if (easy->postfields != NULL && !h->suppress_body)
    method = "POST";
  path = url->path != NULL && url->path[0] != 0 ? url->path : "/";
  if (h->proxy != NULL && !h->tunnel)
    snprintf (target, sizeof target, "%s",
              easy->effective_url != NULL ? easy->effective_url : path);
  else if (url->query != NULL)
    snprintf (target, sizeof target, "%s?%s", path, url->query);
  else
    snprintf (target, sizeof target, "%s", path);
  if (url->port > 0
      && url->port != twist_url_default_port (url->scheme))
    snprintf (authority, sizeof authority, "%s:%d", url->host, url->port);
  else
    snprintf (authority, sizeof authority, "%s", url->host != NULL ? url->host : "");
  if (!h->suppress_body && easy->postfields != NULL)
    {
      body = (const uint8_t *) easy->postfields;
      body_len = easy->postfieldsize_set && easy->postfieldsize >= 0
        ? (size_t) easy->postfieldsize : strlen (easy->postfields);
    }
  extra = request_headers (h);
  http10 = easy->http_version == TWIST_HTTP_VERSION_1_0;
  if (h->mode == HTTP_H2)
    rc = twist_h2_request (h->h2, method, url->scheme, authority, target, extra,
                           body, body_len, &out, &out_len);
  else if (h->mode == HTTP_H3)
    rc = twist_h3_request (h->h3, method, url->scheme, authority, target, extra,
                           body, body_len, &out, &out_len);
  else
    rc = twist_h1_write_request (method, target, authority, http10, extra, body,
                                 body_len, &out, &out_len);
  twist_slist_free_all (extra);
  if (rc != TWIST_OK)
    return rc;
  rc = twist_endpoint_send (twist_connection_endpoint (h->conn), out, out_len);
  free (out);
  if (rc == TWIST_OK)
    h->sent = 1;
  return rc;
}

static void
http_auth_again (void *user)
{
  struct twist_http *h = user;

  h->sent = 0;
  if (arm_parsers (h) != TWIST_OK)
    {
      http_complete (h, TWIST_ERR_NOMEM);
      return;
    }
  if (send_request (h) != TWIST_OK)
    http_complete (h, TWIST_ERR_AUTH);
}

static void
http_restart (void *user)
{
  struct twist_http *h = user;
  struct twist_connection *c = h->conn;

  h->conn = NULL;
  h->sent = 0;
  h->status = 0;
  h->tls_on = 0;
  h->finished = 0;
  free (h->location);
  h->location = NULL;
  free (h->challenge);
  h->challenge = NULL;
  if (c != NULL)
    twist_connection_free (c);
  twist_proxy_free (h->proxy);
  h->proxy = NULL;
  free (h->dial_host);
  h->dial_host = NULL;
  if (arm_parsers (h) != TWIST_OK)
    {
      http_complete (h, TWIST_ERR_NOMEM);
      return;
    }
  http_begin (h);
}

static void
http_message_done (void *user)
{
  struct twist_http *h = user;
  struct twist_easy *easy = h->easy;
  int use_get = 0;

  if (h->status == 401 && h->auth_tries < 2 && h->challenge != NULL
      && easy->username != NULL
      && (easy->auth & (TWISTAUTH_BASIC | TWISTAUTH_DIGEST)) != 0)
    {
      char *hdr = NULL;
      int rc = TWIST_ERR_AUTH;
      const char *method = easy->method != NULL ? easy->method : "GET";
      const char *path = easy->url->path != NULL ? easy->url->path : "/";

      if ((easy->auth & TWISTAUTH_DIGEST) != 0)
        rc = twist_auth_digest (h->challenge, method, path, easy->username,
                                easy->password != NULL ? easy->password : "",
                                (unsigned) (h->auth_tries + 1), "0a4f113b",
                                &hdr);
      if (rc != TWIST_OK && (easy->auth & TWISTAUTH_BASIC) != 0)
        rc = twist_auth_basic (easy->username, easy->password, &hdr);
      if (rc == TWIST_OK)
        {
          free (h->auth_line);
          h->auth_line = hdr;
          h->auth_tries++;
          twist_loop_post (easy->loop, http_auth_again, h);
          return;
        }
    }
  if (h->location != NULL
      && twist_http_should_redirect (h->status, easy->method, easy->follow,
                                     easy->redirs, easy->maxredirs, &use_get))
    {
      struct twist_url *next = NULL;
      if (twist_url_resolve_int (easy->url, h->location, &next) != TWIST_OK)
        {
          http_complete (h, TWIST_ERR_URL);
          return;
        }
      twist_url_free_int (easy->url);
      easy->url = next;
      free (easy->effective_url);
      easy->effective_url = twist_url_format (next);
      easy->redirs++;
      if (use_get)
        h->suppress_body = 1;
      h->https = next->scheme != NULL && strcmp (next->scheme, "https") == 0;
      twist_loop_post (easy->loop, http_restart, h);
      return;
    }
  http_complete (h, TWIST_OK);
}

static size_t
http_receive (struct twist_endpoint *ep, const uint8_t *data, size_t len)
{
  struct twist_http *h = http_of (ep);

  if (h->mode == HTTP_H2)
    return twist_h2_receive (h->h2, data, len);
  if (h->mode == HTTP_H3)
    return twist_h3_receive (h->h3, data, len);
  return twist_h1_receive (h->h1, data, len);
}

static void
http_security (struct twist_endpoint *ep, const char *alpn, size_t alpn_len)
{
  struct twist_http *h = http_of (ep);

  if (alpn_len == 2 && memcmp (alpn, "h2", 2) == 0)
    h->mode = HTTP_H2;
  else if (alpn_len == 2 && memcmp (alpn, "h3", 2) == 0)
    h->mode = HTTP_H3;
  else
    h->mode = HTTP_H1;
  if (send_request (h) != TWIST_OK)
    http_complete (h, TWIST_ERR_PROTOCOL);
}

static void
http_connected (struct twist_endpoint *ep)
{
  struct twist_http *h = http_of (ep);
  const char *alpn[2];
  size_t n = 0;
  int rc;

  if (h->https && !h->tls_on)
    {
      if (h->easy->http_version != TWIST_HTTP_VERSION_1_0
          && h->easy->http_version != TWIST_HTTP_VERSION_1_1)
        alpn[n++] = "h2";
      alpn[n++] = "http/1.1";
      rc = twist_connection_start_tls (h->conn, h->easy->url->host,
                                       h->easy->verifypeer,
                                       n > 0 ? alpn : NULL, n,
                                       h->easy->cainfo);
      if (rc != TWIST_OK)
        {
          http_complete (h, rc);
          return;
        }
      h->tls_on = 1;
      return;
    }
  if (send_request (h) != TWIST_OK)
    http_complete (h, TWIST_ERR_PROTOCOL);
}

static void
http_disconnected (struct twist_endpoint *ep, int error)
{
  struct twist_http *h = http_of (ep);

  if (!h->finished)
    http_complete (h, error != TWIST_OK ? error : TWIST_ERR_CLOSED);
}

static void
http_error (struct twist_endpoint *ep, int error)
{
  struct twist_http *h = http_of (ep);

  if (!h->finished)
    http_complete (h, error);
}

static void
http_read_finished (struct twist_endpoint *ep)
{
  struct twist_http *h = http_of (ep);

  if (!h->finished && h->mode == HTTP_H3)
    http_message_done (h);
}

static void
on_timeout (void *user)
{
  struct twist_http *h = user;

  h->timer = NULL;
  http_complete (h, TWIST_ERR_TIMEOUT);
}

static void
dial (struct twist_http *h, const struct twist_dns_addr *addr)
{
  struct twist_endpoint *ep;
  struct sockaddr_in sin;
  struct sockaddr_in6 sin6;
  const void *sa;
  size_t salen;
  int rc;

  h->conn = twist_connection_new (h->easy->loop);
  if (h->conn == NULL)
    {
      http_complete (h, TWIST_ERR_NOMEM);
      return;
    }
  ep = twist_connection_endpoint (h->conn);
  if (h->proxy != NULL && h->tunnel)
    {
      ep->user_data = h->proxy;
      twist_proxy_set_user (h->proxy, h);
      twist_connection_set_handler (h->conn, twist_proxy_handler (h->proxy));
    }
  else
    {
      ep->user_data = h;
      twist_connection_set_handler (h->conn, &h->handler);
    }
  if (addr->family == 6)
    {
      memset (&sin6, 0, sizeof sin6);
      sin6.sin6_family = AF_INET6;
      memcpy (&sin6.sin6_addr, addr->addr, 16);
      sin6.sin6_port = htons ((uint16_t) h->dial_port);
      sa = &sin6;
      salen = sizeof sin6;
    }
  else
    {
      memset (&sin, 0, sizeof sin);
      sin.sin_family = AF_INET;
      memcpy (&sin.sin_addr, addr->addr, 4);
      sin.sin_port = htons ((uint16_t) h->dial_port);
      sa = &sin;
      salen = sizeof sin;
    }
  rc = twist_connection_connect (h->conn, sa, salen,
                                 (uint64_t) h->easy->connect_timeout_ms);
  if (rc != TWIST_OK)
    http_complete (h, rc);
}

static void
start_quic (struct twist_http *h, const struct twist_dns_addr *addr)
{
  struct twist_easy *easy = h->easy;
  char *saved = easy->url->host;
  char *literal;
  int rc;

  if (twist_quic_connect_fn == NULL)
    {
      http_complete (h, TWIST_ERR_UNSUPPORTED);
      return;
    }
  literal = twist_strdup (addr->text);
  if (literal == NULL || literal[0] == 0)
    {
      free (literal);
      http_complete (h, TWIST_ERR_RESOLVE);
      return;
    }
  easy->url->host = literal;
  rc = twist_quic_connect_fn (easy, &h->conn);
  easy->url->host = saved;
  free (literal);
  if (rc != TWIST_OK)
    {
      http_complete (h, rc);
      return;
    }
  twist_connection_endpoint (h->conn)->user_data = h;
  twist_connection_set_handler (h->conn, &h->handler);
}

static void
on_resolved (void *user, int err, const struct twist_dns_addr *addr)
{
  struct twist_http *h = user;

  if (h->finished)
    return;
  if (err != TWIST_OK || addr == NULL)
    {
      http_complete (h, err != TWIST_OK ? err : TWIST_ERR_RESOLVE);
      return;
    }
  if (h->mode == HTTP_H3)
    {
      start_quic (h, addr);
      return;
    }
  dial (h, addr);
}

static void
http_begin (struct twist_http *h)
{
  struct twist_easy *easy = h->easy;
  struct twist_url *url = easy->url;
  int kind = TWIST_PROXY_NONE;
  char *phost = NULL;
  int pport = 0;
  const char *dial;

  h->https = url->scheme != NULL && strcmp (url->scheme, "https") == 0;
  h->mode = HTTP_H1;
  if (easy->http_version == TWIST_HTTP_VERSION_3
      || easy->http_version == TWIST_HTTP_VERSION_3ONLY)
    h->mode = HTTP_H3;
  if (easy->share != NULL && easy->share->hsts != NULL && !h->https
      && twist_hsts_upgrade (easy->share->hsts, url->host,
                             twist_loop_now (easy->loop)))
    {
      free (url->scheme);
      url->scheme = twist_strdup ("https");
      if (url->port == 80)
        url->port = 443;
      h->https = 1;
      free (easy->effective_url);
      easy->effective_url = twist_url_format (url);
    }
  if (easy->timeout_ms > 0 && h->timer == NULL)
    twist_loop_schedule (easy->loop,
                         twist_loop_now (easy->loop) + (uint64_t) easy->timeout_ms,
                         on_timeout, h, &h->timer);
  h->dial_port = url->port;
  dial = url->host;
  h->tunnel = 0;
  if (h->mode != HTTP_H3 && easy->proxy != NULL)
    {
      if (twist_proxy_parse (easy->proxy, &kind, &phost, &pport) != TWIST_OK)
        {
          http_complete (h, TWIST_ERR_URL);
          return;
        }
      h->tunnel = h->https || kind == TWIST_PROXY_SOCKS5;
      if (h->tunnel || kind == TWIST_PROXY_HTTP)
        {
          dial = phost;
          h->dial_port = pport;
        }
      if (h->tunnel)
        {
          h->proxy = twist_proxy_new (kind, phost, pport, &h->handler);
          if (h->proxy != NULL)
            twist_proxy_set_target (h->proxy, url->host, url->port);
        }
      else if (kind == TWIST_PROXY_HTTP)
        h->proxy = twist_proxy_new (kind, phost, pport, NULL);
    }
  h->dial_host = twist_strdup (dial != NULL ? dial : "");
  free (phost);
  if (h->dial_host == NULL)
    {
      http_complete (h, TWIST_ERR_NOMEM);
      return;
    }
  if (twist_dns_resolve (easy->loop, h->dial_host, on_resolved, h) != TWIST_OK)
    http_complete (h, TWIST_ERR_RESOLVE);
}

static void
http_free_parsers (struct twist_http *h)
{
  twist_h1_free (h->h1);
  twist_h2_free (h->h2);
  twist_h3_free (h->h3);
  h->h1 = NULL;
  h->h2 = NULL;
  h->h3 = NULL;
}

static void
http_free (void *p)
{
  struct twist_http *h = p;

  if (h == NULL)
    return;
  if (h->timer != NULL)
    twist_timer_cancel (h->timer);
  twist_connection_free (h->conn);
  twist_proxy_free (h->proxy);
  http_free_parsers (h);
  free (h->location);
  free (h->challenge);
  free (h->auth_line);
  free (h->dial_host);
  free (h);
}

int
twist_http_attach (struct twist_easy *easy)
{
  struct twist_http *h;

  if (easy == NULL || easy->url == NULL || easy->loop == NULL)
    return TWIST_ERR_INVAL;
  h = calloc (1, sizeof *h);
  if (h == NULL)
    return TWIST_ERR_NOMEM;
  h->easy = easy;
  easy->xfer = h;
  easy->xfer_free = http_free;
  h->handler.connected = http_connected;
  h->handler.receive = http_receive;
  h->handler.disconnected = http_disconnected;
  h->handler.security_established = http_security;
  h->handler.error = http_error;
  h->handler.read_finished = http_read_finished;
  if (easy->username == NULL && easy->url->user != NULL)
    {
      easy->username = twist_strdup (easy->url->user);
      easy->password = twist_strdup (easy->url->password);
    }
  if (arm_parsers (h) != TWIST_OK)
    return TWIST_ERR_NOMEM;
  http_begin (h);
  return h->finished ? easy->result : TWIST_OK;
}

int
twist_http_should_redirect (int status, const char *method, int follow,
                            long redirs, long maxredirs, int *use_get)
{
  (void) method;
  *use_get = 0;
  if (!follow || redirs >= maxredirs)
    return 0;
  if (status != 301 && status != 302 && status != 303
      && status != 307 && status != 308)
    return 0;
  /* 301, 302, and 303 replay as GET.  307 and 308 keep the method.  */
  if (status == 301 || status == 302 || status == 303)
    *use_get = 1;
  return 1;
}
