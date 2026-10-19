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
  int how;
  int have_peer;
  int falling;
  int h3_gave_up;
  int fail_err;
  int https_port;
  int offered_h2c;
  int saw_upgrade_h2c;
  int preface_sent;
  struct twist_session *sess;
  struct twist_h1_events codec;
  int ws;
  int ws_open;
  char ws_key[25];
  char *ws_upgrade;
  char *ws_connection;
  char *ws_accept;
  struct twist_ws *wsess;
  int watch_alt;
  int alt_h3;
  int peer_minor;
  int req_http10;
  struct twist_dns_addr peer;
  char *hdr_line;
  size_t hdr_cap;
  struct twist_coding *coding;
  int decode_err;
};

static void http_begin (struct twist_http *h);
static void http_connected (struct twist_endpoint *ep);
static void http_fail (struct twist_http *h, int err);
static void http_free_parsers (struct twist_http *h);
static void on_version (void *user, int major, int minor);
static int on_switch (void *user);
static int accepts_coding (const char *accept, const char *name);

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

struct twist_session *
twist_session_add (struct twist_multi *multi, const char *key,
                   struct twist_loop *loop, struct twist_connection *conn,
                   struct twist_h2 *h2)
{
  struct twist_session *s;

  if (multi == NULL || key == NULL)
    return NULL;
  s = calloc (1, sizeof *s);
  if (s == NULL)
    return NULL;
  s->key = twist_strdup (key);
  if (s->key == NULL)
    {
      free (s);
      return NULL;
    }
  s->loop = loop;
  s->conn = conn;
  s->h2 = h2;
  s->users = 1;
  s->next = multi->sessions;
  multi->sessions = s;
  return s;
}

struct twist_session *
twist_session_find (struct twist_multi *multi, const char *key,
                    struct twist_loop *loop)
{
  struct twist_session *s;

  if (multi == NULL || key == NULL)
    return NULL;
  for (s = multi->sessions; s != NULL; s = s->next)
    {
      if (s->loop != loop || strcmp (s->key, key) != 0)
        continue;
      if (s->h2 != NULL)
        {
          if (twist_h2_can_open (s->h2))
            return s;
        }
      else if (s->conn != NULL && twist_quic_can_open (s->conn))
        return s;
    }
  return NULL;
}

void
twist_session_release (struct twist_session *session)
{
  if (session != NULL && session->users > 0)
    session->users--;
}

void
twist_session_free_all (struct twist_multi *multi)
{
  struct twist_session *s;

  if (multi == NULL)
    return;
  s = multi->sessions;
  while (s != NULL)
    {
      struct twist_session *next = s->next;

      twist_connection_free (s->conn);
      twist_h2_free (s->h2);
      free (s->key);
      free (s);
      s = next;
    }
  multi->sessions = NULL;
}

static struct twist_pool *
http_pool (struct twist_http *h)
{
  if (h->easy != NULL && h->easy->share != NULL && h->easy->share->pool != NULL)
    return h->easy->share->pool;
  if (h->easy != NULL && h->easy->multi != NULL)
    return h->easy->multi->pool;
  return NULL;
}

static int
http_pool_key (struct twist_http *h, char *buf, size_t cap)
{
  struct twist_url *url;
  int port;
  const char *proxy;
  int n;

  if (h->easy == NULL || h->easy->url == NULL || h->easy->loop == NULL)
    return TWIST_ERR_INVAL;
  url = h->easy->url;
  port = url->port > 0 ? url->port : twist_url_default_port (url->scheme);
  proxy = h->easy->proxy != NULL ? h->easy->proxy : "-";
  n = snprintf (buf, cap, "%p|%s|%s|%d|%s", (void *) h->easy->loop,
                url->scheme != NULL ? url->scheme : "",
                url->host != NULL ? url->host : "", port, proxy);
  if (n < 0 || (size_t) n >= cap)
    return TWIST_ERR_NOMEM;
  return TWIST_OK;
}

static void
http_park (struct twist_http *h)
{
  struct twist_pool *pool;
  struct twist_connection *c;
  char key[1024];

  if (h->mode != HTTP_H1 || h->ws || h->conn == NULL || h->h1 == NULL)
    return;
  if (!twist_h1_keep (h->h1))
    return;
  if (h->proxy != NULL && h->tunnel)
    return;
  pool = http_pool (h);
  if (pool == NULL || http_pool_key (h, key, sizeof key) != TWIST_OK)
    return;
  c = h->conn;
  h->conn = NULL;
  if (twist_pool_put (pool, key, c) != TWIST_OK)
    h->conn = c;
}

static void
http_complete (struct twist_http *h, int err)
{
  if (h->finished)
    return;
  h->finished = 1;
  if (h->ws && h->mode == HTTP_H3 && h->conn != NULL)
    {
      int fr = twist_quic_finish_stream (h->conn);

      if (err == TWIST_OK && fr != TWIST_OK)
        err = fr;
    }
  if (h->timer != NULL)
    {
      twist_timer_cancel (h->timer);
      h->timer = NULL;
    }
  if (err == TWIST_OK
      && twist_http_status_result (h->easy->failonerror, h->status) != TWIST_OK)
    {
      const char *fmt = _("server returned an error: %d");
      size_t n = strlen (fmt) + 16;
      char *msg = twist_xmalloc (n);

      if (msg != NULL
          && snprintf (msg, n, _("server returned an error: %d"),
                       h->status) > 0)
        twist_easy_set_error (h->easy, msg);
      else
        free (msg);
      err = TWIST_ERR_HTTP;
    }
  if (err == TWIST_OK)
    http_park (h);
  twist_easy_finish (h->easy, err);
}

int
twist_http_status_result (int failonerror, int status)
{
  if (failonerror && status >= 400)
    return TWIST_ERR_HTTP;
  return TWIST_OK;
}

static void
on_version (void *user, int major, int minor)
{
  struct twist_http *h = user;

  (void) major;
  h->peer_minor = minor;
}

static int
http_ws_send (void *user, const uint8_t *data, size_t len)
{
  struct twist_http *h = user;
  struct twist_endpoint *ep;

  if (h->conn == NULL)
    return 1;
  ep = twist_connection_endpoint (h->conn);
  if (h->mode == HTTP_H2)
    {
      uint8_t hdr[9];

      if (len > 0xffffff)
        return 1;
      hdr[0] = (uint8_t) (len >> 16);
      hdr[1] = (uint8_t) (len >> 8);
      hdr[2] = (uint8_t) len;
      hdr[3] = 0;
      hdr[4] = 0;
      hdr[5] = 0;
      hdr[6] = 0;
      hdr[7] = 0;
      hdr[8] = 1;
      if (twist_endpoint_send (ep, hdr, sizeof hdr) != TWIST_OK)
        return 1;
    }
  else if (h->mode == HTTP_H3)
    {
      uint8_t hdr[8];
      size_t n = 0;

      hdr[n++] = 0x00;
      if (len < 64)
        hdr[n++] = (uint8_t) len;
      else if (len < 16384)
        {
          hdr[n++] = (uint8_t) (0x40 | (len >> 8));
          hdr[n++] = (uint8_t) len;
        }
      else
        return 1;
      if (twist_endpoint_send (ep, hdr, n) != TWIST_OK)
        return 1;
    }
  return twist_endpoint_send (ep, data, len) == TWIST_OK ? 0 : 1;
}

static void
http_ws_done (void *user, int err)
{
  http_complete (user, err);
}

static int
ws_write_body (struct twist_http *h)
{
  struct twist_easy *easy = h->easy;

  if (easy->postfields != NULL)
    {
      size_t n = easy->postfieldsize_set && easy->postfieldsize >= 0
        ? (size_t) easy->postfieldsize : strlen (easy->postfields);

      return twist_ws_send (h->wsess, 2, 1,
                            (const uint8_t *) easy->postfields, n);
    }
  if (easy->read_cb == NULL)
    return TWIST_OK;
  {
    uint8_t held[512];
    size_t held_n = 0;
    int started = 0;
    int opcode = 2;

    for (;;)
      {
        char buf[512];
        size_t n = easy->read_cb (buf, 1, sizeof buf, easy->read_data);
        int rc;

        if (n == 0)
          {
            if (!started)
              return TWIST_OK;
            return twist_ws_send (h->wsess, opcode, 1, held, held_n);
          }
        if (n > sizeof buf)
          return TWIST_ERR_PROTOCOL;
        if (started)
          {
            rc = twist_ws_send (h->wsess, opcode, 0, held, held_n);
            if (rc != TWIST_OK)
              return rc;
            opcode = 0;
          }
        memcpy (held, buf, n);
        held_n = n;
        started = 1;
      }
  }
}

static int
open_websocket (struct twist_http *h)
{
  int rc;

  if (h->ws_open)
    return 1;
  if (h->mode == HTTP_H2 || h->mode == HTTP_H3)
    {
      if (h->status != 200)
        return 0;
    }
  else if (h->status != 101)
    return 0;
  else
    {
      rc = twist_ws_validate (h->ws_key, h->ws_upgrade, h->ws_connection,
                              h->ws_accept);
      if (rc != TWIST_OK)
        {
          http_complete (h, rc);
          return 1;
        }
    }
  h->wsess = twist_ws_new (h->easy, http_ws_send, h, http_ws_done, h);
  if (h->wsess == NULL)
    {
      http_complete (h, TWIST_ERR_NOMEM);
      return 1;
    }
  h->ws_open = 1;
  rc = ws_write_body (h);
  if (rc != TWIST_OK)
    http_complete (h, rc);
  return 1;
}

static int
on_switch (void *user)
{
  struct twist_http *h = user;
  uint8_t *pre = NULL;
  size_t n = 0;

  if (h->ws)
    return open_websocket (h);
  if (!h->offered_h2c || !h->saw_upgrade_h2c)
    return 0;
  if (twist_h2_preface (&pre, &n) != TWIST_OK)
    return 0;
  if (h->conn != NULL
      && twist_endpoint_send (twist_connection_endpoint (h->conn), pre, n)
         != TWIST_OK)
    {
      free (pre);
      return 0;
    }
  free (pre);
  h->preface_sent = 1;
  h->mode = HTTP_H2;
  return 1;
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
  wr = snprintf (line, sizeof line, "HTTP/1.%d %d\r\n",
                 h->peer_minor == 0 ? 0 : 1, code);
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

  if (name_len == 7 && memcmp (name, ":status", 7) == 0)
    {
      int code = 0;
      size_t i;

      for (i = 0; i < value_len; i++)
        {
          if (value[i] < '0' || value[i] > '9')
            break;
          code = code * 10 + (value[i] - '0');
        }
      if (i == value_len && value_len > 0)
        {
          h->status = code;
          h->easy->http_code = code;
        }
    }
  else if (name_len == 8 && strncasecmp (name, "location", 8) == 0)
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
  else if (name_len == 7 && strncasecmp (name, "upgrade", 7) == 0)
    {
      size_t i;
      for (i = 0; i + 3 <= value_len; i++)
        if (strncasecmp (value + i, "h2c", 3) == 0)
          h->saw_upgrade_h2c = 1;
      if (h->ws)
        {
          free (h->ws_upgrade);
          h->ws_upgrade = ncopy (value, value_len);
        }
    }
  else if (h->ws && name_len == 10 && strncasecmp (name, "connection", 10) == 0)
    {
      free (h->ws_connection);
      h->ws_connection = ncopy (value, value_len);
    }
  else if (h->ws && name_len == 20
           && strncasecmp (name, "sec-websocket-accept", 20) == 0)
    {
      free (h->ws_accept);
      h->ws_accept = ncopy (value, value_len);
    }
  else if (name_len == 7 && strncasecmp (name, "alt-svc", 7) == 0)
    {
      int port = 0;
      int clear = 0;
      int h3 = twist_alt_svc_h3 (value, value_len, &port, &clear);
      const char *host = h->easy->url != NULL ? h->easy->url->host : NULL;

      if (host != NULL && clear)
        twist_origin_set_h3 (h->easy, host, 0, 0);
      else if (host != NULL && h3)
        {
          h->alt_h3 = 1;
          if (port <= 0)
            port = h->https ? 443 : h->easy->url->port;
          twist_origin_set_h3 (h->easy, host, 1, port);
        }
    }
  else if (name_len == 16 && strncasecmp (name, "content-encoding", 16) == 0
           && h->easy->accept_encoding != NULL && h->coding == NULL
           && h->decode_err == 0)
    {
      char token[32];
      size_t i = 0;
      size_t o = 0;

      while (i < value_len && (value[i] == ' ' || value[i] == '\t'))
        i++;
      while (i < value_len && value[i] != ' ' && value[i] != '\t'
             && value[i] != ',' && value[i] != ';')
        {
          if (o + 1 >= sizeof token)
            {
              o = sizeof token;
              break;
            }
          token[o++] = value[i++];
        }
      while (i < value_len && (value[i] == ' ' || value[i] == '\t'))
        i++;
      token[o < sizeof token ? o : 0] = 0;
      if (o == 0 || o >= sizeof token || i != value_len)
        h->decode_err = TWIST_ERR_ENCODING;
      else if (strcasecmp (token, "identity") != 0
               && (accepts_coding (h->easy->accept_encoding, token)
                   || (strcasecmp (token, "x-gzip") == 0
                       && accepts_coding (h->easy->accept_encoding, "gzip"))))
        {
          if (!twist_coding_known (token))
            h->decode_err = TWIST_ERR_ENCODING;
          else
            h->decode_err = twist_coding_open (&h->coding, token);
        }
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
  if (name_len + value_len + 5 > h->hdr_cap)
    {
      size_t cap = name_len + value_len + 5;
      char *grown = realloc (h->hdr_line, cap);

      if (grown == NULL)
        return;
      h->hdr_line = grown;
      h->hdr_cap = cap;
    }
  line = h->hdr_line;
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
}

static int
header_named (const struct twist_slist *list, const char *name)
{
  size_t n = strlen (name);

  for (; list != NULL; list = list->next)
    {
      const char *s = list->data;

      if (s != NULL && strncasecmp (s, name, n) == 0 && s[n] == ':')
        return 1;
    }
  return 0;
}

static int
accepts_coding (const char *accept, const char *name)
{
  size_t n;

  if (accept == NULL || name == NULL)
    return 0;
  if (accept[0] == 0)
    return 1;
  n = strlen (name);
  while (*accept != 0)
    {
      while (*accept == ' ' || *accept == '\t' || *accept == ',')
        accept++;
      if (strncasecmp (accept, name, n) == 0
          && (accept[n] == 0 || accept[n] == ',' || accept[n] == ' '
              || accept[n] == '\t' || accept[n] == ';'))
        return 1;
      while (*accept != 0 && *accept != ',')
        accept++;
    }
  return 0;
}

static void
deliver_body (struct twist_http *h, const uint8_t *data, size_t len)
{
  h->easy->size_download += len;
  if (h->easy->failonerror && h->status >= 400)
    return;
  if (h->easy->write_cb != NULL && len > 0)
    twist_write_bytes (h->easy->write_cb, h->easy->write_data, data, len);
}

static void
release_coding (struct twist_http *h)
{
  uint8_t *tail = NULL;
  size_t n = 0;

  if (h->coding == NULL)
    return;
  if (h->decode_err == 0)
    h->decode_err = twist_coding_finish (h->coding, &tail, &n);
  if (h->decode_err == 0 && n > 0)
    deliver_body (h, tail, n);
  free (tail);
  twist_coding_free (h->coding);
  h->coding = NULL;
}

static void
on_body (void *user, const uint8_t *data, size_t len)
{
  struct twist_http *h = user;

  if (h->ws_open)
    {
      twist_ws_receive (h->wsess, data, len);
      return;
    }
  if (h->decode_err != 0)
    return;
  if (h->coding != NULL)
    {
      uint8_t *plain = NULL;
      size_t n = 0;
      int rc = twist_coding_feed (h->coding, data, len, &plain, &n);

      if (rc != TWIST_OK)
        {
          h->decode_err = rc;
          free (plain);
          return;
        }
      if (n > 0)
        deliver_body (h, plain, n);
      free (plain);
      return;
    }
  deliver_body (h, data, len);
}

static void http_message_done (void *user);

static int
http_h2_emit (void *user, const uint8_t *data, size_t len)
{
  struct twist_http *h = user;

  if (h->conn == NULL)
    return TWIST_ERR_CONNECT;
  return twist_endpoint_send (twist_connection_endpoint (h->conn), data, len);
}

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
  ev.version = on_version;
  ev.switching = on_switch;
  h->codec = ev;
  http_free_parsers (h);
  h->h1 = twist_h1_new (&ev);
  h->h2 = twist_h2_new (&ev);
  h->h3 = twist_h3_new (&ev);
  if (h->h2 != NULL)
    twist_h2_set_emit (h->h2, http_h2_emit, h);
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
  if (easy->accept_encoding != NULL
      && !header_named (easy->headers, "Accept-Encoding"))
    {
      const char *v = easy->accept_encoding[0] != 0
        ? easy->accept_encoding : "gzip, deflate";

      if (strlen (v) + 18 < sizeof buf)
        {
          snprintf (buf, sizeof buf, "Accept-Encoding: %s", v);
          list = twist_slist_append (list, buf);
        }
    }
  if (easy->content_encoding != NULL
      && !header_named (easy->headers, "Content-Encoding")
      && strlen (easy->content_encoding) + 19 < sizeof buf)
    {
      snprintf (buf, sizeof buf, "Content-Encoding: %s", easy->content_encoding);
      list = twist_slist_append (list, buf);
    }
  if (h->offered_h2c)
    {
      list = twist_slist_append (list, "Connection: Upgrade, HTTP2-Settings");
      list = twist_slist_append (list, "Upgrade: h2c");
      /* ENABLE_PUSH = 0, matching the connection preface SETTINGS.  */
      list = twist_slist_append (list, "HTTP2-Settings: AAIAAAAAAAQABAAA");
    }
  if (h->ws && (h->mode == HTTP_H2 || h->mode == HTTP_H3))
    {
      struct twist_slist *proto;

      proto = twist_slist_append (NULL, ":protocol: websocket");
      if (proto != NULL)
        {
          proto->next = list;
          list = proto;
        }
    }
  else if (h->ws)
    {
      list = twist_slist_append (list, "Upgrade: websocket");
      list = twist_slist_append (list, "Connection: Upgrade");
      list = twist_slist_append (list, "Sec-WebSocket-Version: 13");
      snprintf (buf, sizeof buf, "Sec-WebSocket-Key: %s", h->ws_key);
      list = twist_slist_append (list, buf);
    }
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
  uint8_t *owned = NULL;
  uint8_t *out = NULL;
  size_t out_len = 0;
  const char *scheme;
  int keep_open = 0;
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
  scheme = url->scheme;
  if (h->ws)
    {
      method = (h->mode == HTTP_H2 || h->mode == HTTP_H3) ? "CONNECT" : "GET";
      if (h->ws_key[0] == 0 && (rc = twist_ws_key (h->ws_key)) != TWIST_OK)
        return rc;
      if (h->mode == HTTP_H2 || h->mode == HTTP_H3)
        {
          scheme = h->https ? "https" : "http";
          keep_open = 1;
          if (h->mode == HTTP_H3)
            twist_quic_hold_stream (h->conn);
        }
    }
  else if (!h->suppress_body && easy->postfields != NULL)
    {
      body = (const uint8_t *) easy->postfields;
      body_len = easy->postfieldsize_set && easy->postfieldsize >= 0
        ? (size_t) easy->postfieldsize : strlen (easy->postfields);
      if (body_len > 0 && easy->content_encoding != NULL
          && !header_named (easy->headers, "Content-Encoding"))
        {
          rc = twist_coding_encode (easy->content_encoding, body, body_len,
                                    &owned, &body_len);
          if (rc != TWIST_OK)
            return rc;
          body = owned;
        }
    }
  extra = request_headers (h);
  http10 = h->req_http10
           || h->easy->http_version == TWIST_HTTP_VERSION_1_0;
  if (h->mode == HTTP_H2)
    {
      twist_h2_set_next_owner (h->h2, &h->codec);
      rc = twist_h2_request (h->h2, method, scheme, authority, target, extra,
                             body, body_len, keep_open, &out, &out_len);
    }
  else if (h->mode == HTTP_H3)
    rc = twist_h3_request (h->h3, method, scheme, authority, target, extra,
                           body, body_len, &out, &out_len);
  else
    rc = twist_h1_write_request (method, target, authority, http10, extra, body,
                                 body_len, &out, &out_len);
  twist_slist_free_all (extra);
  if (rc != TWIST_OK)
    {
      free (owned);
      return rc;
    }
  if (h->mode == HTTP_H2 && !h->preface_sent)
    {
      uint8_t *pre = NULL;
      size_t pn = 0;

      if (twist_h2_preface (&pre, &pn) != TWIST_OK)
        {
          free (out);
          free (owned);
          return TWIST_ERR_NOMEM;
        }
      rc = twist_connection_send_parts (h->conn, pre, pn, out, out_len);
      free (pre);
      h->preface_sent = 1;
    }
  else if (h->mode == HTTP_H1)
    rc = twist_connection_send_parts (h->conn, out, out_len, body, body_len);
  else
    rc = twist_connection_send_parts (h->conn, out, out_len, NULL, 0);
  free (out);
  free (owned);
  if (rc == TWIST_OK)
    {
      h->sent = 1;
      if (h->sess == NULL && h->easy != NULL && h->easy->multi != NULL
          && (h->mode == HTTP_H2 || h->mode == HTTP_H3) && h->conn != NULL)
        {
          char key[1024];

          if (http_pool_key (h, key, sizeof key) == TWIST_OK)
            {
              h->sess = twist_session_add (h->easy->multi, key, h->easy->loop,
                                           h->conn,
                                           h->mode == HTTP_H2 ? h->h2 : NULL);
              if (h->sess != NULL)
                h->sess->preface = h->preface_sent;
            }
        }
    }
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
  int same = 0;
  int port = 0;

  if (h->easy->url != NULL && h->dial_host != NULL
      && h->easy->url->host != NULL
      && strcmp (h->dial_host, h->easy->url->host) == 0 && h->mode == HTTP_H1)
    {
      port = h->easy->url->port > 0
        ? h->easy->url->port : twist_url_default_port (h->easy->url->scheme);
      if (port == h->dial_port)
        same = 1;
    }
  h->conn = NULL;
  h->sent = 0;
  h->status = 0;
  if (!same)
    h->tls_on = 0;
  h->finished = 0;
  h->ws_open = 0;
  twist_ws_free (h->wsess);
  h->wsess = NULL;
  free (h->ws_upgrade);
  h->ws_upgrade = NULL;
  free (h->ws_connection);
  h->ws_connection = NULL;
  free (h->ws_accept);
  h->ws_accept = NULL;
  free (h->location);
  h->location = NULL;
  free (h->challenge);
  h->challenge = NULL;
  if (same && c != NULL)
    {
      h->conn = c;
      if (twist_connection_tls (c) != NULL)
        h->tls_on = 1;
      if (arm_parsers (h) != TWIST_OK)
        {
          http_complete (h, TWIST_ERR_NOMEM);
          return;
        }
      if (send_request (h) != TWIST_OK)
        http_fail (h, TWIST_ERR_PROTOCOL);
      return;
    }
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
  const char *host = easy->url != NULL ? easy->url->host : NULL;

  release_coding (h);
  if (h->decode_err != 0)
    {
      http_complete (h, h->decode_err);
      return;
    }

  if (host != NULL && (h->peer_minor == 0 || h->peer_minor == 1))
    twist_origin_set_http_minor (easy, host, h->peer_minor);
  /* No h3 Alt-Svc on this response: do not probe HTTP/3 again for
     this host in this session.  An entry that did advertise h3 was
     stored for the next stream and does not change this one.  */
  if (host != NULL && h->watch_alt && !h->alt_h3)
    twist_origin_set_h3 (easy, host, 0, 0);
  if (h->ws)
    {
      int opened = h->ws_open || (h->mode != HTTP_H1 && h->status == 200);

      http_complete (h, opened ? TWIST_OK : TWIST_ERR_HTTP);
      return;
    }
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

  if (h->finished)
    return len;
  if (h->ws_open && h->mode == HTTP_H1)
    {
      size_t n = twist_ws_receive (h->wsess, data, len);

      return h->finished ? len : n;
    }
  if (h->mode == HTTP_H2)
    return twist_h2_receive (h->h2, data, len);
  if (h->mode == HTTP_H3)
    return twist_h3_receive (h->h3, data, len);
  return twist_h1_receive (h->h1, data, len);
}

static size_t
session_receive (struct twist_endpoint *ep, const uint8_t *data, size_t len)
{
  struct twist_session *s = ep->user_data;

  if (s == NULL || s->h2 == NULL)
    return len;
  return twist_h2_receive (s->h2, data, len);
}

static void
session_disc (struct twist_endpoint *ep, int error)
{
  struct twist_session *s = ep->user_data;

  (void) error;
  if (s != NULL && s->h2 != NULL)
    twist_h2_drop_user (s->h2, s->h2);
}

static struct twist_protocol_handler session_ops = {
  NULL,
  session_receive,
  session_disc,
  NULL,
  NULL,
  NULL,
  NULL
};

static void start_attempt (struct twist_http *h);

static void
h3_fallback (void *user)
{
  struct twist_http *h = user;
  struct twist_connection *c;

  if (h->finished)
    return;
  h->falling = 0;
  c = h->conn;
  h->conn = NULL;
  h->tls_on = 0;
  h->sent = 0;
  h->preface_sent = 0;
  if (c != NULL)
    twist_connection_free (c);
  h->how = h->https ? TWIST_DISC_ALPN : TWIST_DISC_H2C;
  h->mode = HTTP_H1;
  h->offered_h2c = h->how == TWIST_DISC_H2C;
  start_attempt (h);
}

static void
http_fail (struct twist_http *h, int err)
{
  if (h->finished)
    return;
  /* HTTP/3 was selected by discovery and could not be opened.  One
     fall back, onto ALPN or h2c.  A pinned HTTP/3-only request does
     not.  */
  if (h->status == 0 && !h->sent && h->mode == HTTP_H3 && !h->h3_gave_up
      && h->easy->http_version != TWIST_HTTP_VERSION_3ONLY)
    {
      if (h->falling)
        return;
      h->falling = 1;
      h->h3_gave_up = 1;
      h->fail_err = err;
      twist_loop_post (h->easy->loop, h3_fallback, h);
      return;
    }
  http_complete (h, err);
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
    http_fail (h, TWIST_ERR_PROTOCOL);
}

static void
http_connected (struct twist_endpoint *ep)
{
  struct twist_http *h = http_of (ep);
  const char *alpn[2];
  size_t n = 0;
  int http10;
  int rc;

  if (h->https && !h->tls_on)
    {
      http10 = h->req_http10
               || h->easy->http_version == TWIST_HTTP_VERSION_1_0;
      if (!http10
          && (h->how == TWIST_DISC_ALPN || h->how == TWIST_DISC_H2_PRIOR
              || h->how == TWIST_DISC_H2C))
        alpn[n++] = "h2";
      if (!http10 && h->how != TWIST_DISC_H2_PRIOR)
        alpn[n++] = "http/1.1";
      rc = twist_connection_start_tls (h->conn, h->easy->url->host,
                                       h->easy->verifypeer,
                                       n > 0 ? alpn : NULL, n,
                                       h->easy->cainfo, h->easy->sslcert,
                                       h->easy->sslkey);
      if (rc != TWIST_OK)
        {
          http_fail (h, rc);
          return;
        }
      h->tls_on = 1;
      return;
    }
  if (send_request (h) != TWIST_OK)
    http_fail (h, TWIST_ERR_PROTOCOL);
}

static void
http_disconnected (struct twist_endpoint *ep, int error)
{
  struct twist_http *h = http_of (ep);

  if (!h->finished)
    http_fail (h, error != TWIST_OK ? error : TWIST_ERR_CLOSED);
}

static void
http_error (struct twist_endpoint *ep, int error)
{
  struct twist_http *h = http_of (ep);

  if (!h->finished)
    http_fail (h, error);
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

static int
prepare_dial (struct twist_http *h)
{
  struct twist_easy *easy = h->easy;
  struct twist_url *url = easy->url;
  const char *dial = url->host;
  int port = url->port;
  int kind = TWIST_PROXY_NONE;
  char *phost = NULL;
  int pport = 0;

  if (h->https_port > 0 && !url->port_set)
    port = h->https_port;
  h->tunnel = 0;
  twist_proxy_free (h->proxy);
  h->proxy = NULL;
  if (h->mode != HTTP_H3 && easy->proxy != NULL)
    {
      if (twist_proxy_parse (easy->proxy, &kind, &phost, &pport) != TWIST_OK)
        {
          free (phost);
          return TWIST_ERR_URL;
        }
      h->tunnel = h->https || kind == TWIST_PROXY_SOCKS5;
      if (h->tunnel || kind == TWIST_PROXY_HTTP)
        {
          dial = phost;
          port = pport;
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
  free (h->dial_host);
  h->dial_host = twist_strdup (dial != NULL ? dial : "");
  h->dial_port = port;
  free (phost);
  return h->dial_host != NULL ? TWIST_OK : TWIST_ERR_NOMEM;
}

static size_t
h3_stream_data (void *user, const uint8_t *data, size_t len, int fin)
{
  struct twist_http *h = user;

  (void) fin;
  if (h == NULL || h->h3 == NULL)
    return len;
  return twist_h3_receive (h->h3, data, len);
}

static int
http_borrow (struct twist_http *h)
{
  struct twist_session *s;
  struct twist_multi *multi;
  char key[1024];

  if ((h->mode != HTTP_H2 && h->mode != HTTP_H3) || h->ws)
    return 0;
  if (h->proxy != NULL && h->tunnel)
    return 0;
  multi = h->easy != NULL ? h->easy->multi : NULL;
  if (multi == NULL || http_pool_key (h, key, sizeof key) != TWIST_OK)
    return 0;
  s = twist_session_find (multi, key, h->easy->loop);
  if (s == NULL || s->conn == NULL)
    return 0;
  if (arm_parsers (h) != TWIST_OK)
    return 0;
  if (h->mode == HTTP_H2)
    {
      if (s->h2 == NULL)
        {
          http_free_parsers (h);
          return 0;
        }
      twist_h2_free (h->h2);
      h->h2 = s->h2;
    }
  else
    {
      if (twist_quic_open_stream (s->conn) != TWIST_OK)
        {
          http_free_parsers (h);
          return 0;
        }
      twist_quic_bind (s->conn, h3_stream_data, h);
    }
  h->conn = s->conn;
  h->sess = s;
  s->users++;
  h->preface_sent = 1;
  if (twist_connection_tls (s->conn) != NULL)
    h->tls_on = 1;
  if (send_request (h) != TWIST_OK)
    {
      twist_h2_drop_user (s->h2, h);
      twist_session_release (s);
      h->sess = NULL;
      if (h->h2 == s->h2)
        h->h2 = NULL;
      h->conn = NULL;
      http_complete (h, TWIST_ERR_CONNECT);
    }
  return 1;
}

static int
http_reuse (struct twist_http *h)
{
  struct twist_pool *pool;
  struct twist_connection *c = NULL;
  struct twist_endpoint *ep;
  char key[1024];

  if (h->mode != HTTP_H1 || (h->proxy != NULL && h->tunnel))
    return 0;
  pool = http_pool (h);
  if (pool == NULL || http_pool_key (h, key, sizeof key) != TWIST_OK)
    return 0;
  if (twist_pool_take (pool, key, &c) != TWIST_OK || c == NULL)
    return 0;
  h->conn = c;
  ep = twist_connection_endpoint (c);
  ep->user_data = h;
  twist_connection_set_handler (c, &h->handler);
  if (twist_connection_tls (c) != NULL)
    h->tls_on = 1;
  http_connected (ep);
  return 1;
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

  if (http_borrow (h) || http_reuse (h))
    return;
  h->conn = twist_connection_new (h->easy->loop);
  if (h->conn == NULL)
    {
      http_fail (h, TWIST_ERR_NOMEM);
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
    http_fail (h, rc);
}

static void
on_proxy_resolved (void *user, int err, const struct twist_dns_addr *addr)
{
  struct twist_http *h = user;

  if (h->finished)
    return;
  if (err != TWIST_OK || addr == NULL)
    {
      http_fail (h, err != TWIST_OK ? err : TWIST_ERR_RESOLVE);
      return;
    }
  h->peer = *addr;
  h->have_peer = 1;
  dial (h, &h->peer);
}

static void
start_quic (struct twist_http *h, const struct twist_dns_addr *addr)
{
  if (http_borrow (h))
    return;
  struct twist_easy *easy = h->easy;
  char *saved = easy->url->host;
  int saved_port = easy->url->port;
  char *literal;
  int rc;

  if (twist_quic_connect_fn == NULL)
    {
      http_fail (h, TWIST_ERR_UNSUPPORTED);
      return;
    }
  literal = twist_strdup (addr->text);
  if (literal == NULL || literal[0] == 0)
    {
      free (literal);
      http_fail (h, TWIST_ERR_RESOLVE);
      return;
    }
  easy->url->host = literal;
  if (h->dial_port > 0)
    easy->url->port = h->dial_port;
  rc = twist_quic_connect_fn (easy, &h->conn);
  easy->url->host = saved;
  easy->url->port = saved_port;
  free (literal);
  if (rc != TWIST_OK)
    {
      http_fail (h, rc);
      return;
    }
  twist_connection_endpoint (h->conn)->user_data = h;
  twist_connection_set_handler (h->conn, &h->handler);
}

static void
start_attempt (struct twist_http *h)
{
  int rc;

  rc = prepare_dial (h);
  if (rc != TWIST_OK)
    {
      http_complete (h, rc);
      return;
    }
  if (h->mode != HTTP_H3 && h->easy->url->host != NULL
      && strcmp (h->dial_host, h->easy->url->host) != 0)
    {
      rc = twist_dns_resolve_easy (h->easy, h->dial_host, on_proxy_resolved, h);
      if (rc != TWIST_OK)
        http_fail (h, rc);
      return;
    }
  if (h->mode == HTTP_H3)
    start_quic (h, &h->peer);
  else
    dial (h, &h->peer);
}

static void
apply_how (struct twist_http *h)
{
  h->offered_h2c = 0;
  h->req_http10 = h->easy->http_version == TWIST_HTTP_VERSION_1_0;
  if (!h->req_http10 && h->easy->url != NULL
      && h->easy->http_version != TWIST_HTTP_VERSION_1_1
      && twist_origin_http_minor (h->easy, h->easy->url->host) == 0)
    h->req_http10 = 1;
  if (h->how == TWIST_DISC_H3)
    h->mode = HTTP_H3;
  else if (h->how == TWIST_DISC_H2_PRIOR && !h->https)
    h->mode = HTTP_H2;
  else
    {
      h->mode = HTTP_H1;
      h->offered_h2c = h->how == TWIST_DISC_H2C;
    }
}

static void
on_resolved (void *user, int err, const struct twist_dns_service *svc)
{
  struct twist_http *h = user;
  const char *host = h->easy->url != NULL ? h->easy->url->host : NULL;
  int rr_h3 = 0;
  int cached_port = 0;
  int cached;
  int i;

  if (h->finished)
    return;
  if (err != TWIST_OK || svc == NULL || svc->addr.family == 0)
    {
      http_complete (h, err != TWIST_OK ? err : TWIST_ERR_RESOLVE);
      return;
    }
  h->peer = svc->addr;
  h->have_peer = 1;
  h->https_port = svc->port;
  for (i = 0; i < svc->nalpn; i++)
    if (strcmp (svc->alpn[i], "h3") == 0)
      rr_h3 = 1;
  cached = twist_origin_h3 (h->easy, host, &cached_port);
  if (h->https && svc->have_https && !rr_h3)
    twist_origin_set_h3 (h->easy, host, 0, 0);
  else if (h->https && rr_h3)
    twist_origin_set_h3 (h->easy, host, 1,
                         svc->port > 0 ? svc->port : h->easy->url->port);
  if (twist_http_discover (h->easy->http_version, h->https, svc->have_https,
                           rr_h3, cached, &h->how) != TWIST_OK)
    {
      http_complete (h, TWIST_ERR_UNSUPPORTED);
      return;
    }
  if (h->ws && !h->https)
    {
      int v = h->easy->http_version;

      /* Cleartext has no QUIC.  HTTP/2, when requested, is prior
         knowledge so it does not share Upgrade with the handshake.  */
      if (v == TWIST_HTTP_VERSION_2_0
          || v == TWIST_HTTP_VERSION_2_PRIOR_KNOWLEDGE)
        h->how = TWIST_DISC_H2_PRIOR;
      else
        h->how = TWIST_DISC_H1;
    }
  if (h->how == TWIST_DISC_H3 && !rr_h3 && cached_port > 0 && h->https_port <= 0)
    h->https_port = cached_port;
  h->watch_alt = h->https && !svc->have_https && h->how != TWIST_DISC_H3
                 && cached != -1;
  apply_how (h);
  start_attempt (h);
}

static void
http_begin (struct twist_http *h)
{
  struct twist_easy *easy = h->easy;
  struct twist_url *url = easy->url;

  h->ws = url->scheme != NULL
          && (strcmp (url->scheme, "ws") == 0 || strcmp (url->scheme, "wss") == 0);
  h->https = url->scheme != NULL
             && (strcmp (url->scheme, "https") == 0
                 || strcmp (url->scheme, "wss") == 0);
  h->peer_minor = -1;
  if (!h->ws && easy->share != NULL && easy->share->hsts != NULL && !h->https
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
  {
    int rc = twist_dns_resolve_service_easy (easy, url->host, on_resolved, h);

    if (rc != TWIST_OK)
      http_complete (h, rc);
  }
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
  if (h->sess != NULL)
    {
      if (h->conn != NULL)
        {
          struct twist_endpoint *ep = twist_connection_endpoint (h->conn);

          if (ep->user_data == h)
            {
              ep->user_data = h->sess;
              twist_connection_set_handler (h->conn, &session_ops);
            }
        }
      twist_h2_drop_user (h->sess->h2, h);
      if (h->h2 == h->sess->h2)
        h->h2 = NULL;
      h->conn = NULL;
      twist_session_release (h->sess);
      h->sess = NULL;
    }
  twist_connection_free (h->conn);
  twist_proxy_free (h->proxy);
  http_free_parsers (h);
  twist_ws_free (h->wsess);
  twist_coding_free (h->coding);
  free (h->ws_upgrade);
  free (h->ws_connection);
  free (h->ws_accept);
  free (h->location);
  free (h->challenge);
  free (h->auth_line);
  free (h->dial_host);
  free (h->hdr_line);
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
