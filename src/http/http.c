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
#include <errno.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <quickstep/crypto.h>
#include <quickstep/status.h>

enum
{
  HTTP_H1 = 1,
  HTTP_H2,
  HTTP_H3
};

/* A transfer on a session, in the session's list of them.  */
struct twist_http;

struct twist_session_user
{
  struct twist_session_user *next;
  struct twist_http *h;
};

struct twist_http
{
  struct twist_transfer *transfer;
  struct twist_connection *conn;
  struct twist_proxy *proxy;
  struct twist_h1 *h1;
  struct twist_h2 *h2;
  struct twist_h3 *h3;
  struct twist_timer *timer;
  struct twist_protocol_handler handler;
  int https;
  int tunnel;
  int tls_tunnel;		/* Through an https proxy: tunnel.c.  */
  int masque;			/* HTTP/3 through CONNECT-UDP: masque.c.  */
  char *tun_tmpl;
  char *tun_user;
  char *tun_pass;
  int tls_on;
  int sent;
  int finished;
  int mode;
  int status;
  int auth_tries;
  int suppress_body;
  int strip_auth;
  char *origin_host;
  int origin_https;
  int origin_set;
  char *location;
  char *challenge;
  char *auth_line;
  char *dial_host;
  int dial_port;
  int how;
  int have_peer;
  int falling;
  /* Commands posted to the loop that hold this record (http_post).  The
     record outlives a free until they have run.  */
  int posted;
  int dead;
  /* A redirect has been taken and its restart is posted.  The connection
     the response came on may close before the restart runs, which is not a
     failure of the transfer, and may not be used again; restart_keep is
     whether the server meant to keep it, and conn_lost whether it did not.  */
  int restarting;
  int restart_keep;
  int conn_lost;
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
  /* Where the transfer stands with its origin (origin.c): waiting for a
     connection that is being made, or for room under the limit on
     connections; the connection it holds against that limit; and the
     connection it is making that others wait for.  Each is a key, or NULL.
     resume_quic says which way to start again.  */
  struct twist_origin_waiter waiter;
  struct twist_session_user su;
  int retried;
  uint8_t *h3_tail;       /* Of a frame, from a shared connection.  */
  size_t h3_tail_len;
  char *slot_key;
  char *lead_key;
  int resume_quic;
  int requeue;                      /* Woken for room that was not there.  */
  int resume_why;                   /* What the table said, atomically.  */
  int peer_minor;
  int req_http10;
  struct twist_dns_addr peer;
  char *hdr_line;
  size_t hdr_cap;
  struct twist_coding *coding;
  int decode_err;
};

static void http_begin (struct twist_http *h);
static void start_quic (struct twist_http *h, const struct twist_dns_addr *addr);
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

/* What the HTTP/2 parser of a session writes on its own account (the window
   updates, the acknowledgements of settings and pings, the rest of a request
   body): to the session's connection, whoever owns it at the moment.  The
   transfer that made the session is not to be relied on, as it ends before
   the session does.  */
static int
session_emit (void *user, const uint8_t *data, size_t len)
{
  struct twist_session *s = user;

  /* A session that is not on a connection has no one to write to, as a
     parser with no emitter has not.  */
  if (s->conn == NULL)
    return TWIST_OK;
  if (s->closed)
    return TWIST_ERR_CONNECT;
  return twist_endpoint_send (twist_connection_endpoint (s->conn), data, len);
}

/* The lane of the runtime that has LOOP; the first if none has.  */
static struct twist_lane *
lane_of_loop (struct twist_runtime *runtime, struct twist_loop *loop)
{
  size_t i;

  for (i = 0; i < runtime->n_lanes; i++)
    if (runtime->lanes[i]->loop == loop)
      return runtime->lanes[i];
  return runtime->lanes[0];
}

struct twist_session *
twist_session_add (struct twist_runtime *runtime, const char *key,
                   struct twist_loop *loop, struct twist_connection *conn,
                   struct twist_h2 *h2)
{
  struct twist_session *s;
  struct twist_lane *lane;

  if (runtime == NULL || key == NULL)
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
  s->runtime = runtime;
  s->conn = conn;
  s->h2 = h2;
  if (h2 != NULL)
    twist_h2_set_emit (h2, session_emit, s);
  lane = lane_of_loop (runtime, loop);
  twist_origintab_session (runtime->origintab, key, 1);
  s->next = lane->sessions;
  lane->sessions = s;
  return s;
}

struct twist_session *
twist_session_find (struct twist_runtime *runtime, const char *key,
                    struct twist_loop *loop)
{
  struct twist_session *s;

  if (runtime == NULL || key == NULL)
    return NULL;
  for (s = lane_of_loop (runtime, loop)->sessions; s != NULL; s = s->next)
    {
      if (s->loop != loop || s->closed || strcmp (s->key, key) != 0)
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
  if (session == NULL)
    return;
  /* A stream is free, which one that waits under the limit on connections
     may use.  */
  if (session->runtime != NULL && session->runtime->origintab != NULL)
    twist_origintab_wake (session->runtime->origintab, session->key);
}

void
twist_session_free_all (struct twist_runtime *runtime)
{
  struct twist_session *s;
  size_t i;

  if (runtime == NULL)
    return;
  for (i = 0; i < runtime->n_lanes; i++)
    {
      s = runtime->lanes[i]->sessions;
      while (s != NULL)
        {
          struct twist_session *next = s->next;

          twist_connection_free (s->conn);
          twist_h2_free (s->h2);
          free (s->slot_key);
          free (s->key);
          free (s);
          s = next;
        }
      runtime->lanes[i]->sessions = NULL;
    }
}

static struct twist_pool *
http_pool (struct twist_http *h)
{
  return twist_transfer_pool (h->transfer);
}

static int
http_pool_key (struct twist_http *h, char *buf, size_t cap)
{
  if (h->transfer == NULL)
    return TWIST_ERR_INVAL;
  return twist_transfer_origin_key (h->transfer, buf, cap);
}

static struct twist_origintab *
http_tab (const struct twist_http *h)
{
  if (h->transfer == NULL || h->transfer->runtime == NULL)
    return NULL;
  return h->transfer->runtime->origintab;
}

/* The connection that was being made for others to share has settled, one way
   or the other, and those who waited for it go on.  It is done once for each
   connection made, and by nobody else.  */
static void
http_settle (struct twist_http *h, int how)
{
  char *key = h->lead_key;
  struct twist_origintab *tab = http_tab (h);

  if (key == NULL)
    return;
  h->lead_key = NULL;
  if (tab != NULL)
    twist_origintab_settle (tab, key, how);
  free (key);
}

/* Give back the connection held against the limit on connections.  */
static void
http_slot_release (struct twist_http *h)
{
  char *key = h->slot_key;
  struct twist_origintab *tab = http_tab (h);

  if (key == NULL)
    return;
  h->slot_key = NULL;
  if (tab != NULL)
    twist_origintab_release (tab, key);
  free (key);
}

static struct twist_protocol_handler session_ops;
static void session_lost (struct twist_session *s, struct twist_http *except,
                          int err);

/* The transfer is on the session S, among the others.  */
static void
session_link (struct twist_http *h, struct twist_session *s)
{
  h->sess = s;
  h->su.h = h;
  h->su.next = s->users_head;
  s->users_head = &h->su;
}

static void
session_unlink (struct twist_http *h)
{
  struct twist_session_user **pp;

  if (h->sess == NULL)
    return;
  for (pp = &h->sess->users_head; *pp != NULL; pp = &(*pp)->next)
    if (*pp == &h->su)
      {
        *pp = h->su.next;
        break;
      }
  h->su.next = NULL;
}

/* Stop using the session, if the transfer is on one.  Its connection is the
   session's, and is handed to it, if the transfer was what it answered to.  */
static void
http_leave_session (struct twist_http *h)
{
  if (h->sess == NULL)
    return;
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
  session_unlink (h);
  twist_session_release (h->sess);
  h->sess = NULL;
}

/* Whether the connection is a tunnel through a proxy, to a target that is not
   the proxy's: such a connection is not kept for others, nor are sessions on
   it shared.  */
static int
via_tunnel (const struct twist_http *h)
{
  return (h->proxy != NULL && h->tunnel) || h->tls_tunnel || h->masque;
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
  if (via_tunnel (h))
    return;
  pool = http_pool (h);
  if (pool == NULL || http_pool_key (h, key, sizeof key) != TWIST_OK)
    return;
  /* A connection kept here is for the transfers of this loop only.  If the
     next in line for one is on another loop, this one is closed (when the
     transfer is let go), and its place goes to that transfer, so that the
     limit on connections holds between loops.  */
  {
    struct twist_loop *next = NULL;
    struct twist_origintab *tab = http_tab (h);

    if (tab != NULL && twist_origintab_next_waiter (tab, key, &next)
        && next != h->transfer->loop)
      return;
  }
  c = h->conn;
  h->conn = NULL;
  {
    struct twist_origintab *tab = http_tab (h);
    int held = tab != NULL && h->slot_key != NULL;

    if ((held ? twist_pool_put_held (pool, key, c)
         : twist_pool_put (pool, key, c)) != TWIST_OK)
      {
        h->conn = c;
        return;
      }
    if (held)
      {
        /* The connection keeps the place it was made under while it is kept:
           the limit counts the connections that are open, whoever has them.
           The pool gives the place back when it closes one, and the transfer
           that takes this one has it.  The first in line for a place is told
           to look again, for this connection.  */
        free (h->slot_key);
        h->slot_key = NULL;
        twist_origintab_idle_add (tab, key, h->transfer->loop);
        twist_origintab_wake (tab, key);
      }
  }
}

static void
http_complete (struct twist_http *h, int err)
{
  if (h->finished)
    return;
  h->finished = 1;
  http_settle (h, TWIST_SETTLE_UNKNOWN);
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
      && twist_http_status_result (h->transfer->failonerror, h->status) != TWIST_OK)
    {
      const char *fmt = _("server returned an error: %d");
      size_t n = strlen (fmt) + 16;
      char *msg = twist_xmalloc (n);

      if (msg != NULL
          && snprintf (msg, n, _("server returned an error: %d"),
                       h->status) > 0)
        twist_transfer_set_error (h->transfer, msg);
      else
        free (msg);
      err = TWIST_ERR_HTTP;
    }
  if (err == TWIST_OK)
    http_park (h);
  twist_transfer_finish (h->transfer, err);
}

int
twist_http_redirect_ok (const char *from, const char *to)
{
  /* By scheme alone.  What a transfer that is encrypted may be carried to is
     encrypted too.  */
  static const struct
  {
    const char *from;
    const char *to;
  } ok[] = {
    { "http", "http" }, { "http", "https" }, { "http", "ftp" },
    { "http", "ftps" }, { "https", "https" }, { "https", "ftps" }
  };
  size_t i;

  if (from == NULL || to == NULL)
    return 0;
  for (i = 0; i < sizeof ok / sizeof ok[0]; i++)
    if (strcasecmp (from, ok[i].from) == 0 && strcasecmp (to, ok[i].to) == 0)
      return 1;
  return 0;
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
  struct twist_transfer *transfer = h->transfer;

  if (transfer->postfields != NULL)
    {
      size_t n = transfer->postfieldsize_set && transfer->postfieldsize >= 0
        ? (size_t) transfer->postfieldsize : strlen (transfer->postfields);

      return twist_ws_send (h->wsess, 2, 1,
                            (const uint8_t *) transfer->postfields, n);
    }
  if (transfer->read_cb == NULL)
    return TWIST_OK;
  {
    uint8_t held[512];
    size_t held_n = 0;
    int started = 0;
    int opcode = 2;

    for (;;)
      {
        char buf[512];
        size_t n = transfer->read_cb (buf, 1, sizeof buf, transfer->read_data);
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
  h->wsess = twist_ws_new (h->transfer, http_ws_send, h, http_ws_done, h);
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
  char line[128];
  int wr;

  h->status = code;
  h->transfer->http_code = code;
  h->transfer->http_version_seen = h->peer_minor == 0
                                   ? TWIST_HTTP_VERSION_1_0
                                   : TWIST_HTTP_VERSION_1_1;
  if (h->transfer->header_cb == NULL)
    return;
  /* The line as the server sent it: the reason phrase is the server's own
     words, and a long one is cut off.  */
  if (n > 64)
    n = 64;
  wr = snprintf (line, sizeof line, "HTTP/1.%d %d%s%.*s\r\n",
                 h->peer_minor == 0 ? 0 : 1, code, n > 0 ? " " : "",
                 (int) n, reason != NULL ? reason : "");
  if (wr > 0)
    h->transfer->header_cb (line, 1, (size_t) wr, h->transfer->header_data);
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
          char status_line[32];
          int wr;

          h->status = code;
          h->transfer->http_code = code;
          h->transfer->http_version_seen = h->mode == HTTP_H3
                                           ? TWIST_HTTP_VERSION_3
                                           : TWIST_HTTP_VERSION_2_0;
          /* The pseudo-header is the status line of an HTTP/2 or HTTP/3
             response, "HTTP/2 200 " as the curl tool writes it, and is not
             a header of its own.  */
          if (h->transfer->header_cb != NULL)
            {
              wr = snprintf (status_line, sizeof status_line,
                             "HTTP/%d %d \r\n", h->mode == HTTP_H3 ? 3 : 2,
                             code);
              if (wr > 0)
                h->transfer->header_cb (status_line, 1, (size_t) wr,
                                        h->transfer->header_data);
            }
        }
      return;
    }
  else if (name_len == 14 && strncasecmp (name, "content-length", 14) == 0)
    {
      char *end;
      char *copy = ncopy (value, value_len);

      /* A body of a known size.  A size of 0 is not looked at as one.  */
      if (copy != NULL && !h->transfer->nobody && !h->ws)
        {
          long long size = strtoll (copy, &end, 10);

          if (end != copy && size > 0)
            twist_progress_dl_size (h->transfer, size);
        }
      free (copy);
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
      free (h->transfer->content_type);
      h->transfer->content_type = ncopy (value, value_len);
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
      const char *host = h->transfer->url != NULL
                         ? h->transfer->url->host : NULL;

      if (h->transfer->unix_path != NULL)
        host = NULL;
      if (host != NULL && clear)
        twist_origin_set_h3 (h->transfer, host, 0, 0);
      else if (host != NULL && h3)
        {
          h->alt_h3 = 1;
          if (port <= 0)
            port = h->https ? 443 : h->transfer->url->port;
          twist_origin_set_h3 (h->transfer, host, 1, port);
        }
    }
  else if (name_len == 16 && strncasecmp (name, "content-encoding", 16) == 0
           && h->transfer->accept_encoding != NULL && h->coding == NULL
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
               && (accepts_coding (h->transfer->accept_encoding, token)
                   || (strcasecmp (token, "x-gzip") == 0
                       && accepts_coding (h->transfer->accept_encoding,
                                          "gzip"))))
        {
          if (!twist_coding_known (token))
            h->decode_err = TWIST_ERR_ENCODING;
          else
            h->decode_err = twist_coding_open (&h->coding, token);
        }
    }
  else if (name_len == 10 && strncasecmp (name, "set-cookie", 10) == 0
           && twist_transfer_jar (h->transfer) != NULL)
    {
      char *cookie = ncopy (value, value_len);
      if (cookie != NULL)
        {
          twist_jar_store (twist_transfer_jar (h->transfer), cookie,
                           h->transfer->url->host, h->transfer->url->path,
                           h->https);
          free (cookie);
        }
    }
  if (h->transfer->header_cb == NULL)
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
  h->transfer->header_cb (line, 1, n, h->transfer->header_data);
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
header_is (const char *line, const char *name)
{
  size_t n = strlen (name);

  return line != NULL && strncasecmp (line, name, n) == 0 && line[n] == ':';
}

static int
header_sensitive (const char *line)
{
  return header_is (line, "Authorization")
         || header_is (line, "Proxy-Authorization")
         || header_is (line, "Cookie");
}

static int
scheme_is_tls (const char *scheme)
{
  return scheme != NULL
         && (strcmp (scheme, "https") == 0 || strcmp (scheme, "wss") == 0);
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

/* Give body data to the application.  One that takes less than it was given
   is saying it cannot go on (a full disk), as curl's write callback does, and
   the transfer ends there, with what was taken counted: the rest of the body
   is not read to be thrown away.  Ending it only queues its completion, so it
   is safe from inside the parser.  */
static void
deliver_body (struct twist_http *h, const uint8_t *data, size_t len)
{
  size_t got = len;

  if (h->finished)
    return;
  if (!(h->transfer->failonerror && h->status >= 400)
      && h->transfer->write_cb != NULL && len > 0)
    got = twist_write_bytes (h->transfer->write_cb, h->transfer->write_data, data, len);
  h->transfer->size_download += got;
  if (got < len)
    http_complete (h, TWIST_ERR_ABORTED);
}

/* Decoded data, in pieces, from the coding; see twist_coding_sink.  */
static int
coding_sink (void *user, const uint8_t *data, size_t len)
{
  deliver_body (user, data, len);
  return 0;
}

static void
release_coding (struct twist_http *h)
{
  if (h->coding == NULL)
    return;
  if (h->decode_err == 0)
    h->decode_err = twist_coding_finish (h->coding, coding_sink, h);
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
  /* What came over the wire, before it is decoded.  */
  twist_progress_downloaded (h->transfer, len);
  if (h->decode_err != 0)
    return;
  if (h->coding != NULL)
    {
      int rc = twist_coding_feed (h->coding, data, len, coding_sink, h);

      if (rc != TWIST_OK)
        h->decode_err = rc;
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

/* Add to LIST a header line made from FMT, as long as it is.  A token, a
   cookie or a URL is whatever length the caller has, and a line cut off at
   some size would be sent as if it were whole.  */
static struct twist_slist * add_header (struct twist_slist *list, const char *fmt, ...)
  __attribute__ ((format (printf, 2, 3)));

static struct twist_slist *
add_header (struct twist_slist *list, const char *fmt, ...)
{
  struct twist_slist *grown;
  va_list ap;
  char *line;
  int n;

  va_start (ap, fmt);
  n = vsnprintf (NULL, 0, fmt, ap);
  va_end (ap);
  if (n < 0)
    return list;
  line = twist_xmalloc ((size_t) n + 1);
  if (line == NULL)
    return list;
  va_start (ap, fmt);
  vsnprintf (line, (size_t) n + 1, fmt, ap);
  va_end (ap);
  grown = twist_slist_append (list, line);
  free (line);
  return grown != NULL ? grown : list;
}

static struct twist_slist *
request_headers (struct twist_http *h)
{
  struct twist_transfer *transfer = h->transfer;
  struct twist_slist *list = NULL;
  struct twist_slist *scan;
  const char *ua = transfer->useragent != NULL ? transfer->useragent
                   : "twist/0.1";

  list = add_header (list, "User-Agent: %s", ua);
  if (!h->strip_auth && h->auth_line != NULL)
    list = twist_slist_append (list, h->auth_line);
  else if (!h->strip_auth && transfer->bearer != NULL)
    {
      list = add_header (list, "Authorization: Bearer %s", transfer->bearer);
    }
  else if (!h->strip_auth && transfer->username != NULL
           && (transfer->auth == 0 || (transfer->auth & TWISTAUTH_BASIC) != 0)
           && (transfer->auth & TWISTAUTH_DIGEST) == 0)
    {
      char *basic = NULL;
      if (twist_auth_basic (transfer->username, transfer->password, &basic) == TWIST_OK)
        {
          list = twist_slist_append (list, basic);
          free (basic);
        }
    }
  if (!h->strip_auth && transfer->cookie != NULL)
    {
      list = add_header (list, "Cookie: %s", transfer->cookie);
    }
  else if (twist_transfer_jar (transfer) != NULL)
    {
      char *cookie = NULL;
      if (twist_jar_header (twist_transfer_jar (transfer), transfer->url->host,
                            transfer->url->path, h->https, &cookie)
          == TWIST_OK
          && cookie != NULL)
        {
          list = twist_slist_append (list, cookie);
          free (cookie);
        }
    }
  if (transfer->range != NULL)
    {
      list = add_header (list, "Range: bytes=%s", transfer->range);
    }
  if (transfer->referer != NULL)
    {
      list = add_header (list, "Referer: %s", transfer->referer);
    }
  for (scan = transfer->headers; scan != NULL; scan = scan->next)
    {
      if (h->strip_auth && header_sensitive (scan->data))
        continue;
      list = twist_slist_append (list, scan->data);
    }
  if (transfer->accept_encoding != NULL
      && !header_named (transfer->headers, "Accept-Encoding"))
    {
      /* What twist can decode, br first when libbrotli is built in.  */
      const char *v = transfer->accept_encoding[0] != 0
        ? transfer->accept_encoding
        : twist_coding_known ("br") ? "br, gzip, deflate" : "gzip, deflate";

      list = add_header (list, "Accept-Encoding: %s", v);
    }
  if (transfer->content_encoding != NULL
      && !header_named (transfer->headers, "Content-Encoding"))
    list = add_header (list, "Content-Encoding: %s",
                       transfer->content_encoding);
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
      list = add_header (list, "Sec-WebSocket-Key: %s", h->ws_key);
    }
  return list;
}

static int
send_request_target (struct twist_http *h, const char *target)
{
  struct twist_transfer *transfer = h->transfer;
  struct twist_url *url = transfer->url;
  const char *method;
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
  if (transfer->nobody)
    method = "HEAD";
  else if (transfer->method != NULL)
    method = transfer->method;
  else if (transfer->postfields != NULL && !h->suppress_body)
    method = "POST";
  {
    char hosttext[400];

    if (twist_url_host_text (url, 0, hosttext, sizeof hosttext) != TWIST_OK)
      return TWIST_ERR_URL;
    if (url->port > 0
        && url->port != twist_url_default_port (url->scheme))
      snprintf (authority, sizeof authority, "%s:%d", hosttext, url->port);
    else
      snprintf (authority, sizeof authority, "%s", hosttext);
  }
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
  else if (!h->suppress_body && transfer->postfields != NULL)
    {
      body = (const uint8_t *) transfer->postfields;
      body_len = transfer->postfieldsize_set && transfer->postfieldsize >= 0
        ? (size_t) transfer->postfieldsize : strlen (transfer->postfields);
      if (body_len > 0 && transfer->content_encoding != NULL
          && !header_named (transfer->headers, "Content-Encoding"))
        {
          rc = twist_coding_encode (transfer->content_encoding, body, body_len,
                                    &owned, &body_len);
          if (rc != TWIST_OK)
            return rc;
          body = owned;
        }
    }
  extra = request_headers (h);
  http10 = h->req_http10
           || h->transfer->http_version == TWIST_HTTP_VERSION_1_0;
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
    {
      /* What answers a HEAD has no body, and the parser must know it before
         the headers come.  */
      twist_h1_set_head (h->h1, strcmp (method, "HEAD") == 0);
      rc = twist_h1_write_request (method, target, authority, http10, extra,
                                   body, body_len, &out, &out_len);
    }
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
  else if (h->mode == HTTP_H3)
    /* A QUIC connection has no TLS layer of its own to send through: its
       endpoint writes to the request stream.  */
    rc = twist_endpoint_send (twist_connection_endpoint (h->conn), out, out_len);
  else
    rc = twist_connection_send_parts (h->conn, out, out_len, NULL, 0);
  free (out);
  free (owned);
  if (rc == TWIST_OK)
    {
      h->sent = 1;
      /* The body is counted as sent when it is handed to the connection.  */
      if (body_len > 0)
        {
          twist_progress_ul_size (h->transfer, (long long) body_len);
          twist_progress_uploaded (h->transfer, body_len);
        }
      if (h->sess == NULL && h->transfer != NULL
          && h->transfer->runtime != NULL
          && (h->mode == HTTP_H2 || h->mode == HTTP_H3) && h->conn != NULL)
        {
          char key[1024];

          if (http_pool_key (h, key, sizeof key) == TWIST_OK)
            {
              struct twist_session *added
                = twist_session_add (h->transfer->runtime, key,
                                     h->transfer->loop, h->conn,
                                     h->mode == HTTP_H2 ? h->h2 : NULL);

              if (added != NULL)
                session_link (h, added);
              if (h->sess != NULL)
                {
                  h->sess->preface = h->preface_sent;
                  /* The connection is the session's now, and so is the
                     place it holds under the limit on connections, until it
                     closes.  A tunnel's is not shared, and stays ours.  */
                  if (!via_tunnel (h))
                    {
                      h->sess->slot_key = h->slot_key;
                      h->slot_key = NULL;
                    }
                }
            }
        }
      /* Those who waited to learn whether the connection could be shared are
         told: they find the session, or make their own.  */
      if (h->mode == HTTP_H2 || h->mode == HTTP_H3)
        http_settle (h, h->sess != NULL ? TWIST_SETTLE_SHARED
                                        : TWIST_SETTLE_UNKNOWN);
    }
  return rc;
}

/* The request target as it goes on the wire: bytes that cannot be in one, a
   space, a control, anything over 0x7f, are percent encoded, as curl does it.
   "GET /a b HTTP/1.1" is not a request, and a server may take it for one
   with a target of "/a".  An escape that is there already is left, and so is
   every other byte.  */
static char *
encode_target (const char *s)
{
  static const char hex[] = "0123456789ABCDEF";
  size_t n = 0;
  const unsigned char *p;
  char *out;
  char *o;

  for (p = (const unsigned char *) s; *p != 0; p++)
    n += (*p <= 0x20 || *p >= 0x7f) ? 3 : 1;
  out = twist_xmalloc (n + 1);
  if (out == NULL)
    return NULL;
  o = out;
  for (p = (const unsigned char *) s; *p != 0; p++)
    if (*p <= 0x20 || *p >= 0x7f)
      {
        *o++ = '%';
        *o++ = hex[*p >> 4];
        *o++ = hex[*p & 15];
      }
    else
      *o++ = (char) *p;
  *o = 0;
  return out;
}

static int
send_request (struct twist_http *h)
{
  struct twist_url *url = h->transfer->url;
  const char *path;
  char *raw;
  char *target;
  int rc;

  if (h->sent || h->conn == NULL)
    return TWIST_OK;
  path = url->path != NULL && url->path[0] != 0 ? url->path : "/";
  if (h->proxy != NULL && !h->tunnel)
    {
      char whole[8192];

      if (twist_url_proxy_target (url, whole, sizeof whole) != TWIST_OK)
        return TWIST_ERR_URL;
      raw = twist_strdup (whole);
    }
  else
    {
      size_t n = strlen (path) + (url->query != NULL ? strlen (url->query) + 1 : 0)
                 + 1;

      raw = twist_xmalloc (n);
      if (raw != NULL)
        {
          if (url->query != NULL)
            snprintf (raw, n, "%s?%s", path, url->query);
          else
            snprintf (raw, n, "%s", path);
        }
    }
  if (raw == NULL)
    return TWIST_ERR_NOMEM;
  target = encode_target (raw);
  free (raw);
  if (target == NULL)
    return TWIST_ERR_NOMEM;
  rc = send_request_target (h, target);
  free (target);
  return rc;
}

/* Post FN to the loop, to run with H.  The transfer can be freed before it
   runs (its handle is removed, or the loop is drained after the handle was
   cleaned up), and the command would then run on freed memory: the record is
   kept until the commands that hold it are done, and they start with
   http_posted_done.  */
static int
http_post (struct twist_http *h, void (*fn) (void *))
{
  /* Counted before it is posted: the loop may run it at once, and the count
     is touched from other threads (http_resume).  */
  __atomic_add_fetch (&h->posted, 1, __ATOMIC_ACQ_REL);
  if (twist_loop_post (h->transfer->loop, fn, h) != TWIST_OK)
    {
      __atomic_sub_fetch (&h->posted, 1, __ATOMIC_ACQ_REL);
      return TWIST_ERR_NOMEM;
    }
  return TWIST_OK;
}

/* A posted command has come up.  True when the transfer was freed meanwhile,
   and the command is to do nothing; the last such command frees the record.  */
static int
http_posted_done (struct twist_http *h)
{
  int left = __atomic_sub_fetch (&h->posted, 1, __ATOMIC_ACQ_REL);

  if (!__atomic_load_n (&h->dead, __ATOMIC_ACQUIRE))
    return 0;
  if (left == 0)
    free (h);
  return 1;
}

static void
http_auth_again (void *user)
{
  struct twist_http *h = user;

  if (http_posted_done (h))
    return;
  h->sent = 0;
  if (arm_parsers (h) != TWIST_OK)
    {
      http_complete (h, TWIST_ERR_NOMEM);
      return;
    }
  if (send_request (h) != TWIST_OK)
    http_complete (h, TWIST_ERR_AUTH);
}

/* Whether the scheme is one this handler hands the transfer to: ftp and
   ftps, which the table of redirects allows and which another handler speaks.  */
static int
http_hands_off (const char *scheme)
{
  return scheme != NULL
         && (strcasecmp (scheme, "ftp") == 0 || strcasecmp (scheme, "ftps") == 0);
}

/* The transfer goes on in the handler of the URL it was redirected to.  This
   handler is let go of, with its connection, and the other is attached to the
   same transfer, with what the transfer has counted so far and what is left of
   its time.  It is posted, to run when nothing of this handler is on the stack
   and the state can be freed.  */
static void
http_handoff (void *user)
{
  struct twist_http *h = user;
  struct twist_transfer *transfer;
  long long left;

  if (http_posted_done (h))
    return;
  /* Completed meanwhile (a timeout): it stays so.  */
  if (h->finished)
    return;
  transfer = h->transfer;
  /* --max-time is for the whole of it, hops included.  */
  transfer->hop_timeout_ms = 0;
  if (transfer->timeout_ms > 0)
    {
      left = (long long) transfer->timeout_ms
             - (long long) (twist_loop_now (transfer->loop)
                            - transfer->progress.start_ms);
      if (left <= 0)
        {
          http_complete (h, TWIST_ERR_TIMEOUT);
          return;
        }
      transfer->hop_timeout_ms = (long) left;
    }
  twist_transfer_chain (transfer);
}

static void
http_restart (void *user)
{
  struct twist_http *h = user;
  struct twist_connection *c;
  int same = 0;
  int port = 0;

  if (http_posted_done (h))
    return;
  h->restarting = 0;
  /* Completed meanwhile (a timeout): it stays so.  */
  if (h->finished)
    return;
  /* A connection that is a session's goes on without us.  */
  http_leave_session (h);
  c = h->conn;
  if (h->transfer->url != NULL && h->dial_host != NULL
      && h->transfer->url->host != NULL && h->restart_keep && !h->conn_lost
      && strcmp (h->dial_host, h->transfer->url->host) == 0
      && h->mode == HTTP_H1)
    {
      port = h->transfer->url->port > 0
        ? h->transfer->url->port
        : twist_url_default_port (h->transfer->url->scheme);
      if (port == h->dial_port && (h->tls_on != 0) == (h->https != 0))
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
  http_slot_release (h);
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
  struct twist_transfer *transfer = h->transfer;
  int use_get = 0;
  int redirect = 0;
  const char *host = transfer->url != NULL ? transfer->url->host : NULL;

  release_coding (h);
  if (h->decode_err != 0)
    {
      http_complete (h, h->decode_err);
      return;
    }

  if (host != NULL && (h->peer_minor == 0 || h->peer_minor == 1))
    twist_origin_set_http_minor (transfer, host, h->peer_minor);
  /* No h3 Alt-Svc on this response: do not probe HTTP/3 again for
     this host in this session.  An entry that did advertise h3 was
     stored for the next stream and does not change this one.  */
  if (host != NULL && h->watch_alt && !h->alt_h3)
    twist_origin_set_h3 (transfer, host, 0, 0);
  if (h->ws)
    {
      int opened = h->ws_open || (h->mode != HTTP_H1 && h->status == 200);

      http_complete (h, opened ? TWIST_OK : TWIST_ERR_HTTP);
      return;
    }
  if (h->status == 401 && h->auth_tries < 2 && h->challenge != NULL
      && transfer->username != NULL
      && (transfer->auth & (TWISTAUTH_BASIC | TWISTAUTH_DIGEST)) != 0)
    {
      char *hdr = NULL;
      int rc = TWIST_ERR_AUTH;
      const char *method = transfer->method != NULL ? transfer->method : "GET";
      const char *path = transfer->url->path != NULL ? transfer->url->path
                         : "/";

      if ((transfer->auth & TWISTAUTH_DIGEST) != 0)
        {
          char cnonce[17];
          uint8_t raw[8];
          static const char *hexd = "0123456789abcdef";
          size_t i;

          if (gq_random (raw, sizeof raw) != GQ_OK)
            rc = TWIST_ERR_AUTH;
          else
            {
              for (i = 0; i < sizeof raw; i++)
                {
                  cnonce[i * 2] = hexd[raw[i] >> 4];
                  cnonce[i * 2 + 1] = hexd[raw[i] & 15];
                }
              cnonce[16] = 0;
              rc = twist_auth_digest (h->challenge, method, path,
                                      transfer->username,
                                      transfer->password != NULL
                                      ? transfer->password : "",
                                      (unsigned) (h->auth_tries + 1), cnonce,
                                      &hdr);
            }
        }
      if (rc != TWIST_OK && (transfer->auth & TWISTAUTH_BASIC) != 0)
        rc = twist_auth_basic (transfer->username, transfer->password, &hdr);
      if (rc == TWIST_OK)
        {
          free (h->auth_line);
          h->auth_line = hdr;
          h->auth_tries++;
          if (http_post (h, http_auth_again) != TWIST_OK)
            http_complete (h, TWIST_ERR_NOMEM);
          return;
        }
    }
  if (h->location != NULL)
    redirect = twist_http_should_redirect (h->status, transfer->method,
                                           transfer->follow, transfer->redirs,
                                           transfer->maxredirs, &use_get);
  if (redirect < 0)
    {
      char msg[96];

      snprintf (msg, sizeof msg, _("Maximum (%ld) redirects followed"),
                transfer->maxredirs);
      twist_transfer_set_error (transfer, twist_strdup (msg));
      http_complete (h, TWIST_ERR_REDIRECT);
      return;
    }
  if (redirect > 0)
    {
      struct twist_url *next = NULL;
      if (twist_url_resolve_int (transfer->url, h->location,
                                 &next) != TWIST_OK)
        {
          http_complete (h, TWIST_ERR_URL);
          return;
        }
      if (!twist_http_redirect_ok (transfer->url->scheme, next->scheme))
        {
          char msg[96];

          /* Refused as curl refuses a protocol that is disabled for a
             redirect (status 1), by the scheme alone.  */
          snprintf (msg, sizeof msg,
                    _("redirect from \"%.10s\" to \"%.20s\" is not followed"),
                    transfer->url->scheme != NULL ? transfer->url->scheme : "",
                    next->scheme != NULL ? next->scheme : "");
          twist_transfer_set_error (transfer, twist_strdup (msg));
          twist_url_free_int (next);
          http_complete (h, TWIST_ERR_UNSUPPORTED);
          return;
        }
      twist_url_free_int (transfer->url);
      transfer->url = next;
      free (transfer->effective_url);
      transfer->effective_url = twist_url_effective (next);
      transfer->redirs++;
      if (http_hands_off (next->scheme))
        {
          /* Another handler's: the headers of this response are done with,
             and the transfer goes on there, as a transfer of its own that has
             none of the credentials that were given for this request.  */
          transfer->creds_stripped = 1;
          twist_progress_hop (transfer);
          h->restarting = 1;
          if (http_post (h, http_handoff) != TWIST_OK)
            http_complete (h, TWIST_ERR_NOMEM);
          return;
        }
      if (use_get)
        h->suppress_body = 1;
      h->https = scheme_is_tls (next->scheme);
      if (twist_http_redirect_sensitive (h->origin_host, h->origin_https,
                                         next->host, h->https))
        {
          free (h->auth_line);
          h->auth_line = NULL;
          h->strip_auth = 1;
          h->suppress_body = 1;
        }
      else
        h->strip_auth = 0;
      twist_progress_hop (transfer);
      h->restarting = 1;
      h->conn_lost = 0;
      h->restart_keep = h->mode == HTTP_H1 && h->h1 != NULL
                        && twist_h1_keep (h->h1);
      if (http_post (h, http_restart) != TWIST_OK)
        http_complete (h, TWIST_ERR_NOMEM);
      return;
    }
  http_complete (h, TWIST_OK);
}

static size_t
http_receive (struct twist_endpoint *ep, const uint8_t *data, size_t len)
{
  struct twist_http *h = http_of (ep);

  if (h->finished)
    {
      /* A connection that is a session's goes on for the others' sake, until
         this transfer is let go and the session answers for it.  */
      if (h->sess != NULL && h->mode == HTTP_H2)
        return twist_h2_receive (h->sess->h2, data, len);
      return len;
    }
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

  if (s != NULL && s->h2 != NULL)
    twist_h2_drop_user (s->h2, s->h2);
  if (s != NULL)
    session_lost (s, NULL, error != TWIST_OK ? error : TWIST_ERR_CLOSED);
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

  if (http_posted_done (h))
    return;
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
  http_slot_release (h);
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
  http_settle (h, TWIST_SETTLE_UNKNOWN);
  /* HTTP/3 was selected by discovery and could not be opened.  One
     fall back, onto ALPN or h2c.  A pinned HTTP/3-only request does
     not.  */
  if (h->status == 0 && !h->sent && h->mode == HTTP_H3 && !h->h3_gave_up
      && h->transfer->http_version != TWIST_HTTP_VERSION_3ONLY)
    {
      if (h->falling)
        return;
      h->falling = 1;
      h->h3_gave_up = 1;
      h->fail_err = err;
      if (http_post (h, h3_fallback) != TWIST_OK)
        http_complete (h, TWIST_ERR_NOMEM);
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
    {
      h->mode = HTTP_H1;
      /* The origin does not multiplex: the next transfer to it need not
         wait to learn that.  */
      http_settle (h, TWIST_SETTLE_H1);
    }
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
               || h->transfer->http_version == TWIST_HTTP_VERSION_1_0;
      if (!http10
          && (h->how == TWIST_DISC_ALPN || h->how == TWIST_DISC_H2_PRIOR
              || h->how == TWIST_DISC_H2C))
        alpn[n++] = "h2";
      if (!http10 && h->how != TWIST_DISC_H2_PRIOR)
        alpn[n++] = "http/1.1";
      rc = twist_connection_start_tls (h->conn, h->transfer->url->host,
                                       h->transfer->verifypeer,
                                       n > 0 ? alpn : NULL, n,
                                       h->transfer->cainfo, h->transfer->capath, h->transfer->sslcert,
                                       h->transfer->sslkey);
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

  /* The session is lost whatever becomes of this transfer.  */
  if (h->sess != NULL)
    session_lost (h->sess, h, error != TWIST_OK ? error : TWIST_ERR_CLOSED);
  if (h->restarting)
    {
      h->conn_lost = 1;
      return;
    }
  if (!h->finished)
    http_fail (h, error != TWIST_OK ? error : TWIST_ERR_CLOSED);
}

static void
http_error (struct twist_endpoint *ep, int error)
{
  struct twist_http *h = http_of (ep);

  if (h->sess != NULL)
    session_lost (h->sess, h, error);
  if (h->restarting)
    {
      h->conn_lost = 1;
      return;
    }
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

/* Whether HTTP/3 goes through a CONNECT-UDP proxy (RFC 9298), and if so which:
   1 with the proxy's host and port, the credentials from its URL and the
   template (NULL for the default); 0 with no proxy; -1 if there is a proxy and
   it cannot carry UDP, which is an error, since HTTP/3 may not go round it.
   A template names the proxy, with its authority; otherwise it is the https
   proxy.  */
static int
masque_plan (struct twist_http *h, char **phost, int *pport, char **puser,
             char **ppass, char **tmpl)
{
  struct twist_transfer *transfer = h->transfer;
  const char *px = twist_transfer_proxy (transfer);
  const char *tp = transfer->proxy_template_udp;
  int kind = TWIST_PROXY_NONE;

  *phost = *puser = *ppass = *tmpl = NULL;
  *pport = 0;
  if (twist_transfer_noproxy (transfer))
    return 0;
  if (px != NULL
      && twist_proxy_parse (px, &kind, phost, pport, puser, ppass) != TWIST_OK)
    return -1;
  if (tp == NULL)
    {
      if (px == NULL)
        return 0;
      if (kind != TWIST_PROXY_HTTPS)
        {
          twist_transfer_set_error (transfer,
                                    twist_strdup (_("HTTP/3 through a proxy "
                                                    "needs an https:// "
                                                    "proxy (CONNECT-UDP)")));
          return -1;
        }
      return 1;
    }
  /* The template's authority is the proxy.  */
  {
    char *uri = NULL;
    char *url = NULL;
    size_t al;
    int rc;

    free (*phost);
    *phost = NULL;
    if (twist_template_expand (tp, "x", 1, &uri) != TWIST_OK)
      return -1;
    al = strcspn (uri + 8, "/?");
    url = twist_xmalloc (al + 9);
    if (url == NULL)
      {
        free (uri);
        return -1;
      }
    memcpy (url, "https://", 8);
    memcpy (url + 8, uri + 8, al);
    url[8 + al] = 0;
    free (uri);
    {
      char *tu = NULL, *tpw = NULL;
      int tk = 0;

      rc = twist_proxy_parse (url, &tk, phost, pport, &tu, &tpw);
      free (url);
      if (rc != TWIST_OK)
        return -1;
      /* Credentials written into the template's authority win; else the
         proxy URL's, if that is an https one.  */
      if (tu != NULL)
        {
          free (*puser);
          if (*ppass != NULL)
            {
              memset (*ppass, 0, strlen (*ppass));
              free (*ppass);
            }
          *puser = tu;
          *ppass = tpw;
        }
      else
        {
          free (tpw);
          if (kind != TWIST_PROXY_HTTPS)
            {
              free (*puser);
              *puser = NULL;
              if (*ppass != NULL)
                {
                  memset (*ppass, 0, strlen (*ppass));
                  free (*ppass);
                  *ppass = NULL;
                }
            }
        }
    }
    *tmpl = twist_strdup (tp);
    return *tmpl != NULL ? 1 : -1;
  }
}

static int
prepare_dial (struct twist_http *h)
{
  struct twist_transfer *transfer = h->transfer;
  struct twist_url *url = transfer->url;
  const char *dial = url->host;
  int port = url->port;
  int kind = TWIST_PROXY_NONE;
  char *phost = NULL, *puser = NULL, *ppass = NULL;
  int pport = 0;

  if (h->https_port > 0 && !url->port_set)
    port = h->https_port;
  h->tunnel = 0;
  h->tls_tunnel = 0;
  h->masque = 0;
  free (h->tun_tmpl);
  h->tun_tmpl = NULL;
  free (h->tun_user);
  h->tun_user = NULL;
  if (h->tun_pass != NULL)
    {
      memset (h->tun_pass, 0, strlen (h->tun_pass));
      free (h->tun_pass);
      h->tun_pass = NULL;
    }
  twist_proxy_free (h->proxy);
  h->proxy = NULL;
  if (h->mode == HTTP_H3)
    {
      int plan = masque_plan (h, &phost, &pport, &puser, &ppass, &h->tun_tmpl);

      if (plan < 0)
        {
          free (phost);
          free (puser);
          if (ppass != NULL)
            {
              memset (ppass, 0, strlen (ppass));
              free (ppass);
            }
          return TWIST_ERR_UNSUPPORTED;
        }
      if (plan > 0)
        {
          h->masque = 1;
          dial = phost;
          port = pport;
          h->tun_user = puser;
          h->tun_pass = ppass;
          puser = ppass = NULL;
        }
    }
  else if (twist_transfer_proxy (transfer) != NULL
           && transfer->unix_path == NULL)
    {
      int prc = twist_proxy_parse (twist_transfer_proxy (transfer), &kind,
                                   &phost,
                                   &pport, &puser, &ppass);

      if (prc != TWIST_OK)
        {
          free (phost);
          if (prc == TWIST_ERR_UNSUPPORTED)
            twist_transfer_set_error (transfer,
                                      twist_strdup (_("this kind of proxy "
                                                      "is not supported; "
                                                      "use http://, "
                                                      "https:// or "
                                                      "socks5://")));
          return prc == TWIST_ERR_UNSUPPORTED ? prc : TWIST_ERR_URL;
        }
      if (kind == TWIST_PROXY_HTTPS)
        {
          /* TLS to the proxy and CONNECT in it, for every target.  */
          h->tls_tunnel = 1;
          dial = phost;
          port = pport;
          h->tun_user = puser;
          h->tun_pass = ppass;
          puser = ppass = NULL;
        }
      h->tunnel = h->https || kind == TWIST_PROXY_SOCKS5;
      if (kind == TWIST_PROXY_HTTPS)
        h->tunnel = 0;
      if (h->tunnel || kind == TWIST_PROXY_HTTP)
        {
          dial = phost;
          port = pport;
        }
      if (kind == TWIST_PROXY_HTTPS)
        ;
      else if (h->tunnel)
        {
          h->proxy = twist_proxy_new (kind, phost, pport, &h->handler);
          if (h->proxy != NULL)
            {
              twist_proxy_set_target (h->proxy, url->host, url->port);
              twist_proxy_configure (h->proxy, transfer, puser, ppass);
            }
        }
      else if (kind == TWIST_PROXY_HTTP)
        h->proxy = twist_proxy_new (kind, phost, pport, NULL);
    }
  free (h->dial_host);
  h->dial_host = twist_strdup (dial != NULL ? dial : "");
  h->dial_port = port;
  free (phost);
  free (puser);
  if (ppass != NULL)
    {
      memset (ppass, 0, strlen (ppass));
      free (ppass);
    }
  return h->dial_host != NULL ? TWIST_OK : TWIST_ERR_NOMEM;
}

/* What arrives on a stream of a shared HTTP/3 connection.  The connection
   keeps what the parser leaves of a frame for the next read, but a stream of
   its own is given what it gets only once, so the transfer keeps it; and the
   end of the stream is the end of the response, as it is on the connection of
   a transfer that has it to itself (http_read_finished).  */
static size_t
h3_stream_data (void *user, const uint8_t *data, size_t len, int fin)
{
  struct twist_http *h = user;
  const uint8_t *p = data;
  size_t n = len;
  size_t used;

  if (h == NULL || h->h3 == NULL)
    return len;
  if (h->h3_tail_len == 0)
    {
      free (h->h3_tail);
      h->h3_tail = NULL;
    }
  if (h->h3_tail_len > 0)
    {
      uint8_t *joined = realloc (h->h3_tail, h->h3_tail_len + len);

      if (joined == NULL)
        {
          http_fail (h, TWIST_ERR_NOMEM);
          return len;
        }
      memcpy (joined + h->h3_tail_len, data, len);
      h->h3_tail = joined;
      h->h3_tail_len += len;
      p = joined;
      n = h->h3_tail_len;
    }
  used = twist_h3_receive (h->h3, p, n);
  if (used < n)
    {
      /* The rest of a frame that is not all here.  */
      if (p == h->h3_tail)
        {
          memmove (h->h3_tail, p + used, n - used);
          h->h3_tail_len = n - used;
        }
      else
        {
          h->h3_tail = twist_xmalloc (n - used);
          if (h->h3_tail == NULL)
            {
              h->h3_tail_len = 0;
              http_fail (h, TWIST_ERR_NOMEM);
              return len;
            }
          memcpy (h->h3_tail, p + used, n - used);
          h->h3_tail_len = n - used;
        }
    }
  else
    h->h3_tail_len = 0;
  if (fin && !h->finished && h->mode == HTTP_H3)
    http_message_done (h);
  return len;
}

/* Whether the transfer's origin can carry other transfers on a connection of
   its own, and the transfer may take part: it is to be HTTP/2 or HTTP/3 from
   the first byte, or it is https and the server is to say which in the
   handshake.  A tunnel or a websocket is not shared.  */
static int
session_wanted (const struct twist_http *h)
{
  /* HTTP/2 prior knowledge over https is negotiated in the handshake like any
     other (twist_http_discover gives it ALPN), so it is covered here and by
     h2_pinned below; only a cleartext one has its mode set from the start.  */
  if (h->ws || via_tunnel (h))
    return 0;
  if (h->mode == HTTP_H2 || h->mode == HTTP_H3)
    return 1;
  return h->https && h->how == TWIST_DISC_ALPN && !h->req_http10;
}

/* Whether the transfer may share a connection with others to its origin, from
   its URL and options alone, before there is a handler: the same as
   session_wanted would say of the handler it is to have.  Only http and https
   transfers can; a websocket, a proxy or a tunnel cannot; HTTP forced to 1.0
   or 1.1 cannot; https can unless that, and cleartext only with HTTP/2 from
   the first byte.  */
int
twist_http_may_multiplex (struct twist_transfer *transfer)
{
  const struct twist_url *url = transfer->url;
  int v = transfer->http_version;
  int https;

  if (url == NULL || url->scheme == NULL || url->host == NULL
      || url->host[0] == 0)
    return 0;
  https = strcmp (url->scheme, "https") == 0;
  if (!https && strcmp (url->scheme, "http") != 0)
    return 0;
  if (twist_transfer_proxy (transfer) != NULL)
    return 0;
  if (v == TWIST_HTTP_VERSION_1_0 || v == TWIST_HTTP_VERSION_1_1)
    return 0;
  if (https)
    return 1;
  return v == TWIST_HTTP_VERSION_2_PRIOR_KNOWLEDGE;
}

/* Whether HTTP/2 was asked for, and not HTTP/3 in its place.  */
static int
h2_pinned (const struct twist_http *h)
{
  int v = h->transfer->http_version;

  return v == TWIST_HTTP_VERSION_2_0 || v == TWIST_HTTP_VERSION_2TLS
         || v == TWIST_HTTP_VERSION_2_PRIOR_KNOWLEDGE;
}

static int
http_borrow (struct twist_http *h)
{
  struct twist_session *s;
  struct twist_runtime *runtime;
  char key[1024];

  if (!session_wanted (h))
    return 0;
  runtime = h->transfer != NULL ? h->transfer->runtime : NULL;
  if (runtime == NULL || http_pool_key (h, key, sizeof key) != TWIST_OK)
    return 0;
  s = twist_session_find (runtime, key, h->transfer->loop);
  if (s == NULL || s->conn == NULL)
    return 0;
  /* A transfer that is to be one or the other takes only that; one that is
     to learn from the handshake takes what is there, unless HTTP/2 was asked
     for.  */
  if (h->mode == HTTP_H2 || h->mode == HTTP_H3)
    {
      if ((h->mode == HTTP_H3) != (s->h2 == NULL))
        return 0;
    }
  else if (s->h2 == NULL && h2_pinned (h))
    return 0;
  if (arm_parsers (h) != TWIST_OK)
    return 0;
  if (s->h2 != NULL)
    {
      twist_h2_free (h->h2);
      h->h2 = s->h2;
      h->mode = HTTP_H2;
    }
  else
    {
      if (twist_quic_open_stream (s->conn) != TWIST_OK)
        {
          arm_parsers (h);
          return 0;
        }
      twist_quic_bind (s->conn, h3_stream_data, h);
      h->mode = HTTP_H3;
    }
  h->conn = s->conn;
  session_link (h, s);
  h->preface_sent = 1;
  if (twist_connection_tls (s->conn) != NULL)
    h->tls_on = 1;
  if (send_request (h) != TWIST_OK)
    {
      twist_h2_drop_user (s->h2, h);
      session_unlink (h);
      twist_session_release (s);
      h->sess = NULL;
      if (h->h2 == s->h2)
        h->h2 = NULL;
      h->conn = NULL;
      http_complete (h, TWIST_ERR_CONNECT);
    }
  return 1;
}

static void dial (struct twist_http *h, const struct twist_dns_addr *addr);
static void start_quic (struct twist_http *h,
                        const struct twist_dns_addr *addr);

/* The step after waiting, from the loop: start again from the top, with the
   place under the limit that was granted, if one was.  The transfer may have
   ended or been freed meanwhile.  */
static void
http_resume_posted (void *user)
{
  struct twist_http *h = user;

  if (http_posted_done (h))
    return;
  if (h->finished)
    return;
  h->requeue = __atomic_load_n (&h->resume_why, __ATOMIC_ACQUIRE)
               == TWIST_RESUME_WOKEN;
  if (h->waiter.state == TWIST_WAIT_GRANTED)
    {
      free (h->slot_key);
      h->slot_key = twist_origin_waiter_take (&h->waiter);
    }
  if (h->resume_quic)
    start_quic (h, &h->peer);
  else
    dial (h, &h->peer);
  /* The place at the head of the queue was for that attempt only.  */
  h->requeue = 0;
}

/* From the loop: the transfer's session lost its connection before any of the
   response came, and the transfer goes again, on a connection of its own.
   This is not done where the loss is found, which may be inside a call that
   the transfer itself is making.  */
static void
session_retry (void *user)
{
  struct twist_http *h = user;
  struct twist_session *s = h->sess;

  if (http_posted_done (h))
    return;
  if (h->finished || s == NULL)
    return;
  twist_h2_drop_user (s->h2, h);
  if (h->h2 == s->h2)
    h->h2 = NULL;
  session_unlink (h);
  twist_session_release (s);
  h->sess = NULL;
  h->conn = NULL;
  /* Half a frame of the lost stream is of no use to the next.  */
  free (h->h3_tail);
  h->h3_tail = NULL;
  h->h3_tail_len = 0;
  h->sent = 0;
  h->preface_sent = 0;
  h->tls_on = 0;
  if (arm_parsers (h) != TWIST_OK)
    {
      http_fail (h, TWIST_ERR_NOMEM);
      return;
    }
  /* Over what the session was on, which the mode says.  */
  h->resume_quic = h->mode == HTTP_H3;
  if (h->resume_quic)
    start_quic (h, &h->peer);
  else
    dial (h, &h->peer);
}

/* The transfer's session has lost its connection.  If nothing of the
   response has come, the transfer goes again, once; else it has failed.  */
static void
session_user_lost (struct twist_http *h, int err)
{
  if (h->finished || h->sess == NULL)
    return;
  if (h->status != 0 || h->retried)
    {
      http_fail (h, err);
      return;
    }
  h->retried = 1;
  if (http_post (h, session_retry) != TWIST_OK)
    http_fail (h, TWIST_ERR_NOMEM);
}

/* The connection of the session is gone: it is not to be used again, the place
   it held under the limit on connections is free, and the transfers on it
   except EXCEPT, which is told by its own handler, are told.  */
static void
session_lost (struct twist_session *s, struct twist_http *except, int err)
{
  struct twist_session_user *u;
  struct twist_session_user *next;

  if (s->closed)
    return;
  s->closed = 1;
  if (s->runtime != NULL && s->runtime->origintab != NULL)
    twist_origintab_session (s->runtime->origintab, s->key, -1);
  if (s->slot_key != NULL)
    {
      char *key = s->slot_key;

      s->slot_key = NULL;
      if (s->runtime != NULL && s->runtime->origintab != NULL)
        twist_origintab_release (s->runtime->origintab, key);
      free (key);
    }
  for (u = s->users_head; u != NULL; u = next)
    {
      next = u->next;
      if (u->h != except)
        session_user_lost (u->h, err);
    }
}

/* Called by the table, when what the transfer waited for has come, with the
   table's lock held and on any thread.  It reads nothing of the transfer, and
   does no more than count a command for it and post one, made ahead, to the
   loop it waits on: the command does every check, there.  The lock is what
   orders this against the transfer's leaving the queue
   (twist_origintab_cancel), so the record is there until this has run.  */
static void
http_resume (void *user, int why)
{
  struct twist_http *h = user;
  struct twist_cmd *node = h->waiter.node;

  /* There is a node whenever the waiter is in a queue: http_gate makes one
     before it queues, and this takes it as the waiter leaves the queue, so it
     is taken once for each time the waiter was queued.  */
  if (node == NULL)
    return;
  h->waiter.node = NULL;
  __atomic_store_n (&h->resume_why, why, __ATOMIC_RELEASE);
  __atomic_add_fetch (&h->posted, 1, __ATOMIC_ACQ_REL);
  twist_loop_cmd_post (h->waiter.loop, node);
}

/* Before a connection is made or taken: wait for a connection to the origin
   that is being made, if it may be shared; then take a place under the limit
   on connections, which are open ones and those being made.  1 if the
   transfer is to wait, to be started again from the top when it is its turn,
   0 if it goes on.  A connection that is kept idle in the pool keeps its place
   (http_park), and a transfer that takes it has the place, so the places held
   are the connections open or being made, wherever they are, and stay within
   the limit.  The transfer is here only when it found no connection to take on
   its own loop; if one is kept idle on another loop, the table has it closed
   to make a place.  A place is held until the connection is kept, closed, or
   the session's.  */
static int
http_gate (struct twist_http *h, int quic)
{
  struct twist_origintab *tab = http_tab (h);
  char key[1024];
  int rc;

  if (tab == NULL || h->slot_key != NULL
      || http_pool_key (h, key, sizeof key) != TWIST_OK)
    return 0;
  h->waiter.resume = http_resume;
  h->waiter.user = h;
  h->waiter.loop = h->transfer->loop;
  /* The command that resumes it, made now, so that waking it cannot fail.  */
  if (h->waiter.node == NULL)
    h->waiter.node = twist_loop_cmd_new (http_resume_posted, h);
  if (h->waiter.node == NULL)
    {
      http_fail (h, TWIST_ERR_NOMEM);
      return 1;
    }
  h->resume_quic = quic;
  if (h->transfer->pipewait && session_wanted (h)
      && twist_origintab_park (tab, key, &h->waiter))
    return 1;
  /* One that was woken and found no room goes back to the head.  */
  rc = twist_origintab_acquire (tab, key, &h->waiter, h->requeue);
  h->requeue = 0;
  if (rc == 0)
    return 1;
  if (rc < 0)
    {
      http_fail (h, rc);
      return 1;
    }
  h->slot_key = twist_strdup (key);
  if (h->slot_key == NULL)
    {
      twist_origintab_release (tab, key);
      http_fail (h, TWIST_ERR_NOMEM);
      return 1;
    }
  return 0;
}

/* A connection is about to be made: if others might share it, say so.  */
static void
http_lead (struct twist_http *h)
{
  struct twist_origintab *tab = http_tab (h);
  char key[1024];

  if (tab == NULL || h->lead_key != NULL || !session_wanted (h)
      || http_pool_key (h, key, sizeof key) != TWIST_OK
      || !twist_origintab_may_lead (tab, key))
    return;
  if (twist_origintab_lead (tab, key) != TWIST_OK)
    return;
  h->lead_key = twist_strdup (key);
  if (h->lead_key == NULL)
    twist_origintab_settle (tab, key, TWIST_SETTLE_UNKNOWN);
}

static int
http_reuse (struct twist_http *h)
{
  struct twist_pool *pool;
  struct twist_connection *c = NULL;
  struct twist_endpoint *ep;
  char key[1024];
  int held = 0;

  if (h->mode != HTTP_H1 || via_tunnel (h))
    return 0;
  pool = http_pool (h);
  if (pool == NULL || http_pool_key (h, key, sizeof key) != TWIST_OK)
    return 0;
  if (twist_pool_take_held (pool, key, &c, &held) != TWIST_OK || c == NULL)
    return 0;
  if (held)
    {
      /* Its place is ours.  One that was already ours is not needed.  */
      struct twist_origintab *tab = http_tab (h);

      if (tab != NULL)
        {
          twist_origintab_idle_del (tab, key, h->transfer->loop);
          if (h->slot_key != NULL)
            twist_origintab_release (tab, key);
          else
            h->slot_key = twist_strdup (key);
        }
    }
  h->conn = c;
  ep = twist_connection_endpoint (c);
  ep->user_data = h;
  twist_connection_set_handler (c, &h->handler);
  if (twist_connection_tls (c) != NULL)
    h->tls_on = 1;
  http_connected (ep);
  return 1;
}

/* Connect to the Unix socket the handle names (TWISTOPT_UNIX_SOCKET), the path
   or the abstract name, which starts with the NUL byte that says so.  */
static int
dial_unix (struct twist_http *h)
{
  struct twist_transfer *transfer = h->transfer;
  struct sockaddr_un sa;
  size_t len = strlen (transfer->unix_path);
  size_t salen;
  char msg[160];
  int rc;

  memset (&sa, 0, sizeof sa);
  sa.sun_family = AF_UNIX;
  if (transfer->unix_abstract)
    {
      if (len + 1 > sizeof sa.sun_path)
        return TWIST_ERR_INVAL;
      memcpy (sa.sun_path + 1, transfer->unix_path, len);
      salen = offsetof (struct sockaddr_un, sun_path) + 1 + len;
    }
  else
    {
      if (len + 1 > sizeof sa.sun_path)
        return TWIST_ERR_INVAL;
      memcpy (sa.sun_path, transfer->unix_path, len + 1);
      salen = offsetof (struct sockaddr_un, sun_path) + len + 1;
    }
  errno = 0;
  rc = twist_connection_connect (h->conn, &sa, salen,
                                 (uint64_t) transfer->connect_timeout_ms);
  if (rc != TWIST_OK)
    {
      snprintf (msg, sizeof msg, _("could not connect to Unix socket %s%s"),
                transfer->unix_abstract ? "@" : "", transfer->unix_path);
      twist_transfer_set_error (transfer, twist_strdup (msg));
    }
  return rc;
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

  if (http_borrow (h))
    {
      /* A stream of a session holds no place under the limit.  */
      http_slot_release (h);
      return;
    }
  /* A connection that is kept is used before a new one is made, and with its
     place.  */
  if (http_reuse (h))
    return;
  if (http_gate (h, 0))
    return;
  http_lead (h);
  if (h->tls_tunnel)
    {
      struct twist_tunnel_spec spec;

      memset (&spec, 0, sizeof spec);
      spec.proxy_host = h->dial_host;
      spec.proxy_port = h->dial_port;
      spec.user = h->tun_user;
      spec.pass = h->tun_pass;
      spec.host = h->transfer->url->host;
      spec.port = h->transfer->url->port > 0
        ? h->transfer->url->port
        : twist_url_default_port (h->transfer->url->scheme);
      rc = twist_tunnel_connect (h->transfer, &spec, addr, &h->handler, h,
                                 &h->conn);
      if (rc != TWIST_OK)
        http_fail (h, rc);
      return;
    }
  h->conn = twist_connection_new (h->transfer->loop);
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
  if (h->transfer->unix_path != NULL)
    {
      rc = dial_unix (h);
      if (rc != TWIST_OK)
        http_fail (h, rc);
      return;
    }
  if (addr->family == 6)
    {
      memset (&sin6, 0, sizeof sin6);
      sin6.sin6_family = AF_INET6;
      memcpy (&sin6.sin6_addr, addr->addr, 16);
      sin6.sin6_scope_id = addr->scope_id;
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
                                 (uint64_t) h->transfer->connect_timeout_ms);
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
  if (h->masque)
    start_quic (h, &h->peer);
  else
    dial (h, &h->peer);
}

static void
start_quic (struct twist_http *h, const struct twist_dns_addr *addr)
{
  struct twist_transfer *transfer = h->transfer;
  char *saved;
  int saved_port;
  int rc;

  if (http_borrow (h))
    {
      http_slot_release (h);
      return;
    }
  if (http_gate (h, 1))
    return;
  http_lead (h);
  saved = transfer->url->host;
  saved_port = transfer->url->port;

  if (twist_quic_connect_fn == NULL)
    {
      http_fail (h, TWIST_ERR_UNSUPPORTED);
      return;
    }
  if (h->masque)
    {
      struct twist_masque_spec spec;

      memset (&spec, 0, sizeof spec);
      spec.proxy_host = h->dial_host;
      spec.proxy_port = h->dial_port;
      spec.user = h->tun_user;
      spec.pass = h->tun_pass;
      spec.tmpl = h->tun_tmpl;
      spec.host = saved;
      spec.port = saved_port;
      rc = twist_masque_connect (transfer, &spec, addr, &h->handler, h,
                                 &h->conn);
      if (rc != TWIST_OK)
        {
          http_fail (h, rc);
          return;
        }
      return;
    }
  rc = twist_quic_connect_fn (transfer, addr,
                              h->dial_port > 0 ? h->dial_port : saved_port,
                              &h->conn);
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
  if ((h->masque || h->mode != HTTP_H3) && h->transfer->url->host != NULL
      && (h->masque || strcmp (h->dial_host, h->transfer->url->host) != 0))
    {
      rc = twist_dns_resolve_transfer (h->transfer, h->dial_host, on_proxy_resolved, h);
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
  h->req_http10 = h->transfer->http_version == TWIST_HTTP_VERSION_1_0;
  if (!h->req_http10 && h->transfer->url != NULL
      && h->transfer->http_version != TWIST_HTTP_VERSION_1_1
      && twist_origin_http_minor (h->transfer, h->transfer->url->host) == 0)
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
  const char *host = h->transfer->url != NULL ? h->transfer->url->host : NULL;
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
  /* A Unix socket is not somewhere HTTP/3 can be found or advertised.  */
  cached = h->transfer->unix_path != NULL ? 0
    : twist_origin_h3 (h->transfer, host, &cached_port);
  if (h->https && svc->have_https && !rr_h3)
    twist_origin_set_h3 (h->transfer, host, 0, 0);
  else if (h->https && rr_h3)
    twist_origin_set_h3 (h->transfer, host, 1,
                         svc->port > 0 ? svc->port : h->transfer->url->port);
  if (twist_http_discover (h->transfer->http_version, h->https,
                           svc->have_https,
                           rr_h3, cached, &h->how) != TWIST_OK)
    {
      http_complete (h, TWIST_ERR_UNSUPPORTED);
      return;
    }
  if (h->transfer->unix_path != NULL && h->how == TWIST_DISC_H3)
    {
      twist_transfer_set_error (h->transfer,
                                twist_strdup (_("HTTP/3 cannot go over "
                                                "a Unix socket")));
      http_complete (h, TWIST_ERR_UNSUPPORTED);
      return;
    }
  if (h->ws && !h->https)
    {
      int v = h->transfer->http_version;

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
                 && cached != -1 && h->transfer->unix_path == NULL;
  apply_how (h);
  start_attempt (h);
}

static void
http_begin (struct twist_http *h)
{
  struct twist_transfer *transfer = h->transfer;
  struct twist_url *url = transfer->url;

  h->ws = url->scheme != NULL
          && (strcmp (url->scheme, "ws") == 0 || strcmp (url->scheme, "wss") == 0);
  h->https = url->scheme != NULL
             && (strcmp (url->scheme, "https") == 0
                 || strcmp (url->scheme, "wss") == 0);
  h->peer_minor = -1;
  if (!h->ws && twist_transfer_hsts (transfer) != NULL && !h->https
      && twist_hsts_upgrade (twist_transfer_hsts (transfer), url->host,
                             twist_loop_now (transfer->loop)))
    {
      free (url->scheme);
      url->scheme = twist_strdup ("https");
      if (url->port == 80)
        url->port = 443;
      h->https = 1;
      free (transfer->effective_url);
      transfer->effective_url = twist_url_effective (url);
    }
  if (!h->origin_set && url->host != NULL && url->host[0] != 0)
    {
      h->origin_host = twist_strdup (url->host);
      if (h->origin_host != NULL)
        {
          h->origin_https = h->https;
          h->origin_set = 1;
        }
    }
  if (transfer->timeout_ms > 0 && h->timer == NULL)
    twist_loop_schedule (transfer->loop,
                         twist_loop_now (transfer->loop) + (uint64_t) transfer->timeout_ms,
                         on_timeout, h, &h->timer);
  if (h->https && transfer->http_version == TWIST_HTTP_VERSION_3ONLY
      && transfer->unix_path == NULL)
    {
      char *ph, *pu, *pp, *pt;
      int pport, plan;

      plan = masque_plan (h, &ph, &pport, &pu, &pp, &pt);
      free (ph);
      free (pu);
      if (pp != NULL)
        {
          memset (pp, 0, strlen (pp));
          free (pp);
        }
      free (pt);
      if (plan > 0)
        {
          /* The proxy looks the target up; the name is not asked for here.
             Only the proxy's own address is needed, and that comes later.  */
          struct twist_dns_service svc;

          memset (&svc, 0, sizeof svc);
          svc.addr.family = 4;
          on_resolved (h, TWIST_OK, &svc);
          return;
        }
      if (plan < 0)
        {
          http_complete (h, TWIST_ERR_UNSUPPORTED);
          return;
        }
    }
  if (transfer->unix_path != NULL)
    {
      /* The host is not looked up: the socket is where it is.  */
      struct twist_dns_service svc;

      if (transfer->http_version == TWIST_HTTP_VERSION_3ONLY)
        {
          twist_transfer_set_error (transfer,
                                    twist_strdup (_("HTTP/3 cannot go over "
                                                    "a Unix socket")));
          http_complete (h, TWIST_ERR_UNSUPPORTED);
          return;
        }
      memset (&svc, 0, sizeof svc);
      svc.addr.family = 4;
      on_resolved (h, TWIST_OK, &svc);
      return;
    }
  {
    int rc = twist_dns_resolve_service_transfer (transfer, url->host,
                                                 on_resolved, h);

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
  /* Out of every queue first: what it was granted, it gives back.  */
  twist_origintab_cancel (http_tab (h), &h->waiter);
  if (h->waiter.node != NULL)
    twist_loop_cmd_free (h->waiter.node);
  h->waiter.node = NULL;
  http_leave_session (h);
  twist_connection_free (h->conn);
  http_slot_release (h);
  http_settle (h, TWIST_SETTLE_UNKNOWN);
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
  free (h->origin_host);
  free (h->dial_host);
  free (h->tun_user);
  free (h->tun_tmpl);
  if (h->tun_pass != NULL)
    {
      memset (h->tun_pass, 0, strlen (h->tun_pass));
      free (h->tun_pass);
    }
  free (h->hdr_line);
  free (h->h3_tail);
  if (__atomic_load_n (&h->posted, __ATOMIC_ACQUIRE) > 0)
    {
      __atomic_store_n (&h->dead, 1, __ATOMIC_RELEASE);
      return;
    }
  free (h);
}

int
twist_http_attach (struct twist_transfer *transfer)
{
  struct twist_http *h;

  if (transfer == NULL || transfer->url == NULL || transfer->loop == NULL)
    return TWIST_ERR_INVAL;
  h = calloc (1, sizeof *h);
  if (h == NULL)
    return TWIST_ERR_NOMEM;
  h->transfer = transfer;
  transfer->state = h;
  transfer->state_free = http_free;
  h->handler.connected = http_connected;
  h->handler.receive = http_receive;
  h->handler.disconnected = http_disconnected;
  h->handler.security_established = http_security;
  h->handler.error = http_error;
  h->handler.read_finished = http_read_finished;
  if (transfer->username == NULL && transfer->url->user != NULL)
    {
      transfer->username = twist_strdup (transfer->url->user);
      transfer->password = twist_strdup (transfer->url->password);
    }
  if (arm_parsers (h) != TWIST_OK)
    return TWIST_ERR_NOMEM;
  http_begin (h);
  return h->finished ? transfer->result : TWIST_OK;
}

/* 1 to follow the redirect, 0 when the response is not one to follow (not a
   redirect, or the transfer does not follow them), and -1 when it is one and
   the limit is reached: curl's CURLE_TOO_MANY_REDIRECTS.  A limit below 0 is
   no limit.  */
int
twist_http_should_redirect (int status, const char *method, int follow,
                            long redirs, long maxredirs, int *use_get)
{
  (void) method;
  *use_get = 0;
  if (!follow)
    return 0;
  if (status != 301 && status != 302 && status != 303
      && status != 307 && status != 308)
    return 0;
  if (maxredirs >= 0 && redirs >= maxredirs)
    return -1;
  /* 301, 302, and 303 replay as GET.  307 and 308 keep the method.  */
  if (status == 301 || status == 302 || status == 303)
    *use_get = 1;
  return 1;
}

int
twist_http_redirect_sensitive (const char *from_host, int from_https,
                               const char *to_host, int to_https)
{
  if (from_https && !to_https)
    return 1;
  if (from_host == NULL || to_host == NULL || from_host[0] == 0
      || to_host[0] == 0)
    return 1;
  return strcasecmp (from_host, to_host) != 0;
}
