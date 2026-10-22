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

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

/* A tunnel through an HTTPS proxy.  TCP goes to the proxy and TLS is made with
   it (its certificate is checked, by default), and the proxy is asked to
   CONNECT to the target: in a stream of HTTP/2 if it speaks that, which is
   what ALPN says, and on the connection itself if it speaks only HTTP/1.1.
   Once the proxy says yes, what goes through is the target's: a second
   connection, the inner one, is given to the protocol, as if it were a
   socket, and its bytes are those of the tunnel.  The protocol can make TLS
   over it, or speak SSH, and does not know.

   The outer connection and the inner one are two, so that TLS can be made
   twice, once to the proxy and once to the target.  The inner has no
   descriptor: what the protocol writes goes to the tunnel (write_fn), and what
   the tunnel receives is ingested.  The tunnel is the inner connection's owner,
   so it goes with it.

   Each tunnel has a connection of its own to the proxy.  One HTTP/2 connection
   could carry many, and does not yet.  */

enum tunnel_state
{
  T_DIAL,			/* TCP to the proxy.  */
  T_TLS,			/* TLS with the proxy.  */
  T_ASK,			/* CONNECT sent; the answer is awaited.  */
  T_UP,
  T_DEAD
};

#define HEAD_MAX 16384u
#define HELD_MAX (1u << 20)

struct twist_tunnel
{
  struct twist_easy *easy;
  struct twist_loop *loop;
  struct twist_connection *outer;
  struct twist_connection *inner;	/* NULL once the protocol let go.  */
  enum tunnel_state state;
  int h2;
  struct twist_h2 *h2c;
  uint32_t stream;
  int status;			/* The proxy's answer.  */
  char *proxy_host;
  char *authority;		/* host:port of the target.  */
  char *auth;			/* The Proxy-Authorization value, or NULL.  */
  uint8_t *head;		/* HTTP/1.1: the answer so far.  */
  size_t head_len;
  uint8_t *held;		/* What the protocol was not ready to take.  */
  size_t held_len;
  size_t held_cap;
  int in_cb;
  struct twist_timer *timer;
};

static void
tunnel_reap (void *p)
{
  struct twist_tunnel *t = p;

  if (t->timer != NULL)
    twist_timer_cancel (t->timer);
  twist_h2_free (t->h2c);
  twist_connection_free (t->outer);
  free (t->proxy_host);
  free (t->authority);
  if (t->auth != NULL)
    {
      memset (t->auth, 0, strlen (t->auth));
      free (t->auth);
    }
  free (t->head);
  free (t->held);
  free (t);
}

/* The protocol let go of the inner connection.  The outer one may be in the
   middle of a call that led here, so it goes a moment later.  */
static void
inner_free (void *p)
{
  struct twist_tunnel *t = p;

  t->inner = NULL;
  t->state = T_DEAD;
  if (t->outer != NULL)
    twist_connection_set_handler (t->outer, NULL);
  if (twist_loop_post (t->loop, tunnel_reap, t) != TWIST_OK)
    tunnel_reap (t);
}

static void
tunnel_fail (struct twist_tunnel *t, int err)
{
  struct twist_connection *inner = t->inner;

  if (t->state == T_DEAD)
    return;
  t->state = T_DEAD;
  if (t->timer != NULL)
    {
      twist_timer_cancel (t->timer);
      t->timer = NULL;
    }
  if (inner != NULL)
    twist_connection_fail (inner, err);
}

static void
refused (struct twist_tunnel *t, int status)
{
  char msg[128];

  snprintf (msg, sizeof msg, _("CONNECT tunnel failed, response %d"), status);
  twist_easy_set_error (t->easy, twist_strdup (msg));
  t->easy->proto_status = 56;
  tunnel_fail (t, TWIST_ERR_PROXY);
}

static void
on_timeout (void *p)
{
  struct twist_tunnel *t = p;
  char msg[128];

  t->timer = NULL;
  if (t->state == T_UP || t->state == T_DEAD)
    return;
  snprintf (msg, sizeof msg, _("timed out after %ld ms making the "
                               "connection"), t->easy->connect_timeout_ms);
  twist_easy_set_error (t->easy, twist_strdup (msg));
  tunnel_fail (t, TWIST_ERR_TIMEOUT);
}

/* What the tunnel receives, for the protocol: it is held back while the
   protocol has paused, and given again when it resumes.  */
static void
deliver (struct twist_tunnel *t, const uint8_t *data, size_t len)
{
  while (len > 0 && t->inner != NULL && t->state == T_UP)
    {
      size_t n = len > 16384 ? 16384 : len;

      if (twist_connection_paused (t->inner) || t->held_len > 0)
        break;
      twist_connection_ingest (t->inner, data, n);
      data += n;
      len -= n;
    }
  if (len == 0 || t->inner == NULL || t->state != T_UP)
    return;
  if (t->held_len + len > HELD_MAX)
    {
      tunnel_fail (t, TWIST_ERR_PROTOCOL);
      return;
    }
  if (t->held_len + len > t->held_cap)
    {
      size_t cap = t->held_cap == 0 ? 16384 : t->held_cap;
      uint8_t *p;

      while (cap < t->held_len + len)
        cap *= 2;
      p = realloc (t->held, cap);
      if (p == NULL)
        {
          tunnel_fail (t, TWIST_ERR_NOMEM);
          return;
        }
      t->held = p;
      t->held_cap = cap;
    }
  memcpy (t->held + t->held_len, data, len);
  t->held_len += len;
  if (t->outer != NULL)
    twist_endpoint_pause_read (twist_connection_endpoint (t->outer));
}

static void
inner_resume (void *p)
{
  struct twist_tunnel *t = p;
  size_t off = 0;

  while (off < t->held_len && t->inner != NULL && t->state == T_UP
         && !twist_connection_paused (t->inner))
    {
      size_t n = t->held_len - off;

      if (n > 16384)
        n = 16384;
      twist_connection_ingest (t->inner, t->held + off, n);
      off += n;
    }
  if (t->inner == NULL)
    return;
  if (off > 0)
    {
      memmove (t->held, t->held + off, t->held_len - off);
      t->held_len -= off;
    }
  if (t->held_len == 0 && t->outer != NULL)
    twist_endpoint_resume_read (twist_connection_endpoint (t->outer));
}

static ssize_t
inner_read (void *p, uint8_t *buf, size_t len)
{
  (void) p;
  (void) buf;
  (void) len;
  errno = EAGAIN;
  return -1;
}

static ssize_t
inner_write (void *p, const uint8_t *buf, size_t len)
{
  struct twist_tunnel *t = p;

  if (t->state != T_UP || t->outer == NULL)
    {
      errno = EAGAIN;
      return -1;
    }
  if (t->h2)
    {
      size_t n = twist_h2_send_data (t->h2c, t->stream, buf, len, 0);

      if (n == 0)
        {
          errno = EAGAIN;
          return -1;
        }
      return (ssize_t) n;
    }
  if (twist_endpoint_send (twist_connection_endpoint (t->outer), buf, len)
      != TWIST_OK)
    {
      errno = EIO;
      return -1;
    }
  return (ssize_t) len;
}

/* The proxy said yes.  */
static void
tunnel_up (struct twist_tunnel *t)
{
  if (t->state != T_ASK || t->inner == NULL)
    return;
  t->state = T_UP;
  if (t->timer != NULL)
    {
      twist_timer_cancel (t->timer);
      t->timer = NULL;
    }
  twist_connection_connected (t->inner);
  if (t->inner != NULL)
    twist_connection_on_writable (t->inner);
}

/* ---- HTTP/2 ---- */

static void
h2_header (void *user, const char *name, size_t nn, const char *value,
           size_t vn)
{
  struct twist_tunnel *t = user;

  if (nn == 7 && memcmp (name, ":status", 7) == 0 && vn == 3)
    t->status = (value[0] - '0') * 100 + (value[1] - '0') * 10
                + (value[2] - '0');
}

static int
h2_switching (void *user)
{
  struct twist_tunnel *t = user;

  if (t->state != T_ASK)
    return 0;
  if (t->status >= 200 && t->status < 300)
    tunnel_up (t);
  else
    refused (t, t->status);
  return 0;
}

static void
h2_body (void *user, const uint8_t *data, size_t len)
{
  struct twist_tunnel *t = user;

  if (t->state == T_UP)
    deliver (t, data, len);
}

static void
h2_done (void *user)
{
  struct twist_tunnel *t = user;

  if (t->state == T_ASK)
    {
      if (t->status >= 200 && t->status < 300)
        tunnel_fail (t, TWIST_ERR_CLOSED);
      else
        refused (t, t->status);
    }
  else if (t->state == T_UP)
    tunnel_fail (t, TWIST_ERR_CLOSED);
}

static void
h2_failure (void *user, int err)
{
  tunnel_fail (user, err == TWIST_OK ? TWIST_ERR_PROTOCOL : err);
}

static int
h2_emit (void *user, const uint8_t *data, size_t len)
{
  struct twist_tunnel *t = user;

  if (t->outer == NULL)
    return TWIST_ERR_CLOSED;
  return twist_endpoint_send (twist_connection_endpoint (t->outer), data, len);
}

static void
h2_writable (void *user)
{
  struct twist_tunnel *t = user;

  if (t->state == T_UP && t->inner != NULL)
    twist_connection_on_writable (t->inner);
}

static int
start_h2 (struct twist_tunnel *t)
{
  struct twist_h1_events ev;
  struct twist_slist *extra = NULL;
  uint8_t *pre = NULL;
  uint8_t *req = NULL;
  size_t pre_n = 0, req_n = 0;
  char line[1100];
  int rc;

  memset (&ev, 0, sizeof ev);
  ev.user = t;
  ev.header = h2_header;
  ev.body = h2_body;
  ev.message_done = h2_done;
  ev.failure = h2_failure;
  ev.switching = h2_switching;
  t->h2c = twist_h2_new (&ev);
  if (t->h2c == NULL)
    return TWIST_ERR_NOMEM;
  twist_h2_set_emit (t->h2c, h2_emit, t);
  twist_h2_set_writable (t->h2c, h2_writable, t);
  if (t->auth != NULL)
    {
      snprintf (line, sizeof line, "proxy-authorization: Basic %s", t->auth);
      extra = twist_slist_append (NULL, line);
      memset (line, 0, sizeof line);
      if (extra == NULL)
        return TWIST_ERR_NOMEM;
    }
  rc = twist_h2_preface (&pre, &pre_n);
  if (rc == TWIST_OK)
    rc = twist_h2_request (t->h2c, "CONNECT", NULL, t->authority, NULL, extra,
                           NULL, 0, 1, &req, &req_n);
  if (extra != NULL)
    {
      memset (extra->data, 0, strlen (extra->data));
      twist_slist_free_all (extra);
    }
  if (rc == TWIST_OK)
    {
      t->stream = twist_h2_last_stream (t->h2c);
      t->h2 = 1;
      rc = twist_endpoint_send (twist_connection_endpoint (t->outer), pre,
                                pre_n);
      if (rc == TWIST_OK)
        rc = twist_endpoint_send (twist_connection_endpoint (t->outer), req,
                                  req_n);
    }
  free (pre);
  free (req);
  return rc;
}

/* ---- HTTP/1.1 ---- */

static int
start_h1 (struct twist_tunnel *t)
{
  char line[1400];
  int n;

  if (t->auth != NULL)
    n = snprintf (line, sizeof line,
                  "CONNECT %s HTTP/1.1\r\nHost: %s\r\n"
                  "Proxy-Authorization: Basic %s\r\n\r\n", t->authority,
                  t->authority, t->auth);
  else
    n = snprintf (line, sizeof line, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n",
                  t->authority, t->authority);
  if (n < 0 || (size_t) n >= sizeof line)
    return TWIST_ERR_URL;
  n = twist_endpoint_send (twist_connection_endpoint (t->outer),
                           (const uint8_t *) line, (size_t) n);
  memset (line, 0, sizeof line);
  return n;
}

/* The answer of an HTTP/1.1 proxy: a status line and headers, to the blank
   line.  What comes after is the tunnel's.  */
static size_t
h1_answer (struct twist_tunnel *t, const uint8_t *data, size_t len)
{
  uint8_t *p;
  size_t old = t->head_len;
  size_t i;
  int status = 0;

  p = realloc (t->head, old + len + 1);
  if (p == NULL)
    {
      tunnel_fail (t, TWIST_ERR_NOMEM);
      return len;
    }
  t->head = p;
  memcpy (t->head + old, data, len);
  t->head_len = old + len;
  t->head[t->head_len] = 0;
  for (i = old >= 3 ? old - 3 : 0; i + 4 <= t->head_len; i++)
    if (memcmp (t->head + i, "\r\n\r\n", 4) == 0)
      break;
  if (i + 4 > t->head_len)
    {
      if (t->head_len > HEAD_MAX)
        tunnel_fail (t, TWIST_ERR_PROTOCOL);
      return len;
    }
  /* "HTTP/1.1 200 ...".  */
  if (t->head_len >= 12 && memcmp (t->head, "HTTP/1.", 7) == 0
      && t->head[8] == ' ' && t->head[9] >= '0' && t->head[9] <= '9'
      && t->head[10] >= '0' && t->head[10] <= '9' && t->head[11] >= '0'
      && t->head[11] <= '9')
    status = (t->head[9] - '0') * 100 + (t->head[10] - '0') * 10
             + (t->head[11] - '0');
  {
    size_t after = i + 4;
    size_t extra = t->head_len - after;
    size_t used = len - extra;

    if (status < 200 || status >= 300)
      {
        if (status == 0)
          tunnel_fail (t, TWIST_ERR_PROTOCOL);
        else
          refused (t, status);
        return len;
      }
    t->status = status;
    tunnel_up (t);
    if (extra > 0 && t->state == T_UP)
      deliver (t, t->head + after, extra);
    free (t->head);
    t->head = NULL;
    t->head_len = 0;
    return used + extra;
  }
}

/* ---- the connection to the proxy ---- */

static void
outer_connected (struct twist_endpoint *ep)
{
  struct twist_tunnel *t = ep->user_data;
  static const char *const alpn[] = { "h2", "http/1.1" };
  struct twist_easy *e = t->easy;
  int rc;

  if (t->state != T_DIAL)
    return;
  t->state = T_TLS;
  rc = twist_connection_start_tls (t->outer, t->proxy_host, e->proxy_verifypeer,
                                   alpn, 2,
                                   e->proxy_cainfo != NULL ? e->proxy_cainfo
                                   : e->cainfo,
                                   e->proxy_cainfo != NULL ? NULL : e->capath,
                                   NULL, NULL);
  if (rc != TWIST_OK)
    tunnel_fail (t, rc);
}

static void
outer_secure (struct twist_endpoint *ep, const char *alpn, size_t len)
{
  struct twist_tunnel *t = ep->user_data;
  int rc;

  if (t->state != T_TLS)
    return;
  t->state = T_ASK;
  if (len == 2 && memcmp (alpn, "h2", 2) == 0)
    rc = start_h2 (t);
  else
    rc = start_h1 (t);
  if (rc != TWIST_OK)
    tunnel_fail (t, rc);
}

static size_t
outer_receive (struct twist_endpoint *ep, const uint8_t *data, size_t len)
{
  struct twist_tunnel *t = ep->user_data;
  size_t used;

  if (t->state == T_DEAD)
    return len;
  t->in_cb++;
  if (t->state == T_ASK && !t->h2)
    used = h1_answer (t, data, len);
  else if (t->h2)
    used = twist_h2_receive (t->h2c, data, len);
  else
    {
      deliver (t, data, len);
      used = len;
    }
  t->in_cb--;
  return used;
}

static void
outer_disconnected (struct twist_endpoint *ep, int err)
{
  struct twist_tunnel *t = ep->user_data;

  if (t->state == T_DEAD)
    return;
  if (t->state == T_UP)
    tunnel_fail (t, err == TWIST_OK ? TWIST_ERR_CLOSED : err);
  else
    tunnel_fail (t, err == TWIST_OK ? TWIST_ERR_CONNECT : err);
}

static const struct twist_protocol_handler outer_handler = {
  outer_connected,
  outer_receive,
  outer_disconnected,
  outer_secure,
  NULL,
  NULL,
  NULL
};

/* host:port, with brackets round an IPv6 address.  */
static char *
authority_of (const char *host, int port)
{
  size_t n = strlen (host) + 16;
  char *s = twist_xmalloc (n);

  if (s == NULL)
    return NULL;
  if (strchr (host, ':') != NULL)
    snprintf (s, n, "[%s]:%d", host, port);
  else
    snprintf (s, n, "%s:%d", host, port);
  return s;
}

static char *
basic_of (const char *user, const char *pass)
{
  char cred[600];
  char *enc = NULL;
  int n = snprintf (cred, sizeof cred, "%s:%s", user, pass != NULL ? pass : "");

  if (n < 0 || (size_t) n >= sizeof cred
      || twist_b64_encode ((const uint8_t *) cred, (size_t) n, &enc)
         != TWIST_OK)
    enc = NULL;
  memset (cred, 0, sizeof cred);
  return enc;
}

int
twist_tunnel_connect (struct twist_easy *easy,
                      const struct twist_tunnel_spec *spec,
                      const struct twist_dns_addr *proxy_addr,
                      const struct twist_protocol_handler *handler,
                      void *user, struct twist_connection **out)
{
  struct twist_tunnel *t;
  struct sockaddr_in sin;
  struct sockaddr_in6 sin6;
  const void *sa;
  size_t salen;
  const char *u = spec->user;
  const char *pw = spec->pass;
  char *split = NULL;
  int rc;

  *out = NULL;
  t = calloc (1, sizeof *t);
  if (t == NULL)
    return TWIST_ERR_NOMEM;
  t->easy = easy;
  t->loop = easy->loop;
  t->proxy_host = twist_strdup (spec->proxy_host);
  t->authority = authority_of (spec->host, spec->port);
  /* Credentials of the proxy's URL, or else -U, as given.  */
  if (u == NULL && easy->proxy_userpwd != NULL)
    {
      const char *c = strchr (easy->proxy_userpwd, ':');

      if (c != NULL)
        {
          split = twist_xmalloc ((size_t) (c - easy->proxy_userpwd) + 1);
          if (split != NULL)
            {
              memcpy (split, easy->proxy_userpwd,
                      (size_t) (c - easy->proxy_userpwd));
              split[c - easy->proxy_userpwd] = 0;
            }
          u = split;
          pw = c + 1;
        }
      else
        {
          u = easy->proxy_userpwd;
          pw = "";
        }
    }
  if (u != NULL)
    t->auth = basic_of (u, pw);
  free (split);
  t->outer = twist_connection_new (easy->loop);
  t->inner = twist_connection_new (easy->loop);
  if (t->proxy_host == NULL || t->authority == NULL || t->outer == NULL
      || t->inner == NULL || (u != NULL && t->auth == NULL))
    {
      twist_connection_free (t->inner);
      t->inner = NULL;
      tunnel_reap (t);
      return TWIST_ERR_NOMEM;
    }
  t->state = T_DIAL;
  twist_connection_set_io (t->inner, inner_read, inner_write, t);
  twist_connection_set_owner (t->inner, t, inner_free, inner_resume);
  twist_connection_endpoint (t->inner)->user_data = user;
  twist_connection_set_handler (t->inner, handler);
  twist_connection_endpoint (t->outer)->user_data = t;
  twist_connection_set_handler (t->outer, &outer_handler);
  if (proxy_addr->family == 6)
    {
      memset (&sin6, 0, sizeof sin6);
      sin6.sin6_family = AF_INET6;
      memcpy (&sin6.sin6_addr, proxy_addr->addr, 16);
      sin6.sin6_scope_id = proxy_addr->scope_id;
      sin6.sin6_port = htons ((uint16_t) spec->proxy_port);
      sa = &sin6;
      salen = sizeof sin6;
    }
  else
    {
      memset (&sin, 0, sizeof sin);
      sin.sin_family = AF_INET;
      memcpy (&sin.sin_addr, proxy_addr->addr, 4);
      sin.sin_port = htons ((uint16_t) spec->proxy_port);
      sa = &sin;
      salen = sizeof sin;
    }
  if (easy->connect_timeout_ms > 0)
    twist_loop_schedule (easy->loop,
                         twist_loop_now (easy->loop)
                         + (uint64_t) easy->connect_timeout_ms,
                         on_timeout, t, &t->timer);
  rc = twist_connection_connect (t->outer, sa, salen,
                                 (uint64_t) easy->connect_timeout_ms);
  if (rc != TWIST_OK)
    {
      /* The inner connection is the caller's to free, as it would be.  */
      t->state = T_DEAD;
      *out = t->inner;
      return rc;
    }
  *out = t->inner;
  return TWIST_OK;
}
