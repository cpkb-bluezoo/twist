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

   The connection to the proxy is a HUB, and is shared: tunnels to one proxy
   (the same address, credentials and trust) are streams of one HTTP/2
   connection, and a tunnel that finds the hub still being made waits for it.
   A hub that turns out to speak only HTTP/1.1 carries a single tunnel, since
   a CONNECT takes the connection; the others make hubs of their own, and the
   next ones do not wait to be told again.  A hub with no tunnel is kept a
   while, for the next.  */

enum tunnel_state
{
  T_WAIT,			/* On a hub that is not yet up.  */
  T_ASK,			/* CONNECT sent; the answer is awaited.  */
  T_UP,
  T_DEAD
};

enum hub_state
{
  H_DIAL,			/* TCP to the proxy.  */
  H_TLS,			/* TLS with the proxy.  */
  H_H2,
  H_H1,
  H_DEAD
};

#define HEAD_MAX 16384u
#define HELD_MAX (1u << 20)
#define HUB_LINGER_MS 30000

struct tunnel_hub;

struct twist_tunnel
{
  struct twist_transfer *transfer;
  struct twist_loop *loop;
  struct tunnel_hub *hub;
  struct twist_tunnel *next;	/* On the hub.  */
  struct twist_connection *inner;	/* NULL once the protocol let go.  */
  enum tunnel_state state;
  uint32_t stream;
  int status;			/* The proxy's answer.  */
  struct twist_dns_addr addr;	/* The proxy, to go to another hub.  */
  int proxy_port;
  char *proxy_host;
  char *authority;		/* host:port of the target.  */
  char *auth;			/* The Proxy-Authorization value, or NULL.  */
  char *key;			/* Which hub it can be on.  */
  uint8_t *head;		/* HTTP/1.1: the answer so far.  */
  size_t head_len;
  uint8_t *held;		/* What the protocol was not ready to take.  */
  size_t held_len;
  size_t held_cap;
  struct twist_timer *timer;
};

struct tunnel_hub
{
  struct twist_lane *lane;
  struct twist_loop *loop;
  struct twist_connection *outer;
  struct twist_h2 *h2c;
  enum hub_state state;
  int exclusive;		/* Made for one tunnel: HTTP/1.1 is expected.  */
  int freeing;
  char *key;
  char *proxy_host;
  char *cainfo;
  char *capath;
  int verify;
  struct twist_tunnel *tunnels;
  size_t n;
  struct twist_timer *idle;
  struct tunnel_hub *next;
};

static void tunnel_fail (struct twist_tunnel *t, int err);
static int tunnel_place (struct twist_tunnel *t);

/* ---- hubs ---- */

static void
hub_free (struct tunnel_hub *hub)
{
  struct twist_tunnel *t;
  struct tunnel_hub **pp;

  if (hub->idle != NULL)
    twist_timer_cancel (hub->idle);
  for (pp = &hub->lane->hubs; *pp != NULL; pp = &(*pp)->next)
    if (*pp == hub)
      {
        *pp = hub->next;
        break;
      }
  for (t = hub->tunnels; t != NULL; t = t->next)
    t->hub = NULL;
  twist_h2_free (hub->h2c);
  twist_connection_free (hub->outer);
  if (hub->key != NULL)
    {
      memset (hub->key, 0, strlen (hub->key));
      free (hub->key);
    }
  free (hub->proxy_host);
  free (hub->cainfo);
  free (hub->capath);
  free (hub);
}

static void
hub_free_posted (void *p)
{
  hub_free (p);
}

/* Free the hub a moment later: it may be in the middle of a call.  */
static void
hub_drop (struct tunnel_hub *hub)
{
  if (hub->freeing)
    return;
  hub->freeing = 1;
  if (hub->idle != NULL)
    {
      twist_timer_cancel (hub->idle);
      hub->idle = NULL;
    }
  if (twist_loop_post (hub->loop, hub_free_posted, hub) != TWIST_OK)
    hub_free (hub);
}

static void
hub_idle_expired (void *p)
{
  struct tunnel_hub *hub = p;

  hub->idle = NULL;
  if (hub->n == 0)
    hub_drop (hub);
}

/* What is to be done with a hub that has no tunnel (or never had one).  */
static void
hub_release (struct tunnel_hub *hub)
{
  if (hub->n > 0 || hub->freeing)
    return;
  if (hub->state == H_DEAD || hub->state == H_H1)
    hub_drop (hub);
  else if (hub->state == H_H2 && hub->idle == NULL)
    twist_loop_schedule (hub->loop,
                         twist_loop_now (hub->loop) + HUB_LINGER_MS,
                         hub_idle_expired, hub, &hub->idle);
}

static void
hub_link (struct tunnel_hub *hub, struct twist_tunnel *t)
{
  struct twist_tunnel **pp = &hub->tunnels;

  while (*pp != NULL)
    pp = &(*pp)->next;
  *pp = t;
  t->next = NULL;
  t->hub = hub;
  hub->n++;
  if (hub->idle != NULL)
    {
      twist_timer_cancel (hub->idle);
      hub->idle = NULL;
    }
}

static void
hub_unlink (struct twist_tunnel *t)
{
  struct tunnel_hub *hub = t->hub;
  struct twist_tunnel **pp;

  if (hub == NULL)
    return;
  for (pp = &hub->tunnels; *pp != NULL; pp = &(*pp)->next)
    if (*pp == t)
      {
        *pp = t->next;
        hub->n--;
        break;
      }
  t->hub = NULL;
  t->next = NULL;
}

/* The connection to the proxy has failed, or the proxy has gone: every tunnel
   on it has.  */
static void
hub_fail (struct tunnel_hub *hub, int err)
{
  struct twist_tunnel *t;

  if (hub->state == H_DEAD)
    return;
  hub->state = H_DEAD;
  if (hub->idle != NULL)
    {
      twist_timer_cancel (hub->idle);
      hub->idle = NULL;
    }
  /* A tunnel that fails may let go of its connection, and a tunnel is
     unlinked only a moment after, so the list stands while this goes
     through it; a tunnel that has failed is passed.  */
  for (t = hub->tunnels; t != NULL; t = t->next)
    if (t->state != T_DEAD)
      {
        int e = err;

        if (e == TWIST_OK)
          e = t->state == T_UP ? TWIST_ERR_CLOSED : TWIST_ERR_CONNECT;
        tunnel_fail (t, e);
      }
  hub_release (hub);
}

/* ---- a tunnel ---- */

static void
tunnel_reap (void *p)
{
  struct twist_tunnel *t = p;
  struct tunnel_hub *hub = t->hub;

  hub_unlink (t);
  if (hub != NULL)
    hub_release (hub);
  if (t->timer != NULL)
    twist_timer_cancel (t->timer);
  free (t->proxy_host);
  free (t->authority);
  if (t->auth != NULL)
    {
      memset (t->auth, 0, strlen (t->auth));
      free (t->auth);
    }
  if (t->key != NULL)
    {
      memset (t->key, 0, strlen (t->key));
      free (t->key);
    }
  free (t->head);
  free (t->held);
  free (t);
}

/* The protocol let go of the inner connection.  The outer one may be in the
   middle of a call that led here, so the tunnel goes a moment later.  */
static void
inner_free (void *p)
{
  struct twist_tunnel *t = p;
  struct tunnel_hub *hub = t->hub;

  t->inner = NULL;
  t->state = T_DEAD;
  if (t->timer != NULL)
    {
      twist_timer_cancel (t->timer);
      t->timer = NULL;
    }
  if (hub != NULL && hub->state == H_H2 && t->stream != 0)
    {
      twist_h2_drop_user (hub->h2c, t);
      twist_h2_cancel (hub->h2c, t->stream);
    }
  else if (hub != NULL && hub->state == H_H1)
    {
      /* The proxy's connection is the tunnel's, and ends with it.  */
      hub->state = H_DEAD;
    }
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
  twist_transfer_set_error (t->transfer, twist_strdup (msg));
  t->transfer->proto_status = 56;
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
                               "connection"), t->transfer->connect_timeout_ms);
  twist_transfer_set_error (t->transfer, twist_strdup (msg));
  tunnel_fail (t, TWIST_ERR_TIMEOUT);
}

/* Stop what the proxy sends for this tunnel until the protocol takes what it
   has: in HTTP/2 the stream's window is not given back, so that the proxy
   stops by itself and the other tunnels go on; the HTTP/1.1 connection is
   the tunnel's, and is not read.  */
static void
tunnel_hold (struct twist_tunnel *t, int hold)
{
  struct tunnel_hub *hub = t->hub;

  if (hub == NULL || hub->outer == NULL)
    return;
  if (hub->state == H_H2)
    twist_h2_hold_stream (hub->h2c, t->stream, hold);
  else if (hold)
    twist_endpoint_pause_read (twist_connection_endpoint (hub->outer));
  else
    twist_endpoint_resume_read (twist_connection_endpoint (hub->outer));
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
  tunnel_hold (t, 1);
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
  if (t->held_len == 0)
    tunnel_hold (t, 0);
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
  struct tunnel_hub *hub = t->hub;

  if (t->state != T_UP || hub == NULL || hub->outer == NULL)
    {
      errno = EAGAIN;
      return -1;
    }
  /* What is written here goes into the proxy's connection: while that holds a
     chunk it has not written, this waits (hub_drained says when it has).  */
  if (twist_endpoint_full (twist_connection_endpoint (hub->outer)))
    {
      errno = EAGAIN;
      return -1;
    }
  if (hub->state == H_H2)
    {
      size_t n = twist_h2_send_data (hub->h2c, t->stream, buf, len, 0);

      if (n == 0)
        {
          errno = EAGAIN;
          return -1;
        }
      return (ssize_t) n;
    }
  if (twist_endpoint_send (twist_connection_endpoint (hub->outer), buf, len)
      != TWIST_OK)
    {
      errno = EIO;
      return -1;
    }
  return (ssize_t) len;
}

/* The protocol has sent all it will on this tunnel (the end of an upload):
   its direction ends, and the other goes on.  */
static void
inner_shutdown (void *p)
{
  struct twist_tunnel *t = p;
  struct tunnel_hub *hub = t->hub;

  if (t->state != T_UP || hub == NULL || hub->outer == NULL)
    return;
  if (hub->state == H_H2)
    twist_h2_send_data (hub->h2c, t->stream, NULL, 0, 1);
  else
    twist_connection_half_close (hub->outer);
}

/* The tunnels on the hub can write, each to the protocol that has it.  A
   protocol that lets go of its tunnel does not unlink it until later, so the
   list stands.  */
static void
hub_writable (struct tunnel_hub *hub)
{
  struct twist_tunnel *t;

  for (t = hub->tunnels; t != NULL; t = t->next)
    if (t->state == T_UP && t->inner != NULL)
      twist_connection_on_writable (t->inner);
}

/* The proxy's connection has written all that was queued on it: what is
   inside the tunnels can go on.  */
static void
hub_drained (struct twist_endpoint *ep)
{
  struct tunnel_hub *hub = ep->write_user;

  if (hub != NULL && hub->state != H_DEAD)
    hub_writable (hub);
}

static void
h2_writable (void *user)
{
  struct tunnel_hub *hub = user;

  if (hub->state == H_H2)
    hub_writable (hub);
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
    t->status = twist_status_code (value);
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

/* The codec is the hub's, and its failure is the connection's.  */
static void
h2_hub_failure (void *user, int err)
{
  hub_fail (user, err == TWIST_OK ? TWIST_ERR_PROTOCOL : err);
}

static int
h2_emit (void *user, const uint8_t *data, size_t len)
{
  struct tunnel_hub *hub = user;

  if (hub->outer == NULL)
    return TWIST_ERR_CLOSED;
  return twist_endpoint_send (twist_connection_endpoint (hub->outer), data, len);
}

/* CONNECT on a stream of its own.  TWIST_ERR_AGAIN: the connection has no
   stream to give, and the tunnel is to go to another.  */
static int
open_stream (struct twist_tunnel *t)
{
  struct tunnel_hub *hub = t->hub;
  struct twist_h1_events ev;
  struct twist_slist *extra = NULL;
  uint8_t *req = NULL;
  size_t req_n = 0;
  char line[1100];
  int rc;

  if (!twist_h2_can_open (hub->h2c))
    return TWIST_ERR_AGAIN;
  memset (&ev, 0, sizeof ev);
  ev.user = t;
  ev.header = h2_header;
  ev.body = h2_body;
  ev.message_done = h2_done;
  ev.failure = h2_failure;
  ev.switching = h2_switching;
  if (t->auth != NULL)
    {
      snprintf (line, sizeof line, "proxy-authorization: Basic %s", t->auth);
      extra = twist_slist_append (NULL, line);
      memset (line, 0, sizeof line);
      if (extra == NULL)
        return TWIST_ERR_NOMEM;
    }
  twist_h2_set_next_owner (hub->h2c, &ev);
  rc = twist_h2_request (hub->h2c, "CONNECT", NULL, t->authority, NULL, extra,
                         NULL, 0, 1, &req, &req_n);
  twist_h2_set_next_owner (hub->h2c, NULL);
  if (extra != NULL)
    {
      memset (extra->data, 0, strlen (extra->data));
      twist_slist_free_all (extra);
    }
  if (rc == TWIST_OK)
    {
      t->stream = twist_h2_last_stream (hub->h2c);
      t->state = T_ASK;
      rc = twist_endpoint_send (twist_connection_endpoint (hub->outer), req,
                                req_n);
    }
  free (req);
  return rc;
}

/* ---- HTTP/1.1 ---- */

static int
start_h1 (struct twist_tunnel *t)
{
  struct tunnel_hub *hub = t->hub;
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
  t->state = T_ASK;
  n = twist_endpoint_send (twist_connection_endpoint (hub->outer),
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
hub_connected (struct twist_endpoint *ep)
{
  struct tunnel_hub *hub = ep->user_data;
  static const char *const alpn[] = { "h2", "http/1.1" };
  int rc;

  if (hub->state != H_DIAL)
    return;
  hub->state = H_TLS;
  rc = twist_connection_start_tls (hub->outer, hub->proxy_host, hub->verify,
                                   alpn, 2, hub->cainfo, hub->capath, NULL,
                                   NULL);
  if (rc != TWIST_OK)
    hub_fail (hub, rc);
}

/* The proxy speaks HTTP/2: the tunnels that wait are given streams.  */
static int
hub_start_h2 (struct tunnel_hub *hub)
{
  struct twist_h1_events ev;
  struct twist_tunnel *t, *next;
  uint8_t *pre = NULL;
  size_t pre_n = 0;
  int rc;

  memset (&ev, 0, sizeof ev);
  ev.user = hub;
  ev.failure = h2_hub_failure;
  hub->h2c = twist_h2_new (&ev);
  if (hub->h2c == NULL)
    return TWIST_ERR_NOMEM;
  twist_h2_set_emit (hub->h2c, h2_emit, hub);
  twist_h2_set_writable (hub->h2c, h2_writable, hub);
  rc = twist_h2_preface (&pre, &pre_n);
  if (rc == TWIST_OK)
    rc = twist_endpoint_send (twist_connection_endpoint (hub->outer), pre,
                              pre_n);
  free (pre);
  if (rc != TWIST_OK)
    return rc;
  hub->state = H_H2;
  hub->exclusive = 0;
  for (t = hub->tunnels; t != NULL; t = next)
    {
      next = t->next;
      if (t->state != T_WAIT)
        continue;
      rc = open_stream (t);
      if (rc == TWIST_ERR_AGAIN)
        {
          /* More waited than the proxy allows at once.  */
          hub_unlink (t);
          rc = tunnel_place (t);
        }
      if (rc != TWIST_OK)
        tunnel_fail (t, rc);
    }
  hub_release (hub);
  return TWIST_OK;
}

/* The proxy speaks HTTP/1.1: the first tunnel takes the connection, and the
   others go to connections of their own.  */
static int
hub_start_h1 (struct tunnel_hub *hub)
{
  struct twist_tunnel *t, *next, *first = NULL;
  int rc = TWIST_OK;

  hub->state = H_H1;
  hub->exclusive = 1;
  for (t = hub->tunnels; t != NULL; t = next)
    {
      next = t->next;
      if (t->state != T_WAIT)
        continue;
      if (first == NULL)
        {
          first = t;
          continue;
        }
      hub_unlink (t);
      rc = tunnel_place (t);
      if (rc != TWIST_OK)
        tunnel_fail (t, rc);
    }
  if (first != NULL)
    {
      rc = start_h1 (first);
      if (rc != TWIST_OK)
        tunnel_fail (first, rc);
    }
  hub_release (hub);
  return TWIST_OK;
}

static void
hub_secure (struct twist_endpoint *ep, const char *alpn, size_t len)
{
  struct tunnel_hub *hub = ep->user_data;
  int rc;

  if (hub->state != H_TLS)
    return;
  if (len == 2 && memcmp (alpn, "h2", 2) == 0)
    rc = hub_start_h2 (hub);
  else
    rc = hub_start_h1 (hub);
  if (rc != TWIST_OK)
    hub_fail (hub, rc);
}

static size_t
hub_receive (struct twist_endpoint *ep, const uint8_t *data, size_t len)
{
  struct tunnel_hub *hub = ep->user_data;
  struct twist_tunnel *t = hub->tunnels;

  if (hub->state == H_H2)
    return twist_h2_receive (hub->h2c, data, len);
  if (hub->state != H_H1 || t == NULL || t->state == T_DEAD)
    return len;
  if (t->state == T_ASK)
    return h1_answer (t, data, len);
  deliver (t, data, len);
  return len;
}

static void
hub_disconnected (struct twist_endpoint *ep, int err)
{
  struct tunnel_hub *hub = ep->user_data;

  hub_fail (hub, err);
}

static const struct twist_protocol_handler hub_handler = {
  hub_connected,
  hub_receive,
  hub_disconnected,
  hub_secure,
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

/* Which connection a tunnel can share: the proxy's address and name, how it
   is trusted and the credentials it is given.  */
static char *
key_of (const struct twist_transfer *e, const struct twist_dns_addr *a,
        const char *host, int port, const char *auth)
{
  const char *ca = e->proxy_cainfo != NULL ? e->proxy_cainfo : e->cainfo;
  const char *cp = e->proxy_cainfo != NULL ? NULL : e->capath;
  char abuf[sizeof a->addr * 2 + 1];
  size_t i, n;
  char *k;

  for (i = 0; i < sizeof a->addr; i++)
    snprintf (abuf + i * 2, 3, "%02x", a->addr[i]);
  n = strlen (abuf) + strlen (host) + strlen (auth != NULL ? auth : "")
      + strlen (ca != NULL ? ca : "") + strlen (cp != NULL ? cp : "") + 64;
  k = twist_xmalloc (n);
  if (k == NULL)
    return NULL;
  snprintf (k, n, "%d|%s|%u|%d|%s|%d|%s|%s|%s", a->family, abuf,
            (unsigned) a->scope_id, port, host, e->proxy_verifypeer != 0,
            auth != NULL ? auth : "", ca != NULL ? ca : "",
            cp != NULL ? cp : "");
  return k;
}

static struct tunnel_hub *
hub_new (struct twist_tunnel *t)
{
  struct twist_transfer *e = t->transfer;
  struct tunnel_hub *hub = calloc (1, sizeof *hub);
  const char *ca = e->proxy_cainfo != NULL ? e->proxy_cainfo : e->cainfo;
  const char *cp = e->proxy_cainfo != NULL ? NULL : e->capath;

  if (hub == NULL)
    return NULL;
  hub->lane = twist_lane_of_loop (twist_loop_runtime (t->loop), t->loop);
  hub->loop = t->loop;
  hub->key = twist_strdup (t->key);
  hub->proxy_host = twist_strdup (t->proxy_host);
  hub->cainfo = ca != NULL ? twist_strdup (ca) : NULL;
  hub->capath = cp != NULL ? twist_strdup (cp) : NULL;
  hub->verify = e->proxy_verifypeer;
  hub->outer = twist_connection_new (t->loop);
  if (hub->key == NULL || hub->proxy_host == NULL || hub->outer == NULL
      || (ca != NULL && hub->cainfo == NULL)
      || (cp != NULL && hub->capath == NULL))
    {
      hub_free (hub);
      return NULL;
    }
  /* The proxy's own socket is the one that is kept to the limit.  */
  twist_connection_limit (hub->outer, e);
  twist_connection_endpoint (hub->outer)->user_data = hub;
  twist_connection_endpoint (hub->outer)->on_write_ready = hub_drained;
  twist_connection_endpoint (hub->outer)->write_user = hub;
  twist_connection_set_handler (hub->outer, &hub_handler);
  hub->state = H_DIAL;
  return hub;
}

static int
hub_dial (struct tunnel_hub *hub, const struct twist_tunnel *t)
{
  struct sockaddr_in sin;
  struct sockaddr_in6 sin6;
  const void *sa;
  size_t salen;

  if (t->addr.family == 6)
    {
      memset (&sin6, 0, sizeof sin6);
      sin6.sin6_family = AF_INET6;
      memcpy (&sin6.sin6_addr, t->addr.addr, 16);
      sin6.sin6_scope_id = t->addr.scope_id;
      sin6.sin6_port = htons ((uint16_t) t->proxy_port);
      sa = &sin6;
      salen = sizeof sin6;
    }
  else
    {
      memset (&sin, 0, sizeof sin);
      sin.sin_family = AF_INET;
      memcpy (&sin.sin_addr, t->addr.addr, 4);
      sin.sin_port = htons ((uint16_t) t->proxy_port);
      sa = &sin;
      salen = sizeof sin;
    }
  return twist_connection_connect (hub->outer, sa, salen,
                                   (uint64_t) t->transfer->connect_timeout_ms);
}

/* Put the tunnel on a hub: one that is up and has a stream to give, or is
   being made, and else a new one.  A tunnel moved off an HTTP/1.1 hub does
   not wait for another to find out, since this one has.  */
static int
tunnel_place (struct twist_tunnel *t)
{
  struct twist_lane *lane = twist_lane_of_loop (twist_loop_runtime (t->loop),
                                                t->loop);
  struct tunnel_hub *hub, *use = NULL;
  int learned_h1 = 0;
  int rc;

  for (hub = lane->hubs; hub != NULL; hub = hub->next)
    {
      if (hub->freeing || hub->state == H_DEAD
          || strcmp (hub->key, t->key) != 0)
        continue;
      if (hub->state == H_H1)
        learned_h1 = 1;
      else if (hub->exclusive)
        continue;
      else if (hub->state == H_H2 ? twist_h2_can_open (hub->h2c) : 1)
        {
          use = hub;
          break;
        }
    }
  if (use == NULL)
    {
      use = hub_new (t);
      if (use == NULL)
        return TWIST_ERR_NOMEM;
      use->exclusive = learned_h1;
      use->next = use->lane->hubs;
      use->lane->hubs = use;
      hub_link (use, t);
      rc = hub_dial (use, t);
      if (rc != TWIST_OK)
        {
          hub_unlink (t);
          use->state = H_DEAD;
          hub_drop (use);
          return rc;
        }
      t->state = T_WAIT;
      return TWIST_OK;
    }
  hub_link (use, t);
  if (use->state == H_H2)
    {
      rc = open_stream (t);
      if (rc == TWIST_ERR_AGAIN)
        {
          hub_unlink (t);
          return tunnel_place (t);
        }
      return rc;
    }
  t->state = T_WAIT;
  return TWIST_OK;
}

int
twist_tunnel_connect (struct twist_transfer *transfer,
                      const struct twist_tunnel_spec *spec,
                      const struct twist_dns_addr *proxy_addr,
                      const struct twist_protocol_handler *handler,
                      void *user, struct twist_connection **out)
{
  struct twist_tunnel *t;
  const char *u = spec->user;
  const char *pw = spec->pass;
  char *split = NULL;
  int rc;

  *out = NULL;
  t = calloc (1, sizeof *t);
  if (t == NULL)
    return TWIST_ERR_NOMEM;
  t->transfer = transfer;
  t->loop = transfer->loop;
  t->addr = *proxy_addr;
  t->proxy_port = spec->proxy_port;
  t->proxy_host = twist_strdup (spec->proxy_host);
  t->authority = authority_of (spec->host, spec->port);
  /* Credentials of the proxy's URL, or else -U, as given.  */
  if (u == NULL && transfer->proxy_userpwd != NULL)
    {
      const char *c = strchr (transfer->proxy_userpwd, ':');

      if (c != NULL)
        {
          split = twist_xmalloc ((size_t) (c - transfer->proxy_userpwd) + 1);
          if (split != NULL)
            {
              memcpy (split, transfer->proxy_userpwd,
                      (size_t) (c - transfer->proxy_userpwd));
              split[c - transfer->proxy_userpwd] = 0;
            }
          u = split;
          pw = c + 1;
        }
      else
        {
          u = transfer->proxy_userpwd;
          pw = "";
        }
    }
  if (u != NULL)
    t->auth = basic_of (u, pw);
  free (split);
  t->inner = twist_connection_new (transfer->loop);
  if (t->proxy_host != NULL && (u == NULL || t->auth != NULL))
    t->key = key_of (transfer, proxy_addr, spec->proxy_host, spec->proxy_port,
                     t->auth);
  if (t->proxy_host == NULL || t->authority == NULL || t->inner == NULL
      || t->key == NULL || (u != NULL && t->auth == NULL))
    {
      twist_connection_free (t->inner);
      t->inner = NULL;
      tunnel_reap (t);
      return TWIST_ERR_NOMEM;
    }
  t->state = T_WAIT;
  twist_connection_set_io (t->inner, inner_read, inner_write, t);
  twist_connection_set_owner (t->inner, t, inner_free, inner_resume);
  twist_connection_set_shutdown (t->inner, inner_shutdown);
  twist_connection_endpoint (t->inner)->user_data = user;
  twist_connection_set_handler (t->inner, handler);
  rc = tunnel_place (t);
  if (rc != TWIST_OK)
    {
      /* The inner connection is the caller's to free, as it would be.  */
      t->state = T_DEAD;
      *out = t->inner;
      return rc;
    }
  if (transfer->connect_timeout_ms > 0 && t->state != T_UP)
    twist_loop_schedule (transfer->loop,
                         twist_loop_now (transfer->loop)
                         + (uint64_t) transfer->connect_timeout_ms,
                         on_timeout, t, &t->timer);
  *out = t->inner;
  return TWIST_OK;
}

/* The runtime is going: the hubs go with it, and the tunnels that are still
   to be let go of no longer have one.  */
void
twist_tunnel_free_all (struct twist_runtime *runtime)
{
  size_t i;

  if (runtime == NULL)
    return;
  for (i = 0; i < runtime->n_lanes; i++)
    while (runtime->lanes[i]->hubs != NULL)
      {
        struct tunnel_hub *hub = runtime->lanes[i]->hubs;

        hub->freeing = 1;
        hub_free (hub);
      }
}
