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
#include <strings.h>

/* CONNECT-UDP (RFC 9298) to an HTTP/3 proxy, so that HTTP/3 can go through a
   proxy: the target is reached by QUIC, and QUIC is UDP.

   Two QUIC connections.  The outer one is to the proxy: its ALPN is h3, it
   has DATAGRAM frames (RFC 9221) and says H3_DATAGRAM (RFC 9297) in its
   SETTINGS, and on its first request stream is the extended CONNECT with
   :protocol connect-udp and the proxy's URI Template expanded for the target.
   The inner one is to the target: a QUIC client that has no socket, whose
   packets are given to this module as they are made.  Each goes to the proxy
   in a datagram that begins with the quarter stream ID of the request (the
   stream's number over four) and the context ID 0, and what the proxy sends
   back the same way is fed to the inner connection.  The proxy looks up the
   target's name; twist does not.

   The inner connection's first flight is at least 1200 bytes (RFC 9000, 14.1)
   and has to fit a datagram of the outer one, which starts at 1200 and grows
   by path MTU discovery.  What does not fit yet is held, and sent when it
   does.  A datagram that is lost is lost; QUIC makes up for it.  */

#define HOLD_MAX 32u

enum mstate
{
  M_ASK,
  M_UP,
  M_DEAD
};

struct held
{
  uint8_t *data;
  size_t len;
};

struct twist_masque
{
  struct twist_easy *easy;
  struct twist_loop *loop;
  struct twist_connection *outer;
  struct twist_connection *inner;
  struct twist_h3 *h3;
  enum mstate state;
  int status;
  uint64_t qsid;
  char *authority;
  char *path;
  char *auth;
  struct held held[HOLD_MAX];
  size_t n_held;
  struct twist_timer *timer;
  struct twist_timer *retry;
};

static const struct twist_protocol_handler outer_handler;

static void
masque_reap (void *p)
{
  struct twist_masque *m = p;
  size_t i;

  if (m->timer != NULL)
    twist_timer_cancel (m->timer);
  if (m->retry != NULL)
    twist_timer_cancel (m->retry);
  twist_h3_free (m->h3);
  twist_connection_free (m->outer);
  for (i = 0; i < m->n_held; i++)
    free (m->held[i].data);
  free (m->authority);
  free (m->path);
  if (m->auth != NULL)
    {
      memset (m->auth, 0, strlen (m->auth));
      free (m->auth);
    }
  free (m);
}

/* The protocol let go of the inner connection.  The outer one may be in the
   middle of a call that led here, so it goes a moment later.  */
static void
inner_free (void *p)
{
  struct twist_masque *m = p;

  m->inner = NULL;
  m->state = M_DEAD;
  if (m->outer != NULL)
    {
      twist_connection_set_handler (m->outer, NULL);
      twist_quic_on_datagram (m->outer, NULL, NULL);
    }
  if (twist_loop_post (m->loop, masque_reap, m) != TWIST_OK)
    masque_reap (m);
}

static void
masque_fail (struct twist_masque *m, int err)
{
  struct twist_connection *inner = m->inner;

  if (m->state == M_DEAD)
    return;
  m->state = M_DEAD;
  if (m->timer != NULL)
    {
      twist_timer_cancel (m->timer);
      m->timer = NULL;
    }
  if (inner != NULL)
    twist_connection_fail (inner, err);
}

static void
refused (struct twist_masque *m, int status)
{
  char msg[128];

  snprintf (msg, sizeof msg, _("CONNECT-UDP tunnel failed, response %d"),
            status);
  twist_easy_set_error (m->easy, twist_strdup (msg));
  m->easy->proto_status = 56;
  masque_fail (m, TWIST_ERR_PROXY);
}

static void
on_timeout (void *p)
{
  struct twist_masque *m = p;
  char msg[128];

  m->timer = NULL;
  if (m->state != M_ASK)
    return;
  snprintf (msg, sizeof msg, _("timed out after %ld ms making the "
                               "connection"), m->easy->connect_timeout_ms);
  twist_easy_set_error (m->easy, twist_strdup (msg));
  masque_fail (m, TWIST_ERR_TIMEOUT);
}

/* ---- HTTP Datagrams ---- */

static size_t
put_varint (uint8_t *buf, uint64_t v)
{
  if (v < 64)
    {
      buf[0] = (uint8_t) v;
      return 1;
    }
  if (v < 16384)
    {
      buf[0] = (uint8_t) (0x40 | (v >> 8));
      buf[1] = (uint8_t) v;
      return 2;
    }
  buf[0] = (uint8_t) (0x80 | (v >> 24));
  buf[1] = (uint8_t) (v >> 16);
  buf[2] = (uint8_t) (v >> 8);
  buf[3] = (uint8_t) v;
  return 4;
}

static size_t
get_varint (const uint8_t *p, size_t len, uint64_t *out)
{
  size_t n;
  uint64_t v;
  size_t i;

  if (len == 0)
    return 0;
  n = (size_t) 1 << (p[0] >> 6);
  if (len < n)
    return 0;
  v = p[0] & 0x3fu;
  for (i = 1; i < n; i++)
    v = (v << 8) | p[i];
  *out = v;
  return n;
}

/* The HTTP Datagram for PAYLOAD (RFC 9297 section 2.1, RFC 9298 section 5):
   the quarter stream ID, context ID 0, the payload.  Returns its length, or 0
   if it does not fit in CAP.  */
size_t
twist_masque_wrap (uint64_t qsid, const uint8_t *payload, size_t len,
                   uint8_t *out, size_t cap)
{
  size_t n;

  if (cap < 4 || qsid >= ((uint64_t) 1 << 30))
    return 0;
  n = put_varint (out, qsid);
  if (n + 1 + len > cap)
    return 0;
  out[n++] = 0;
  memcpy (out + n, payload, len);
  return n + len;
}

/* The UDP payload of an HTTP Datagram if it is one of stream QSID's with
   context ID 0 (the only one there is, without extensions); else 0, and the
   datagram is to be dropped.  */
int
twist_masque_unwrap (uint64_t qsid, const uint8_t *data, size_t len,
                     const uint8_t **payload, size_t *plen)
{
  uint64_t q, ctx;
  size_t a, b;

  a = get_varint (data, len, &q);
  if (a == 0 || q != qsid)
    return 0;
  b = get_varint (data + a, len - a, &ctx);
  if (b == 0 || ctx != 0)
    return 0;
  *payload = data + a + b;
  *plen = len - a - b;
  return 1;
}

static size_t
wrap (const struct twist_masque *m, const uint8_t *payload, size_t len,
      uint8_t *out, size_t cap)
{
  return twist_masque_wrap (m->qsid, payload, len, out, cap);
}

/* From the proxy.  */
static void
datagram_in (void *user, const uint8_t *data, size_t len)
{
  struct twist_masque *m = user;
  const uint8_t *payload;
  size_t plen;

  if (m->state != M_UP || m->inner == NULL)
    return;
  if (twist_masque_unwrap (m->qsid, data, len, &payload, &plen))
    twist_quic_feed (m->inner, payload, plen);
}

static void
pump (struct twist_masque *m);

static void
retry_cb (void *user)
{
  struct twist_masque *m = user;

  m->retry = NULL;
  pump (m);
}

/* Send what is held, in order, until one does not fit.  */
static void
pump (struct twist_masque *m)
{
  size_t i = 0;

  if (m->state != M_UP || m->outer == NULL)
    return;
  while (i < m->n_held)
    {
      int rc = twist_quic_datagram_send (m->outer, m->held[i].data,
                                         m->held[i].len);

      if (rc == TWIST_ERR_AGAIN)
        break;
      free (m->held[i].data);
      i++;
    }
  if (i > 0)
    {
      memmove (m->held, m->held + i, (m->n_held - i) * sizeof m->held[0]);
      m->n_held -= i;
    }
  if (m->n_held > 0 && m->retry == NULL)
    twist_loop_schedule (m->loop, twist_loop_now (m->loop) + 10, retry_cb, m,
                         &m->retry);
}

/* From the inner connection.  Before the proxy has said yes, or when the
   outer path does not take a datagram this size yet, the datagram is held.  */
static int
carrier_send (void *user, const uint8_t *data, size_t len)
{
  struct twist_masque *m = user;
  uint8_t buf[2048];
  size_t n = wrap (m, data, len, buf, sizeof buf);

  if (n == 0 || m->state == M_DEAD)
    return TWIST_ERR_INVAL;
  if (m->state == M_UP && m->n_held == 0
      && twist_quic_datagram_send (m->outer, buf, n) != TWIST_ERR_AGAIN)
    return TWIST_OK;
  if (m->n_held >= HOLD_MAX)
    return TWIST_ERR_AGAIN;
  m->held[m->n_held].data = twist_xmalloc (n);
  if (m->held[m->n_held].data == NULL)
    return TWIST_ERR_NOMEM;
  memcpy (m->held[m->n_held].data, buf, n);
  m->held[m->n_held].len = n;
  m->n_held++;
  if (m->state == M_UP && m->retry == NULL)
    twist_loop_schedule (m->loop, twist_loop_now (m->loop) + 10, retry_cb, m,
                         &m->retry);
  return TWIST_OK;
}

/* ---- the request stream ---- */

static void
h3_header (void *user, const char *name, size_t nn, const char *value,
           size_t vn)
{
  struct twist_masque *m = user;

  if (nn == 7 && memcmp (name, ":status", 7) == 0 && vn == 3)
    m->status = (value[0] - '0') * 100 + (value[1] - '0') * 10
                + (value[2] - '0');
}

static int
h3_switching (void *user)
{
  struct twist_masque *m = user;

  if (m->state != M_ASK)
    return 0;
  if (m->status < 200 || m->status >= 300)
    {
      refused (m, m->status);
      return 0;
    }
  if (twist_quic_datagram_max (m->outer) == 0)
    {
      twist_easy_set_error (m->easy,
                            twist_strdup (_("the proxy does not accept HTTP "
                                            "Datagrams, so it cannot do "
                                            "CONNECT-UDP")));
      masque_fail (m, TWIST_ERR_PROXY);
      return 0;
    }
  m->state = M_UP;
  if (m->timer != NULL)
    {
      twist_timer_cancel (m->timer);
      m->timer = NULL;
    }
  pump (m);
  return 0;
}

static void
h3_done (void *user)
{
  struct twist_masque *m = user;

  if (m->state == M_ASK && (m->status < 200 || m->status >= 300))
    refused (m, m->status);
  else
    masque_fail (m, TWIST_ERR_CLOSED);
}

static void
h3_failure (void *user, int err)
{
  masque_fail (user, err == TWIST_OK ? TWIST_ERR_PROTOCOL : err);
}

static void
outer_secure (struct twist_endpoint *ep, const char *alpn, size_t len)
{
  struct twist_masque *m = ep->user_data;
  struct twist_slist *extra;
  uint8_t *req = NULL;
  size_t req_n = 0;
  char line[1100];
  int rc;
  uint64_t id;

  (void) alpn;
  (void) len;
  if (m->state != M_ASK)
    return;
  id = twist_quic_stream_id (m->outer);
  if (id == UINT64_MAX)
    {
      masque_fail (m, TWIST_ERR_PROTOCOL);
      return;
    }
  m->qsid = id / 4;
  extra = twist_slist_append (NULL, ":protocol: connect-udp");
  extra = twist_slist_append (extra, "capsule-protocol: ?1");
  if (m->auth != NULL && extra != NULL)
    {
      snprintf (line, sizeof line, "proxy-authorization: Basic %s", m->auth);
      extra = twist_slist_append (extra, line);
      memset (line, 0, sizeof line);
    }
  if (extra == NULL)
    {
      masque_fail (m, TWIST_ERR_NOMEM);
      return;
    }
  twist_quic_hold_stream (m->outer);
  rc = twist_h3_request (m->h3, "CONNECT", "https", m->authority, m->path,
                         extra, NULL, 0, &req, &req_n);
  {
    struct twist_slist *x;

    for (x = extra; x != NULL; x = x->next)
      memset (x->data, 0, strlen (x->data));
  }
  twist_slist_free_all (extra);
  if (rc == TWIST_OK)
    rc = twist_endpoint_send (ep, req, req_n);
  free (req);
  if (rc != TWIST_OK)
    masque_fail (m, rc);
}

static size_t
outer_receive (struct twist_endpoint *ep, const uint8_t *data, size_t len)
{
  struct twist_masque *m = ep->user_data;

  if (m->state == M_DEAD)
    return len;
  return twist_h3_receive (m->h3, data, len);
}

static void
outer_finished (struct twist_endpoint *ep)
{
  struct twist_masque *m = ep->user_data;

  if (m->state != M_DEAD)
    h3_done (m);
}

static void
outer_disconnected (struct twist_endpoint *ep, int err)
{
  struct twist_masque *m = ep->user_data;

  if (m->state == M_DEAD)
    return;
  masque_fail (m, err == TWIST_OK ? TWIST_ERR_CLOSED : err);
}

static const struct twist_protocol_handler outer_handler = {
  NULL,
  outer_receive,
  outer_disconnected,
  outer_secure,
  NULL,
  outer_finished,
  NULL
};

/* The part of AUTHORITY..: "https://host:port/path?query" gives "host:port"
   and "/path?query".  */
static int
split_uri (const char *uri, char **authority, char **path)
{
  const char *a = uri + 8;
  size_t al = strcspn (a, "/?");
  const char *rest = a + al;

  *authority = twist_xmalloc (al + 1);
  if (*authority == NULL)
    return TWIST_ERR_NOMEM;
  memcpy (*authority, a, al);
  (*authority)[al] = 0;
  if (*rest == '/')
    *path = twist_strdup (rest);
  else if (*rest == '?')
    {
      *path = twist_xmalloc (strlen (rest) + 2);
      if (*path != NULL)
        {
          (*path)[0] = '/';
          strcpy (*path + 1, rest);
        }
    }
  else
    *path = twist_strdup ("/");
  if (*path == NULL)
    {
      free (*authority);
      *authority = NULL;
      return TWIST_ERR_NOMEM;
    }
  return TWIST_OK;
}

int
twist_masque_connect (struct twist_easy *easy,
                      const struct twist_masque_spec *spec,
                      const struct twist_dns_addr *proxy_addr,
                      const struct twist_protocol_handler *handler,
                      void *user, struct twist_connection **out)
{
  struct twist_masque *m;
  struct twist_quic_opts oo, io;
  char *tmpl = NULL;
  char *uri = NULL;
  char *split = NULL;
  const char *u = spec->user;
  const char *pw = spec->pass;
  char err[200];
  int rc;

  *out = NULL;
  if (spec->tmpl != NULL)
    tmpl = twist_strdup (spec->tmpl);
  else
    {
      rc = twist_template_default (spec->proxy_host, spec->proxy_port, &tmpl);
      if (rc != TWIST_OK)
        return rc;
    }
  if (tmpl == NULL)
    return TWIST_ERR_NOMEM;
  if (twist_template_check (tmpl, err, sizeof err) != TWIST_OK)
    {
      twist_easy_set_error (easy, twist_strdup (err));
      free (tmpl);
      return TWIST_ERR_URL;
    }
  rc = twist_template_expand (tmpl, spec->host, spec->port, &uri);
  free (tmpl);
  if (rc != TWIST_OK)
    return rc;
  m = calloc (1, sizeof *m);
  if (m == NULL)
    {
      free (uri);
      return TWIST_ERR_NOMEM;
    }
  m->easy = easy;
  m->loop = easy->loop;
  rc = split_uri (uri, &m->authority, &m->path);
  free (uri);
  if (rc != TWIST_OK)
    {
      free (m);
      return rc;
    }
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
    {
      char cred[600];
      int n = snprintf (cred, sizeof cred, "%s:%s", u, pw != NULL ? pw : "");

      if (n > 0 && (size_t) n < sizeof cred)
        twist_b64_encode ((const uint8_t *) cred, (size_t) n, &m->auth);
      memset (cred, 0, sizeof cred);
    }
  free (split);
  {
    struct twist_h1_events ev;

    memset (&ev, 0, sizeof ev);
    ev.user = m;
    ev.header = h3_header;
    ev.switching = h3_switching;
    ev.message_done = h3_done;
    ev.failure = h3_failure;
    m->h3 = twist_h3_new (&ev);
  }
  if (m->h3 == NULL || (u != NULL && m->auth == NULL))
    {
      masque_reap (m);
      return TWIST_ERR_NOMEM;
    }
  m->state = M_ASK;
  /* To the proxy: QUIC with datagrams.  */
  memset (&oo, 0, sizeof oo);
  oo.datagrams = 1;
  rc = twist_quic_dial (easy->loop, spec->proxy_host, "h3", proxy_addr,
                        spec->proxy_port,
                        easy->proxy_cainfo != NULL ? easy->proxy_cainfo
                        : easy->cainfo,
                        easy->proxy_cainfo != NULL ? NULL : easy->capath, NULL,
                        NULL, easy->proxy_verifypeer, &oo, &m->outer);
  if (rc != TWIST_OK)
    {
      m->outer = NULL;
      masque_reap (m);
      return rc;
    }
  twist_connection_endpoint (m->outer)->user_data = m;
  twist_connection_set_handler (m->outer, &outer_handler);
  twist_quic_on_datagram (m->outer, datagram_in, m);
  /* To the target: QUIC whose packets are ours.  The address is of no use, the
     proxy looks the name up.  */
  memset (&io, 0, sizeof io);
  io.send = carrier_send;
  io.send_user = m;
  {
    struct twist_dns_addr none;

    memset (&none, 0, sizeof none);
    none.family = 4;
    rc = twist_quic_dial (easy->loop, spec->host, "h3", &none, spec->port,
                          easy->cainfo, easy->capath, easy->sslcert,
                          easy->sslkey, easy->verifypeer, &io, &m->inner);
  }
  if (rc != TWIST_OK)
    {
      m->inner = NULL;
      masque_reap (m);
      return rc;
    }
  twist_connection_set_owner (m->inner, m, inner_free, NULL);
  twist_connection_endpoint (m->inner)->user_data = user;
  twist_connection_set_handler (m->inner, handler);
  if (easy->connect_timeout_ms > 0)
    twist_loop_schedule (easy->loop,
                         twist_loop_now (easy->loop)
                         + (uint64_t) easy->connect_timeout_ms,
                         on_timeout, m, &m->timer);
  *out = m->inner;
  return TWIST_OK;
}
