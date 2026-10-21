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

#include <foxtrot/crypto.h>
#include <foxtrot/session.h>
#include <foxtrot/status.h>

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* scp and sftp: an SSH session from foxtrot on a TCP endpoint.  foxtrot
   does no I/O.  Bytes from the endpoint go to gf_session_receive, the
   session's write callback goes to the endpoint, and the session's one
   deadline is kept on a loop timer.

   Stage 1: connect and run the key exchange.  The host key is trusted
   only when peer verification is turned off, because known_hosts is not
   read yet.  When the exchange is complete the transfer ends with
   TWIST_ERR_UNSUPPORTED, since authentication and the transfers are not
   written yet.  */

struct twist_ssh
{
  struct twist_easy *easy;
  struct twist_mail_link link;
  struct twist_endpoint *ep;
  struct twist_timer *timer;
  gf_session *session;
  gf_session_config config;
  gf_session_events events;
  char *user;
  /* In-process driving: where output goes without an endpoint, and the
     clock when there is no loop.  */
  int (*sink) (void *user, const uint8_t *data, size_t len);
  void *sink_user;
  uint64_t clock_us;
  int kex_done;
  int ending;
  int finished;
  int pending_err;
};

static void ssh_complete (struct twist_ssh *s, int err);

static uint64_t
ssh_now_us (const struct twist_ssh *s)
{
  if (s->easy->loop != NULL)
    return twist_loop_now (s->easy->loop) * 1000u;
  return s->clock_us;
}

/* Replace the detail message of the transfer with TEXT unless a more
   specific one was already given.  */
static void
ssh_detail (struct twist_ssh *s, const char *text)
{
  if (twist_easy_error (s->easy) != NULL)
    return;
  twist_easy_set_error (s->easy, twist_strdup (text));
}

static int
ssh_map_status (int status)
{
  switch (status)
    {
    case GF_ERR_NOMEM:
      return TWIST_ERR_NOMEM;
    case GF_ERR_HOSTKEY:
      return TWIST_ERR_HOSTKEY;
    case GF_ERR_AUTH:
    case GF_ERR_PASSPHRASE:
      return TWIST_ERR_AUTH;
    case GF_ERR_TIMEOUT:
      return TWIST_ERR_TIMEOUT;
    case GF_ERR_CLOSED:
      return TWIST_ERR_CLOSED;
    default:
      return TWIST_ERR_PROTOCOL;
    }
}

/* Fail the transfer for a foxtrot status.  A more specific error that a
   callback recorded wins.  */
static void
ssh_fail_status (struct twist_ssh *s, int status)
{
  char buf[256];

  if (s->finished)
    return;
  snprintf (buf, sizeof buf, "SSH: %s", gf_strerror (status));
  ssh_detail (s, buf);
  ssh_complete (s, s->pending_err != TWIST_OK ? s->pending_err
                                              : ssh_map_status (status));
}

static void
ssh_complete (struct twist_ssh *s, int err)
{
  if (s == NULL || s->finished)
    return;
  s->finished = 1;
  if (s->timer != NULL)
    {
      twist_timer_cancel (s->timer);
      s->timer = NULL;
    }
  twist_easy_finish (s->easy, err);
}

static void
ssh_on_timer (void *user)
{
  struct twist_ssh *s = user;

  s->timer = NULL;
  twist_ssh_timeout (s);
}

/* Keep one loop timer at the session's deadline.  */
static void
ssh_arm (struct twist_ssh *s)
{
  uint64_t us, ms;

  if (s->timer != NULL)
    {
      twist_timer_cancel (s->timer);
      s->timer = NULL;
    }
  if (s->finished || s->session == NULL || s->easy->loop == NULL)
    return;
  us = gf_session_timeout (s->session);
  if (us == UINT64_MAX)
    return;
  ms = us / 1000u + (us % 1000u != 0);
  twist_loop_schedule (s->easy->loop, ms, ssh_on_timer, s, &s->timer);
}

/* Once the key exchange is done there is nothing more to do yet: say
   goodbye and report that the rest is not written.  Runs outside the
   session's callbacks, which must not disconnect.  */
static void
ssh_after (struct twist_ssh *s)
{
  const gf_conn_info *info;
  char buf[256];

  if (s->finished || !s->kex_done)
    return;
  info = gf_session_info (s->session);
  snprintf (buf, sizeof buf,
            _("SSH key exchange with %.*s completed; authentication is not "
              "implemented yet"),
            info != NULL ? (int) info->peer_software.len : 0,
            info != NULL ? (const char *) info->peer_software.data : "");
  ssh_detail (s, buf);
  /* The disconnect raises the closed event, which must not decide the
     result.  */
  s->ending = 1;
  gf_session_disconnect (s->session, ssh_now_us (s),
                         GF_DISCONNECT_BY_APPLICATION, "done");
  ssh_complete (s, TWIST_ERR_UNSUPPORTED);
}

static int
ssh_write (void *user, const uint8_t *data, size_t len)
{
  struct twist_ssh *s = user;

  if (s->sink != NULL)
    return s->sink (s->sink_user, data, len);
  if (s->ep == NULL)
    return -1;
  return twist_endpoint_send (s->ep, data, len) != TWIST_OK;
}

/* The server's host key.  known_hosts is not read yet, so the key is
   trusted only if the user turned verification off.  */
static int
ssh_host_key (void *user, const gf_key *key)
{
  struct twist_ssh *s = user;

  (void) key;
  if (!s->easy->verifypeer)
    return 0;
  s->pending_err = TWIST_ERR_HOSTKEY;
  ssh_detail (s, _("the host key cannot be checked yet (known_hosts is not "
                   "read); skip the check with -k"));
  return 1;
}

static int
ssh_established (void *user, const gf_conn_info *info)
{
  struct twist_ssh *s = user;

  (void) info;
  s->kex_done = 1;
  return 0;
}

static void
ssh_closed (void *user, int error, uint32_t reason, gf_slice text)
{
  struct twist_ssh *s = user;

  (void) reason;
  (void) text;
  if (s->finished || s->ending)
    return;
  if (error != 0)
    ssh_fail_status (s, error);
  else
    ssh_complete (s, TWIST_ERR_CLOSED);
}

int
twist_ssh_start (struct twist_ssh *s)
{
  int rc;

  if (s == NULL || s->session != NULL)
    return TWIST_ERR_INVAL;
  if (gf_crypto_init () != GF_OK)
    {
      ssh_detail (s, _("SSH needs libgcrypt 1.12.4 or later, and the one in "
                       "use is older or unusable"));
      return TWIST_ERR_UNSUPPORTED;
    }
  memset (&s->config, 0, sizeof s->config);
  memset (&s->events, 0, sizeof s->events);
  s->config.conn.software = "twist_" TWIST_VERSION_STRING;
  s->config.client_auth.user = s->user;
  s->events.user = s;
  s->events.write = ssh_write;
  s->events.host_key = ssh_host_key;
  s->events.established = ssh_established;
  s->events.closed = ssh_closed;
  rc = gf_session_client_new (&s->session, &s->config, &s->events);
  if (rc != GF_OK)
    return rc == GF_ERR_NOMEM ? TWIST_ERR_NOMEM : TWIST_ERR_UNSUPPORTED;
  rc = gf_session_start (s->session, ssh_now_us (s));
  if (rc != GF_OK)
    {
      ssh_fail_status (s, rc);
      return s->easy->result != TWIST_OK ? s->easy->result : TWIST_ERR_PROTOCOL;
    }
  ssh_arm (s);
  return TWIST_OK;
}

size_t
twist_ssh_receive (struct twist_ssh *s, const uint8_t *data, size_t len)
{
  int rc;

  if (s == NULL || s->session == NULL || s->finished)
    return len;
  rc = gf_session_receive (s->session, ssh_now_us (s), data, len);
  if (rc != GF_OK)
    ssh_fail_status (s, rc);
  ssh_after (s);
  ssh_arm (s);
  return len;
}

void
twist_ssh_timeout (struct twist_ssh *s)
{
  int rc;

  if (s == NULL || s->session == NULL || s->finished)
    return;
  rc = gf_session_on_timeout (s->session, ssh_now_us (s));
  if (rc != GF_OK)
    ssh_fail_status (s, rc);
  ssh_after (s);
  ssh_arm (s);
}

uint64_t
twist_ssh_deadline (const struct twist_ssh *s)
{
  if (s == NULL || s->session == NULL)
    return UINT64_MAX;
  return gf_session_timeout (s->session);
}

void
twist_ssh_set_sink (struct twist_ssh *s,
                    int (*sink) (void *user, const uint8_t *data, size_t len),
                    void *user)
{
  s->sink = sink;
  s->sink_user = user;
}

void
twist_ssh_set_time (struct twist_ssh *s, uint64_t now_us)
{
  s->clock_us = now_us;
}

/* ---- endpoint callbacks ---- */

static void
ssh_fail (void *user, int err)
{
  ssh_complete (user, err);
}

static void
ssh_connected (struct twist_endpoint *ep)
{
  struct twist_ssh *s = ep->user_data;
  int rc;

  s->ep = ep;
  rc = twist_ssh_start (s);
  if (rc != TWIST_OK)
    ssh_complete (s, rc);
}

static size_t
ssh_on_recv (struct twist_endpoint *ep, const uint8_t *data, size_t len)
{
  struct twist_ssh *s = ep->user_data;

  s->ep = ep;
  return twist_ssh_receive (s, data, len);
}

static void
ssh_secure (struct twist_endpoint *ep, const char *alpn, size_t alpn_len)
{
  (void) ep;
  (void) alpn;
  (void) alpn_len;
}

static void
ssh_disconnected (struct twist_endpoint *ep, int error)
{
  struct twist_ssh *s = ep->user_data;

  if (!s->finished)
    ssh_complete (s, error != TWIST_OK ? error : TWIST_ERR_CLOSED);
}

static void
ssh_error (struct twist_endpoint *ep, int error)
{
  struct twist_ssh *s = ep->user_data;

  if (!s->finished && error != TWIST_OK && error != TWIST_ERR_CLOSED)
    ssh_complete (s, error);
}

static const struct twist_protocol_handler ssh_handler = {
  ssh_connected,
  ssh_on_recv,
  ssh_disconnected,
  ssh_secure,
  ssh_error,
  NULL,
  NULL
};

void
twist_ssh_free (void *p)
{
  struct twist_ssh *s = p;

  if (s == NULL)
    return;
  if (s->timer != NULL)
    twist_timer_cancel (s->timer);
  twist_mail_link_close (&s->link);
  if (s->session != NULL)
    gf_session_free (s->session);
  free (s->user);
  free (s);
}

static const char *
ssh_user_name (const struct twist_easy *easy)
{
  if (easy->username != NULL && easy->username[0] != 0)
    return easy->username;
  if (easy->url->user != NULL)
    return easy->url->user;
  return "";
}

struct twist_ssh *
twist_ssh_new (struct twist_easy *easy, int live)
{
  struct twist_ssh *s;

  (void) live;
  if (easy == NULL || easy->url == NULL)
    return NULL;
  s = calloc (1, sizeof *s);
  if (s == NULL)
    return NULL;
  s->easy = easy;
  s->user = twist_strdup (ssh_user_name (easy));
  if (s->user == NULL)
    {
      free (s);
      return NULL;
    }
  easy->xfer = s;
  easy->xfer_free = twist_ssh_free;
  return s;
}

int
twist_ssh_attach (struct twist_easy *easy)
{
  struct twist_ssh *s;
  int rc;

  s = twist_ssh_new (easy, 1);
  if (s == NULL)
    return TWIST_ERR_NOMEM;
  rc = twist_mail_link_open (&s->link, easy, &ssh_handler, s, ssh_fail);
  if (rc != TWIST_OK)
    ssh_complete (s, rc);
  return easy->done ? easy->result : TWIST_OK;
}
