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
#include "ssh/ssh-int.h"

#include <foxtrot/crypto.h>
#include <foxtrot/status.h>

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* scp and sftp: an SSH session from foxtrot on a TCP endpoint.  foxtrot
   does no I/O.  Bytes from the endpoint go to gf_session_receive, the
   session's write callback goes to the endpoint, and the session's one
   deadline is kept on a loop timer.  Once the user is authenticated the
   transfer is sftp.c's; scp:// is the same transfer over SFTP, as OpenSSH's
   own scp has been since 9.0.  */

static void ssh_complete (struct twist_ssh *s, int err);
static void ssh_arm (struct twist_ssh *s);

uint64_t
twist_ssh_now_us (const struct twist_ssh *s)
{
  if (s->easy->loop != NULL)
    return twist_loop_now (s->easy->loop) * 1000u;
  return s->clock_us;
}

void
twist_ssh_detail (struct twist_ssh *s, const char *detail)
{
  if (twist_easy_error (s->easy) != NULL)
    return;
  twist_easy_set_error (s->easy, twist_strdup (detail));
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
  twist_ssh_detail (s, buf);
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
ssh_end (struct twist_ssh *s, int err)
{
  /* The disconnect raises the closed event, which must not decide the
     result.  */
  if (s->session != NULL && !s->ending
      && gf_session_phase (s->session) != GF_PHASE_CLOSED)
    {
      s->ending = 1;
      gf_session_disconnect (s->session, twist_ssh_now_us (s),
                             GF_DISCONNECT_BY_APPLICATION, "done");
    }
  ssh_complete (s, err);
}

void
twist_ssh_finish (struct twist_ssh *s, int err)
{
  if (s == NULL || twist_ssh_done (s))
    return;
  if (s->depth > 0)
    {
      s->end_pending = 1;
      s->end_err = err;
      return;
    }
  ssh_end (s, err);
}

/* Back from a call into the session: a finish asked for inside it, or the
   failure it reported, ends the transfer.  A finish asked for wins.  */
static void
ssh_after (struct twist_ssh *s, int rc)
{
  if (s->end_pending && !s->finished)
    {
      int err = s->end_err;

      s->end_pending = 0;
      ssh_end (s, err);
    }
  else if (rc != GF_OK)
    ssh_fail_status (s, rc);
  ssh_arm (s);
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

/* Nothing is left to try.  */
static int
ssh_auth_failed (void *user)
{
  struct twist_ssh *s = user;
  char buf[320];

  snprintf (buf, sizeof buf, "%s", _("permission denied: the server accepted "
                                     "none of the ways offered"));
  twist_ssh_auth_hint (s, buf, sizeof buf);
  twist_ssh_detail (s, buf);
  twist_ssh_finish (s, TWIST_ERR_AUTH);
  return 0;
}

static void
ssh_closed (void *user, int error, uint32_t reason, gf_slice text)
{
  struct twist_ssh *s = user;

  (void) reason;
  (void) text;
  if (twist_ssh_done (s) || s->ending)
    return;
  if (error != 0)
    ssh_fail_status (s, error);
  else
    ssh_complete (s, TWIST_ERR_CLOSED);
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

static const char *
ssh_password (const struct twist_easy *easy)
{
  if (easy->password != NULL && easy->password[0] != 0)
    return easy->password;
  if (easy->url->password != NULL && easy->url->password[0] != 0)
    return easy->url->password;
  return NULL;
}

/* The agent is asked to sign for a key it holds.  */
static int
ssh_auth_sign (void *user, const gf_key *key, enum gf_sigalg alg,
               gf_slice data)
{
  return twist_ssh_agent_sign (user, key, alg, data);
}

/* The key exchange is done and the host key is trusted: tell the agent
   which server this is, so that it will sign for keys restricted to it.  */
static int
ssh_established (void *user, const gf_conn_info *info)
{
  twist_ssh_agent_bind (user, info);
  return 0;
}

/* The agent's answer, or its failure, for the session.  They come from the
   loop and not from inside a call into the session, so the session may act
   on them and call back; see depth.  */
void
twist_ssh_sign_answer (struct twist_ssh *s, const uint8_t *sig, size_t len)
{
  int rc;

  if (s->session == NULL || twist_ssh_done (s))
    return;
  s->depth++;
  rc = gf_session_auth_sign_respond (s->session, sig, len);
  s->depth--;
  ssh_after (s, rc);
}

void
twist_ssh_sign_failed (struct twist_ssh *s)
{
  int rc;

  if (s->session == NULL || twist_ssh_done (s))
    return;
  s->depth++;
  rc = gf_session_auth_sign_fail (s->session);
  s->depth--;
  ssh_after (s, rc);
}

/* The files are loaded: make the session and start it.  */
int
twist_ssh_begin (struct twist_ssh *s)
{
  int rc;

  memset (&s->config, 0, sizeof s->config);
  memset (&s->events, 0, sizeof s->events);
  if (s->nalgs > 0)
    {
      s->config.conn.prefs.nsigalgs = s->nalgs;
      s->config.conn.prefs.sigalgs = s->algs;
    }
  s->config.conn.software = "twist_" TWIST_VERSION_STRING;
  s->config.client_auth.user = s->user;
  /* The agent's keys first, then those read from files.  */
  {
    size_t total = s->nakeys + s->nkeys, i;

    if (total > 0)
      {
        s->allkeys = calloc (total, sizeof *s->allkeys);
        if (s->allkeys == NULL)
          return TWIST_ERR_NOMEM;
        for (i = 0; i < s->nakeys; i++)
          s->allkeys[i] = s->akeys[i];
        for (i = 0; i < s->nkeys; i++)
          s->allkeys[s->nakeys + i] = s->keys[i];
      }
    s->config.client_auth.keys = s->allkeys;
    s->config.client_auth.nkeys = total;
    /* No limit of ours on how many keys are offered.  foxtrot counts an
       attempt only for a request that carries a signature or a password,
       not for asking whether the server would have a key, so a server that
       turns keys away does not use them up; its own limit decides, as it
       does for curl and ssh.  */
  }
  s->config.client_auth.password = s->password;
  s->events.user = s;
  s->events.write = ssh_write;
  s->events.host_key = twist_ssh_host_key;
  s->events.established = ssh_established;
  s->events.auth_sign = ssh_auth_sign;
  s->events.authenticated = twist_sftp_authenticated;
  s->events.auth_failed = ssh_auth_failed;
  s->events.channel_confirmed = twist_sftp_confirmed;
  s->events.channel_failed = twist_sftp_channel_failed;
  s->events.channel_request_reply = twist_sftp_request_reply;
  s->events.channel_closed = twist_sftp_channel_closed;
  s->events.closed = ssh_closed;
  rc = gf_session_client_new (&s->session, &s->config, &s->events);
  if (rc != GF_OK)
    return rc == GF_ERR_NOMEM ? TWIST_ERR_NOMEM : TWIST_ERR_UNSUPPORTED;
  s->depth++;
  rc = gf_session_start (s->session, twist_ssh_now_us (s));
  s->depth--;
  ssh_after (s, rc);
  /* What the server sent while the files were loading was not taken; the
     connection offers it again.  */
  if (s->read_paused && s->ep != NULL)
    {
      s->read_paused = 0;
      twist_endpoint_resume_read (s->ep);
    }
  return rc == GF_OK ? TWIST_OK
                     : s->easy->result != TWIST_OK ? s->easy->result
                                                   : TWIST_ERR_PROTOCOL;
}

void
twist_ssh_maybe_begin (struct twist_ssh *s)
{
  int rc;

  if (twist_ssh_done (s) || s->begun || !s->load_ready || s->agent_wait)
    return;
  s->begun = 1;
  rc = twist_ssh_begin (s);
  if (rc != TWIST_OK)
    twist_ssh_finish (s, rc);
}

/* Begin a transfer: check what can be checked, then load the files on the
   storage pool, and the loop goes on from there.  An error returned is for
   the caller to end the transfer with; once the job is submitted the
   transfer ends itself.  */
int
twist_ssh_start (struct twist_ssh *s)
{
  if (s == NULL || s->session != NULL || s->load != NULL)
    return TWIST_ERR_INVAL;
  if (gf_crypto_init () != GF_OK)
    {
      twist_ssh_detail (s, _("SSH needs libgcrypt 1.12.4 or later, and the "
                             "one in use is older or unusable"));
      return TWIST_ERR_UNSUPPORTED;
    }
  if (s->user[0] == 0)
    {
      twist_ssh_detail (s, _("no user name for SSH; give one in the URL or "
                             "with --user"));
      return TWIST_ERR_AUTH;
    }
  /* The agent is asked first, so that the files cannot finish ahead of the
     wish to wait for it.  */
  twist_ssh_agent_start (s);
  return twist_ssh_load_start (s);
}

size_t
twist_ssh_receive (struct twist_ssh *s, const uint8_t *data, size_t len)
{
  int rc;

  if (s == NULL || s->finished)
    return len;
  /* The files are still loading: the session does not exist, and it must
     see these bytes when it does.  Take none of them.  */
  if (s->session == NULL)
    return 0;
  s->depth++;
  rc = gf_session_receive (s->session, twist_ssh_now_us (s), data, len);
  s->depth--;
  ssh_after (s, rc);
  return len;
}

void
twist_ssh_timeout (struct twist_ssh *s)
{
  int rc;

  if (s == NULL || s->session == NULL || s->finished)
    return;
  s->depth++;
  rc = gf_session_on_timeout (s->session, twist_ssh_now_us (s));
  s->depth--;
  ssh_after (s, rc);
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
  size_t took;

  s->ep = ep;
  took = twist_ssh_receive (s, data, len);
  if (took == 0 && s->session == NULL && !s->finished && !s->read_paused)
    {
      /* Nothing to read it with yet: stop reading until there is.  */
      s->read_paused = 1;
      twist_endpoint_pause_read (ep);
    }
  return took;
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
  twist_ssh_load_abandon (s);
  twist_ssh_agent_free (s);
  /* The session owns the SFTP client, so it goes first.  */
  if (s->session != NULL)
    gf_session_free (s->session);
  twist_sftp_free (s->sftp);
  twist_ssh_keys_free (s);
  free (s->allkeys);
  gf_knownhosts_free (s->known);
  free (s->user);
  if (s->password != NULL)
    {
      memset (s->password, 0, strlen (s->password));
      free (s->password);
    }
  free (s);
}

struct twist_ssh *
twist_ssh_new (struct twist_easy *easy, int live)
{
  struct twist_ssh *s;
  const char *pw;

  (void) live;
  if (easy == NULL || easy->url == NULL)
    return NULL;
  s = calloc (1, sizeof *s);
  if (s == NULL)
    return NULL;
  s->easy = easy;
  s->user = twist_strdup (ssh_user_name (easy));
  pw = ssh_password (easy);
  if (pw != NULL)
    s->password = twist_strdup (pw);
  if (s->user == NULL || (pw != NULL && s->password == NULL))
    {
      free (s->user);
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
