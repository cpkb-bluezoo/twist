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
static void ssh_after (struct twist_ssh *s, int rc);
static const char *ssh_user_name (const struct twist_transfer *transfer);
static const char *ssh_password (const struct twist_transfer *transfer);
static const struct twist_protocol_handler ssh_handler;

uint64_t
twist_ssh_now_us (const struct twist_ssh *s)
{
  if (s->transfer->loop != NULL)
    return twist_loop_now (s->transfer->loop) * 1000u;
  return s->clock_us;
}

void
twist_ssh_detail (struct twist_ssh *s, const char *detail)
{
  if (twist_transfer_error (s->transfer) != NULL)
    return;
  twist_transfer_set_error (s->transfer, twist_strdup (detail));
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
  twist_transfer_finish (s->transfer, err);
}

/* ---- keeping the session for the next URL ----

   A transfer that ends well leaves a session that is logged in, with an SFTP
   channel open and nothing in it.  Logging in is most of the cost of a
   transfer, so the session is parked in the pool, and the next URL for the
   same host, user and terms takes it.  The terms are what the session was
   made under: a session that was allowed in with another password, or
   without checking the host key, is not one that this URL's options would
   have produced.  So the key holds a hash of every option that decides who
   we are or whom we trust.  */

static void
terms_add (uint8_t **buf, size_t *len, size_t *cap, const char *s)
{
  size_t n = s != NULL ? strlen (s) + 1 : 0;

  if (*len + n + 8 > *cap)
    {
      size_t want = (*cap + n + 8) * 2;
      uint8_t *grown = realloc (*buf, want);

      if (grown == NULL)
        {
          *len = (size_t) -1;
          return;
        }
      *buf = grown;
      *cap = want;
    }
  /* A length and a byte for presence, so that fields cannot run together and
     an empty string is not an absent one.  */
  (*buf)[(*len)++] = s != NULL;
  (*buf)[(*len)++] = (uint8_t) (n >> 24);
  (*buf)[(*len)++] = (uint8_t) (n >> 16);
  (*buf)[(*len)++] = (uint8_t) (n >> 8);
  (*buf)[(*len)++] = (uint8_t) n;
  if (n > 0)
    memcpy (*buf + *len, s, n);
  *len += n;
}

static int
ssh_pool_key (struct twist_transfer *e, char *key, size_t cap)
{
  uint8_t *buf = NULL, d[32];
  size_t len = 0, bcap = 0, i;
  char hex[65];
  const char *agent = e->ssh_agent_socket;
  int port;

  if (e->url == NULL || e->url->host == NULL || e->loop == NULL)
    return TWIST_ERR_INVAL;
  if (agent == NULL)
    agent = twist_getenv_secure ("SSH_AUTH_SOCK");
  terms_add (&buf, &len, &bcap, ssh_password (e));
  terms_add (&buf, &len, &bcap, e->sslkey);
  terms_add (&buf, &len, &bcap, e->keypasswd);
  terms_add (&buf, &len, &bcap, e->ssh_knownhosts);
  terms_add (&buf, &len, &bcap, e->ssh_hostpubsha256);
  terms_add (&buf, &len, &bcap, agent);
  terms_add (&buf, &len, &bcap, e->verifypeer ? "verify" : "no-verify");
  /* A tunnel through one proxy is not one through another, or through the
     same with other credentials: the proxy is part of who the server sees
     and what let us in.  */
  terms_add (&buf, &len, &bcap, twist_transfer_proxy (e));
  terms_add (&buf, &len, &bcap, e->proxy_userpwd);
  if (len == (size_t) -1 || twist_sha256 (buf, len, d) != TWIST_OK)
    {
      free (buf);
      return TWIST_ERR_NOMEM;
    }
  if (buf != NULL)
    memset (buf, 0, len);
  free (buf);
  for (i = 0; i < 32; i++)
    snprintf (hex + 2 * i, 3, "%02x", d[i]);
  port = e->url->port > 0 ? e->url->port : twist_url_default_port ("sftp");
  return snprintf (key, cap, "ssh|%p|%s|%d|%s|%s", (void *) e->loop,
                   e->url->host, port, ssh_user_name (e), hex) < (int) cap
         ? TWIST_OK : TWIST_ERR_NOMEM;
}

/* Keep the session, if it can be kept.  It can when it is logged in on a
   connection of its own, the channel has nothing in it, and there is a pool
   to keep it in.  On success the pool has it, and the transfer is no longer
   its owner.  */
/* A parked session that is dropped says so to the server, as ssh does when it
   is closed, before its connection goes: the pool calls this with the
   connection still open.  The transfer that parked it has gone, so nothing
   the session reports now is a result.  */
static void
ssh_farewell (void *payload, struct twist_connection *conn)
{
  struct twist_ssh *s = payload;

  if (s->session == NULL || s->ending
      || gf_session_phase (s->session) == GF_PHASE_CLOSED)
    return;
  s->ending = 1;
  s->ep = twist_connection_endpoint (conn);
  /* The clock is the loop's, not the transfer's, which may be gone.  */
  gf_session_disconnect (s->session,
                         twist_loop_now (twist_endpoint_loop (s->ep)) * 1000u,
                         GF_DISCONNECT_BY_APPLICATION, "done");
  s->ep = NULL;
}

static int
ssh_park (struct twist_ssh *s)
{
  struct twist_transfer *e = s->transfer;
  struct twist_pool *pool;
  struct twist_connection *conn;
  char key[1024];

  if (s->sink != NULL || s->ep == NULL || s->link.conn == NULL
      || s->ending || s->session == NULL
      || gf_session_phase (s->session) != GF_PHASE_READY
      || !twist_sftp_idle (s->sftp))
    return 0;
  pool = twist_transfer_pool (e);
  if (pool == NULL || ssh_pool_key (e, key, sizeof key) != TWIST_OK)
    return 0;
  conn = twist_mail_link_detach (&s->link);
  if (twist_pool_put_payload (pool, key, conn, s, twist_ssh_free) != TWIST_OK)
    {
      s->link.conn = conn;
      return 0;
    }
  twist_pool_set_farewell (pool, conn, ssh_farewell);
  /* The pool has the session.  The agent was for logging in.  */
  twist_sftp_recycle (s->sftp);
  twist_ssh_agent_free (s);
  s->ep = NULL;
  e->state = NULL;
  e->state_free = NULL;
  return 1;
}

static void
ssh_end (struct twist_ssh *s, int err)
{
  if (err == TWIST_OK && ssh_park (s))
    {
      ssh_complete (s, err);
      return;
    }
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
  if (s->finished || s->session == NULL || s->transfer->loop == NULL)
    return;
  us = gf_session_timeout (s->session);
  if (us == UINT64_MAX)
    return;
  ms = us / 1000u + (us % 1000u != 0);
  twist_loop_schedule (s->transfer->loop, ms, ssh_on_timer, s, &s->timer);
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
ssh_user_name (const struct twist_transfer *transfer)
{
  if (transfer->username != NULL && transfer->username[0] != 0)
    return transfer->username;
  if (transfer->url->user != NULL)
    return transfer->url->user;
  return "";
}

static const char *
ssh_password (const struct twist_transfer *transfer)
{
  if (transfer->password != NULL && transfer->password[0] != 0)
    return transfer->password;
  if (transfer->url->password != NULL && transfer->url->password[0] != 0)
    return transfer->url->password;
  return NULL;
}

size_t
twist_ssh_sanitize (uint8_t *out, const uint8_t *in, size_t n)
{
  size_t i = 0, o = 0;

  while (i < n)
    {
      uint8_t c = in[i];

      if (c < 0x20 || c == 0x7f)
        {
          out[o++] = '?';
          i++;
        }
      else if (c == 0xc2 && i + 1 < n && in[i + 1] >= 0x80 && in[i + 1] <= 0x9f)
        {
          out[o++] = '?';
          i += 2;
        }
      else
        {
          out[o++] = c;
          i++;
        }
    }
  return o;
}

/* Keyboard-interactive: the server asks questions, and twist has a password.
   It answers one question that is not shown as it is typed with the
   password.  Anything else gets empty answers, so that the
   password is not given to a question that might not be asking for it: a
   code, a second question, a name.  Then the method fails, and the others
   are tried.  The count of answers has to be the count of questions, and a
   nonzero return would end the session, so there is always an answer.  */
static void
kbdint_note (struct twist_ssh *s, size_t nprompts, const gf_slice *prompts)
{
  char note[sizeof s->kbdint_note];

  if (s->kbdint_note[0] != 0)
    return;
  if (nprompts != 1)
    {
      snprintf (note, sizeof note,
                _("the server asked more than one question, and twist can "
                  "answer only a password"));
    }
  else
    {
      uint8_t clean[128];
      size_t n = prompts[0].len > 60 ? 60 : prompts[0].len, m;

      /* Not in the middle of a UTF-8 character.  */
      while (n > 0 && n < prompts[0].len && (prompts[0].data[n] & 0xc0) == 0x80)
        n--;
      m = twist_ssh_sanitize (clean, prompts[0].data, n);
      while (m > 0 && (clean[m - 1] == ' ' || clean[m - 1] == ':'))
        m--;
      clean[m] = 0;
      snprintf (note, sizeof note,
                _("the server asked \"%s\", which is not a password"),
                (const char *) clean);
    }
  snprintf (s->kbdint_note, sizeof s->kbdint_note, "%s", note);
}

static int
ssh_auth_kbdint (void *user, gf_slice name, gf_slice instruction,
                 size_t nprompts, const gf_slice *prompts, const int *echo)
{
  struct twist_ssh *s = user;
  const char *answers[GF_AUTH_MAX_PROMPTS];
  size_t i;

  (void) name;
  (void) instruction;
  for (i = 0; i < nprompts && i < GF_AUTH_MAX_PROMPTS; i++)
    answers[i] = "";
  if (nprompts == 1 && !echo[0] && s->password != NULL)
    answers[0] = s->password;
  else
    kbdint_note (s, nprompts, prompts);
  gf_session_auth_kbdint_respond (s->session, nprompts, answers);
  return 0;
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

void
twist_ssh_enter (struct twist_ssh *s)
{
  s->depth++;
}

void
twist_ssh_leave (struct twist_ssh *s)
{
  s->depth--;
  ssh_after (s, GF_OK);
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
  /* The key exchange has the time allowed for connecting, not foxtrot's 60
     seconds; the time to be connected in is the user's to set.  */
  if (s->transfer->connect_timeout_ms > 0)
    s->config.conn.kex_timeout_us = (uint64_t) s->transfer->connect_timeout_ms * 1000u;
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
       does for ssh.  */
  }
  s->config.client_auth.password = s->password;
  s->events.user = s;
  s->events.write = ssh_write;
  s->events.host_key = twist_ssh_host_key;
  s->events.established = ssh_established;
  s->events.auth_sign = ssh_auth_sign;
  /* With no password there is nothing to answer a question with, so the
     method is not tried.  */
  if (s->password != NULL)
    s->events.auth_kbdint = ssh_auth_kbdint;
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
                     : s->transfer->result != TWIST_OK ? s->transfer->result
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
twist_ssh_new (struct twist_transfer *transfer, int live)
{
  struct twist_ssh *s;
  const char *pw;

  (void) live;
  if (transfer == NULL || transfer->url == NULL)
    return NULL;
  s = calloc (1, sizeof *s);
  if (s == NULL)
    return NULL;
  s->transfer = transfer;
  s->user = twist_strdup (ssh_user_name (transfer));
  pw = ssh_password (transfer);
  if (pw != NULL)
    s->password = twist_strdup (pw);
  if (s->user == NULL || (pw != NULL && s->password == NULL))
    {
      free (s->user);
      free (s);
      return NULL;
    }
  transfer->state = s;
  transfer->state_free = twist_ssh_free;
  return s;
}

/* A session that an earlier transfer kept, for this one, if there is one
   that was made under the same terms.  It is taken whole, and goes straight
   to the file.  */
static struct twist_ssh *
ssh_resume (struct twist_transfer *transfer)
{
  struct twist_pool *pool = twist_transfer_pool (transfer);
  struct twist_connection *conn = NULL;
  struct twist_ssh *s = NULL;
  char key[1024];
  int rc;

  if (pool == NULL || ssh_pool_key (transfer, key, sizeof key) != TWIST_OK)
    return NULL;
  if (twist_pool_take_payload (pool, key, &conn, (void **) &s) != TWIST_OK
      || conn == NULL || s == NULL)
    return NULL;
  s->transfer = transfer;
  transfer->state = s;
  transfer->state_free = twist_ssh_free;
  s->finished = s->ending = s->pending_err = 0;
  s->depth = s->end_pending = s->end_err = 0;
  s->read_paused = 0;
  s->ep = twist_connection_endpoint (conn);
  twist_mail_link_attach (&s->link, transfer, conn);
  /* Back in the session as a callback is: what it asks of the session is
     done when it is back.  */
  s->depth++;
  rc = twist_sftp_next (s);
  if (rc != TWIST_OK)
    twist_ssh_finish (s, rc);
  s->depth--;
  ssh_after (s, GF_OK);
  return s;
}

int
twist_ssh_attach (struct twist_transfer *transfer)
{
  struct twist_ssh *s;
  int rc;

  if (ssh_resume (transfer) != NULL)
    return transfer->done ? transfer->result : TWIST_OK;
  s = twist_ssh_new (transfer, 1);
  if (s == NULL)
    return TWIST_ERR_NOMEM;
  rc = twist_mail_link_open (&s->link, transfer, &ssh_handler, s, ssh_fail);
  if (rc != TWIST_OK)
    ssh_complete (s, rc);
  else
    /* Connected, through a proxy if there is one, and logged in, in the time
       allowed for it.  */
    twist_mail_link_phase_begin (&s->link);
  return transfer->done ? transfer->result : TWIST_OK;
}
