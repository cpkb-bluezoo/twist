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

#include <foxtrot/agent.h>
#include <foxtrot/status.h>

#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>

/* An ssh-agent, as a client.  The agent holds private keys and signs with
   them; twist never sees them.  foxtrot has the protocol (agent.h): the
   framing, and the requests and replies, with no I/O.  This is the I/O: a
   Unix socket, an endpoint on the loop like any other, so nothing blocks.

   The session needs the list of keys when it is made, so the identities are
   asked for as the transfer starts, alongside the loading of the files, and
   the session starts when both have come.  The agent is optional in every
   way.  Whatever goes wrong with it, no socket, no answer, nonsense, a
   refusal, the transfer goes on with the other keys and the password; it
   only leaves a note, which is said if authentication then fails.

   Replies come in the order of the requests, so a first-in first-out record
   of what was asked says what each reply answers.  The requests that are
   made are the list of identities, signatures, and the session-bind that
   tells the agent which server this is.  Nothing else: twist does not add,
   remove or lock keys.  */

#define AGENT_QUEUE 8
#define AGENT_IDENTITIES_MS 10000u

enum agent_req
{
  REQ_IDENTITIES = 1,
  REQ_SIGN,
  REQ_BIND
};

struct ssh_agent
{
  struct twist_ssh *ssh;
  struct twist_connection *conn;
  struct twist_endpoint *ep;
  gf_agent_reader *reader;
  struct twist_timer *timer;	/* The wait for the identities.  */
  int connected;
  int dead;			/* Failed, or closed: no more requests.  */
  int closed;			/* The connection has ended.  */
  int identities_done;
  enum agent_req queue[AGENT_QUEUE];
  size_t nq;
};

static void
set_note (struct twist_ssh *s, const char *text)
{
  if (s->agent_note[0] == 0)
    snprintf (s->agent_note, sizeof s->agent_note, "%s", text);
}

/* The agent is of no more use.  What waits for it goes on without.  */
static void
agent_fail (struct ssh_agent *a, const char *why)
{
  struct twist_ssh *s = a->ssh;
  int waiting = !a->identities_done;
  int signing = 0;
  size_t i;

  if (a->dead)
    return;
  a->dead = 1;
  set_note (s, why);
  if (a->timer != NULL)
    {
      twist_timer_cancel (a->timer);
      a->timer = NULL;
    }
  for (i = 0; i < a->nq; i++)
    if (a->queue[i] == REQ_SIGN)
      signing = 1;
  a->nq = 0;
  a->identities_done = 1;
  s->agent_wait = 0;
  if (a->ep != NULL && !a->closed)
    twist_endpoint_close (a->ep);
  if (waiting)
    twist_ssh_maybe_begin (s);
  if (signing)
    twist_ssh_sign_failed (s);
}

static int
send_request (struct ssh_agent *a, const uint8_t *frame, size_t len,
              enum agent_req kind)
{
  if (a->dead || !a->connected || a->ep == NULL || a->nq >= AGENT_QUEUE)
    return -1;
  if (twist_endpoint_send (a->ep, frame, len) != TWIST_OK)
    return -1;
  a->queue[a->nq++] = kind;
  return 0;
}

/* ---- the identities ---- */

/* One key the agent holds.  The key is valid only during the call, so keep
   a copy, made from its blob.  */
static int
identity (void *user, const gf_key *key, gf_slice comment)
{
  struct ssh_agent *a = user;
  struct twist_ssh *s = a->ssh;
  const uint8_t *blob;
  size_t blen;
  gf_key *copy = NULL;

  (void) comment;
  blob = gf_key_blob (key, &blen);
  if (blob == NULL || gf_key_from_blob (&copy, blob, blen) != GF_OK)
    return 0;
  if (s->nakeys == s->cap_akeys)
    {
      size_t cap = s->cap_akeys == 0 ? 8 : s->cap_akeys * 2;
      gf_key **grown = realloc (s->akeys, cap * sizeof *grown);

      if (grown == NULL)
        {
          gf_key_free (copy);
          return 1;
        }
      s->akeys = grown;
      s->cap_akeys = cap;
    }
  s->akeys[s->nakeys++] = copy;
  return 0;
}

static void
got_identities (struct ssh_agent *a, const uint8_t *payload, size_t len)
{
  struct twist_ssh *s = a->ssh;
  enum gf_agent_type type = gf_agent_type (payload, len);

  if (a->timer != NULL)
    {
      twist_timer_cancel (a->timer);
      a->timer = NULL;
    }
  if (type == GF_AGENT_IDENTITIES_ANSWER)
    {
      size_t skipped = 0;

      if (gf_agent_identities (payload, len, identity, a, &skipped) != GF_OK)
        set_note (s, _("its list of keys was not understood"));
    }
  else if (type == GF_AGENT_FAILURE)
    set_note (s, _("the agent would not list its keys"));
  else
    set_note (s, _("an answer that is not a list of keys"));
  a->identities_done = 1;
  s->agent_wait = 0;
  twist_ssh_maybe_begin (s);
}

static void
identities_timeout (void *user)
{
  struct ssh_agent *a = user;

  a->timer = NULL;
  agent_fail (a, _("the agent did not answer"));
}

/* ---- the answers ---- */

static int
frame (void *user, const uint8_t *payload, size_t len)
{
  struct ssh_agent *a = user;
  enum agent_req kind;
  gf_slice sig;

  if (a->nq == 0)
    {
      agent_fail (a, _("an answer to nothing that was asked"));
      return 1;
    }
  kind = a->queue[0];
  a->nq--;
  memmove (a->queue, a->queue + 1, a->nq * sizeof a->queue[0]);
  switch (kind)
    {
    case REQ_IDENTITIES:
      got_identities (a, payload, len);
      break;
    case REQ_SIGN:
      if (gf_agent_type (payload, len) == GF_AGENT_SIGN_RESPONSE
          && gf_agent_sign_response (payload, len, &sig) == GF_OK)
        twist_ssh_sign_answer (a->ssh, sig.data, sig.len);
      else
        {
          set_note (a->ssh, _("the agent refused to sign"));
          twist_ssh_sign_failed (a->ssh);
        }
      break;
    case REQ_BIND:
      /* SUCCESS, or FAILURE from an agent that does not know it, which is
         not an error: OpenSSH ignores it as well.  */
      break;
    }
  return a->dead;
}

static size_t
agent_receive (struct twist_endpoint *ep, const uint8_t *data, size_t len)
{
  struct ssh_agent *a = ep->user_data;

  if (a == NULL || a->dead)
    return len;
  if (gf_agent_reader_feed (a->reader, data, len, frame, a) != GF_OK)
    agent_fail (a, _("the agent sent something that is not the protocol"));
  return len;
}

static void
agent_connected (struct twist_endpoint *ep)
{
  struct ssh_agent *a = ep->user_data;
  struct twist_ssh *s = a->ssh;
  uint8_t req[16];
  size_t n = 0;
  unsigned ms = s->agent_timeout_ms != 0 ? s->agent_timeout_ms
                                         : AGENT_IDENTITIES_MS;

  a->ep = ep;
  a->connected = 1;
  if (gf_agent_request_identities (req, sizeof req, &n) != GF_OK
      || send_request (a, req, n, REQ_IDENTITIES) != 0)
    {
      agent_fail (a, _("cannot write to the agent"));
      return;
    }
  twist_loop_schedule (s->easy->loop, twist_loop_now (s->easy->loop) + ms,
                       identities_timeout, a, &a->timer);
}

static void
agent_disconnected (struct twist_endpoint *ep, int error)
{
  struct ssh_agent *a = ep->user_data;

  (void) error;
  if (a == NULL)
    return;
  a->closed = 1;
  agent_fail (a, _("the agent closed the connection"));
}

static void
agent_error (struct twist_endpoint *ep, int error)
{
  struct ssh_agent *a = ep->user_data;

  if (a == NULL || error == TWIST_OK)
    return;
  a->closed = 1;
  agent_fail (a, _("the connection to the agent failed"));
}

static const struct twist_protocol_handler agent_handler = {
  agent_connected,
  agent_receive,
  agent_disconnected,
  NULL,
  agent_error,
  NULL,
  NULL
};

/* ---- the transfer's side ---- */

void
twist_ssh_agent_start (struct twist_ssh *s)
{
  struct twist_easy *e = s->easy;
  struct sockaddr_un sa;
  struct ssh_agent *a;
  const char *path;
  char note[sizeof s->agent_note];
  int rc, err;

  /* A key named by the user is used alone.  Without a loop there is nothing
     to run a socket on.  */
  if (e->loop == NULL || e->sslkey != NULL)
    return;
  path = e->ssh_agent_socket != NULL ? e->ssh_agent_socket
                                     : getenv ("SSH_AUTH_SOCK");
  if (path == NULL || path[0] == 0)
    return;
  if (strlen (path) >= sizeof sa.sun_path)
    {
      snprintf (note, sizeof note,
                _("the socket path is too long (a Unix socket's is at most "
                  "%zu characters)"), sizeof sa.sun_path - 1);
      set_note (s, note);
      return;
    }
  a = calloc (1, sizeof *a);
  if (a == NULL)
    return;
  a->ssh = s;
  if (gf_agent_reader_new (&a->reader) != GF_OK)
    {
      free (a);
      return;
    }
  a->conn = twist_connection_new (e->loop);
  if (a->conn == NULL)
    {
      gf_agent_reader_free (a->reader);
      free (a);
      return;
    }
  s->agent = a;
  a->ep = twist_connection_endpoint (a->conn);
  a->ep->user_data = a;
  twist_connection_set_handler (a->conn, &agent_handler);
  memset (&sa, 0, sizeof sa);
  sa.sun_family = AF_UNIX;
  memcpy (sa.sun_path, path, strlen (path) + 1);
  /* Set before the connect: a Unix socket is connected at once, and the
     handler runs inside it.  */
  s->agent_wait = 1;
  errno = 0;
  rc = twist_connection_connect (a->conn, &sa,
                                 offsetof (struct sockaddr_un, sun_path)
                                 + strlen (path) + 1, 0);
  err = errno;
  if (rc != TWIST_OK)
    {
      snprintf (note, sizeof note, _("cannot connect to %s (%s)"), path,
                err != 0 ? strerror (err) : _("failed"));
      a->identities_done = 1;
      s->agent_wait = 0;
      set_note (s, note);
      /* Nothing was started that could call back.  */
    }
}

void
twist_ssh_agent_free (struct twist_ssh *s)
{
  struct ssh_agent *a = s->agent;

  if (a == NULL)
    return;
  s->agent = NULL;
  if (a->timer != NULL)
    twist_timer_cancel (a->timer);
  if (a->conn != NULL)
    {
      struct twist_endpoint *ep = twist_connection_endpoint (a->conn);

      if (ep != NULL)
        ep->user_data = NULL;
      twist_connection_set_handler (a->conn, NULL);
      twist_connection_free (a->conn);
    }
  gf_agent_reader_free (a->reader);
  free (a);
}

int
twist_ssh_agent_sign (struct twist_ssh *s, const gf_key *key,
                      enum gf_sigalg alg, gf_slice data)
{
  struct ssh_agent *a = s->agent;
  size_t blen, n = 0, need;
  uint8_t *req;
  int rc;

  if (a == NULL || a->dead || !a->connected)
    return 1;
  if (gf_key_blob (key, &blen) == NULL)
    return 1;
  need = GF_AGENT_SIGN_OVERHEAD + blen + data.len;
  req = malloc (need);
  if (req == NULL)
    return 1;
  rc = gf_agent_sign_request (key, alg, data.data, data.len, req, need, &n);
  if (rc == GF_OK)
    rc = send_request (a, req, n, REQ_SIGN);
  free (req);
  return rc == GF_OK ? 0 : 1;
}

void
twist_ssh_agent_bind (struct twist_ssh *s, const gf_conn_info *info)
{
  struct ssh_agent *a = s->agent;
  gf_slice session, sig;
  size_t blen, n = 0, need;
  uint8_t *req;

  /* Only an agent that holds something has any use for it.  */
  if (a == NULL || a->dead || !a->connected || s->nakeys == 0 || info == NULL
      || info->host_key == NULL || info->host_sig == NULL
      || info->session_id == NULL)
    return;
  if (gf_key_blob (info->host_key, &blen) == NULL)
    return;
  session.data = info->session_id;
  session.len = info->session_id_len;
  sig.data = info->host_sig;
  sig.len = info->host_sig_len;
  need = GF_AGENT_BIND_OVERHEAD + blen + session.len + sig.len;
  req = malloc (need);
  if (req == NULL)
    return;
  if (gf_agent_session_bind (info->host_key, session, sig, req, need, &n)
      == GF_OK)
    send_request (a, req, n, REQ_BIND);
  free (req);
}
