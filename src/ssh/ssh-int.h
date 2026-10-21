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

#ifndef TWIST_SSH_INT_H
#define TWIST_SSH_INT_H

#include "twist-int.h"

#include <foxtrot/knownhosts.h>
#include <foxtrot/session.h>

#include <pthread.h>

/* The parts of the scp and sftp handler:

     ssh.c      the session on the endpoint, its timer, the end of a transfer
     hostkey.c  known_hosts, a pinned fingerprint, and the client's keys
     sftp.c     the channel, the subsystem and the download

   One struct twist_ssh is the handler; the others hang from it.  */

#define SSH_MAX_KEYS 4
#define SSH_MAX_ALGS 16

struct twist_sftp_xfer;
struct twist_ssh_load;
struct ssh_agent;

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
  char *password;
  /* The keys that were read from files, which have a private part.  */
  gf_key *keys[SSH_MAX_KEYS];
  size_t nkeys;
  /* The keys the agent holds: public parts, signed for by the agent.  */
  gf_key **akeys;
  size_t nakeys, cap_akeys;
  /* All of them as the session takes them: the agent's first.  */
  const gf_key **allkeys;
  /* Default key files that were not offered because the library cannot
     decrypt them.  */
  unsigned keys_skipped;
  /* The session starts when the files are loaded and the agent has said
     what it holds (or was not asked, or failed); whichever is last starts it. */
  int load_ready;
  int agent_wait;
  int begun;
  struct ssh_agent *agent;
  char agent_note[240];
  char kbdint_note[240];
  unsigned agent_timeout_ms;	/* For the identities; 0: 10 seconds.  */
  gf_knownhosts *known;
  enum gf_sigalg algs[SSH_MAX_ALGS];
  struct twist_sftp_xfer *sftp;
  /* The files are read on the storage pool; while that is under way this is
     the job.  */
  struct twist_ssh_load *load;
  size_t nalgs;
  /* Where the job ran, for the tests.  */
  pthread_t load_thread;
  int load_thread_set;
  /* In-process driving: where output goes without an endpoint, and the
     clock when there is no loop.  */
  int (*sink) (void *user, const uint8_t *data, size_t len);
  void *sink_user;
  uint64_t clock_us;
  int ending;
  int finished;
  int pending_err;
  /* A finish asked for inside a call into the session is carried out when
     the call returns: the session must not be disconnected from its own
     callbacks, which may be inside the SFTP client.  */
  int depth;
  int end_pending;
  int end_err;
  /* Reading was paused because bytes came before the session existed.  */
  int read_paused;
};

/* The transfer is over or about to be.  */
static inline int
twist_ssh_done (const struct twist_ssh *s)
{
  return s->finished || s->end_pending;
}

/* ssh.c */
/* Copy IN to OUT with the control characters, and the UTF-8 form of the C1
   ones, made ?.  Anything the server sends that is shown, or written to the
   application's output, goes through this: it is not trusted with a terminal
   or with the line structure of the output.  OUT has room for N bytes.
   Returns how many were written.  */
size_t twist_ssh_sanitize (uint8_t *out, const uint8_t *in, size_t n);
/* Make the session from what the job loaded and start it.  */
int twist_ssh_begin (struct twist_ssh *s);
/* Start the session if everything it waits for has come, once.  An error
   ends the transfer.  */
void twist_ssh_maybe_begin (struct twist_ssh *s);
/* The agent's answer to a request to sign, for the session; or that it
   could not.  */
void twist_ssh_sign_answer (struct twist_ssh *s, const uint8_t *sig, size_t len);
void twist_ssh_sign_failed (struct twist_ssh *s);
uint64_t twist_ssh_now_us (const struct twist_ssh *s);
/* Keep DETAIL as the message of the transfer unless one is already set.  */
void twist_ssh_detail (struct twist_ssh *s, const char *detail);
/* Say goodbye and end the transfer with ERR.  */
void twist_ssh_finish (struct twist_ssh *s, int err);

/* hostkey.c: known_hosts, the client's keys and the host key callback of the
   session.  The files are read, and parsed, by a job on the storage pool
   that twist_ssh_load_start submits; when it is done the loop calls
   twist_ssh_begin, which makes the session.  An error that stops the job
   from starting is returned, and the caller ends the transfer; one that the
   job finds ends it itself.  */
int twist_ssh_load_start (struct twist_ssh *s);
/* The transfer is going away; the job, if any, finishes on its own.  */
void twist_ssh_load_abandon (struct twist_ssh *s);
int twist_ssh_host_key (void *user, const gf_key *key);
void twist_ssh_keys_free (struct twist_ssh *s);
/* Add what the failure of authentication leaves to say.  */
void twist_ssh_auth_hint (struct twist_ssh *s, char *buf, size_t cap);

/* agent.c: the ssh-agent, a socket on the loop.  The codec is foxtrot's. */
/* Connect and ask what the agent holds, if there is one to ask: the file
   named by the option or SSH_AUTH_SOCK, and no key was named.  Sets
   agent_wait while the answer is awaited.  Never fails the transfer.  */
void twist_ssh_agent_start (struct twist_ssh *s);
void twist_ssh_agent_free (struct twist_ssh *s);
/* Ask the agent to sign.  0 if it has the job; nonzero if it cannot.  */
int twist_ssh_agent_sign (struct twist_ssh *s, const gf_key *key,
                          enum gf_sigalg alg, gf_slice data);
/* Tell the agent which server this is, once the host key is trusted.  */
void twist_ssh_agent_bind (struct twist_ssh *s, const gf_conn_info *info);

/* sftp.c: the session events that carry a download, and the end of it.  */
int twist_sftp_authenticated (void *user, gf_slice username);
int twist_sftp_confirmed (void *user, uint32_t id);
int twist_sftp_channel_failed (void *user, uint32_t id, uint32_t reason,
                               gf_slice text);
int twist_sftp_request_reply (void *user, uint32_t id, int success);
int twist_sftp_channel_closed (void *user, uint32_t id);
void twist_sftp_free (struct twist_sftp_xfer *xfer);
/* Keeping the session for the next URL: forget the transfer and keep the
   channel; ask whether nothing is in it; start the next transfer on it.  */
void twist_sftp_recycle (struct twist_sftp_xfer *xfer);
int twist_sftp_idle (const struct twist_sftp_xfer *xfer);
int twist_sftp_next (struct twist_ssh *s);

#endif /* TWIST_SSH_INT_H */
