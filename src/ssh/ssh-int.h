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

/* The parts of the scp and sftp handler:

     ssh.c      the session on the endpoint, its timer, the end of a transfer
     hostkey.c  known_hosts, a pinned fingerprint, and the client's keys
     sftp.c     the channel, the subsystem and the download

   One struct twist_ssh is the handler; the others hang from it.  */

#define SSH_MAX_KEYS 4
#define SSH_MAX_ALGS 16

struct twist_sftp_get;

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
  gf_key *keys[SSH_MAX_KEYS];
  const gf_key *key_ptrs[SSH_MAX_KEYS];
  size_t nkeys;
  /* Default key files that were not offered because the library cannot
     decrypt them.  */
  unsigned keys_skipped;
  gf_knownhosts *known;
  enum gf_sigalg algs[SSH_MAX_ALGS];
  struct twist_sftp_get *get;
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
};

/* The transfer is over or about to be.  */
static inline int
twist_ssh_done (const struct twist_ssh *s)
{
  return s->finished || s->end_pending;
}

/* ssh.c */
uint64_t twist_ssh_now_us (const struct twist_ssh *s);
/* Keep DETAIL as the message of the transfer unless one is already set.  */
void twist_ssh_detail (struct twist_ssh *s, const char *detail);
/* Say goodbye and end the transfer with ERR.  */
void twist_ssh_finish (struct twist_ssh *s, int err);

/* hostkey.c: known_hosts and the pin, before the session is made, and the
   host key callback of the session.  */
int twist_ssh_trust_load (struct twist_ssh *s);
int twist_ssh_host_key (void *user, const gf_key *key);
/* The client's private keys: the key file given, or the usual ones.  */
int twist_ssh_keys_load (struct twist_ssh *s);
void twist_ssh_keys_free (struct twist_ssh *s);
/* Add what the failure of authentication leaves to say.  */
void twist_ssh_auth_hint (struct twist_ssh *s, char *buf, size_t cap);

/* sftp.c: the session events that carry a download, and the end of it.  */
int twist_sftp_authenticated (void *user, gf_slice username);
int twist_sftp_confirmed (void *user, uint32_t id);
int twist_sftp_channel_failed (void *user, uint32_t id, uint32_t reason,
                               gf_slice text);
int twist_sftp_request_reply (void *user, uint32_t id, int success);
int twist_sftp_channel_closed (void *user, uint32_t id);
void twist_sftp_free (struct twist_sftp_get *get);

#endif /* TWIST_SSH_INT_H */
