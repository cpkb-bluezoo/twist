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

#ifndef TWIST_TEST_SMBSRV_H
#define TWIST_TEST_SMBSRV_H

#include "twist-int.h"

/* A scripted SMB 3.1.1 server for the tests: it reads what the client sends,
   keeps the pre-authentication hash itself, derives the same keys as the
   client, signs the last SESSION_SETUP response, and encrypts its answers.
   The SPNEGO tokens are those of test-spnego, whose NTLM values the random
   hook fixes (client challenge 0xaa, session key 0x55), so the session key is
   known to both ends.  */

size_t unhex (const char *h, uint8_t *out);

struct msg
{
  uint8_t b[72000];
  size_t n;
};

void p8 (struct msg *m, unsigned v);
void p16 (struct msg *m, unsigned v);
void p32 (struct msg *m, uint32_t v);
void p64 (struct msg *m, uint64_t v);
void pz (struct msg *m, size_t n);
void pb (struct msg *m, const void *d, size_t n);

#define SESSION_ID 0x1122334455667788ull

/* A response message (no framing).  */
void header (struct msg *m, unsigned cmd, uint32_t status, uint32_t flags,
             uint64_t msgid, uint64_t session, uint32_t tree);

struct srv_opts
{
  unsigned dialect;
  unsigned mode;
  unsigned caps;
  unsigned cipher;		/* 0: no encryption context.  */
  unsigned signing;		/* 0xffff: no signing context.  */
  unsigned hash;
  int compression;
  int two_hashes;
  unsigned session_flags;
  int unsigned_final;
  int bad_final_sig;
  int plain_tree;		/* The tree response is not encrypted.  */
  int bad_tag;
  int wrong_session;
  int repeat_nonce;
  uint32_t login_status;	/* Refuse the login with this at the end.  */
  uint32_t max_read;
  uint64_t tree_msgid;
  int mitm;
  uint32_t tree_status;	/* An error for the TREE_CONNECT.  */
};


struct srv_opts srv_good (void);

struct smbsrv
{
  struct srv_opts o;
  uint8_t hash[64];
  uint8_t sign[16], c2s[32], s2c[32];
  size_t keylen;
  uint64_t nonce;
  uint8_t last_nonce[12];
  void *user;
  /* Where a message of the server's goes (no framing).  */
  void (*give) (void *user, const uint8_t *m, size_t n);
};

void srv_init (struct smbsrv *v, struct srv_opts o,
               void (*give) (void *user, const uint8_t *m, size_t n),
               void *user);
/* The client's frames (with their four-byte headers) are given to these.  */
void srv_negotiate (struct smbsrv *v, const uint8_t *req, size_t n);
void srv_setup1 (struct smbsrv *v, const uint8_t *req, size_t n);
void srv_setup2 (struct smbsrv *v, const uint8_t *req, size_t n);
/* Open an encrypted frame of the client's; the plaintext message.  */
int srv_open (struct smbsrv *v, const uint8_t *frame, size_t n, struct msg *plain);
/* Answer a TREE_CONNECT (encrypted).  */
int srv_tree (struct smbsrv *v, const uint8_t *f, size_t n, uint32_t tree_id);
/* Send PLAIN, encrypted.  */
void srv_seal (struct smbsrv *v, const struct msg *plain);

#endif
