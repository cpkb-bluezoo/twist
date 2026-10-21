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

#include <foxtrot/keyfmt.h>
#include <foxtrot/status.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* Who the server is, and who we are.

   The host key is checked as the curl tool does: against ~/.ssh/known_hosts
   unless that is turned off with -k, and a key that is not there, or that
   differs from the one that is, fails the transfer.  There is no
   accept-new.  A fingerprint given with TWISTOPT_SSH_HOST_PUBLIC_KEY_SHA256
   is another way to trust a host; it is checked first, a match is enough,
   and a mismatch fails whatever -k says.

   Files are read whole, once, before the connection is used: they are small
   and local, and a transfer does not start without them.  */

#define SSH_FILE_MAX (1024 * 1024)

/* The contents of PATH, NUL-terminated, or NULL.  */
static char *
read_file (const char *path, size_t *len)
{
  FILE *fp = fopen (path, "rb");
  char *buf;
  size_t n, cap = 4096, used = 0;

  if (fp == NULL)
    return NULL;
  buf = malloc (cap + 1);
  while (buf != NULL)
    {
      n = fread (buf + used, 1, cap - used, fp);
      used += n;
      if (used < cap)
        break;
      if (cap >= SSH_FILE_MAX)
        {
          free (buf);
          buf = NULL;
          break;
        }
      cap *= 2;
      {
        char *grown = realloc (buf, cap + 1);

        if (grown == NULL)
          free (buf);
        buf = grown;
      }
    }
  fclose (fp);
  if (buf == NULL)
    return NULL;
  buf[used] = 0;
  *len = used;
  return buf;
}

static int
home_path (char *out, size_t cap, const char *rest)
{
  const char *home = getenv ("HOME");

  if (home == NULL || home[0] == 0)
    return 0;
  return snprintf (out, cap, "%s/%s", home, rest) < (int) cap;
}

/* ---- host keys ---- */

/* The host as known_hosts names it: an IPv6 literal without brackets.  */
static void
host_name (const struct twist_url *url, char *out, size_t cap)
{
  const char *h = url->host != NULL ? url->host : "";
  size_t n = strlen (h);

  if (n >= 2 && h[0] == '[' && h[n - 1] == ']')
    {
      h++;
      n -= 2;
    }
  if (n >= cap)
    n = cap - 1;
  memcpy (out, h, n);
  out[n] = 0;
}

int
twist_ssh_trust_load (struct twist_ssh *s)
{
  struct twist_easy *e = s->easy;
  char def[1024], host[256], msg[1100];
  const char *path = e->ssh_knownhosts;
  int explicit_path = path != NULL;
  char *text;
  size_t n = 0;

  if (!e->verifypeer)
    return TWIST_OK;
  if (path == NULL && home_path (def, sizeof def, ".ssh/known_hosts"))
    path = def;
  if (gf_knownhosts_new (&s->known) != GF_OK)
    return TWIST_ERR_NOMEM;
  if (path != NULL)
    {
      text = read_file (path, &n);
      if (text != NULL)
        {
          gf_knownhosts_load (s->known, text, n, NULL);
          free (text);
        }
      else if (explicit_path)
        {
          snprintf (msg, sizeof msg, _("cannot read the known_hosts file %s"),
                    path);
          twist_ssh_detail (s, msg);
          return TWIST_ERR_FILE;
        }
    }
  /* A host known by one kind of key is asked for that kind, so that it
     cannot answer with another.  */
  host_name (e->url, host, sizeof host);
  s->config.conn.prefs.nsigalgs
    = gf_knownhosts_sigalgs (s->known, host, (unsigned) e->url->port,
                             s->algs, SSH_MAX_ALGS);
  s->config.conn.prefs.sigalgs = s->algs;
  return TWIST_OK;
}

/* A fingerprint as ssh-keygen prints it or as curl is given one: without
   the "SHA256:" and without padding.  */
static int
fingerprint_equal (const char *a, const char *b)
{
  size_t la, lb;

  if (strncmp (a, "SHA256:", 7) == 0)
    a += 7;
  if (strncmp (b, "SHA256:", 7) == 0)
    b += 7;
  la = strlen (a);
  lb = strlen (b);
  while (la > 0 && a[la - 1] == '=')
    la--;
  while (lb > 0 && b[lb - 1] == '=')
    lb--;
  return la == lb && la > 0 && memcmp (a, b, la) == 0;
}

int
twist_ssh_host_key (void *user, const gf_key *key)
{
  struct twist_ssh *s = user;
  struct twist_easy *e = s->easy;
  char fp[64], host[256], msg[512];
  time_t now;
  enum gf_hostcheck r = GF_HOST_UNKNOWN;

  gf_key_fingerprint (key, fp, sizeof fp);
  if (e->ssh_hostpubsha256 != NULL)
    {
      if (fingerprint_equal (e->ssh_hostpubsha256, fp))
        return 0;
      snprintf (msg, sizeof msg,
                _("the host key (%s) does not match the pinned SHA-256"), fp);
      twist_ssh_detail (s, msg);
      s->pending_err = TWIST_ERR_HOSTKEY;
      return 1;
    }
  if (!e->verifypeer)
    return 0;
  host_name (e->url, host, sizeof host);
  now = time (NULL);
  if (s->known != NULL)
    r = gf_knownhosts_check (s->known, host, (unsigned) e->url->port, key,
                             now < 0 ? 0 : (uint64_t) now);
  if (r == GF_HOST_MATCH)
    return 0;
  if (r == GF_HOST_CHANGED)
    snprintf (msg, sizeof msg,
              _("WARNING: the host key of %s has CHANGED (now %s); this "
                "could be someone listening in, or the host was reinstalled"),
              host, fp);
  else if (r == GF_HOST_REVOKED)
    snprintf (msg, sizeof msg, _("the host key of %s is REVOKED (%s)"), host,
              fp);
  else
    snprintf (msg, sizeof msg,
              _("the host key of %s is not in known_hosts (%s); add it, or "
                "give its fingerprint with --hostpubsha256"), host, fp);
  twist_ssh_detail (s, msg);
  s->pending_err = TWIST_ERR_HOSTKEY;
  return 1;
}

/* ---- the client's keys ---- */

/* Read the private key in PATH in whichever format it has.  The OpenSSH
   format is read without a passphrase: its key derivation, bcrypt-pbkdf,
   is not in libgcrypt, and twist does not take it from anywhere else.  */
static int
load_private_key (gf_key **out, const char *path, const char *passphrase,
                  int *openssh_format)
{
  size_t n = 0;
  char *t = read_file (path, &n);
  int rc;

  *openssh_format = 0;
  if (t == NULL)
    return GF_ERR_INVAL;
  if (strncmp (t, "-----BEGIN OPENSSH PRIVATE KEY-----", 35) == 0)
    {
      *openssh_format = 1;
      rc = gf_key_from_openssh_private (out, t, n);
    }
  else if (strncmp (t, "-----BEGIN ", 11) == 0)
    rc = gf_key_from_pem (out, t, n, passphrase);
  else if (strncmp (t, "PuTTY-User-Key-File-", 20) == 0)
    rc = gf_key_from_ppk (out, t, n, passphrase, NULL, 0);
  else
    rc = GF_ERR_ENCODING;
  memset (t, 0, n);
  free (t);
  return rc;
}

static int
add_key (struct twist_ssh *s, gf_key *key)
{
  if (!gf_key_has_private (key) || s->nkeys >= SSH_MAX_KEYS)
    {
      /* A security key (FIDO) has no private part here, and nothing yet
         drives a token.  */
      gf_key_free (key);
      return 0;
    }
  s->keys[s->nkeys] = key;
  s->key_ptrs[s->nkeys] = key;
  s->nkeys++;
  return 1;
}

int
twist_ssh_keys_load (struct twist_ssh *s)
{
  struct twist_easy *e = s->easy;
  static const char *const usual[] = {
    ".ssh/id_ed25519", ".ssh/id_ecdsa", ".ssh/id_rsa"
  };
  char path[1024], msg[1200];
  gf_key *key = NULL;
  int openssh, rc;
  size_t i;

  if (e->sslkey != NULL)
    {
      rc = load_private_key (&key, e->sslkey, e->keypasswd, &openssh);
      if (rc == GF_OK && gf_key_has_private (key))
        {
          add_key (s, key);
          return TWIST_OK;
        }
      gf_key_free (key);
      if (rc == GF_ERR_INVAL)
        snprintf (msg, sizeof msg, _("cannot read the private key file %s"),
                  e->sslkey);
      else if (rc == GF_ERR_UNSUPPORTED && openssh)
        snprintf (msg, sizeof msg,
                  _("%s is protected by a passphrase, in the OpenSSH format, "
                    "which twist cannot decrypt yet; use an ssh-agent, or "
                    "convert it (ssh-keygen -p -m PKCS8)"), e->sslkey);
      else if (rc == GF_ERR_PASSPHRASE)
        snprintf (msg, sizeof msg,
                  _("the passphrase for %s is wrong or missing (--pass)"),
                  e->sslkey);
      else
        snprintf (msg, sizeof msg,
                  _("cannot use %s as a private key (%s)"), e->sslkey,
                  gf_strerror (rc));
      twist_ssh_detail (s, msg);
      return rc == GF_ERR_INVAL ? TWIST_ERR_FILE : TWIST_ERR_AUTH;
    }
  for (i = 0; i < sizeof usual / sizeof usual[0]; i++)
    {
      if (!home_path (path, sizeof path, usual[i]))
        break;
      key = NULL;
      rc = load_private_key (&key, path, e->keypasswd, &openssh);
      if (rc == GF_OK)
        add_key (s, key);
      else if (rc != GF_ERR_INVAL)
        {
          /* There, but not usable: say so if nothing else works.  */
          gf_key_free (key);
          s->keys_skipped++;
        }
    }
  return TWIST_OK;
}

void
twist_ssh_keys_free (struct twist_ssh *s)
{
  size_t i;

  for (i = 0; i < s->nkeys; i++)
    gf_key_free (s->keys[i]);
  s->nkeys = 0;
}

void
twist_ssh_auth_hint (struct twist_ssh *s, char *buf, size_t cap)
{
  size_t used = strlen (buf);

  if (s->keys_skipped > 0 && used + 1 < cap)
    snprintf (buf + used, cap - used,
              _(" (%u of the usual key files in ~/.ssh could not be used: "
                "they are passphrase-protected or in a format twist cannot "
                "read; passphrase-protected OpenSSH keys cannot be "
                "decrypted yet)"),
              s->keys_skipped);
  else if (s->nkeys == 0 && s->password == NULL && used + 1 < cap)
    snprintf (buf + used, cap - used,
              _(" (no private key or password was available)"));
}
