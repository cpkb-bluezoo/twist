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

#include <foxtrot/key.h>
#include <foxtrot/keyfmt.h>
#include <foxtrot/status.h>

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* Who the server is, and who we are.

   The host key is checked against ~/.ssh/known_hosts
   unless that is turned off with -k, and a key that is not there, or that
   differs from the one that is, fails the transfer.  There is no
   accept-new.  A fingerprint given with TWISTOPT_SSH_HOST_PUBLIC_KEY_SHA256
   is another way to trust a host; it is checked first, a match is enough,
   and a mismatch fails whatever -k says.

   The files are read, and parsed, on the storage pool and not on the loop:
   a read can wait on a slow disk, and a passphrase-protected key can ask for
   millions of rounds of key derivation.  The job works on a copy of what it
   needs and touches nothing of the transfer, which may be gone before it is
   done; the loop adopts the result, or drops it if the transfer is gone.  */

#define SSH_FILE_MAX (1024 * 1024)

struct twist_ssh_load
{
  struct twist_ssh *ssh;	/* NULL once the transfer is gone.  */
  /* In: copies.  */
  int verify;
  char *knownhosts;		/* Named, or NULL for the default.  */
  char *home;
  char *keyfile;		/* Named, or NULL for the usual ones.  */
  char *passphrase;
  char *user;			/* For the principals of a certificate.  */
  char host[256];
  unsigned port;
  /* Out.  */
  int err;
  char detail[1200];
  pthread_t thread;
  gf_knownhosts *known;
  enum gf_sigalg algs[SSH_MAX_ALGS];
  size_t nalgs;
  gf_key *keys[SSH_MAX_KEYS];
  size_t nkeys;
  unsigned skipped;
  char cert_note[240];
};

static void
load_free (struct twist_ssh_load *l)
{
  size_t i;

  if (l == NULL)
    return;
  free (l->knownhosts);
  free (l->home);
  free (l->keyfile);
  free (l->user);
  if (l->passphrase != NULL)
    {
      memset (l->passphrase, 0, strlen (l->passphrase));
      free (l->passphrase);
    }
  gf_knownhosts_free (l->known);
  for (i = 0; i < l->nkeys; i++)
    gf_key_free (l->keys[i]);
  free (l);
}

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
home_path (const struct twist_ssh_load *l, char *out, size_t cap,
           const char *rest)
{
  if (l->home == NULL || l->home[0] == 0)
    return 0;
  return snprintf (out, cap, "%s/%s", l->home, rest) < (int) cap;
}

/* ---- the known_hosts file ---- */

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

static void
load_known_hosts (struct twist_ssh_load *l)
{
  char def[1024];
  const char *path = l->knownhosts;
  char *text;
  size_t n = 0;

  if (!l->verify)
    return;
  if (path == NULL && home_path (l, def, sizeof def, ".ssh/known_hosts"))
    path = def;
  if (gf_knownhosts_new (&l->known) != GF_OK)
    {
      l->err = TWIST_ERR_NOMEM;
      return;
    }
  if (path != NULL)
    {
      text = read_file (path, &n);
      if (text != NULL)
        {
          gf_knownhosts_load (l->known, text, n, NULL);
          free (text);
        }
      else if (l->knownhosts != NULL)
        {
          l->err = TWIST_ERR_FILE;
          snprintf (l->detail, sizeof l->detail,
                    _("cannot read the known_hosts file %s"), l->knownhosts);
          return;
        }
    }
  /* A host known by one kind of key is asked for that kind, so that it
     cannot answer with another.  */
  l->nalgs = gf_knownhosts_sigalgs (l->known, l->host, l->port, l->algs,
                                    SSH_MAX_ALGS);
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

static void
add_key (struct twist_ssh_load *l, gf_key *key)
{
  if (!gf_key_has_private (key) || l->nkeys >= SSH_MAX_KEYS)
    {
      /* A security key (FIDO) has no private part here, and nothing yet
         drives a token.  */
      gf_key_free (key);
      return;
    }
  l->keys[l->nkeys++] = key;
}


/* The certificate beside the private key at PATH, if there is one: PATH with
   -cert.pub added, as ssh looks for it.  A certificate that is there and good
   is offered before the plain key.  One that is not good is left out and
   said so, since the server will not say why it refused: the plain key is
   still offered, and may be the one the server knows.  KEY is added in any
   case.  */
static void
add_key_with_certificate (struct twist_ssh_load *l, gf_key *key,
                          const char *path)
{
  char cpath[1100];
  char *text;
  size_t n = 0;
  gf_key *cert = NULL, *both = NULL;
  const char *why = NULL;

  if (snprintf (cpath, sizeof cpath, "%s-cert.pub", path) >= (int) sizeof cpath
      || (text = read_file (cpath, &n)) == NULL)
    {
      add_key (l, key);
      return;
    }
  /* The reason is for the first certificate that is no good.  */
  if (l->cert_note[0] != 0)
    {
      free (text);
      add_key (l, key);
      return;
    }
  if (gf_key_from_text (&cert, text, n, NULL) != GF_OK
      || !gf_key_is_certificate (cert))
    snprintf (l->cert_note, sizeof l->cert_note,
              _("%s is not a usable certificate"), cpath);
  else if (gf_key_with_certificate (key, cert, &both) != GF_OK)
    snprintf (l->cert_note, sizeof l->cert_note,
              _("the certificate in %s is not for this key"), cpath);
  else if (gf_cert_check (cert, GF_CERT_USER, (uint64_t) time (NULL), &why)
           != GF_OK)
    {
      snprintf (l->cert_note, sizeof l->cert_note,
                _("the certificate in %s cannot be used: %s"), cpath,
                why != NULL ? why : "");
      gf_key_free (both);
      both = NULL;
    }
  else if (l->user != NULL
           && !gf_cert_has_principal (cert, l->user, strlen (l->user), 0))
    {
      snprintf (l->cert_note, sizeof l->cert_note,
                _("the certificate in %s is not for the user %s"), cpath,
                l->user);
      gf_key_free (both);
      both = NULL;
    }
  free (text);
  gf_key_free (cert);
  if (both != NULL)
    add_key (l, both);
  add_key (l, key);
}

static void
load_keys (struct twist_ssh_load *l)
{
  static const char *const usual[] = {
    ".ssh/id_ed25519", ".ssh/id_ecdsa", ".ssh/id_rsa"
  };
  char path[1024];
  gf_key *key = NULL;
  int openssh, rc;
  size_t i;

  if (l->keyfile != NULL)
    {
      rc = load_private_key (&key, l->keyfile, l->passphrase, &openssh);
      if (rc == GF_OK && gf_key_has_private (key))
        {
          add_key_with_certificate (l, key, l->keyfile);
          return;
        }
      gf_key_free (key);
      if (rc == GF_ERR_INVAL)
        {
          l->err = TWIST_ERR_FILE;
          snprintf (l->detail, sizeof l->detail,
                    _("cannot read the private key file %s"), l->keyfile);
        }
      else if (rc == GF_ERR_UNSUPPORTED && openssh)
        {
          l->err = TWIST_ERR_AUTH;
          snprintf (l->detail, sizeof l->detail,
                    _("%s is protected by a passphrase, in the OpenSSH "
                      "format, which twist cannot decrypt yet; use an "
                      "ssh-agent, or convert it (ssh-keygen -p -m PKCS8)"),
                    l->keyfile);
        }
      else if (rc == GF_ERR_PASSPHRASE)
        {
          l->err = TWIST_ERR_AUTH;
          snprintf (l->detail, sizeof l->detail,
                    _("the passphrase for %s is wrong or missing (--pass)"),
                    l->keyfile);
        }
      else
        {
          l->err = TWIST_ERR_AUTH;
          snprintf (l->detail, sizeof l->detail,
                    _("cannot use %s as a private key (%s)"), l->keyfile,
                    gf_strerror (rc));
        }
      return;
    }
  for (i = 0; i < sizeof usual / sizeof usual[0]; i++)
    {
      if (!home_path (l, path, sizeof path, usual[i]))
        break;
      key = NULL;
      rc = load_private_key (&key, path, l->passphrase, &openssh);
      if (rc == GF_OK)
        add_key_with_certificate (l, key, path);
      else if (rc != GF_ERR_INVAL)
        {
          /* There, but not usable: say so if nothing else works.  */
          gf_key_free (key);
          l->skipped++;
        }
    }
}

/* ---- the job ---- */

/* On a worker thread.  Touches the load and nothing else.  */
static void
load_work (void *arg)
{
  struct twist_ssh_load *l = arg;

  l->thread = pthread_self ();
  load_known_hosts (l);
  if (l->err == TWIST_OK)
    load_keys (l);
}

/* On the loop.  The transfer takes what the job made, if it is still
   there, and goes on.  */
static void
load_done (void *user, int err)
{
  struct twist_ssh_load *l = user;
  struct twist_ssh *s = l->ssh;
  size_t i;

  if (s != NULL)
    {
      s->load = NULL;
      if (err != TWIST_OK && l->err == TWIST_OK)
        l->err = err;
      s->known = l->known;
      l->known = NULL;
      memcpy (s->algs, l->algs, sizeof s->algs);
      s->nalgs = l->nalgs;
      for (i = 0; i < l->nkeys; i++)
        s->keys[i] = l->keys[i];
      s->nkeys = l->nkeys;
      l->nkeys = 0;
      s->keys_skipped = l->skipped;
      memcpy (s->cert_note, l->cert_note, sizeof s->cert_note);
      s->load_thread = l->thread;
      s->load_thread_set = 1;
      if (!twist_ssh_done (s) && l->err != TWIST_OK)
        {
          twist_ssh_detail (s, l->detail);
          twist_ssh_finish (s, l->err);
        }
      else if (!twist_ssh_done (s))
        {
          s->load_ready = 1;
          twist_ssh_maybe_begin (s);
        }
    }
  load_free (l);
}

static char *
copy_or_null (const char *s)
{
  return s != NULL ? twist_strdup (s) : NULL;
}

int
twist_ssh_load_start (struct twist_ssh *s)
{
  struct twist_easy *e = s->easy;
  struct twist_ssh_load *l = calloc (1, sizeof *l);
  char home[1024];
  int have_home = twist_home_dir (home, sizeof home);
  int rc;

  if (l == NULL)
    return TWIST_ERR_NOMEM;
  l->ssh = s;
  l->verify = e->verifypeer;
  l->knownhosts = copy_or_null (e->ssh_knownhosts);
  l->home = have_home ? twist_strdup (home) : NULL;
  l->keyfile = copy_or_null (e->sslkey);
  l->passphrase = copy_or_null (e->keypasswd);
  l->user = copy_or_null (s->user);
  host_name (e->url, l->host, sizeof l->host);
  l->port = (unsigned) e->url->port;
  if ((e->ssh_knownhosts != NULL && l->knownhosts == NULL)
      || (have_home && l->home == NULL)
      || (e->sslkey != NULL && l->keyfile == NULL)
      || (e->keypasswd != NULL && l->passphrase == NULL)
      || (s->user != NULL && l->user == NULL))
    {
      load_free (l);
      return TWIST_ERR_NOMEM;
    }
  s->load = l;
  if (e->multi != NULL && e->multi->storage != NULL && e->loop != NULL)
    {
      rc = twist_storage_submit (e->multi->storage, load_work, l, load_done, l,
                                 e->loop);
      if (rc != TWIST_OK)
        {
          s->load = NULL;
          load_free (l);
        }
      return rc;
    }
  /* No loop, as when the handler is driven in-process: do it here.  */
  load_work (l);
  load_done (l, TWIST_OK);
  return TWIST_OK;
}

/* The transfer is going away with the job unfinished: the job finishes by
   itself and frees what it has.  */
void
twist_ssh_load_abandon (struct twist_ssh *s)
{
  if (s->load != NULL)
    {
      s->load->ssh = NULL;
      s->load = NULL;
    }
}

/* ---- the host key callback ---- */

/* A fingerprint as ssh-keygen prints it or as the option is given one: without
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

void
twist_ssh_keys_free (struct twist_ssh *s)
{
  size_t i;

  for (i = 0; i < s->nkeys; i++)
    gf_key_free (s->keys[i]);
  s->nkeys = 0;
  for (i = 0; i < s->nakeys; i++)
    gf_key_free (s->akeys[i]);
  free (s->akeys);
  s->akeys = NULL;
  s->nakeys = s->cap_akeys = 0;
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
  else if (s->nkeys == 0 && s->nakeys == 0 && s->password == NULL
           && used + 1 < cap)
    snprintf (buf + used, cap - used,
              _(" (no private key or password was available)"));
  used = strlen (buf);
  if (s->cert_note[0] != 0 && used + 1 < cap)
    snprintf (buf + used, cap - used, " (%s)", s->cert_note);
  used = strlen (buf);
  if (s->agent_note[0] != 0 && used + 1 < cap)
    snprintf (buf + used, cap - used, _(" (ssh-agent: %s)"), s->agent_note);
  used = strlen (buf);
  if (s->kbdint_note[0] != 0 && used + 1 < cap)
    snprintf (buf + used, cap - used, _(" (keyboard-interactive: %s)"),
              s->kbdint_note);
}
