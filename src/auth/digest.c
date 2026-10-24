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

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

static void
hex_bytes (const uint8_t *in, size_t n, char *out)
{
  static const char *hexd = "0123456789abcdef";
  size_t i;

  for (i = 0; i < n; i++)
    {
      out[i * 2] = hexd[in[i] >> 4];
      out[i * 2 + 1] = hexd[in[i] & 15];
    }
  out[n * 2] = 0;
}

static int
hash_hex (int sha, const char *s, char *out, size_t cap)
{
  if (sha)
    {
      uint8_t d[32];

      if (cap < 65)
        return TWIST_ERR_AUTH;
      if (twist_sha256 (s, strlen (s), d) != TWIST_OK)
        return TWIST_ERR_AUTH;
      hex_bytes (d, 32, out);
      return TWIST_OK;
    }
  {
    uint8_t d[16];

    if (cap < 33)
      return TWIST_ERR_AUTH;
    if (twist_md5 (s, strlen (s), d) != TWIST_OK)
      return TWIST_ERR_AUTH;
    hex_bytes (d, 16, out);
    return TWIST_OK;
  }
}

static int
qop_is_auth (const char *qop)
{
  const char *p;

  if (qop == NULL)
    return 0;
  p = qop;
  while (*p != 0)
    {
      while (*p == ' ' || *p == '\t' || *p == ',')
        p++;
      if (strncasecmp (p, "auth", 4) == 0
          && (p[4] == 0 || p[4] == ',' || p[4] == ' ' || p[4] == '\t'))
        return 1;
      while (*p != 0 && *p != ',')
        p++;
    }
  return 0;
}

static int
bad_digest_field (const char *s)
{
  return s != NULL && (twist_has_ctl (s) || strchr (s, '"') != NULL);
}

/* The auth-param KEY of the challenge, copied to BUF (CAP bytes), or NULL if
   there is none or it does not fit.  The challenge is a list of name=value,
   the value a token or a quoted string: a name is found only where a name
   begins (not in "cnonce" for "nonce"), never inside a quoted value, and in
   any case.  */
static const char *
param (const char *chal, const char *key, char *buf, size_t cap)
{
  const char *p = chal;
  size_t kl = strlen (key);

  while (*p != 0)
    {
      const char *name;
      size_t nl;
      size_t n = 0;
      int match;

      while (*p == ' ' || *p == '\t' || *p == ',')
        p++;
      name = p;
      while (*p != 0 && *p != '=' && *p != ',' && *p != ' ' && *p != '\t')
        p++;
      nl = (size_t) (p - name);
      while (*p == ' ' || *p == '\t')
        p++;
      if (*p != '=')
        {
          /* A word with no value, the scheme "Digest" first of all.  */
          if (nl == 0 && *p != 0)
            p++;
          continue;
        }
      p++;
      while (*p == ' ' || *p == '\t')
        p++;
      match = nl == kl && strncasecmp (name, key, kl) == 0;
      if (*p == '"')
        {
          p++;
          while (*p != 0 && *p != '"')
            {
              if (*p == '\\' && p[1] != 0)
                p++;
              if (match)
                {
                  if (n + 1 >= cap)
                    return NULL;
                  buf[n] = *p;
                }
              n++;
              p++;
            }
          if (*p != '"')
            return NULL;
          p++;
        }
      else
        {
          while (*p != 0 && *p != ',' && *p != ' ' && *p != '\t')
            {
              if (match)
                {
                  if (n + 1 >= cap)
                    return NULL;
                  buf[n] = *p;
                }
              n++;
              p++;
            }
        }
      if (match)
        {
          buf[n] = 0;
          return buf;
        }
    }
  return NULL;
}

/* A formatted string of whatever length, in memory of its own.  */
static char * dformat (const char *fmt, ...)
  __attribute__ ((format (printf, 1, 2)));

static char *
dformat (const char *fmt, ...)
{
  va_list ap;
  char *s;
  int n;

  va_start (ap, fmt);
  n = vsnprintf (NULL, 0, fmt, ap);
  va_end (ap);
  if (n < 0)
    return NULL;
  s = twist_xmalloc ((size_t) n + 1);
  if (s == NULL)
    return NULL;
  va_start (ap, fmt);
  vsnprintf (s, (size_t) n + 1, fmt, ap);
  va_end (ap);
  return s;
}

/* Hash a string that holds a secret, and wipe it.  */
static int
hash_secret (int sha, char *s, char *out, size_t cap)
{
  int rc;

  if (s == NULL)
    return TWIST_ERR_NOMEM;
  rc = hash_hex (sha, s, out, cap);
  memset (s, 0, strlen (s));
  free (s);
  return rc;
}

int
twist_auth_digest (const char *challenge, const char *method, const char *uri,
                   const char *user, const char *pass, unsigned nc,
                   const char *cnonce, char **out)
{
  char realm[512], nonce[512], opaque[512], qop[64], algo[32];
  const char *rp, *np, *qp, *ap, *op;
  char ha1[65], ha2[65], resp[65];
  char *hdr;
  int sha = 0;
  int auth;
  int rc;

  rp = param (challenge, "realm", realm, sizeof realm);
  np = param (challenge, "nonce", nonce, sizeof nonce);
  qp = param (challenge, "qop", qop, sizeof qop);
  ap = param (challenge, "algorithm", algo, sizeof algo);
  op = param (challenge, "opaque", opaque, sizeof opaque);
  if (rp == NULL || np == NULL)
    return TWIST_ERR_AUTH;
  if (bad_digest_field (user) || bad_digest_field (uri)
      || bad_digest_field (realm) || bad_digest_field (nonce)
      || bad_digest_field (op))
    return TWIST_ERR_AUTH;
  if (qp != NULL && qop[0] != 0 && !qop_is_auth (qop))
    return TWIST_ERR_UNSUPPORTED;
  if (ap != NULL && strcasecmp (algo, "SHA-256") == 0)
    sha = 1;
  else if (ap != NULL && algo[0] != 0 && strcasecmp (algo, "MD5") != 0)
    return TWIST_ERR_UNSUPPORTED;
  auth = qp != NULL && qop_is_auth (qop);
  /* Every string here is made to its own length: the user, the password and
     the URI are whatever the caller has, and one cut off in a buffer gave a
     response that matched nothing.  */
  rc = hash_secret (sha, dformat ("%s:%s:%s", user, realm, pass), ha1,
                    sizeof ha1);
  if (rc != TWIST_OK)
    return rc;
  rc = hash_secret (sha, dformat ("%s:%s", method, uri), ha2, sizeof ha2);
  if (rc != TWIST_OK)
    return rc;
  if (auth)
    rc = hash_secret (sha, dformat ("%s:%s:%08x:%s:auth:%s", ha1, nonce, nc,
                                    cnonce != NULL ? cnonce : "twist", ha2),
                      resp, sizeof resp);
  else
    rc = hash_secret (sha, dformat ("%s:%s:%s", ha1, nonce, ha2), resp,
                      sizeof resp);
  memset (ha1, 0, sizeof ha1);
  if (rc != TWIST_OK)
    return rc;
  /* The opaque goes back as it came, and the algorithm is named unless it is
     the default (RFC 7616).  */
  {
    char *qpart = auth ? dformat (", qop=auth, nc=%08x, cnonce=\"%s\"", nc,
                                  cnonce != NULL ? cnonce : "twist")
                       : twist_strdup ("");
    char *opart = op != NULL ? dformat (", opaque=\"%s\"", op)
                             : twist_strdup ("");

    if (qpart == NULL || opart == NULL)
      {
        free (qpart);
        free (opart);
        return TWIST_ERR_NOMEM;
      }
    hdr = dformat ("Authorization: Digest username=\"%s\", realm=\"%s\", "
                   "nonce=\"%s\", uri=\"%s\"%s, response=\"%s\"%s%s",
                   user, realm, nonce, uri, qpart, resp,
                   sha ? ", algorithm=SHA-256" : "", opart);
    free (qpart);
    free (opart);
  }
  if (hdr == NULL)
    return TWIST_ERR_NOMEM;
  *out = hdr;
  return TWIST_OK;
}
