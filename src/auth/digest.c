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

static const char *
param (const char *chal, const char *key, char *buf, size_t cap)
{
  const char *p = strstr (chal, key);
  size_t n;
  if (p == NULL)
    return NULL;
  p += strlen (key);
  while (*p == ' ' || *p == '=')
    p++;
  if (*p == '"')
    {
      const char *e;
      p++;
      e = strchr (p, '"');
      if (e == NULL)
        return NULL;
      n = (size_t) (e - p);
    }
  else
    {
      const char *e = p;
      while (*e != 0 && *e != ',' && *e != ' ')
        e++;
      n = (size_t) (e - p);
    }
  if (n + 1 > cap)
    return NULL;
  memcpy (buf, p, n);
  buf[n] = 0;
  return buf;
}

int
twist_auth_digest (const char *challenge, const char *method, const char *uri,
                   const char *user, const char *pass, unsigned nc,
                   const char *cnonce, char **out)
{
  char realm[128], nonce[128], qop[64], algo[32];
  const char *rp, *np, *qp, *ap;
  char ha1[65], ha2[65], resp[65];
  char tmp[768];
  char *hdr;
  int sha = 0;
  int rc;

  rp = param (challenge, "realm", realm, sizeof realm);
  np = param (challenge, "nonce", nonce, sizeof nonce);
  qp = param (challenge, "qop", qop, sizeof qop);
  ap = param (challenge, "algorithm", algo, sizeof algo);
  if (rp == NULL || np == NULL)
    return TWIST_ERR_AUTH;
  if (bad_digest_field (user) || bad_digest_field (uri)
      || bad_digest_field (realm) || bad_digest_field (nonce))
    return TWIST_ERR_AUTH;
  if (qp != NULL && qop[0] != 0 && !qop_is_auth (qop))
    return TWIST_ERR_UNSUPPORTED;
  if (ap != NULL && strcasecmp (algo, "SHA-256") == 0)
    sha = 1;
  else if (ap != NULL && algo[0] != 0 && strcasecmp (algo, "MD5") != 0)
    return TWIST_ERR_UNSUPPORTED;
  snprintf (tmp, sizeof tmp, "%s:%s:%s", user, realm, pass);
  rc = hash_hex (sha, tmp, ha1, sizeof ha1);
  if (rc != TWIST_OK)
    return rc;
  snprintf (tmp, sizeof tmp, "%s:%s", method, uri);
  rc = hash_hex (sha, tmp, ha2, sizeof ha2);
  if (rc != TWIST_OK)
    return rc;
  if (qp != NULL && qop_is_auth (qop))
    snprintf (tmp, sizeof tmp, "%s:%s:%08x:%s:auth:%s", ha1, nonce, nc,
              cnonce != NULL ? cnonce : "twist", ha2);
  else
    snprintf (tmp, sizeof tmp, "%s:%s:%s", ha1, nonce, ha2);
  rc = hash_hex (sha, tmp, resp, sizeof resp);
  if (rc != TWIST_OK)
    return rc;
  hdr = twist_xmalloc (512);
  if (hdr == NULL)
    return TWIST_ERR_NOMEM;
  if (qp != NULL && qop_is_auth (qop))
    snprintf (hdr, 512,
              "Authorization: Digest username=\"%s\", realm=\"%s\", nonce=\"%s\", uri=\"%s\", qop=auth, nc=%08x, cnonce=\"%s\", response=\"%s\"",
              user, realm, nonce, uri, nc, cnonce != NULL ? cnonce : "twist",
              resp);
  else
    snprintf (hdr, 512,
              "Authorization: Digest username=\"%s\", realm=\"%s\", nonce=\"%s\", uri=\"%s\", response=\"%s\"",
              user, realm, nonce, uri, resp);
  *out = hdr;
  return TWIST_OK;
}

