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

#include <quickstep/sign.h>
#include <quickstep/status.h>
#include <quickstep/tls.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* A client identity is an unencrypted PEM private key and a PEM
   certificate file.  Certificates in that file are sent leaf first.
   The CA bundle is the peer trust store, loaded separately.  */

#define CHAIN_MAX 8

struct twist_client_auth
{
  gq_privkey *key;
  gq_slice chain[CHAIN_MAX];
  size_t nchain;
  uint8_t *der;
};

static int
b64_digit (unsigned char c)
{
  if (c >= 'A' && c <= 'Z')
    return c - 'A';
  if (c >= 'a' && c <= 'z')
    return c - 'a' + 26;
  if (c >= '0' && c <= '9')
    return c - '0' + 52;
  if (c == '+')
    return 62;
  if (c == '/')
    return 63;
  return -1;
}

static int
b64_decode (const char *in, size_t len, uint8_t *out, size_t cap,
            size_t *out_len)
{
  char group[4];
  int n = 0;
  size_t i;
  size_t o = 0;

  for (i = 0; i < len; i++)
    {
      unsigned char c = (unsigned char) in[i];
      int d;
      unsigned packed;
      int pad = 0;
      int k;

      if (c == ' ' || c == '\t' || c == '\r' || c == '\n')
        continue;
      group[n++] = (char) c;
      if (n < 4)
        continue;
      n = 0;
      for (k = 0; k < 4; k++)
        {
          if (group[k] == '=')
            {
              pad++;
              d = 0;
            }
          else
            {
              if (pad)
                return TWIST_ERR_TLS;
              d = b64_digit ((unsigned char) group[k]);
              if (d < 0)
                return TWIST_ERR_TLS;
            }
          group[k] = (char) d;
        }
      if (pad > 2)
        return TWIST_ERR_TLS;
      packed = ((unsigned) (unsigned char) group[0] << 18)
               | ((unsigned) (unsigned char) group[1] << 12)
               | ((unsigned) (unsigned char) group[2] << 6)
               | (unsigned) (unsigned char) group[3];
      if (o >= cap)
        return TWIST_ERR_TLS;
      out[o++] = (uint8_t) (packed >> 16);
      if (pad < 2)
        {
          if (o >= cap)
            return TWIST_ERR_TLS;
          out[o++] = (uint8_t) (packed >> 8);
        }
      if (pad < 1)
        {
          if (o >= cap)
            return TWIST_ERR_TLS;
          out[o++] = (uint8_t) packed;
        }
    }
  if (n != 0)
    return TWIST_ERR_TLS;
  if (o == 0)
    return TWIST_ERR_TLS;
  *out_len = o;
  return TWIST_OK;
}

static int
find_at (const char *text, size_t len, size_t from, const char *tok,
         size_t *at)
{
  size_t n = strlen (tok);
  size_t i;

  if (from > len || n > len - from)
    return 0;
  for (i = from; i + n <= len; i++)
    if (memcmp (text + i, tok, n) == 0)
      {
        *at = i;
        return 1;
      }
  return 0;
}

int
twist_pem_certificates (const char *text, size_t len, gq_slice *chain,
                        size_t cap, size_t *nchain, uint8_t **storage)
{
  static const char begin[] = "-----BEGIN CERTIFICATE-----";
  static const char end[] = "-----END CERTIFICATE-----";
  uint8_t *der;
  size_t used = 0;
  size_t n = 0;
  size_t at = 0;

  if (text == NULL || chain == NULL || nchain == NULL || storage == NULL
      || cap == 0)
    return TWIST_ERR_INVAL;
  *storage = NULL;
  *nchain = 0;
  der = malloc (len > 0 ? len : 1);
  if (der == NULL)
    return TWIST_ERR_NOMEM;
  while (find_at (text, len, at, begin, &at))
    {
      size_t body;
      size_t stop;
      size_t dlen = 0;

      at += sizeof begin - 1;
      if (at < len && text[at] == '\r')
        at++;
      if (at >= len || text[at] != '\n')
        {
          free (der);
          return TWIST_ERR_TLS;
        }
      body = at + 1;
      if (!find_at (text, len, body, end, &stop))
        {
          free (der);
          return TWIST_ERR_TLS;
        }
      if (n >= cap)
        {
          free (der);
          return TWIST_ERR_TLS;
        }
      if (b64_decode (text + body, stop - body, der + used, len - used, &dlen)
          != TWIST_OK)
        {
          free (der);
          return TWIST_ERR_TLS;
        }
      chain[n].data = der + used;
      chain[n].len = dlen;
      used += dlen;
      n++;
      at = stop + sizeof end - 1;
    }
  if (n == 0)
    {
      free (der);
      return TWIST_ERR_TLS;
    }
  *storage = der;
  *nchain = n;
  return TWIST_OK;
}

static int
read_file (const char *path, char **out, size_t *out_len)
{
  FILE *fp;
  char *buf;
  size_t cap = 4096;
  size_t n = 0;

  fp = fopen (path, "rb");
  if (fp == NULL)
    return TWIST_ERR_TLS;
  buf = malloc (cap);
  if (buf == NULL)
    {
      fclose (fp);
      return TWIST_ERR_NOMEM;
    }
  for (;;)
    {
      size_t got;

      if (n == cap)
        {
          size_t ncap = cap * 2;
          char *grown;

          if (ncap > TWIST_IN_CEILING)
            {
              free (buf);
              fclose (fp);
              return TWIST_ERR_TLS;
            }
          grown = realloc (buf, ncap);
          if (grown == NULL)
            {
              free (buf);
              fclose (fp);
              return TWIST_ERR_NOMEM;
            }
          buf = grown;
          cap = ncap;
        }
      got = fread (buf + n, 1, cap - n, fp);
      n += got;
      if (got == 0)
        break;
    }
  if (ferror (fp))
    {
      free (buf);
      fclose (fp);
      return TWIST_ERR_TLS;
    }
  fclose (fp);
  *out = buf;
  *out_len = n;
  return TWIST_OK;
}

int
twist_client_auth_load (struct twist_client_auth **out, const char *certfile,
                        const char *keyfile)
{
  struct twist_client_auth *auth;
  char *pem = NULL;
  size_t pem_len = 0;
  int rc;

  if (out == NULL)
    return TWIST_ERR_INVAL;
  *out = NULL;
  if ((certfile == NULL || certfile[0] == 0)
      && (keyfile == NULL || keyfile[0] == 0))
    return TWIST_OK;
  if (certfile == NULL || certfile[0] == 0 || keyfile == NULL
      || keyfile[0] == 0)
    return TWIST_ERR_INVAL;
  auth = calloc (1, sizeof *auth);
  if (auth == NULL)
    return TWIST_ERR_NOMEM;
  rc = read_file (certfile, &pem, &pem_len);
  if (rc != TWIST_OK)
    {
      free (auth);
      return rc;
    }
  rc = twist_pem_certificates (pem, pem_len, auth->chain, CHAIN_MAX,
                               &auth->nchain, &auth->der);
  free (pem);
  if (rc != TWIST_OK)
    {
      free (auth);
      return rc;
    }
  if (gq_privkey_from_pem_file (&auth->key, keyfile) != GQ_OK)
    {
      free (auth->der);
      free (auth);
      return TWIST_ERR_TLS;
    }
  *out = auth;
  return TWIST_OK;
}

void
twist_client_auth_free (struct twist_client_auth *auth)
{
  if (auth == NULL)
    return;
  gq_privkey_free (auth->key);
  free (auth->der);
  free (auth);
}

void
twist_client_auth_apply (const struct twist_client_auth *auth,
                         struct gq_tls_config *cfg)
{
  if (auth == NULL || cfg == NULL || auth->key == NULL || auth->nchain == 0)
    return;
  cfg->client_key = auth->key;
  cfg->client_chain = auth->chain;
  cfg->n_client_chain = auth->nchain;
}

int
twist_client_auth_missing (const struct gq_tls_info *info)
{
  return info != NULL && info->client_auth_requested && !info->client_auth_sent;
}
