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

#include <stdlib.h>
#include <string.h>
#include <strings.h>

/* Protocols share one SASL client.  The wire token is base64; the
   mechanism itself stays in src/auth.  */

const char *
twist_mail_user (const struct twist_transfer *transfer)
{
  if (transfer == NULL)
    return NULL;
  if (transfer->username != NULL && transfer->username[0] != 0)
    return transfer->username;
  if (transfer->url != NULL && transfer->url->user != NULL
      && transfer->url->user[0] != 0)
    return transfer->url->user;
  return NULL;
}

const char *
twist_mail_pass (const struct twist_transfer *transfer)
{
  if (transfer == NULL)
    return NULL;
  if (transfer->password != NULL)
    return transfer->password;
  if (transfer->url != NULL && transfer->url->password != NULL)
    return transfer->url->password;
  return "";
}

void
twist_mail_sasl_init (struct twist_mail_sasl *sasl)
{
  if (sasl != NULL)
    memset (sasl, 0, sizeof *sasl);
}

void
twist_mail_sasl_close (struct twist_mail_sasl *sasl)
{
  if (sasl == NULL)
    return;
  twist_sasl_client_free (sasl->client);
  sasl->client = NULL;
  sasl->done = 0;
}

static int
has_mech (const char *advertised, const char *name)
{
  size_t n;
  const char *p;

  if (advertised == NULL || advertised[0] == 0)
    return 1;
  n = strlen (name);
  for (p = advertised; *p != 0; )
    {
      while (*p == ' ')
        p++;
      if (strncasecmp (p, name, n) == 0
          && (p[n] == 0 || p[n] == ' '))
        return 1;
      while (*p != 0 && *p != ' ')
        p++;
    }
  return 0;
}

static int
encode_step (struct twist_mail_sasl *sasl, char **b64)
{
  uint8_t *raw = NULL;
  size_t n = 0;
  int done = 0;
  int rc;

  rc = twist_sasl_step (sasl->client, NULL, 0, &raw, &n, &done);
  if (rc != TWIST_OK)
    return rc;
  rc = twist_b64_encode (raw, n, b64);
  free (raw);
  if (rc == TWIST_OK)
    sasl->done = done;
  return rc;
}

int
twist_mail_sasl_start (struct twist_mail_sasl *sasl,
                       struct twist_transfer *transfer,
                       const char *advertised, char **b64, int *initial)
{
  const char *user;
  const char *pass;
  const char *token;
  int mech = 0;

  if (sasl == NULL || transfer == NULL || b64 == NULL || initial == NULL)
    return TWIST_ERR_INVAL;
  *b64 = NULL;
  *initial = 0;
  twist_mail_sasl_close (sasl);
  user = twist_mail_user (transfer);
  pass = twist_mail_pass (transfer);
  token = transfer->bearer != NULL ? transfer->bearer : "";
  if (token[0] != 0 && has_mech (advertised, "XOAUTH2"))
    mech = TWIST_SASL_XOAUTH2;
  else if (user != NULL && has_mech (advertised, "PLAIN"))
    mech = TWIST_SASL_PLAIN;
  else if (user != NULL && has_mech (advertised, "LOGIN"))
    mech = TWIST_SASL_LOGIN;
  else
    return TWIST_ERR_AUTH;
  sasl->client = twist_sasl_client_new (mech, user, pass, token);
  if (sasl->client == NULL)
    return TWIST_ERR_NOMEM;
  sasl->mech = mech;
  if (!twist_sasl_has_initial (sasl->client))
    return TWIST_OK;
  *initial = 1;
  return encode_step (sasl, b64);
}

int
twist_mail_sasl_continue (struct twist_mail_sasl *sasl, char **b64)
{
  if (sasl == NULL || b64 == NULL || sasl->client == NULL)
    return TWIST_ERR_INVAL;
  *b64 = NULL;
  if (sasl->done)
    return TWIST_ERR_AUTH;
  return encode_step (sasl, b64);
}
