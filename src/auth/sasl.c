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

/* Client SASL mechanisms protocols share.  Responses are raw bytes.
   The protocol base64-encodes them when the wire requires it.  */

struct twist_sasl_client
{
  int mech;
  char *user;
  char *pass;
  char *token;
  int step;
  int done;
};

void twist_sasl_client_free (struct twist_sasl_client *c);

static char *
dup_or_empty (const char *s)
{
  return twist_strdup (s != NULL ? s : "");
}

static int
emit (const void *data, size_t n, uint8_t **out, size_t *out_len)
{
  uint8_t *p = twist_xmalloc (n > 0 ? n : 1);

  if (p == NULL)
    return TWIST_ERR_NOMEM;
  if (n > 0)
    memcpy (p, data, n);
  *out = p;
  *out_len = n;
  return TWIST_OK;
}

int
twist_sasl_from_name (const char *name)
{
  if (name == NULL)
    return 0;
  if (strcasecmp (name, "PLAIN") == 0)
    return TWIST_SASL_PLAIN;
  if (strcasecmp (name, "LOGIN") == 0)
    return TWIST_SASL_LOGIN;
  if (strcasecmp (name, "XOAUTH2") == 0)
    return TWIST_SASL_XOAUTH2;
  return 0;
}

const char *
twist_sasl_name (int mech)
{
  switch (mech)
    {
    case TWIST_SASL_PLAIN:
      return "PLAIN";
    case TWIST_SASL_LOGIN:
      return "LOGIN";
    case TWIST_SASL_XOAUTH2:
      return "XOAUTH2";
    default:
      return NULL;
    }
}

struct twist_sasl_client *
twist_sasl_client_new (int mech, const char *user, const char *pass,
                       const char *token)
{
  struct twist_sasl_client *c;

  if (twist_sasl_name (mech) == NULL)
    return NULL;
  c = calloc (1, sizeof *c);
  if (c == NULL)
    return NULL;
  c->mech = mech;
  c->user = dup_or_empty (user);
  c->pass = dup_or_empty (pass);
  c->token = dup_or_empty (token);
  if (c->user == NULL || c->pass == NULL || c->token == NULL)
    {
      twist_sasl_client_free (c);
      return NULL;
    }
  return c;
}

void
twist_sasl_client_free (struct twist_sasl_client *c)
{
  if (c == NULL)
    return;
  free (c->user);
  free (c->pass);
  free (c->token);
  free (c);
}

int
twist_sasl_has_initial (const struct twist_sasl_client *c)
{
  return c != NULL
         && (c->mech == TWIST_SASL_PLAIN || c->mech == TWIST_SASL_XOAUTH2);
}

static int
plain_initial (struct twist_sasl_client *c, uint8_t **out, size_t *out_len)
{
  size_t nu = strlen (c->user);
  size_t np = strlen (c->pass);
  size_t n = nu + np + 2;
  uint8_t *p = twist_xmalloc (n);

  if (p == NULL)
    return TWIST_ERR_NOMEM;
  p[0] = 0;
  memcpy (p + 1, c->user, nu);
  p[1 + nu] = 0;
  memcpy (p + 2 + nu, c->pass, np);
  *out = p;
  *out_len = n;
  c->done = 1;
  return TWIST_OK;
}

static int
xoauth2_initial (struct twist_sasl_client *c, uint8_t **out, size_t *out_len)
{
  char *msg;
  int n;
  int rc;

  n = snprintf (NULL, 0, "user=%s\001auth=Bearer %s\001\001", c->user,
                c->token);
  if (n < 0)
    return TWIST_ERR_AUTH;
  msg = twist_xmalloc ((size_t) n + 1);
  if (msg == NULL)
    return TWIST_ERR_NOMEM;
  snprintf (msg, (size_t) n + 1, "user=%s\001auth=Bearer %s\001\001", c->user,
            c->token);
  rc = emit (msg, (size_t) n, out, out_len);
  free (msg);
  if (rc == TWIST_OK)
    c->done = 1;
  return rc;
}

int
twist_sasl_step (struct twist_sasl_client *c, const uint8_t *challenge,
                 size_t len, uint8_t **out, size_t *out_len, int *done)
{
  int rc;

  (void) challenge;
  (void) len;
  if (c == NULL || out == NULL || out_len == NULL || done == NULL)
    return TWIST_ERR_INVAL;
  *out = NULL;
  *out_len = 0;
  *done = 0;
  if (c->done)
    return TWIST_ERR_AUTH;
  switch (c->mech)
    {
    case TWIST_SASL_PLAIN:
      rc = plain_initial (c, out, out_len);
      break;
    case TWIST_SASL_XOAUTH2:
      rc = xoauth2_initial (c, out, out_len);
      break;
    case TWIST_SASL_LOGIN:
      if (c->step == 0)
        {
          c->step = 1;
          rc = emit (c->user, strlen (c->user), out, out_len);
        }
      else
        {
          c->done = 1;
          rc = emit (c->pass, strlen (c->pass), out, out_len);
        }
      break;
    default:
      rc = TWIST_ERR_UNSUPPORTED;
      break;
    }
  if (rc == TWIST_OK)
    *done = c->done;
  return rc;
}
