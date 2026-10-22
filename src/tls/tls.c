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

#include <quickstep/crypto.h>
#include <quickstep/status.h>
#include <quickstep/tlsauto.h>
#include <quickstep/trust.h>

#include <stdlib.h>
#include <string.h>

struct twist_tls
{
  gq_tlsauto *tls;
  gq_trust *trust;
  struct twist_client_auth *auth;
  gq_slice alpn[2];
  uint8_t alpn_mem[2][16];
  size_t n_alpn;
  char *server_name;
};

static int
tls_write (void *user, const uint8_t *data, size_t len)
{
  struct twist_connection *c = user;

  return twist_connection_queue_out (c, data, len) == TWIST_OK ? 0 : -1;
}

static int
tls_data (void *user, const uint8_t *data, size_t len)
{
  twist_connection_deliver_app (user, data, len);
  return 0;
}

static int
tls_connected (void *user, const gq_tls_info *info)
{
  const char *alpn = "";
  size_t n = 0;

  if (twist_client_auth_missing (info))
    return -1;
  if (info != NULL && info->alpn_len > 0)
    {
      alpn = (const char *) info->alpn;
      n = info->alpn_len;
    }
  twist_connection_set_alpn (user, alpn, n);
  return 0;
}

static int
tls_ticket (void *user, const gq_tls_ticket *ticket)
{
  (void) user;
  (void) ticket;
  return 0;
}

static int
tls_early (void *user, const uint8_t *data, size_t len)
{
  (void) user;
  (void) data;
  (void) len;
  return 0;
}

static void
tls_early_result (void *user, int accepted)
{
  (void) user;
  (void) accepted;
}

static void
tls_closed (void *user, int error, int alert)
{
  (void) alert;
  twist_connection_fail (user, error == 0 ? TWIST_OK : TWIST_ERR_TLS);
}

static void
tls_free (void *p)
{
  struct twist_tls *t = p;

  if (t == NULL)
    return;
  gq_tlsauto_free (t->tls);
  gq_trust_free (t->trust);
  twist_client_auth_free (t->auth);
  free (t->server_name);
  free (t);
}

static int
tls_start (struct twist_connection *conn, const struct twist_tls_want *want)
{
  struct twist_tls *t;
  gq_tls_config cfg;
  gq_tlsconn_events ev;
  size_t i;
  int rc;

  if (conn == NULL || want == NULL)
    return TWIST_ERR_INVAL;
  if (gq_crypto_init () != GQ_OK)
    return TWIST_ERR_TLS;
  t = calloc (1, sizeof *t);
  if (t == NULL)
    return TWIST_ERR_NOMEM;
  if (gq_trust_new (&t->trust) != GQ_OK)
    {
      free (t);
      return TWIST_ERR_TLS;
    }
  rc = twist_trust_load (t->trust, want->cafile, want->capath, want->verify);
  if (rc != TWIST_OK)
    {
      tls_free (t);
      return rc;
    }
  t->server_name = twist_strdup (want->server_name);
  for (i = 0; i < want->n_alpn && i < 2; i++)
    {
      size_t n = strlen (want->alpn[i]);
      if (n > sizeof t->alpn_mem[i])
        n = sizeof t->alpn_mem[i];
      memcpy (t->alpn_mem[i], want->alpn[i], n);
      t->alpn[i].data = t->alpn_mem[i];
      t->alpn[i].len = n;
      t->n_alpn++;
    }
  rc = twist_client_auth_load (&t->auth, want->certfile, want->keyfile);
  if (rc != TWIST_OK)
    {
      tls_free (t);
      return rc;
    }
  memset (&cfg, 0, sizeof cfg);
  cfg.server_name = t->server_name;
  cfg.alpn = t->n_alpn > 0 ? t->alpn : NULL;
  cfg.n_alpn = t->n_alpn;
  cfg.trust = t->trust;
  if (twist_keylog_wanted ())
    cfg.keylog = twist_keylog_write;
  twist_client_auth_apply (t->auth, &cfg);
  memset (&ev, 0, sizeof ev);
  ev.user = conn;
  ev.write = tls_write;
  ev.data = tls_data;
  ev.connected = tls_connected;
  ev.ticket = tls_ticket;
  ev.early_data = tls_early;
  ev.early_data_result = tls_early_result;
  ev.closed = tls_closed;
  /* -k: the chain is not looked at.  */
  if (!want->verify)
    ev.verify_peer = twist_verify_accept;
  rc = gq_tlsauto_client_new (&t->tls, &cfg, &ev, 0);
  if (rc != GQ_OK)
    {
      tls_free (t);
      return TWIST_ERR_TLS;
    }
  twist_connection_set_tls (conn, t, tls_free);
  if (gq_tlsauto_start (t->tls) != GQ_OK)
    return TWIST_ERR_TLS;
  return TWIST_OK;
}

static int
tls_receive (struct twist_connection *conn, const uint8_t *data, size_t len)
{
  struct twist_tls *t = twist_connection_tls (conn);

  if (t == NULL || t->tls == NULL)
    return TWIST_ERR_TLS;
  if (len == 0)
    return TWIST_OK;
  if (gq_tlsauto_receive (t->tls, data, len) != GQ_OK)
    return TWIST_ERR_TLS;
  return TWIST_OK;
}

static int
tls_send_plain (struct twist_connection *conn, const uint8_t *data, size_t len)
{
  struct twist_tls *t = twist_connection_tls (conn);

  if (t == NULL || t->tls == NULL)
    return TWIST_ERR_TLS;
  if (gq_tlsauto_send (t->tls, data, len) != GQ_OK)
    return TWIST_ERR_TLS;
  return TWIST_OK;
}

int
twist_tls_register (void)
{
  twist_tls_start_fn = tls_start;
  twist_tls_receive_fn = tls_receive;
  twist_tls_send_plain_fn = tls_send_plain;
  return TWIST_OK;
}
