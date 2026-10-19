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

#include "check.h"
#include "twist-int.h"
#include <quickstep/tls.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void
test_client_auth (void)
{
  static const char pem[] =
    "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n"
    "-----BEGIN CERTIFICATE-----\nAQIDBA==\n-----END CERTIFICATE-----\n"
    "-----BEGIN CERTIFICATE-----\nBQYH\n-----END CERTIFICATE-----\n";
  gq_slice chain[4];
  size_t n = 0;
  uint8_t *storage = NULL;
  struct twist_client_auth *auth = NULL;
  struct gq_tls_info info;

  check (twist_pem_certificates (pem, sizeof pem - 1, chain, 4, &n, &storage)
         == TWIST_OK && n == 2, "pem certs");
  check (storage != NULL && chain[0].len == 4 && chain[0].data[0] == 1
         && chain[0].data[1] == 2 && chain[0].data[2] == 3
         && chain[0].data[3] == 4 && chain[1].len == 3
         && chain[1].data[0] == 5 && chain[1].data[1] == 6
         && chain[1].data[2] == 7, "pem der");
  free (storage);
  storage = NULL;
  check (twist_pem_certificates ("nope", 4, chain, 4, &n, &storage)
         == TWIST_ERR_TLS && storage == NULL, "pem none");
  check (twist_client_auth_load (&auth, NULL, NULL) == TWIST_OK
         && auth == NULL, "client auth absent");
  check (twist_client_auth_load (&auth, "cert.pem", NULL) == TWIST_ERR_INVAL,
         "client auth half");
  memset (&info, 0, sizeof info);
  check (!twist_client_auth_missing (&info), "mtls quiet");
  info.client_auth_requested = 1;
  check (twist_client_auth_missing (&info), "mtls required");
  info.client_auth_sent = 1;
  check (!twist_client_auth_missing (&info), "mtls sent");
}

int
main (void)
{
  test_client_auth ();
  return tests_finish ();
}
