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
#include <quickstep/trust.h>

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

/* A certificate valid, as its own authority, for dot.example and for
   192.0.2.53 (EC P-256, SHA-256, for a hundred years).  */
static const char names_pem[] =
    "-----BEGIN CERTIFICATE-----\n"
    "MIIByTCCAW6gAwIBAgIUR4Yg8tALVZqPtV5/4eXcaTbhrg0wCgYIKoZIzj0EAwIw\n"
    "FjEUMBIGA1UEAwwLZG90LmV4YW1wbGUwIBcNMjYxMDIyMTUyNjQyWhgPMjEyNjA5\n"
    "MjgxNTI2NDJaMBYxFDASBgNVBAMMC2RvdC5leGFtcGxlMFkwEwYHKoZIzj0CAQYI\n"
    "KoZIzj0DAQcDQgAEtMl4X1nBb0L8rfXMcjJI1tZkJbCGF8WQ0bfHcfOadqf5e+1R\n"
    "E9YFb0D5/CxtPVMbhMAHRg0sdVopo9shtnBP2aOBlzCBlDAdBgNVHQ4EFgQUXyow\n"
    "I0rxbfe46dKLIktIQpUZCYMwHwYDVR0jBBgwFoAUXyowI0rxbfe46dKLIktIQpUZ\n"
    "CYMwHAYDVR0RBBUwE4ILZG90LmV4YW1wbGWHBMAAAjUwDwYDVR0TAQH/BAUwAwEB\n"
    "/zAOBgNVHQ8BAf8EBAMCAoQwEwYDVR0lBAwwCgYIKwYBBQUHAwEwCgYIKoZIzj0E\n"
    "AwIDSQAwRgIhAKPYZj1GHnuII2DVqbafRHb1Nbry1N5j8BGDg4eTIqUIAiEAwnF3\n"
    "rOo0hMsUxrVWUNT5XQo4BA4MCDLdjQEZvcGKbrI=\n"
    "-----END CERTIFICATE-----\n"
    "";

/* A resolver found by discovery (RFC 9462 section 4.2) is found over plain
   UDP, so anyone who can answer that can name a resolver of their own, with a
   good certificate for its own name.  What they cannot have is a certificate
   that also covers the address of the resolver that was asked.  So both names
   must be proved, and a certificate for the first alone is not enough.  */
static void
test_verify_two_names (void)
{
  struct gq_trust *trust = NULL;
  struct gq_trust *empty = NULL;
  gq_slice chain[4];
  size_t n = 0;
  uint8_t *storage = NULL;

  check (gq_trust_new (&trust) == 0 && gq_trust_new (&empty) == 0, "trust");
  check (gq_trust_add_pem (trust, names_pem, sizeof names_pem - 1) == 0,
         "the certificate is an authority");
  check (twist_pem_certificates (names_pem, sizeof names_pem - 1, chain, 4, &n,
                                 &storage) == TWIST_OK && n == 1, "the chain");
  check (twist_verify_chain_names (trust, chain, n, "dot.example", NULL) == 0,
         "the resolver's name alone");
  check (twist_verify_chain_names (trust, chain, n, "dot.example",
                                   "192.0.2.53") == 0,
         "its name and the address that was asked");
  check (twist_verify_chain_names (trust, chain, n, "dot.example",
                                   "192.0.2.54") != 0,
         "not for another address");
  check (twist_verify_chain_names (trust, chain, n, "dot.example",
                                   "10.0.0.1") != 0,
         "nor a private one");
  check (twist_verify_chain_names (trust, chain, n, "evil.example",
                                   "192.0.2.53") != 0,
         "nor for another name");
  check (twist_verify_chain_names (trust, chain, n, "evil.example", NULL) != 0,
         "a wrong name alone");
  check (twist_verify_chain_names (empty, chain, n, "dot.example",
                                   "192.0.2.53") != 0,
         "no authority, no trust");
  free (storage);
  gq_trust_free (trust);
  gq_trust_free (empty);
}

int
main (void)
{
  test_client_auth ();
  test_verify_two_names ();
  return tests_finish ();
}
