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

#include <quickstep/status.h>
#include <quickstep/trust.h>

#include <arpa/inet.h>
#include <dirent.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

/* The environment variables that reach the TLS and QUIC layers: QLOGDIR makes
   a log of a QUIC connection, SSLKEYLOGFILE takes the secrets of a TLS one.
   The certificate variables need a server, and are in integration/env.sh.  */

static void
test_keylog_writer (void)
{
  char dir[] = "/tmp/twist-env-XXXXXX";
  char path[128];
  char buf[256];
  struct stat st;
  FILE *fp;
  size_t n;

  check (mkdtemp (dir) != NULL, "temp dir");
  snprintf (path, sizeof path, "%s/keys", dir);
  unsetenv ("SSLKEYLOGFILE");
  check (!twist_keylog_wanted (), "no key log without the variable");
  setenv ("SSLKEYLOGFILE", "", 1);
  check (!twist_keylog_wanted (), "nor with an empty one");
  setenv ("SSLKEYLOGFILE", path, 1);
  check (twist_keylog_wanted (), "with it");
  twist_keylog_write (NULL, "CLIENT_TRAFFIC_SECRET_0 aa bb");
  twist_keylog_write (NULL, "SERVER_TRAFFIC_SECRET_0 cc dd");
  fp = fopen (path, "r");
  check (fp != NULL, "the file is made");
  n = fp != NULL ? fread (buf, 1, sizeof buf - 1, fp) : 0;
  buf[n] = 0;
  if (fp != NULL)
    fclose (fp);
  check (strcmp (buf, "CLIENT_TRAFFIC_SECRET_0 aa bb\n"
                      "SERVER_TRAFFIC_SECRET_0 cc dd\n") == 0,
         "a line each, added to the file");
  check (stat (path, &st) == 0 && (st.st_mode & 077) == 0,
         "readable by the owner only");
  unsetenv ("SSLKEYLOGFILE");
  unlink (path);
  rmdir (dir);
}


/* A self-signed authority, good from the year 2000 to 2999.  */
static const char ca_pem[] =
  "-----BEGIN CERTIFICATE-----\n"
  "MIIBQjCB6qADAgECAgEBMAoGCCqGSM49BAMCMBgxFjAUBgNVBAMMDXR3aXN0IHRl\n"
  "c3QgQ0EwIBcNMDAwMTAxMDAwMDAwWhgPMjk5OTEyMzEwMDAwMDBaMBgxFjAUBgNV\n"
  "BAMMDXR3aXN0IHRlc3QgQ0EwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQ5AR62\n"
  "6tzatUawNljQwiM4UL7nwLjP3OJd9HYEomiEbBOdgSYMI3NYcwxa0A+LNbgSOS9w\n"
  "N5TH9IbPRoqe7MESoyMwITAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIC\n"
  "BDAKBggqhkjOPQQDAgNHADBEAiAsbH4mFRQ3+URzRTxpr+Cf7M+PNPgx9X86nF+y\n"
  "DEQqUAIgWJaOJJKpiDptzdL4TGzEZMtMA8yngcwls6kS+Pz6aQc=\n"
  "-----END CERTIFICATE-----\n";

static void
put (const char *dir, const char *name, const char *text)
{
  char path[600];
  FILE *fp;

  snprintf (path, sizeof path, "%s/%s", dir, name);
  fp = fopen (path, "w");
  if (fp != NULL)
    {
      fputs (text, fp);
      fclose (fp);
    }
}

static void
drop (const char *dir, const char *name)
{
  char path[600];

  snprintf (path, sizeof path, "%s/%s", dir, name);
  unlink (path);
}

/* Whether a trust store made with these arguments trusts the authority's own
   certificate.  Returns the status of the load if it failed.  */
static int
trusts (const char *cafile, const char *capath, int verify, int *rc_out)
{
  gq_trust *trust = NULL;
  gq_slice chain[4];
  size_t n = 0;
  uint8_t *der = NULL;
  int rc;
  int ok;

  check (gq_trust_new (&trust) == GQ_OK, "a trust store");
  rc = twist_trust_load (trust, cafile, capath, verify);
  if (rc_out != NULL)
    *rc_out = rc;
  check (twist_pem_certificates (ca_pem, sizeof ca_pem - 1, chain, 4, &n, &der)
         == TWIST_OK && n == 1, "the certificate");
  ok = gq_trust_verify_chain (trust, chain, n, NULL, NULL) == GQ_OK;
  free (der);
  gq_trust_free (trust);
  return ok;
}

static void
clear_ca_env (void)
{
  unsetenv ("TWIST_CA_BUNDLE");
  unsetenv ("SSL_CERT_FILE");
  unsetenv ("SSL_CERT_DIR");
}

static void
test_trust (void)
{
  char dir[] = "/tmp/twist-trust-XXXXXX";
  char sub[128], bundle[160], hashed[160], junk[160], missing[160];
  int rc = -1;

  check (mkdtemp (dir) != NULL, "temp dir");
  clear_ca_env ();
  snprintf (sub, sizeof sub, "%s/dir", dir);
  snprintf (hashed, sizeof hashed, "%s/hashed", dir);
  snprintf (junk, sizeof junk, "%s/junk", dir);
  snprintf (bundle, sizeof bundle, "%s/ca.pem", dir);
  snprintf (missing, sizeof missing, "%s/missing", dir);
  mkdir (sub, 0700);
  mkdir (hashed, 0700);
  mkdir (junk, 0700);
  put (dir, "ca.pem", ca_pem);
  put (sub, "authority.pem", ca_pem);
  put (hashed, "87c2c640.0", ca_pem);
  put (junk, "readme.txt", ca_pem);
  put (junk, "empty.pem", "");
  put (junk, "87c2c64.0", ca_pem);
  put (junk, "zzzzzzzz.0", ca_pem);
  put (junk, "87c2c640.x", ca_pem);

  /* What is given.  */
  check (trusts (bundle, NULL, 1, &rc) && rc == TWIST_OK, "a file");
  check (trusts (NULL, sub, 1, &rc) && rc == TWIST_OK, "a directory");
  check (trusts (NULL, hashed, 1, &rc) && rc == TWIST_OK,
         "a directory of hashed names");
  check (!trusts (NULL, junk, 1, &rc) && rc == TWIST_OK,
         "files that are not authorities are passed over");
  check (trusts (bundle, junk, 1, &rc) && rc == TWIST_OK, "both");
  check (trusts (missing, sub, 1, &rc) && rc == TWIST_ERR_TLS,
         "what is not there is an error, the rest still loaded");
  trusts (missing, NULL, 0, &rc);
  check (rc == TWIST_ERR_TLS, "a file that is not there is an error, verified or not");
  trusts (NULL, missing, 0, &rc);
  check (rc == TWIST_ERR_TLS, "and a directory");

  /* The environment, when nothing is given.  */
  setenv ("SSL_CERT_FILE", bundle, 1);
  check (trusts (NULL, NULL, 1, &rc) && rc == TWIST_OK, "SSL_CERT_FILE");
  clear_ca_env ();
  setenv ("SSL_CERT_DIR", sub, 1);
  check (trusts (NULL, NULL, 1, &rc) && rc == TWIST_OK, "SSL_CERT_DIR");
  clear_ca_env ();
  setenv ("SSL_CERT_DIR", junk, 1);
  setenv ("SSL_CERT_FILE", bundle, 1);
  check (trusts (NULL, NULL, 1, &rc) && rc == TWIST_OK, "both of them");
  clear_ca_env ();
  setenv ("TWIST_CA_BUNDLE", bundle, 1);
  check (trusts (NULL, NULL, 1, &rc) && rc == TWIST_OK, "TWIST_CA_BUNDLE");
  setenv ("SSL_CERT_FILE", missing, 1);
  check (trusts (NULL, NULL, 1, &rc) && rc == TWIST_OK,
         "TWIST_CA_BUNDLE, and not SSL_CERT_FILE");
  clear_ca_env ();
  setenv ("TWIST_CA_BUNDLE", junk, 1);
  setenv ("SSL_CERT_FILE", bundle, 1);
  check (!trusts (NULL, NULL, 1, &rc), "TWIST_CA_BUNDLE alone when it is set");
  clear_ca_env ();
  setenv ("SSL_CERT_FILE", "", 1);
  setenv ("SSL_CERT_DIR", "", 1);

  /* What is given is not mixed with the environment.  */
  clear_ca_env ();
  setenv ("SSL_CERT_FILE", bundle, 1);
  check (!trusts (NULL, junk, 1, &rc), "a directory given: not SSL_CERT_FILE");
  check (!trusts (missing, NULL, 1, &rc), "a file given: not SSL_CERT_FILE");

  /* A variable that is wrong is an error when the peer is checked.  */
  clear_ca_env ();
  setenv ("SSL_CERT_FILE", missing, 1);
  trusts (NULL, NULL, 1, &rc);
  check (rc == TWIST_ERR_TLS, "SSL_CERT_FILE that is not there");
  trusts (NULL, NULL, 0, &rc);
  check (rc == TWIST_OK, "and is no matter when nothing is checked");
  clear_ca_env ();
  setenv ("SSL_CERT_DIR", missing, 1);
  trusts (NULL, NULL, 1, &rc);
  check (rc == TWIST_ERR_TLS, "SSL_CERT_DIR that is not there");
  trusts (NULL, NULL, 0, &rc);
  check (rc == TWIST_OK, "likewise");
  clear_ca_env ();

  unlink (bundle);
  drop (sub, "authority.pem");
  drop (hashed, "87c2c640.0");
  drop (junk, "readme.txt");
  drop (junk, "empty.pem");
  drop (junk, "87c2c64.0");
  drop (junk, "zzzzzzzz.0");
  drop (junk, "87c2c640.x");
  rmdir (sub);
  rmdir (hashed);
  rmdir (junk);
  rmdir (dir);
}

/* A QUIC connection to a port where nothing answers still sends its Initial,
   and that is events enough.  */
static void
test_qlog (void)
{
  char dir[] = "/tmp/twist-qlog-XXXXXX";
  struct twist_loop *loop = twist_loop_new (1);
  struct twist_connection *conn = NULL;
  struct twist_dns_addr addr;
  struct sockaddr_in sin;
  socklen_t sl = sizeof sin;
  int udp = socket (AF_INET, SOCK_DGRAM, 0);
  DIR *d;
  struct dirent *e;
  char name[600] = "";
  int files = 0;
  int rc;

  check (mkdtemp (dir) != NULL && loop != NULL && udp >= 0, "set up");
  memset (&sin, 0, sizeof sin);
  sin.sin_family = AF_INET;
  inet_pton (AF_INET, "127.0.0.1", &sin.sin_addr);
  check (bind (udp, (struct sockaddr *) &sin, sl) == 0
         && getsockname (udp, (struct sockaddr *) &sin, &sl) == 0, "a port");
  memset (&addr, 0, sizeof addr);
  addr.family = 4;
  inet_pton (AF_INET, "127.0.0.1", addr.addr);

  /* Without the variable: no file.  */
  unsetenv ("QLOGDIR");
  rc = twist_quic_dial (loop, "example.test", "h3", &addr,
                        ntohs (sin.sin_port), NULL, NULL, NULL, NULL, &conn);
  check (rc == TWIST_OK && conn != NULL, "dial without QLOGDIR");
  twist_connection_free (conn);
  d = opendir (dir);
  while (d != NULL && (e = readdir (d)) != NULL)
    files += e->d_name[0] != '.';
  if (d != NULL)
    closedir (d);
  check (files == 0, "no log without QLOGDIR");

  setenv ("QLOGDIR", dir, 1);
  conn = NULL;
  rc = twist_quic_dial (loop, "example.test", "h3", &addr,
                        ntohs (sin.sin_port), NULL, NULL, NULL, NULL, &conn);
  check (rc == TWIST_OK && conn != NULL, "dial with QLOGDIR");
  twist_connection_free (conn);
  files = 0;
  d = opendir (dir);
  while (d != NULL && (e = readdir (d)) != NULL)
    if (e->d_name[0] != '.')
      {
        files++;
        snprintf (name, sizeof name, "%s/%s", dir, e->d_name);
      }
  if (d != NULL)
    closedir (d);
  check (files == 1, "one log for the connection");
  if (files == 1)
    {
    size_t n = strlen (name);
    char text[8192];
    size_t got = 0;
    FILE *fp = fopen (name, "r");
    struct stat st;

    check (n > 5 && strcmp (name + n - 5, ".qlog") == 0, "named .qlog");
    if (fp != NULL)
      {
        got = fread (text, 1, sizeof text - 1, fp);
        fclose (fp);
      }
    text[got] = 0;
    check (strstr (text, " quic:connection_started") != NULL,
           "it starts with the connection");
    check (strstr (text, " quic:packet_sent ") != NULL, "and has the Initial");
    check (text[0] >= '0' && text[0] <= '9', "each line starts with a time");
    check (stat (name, &st) == 0 && (st.st_mode & 077) == 0,
           "readable by the owner only");
    {
      /* The name is the connection ID in hex.  */
      const char *base = strrchr (name, '/') + 1;
      size_t k;

      check (strlen (base) >= 9, "named after the connection ID");
      for (k = 0; base[k] != '.' && base[k] != 0; k++)
        if (!((base[k] >= '0' && base[k] <= '9')
              || (base[k] >= 'a' && base[k] <= 'f')))
          break;
      check (base[k] == '.', "in hex");
    }
    unlink (name);
  }
  /* A directory that is not there is no log, and no harm.  */
  setenv ("QLOGDIR", "/nonexistent/twist/qlog", 1);
  conn = NULL;
  rc = twist_quic_dial (loop, "example.test", "h3", &addr,
                        ntohs (sin.sin_port), NULL, NULL, NULL, NULL, &conn);
  check (rc == TWIST_OK && conn != NULL, "dial with a bad QLOGDIR");
  twist_connection_free (conn);
  unsetenv ("QLOGDIR");
  close (udp);
  twist_loop_free (loop);
  rmdir (dir);
}

int
main (void)
{
  test_keylog_writer ();
  test_trust ();
  test_qlog ();
  return tests_finish ();
}
