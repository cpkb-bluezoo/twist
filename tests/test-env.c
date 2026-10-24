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


/* A self-signed authority, good from the year 2000 to 2999.  Its key usage
   has digitalSignature as well as keyCertSign: the chain is this one
   certificate, so quickstep checks it as it checks a server's own, and
   refuses a leaf that cannot sign a handshake.  */
static const char ca_pem[] =
  "-----BEGIN CERTIFICATE-----\n"
  "MIIBQjCB6qADAgECAgEBMAoGCCqGSM49BAMCMBgxFjAUBgNVBAMMDXR3aXN0IHRl\n"
  "c3QgQ0EwIBcNMDAwMTAxMDAwMDAwWhgPMjk5OTEyMzEwMDAwMDBaMBgxFjAUBgNV\n"
  "BAMMDXR3aXN0IHRlc3QgQ0EwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQGOHkV\n"
  "gx10KFFFG7mahjVswfl2pYZRzR9dCPbuwalmr/rwPer4illNs6M7UPz90H4CDJGa\n"
  "9HBZLfDUphOyll4doyMwITAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIC\n"
  "hDAKBggqhkjOPQQDAgNHADBEAiBeJGusEYeRyxURPX5wzl6LfkLNrGcMnycJwHmP\n"
  "wqmoMQIgLGetpxOAqf2EXlxyEv7A0edTCcjtQMIlqQhguvs3shU=\n"
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
                        ntohs (sin.sin_port), NULL, NULL, NULL, NULL, 1, NULL, &conn);
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
                        ntohs (sin.sin_port), NULL, NULL, NULL, NULL, 1, NULL, &conn);
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
                        ntohs (sin.sin_port), NULL, NULL, NULL, NULL, 1, NULL, &conn);
  check (rc == TWIST_OK && conn != NULL, "dial with a bad QLOGDIR");
  twist_connection_free (conn);
  unsetenv ("QLOGDIR");
  close (udp);
  twist_loop_free (loop);
  rmdir (dir);
}

/* Direct HTTP/3 dials the address a lookup gave, but the certificate must be
   checked against the host of the URL.  It was checked against the address,
   so that anyone who could answer the lookup, and held a certificate that
   names their own address, was taken for the origin.  The address stands in
   for the lookup here and nothing answers at it.  */
static void
test_quic_server_name (void)
{
  struct twist_loop *loop = twist_loop_new (0);
  struct twist_transfer *transfer = twist_transfer_new ();
  struct twist_connection *conn = NULL;
  struct twist_dns_addr addr;
  struct sockaddr_in sin;
  socklen_t sl = sizeof sin;
  int udp = socket (AF_INET, SOCK_DGRAM, 0);
  char url[64];
  const char *name;
  int rc;

  check (loop != NULL && transfer != NULL && udp >= 0, "name test set up");
  check (twist_quic_register () == TWIST_OK && twist_quic_connect_fn != NULL,
         "the QUIC dialer is registered");
  memset (&sin, 0, sizeof sin);
  sin.sin_family = AF_INET;
  inet_pton (AF_INET, "127.0.0.1", &sin.sin_addr);
  check (bind (udp, (struct sockaddr *) &sin, sl) == 0
         && getsockname (udp, (struct sockaddr *) &sin, &sl) == 0, "a port");
  memset (&addr, 0, sizeof addr);
  addr.family = 4;
  inet_pton (AF_INET, "127.0.0.1", addr.addr);
  snprintf (url, sizeof url, "https://example.test:%d/", ntohs (sin.sin_port));
  check (twist_url_parse_int (url, &transfer->url) == TWIST_OK
         && transfer->url != NULL, "a URL");
  transfer->loop = loop;

  rc = twist_quic_connect_fn (transfer, &addr, ntohs (sin.sin_port), &conn);
  check (rc == TWIST_OK && conn != NULL, "dial");
  name = conn != NULL ? twist_quic_server_name (conn) : NULL;
  check (name != NULL && strcmp (name, "example.test") == 0,
         "the server name is the host of the URL, not the address");
  if (conn != NULL)
    twist_connection_free (conn);
  twist_transfer_free (transfer);
  close (udp);
  twist_loop_free (loop);
}

/* The environment of a privileged process is not its own.  A process that is
   set-user-ID, or set-group-ID, or has capabilities, and links libtwist, took
   its trust store from SSL_CERT_FILE, its secrets' log from SSLKEYLOGFILE, its
   proxy from the *_proxy variables, its agent from SSH_AUTH_SOCK: all of them
   chosen by whoever ran it.  They are not read there.  */
static void
test_privileged_environment (void)
{
  char dir[] = "/tmp/twist-priv-XXXXXX";
  char path[128];
  int rc = 0;

  setenv ("TWIST_TEST_SECURE", "value", 1);
  twist_set_privileged (0);
  check (twist_getenv_secure ("TWIST_TEST_SECURE") != NULL
         && strcmp (twist_getenv_secure ("TWIST_TEST_SECURE"), "value") == 0,
         "an ordinary process reads its environment");
  twist_set_privileged (1);
  check (twist_getenv_secure ("TWIST_TEST_SECURE") == NULL,
         "a privileged one does not");
  twist_set_privileged (0);
  unsetenv ("TWIST_TEST_SECURE");
  check (twist_getenv_secure ("TWIST_TEST_SECURE") == NULL, "unset is NULL");
  twist_set_privileged (-1);
  check (twist_getenv_secure ("PATH") != NULL, "and by default, it asks the system");

  /* The trust store of the environment, which fails when it is not there, is
     not looked at.  */
  clear_ca_env ();
  setenv ("SSL_CERT_FILE", "/nonexistent/twist/ca.pem", 1);
  twist_set_privileged (0);
  trusts (NULL, NULL, 1, &rc);
  check (rc == TWIST_ERR_TLS, "an ordinary process takes SSL_CERT_FILE");
  twist_set_privileged (1);
  trusts (NULL, NULL, 1, &rc);
  check (rc == TWIST_OK, "a privileged one does not");
  clear_ca_env ();

  /* The key log is not written.  */
  check (mkdtemp (dir) != NULL, "temp dir");
  snprintf (path, sizeof path, "%s/keys", dir);
  setenv ("SSLKEYLOGFILE", path, 1);
  twist_set_privileged (0);
  check (twist_keylog_wanted (), "an ordinary process logs keys");
  twist_set_privileged (1);
  check (!twist_keylog_wanted (), "a privileged one does not");
  twist_set_privileged (-1);
  unsetenv ("SSLKEYLOGFILE");
  rmdir (dir);
}

/* Which streams of a QUIC connection are the transfer's.  The client opens
   the bidirectional ones (ids 0, 4, 8...); the server may open unidirectional
   ones (3, 7, 11...), which are ignored, and may not open a bidirectional one
   (1, 5, 9...), which ends the connection.  */
static void
test_quic_stream_action (void)
{
  uint64_t i;
  int ok = 1;

  check (twist_quic_stream_action (0, 1) == 0 && twist_quic_stream_action (4, 1) == 0,
         "a stream of ours is the transfer's");
  check (twist_quic_stream_action (0, 0) == 0 && twist_quic_stream_action (8, 0) == 0,
         "so is data on a client stream that is not tracked, as it was");
  check (twist_quic_stream_action (3, 0) == 1 && twist_quic_stream_action (7, 0) == 1
         && twist_quic_stream_action (11, 0) == 1,
         "a unidirectional stream of the server is ignored");
  check (twist_quic_stream_action (1, 0) == 2 && twist_quic_stream_action (5, 0) == 2
         && twist_quic_stream_action (9, 0) == 2,
         "a bidirectional stream of the server is an error");
  for (i = 0; i < 4096; i++)
    if ((i & 3) == 1 && twist_quic_stream_action (i, 0) != 2)
      ok = 0;
  check (ok, "all of them");
  check (twist_quic_stream_action (1, 1) == 0,
         "unless it was one we opened, which no server stream is");
}

int
main (void)
{
  test_keylog_writer ();
  test_trust ();
  test_qlog ();
  test_quic_server_name ();
  test_quic_stream_action ();
  test_privileged_environment ();
  return tests_finish ();
}
