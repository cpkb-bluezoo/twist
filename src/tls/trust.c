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

#include <quickstep/status.h>
#include <quickstep/trust.h>

#include <ctype.h>
#include <dirent.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* The certificate authorities a connection trusts, and the files that tell
   what to do with the secrets of the connections, for TLS (tls.c) and QUIC
   (quic.c) alike.  */

/* A file of a directory of authorities: the name ends in .pem, .crt or .cer,
   or is the hash that OpenSSL's c_rehash makes, eight hex digits, a dot and a
   number.  */
static int
ca_name (const char *name)
{
  size_t n = strlen (name);
  size_t i;

  if (n > 4 && (strcmp (name + n - 4, ".pem") == 0
                || strcmp (name + n - 4, ".crt") == 0
                || strcmp (name + n - 4, ".cer") == 0))
    return 1;
  if (n < 10 || name[8] != '.')
    return 0;
  for (i = 0; i < 8; i++)
    if (!isxdigit ((unsigned char) name[i]))
      return 0;
  for (i = 9; i < n; i++)
    if (!isdigit ((unsigned char) name[i]))
      return 0;
  return 1;
}

/* Add the certificates of the files of DIR.  A file that is not one is
   passed over.  Returns -1 if the directory cannot be read.  */
static int
add_dir (gq_trust *trust, const char *dir)
{
  DIR *d = opendir (dir);
  struct dirent *e;
  size_t dl = strlen (dir);
  int added = 0;

  if (d == NULL)
    return -1;
  while ((e = readdir (d)) != NULL)
    {
      size_t nl = strlen (e->d_name);
      char *path;
      struct stat st;

      if (!ca_name (e->d_name))
        continue;
      path = twist_xmalloc (dl + 1 + nl + 1);
      if (path == NULL)
        break;
      memcpy (path, dir, dl);
      path[dl] = '/';
      memcpy (path + dl + 1, e->d_name, nl + 1);
      if (stat (path, &st) == 0 && S_ISREG (st.st_mode)
          && gq_trust_add_pem_file (trust, path) == GQ_OK)
        added++;
      free (path);
    }
  closedir (d);
  return added;
}

/* Fill TRUST.  CAFILE and CAPATH are what the transfer was given (a file and
   a directory, both used); with neither, the environment's: TWIST_CA_BUNDLE
   as a file, else SSL_CERT_DIR as a directory and SSL_CERT_FILE as a file;
   with none of those, the system's.  What was asked for by name must load.
   What came from the environment must when the peer is verified, so that a
   stale variable does not stop a transfer that checks nothing.  */
int
twist_trust_load (gq_trust *trust, const char *cafile, const char *capath,
                  int verify)
{
  int given = cafile != NULL || capath != NULL;
  int must = given || verify;
  int rc = TWIST_OK;

  if (!given)
    {
      const char *bundle = getenv ("TWIST_CA_BUNDLE");
      const char *dir = getenv ("SSL_CERT_DIR");
      const char *file = getenv ("SSL_CERT_FILE");

      if (bundle != NULL && bundle[0] != 0)
        cafile = bundle;
      else
        {
          if (dir != NULL && dir[0] != 0)
            capath = dir;
          if (file != NULL && file[0] != 0)
            cafile = file;
        }
    }
  if (cafile == NULL && capath == NULL)
    {
      if (gq_trust_add_system (trust, NULL) != GQ_OK && verify)
        rc = TWIST_ERR_TLS;
      return rc;
    }
  if (cafile != NULL && gq_trust_add_pem_file (trust, cafile) != GQ_OK && must)
    rc = TWIST_ERR_TLS;
  if (capath != NULL && add_dir (trust, capath) < 0 && must)
    rc = TWIST_ERR_TLS;
  return rc;
}

/* The key log: the file named by SSLKEYLOGFILE gets a line for each secret of
   a connection, in the format that Wireshark reads.  Each line is written
   whole, with one write to a file opened to append, so that connections of
   several programs can share it.  */
int
twist_keylog_wanted (void)
{
  const char *path = getenv ("SSLKEYLOGFILE");

  return path != NULL && path[0] != 0;
}

void
twist_keylog_write (void *user, const char *line)
{
  const char *path = getenv ("SSLKEYLOGFILE");
  size_t n = strlen (line);
  char *buf;
  int fd;

  (void) user;
  if (path == NULL || path[0] == 0)
    return;
  buf = twist_xmalloc (n + 1);
  if (buf == NULL)
    return;
  memcpy (buf, line, n);
  buf[n] = '\n';
  fd = open (path, O_WRONLY | O_APPEND | O_CREAT | O_CLOEXEC, 0600);
  if (fd >= 0)
    {
      ssize_t put = write (fd, buf, n + 1);

      (void) put;
      close (fd);
    }
  free (buf);
}
