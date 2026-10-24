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

#include <ctype.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

/* The hosts file, and the names that need no lookup.  A name is looked for here
   before any DNS is asked, so that a name that is only on this machine can be
   reached, and does not go out to a resolver that does not know it.

   The file is read into a table of its names, when it is first asked of and
   again when it changes (its size, time, or inode), so that a lookup is a hash
   and not a read of a file that can be as long as the lists that block
   advertisements.  Loops on several threads ask: the lock covers the check, the
   read, and the lookup, and nothing is called with it held.  */

#define HOSTS_DEFAULT "/etc/hosts"
#define HOSTS_MAX (64u * 1024 * 1024)   /* A larger file is not read.  */
#define NAME_MAX_LEN 253

struct host_rec
{
  struct host_rec *next;
  int has4;
  int has6;
  struct twist_dns_addr a4;     /* The first IPv4 address of the name.  */
  struct twist_dns_addr a6;     /* And the first IPv6 one.  */
  char name[1];
};

struct host_table
{
  struct host_rec **bucket;
  size_t nbucket;               /* A power of two.  */
};

static pthread_mutex_t hosts_lock = PTHREAD_MUTEX_INITIALIZER;
static char *hosts_override;    /* twist_dns_set_hosts_file.  */
static char *hosts_loaded;      /* The path the table is of.  */
static int hosts_stat_ok;       /* The file was there.  */
static struct stat hosts_stat;
static struct host_table *hosts_tab;

static unsigned long
hash_name (const char *s)
{
  unsigned long h = 5381ul;

  for (; *s != 0; s++)
    h = h * 33ul + (unsigned char) *s;
  return h;
}

static void
table_free (struct host_table *t)
{
  size_t i;

  if (t == NULL)
    return;
  for (i = 0; i < t->nbucket; i++)
    {
      struct host_rec *r = t->bucket[i];

      while (r != NULL)
        {
          struct host_rec *next = r->next;

          free (r);
          r = next;
        }
    }
  free (t->bucket);
  free (t);
}

/* NAME in lower case with one dot at its end taken off, in OUT.  False if it
   is empty or too long to be a name.  */
static int
normalise (const char *name, char *out, size_t cap)
{
  size_t n = strlen (name);
  size_t i;

  if (n > 0 && name[n - 1] == '.')
    n--;
  if (n == 0 || n > NAME_MAX_LEN || n >= cap)
    return 0;
  for (i = 0; i < n; i++)
    out[i] = (char) tolower ((unsigned char) name[i]);
  out[n] = 0;
  return 1;
}

static struct host_rec *
table_find (const struct host_table *t, const char *name)
{
  struct host_rec *r;

  for (r = t->bucket[hash_name (name) & (t->nbucket - 1)]; r != NULL; r = r->next)
    if (strcmp (r->name, name) == 0)
      return r;
  return NULL;
}

/* Note that NAME is at ADDR, keeping the first of each family.  */
static int
table_add (struct host_table *t, const char *name,
           const struct twist_dns_addr *addr)
{
  struct host_rec *r = table_find (t, name);

  if (r == NULL)
    {
      size_t at = hash_name (name) & (t->nbucket - 1);

      r = calloc (1, sizeof *r + strlen (name));
      if (r == NULL)
        return TWIST_ERR_NOMEM;
      strcpy (r->name, name);
      r->next = t->bucket[at];
      t->bucket[at] = r;
    }
  if (addr->family == 4 && !r->has4)
    {
      r->a4 = *addr;
      r->has4 = 1;
    }
  else if (addr->family == 6 && !r->has6)
    {
      r->a6 = *addr;
      r->has6 = 1;
    }
  return TWIST_OK;
}

/* One line: an address, then names.  A # ends the line.  A line whose address
   is not one is not used.  */
static int
table_line (struct host_table *t, char *line)
{
  char *hash = strchr (line, '#');
  char *p = line;
  char *tok;
  struct twist_dns_addr addr;
  int rc = TWIST_OK;

  if (hash != NULL)
    *hash = 0;
  while (*p != 0 && isspace ((unsigned char) *p))
    p++;
  tok = p;
  while (*p != 0 && !isspace ((unsigned char) *p))
    p++;
  if (tok == p)
    return TWIST_OK;
  if (*p != 0)
    *p++ = 0;
  if (!twist_dns_literal (tok, &addr))
    return TWIST_OK;
  while (rc == TWIST_OK)
    {
      char name[NAME_MAX_LEN + 2];

      while (*p != 0 && isspace ((unsigned char) *p))
        p++;
      if (*p == 0)
        break;
      tok = p;
      while (*p != 0 && !isspace ((unsigned char) *p))
        p++;
      if (*p != 0)
        *p++ = 0;
      if (normalise (tok, name, sizeof name))
        rc = table_add (t, name, &addr);
    }
  return rc;
}

static struct host_table *
table_read (const char *path, const struct stat *st)
{
  struct host_table *t;
  FILE *fp;
  char *buf;
  size_t n, lines = 1, i, nb = 64;
  char *line, *end;

  if ((unsigned long long) st->st_size > HOSTS_MAX)
    return NULL;
  fp = fopen (path, "rb");
  if (fp == NULL)
    return NULL;
  buf = malloc ((size_t) st->st_size + 1);
  if (buf == NULL)
    {
      fclose (fp);
      return NULL;
    }
  n = fread (buf, 1, (size_t) st->st_size, fp);
  fclose (fp);
  buf[n] = 0;
  for (i = 0; i < n; i++)
    if (buf[i] == '\n')
      lines++;
  while (nb < lines)
    nb <<= 1;
  t = calloc (1, sizeof *t);
  if (t != NULL)
    t->bucket = calloc (nb, sizeof *t->bucket);
  if (t == NULL || t->bucket == NULL)
    {
      free (t);
      free (buf);
      return NULL;
    }
  t->nbucket = nb;
  for (line = buf; line < buf + n; line = end + 1)
    {
      end = memchr (line, '\n', (size_t) (buf + n - line));
      if (end == NULL)
        end = buf + n;
      *end = 0;
      if (table_line (t, line) != TWIST_OK)
        {
          table_free (t);
          free (buf);
          return NULL;
        }
    }
  free (buf);
  return t;
}

static int
same_file (const struct stat *a, const struct stat *b)
{
  if (a->st_size != b->st_size || a->st_ino != b->st_ino
      || a->st_dev != b->st_dev || a->st_mtime != b->st_mtime)
    return 0;
#if defined __APPLE__
  return a->st_mtimespec.tv_nsec == b->st_mtimespec.tv_nsec;
#elif defined __linux__
  return a->st_mtim.tv_nsec == b->st_mtim.tv_nsec;
#else
  return 1;
#endif
}

/* Make the table that of PATH as it is now.  */
static void
table_refresh (const char *path)
{
  struct stat st;
  int have = stat (path, &st) == 0 && S_ISREG (st.st_mode);

  if (hosts_loaded != NULL && strcmp (hosts_loaded, path) == 0
      && have == hosts_stat_ok && (!have || same_file (&st, &hosts_stat)))
    return;
  table_free (hosts_tab);
  hosts_tab = NULL;
  free (hosts_loaded);
  hosts_loaded = twist_strdup (path);
  hosts_stat_ok = have;
  if (have)
    {
      hosts_stat = st;
      hosts_tab = table_read (path, &st);
    }
}

int
twist_hosts_lookup (const char *path, const char *host,
                    struct twist_dns_addr *out)
{
  char name[NAME_MAX_LEN + 2];
  const struct host_rec *r;
  int found = 0;

  if (host == NULL || out == NULL || !normalise (host, name, sizeof name))
    return 0;
  pthread_mutex_lock (&hosts_lock);
  if (path == NULL)
    path = hosts_override != NULL ? hosts_override : HOSTS_DEFAULT;
  table_refresh (path);
  r = hosts_tab != NULL ? table_find (hosts_tab, name) : NULL;
  if (r != NULL && (r->has4 || r->has6))
    {
      *out = r->has4 ? r->a4 : r->a6;
      found = 1;
    }
  pthread_mutex_unlock (&hosts_lock);
  return found;
}

int
twist_hosts_lookup_all (const char *path, const char *host,
                        struct twist_dns_addr out[2])
{
  char name[NAME_MAX_LEN + 2];
  const struct host_rec *r;
  int n = 0;

  if (host == NULL || out == NULL || !normalise (host, name, sizeof name))
    return 0;
  pthread_mutex_lock (&hosts_lock);
  if (path == NULL)
    path = hosts_override != NULL ? hosts_override : HOSTS_DEFAULT;
  table_refresh (path);
  r = hosts_tab != NULL ? table_find (hosts_tab, name) : NULL;
  if (r != NULL)
    {
      if (r->has6)
        out[n++] = r->a6;
      if (r->has4)
        out[n++] = r->a4;
    }
  pthread_mutex_unlock (&hosts_lock);
  return n;
}

void
twist_dns_set_hosts_file (const char *path)
{
  pthread_mutex_lock (&hosts_lock);
  free (hosts_override);
  hosts_override = path != NULL ? twist_strdup (path) : NULL;
  free (hosts_loaded);
  hosts_loaded = NULL;
  pthread_mutex_unlock (&hosts_lock);
}

int
twist_dns_local_name (const char *host, struct twist_dns_addr *out)
{
  char name[NAME_MAX_LEN + 2];
  size_t n, i;

  if (host == NULL || !normalise (host, name, sizeof name))
    return 0;
  n = strlen (name);
  /* No empty label anywhere: "a..localhost" is not a name.  */
  if (name[0] == '.')
    return 0;
  for (i = 1; i < n; i++)
    if (name[i] == '.' && name[i - 1] == '.')
      return 0;
  if (name[n - 1] == '.')
    return 0;
  if (strcmp (name, "localhost") != 0
      && !(n > 10 && strcmp (name + n - 10, ".localhost") == 0))
    return 0;
  if (out != NULL)
    {
      memset (out, 0, sizeof *out);
      out->family = 4;
      out->addr[0] = 127;
      out->addr[3] = 1;
      snprintf (out->text, sizeof out->text, "127.0.0.1");
    }
  return 1;
}

int
twist_dns_local_addrs (const char *host, struct twist_dns_addr out[2])
{
  if (!twist_dns_local_name (host, &out[1]))
    return 0;
  memset (&out[0], 0, sizeof out[0]);
  out[0].family = 6;
  out[0].addr[15] = 1;
  snprintf (out[0].text, sizeof out[0].text, "::1");
  return 2;
}
