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
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

struct twist_cookie
{
  char *name;
  char *value;
  char *domain;
  char *path;
  int secure;
  int host_only;
  struct twist_cookie *next;
};

struct twist_jar
{
  pthread_mutex_t mu;           /* Loops on several threads share it.  */
  struct twist_cookie *head;
};

struct twist_jar *
twist_jar_new (void)
{
  struct twist_jar *jar = calloc (1, sizeof (struct twist_jar));

  if (jar != NULL)
    pthread_mutex_init (&jar->mu, NULL);
  return jar;
}

void
twist_jar_free (struct twist_jar *jar)
{
  struct twist_cookie *c;

  if (jar == NULL)
    return;
  c = jar->head;
  while (c != NULL)
    {
      struct twist_cookie *next = c->next;
      free (c->name);
      free (c->value);
      free (c->domain);
      free (c->path);
      free (c);
      c = next;
    }
  pthread_mutex_destroy (&jar->mu);
  free (jar);
}

size_t
twist_jar_count (struct twist_jar *jar)
{
  const struct twist_cookie *c;
  size_t n = 0;

  if (jar == NULL)
    return 0;
  pthread_mutex_lock (&jar->mu);
  for (c = jar->head; c != NULL; c = c->next)
    n++;
  pthread_mutex_unlock (&jar->mu);
  return n;
}

static char *
tokdup (const char *s, size_t n)
{
  char *p = twist_xmalloc (n + 1);
  if (p == NULL)
    return NULL;
  memcpy (p, s, n);
  p[n] = 0;
  return p;
}

static int
domain_match (const char *host, const char *domain, int host_only)
{
  size_t hl;
  size_t dl;

  if (host == NULL || domain == NULL)
    return 0;
  if (strcasecmp (host, domain) == 0)
    return 1;
  if (host_only)
    return 0;
  hl = strlen (host);
  dl = strlen (domain);
  if (dl + 1 < hl && host[hl - dl - 1] == '.'
      && strcasecmp (host + hl - dl, domain) == 0)
    return 1;
  return 0;
}

static int
path_match (const char *req, const char *cookie_path)
{
  size_t n;

  if (cookie_path == NULL || cookie_path[0] == 0)
    return 1;
  if (req == NULL)
    req = "/";
  n = strlen (cookie_path);
  if (strncmp (req, cookie_path, n) != 0)
    return 0;
  return req[n] == 0 || req[n] == '/' || cookie_path[n - 1] == '/';
}

/* RFC 6265, section 6.1: at least 4096 bytes of name and value in a cookie,
   50 cookies for a domain and 3000 in all.  A server cannot make the jar
   hold more than these, and the oldest go first.  */
#define JAR_COOKIE_MAX 4096
#define JAR_DOMAIN_MAX 50
#define JAR_TOTAL_MAX 3000

static void
cookie_free (struct twist_cookie *c)
{
  if (c == NULL)
    return;
  free (c->name);
  free (c->value);
  free (c->domain);
  free (c->path);
  free (c);
}

/* Whether HOST is an IP address, which a cookie matches only as a whole: no
   address is a suffix of another's.  */
static int
host_is_address (const char *host)
{
  const char *p;

  if (strchr (host, ':') != NULL || host[0] == '[')
    return 1;
  for (p = host; *p != 0; p++)
    if (*p != '.' && (*p < '0' || *p > '9'))
      return 0;
  return host[0] != 0;
}

/* Take out and free the oldest cookie of DOMAIN, or of any domain if DOMAIN
   is NULL.  The jar is newest first.  */
static void
evict_oldest (struct twist_jar *jar, const char *domain)
{
  struct twist_cookie **victim = NULL;
  struct twist_cookie **link;

  for (link = &jar->head; *link != NULL; link = &(*link)->next)
    if (domain == NULL || strcasecmp ((*link)->domain, domain) == 0)
      victim = link;
  if (victim != NULL)
    {
      struct twist_cookie *gone = *victim;

      *victim = gone->next;
      cookie_free (gone);
    }
}

static int
jar_store (struct twist_jar *jar, const char *set_cookie,
           const char *host, const char *path, int https)
{
  const char *semi;
  const char *eq;
  struct twist_cookie *c;
  struct twist_cookie **link;
  char *pair;
  char *scan;
  size_t in_domain = 0;
  size_t total = 0;

  if (jar == NULL || set_cookie == NULL || host == NULL)
    return TWIST_ERR_INVAL;
  semi = strchr (set_cookie, ';');
  eq = strchr (set_cookie, '=');
  if (eq == NULL || (semi != NULL && eq > semi))
    return TWIST_ERR_PROTOCOL;
  c = calloc (1, sizeof *c);
  if (c == NULL)
    return TWIST_ERR_NOMEM;
  c->name = tokdup (set_cookie, (size_t) (eq - set_cookie));
  if (semi != NULL)
    c->value = tokdup (eq + 1, (size_t) (semi - eq - 1));
  else
    c->value = twist_strdup (eq + 1);
  c->domain = twist_strdup (host);
  c->path = twist_strdup (path != NULL && path[0] != 0 ? path : "/");
  c->host_only = 1;
  if (c->name == NULL || c->value == NULL || c->domain == NULL || c->path == NULL)
    {
      cookie_free (c);
      return TWIST_ERR_NOMEM;
    }
  pair = twist_strdup (set_cookie);
  if (pair == NULL)
    {
      cookie_free (c);
      return TWIST_ERR_NOMEM;
    }
  scan = pair;
  while (scan != NULL)
    {
      char *attr = strchr (scan, ';');
      if (attr != NULL)
        *attr++ = 0;
      while (*scan == ' ')
        scan++;
      if (strncasecmp (scan, "Domain=", 7) == 0)
        {
          free (c->domain);
          c->domain = twist_strdup (scan + 7);
          c->host_only = 0;
        }
      else if (strncasecmp (scan, "Path=", 5) == 0)
        {
          free (c->path);
          c->path = twist_strdup (scan + 5);
        }
      else if (strcasecmp (scan, "Secure") == 0)
        c->secure = 1;
      scan = attr;
    }
  free (pair);
  if (c->domain == NULL || c->path == NULL)
    {
      cookie_free (c);
      return TWIST_ERR_NOMEM;
    }
  if (twist_has_ctl (c->name) || twist_has_ctl (c->value)
      || strlen (c->name) + strlen (c->value) > JAR_COOKIE_MAX)
    {
      cookie_free (c);
      return TWIST_ERR_PROTOCOL;
    }
  /* Whoever can rewrite a response over http can set any cookie in it, so
     one that says it is only for https is not believed from there.  */
  if (c->secure && !https)
    {
      cookie_free (c);
      return TWIST_ERR_PROTOCOL;
    }
  if (c->domain[0] == '.')
    memmove (c->domain, c->domain + 1, strlen (c->domain));
  if (c->domain[0] == 0 || !domain_match (host, c->domain, 0))
    {
      cookie_free (c);
      return TWIST_ERR_PROTOCOL;
    }
  /* The cookie is for the host that set it, however wide it asked to be.
     Telling a registry suffix from a domain needs the Public Suffix List,
     which is never current; the host alone needs nothing.  An address is
     no one's suffix either, so its own is the only Domain it can name.  */
  if (!c->host_only)
    {
      if (host_is_address (host) && strcasecmp (host, c->domain) != 0)
        {
          cookie_free (c);
          return TWIST_ERR_PROTOCOL;
        }
      free (c->domain);
      c->domain = twist_strdup (host);
      if (c->domain == NULL)
        {
          cookie_free (c);
          return TWIST_ERR_NOMEM;
        }
      c->host_only = 1;
    }

  /* The same cookie (name, domain and path) replaces the old one, which an
     insecure origin may not do to a Secure one.  */
  for (link = &jar->head; *link != NULL; link = &(*link)->next)
    {
      struct twist_cookie *old = *link;

      if (strcmp (old->name, c->name) == 0
          && strcasecmp (old->domain, c->domain) == 0
          && strcmp (old->path, c->path) == 0)
        {
          if (old->secure && !https)
            {
              cookie_free (c);
              return TWIST_ERR_PROTOCOL;
            }
          c->next = old->next;
          *link = c;
          cookie_free (old);
          return TWIST_OK;
        }
    }
  {
    struct twist_cookie *k;

    for (k = jar->head; k != NULL; k = k->next)
      {
        total++;
        if (strcasecmp (k->domain, c->domain) == 0)
          in_domain++;
      }
  }
  if (in_domain >= JAR_DOMAIN_MAX)
    {
      evict_oldest (jar, c->domain);
      total--;
    }
  if (total >= JAR_TOTAL_MAX)
    evict_oldest (jar, NULL);
  c->next = jar->head;
  jar->head = c;
  return TWIST_OK;
}

static int
jar_header (struct twist_jar *jar, const char *host, const char *path,
            int https, char **out)
{
  struct twist_cookie *c;
  size_t cap = 64;
  size_t n = 0;
  char *buf;

  if (out == NULL)
    return TWIST_ERR_INVAL;
  *out = NULL;
  if (jar == NULL)
    return TWIST_OK;
  buf = twist_xmalloc (cap);
  if (buf == NULL)
    return TWIST_ERR_NOMEM;
  buf[0] = 0;
  for (c = jar->head; c != NULL; c = c->next)
    {
      size_t need;
      if (c->secure && !https)
        continue;
      if (!domain_match (host, c->domain, c->host_only))
        continue;
      if (!path_match (path, c->path))
        continue;
      need = strlen (c->name) + strlen (c->value) + 3;
      if (n + need + 16 > cap)
        {
          char *grown;
          cap = cap * 2 + need;
          grown = realloc (buf, cap);
          if (grown == NULL)
            {
              free (buf);
              return TWIST_ERR_NOMEM;
            }
          buf = grown;
        }
      if (n == 0)
        n = (size_t) sprintf (buf, "Cookie: %s=%s", c->name, c->value);
      else
        n += (size_t) sprintf (buf + n, "; %s=%s", c->name, c->value);
    }
  if (n == 0)
    {
      free (buf);
      return TWIST_OK;
    }
  *out = buf;
  return TWIST_OK;
}

int
twist_jar_store (struct twist_jar *jar, const char *set_cookie,
                 const char *host, const char *path, int https)
{
  int rc;

  if (jar == NULL)
    return TWIST_ERR_INVAL;
  pthread_mutex_lock (&jar->mu);
  rc = jar_store (jar, set_cookie, host, path, https);
  pthread_mutex_unlock (&jar->mu);
  return rc;
}

int
twist_jar_header (struct twist_jar *jar, const char *host, const char *path,
                  int https, char **out)
{
  int rc;

  if (jar == NULL)
    return TWIST_ERR_INVAL;
  pthread_mutex_lock (&jar->mu);
  rc = jar_header (jar, host, path, https, out);
  pthread_mutex_unlock (&jar->mu);
  return rc;
}
