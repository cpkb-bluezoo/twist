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
  struct twist_cookie *head;
};

struct twist_jar *
twist_jar_new (void)
{
  return calloc (1, sizeof (struct twist_jar));
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
  free (jar);
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

int
twist_jar_store (struct twist_jar *jar, const char *set_cookie,
                 const char *host, const char *path, int https)
{
  const char *semi;
  const char *eq;
  struct twist_cookie *c;
  char *pair;
  char *scan;

  (void) https;
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
      free (c->name);
      free (c->value);
      free (c->domain);
      free (c->path);
      free (c);
      return TWIST_ERR_NOMEM;
    }
  pair = twist_strdup (set_cookie);
  if (pair == NULL)
    {
      free (c->name);
      free (c->value);
      free (c->domain);
      free (c->path);
      free (c);
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
  if (twist_has_ctl (c->name) || twist_has_ctl (c->value))
    {
      free (c->name);
      free (c->value);
      free (c->domain);
      free (c->path);
      free (c);
      return TWIST_ERR_PROTOCOL;
    }
  if (c->domain != NULL && c->domain[0] == '.')
    {
      char *stripped = twist_strdup (c->domain + 1);

      if (stripped == NULL)
        {
          free (c->name);
          free (c->value);
          free (c->domain);
          free (c->path);
          free (c);
          return TWIST_ERR_NOMEM;
        }
      free (c->domain);
      c->domain = stripped;
    }
  if (c->domain == NULL || c->domain[0] == 0
      || !domain_match (host, c->domain, 0))
    {
      free (c->name);
      free (c->value);
      free (c->domain);
      free (c->path);
      free (c);
      return TWIST_ERR_PROTOCOL;
    }
  c->next = jar->head;
  jar->head = c;
  return TWIST_OK;
}

int
twist_jar_header (struct twist_jar *jar, const char *host, const char *path,
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
