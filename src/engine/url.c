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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int
is_scheme_char (int c)
{
  return isalnum (c) || c == '+' || c == '-' || c == '.';
}

static void
url_clear (struct twist_url *u)
{
  free (u->scheme);
  free (u->user);
  free (u->password);
  free (u->host);
  free (u->path);
  free (u->query);
  free (u->fragment);
  free (u);
}

int
twist_url_parse_int (const char *input, struct twist_url **out)
{
  const char *p;
  const char *colon;
  const char *slash;
  const char *at;
  const char *host;
  const char *endhost;
  struct twist_url *u;
  size_t n;

  if (input == NULL || input[0] == 0)
    return TWIST_ERR_URL;
  u = calloc (1, sizeof *u);
  if (u == NULL)
    return TWIST_ERR_NOMEM;
  p = input;
  colon = strchr (p, ':');
  if (colon == NULL || colon == p)
    {
      url_clear (u);
      return TWIST_ERR_URL;
    }
  for (n = 0; p + n < colon; n++)
    if (!is_scheme_char ((unsigned char) p[n]))
      {
        url_clear (u);
        return TWIST_ERR_URL;
      }
  u->scheme = twist_xmalloc (n + 1);
  if (u->scheme == NULL)
    {
      url_clear (u);
      return TWIST_ERR_NOMEM;
    }
  memcpy (u->scheme, p, n);
  u->scheme[n] = 0;
  for (n = 0; u->scheme[n] != 0; n++)
    u->scheme[n] = (char) tolower ((unsigned char) u->scheme[n]);
  p = colon + 1;
  if (p[0] == '/' && p[1] == '/')
    {
      p += 2;
      slash = strpbrk (p, "/?#");
      at = NULL;
      {
        const char *scan = p;
        const char *limit = slash != NULL ? slash : p + strlen (p);
        for (; scan < limit; scan++)
          if (*scan == '@')
            at = scan;
      }
      if (at != NULL)
        {
          const char *pw = memchr (p, ':', (size_t) (at - p));
          if (pw != NULL)
            {
              u->user = twist_xmalloc ((size_t) (pw - p) + 1);
              u->password = twist_xmalloc ((size_t) (at - pw));
              if (u->user == NULL || u->password == NULL)
                {
                  url_clear (u);
                  return TWIST_ERR_NOMEM;
                }
              memcpy (u->user, p, (size_t) (pw - p));
              u->user[pw - p] = 0;
              memcpy (u->password, pw + 1, (size_t) (at - pw - 1));
              u->password[at - pw - 1] = 0;
            }
          else
            {
              u->user = twist_xmalloc ((size_t) (at - p) + 1);
              if (u->user == NULL)
                {
                  url_clear (u);
                  return TWIST_ERR_NOMEM;
                }
              memcpy (u->user, p, (size_t) (at - p));
              u->user[at - p] = 0;
            }
          p = at + 1;
        }
      host = p;
      if (*host == '[')
        {
          endhost = strchr (host, ']');
          if (endhost == NULL)
            {
              url_clear (u);
              return TWIST_ERR_URL;
            }
          u->host = twist_xmalloc ((size_t) (endhost - host - 1) + 1);
          if (u->host == NULL)
            {
              url_clear (u);
              return TWIST_ERR_NOMEM;
            }
          memcpy (u->host, host + 1, (size_t) (endhost - host - 1));
          u->host[endhost - host - 1] = 0;
          p = endhost + 1;
        }
      else
        {
          endhost = host;
          while (*endhost != 0 && *endhost != ':' && *endhost != '/'
                 && *endhost != '?' && *endhost != '#')
            endhost++;
          u->host = twist_xmalloc ((size_t) (endhost - host) + 1);
          if (u->host == NULL)
            {
              url_clear (u);
              return TWIST_ERR_NOMEM;
            }
          memcpy (u->host, host, (size_t) (endhost - host));
          u->host[endhost - host] = 0;
          p = endhost;
        }
      if (*p == ':')
        {
          char *end = NULL;
          long port = strtol (p + 1, &end, 10);
          if (end == p + 1 || port < 0 || port > 65535)
            {
              url_clear (u);
              return TWIST_ERR_URL;
            }
          u->port = (int) port;
          u->port_set = 1;
          p = end;
        }
    }
  if (*p == 0)
    u->path = twist_strdup ("/");
  else if (*p == '?')
    {
      u->path = twist_strdup ("/");
      p++;
      {
        const char *hash = strchr (p, '#');
        size_t qn = hash != NULL ? (size_t) (hash - p) : strlen (p);
        u->query = twist_xmalloc (qn + 1);
        if (u->path == NULL || u->query == NULL)
          {
            url_clear (u);
            return TWIST_ERR_NOMEM;
          }
        memcpy (u->query, p, qn);
        u->query[qn] = 0;
        if (hash != NULL)
          u->fragment = twist_strdup (hash + 1);
        p = "";
      }
    }
  else
    {
      const char *q = strchr (p, '?');
      const char *hash = strchr (p, '#');
      const char *stop = p + strlen (p);
      if (q != NULL && (hash == NULL || q < hash))
        stop = q;
      else if (hash != NULL)
        stop = hash;
      u->path = twist_xmalloc ((size_t) (stop - p) + 1);
      if (u->path == NULL)
        {
          url_clear (u);
          return TWIST_ERR_NOMEM;
        }
      memcpy (u->path, p, (size_t) (stop - p));
      u->path[stop - p] = 0;
      u->path_set = 1;
      if (*stop == '?')
        {
          const char *qs = stop + 1;
          const char *he = strchr (qs, '#');
          size_t qn = he != NULL ? (size_t) (he - qs) : strlen (qs);
          u->query = twist_xmalloc (qn + 1);
          if (u->query == NULL)
            {
              url_clear (u);
              return TWIST_ERR_NOMEM;
            }
          memcpy (u->query, qs, qn);
          u->query[qn] = 0;
          if (he != NULL)
            u->fragment = twist_strdup (he + 1);
        }
      else if (*stop == '#')
        u->fragment = twist_strdup (stop + 1);
    }
  if (u->path == NULL)
    u->path = twist_strdup ("");
  if (u->port == 0 && !u->port_set)
    u->port = twist_url_default_port (u->scheme);
  *out = u;
  return TWIST_OK;
}

void
twist_url_free_int (struct twist_url *url)
{
  if (url != NULL)
    url_clear (url);
}

int
twist_url_default_port (const char *scheme)
{
  if (scheme == NULL)
    return 0;
  if (strcmp (scheme, "http") == 0 || strcmp (scheme, "ws") == 0)
    return 80;
  if (strcmp (scheme, "https") == 0 || strcmp (scheme, "wss") == 0)
    return 443;
  if (strcmp (scheme, "ftp") == 0)
    return 21;
  if (strcmp (scheme, "ftps") == 0)
    return 990;
  if (strcmp (scheme, "smtp") == 0)
    return 25;
  if (strcmp (scheme, "smtps") == 0)
    return 465;
  if (strcmp (scheme, "imap") == 0)
    return 143;
  if (strcmp (scheme, "imaps") == 0)
    return 993;
  if (strcmp (scheme, "pop3") == 0)
    return 110;
  if (strcmp (scheme, "pop3s") == 0)
    return 995;
  if (strcmp (scheme, "ldap") == 0)
    return 389;
  if (strcmp (scheme, "ldaps") == 0)
    return 636;
  if (strcmp (scheme, "mqtt") == 0)
    return 1883;
  if (strcmp (scheme, "tftp") == 0)
    return 69;
  if (strcmp (scheme, "dict") == 0)
    return 2628;
  if (strcmp (scheme, "gopher") == 0)
    return 70;
  if (strcmp (scheme, "telnet") == 0)
    return 23;
  if (strcmp (scheme, "rtsp") == 0)
    return 554;
  if (strcmp (scheme, "smb") == 0)
    return 445;
  if (strcmp (scheme, "ssh") == 0 || strcmp (scheme, "scp") == 0
      || strcmp (scheme, "sftp") == 0)
    return 22;
  return 0;
}

char *
twist_url_format (const struct twist_url *url)
{
  char buf[2048];
  int n;

  if (url == NULL || url->scheme == NULL)
    return NULL;
  n = snprintf (buf, sizeof buf, "%s://%s%s%s%s%s:%d%s%s%s",
                url->scheme,
                url->user != NULL ? url->user : "",
                url->password != NULL ? ":" : "",
                url->password != NULL ? url->password : "",
                url->user != NULL ? "@" : "",
                url->host != NULL ? url->host : "",
                url->port,
                url->path != NULL ? url->path : "/",
                url->query != NULL ? "?" : "",
                url->query != NULL ? url->query : "");
  if (n < 0 || (size_t) n >= sizeof buf)
    return NULL;
  return twist_strdup (buf);
}

int
twist_url_resolve_int (const struct twist_url *base, const char *ref,
                       struct twist_url **out)
{
  struct twist_url *abs;
  int rc;

  if (ref == NULL)
    return TWIST_ERR_URL;
  if (strstr (ref, "://") != NULL)
    return twist_url_parse_int (ref, out);
  if (base == NULL)
    return TWIST_ERR_URL;
  rc = twist_url_parse_int (ref[0] == '/' ? "http://h/" : "http://h/b", &abs);
  if (rc != TWIST_OK)
    return rc;
  /* Rebuild from the base and the reference path.  */
  {
    char buf[2048];
    const char *path;
    char *dir;
    const char *slash;

    if (ref[0] == '/')
      path = ref;
    else
      {
        dir = twist_strdup (base->path != NULL ? base->path : "/");
        if (dir == NULL)
          {
            twist_url_free_int (abs);
            return TWIST_ERR_NOMEM;
          }
        slash = strrchr (dir, '/');
        if (slash != NULL)
          {
            char *joined;
            size_t dn = (size_t) (slash - dir + 1);
            joined = twist_xmalloc (dn + strlen (ref) + 1);
            if (joined == NULL)
              {
                free (dir);
                twist_url_free_int (abs);
                return TWIST_ERR_NOMEM;
              }
            memcpy (joined, dir, dn);
            memcpy (joined + dn, ref, strlen (ref) + 1);
            path = joined;
            snprintf (buf, sizeof buf, "%s://%s:%d%s", base->scheme,
                      base->host != NULL ? base->host : "", base->port, path);
            free (joined);
            free (dir);
            twist_url_free_int (abs);
            return twist_url_parse_int (buf, out);
          }
        free (dir);
        path = ref;
      }
    snprintf (buf, sizeof buf, "%s://%s:%d%s", base->scheme,
              base->host != NULL ? base->host : "", base->port, path);
    twist_url_free_int (abs);
    return twist_url_parse_int (buf, out);
  }
}

int
twist_url_parse (const char *input, twist_url **out)
{
  return twist_url_parse_int (input, out);
}

void
twist_url_free (twist_url *url)
{
  twist_url_free_int (url);
}

const char *
twist_url_scheme (const twist_url *url)
{
  return url->scheme;
}

const char *
twist_url_host (const twist_url *url)
{
  return url->host;
}

int
twist_url_port (const twist_url *url)
{
  return url->port;
}

const char *
twist_url_path (const twist_url *url)
{
  return url->path;
}

const char *
twist_url_query (const twist_url *url)
{
  return url->query;
}

int
twist_url_resolve (const twist_url *base, const char *ref, twist_url **out)
{
  return twist_url_resolve_int (base, ref, out);
}
