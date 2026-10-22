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
#include "gettext.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

/* The URI Template of a UDP proxy (RFC 9298, section 2).  Only the two forms
   that proxies use of RFC 6570 are understood: {name}, and {?name,name} for a
   query.  A template with another operator is refused, and not guessed at.  */

enum expr_kind
{
  E_SIMPLE,
  E_QUERY
};

struct expr
{
  enum expr_kind kind;
  const char *vars;		/* After the operator.  */
  size_t len;			/* Of the names, with their commas.  */
};

static void
reason (char *err, size_t cap, const char *msg)
{
  if (err != NULL && cap > 0)
    snprintf (err, cap, "%s", msg);
}

/* The expression that starts after the '{' at P.  Returns the number of bytes
   to the '}' (exclusive), or -1.  */
static int
parse_expr (const char *p, struct expr *e, char *err, size_t cap)
{
  const char *end = strchr (p, '}');
  const char *q;

  if (end == NULL)
    {
      reason (err, cap, _("a { in the template has no }"));
      return -1;
    }
  e->kind = E_SIMPLE;
  e->vars = p;
  if (*p == '?')
    {
      e->kind = E_QUERY;
      e->vars = p + 1;
    }
  else if (strchr ("+#./;&=,!@|", *p) != NULL && p < end)
    {
      reason (err, cap, _("the template uses an operator that is not "
                          "supported; use {name} or {?name,name}"));
      return -1;
    }
  e->len = (size_t) (end - e->vars);
  if (e->len == 0)
    {
      reason (err, cap, _("the template has an empty {}"));
      return -1;
    }
  for (q = e->vars; q < end; q++)
    if (!((*q >= 'a' && *q <= 'z') || (*q >= 'A' && *q <= 'Z')
          || (*q >= '0' && *q <= '9') || *q == '_' || *q == ','
          || *q == '.'))
      {
        reason (err, cap, _("a name in the template is not a name"));
        return -1;
      }
  return (int) (end - p);
}

/* Whether the comma-separated names of E include NAME.  */
static int
has_var (const struct expr *e, const char *name)
{
  size_t nl = strlen (name);
  const char *p = e->vars;
  const char *end = e->vars + e->len;

  while (p < end)
    {
      const char *comma = memchr (p, ',', (size_t) (end - p));
      size_t l = comma != NULL ? (size_t) (comma - p) : (size_t) (end - p);

      if (l == nl && memcmp (p, name, nl) == 0)
        return 1;
      p += l + 1;
    }
  return 0;
}

int
twist_template_check (const char *tmpl, char *err, size_t errcap)
{
  const char *p;
  const char *host;
  int host_seen = 0, port_seen = 0;

  if (tmpl == NULL || tmpl[0] == 0)
    {
      reason (err, errcap, _("the template is empty"));
      return TWIST_ERR_URL;
    }
  if (strncasecmp (tmpl, "https://", 8) != 0)
    {
      reason (err, errcap, _("the template is not an https URI"));
      return TWIST_ERR_URL;
    }
  host = tmpl + 8;
  if (*host == 0 || *host == '/' || *host == '{' || *host == '?')
    {
      reason (err, errcap, _("the template has no host"));
      return TWIST_ERR_URL;
    }
  if (strchr (tmpl, '#') != NULL)
    {
      reason (err, errcap, _("the template has a fragment"));
      return TWIST_ERR_URL;
    }
  for (p = tmpl; *p != 0; p++)
    {
      if (*p == '}')
        {
          reason (err, errcap, _("a } in the template has no {"));
          return TWIST_ERR_URL;
        }
      if (*p == '{')
        {
          struct expr e;
          int n = parse_expr (p + 1, &e, err, errcap);

          if (n < 0)
            return TWIST_ERR_URL;
          /* The host of the proxy is not a variable.  */
          if (p < host + strcspn (host, "/?"))
            {
              reason (err, errcap, _("the host in the template is a "
                                     "variable"));
              return TWIST_ERR_URL;
            }
          if (has_var (&e, "target_host"))
            host_seen = 1;
          if (has_var (&e, "target_port"))
            port_seen = 1;
          p += n + 1;
        }
    }
  if (!host_seen)
    {
      reason (err, errcap, _("the template does not have target_host"));
      return TWIST_ERR_URL;
    }
  if (!port_seen)
    {
      reason (err, errcap, _("the template does not have target_port"));
      return TWIST_ERR_URL;
    }
  return TWIST_OK;
}

/* Append S, percent-encoding what RFC 3986 does not call unreserved.  */
static int
append_enc (char **buf, size_t *n, size_t *cap, const char *s)
{
  for (; *s != 0; s++)
    {
      unsigned char c = (unsigned char) *s;
      int plain = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
                  || (c >= '0' && c <= '9') || c == '-' || c == '.'
                  || c == '_' || c == '~';

      if (*n + 4 > *cap)
        {
          size_t ncap = *cap * 2;
          char *p = realloc (*buf, ncap);

          if (p == NULL)
            return TWIST_ERR_NOMEM;
          *buf = p;
          *cap = ncap;
        }
      if (plain)
        (*buf)[(*n)++] = (char) c;
      else
        *n += (size_t) snprintf (*buf + *n, 4, "%%%02X", c);
    }
  return TWIST_OK;
}

static int
append_raw (char **buf, size_t *n, size_t *cap, const char *s, size_t len)
{
  if (*n + len + 1 > *cap)
    {
      size_t ncap = *cap;
      char *p;

      while (*n + len + 1 > ncap)
        ncap *= 2;
      p = realloc (*buf, ncap);
      if (p == NULL)
        return TWIST_ERR_NOMEM;
      *buf = p;
      *cap = ncap;
    }
  memcpy (*buf + *n, s, len);
  *n += len;
  return TWIST_OK;
}

int
twist_template_expand (const char *tmpl, const char *host, int port, char **out)
{
  size_t cap = strlen (tmpl) + strlen (host) * 3 + 64;
  char *buf = twist_xmalloc (cap);
  size_t n = 0;
  const char *p;
  char portbuf[16];
  int rc = TWIST_OK;

  if (buf == NULL)
    return TWIST_ERR_NOMEM;
  snprintf (portbuf, sizeof portbuf, "%d", port);
  for (p = tmpl; *p != 0 && rc == TWIST_OK; p++)
    {
      if (*p == '{')
        {
          struct expr e;
          int len = parse_expr (p + 1, &e, NULL, 0);
          const char *q;
          const char *end;
          int first = 1;

          if (len < 0)
            {
              free (buf);
              return TWIST_ERR_URL;
            }
          end = e.vars + e.len;
          for (q = e.vars; q < end && rc == TWIST_OK;)
            {
              const char *comma = memchr (q, ',', (size_t) (end - q));
              size_t l = comma != NULL ? (size_t) (comma - q) : (size_t) (end - q);
              const char *value = NULL;

              if (l == 11 && memcmp (q, "target_host", 11) == 0)
                value = host;
              else if (l == 11 && memcmp (q, "target_port", 11) == 0)
                value = portbuf;
              if (e.kind == E_QUERY)
                {
                  /* Undefined variables are left out.  */
                  if (value != NULL)
                    {
                      rc = append_raw (&buf, &n, &cap, first ? "?" : "&", 1);
                      if (rc == TWIST_OK)
                        rc = append_raw (&buf, &n, &cap, q, l);
                      if (rc == TWIST_OK)
                        rc = append_raw (&buf, &n, &cap, "=", 1);
                      if (rc == TWIST_OK)
                        rc = append_enc (&buf, &n, &cap, value);
                      first = 0;
                    }
                }
              else if (value != NULL)
                rc = append_enc (&buf, &n, &cap, value);
              q += l + 1;
            }
          p += len + 1;
          continue;
        }
      rc = append_raw (&buf, &n, &cap, p, 1);
    }
  if (rc != TWIST_OK)
    {
      free (buf);
      return rc;
    }
  buf[n] = 0;
  *out = buf;
  return TWIST_OK;
}

int
twist_template_default (const char *proxy_host, int proxy_port, char **out)
{
  size_t n = strlen (proxy_host) + 96;
  char *s = twist_xmalloc (n);

  if (s == NULL)
    return TWIST_ERR_NOMEM;
  if (strchr (proxy_host, ':') != NULL)
    snprintf (s, n, "https://[%s]:%d/.well-known/masque/udp/{target_host}/"
              "{target_port}/", proxy_host, proxy_port);
  else
    snprintf (s, n, "https://%s:%d/.well-known/masque/udp/{target_host}/"
              "{target_port}/", proxy_host, proxy_port);
  *out = s;
  return TWIST_OK;
}
