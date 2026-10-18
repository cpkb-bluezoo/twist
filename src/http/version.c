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

struct twist_origin_hint
{
  char *host;
  int h3;
  int h3_port;
  int http_minor;
  struct twist_origin_hint *next;
};

/* How this request is allowed to start.  HTTP/3 is used only when an
   HTTPS record or a cached Alt-Svc entry says so.  HTTP/2 on TLS is
   ALPN.  Cleartext HTTP/2 is an h2c upgrade, unless the user asked
   for prior knowledge.  HTTP/1.0 versus 1.1 is not chosen here: the
   response status line is the discovery.  */

int
twist_http_discover (int pinned, int https, int rr, int rr_h3, int cached,
                     int *how)
{
  if (how == NULL)
    return TWIST_ERR_INVAL;
  if (pinned == TWIST_HTTP_VERSION_1_0 || pinned == TWIST_HTTP_VERSION_1_1)
    {
      *how = TWIST_DISC_H1;
      return TWIST_OK;
    }
  if (pinned == TWIST_HTTP_VERSION_3ONLY)
    {
      *how = TWIST_DISC_H3;
      return TWIST_OK;
    }
  if (pinned == TWIST_HTTP_VERSION_2_PRIOR_KNOWLEDGE)
    {
      *how = https ? TWIST_DISC_ALPN : TWIST_DISC_H2_PRIOR;
      return TWIST_OK;
    }
  if (pinned == TWIST_HTTP_VERSION_2_0)
    {
      *how = https ? TWIST_DISC_ALPN : TWIST_DISC_H2C;
      return TWIST_OK;
    }
  if (pinned == TWIST_HTTP_VERSION_2TLS)
    {
      *how = https ? TWIST_DISC_ALPN : TWIST_DISC_H1;
      return TWIST_OK;
    }
  /* No pin, or HTTP/3 with fallback.  A fresh HTTPS record that does
     not list h3 is a permanent no.  Alt-Svc is only consulted when
     there was no HTTPS record.  */
  if (https && rr_h3)
    {
      *how = TWIST_DISC_H3;
      return TWIST_OK;
    }
  if (https && !rr && cached == 1)
    {
      *how = TWIST_DISC_H3;
      return TWIST_OK;
    }
  *how = https ? TWIST_DISC_ALPN : TWIST_DISC_H2C;
  return TWIST_OK;
}

static int
span_port (const char *s, size_t n, int *port)
{
  size_t i;
  int v = 0;

  if (n == 0 || n > 5)
    return 0;
  for (i = 0; i < n; i++)
    {
      if (s[i] < '0' || s[i] > '9')
        return 0;
      v = v * 10 + (s[i] - '0');
    }
  if (v <= 0 || v > 65535)
    return 0;
  *port = v;
  return 1;
}

int
twist_alt_svc_h3 (const char *value, size_t len, int *port, int *clear)
{
  size_t i = 0;

  if (port != NULL)
    *port = 0;
  if (clear != NULL)
    *clear = 0;
  if (value == NULL)
    return 0;
  while (i < len && (value[i] == ' ' || value[i] == '\t'))
    i++;
  if (len - i == 5 && memcmp (value + i, "clear", 5) == 0)
    {
      if (clear != NULL)
        *clear = 1;
      return 0;
    }
  while (i < len)
    {
      while (i < len && (value[i] == ' ' || value[i] == '\t' || value[i] == ','))
        i++;
      if (i + 4 <= len && memcmp (value + i, "h3=\"", 4) == 0)
        {
          size_t colon = 0;
          int saw_colon = 0;

          i += 4;
          while (i < len && value[i] != '"')
            {
              if (value[i] == ':')
                {
                  colon = i;
                  saw_colon = 1;
                }
              i++;
            }
          if (i >= len || !saw_colon)
            return 0;
          if (span_port (value + colon + 1, i - colon - 1, port))
            return 1;
          return 0;
        }
      while (i < len && value[i] != ',')
        i++;
    }
  return 0;
}

static struct twist_origin_hint *
find_hint (struct twist_easy *easy, const char *host, int make)
{
  struct twist_origin_hint *e;

  if (easy == NULL || host == NULL)
    return NULL;
  for (e = easy->origins; e != NULL; e = e->next)
    if (strcasecmp (e->host, host) == 0)
      return e;
  if (!make)
    return NULL;
  e = calloc (1, sizeof *e);
  if (e == NULL)
    return NULL;
  e->host = twist_strdup (host);
  e->http_minor = -1;
  if (e->host == NULL)
    {
      free (e);
      return NULL;
    }
  e->next = easy->origins;
  easy->origins = e;
  return e;
}

void
twist_origin_clear (struct twist_easy *easy)
{
  struct twist_origin_hint *e;

  if (easy == NULL)
    return;
  e = easy->origins;
  while (e != NULL)
    {
      struct twist_origin_hint *next = e->next;
      free (e->host);
      free (e);
      e = next;
    }
  easy->origins = NULL;
}

int
twist_origin_h3 (struct twist_easy *easy, const char *host, int *port)
{
  struct twist_origin_hint *e = find_hint (easy, host, 0);
  const char *alt;

  if (port != NULL)
    *port = 0;
  if (e != NULL && e->h3 != 0)
    {
      if (port != NULL)
        *port = e->h3_port;
      return e->h3;
    }
  if (easy == NULL || easy->share == NULL || easy->share->altsvc == NULL)
    return 0;
  alt = twist_altsvc_lookup (easy->share->altsvc, host);
  if (alt == NULL)
    return 0;
  if (strcmp (alt, "none") == 0)
    return -1;
  if (strncmp (alt, "h3:", 3) == 0)
    {
      int p = 0;
      if (span_port (alt + 3, strlen (alt + 3), &p) && port != NULL)
        *port = p;
      return 1;
    }
  return 0;
}

void
twist_origin_set_h3 (struct twist_easy *easy, const char *host, int yes,
                     int port)
{
  struct twist_origin_hint *e = find_hint (easy, host, 1);
  char buf[16];

  if (e == NULL)
    return;
  e->h3 = yes > 0 ? 1 : -1;
  e->h3_port = yes > 0 ? port : 0;
  if (easy->share == NULL || easy->share->altsvc == NULL)
    return;
  if (yes > 0)
    snprintf (buf, sizeof buf, "h3:%d", port > 0 ? port : 443);
  else
    snprintf (buf, sizeof buf, "none");
  twist_altsvc_note (easy->share->altsvc, host, buf);
}

int
twist_origin_http_minor (struct twist_easy *easy, const char *host)
{
  struct twist_origin_hint *e = find_hint (easy, host, 0);

  return e != NULL ? e->http_minor : -1;
}

void
twist_origin_set_http_minor (struct twist_easy *easy, const char *host,
                             int minor)
{
  struct twist_origin_hint *e = find_hint (easy, host, 1);

  if (e != NULL && (minor == 0 || minor == 1))
    e->http_minor = minor;
}
