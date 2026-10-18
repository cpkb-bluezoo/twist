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

/* RFC 8484.  One DNS message is an HTTP POST body of type
   application/dns-message.  The reply body is one DNS message.  The
   HTTP parser keeps the short tail; the message itself is capped
   because compression pointers need the whole message present.  */

#define DOH_BODY 65535

struct twist_doh
{
  struct twist_h1 *h1;
  int status;
  int bad_type;
  int saw_type;
  int failed;
  int complete;
  uint8_t *body;
  size_t len;
  size_t cap;
  void (*done) (void *user, int err, const uint8_t *msg, size_t len);
  void *user;
};

static int
contains_ci (const char *s, size_t n, const char *lit)
{
  size_t ln = strlen (lit);
  size_t i;

  if (ln > n)
    return 0;
  for (i = 0; i + ln <= n; i++)
    if (strncasecmp (s + i, lit, ln) == 0)
      return 1;
  return 0;
}

static void
doh_fail (struct twist_doh *d, int err)
{
  if (d->failed)
    return;
  d->failed = 1;
  d->complete = 1;
  d->status = err;
}

static void
on_status (void *user, int code, const char *reason, size_t n)
{
  struct twist_doh *d = user;

  (void) reason;
  (void) n;
  d->status = code;
}

static void
on_header (void *user, const char *name, size_t name_len, const char *value,
           size_t value_len)
{
  struct twist_doh *d = user;

  if (name_len == 12 && strncasecmp (name, "content-type", 12) == 0)
    {
      d->saw_type = 1;
      if (!contains_ci (value, value_len, "dns-message"))
        d->bad_type = 1;
    }
}

static void
on_body (void *user, const uint8_t *data, size_t len)
{
  struct twist_doh *d = user;

  if (d->failed || len == 0)
    return;
  if (d->len + len > DOH_BODY)
    {
      doh_fail (d, TWIST_ERR_PROTOCOL);
      return;
    }
  if (d->len + len > d->cap)
    {
      size_t cap = d->cap == 0 ? 512 : d->cap;
      uint8_t *p;

      while (cap < d->len + len)
        cap *= 2;
      if (cap > DOH_BODY)
        cap = DOH_BODY;
      p = realloc (d->body, cap);
      if (p == NULL)
        {
          doh_fail (d, TWIST_ERR_NOMEM);
          return;
        }
      d->body = p;
      d->cap = cap;
    }
  memcpy (d->body + d->len, data, len);
  d->len += len;
}

static void
on_done (void *user)
{
  struct twist_doh *d = user;

  if (!d->failed)
    d->complete = 1;
}

static void
on_h1_fail (void *user, int err)
{
  doh_fail (user, err);
}

static int
arm (struct twist_doh *d)
{
  struct twist_h1_events ev;

  memset (&ev, 0, sizeof ev);
  ev.user = d;
  ev.status_line = on_status;
  ev.header = on_header;
  ev.body = on_body;
  ev.message_done = on_done;
  ev.failure = on_h1_fail;
  twist_h1_free (d->h1);
  d->h1 = twist_h1_new (&ev);
  d->status = 0;
  d->bad_type = 0;
  d->saw_type = 0;
  d->failed = 0;
  d->complete = 0;
  d->len = 0;
  return d->h1 != NULL ? TWIST_OK : TWIST_ERR_NOMEM;
}

struct twist_doh *
twist_doh_new (void (*done) (void *user, int err, const uint8_t *msg,
                             size_t len),
               void *user)
{
  struct twist_doh *d = calloc (1, sizeof *d);

  if (d == NULL)
    return NULL;
  d->done = done;
  d->user = user;
  if (arm (d) != TWIST_OK)
    {
      free (d);
      return NULL;
    }
  return d;
}

void
twist_doh_reset (struct twist_doh *d)
{
  if (d == NULL)
    return;
  arm (d);
}

void
twist_doh_free (struct twist_doh *d)
{
  if (d == NULL)
    return;
  twist_h1_free (d->h1);
  free (d->body);
  free (d);
}

size_t
twist_doh_receive (struct twist_doh *d, const uint8_t *data, size_t len)
{
  size_t n;
  int err;
  const uint8_t *msg;
  size_t msg_len;

  if (d == NULL || d->h1 == NULL)
    return 0;
  n = twist_h1_receive (d->h1, data, len);
  if (!d->complete)
    return n;
  d->complete = 0;
  if (d->failed)
    err = d->status != 0 ? d->status : TWIST_ERR_PROTOCOL;
  else if (d->status != 200 || d->bad_type)
    err = TWIST_ERR_RESOLVE;
  else
    err = TWIST_OK;
  msg = err == TWIST_OK ? d->body : NULL;
  msg_len = err == TWIST_OK ? d->len : 0;
  if (d->done != NULL)
    d->done (d->user, err, msg, msg_len);
  arm (d);
  return n;
}

static int
host_header (const struct twist_url *url, char *buf, size_t cap)
{
  const char *host = url->host != NULL ? url->host : "";
  int v6 = strchr (host, ':') != NULL;
  int wr;

  if (url->port > 0 && url->port != 443)
    wr = snprintf (buf, cap, v6 ? "[%s]:%d" : "%s:%d", host, url->port);
  else
    wr = snprintf (buf, cap, v6 ? "[%s]" : "%s", host);
  if (wr < 0 || (size_t) wr >= cap)
    return TWIST_ERR_URL;
  return TWIST_OK;
}

int
twist_doh_encode_url (const char *url_text, const uint8_t *msg, size_t msg_len,
                      uint8_t **out, size_t *out_len)
{
  struct twist_url *url = NULL;
  struct twist_slist *extra = NULL;
  char host[512];
  char target[2048];
  const char *path;
  int rc;

  if (url_text == NULL || out == NULL || out_len == NULL)
    return TWIST_ERR_INVAL;
  if (msg_len > 0 && msg == NULL)
    return TWIST_ERR_INVAL;
  rc = twist_url_parse_int (url_text, &url);
  if (rc != TWIST_OK)
    return rc;
  if (url->scheme == NULL || strcmp (url->scheme, "https") != 0
      || url->host == NULL || url->host[0] == 0)
    {
      twist_url_free_int (url);
      return TWIST_ERR_URL;
    }
  path = url->path != NULL && url->path[0] != 0 ? url->path : "/";
  if (url->query != NULL)
    {
      int wr = snprintf (target, sizeof target, "%s?%s", path, url->query);

      if (wr < 0 || (size_t) wr >= sizeof target)
        {
          twist_url_free_int (url);
          return TWIST_ERR_URL;
        }
    }
  else if (strlen (path) >= sizeof target)
    {
      twist_url_free_int (url);
      return TWIST_ERR_URL;
    }
  else
    memcpy (target, path, strlen (path) + 1);
  if (host_header (url, host, sizeof host) != TWIST_OK)
    {
      twist_url_free_int (url);
      return TWIST_ERR_URL;
    }
  extra = twist_slist_append (extra, "Accept: application/dns-message");
  extra = twist_slist_append (extra, "Content-Type: application/dns-message");
  rc = twist_h1_write_request ("POST", target, host, 0, extra, msg, msg_len,
                               out, out_len);
  twist_slist_free_all (extra);
  twist_url_free_int (url);
  return rc;
}
