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

#include <stdlib.h>
#include <string.h>
#include <strings.h>

struct twist_hsts_entry
{
  char *host;
  uint64_t expiry;
  struct twist_hsts_entry *next;
};

struct twist_hsts
{
  struct twist_hsts_entry *head;
};

struct twist_altsvc_entry
{
  char *origin;
  char *alt;
  struct twist_altsvc_entry *next;
};

struct twist_altsvc
{
  struct twist_altsvc_entry *head;
};

struct twist_hsts *
twist_hsts_new (void)
{
  return calloc (1, sizeof (struct twist_hsts));
}

void
twist_hsts_free (struct twist_hsts *h)
{
  struct twist_hsts_entry *e;

  if (h == NULL)
    return;
  e = h->head;
  while (e != NULL)
    {
      struct twist_hsts_entry *next = e->next;
      free (e->host);
      free (e);
      e = next;
    }
  free (h);
}

int
twist_hsts_note (struct twist_hsts *h, const char *host, uint64_t expiry)
{
  struct twist_hsts_entry *e;

  if (h == NULL || host == NULL)
    return TWIST_ERR_INVAL;
  for (e = h->head; e != NULL; e = e->next)
    if (strcasecmp (e->host, host) == 0)
      {
        e->expiry = expiry;
        return TWIST_OK;
      }
  e = calloc (1, sizeof *e);
  if (e == NULL)
    return TWIST_ERR_NOMEM;
  e->host = twist_strdup (host);
  if (e->host == NULL)
    {
      free (e);
      return TWIST_ERR_NOMEM;
    }
  e->expiry = expiry;
  e->next = h->head;
  h->head = e;
  return TWIST_OK;
}

int
twist_hsts_upgrade (struct twist_hsts *h, const char *host, uint64_t now)
{
  struct twist_hsts_entry *e;

  if (h == NULL || host == NULL)
    return 0;
  for (e = h->head; e != NULL; e = e->next)
    if (strcasecmp (e->host, host) == 0 && e->expiry > now)
      return 1;
  return 0;
}

struct twist_altsvc *
twist_altsvc_new (void)
{
  return calloc (1, sizeof (struct twist_altsvc));
}

void
twist_altsvc_free (struct twist_altsvc *a)
{
  struct twist_altsvc_entry *e;

  if (a == NULL)
    return;
  e = a->head;
  while (e != NULL)
    {
      struct twist_altsvc_entry *next = e->next;
      free (e->origin);
      free (e->alt);
      free (e);
      e = next;
    }
  free (a);
}

int
twist_altsvc_note (struct twist_altsvc *a, const char *origin, const char *alt)
{
  struct twist_altsvc_entry *e;

  if (a == NULL || origin == NULL || alt == NULL)
    return TWIST_ERR_INVAL;
  for (e = a->head; e != NULL; e = e->next)
    if (strcmp (e->origin, origin) == 0)
      {
        char *copy = twist_strdup (alt);
        if (copy == NULL)
          return TWIST_ERR_NOMEM;
        free (e->alt);
        e->alt = copy;
        return TWIST_OK;
      }
  e = calloc (1, sizeof *e);
  if (e == NULL)
    return TWIST_ERR_NOMEM;
  e->origin = twist_strdup (origin);
  e->alt = twist_strdup (alt);
  if (e->origin == NULL || e->alt == NULL)
    {
      free (e->origin);
      free (e->alt);
      free (e);
      return TWIST_ERR_NOMEM;
    }
  e->next = a->head;
  a->head = e;
  return TWIST_OK;
}

const char *
twist_altsvc_lookup (struct twist_altsvc *a, const char *origin)
{
  struct twist_altsvc_entry *e;

  if (a == NULL || origin == NULL)
    return NULL;
  for (e = a->head; e != NULL; e = e->next)
    if (strcmp (e->origin, origin) == 0)
      return e->alt;
  return NULL;
}

twist_share *
twist_share_init (void)
{
  struct twist_share *s = calloc (1, sizeof *s);
  if (s == NULL)
    return NULL;
  s->jar = twist_jar_new ();
  s->pool = twist_pool_new ();
  s->hsts = twist_hsts_new ();
  s->altsvc = twist_altsvc_new ();
  s->dns = twist_dns_cache_new ();
  if (s->jar == NULL || s->pool == NULL || s->hsts == NULL || s->altsvc == NULL
      || s->dns == NULL)
    {
      twist_share_cleanup (s);
      return NULL;
    }
  return s;
}

void
twist_share_cleanup (twist_share *share)
{
  if (share == NULL)
    return;
  twist_jar_free (share->jar);
  twist_pool_free (share->pool);
  twist_hsts_free (share->hsts);
  twist_altsvc_free (share->altsvc);
  twist_dns_cache_free (share->dns);
  free (share);
}

int
twist_share_setopt (twist_share *share, unsigned lock_data)
{
  if (share == NULL)
    return TWIST_ERR_INVAL;
  share->locks |= lock_data;
  if ((lock_data & TWIST_LOCK_DATA_CONNECT) != 0)
    twist_pool_set_lock (share->pool, 1);
  if ((lock_data & TWIST_LOCK_DATA_DNS) != 0)
    twist_dns_cache_set_lock (share->dns, 1);
  return TWIST_OK;
}
