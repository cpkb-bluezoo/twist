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

#include <pthread.h>
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
  {
    pthread_mutex_t *mu = malloc (sizeof *mu);

    if (mu != NULL && pthread_mutex_init (mu, NULL) == 0)
      s->data_mu = mu;
    else
      free (mu);
  }
  if (s->jar == NULL || s->pool == NULL || s->hsts == NULL || s->altsvc == NULL
      || s->dns == NULL || s->data_mu == NULL)
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
  if (share->data_mu != NULL)
    {
      pthread_mutex_destroy (share->data_mu);
      free (share->data_mu);
    }
  free (share);
}

/* The lock for the cookie jar, the HSTS list and the Alt-Svc list, taken when
   the share's locks ask for BIT, so that a share used by handles of several
   threads does not change one list from two.  Without the bit it is nothing,
   and a share used from one thread pays for no lock.  */
static int
data_locked (const struct twist_share *share, unsigned bit)
{
  return share != NULL && share->data_mu != NULL && (share->locks & bit) != 0;
}

void
twist_share_data_lock (struct twist_share *share, unsigned bit)
{
  if (data_locked (share, bit))
    pthread_mutex_lock (share->data_mu);
}

void
twist_share_data_unlock (struct twist_share *share, unsigned bit)
{
  if (data_locked (share, bit))
    pthread_mutex_unlock (share->data_mu);
}

int
twist_share_cookie_store (struct twist_share *share, const char *set_cookie,
                          const char *host, const char *path, int https)
{
  int rc;

  twist_share_data_lock (share, TWIST_LOCK_DATA_COOKIE);
  rc = twist_jar_store (share->jar, set_cookie, host, path, https);
  twist_share_data_unlock (share, TWIST_LOCK_DATA_COOKIE);
  return rc;
}

int
twist_share_cookie_header (struct twist_share *share, const char *host,
                           const char *path, int https, char **out)
{
  int rc;

  twist_share_data_lock (share, TWIST_LOCK_DATA_COOKIE);
  rc = twist_jar_header (share->jar, host, path, https, out);
  twist_share_data_unlock (share, TWIST_LOCK_DATA_COOKIE);
  return rc;
}

int
twist_share_hsts_upgrade (struct twist_share *share, const char *host,
                          uint64_t now)
{
  int rc;

  twist_share_data_lock (share, TWIST_LOCK_DATA_HSTS);
  rc = twist_hsts_upgrade (share->hsts, host, now);
  twist_share_data_unlock (share, TWIST_LOCK_DATA_HSTS);
  return rc;
}

int
twist_share_altsvc_note (struct twist_share *share, const char *origin,
                         const char *alt)
{
  int rc;

  twist_share_data_lock (share, TWIST_LOCK_DATA_ALT_SVC);
  rc = twist_altsvc_note (share->altsvc, origin, alt);
  twist_share_data_unlock (share, TWIST_LOCK_DATA_ALT_SVC);
  return rc;
}

/* The entry is in the list, which another thread may change as soon as the
   lock is let go, so it is copied out under it.  */
int
twist_share_altsvc_lookup (struct twist_share *share, const char *origin,
                           char *out, size_t cap)
{
  const char *alt;
  int found = 0;

  twist_share_data_lock (share, TWIST_LOCK_DATA_ALT_SVC);
  alt = twist_altsvc_lookup (share->altsvc, origin);
  if (alt != NULL && cap > 0)
    {
      snprintf (out, cap, "%s", alt);
      found = 1;
    }
  twist_share_data_unlock (share, TWIST_LOCK_DATA_ALT_SVC);
  return found;
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
