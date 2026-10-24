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

/* The hosts that have said, with Strict-Transport-Security, that they are to be
   reached over https only, and until when.  A runtime keeps one list for the
   transfers that ask for it (TWISTOPT_USE_HSTS).  */

struct twist_hsts_entry
{
  char *host;
  uint64_t expiry;
  struct twist_hsts_entry *next;
};

struct twist_hsts
{
  pthread_mutex_t mu;           /* Loops on several threads share it.  */
  struct twist_hsts_entry *head;
};

struct twist_hsts *
twist_hsts_new (void)
{
  struct twist_hsts *h = calloc (1, sizeof (struct twist_hsts));

  if (h != NULL)
    pthread_mutex_init (&h->mu, NULL);
  return h;
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
  pthread_mutex_destroy (&h->mu);
  free (h);
}

static int
hsts_note (struct twist_hsts *h, const char *host, uint64_t expiry)
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

static int
hsts_upgrade (struct twist_hsts *h, const char *host, uint64_t now)
{
  struct twist_hsts_entry *e;

  if (h == NULL || host == NULL)
    return 0;
  for (e = h->head; e != NULL; e = e->next)
    if (strcasecmp (e->host, host) == 0 && e->expiry > now)
      return 1;
  return 0;
}

int
twist_hsts_note (struct twist_hsts *h, const char *host, uint64_t expiry)
{
  int rc;

  if (h == NULL)
    return TWIST_ERR_INVAL;
  pthread_mutex_lock (&h->mu);
  rc = hsts_note (h, host, expiry);
  pthread_mutex_unlock (&h->mu);
  return rc;
}

int
twist_hsts_upgrade (struct twist_hsts *h, const char *host, uint64_t now)
{
  int rc;

  if (h == NULL)
    return 0;
  pthread_mutex_lock (&h->mu);
  rc = hsts_upgrade (h, host, now);
  pthread_mutex_unlock (&h->mu);
  return rc;
}
