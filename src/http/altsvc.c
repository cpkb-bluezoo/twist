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

/* The alternative services that servers have offered for their origins (RFC
   7838), as the text of the offer.  A runtime keeps one list for the
   transfers that ask for it (TWISTOPT_USE_ALTSVC).  */

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
