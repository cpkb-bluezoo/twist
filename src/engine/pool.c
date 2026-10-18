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

struct twist_pool_slot
{
  char *key;
  struct twist_connection *conn;
  struct twist_pool_slot *next;
};

struct twist_pool
{
  struct twist_pool_slot *head;
};

struct twist_pool *
twist_pool_new (void)
{
  return calloc (1, sizeof (struct twist_pool));
}

void
twist_pool_free (struct twist_pool *pool)
{
  struct twist_pool_slot *s;

  if (pool == NULL)
    return;
  s = pool->head;
  while (s != NULL)
    {
      struct twist_pool_slot *next = s->next;
      free (s->key);
      free (s);
      s = next;
    }
  free (pool);
}

int
twist_pool_take (struct twist_pool *pool, const char *key,
                 struct twist_connection **out)
{
  struct twist_pool_slot **pp;

  if (out != NULL)
    *out = NULL;
  if (pool == NULL || key == NULL)
    return TWIST_ERR_INVAL;
  for (pp = &pool->head; *pp != NULL; pp = &(*pp)->next)
    if (strcmp ((*pp)->key, key) == 0)
      {
        struct twist_pool_slot *s = *pp;
        *pp = s->next;
        if (out != NULL)
          *out = s->conn;
        free (s->key);
        free (s);
        return TWIST_OK;
      }
  return TWIST_ERR_AGAIN;
}

int
twist_pool_put (struct twist_pool *pool, const char *key,
                struct twist_connection *conn)
{
  struct twist_pool_slot *s;

  if (pool == NULL || key == NULL || conn == NULL)
    return TWIST_ERR_INVAL;
  s = calloc (1, sizeof *s);
  if (s == NULL)
    return TWIST_ERR_NOMEM;
  s->key = twist_strdup (key);
  if (s->key == NULL)
    {
      free (s);
      return TWIST_ERR_NOMEM;
    }
  s->conn = conn;
  s->next = pool->head;
  pool->head = s;
  return TWIST_OK;
}
