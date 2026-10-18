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

void *
twist_xmalloc (size_t n)
{
  void *p;

  if (n == 0)
    n = 1;
  p = malloc (n);
  return p;
}

char *
twist_strdup (const char *s)
{
  size_t n;
  char *p;

  if (s == NULL)
    return NULL;
  n = strlen (s) + 1;
  p = twist_xmalloc (n);
  if (p == NULL)
    return NULL;
  memcpy (p, s, n);
  return p;
}

struct twist_slist *
twist_slist_append (struct twist_slist *list, const char *data)
{
  struct twist_slist *node;
  struct twist_slist *tail;

  node = twist_xmalloc (sizeof *node);
  if (node == NULL)
    return list;
  node->data = twist_strdup (data);
  node->next = NULL;
  if (node->data == NULL)
    {
      free (node);
      return list;
    }
  if (list == NULL)
    return node;
  tail = list;
  while (tail->next != NULL)
    tail = tail->next;
  tail->next = node;
  return list;
}

void
twist_slist_free_all (struct twist_slist *list)
{
  while (list != NULL)
    {
      struct twist_slist *next = list->next;
      free (list->data);
      free (list);
      list = next;
    }
}
