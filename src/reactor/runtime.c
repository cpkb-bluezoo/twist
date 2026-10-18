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

struct twist_runtime
{
  size_t nloops;
  struct twist_loop **loops;
  size_t dial_rr;
  struct twist_storage *storage;
};

struct twist_runtime *
twist_runtime_new (size_t nloops)
{
  struct twist_runtime *rt;
  size_t i;

  if (nloops == 0)
    nloops = 1;
  rt = calloc (1, sizeof *rt);
  if (rt == NULL)
    return NULL;
  rt->loops = calloc (nloops, sizeof *rt->loops);
  if (rt->loops == NULL)
    {
      free (rt);
      return NULL;
    }
  rt->nloops = nloops;
  for (i = 0; i < nloops; i++)
    {
      rt->loops[i] = twist_loop_new (0);
      if (rt->loops[i] == NULL)
        {
          twist_runtime_free (rt);
          return NULL;
        }
    }
  rt->storage = twist_storage_new (1, 32);
  if (rt->storage == NULL)
    {
      twist_runtime_free (rt);
      return NULL;
    }
  return rt;
}

void
twist_runtime_free (struct twist_runtime *rt)
{
  size_t i;

  if (rt == NULL)
    return;
  twist_storage_free (rt->storage);
  for (i = 0; i < rt->nloops; i++)
    twist_loop_free (rt->loops[i]);
  free (rt->loops);
  free (rt);
}

size_t
twist_runtime_next_worker (struct twist_runtime *rt)
{
  size_t i = rt->dial_rr % rt->nloops;
  rt->dial_rr++;
  return i;
}

struct twist_loop *
twist_runtime_dial_loop (struct twist_runtime *rt)
{
  return rt->loops[twist_runtime_next_worker (rt)];
}

struct twist_storage *
twist_runtime_storage (struct twist_runtime *rt)
{
  return rt->storage;
}
