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

struct twist_file
{
  struct twist_easy *easy;
  uint8_t *data;
  size_t len;
  int err;
};

static void
file_free (void *p)
{
  struct twist_file *f = p;

  if (f == NULL)
    return;
  free (f->data);
  free (f);
}

static void
file_work (void *arg)
{
  struct twist_file *f = arg;
  const char *path;
  FILE *fp;
  long sz;

  path = f->easy->url != NULL ? f->easy->url->path : NULL;
  if (path == NULL || path[0] == 0)
    {
      f->err = TWIST_ERR_URL;
      return;
    }
  fp = fopen (path, "rb");
  if (fp == NULL)
    {
      f->err = TWIST_ERR_URL;
      return;
    }
  if (fseek (fp, 0, SEEK_END) != 0)
    {
      fclose (fp);
      f->err = TWIST_ERR_URL;
      return;
    }
  sz = ftell (fp);
  if (sz < 0 || fseek (fp, 0, SEEK_SET) != 0)
    {
      fclose (fp);
      f->err = TWIST_ERR_URL;
      return;
    }
  f->data = twist_xmalloc ((size_t) sz + 1);
  if (f->data == NULL)
    {
      fclose (fp);
      f->err = TWIST_ERR_NOMEM;
      return;
    }
  if (sz > 0 && fread (f->data, 1, (size_t) sz, fp) != (size_t) sz)
    {
      fclose (fp);
      f->err = TWIST_ERR_URL;
      return;
    }
  f->len = (size_t) sz;
  fclose (fp);
}

static void
file_done (void *user, int err)
{
  struct twist_file *f = user;
  struct twist_easy *easy = f->easy;

  if (f->err != TWIST_OK)
    err = f->err;
  if (err == TWIST_OK && f->data != NULL && easy->write_cb != NULL && f->len > 0)
    {
      size_t n = easy->write_cb ((char *) f->data, 1, f->len, easy->write_data);
      if (n < f->len)
        err = TWIST_ERR_ABORTED;
    }
  if (err == TWIST_OK)
    easy->size_download = f->len;
  twist_easy_finish (easy, err);
}

int
twist_file_attach (struct twist_easy *easy)
{
  struct twist_file *f;
  struct twist_storage *st;
  int rc;

  f = calloc (1, sizeof *f);
  if (f == NULL)
    return TWIST_ERR_NOMEM;
  f->easy = easy;
  easy->xfer = f;
  easy->xfer_free = file_free;
  st = twist_storage_new (0, 1);
  if (st == NULL)
    return TWIST_ERR_NOMEM;
  rc = twist_storage_submit (st, file_work, f, file_done, f, NULL);
  twist_storage_free (st);
  return rc;
}
