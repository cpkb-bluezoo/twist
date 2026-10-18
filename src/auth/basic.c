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

int
twist_auth_basic (const char *user, const char *pass, char **out)
{
  char raw[256];
  char *enc = NULL;
  char *hdr;
  int n;
  int rc;

  n = snprintf (raw, sizeof raw, "%s:%s", user != NULL ? user : "",
                pass != NULL ? pass : "");
  if (n < 0 || (size_t) n >= sizeof raw)
    return TWIST_ERR_AUTH;
  rc = twist_b64_encode ((const uint8_t *) raw, (size_t) n, &enc);
  if (rc != TWIST_OK)
    return rc;
  hdr = twist_xmalloc (strlen (enc) + 32);
  if (hdr == NULL)
    {
      free (enc);
      return TWIST_ERR_NOMEM;
    }
  sprintf (hdr, "Authorization: Basic %s", enc);
  free (enc);
  *out = hdr;
  return TWIST_OK;
}

