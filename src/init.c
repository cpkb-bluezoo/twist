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

#include <foxtrot/crypto.h>

static int inited;

int
twist_global_init (void)
{
  int rc;

  if (inited)
    return TWIST_OK;
  twist_i18n_init ();
  /* libgcrypt must be initialised before the storage pool starts threads.
     Only SSH needs it, and foxtrot refuses a libgcrypt that is too old, so
     a failure here is not fatal: the SSH schemes report it when used.  */
  (void) gf_crypto_init ();
  rc = twist_tls_register ();
  if (rc != TWIST_OK)
    return rc;
  rc = twist_quic_register ();
  if (rc != TWIST_OK)
    return rc;
  inited = 1;
  return TWIST_OK;
}

void
twist_global_cleanup (void)
{
  inited = 0;
}
