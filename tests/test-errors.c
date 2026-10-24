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

#include "check.h"
#include "twist-int.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void
test_errors (void)
{
  struct twist_easy *easy;

  check (strcmp (twist_strerror (TWIST_ERR_FILE),
                 twist_strerror (TWIST_ERR_URL)) != 0, "file distinct");
  check (strcmp (twist_strerror (TWIST_ERR_HTTP),
                 twist_strerror (TWIST_ERR_PROTOCOL)) != 0, "http distinct");
  check (strcmp (twist_strerror (TWIST_ERR_HOSTKEY),
                 twist_strerror (TWIST_ERR_AUTH)) != 0, "hostkey distinct");
  check (strcmp (twist_strerror (TWIST_ERR_RANGE),
                 twist_strerror (TWIST_ERR_RESUME)) != 0, "range distinct");
  check (strcmp (twist_strerror (TWIST_ERR_RESUME),
                 twist_strerror (TWIST_ERR_ABORTED)) != 0, "resume distinct");
  check (strcmp (twist_strerror (TWIST_ERR_PARTIAL),
                 twist_strerror (TWIST_ERR_CLOSED)) != 0, "partial distinct");
  check (strcmp (twist_strerror (TWIST_ERR_RECURSIVE),
                 twist_strerror (TWIST_ERR_INVAL)) != 0, "recursive distinct");
  check (strcmp (twist_strerror (TWIST_ERR_UNKNOWN_OPTION),
                 twist_strerror (TWIST_ERR_OPTION_SYNTAX)) != 0,
         "option errors distinct");
  check (strcmp (twist_strerror (TWIST_ERR_UNKNOWN_OPTION),
                 twist_strerror (-1)) != 0, "unknown option has a sentence");
  check (strcmp (twist_strerror (TWIST_ERR_OPTION_SYNTAX),
                 twist_strerror (-1)) != 0, "option syntax has a sentence");
  easy = twist_easy_init ();
  check (easy != NULL && twist_easy_error (easy) == NULL, "no detail");
  twist_easy_set_error (easy, twist_strdup ("could not open file /no/such"));
  check (twist_easy_error (easy) != NULL
         && strcmp (twist_easy_error (easy),
                    "could not open file /no/such") == 0, "detail");
  twist_easy_cleanup (easy);
}

int
main (void)
{
  test_errors ();
  return tests_finish ();
}
