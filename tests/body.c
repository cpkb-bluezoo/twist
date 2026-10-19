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

#include "body.h"

#include <string.h>

char mail_body[128];
size_t mail_body_len;

size_t
mail_write (char *ptr, size_t size, size_t nmemb, void *user)
{
  size_t n = size * nmemb;

  (void) user;
  if (mail_body_len + n < sizeof mail_body)
    {
      memcpy (mail_body + mail_body_len, ptr, n);
      mail_body_len += n;
    }
  return n;
}
