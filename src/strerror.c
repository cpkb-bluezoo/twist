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

#include "gettext.h"
#include "twist-int.h"

const char *
twist_strerror (int err)
{
  switch (err)
    {
    case TWIST_OK:
      return _("no error");
    case TWIST_ERR_NOMEM:
      return _("out of memory");
    case TWIST_ERR_INVAL:
      return _("invalid argument");
    case TWIST_ERR_UNSUPPORTED:
      return _("unsupported protocol or option");
    case TWIST_ERR_RESOLVE:
      return _("could not resolve host");
    case TWIST_ERR_CONNECT:
      return _("could not connect");
    case TWIST_ERR_TIMEOUT:
      return _("operation timed out");
    case TWIST_ERR_PROTOCOL:
      return _("protocol error");
    case TWIST_ERR_TLS:
      return _("TLS error");
    case TWIST_ERR_CLOSED:
      return _("connection closed");
    case TWIST_ERR_AGAIN:
      return _("resource temporarily unavailable");
    case TWIST_ERR_AUTH:
      return _("authentication failed");
    case TWIST_ERR_REDIRECT:
      return _("too many redirects");
    case TWIST_ERR_URL:
      return _("malformed URL");
    case TWIST_ERR_ABORTED:
      return _("transfer aborted");
    case TWIST_ERR_FILE:
      return _("could not open file");
    case TWIST_ERR_HTTP:
      return _("server returned an error");
    case TWIST_ERR_ENCODING:
      return _("bad content encoding");
    case TWIST_ERR_HOSTKEY:
      return _("host key verification failed");
    case TWIST_ERR_RANGE:
      return _("the range cannot be delivered");
    case TWIST_ERR_RESUME:
      return _("the transfer cannot be resumed");
    case TWIST_ERR_QUOTE:
      return _("a quote command failed");
    case TWIST_ERR_PARTIAL:
      return _("transferred a partial file");
    case TWIST_ERR_RECURSIVE:
      return _("an API function was called from inside a callback");
    case TWIST_ERR_PROXY:
      return _("the proxy refused the connection");
    default:
      return _("unknown error");
    }
}

const char *
twist_version (void)
{
  return TWIST_VERSION_STRING;
}
