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

#include <string.h>

int
twist_scheme_unsupported (struct twist_easy *easy)
{
  (void) easy;
  return TWIST_ERR_UNSUPPORTED;
}

static int
attach_http (struct twist_easy *easy)
{
  return twist_http_attach (easy);
}

static int
attach_file (struct twist_easy *easy)
{
  return twist_file_attach (easy);
}

static int
attach_ftp (struct twist_easy *easy)
{
  return twist_ftp_attach (easy);
}

static int
attach_smtp (struct twist_easy *easy)
{
  return twist_smtp_attach (easy);
}

static int
attach_imap (struct twist_easy *easy)
{
  return twist_imap_attach (easy);
}

static int
attach_pop3 (struct twist_easy *easy)
{
  return twist_pop3_attach (easy);
}

static int
attach_mqtt (struct twist_easy *easy)
{
  return twist_mqtt_attach (easy);
}

static int
attach_ldap (struct twist_easy *easy)
{
  return twist_ldap_attach (easy);
}

static int
attach_gopher (struct twist_easy *easy)
{
  return twist_gopher_attach (easy);
}

static int
attach_dict (struct twist_easy *easy)
{
  return twist_dict_attach (easy);
}

static const struct twist_scheme schemes[] = {
  { "http", 80, TWIST_SCHEME_PROXY_OK | TWIST_SCHEME_READY, attach_http },
  { "https", 443, TWIST_SCHEME_TLS | TWIST_SCHEME_PROXY_OK | TWIST_SCHEME_READY,
    attach_http },
  { "ws", 80, TWIST_SCHEME_PROXY_OK | TWIST_SCHEME_READY, attach_http },
  { "wss", 443, TWIST_SCHEME_TLS | TWIST_SCHEME_PROXY_OK | TWIST_SCHEME_READY,
    attach_http },
  { "ftp", 21, TWIST_SCHEME_MULTI | TWIST_SCHEME_PROXY_OK | TWIST_SCHEME_READY,
    attach_ftp },
  { "ftps", 990,
    TWIST_SCHEME_TLS | TWIST_SCHEME_MULTI | TWIST_SCHEME_PROXY_OK | TWIST_SCHEME_READY,
    attach_ftp },
  { "smtp", 25, TWIST_SCHEME_PROXY_OK | TWIST_SCHEME_READY, attach_smtp },
  { "smtps", 465, TWIST_SCHEME_TLS | TWIST_SCHEME_PROXY_OK | TWIST_SCHEME_READY,
    attach_smtp },
  { "imap", 143, TWIST_SCHEME_PROXY_OK | TWIST_SCHEME_READY, attach_imap },
  { "imaps", 993, TWIST_SCHEME_TLS | TWIST_SCHEME_PROXY_OK | TWIST_SCHEME_READY,
    attach_imap },
  { "pop3", 110, TWIST_SCHEME_PROXY_OK | TWIST_SCHEME_READY, attach_pop3 },
  { "pop3s", 995, TWIST_SCHEME_TLS | TWIST_SCHEME_PROXY_OK | TWIST_SCHEME_READY,
    attach_pop3 },
  { "ldap", 389, TWIST_SCHEME_PROXY_OK | TWIST_SCHEME_READY, attach_ldap },
  { "ldaps", 636, TWIST_SCHEME_TLS | TWIST_SCHEME_PROXY_OK | TWIST_SCHEME_READY,
    attach_ldap },
  { "mqtt", 1883, TWIST_SCHEME_PROXY_OK | TWIST_SCHEME_READY, attach_mqtt },
  { "mqtts", 8883, TWIST_SCHEME_TLS | TWIST_SCHEME_PROXY_OK | TWIST_SCHEME_READY,
    attach_mqtt },
  { "dict", 2628, TWIST_SCHEME_PROXY_OK | TWIST_SCHEME_READY, attach_dict },
  { "gopher", 70, TWIST_SCHEME_PROXY_OK | TWIST_SCHEME_READY, attach_gopher },
  { "gophers", 70, TWIST_SCHEME_TLS | TWIST_SCHEME_PROXY_OK | TWIST_SCHEME_READY,
    attach_gopher },
  { "telnet", 23, TWIST_SCHEME_PROXY_OK, twist_scheme_unsupported },
  { "rtsp", 554, TWIST_SCHEME_PROXY_OK, twist_scheme_unsupported },
  { "tftp", 69, TWIST_SCHEME_DATAGRAM, twist_scheme_unsupported },
  { "file", 0, TWIST_SCHEME_READY, attach_file },
  { "scp", 22, TWIST_SCHEME_PROXY_OK, twist_scheme_unsupported },
  { "sftp", 22, TWIST_SCHEME_PROXY_OK, twist_scheme_unsupported },
  { "smb", 445, TWIST_SCHEME_PROXY_OK, twist_scheme_unsupported },
  { "smbs", 445, TWIST_SCHEME_TLS | TWIST_SCHEME_PROXY_OK, twist_scheme_unsupported },
  { "rtmp", 1935, TWIST_SCHEME_PROXY_OK, twist_scheme_unsupported },
  { "rtmps", 443, TWIST_SCHEME_TLS | TWIST_SCHEME_PROXY_OK, twist_scheme_unsupported }
};

const struct twist_scheme *
twist_scheme_by_name (const char *name)
{
  size_t i;

  if (name == NULL)
    return NULL;
  for (i = 0; i < sizeof schemes / sizeof schemes[0]; i++)
    if (strcmp (schemes[i].name, name) == 0)
      return &schemes[i];
  return NULL;
}
