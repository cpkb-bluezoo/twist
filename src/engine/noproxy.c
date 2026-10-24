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

#include <arpa/inet.h>
#include <ctype.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

/* Which proxy a transfer uses: the one it was given, or else the
   environment's, unless the host is on the list of those that go direct,
   which is also the application's or the environment's.  */

/* Whether ADDRESS is within NETWORK/BITS.  BITS 0 is all of it: an address
   with no number names one host.  */
static int
cidr4 (const char *address, const char *network, unsigned long bits)
{
  struct in_addr a, n;
  uint32_t mask;

  if (bits > 32 || inet_pton (AF_INET, address, &a) != 1
      || inet_pton (AF_INET, network, &n) != 1)
    return 0;
  if (bits == 0 || bits == 32)
    return a.s_addr == n.s_addr;
  mask = htonl (0xffffffffu << (32 - bits));
  return ((a.s_addr ^ n.s_addr) & mask) == 0;
}

static int
cidr6 (const char *address, const char *network, unsigned long bits)
{
  unsigned char a[16], n[16];
  unsigned bytes, rest;

  if (bits == 0)
    bits = 128;
  if (bits > 128 || inet_pton (AF_INET6, address, a) != 1
      || inet_pton (AF_INET6, network, n) != 1)
    return 0;
  bytes = (unsigned) bits / 8;
  rest = (unsigned) bits & 7;
  if (bytes > 0 && memcmp (a, n, bytes) != 0)
    return 0;
  if (rest != 0 && ((a[bytes] ^ n[bytes]) & (0xffu << (8 - rest)) & 0xffu) != 0)
    return 0;
  return 1;
}

int
twist_noproxy_match (const char *name, const char *list)
{
  enum { HOST, IPV4, IPV6 } type = HOST;
  char hostip[128];
  size_t namelen;
  const char *p;
  struct in_addr probe;

  if (name == NULL || name[0] == 0 || list == NULL || list[0] == 0)
    return 0;
  if (strcmp (list, "*") == 0)
    return 1;
  if (name[0] == '[' || strchr (name, ':') != NULL)
    {
      /* An IPv6 address, with or without brackets, and maybe a zone.  */
      const char *end;

      if (name[0] == '[')
        {
          name++;
          end = strchr (name, ']');
          if (end == NULL)
            return 0;
        }
      else
        {
          end = strchr (name, '%');
          if (end == NULL)
            end = name + strlen (name);
        }
      namelen = (size_t) (end - name);
      if (namelen >= sizeof hostip)
        return 0;
      memcpy (hostip, name, namelen);
      hostip[namelen] = 0;
      name = hostip;
      type = IPV6;
    }
  else
    {
      namelen = strlen (name);
      if (inet_pton (AF_INET, name, &probe) == 1)
        type = IPV4;
      else if (name[namelen - 1] == '.')
        namelen--;
    }
  p = list;
  while (*p != 0)
    {
      const char *token;
      size_t tokenlen = 0;
      int match = 0;

      while (*p == ' ' || *p == '\t')
        p++;
      token = p;
      while (*p != 0 && *p != ' ' && *p != '\t' && *p != ',')
        {
          p++;
          tokenlen++;
        }
      if (tokenlen > 0)
        {
          if (type == HOST)
            {
              /* A trailing dot and a leading one do not count.  */
              if (token[tokenlen - 1] == '.')
                tokenlen--;
              if (tokenlen > 0 && *token == '.')
                {
                  token++;
                  tokenlen--;
                }
              /* example.com matches example.com and www.example.com, and not
                 nonexample.com.  */
              if (tokenlen == namelen)
                match = strncasecmp (token, name, namelen) == 0;
              else if (tokenlen > 0 && tokenlen < namelen)
                match = name[namelen - tokenlen - 1] == '.'
                        && strncasecmp (token, name + (namelen - tokenlen),
                                        tokenlen) == 0;
            }
          else if (tokenlen < sizeof hostip)
            {
              char check[128];
              char *slash;
              unsigned long bits = 0;

              memcpy (check, token, tokenlen);
              check[tokenlen] = 0;
              slash = strchr (check, '/');
              if (slash != NULL)
                {
                  char *end;

                  *slash = 0;
                  bits = strtoul (slash + 1, &end, 10);
                  if (end == slash + 1 || *end != 0)
                    bits = 1000;	/* Never a match.  */
                }
              match = type == IPV6 ? cidr6 (name, check, bits)
                                   : cidr4 (name, check, bits);
            }
        }
      if (match)
        return 1;
      while (*p == ' ' || *p == '\t')
        p++;
      /* A name after a blank is another name, as if there were a comma.  */
      while (*p == ',')
        p++;
    }
  return 0;
}

/* The value of the environment variable for SCHEME's proxy, the lower-case
   name before the upper-case one.  http_proxy is the exception, as the upper
   case one can be set by a web server from a header (CGI).  */
static const char *
env_proxy (const char *scheme)
{
  char lower[64];
  char upper[64];
  const char *v;
  size_t n = strlen (scheme);
  size_t i;

  if (n + sizeof "_proxy" > sizeof lower)
    return NULL;
  for (i = 0; i < n; i++)
    {
      lower[i] = (char) tolower ((unsigned char) scheme[i]);
      upper[i] = (char) toupper ((unsigned char) scheme[i]);
    }
  memcpy (lower + n, "_proxy", sizeof "_proxy");
  memcpy (upper + n, "_PROXY", sizeof "_PROXY");
  v = twist_getenv_secure (lower);
  if (v == NULL && strcmp (lower, "http_proxy") != 0)
    v = twist_getenv_secure (upper);
  if (v != NULL)
    return v;
  /* A WebSocket goes through the proxy of the HTTP it is made from.  */
  if (strcmp (lower, "ws_proxy") == 0)
    v = twist_getenv_secure ("http_proxy");
  else if (strcmp (lower, "wss_proxy") == 0)
    {
      v = twist_getenv_secure ("https_proxy");
      if (v == NULL)
        v = twist_getenv_secure ("HTTPS_PROXY");
    }
  if (v != NULL)
    return v;
  v = twist_getenv_secure ("all_proxy");
  if (v == NULL)
    v = twist_getenv_secure ("ALL_PROXY");
  return v;
}

/* Whether the host of the URL is one that goes direct: on the list given, or
   else the environment's.  */
int
twist_transfer_noproxy (const struct twist_transfer *transfer)
{
  const char *noproxy = transfer->noproxy_set ? transfer->noproxy : NULL;

  if (!transfer->noproxy_set)
    {
      noproxy = twist_getenv_secure ("no_proxy");
      if (noproxy == NULL)
        noproxy = twist_getenv_secure ("NO_PROXY");
    }
  return transfer->url != NULL && twist_noproxy_match (transfer->url->host,
                                                       noproxy);
}

const char *
twist_transfer_proxy (const struct twist_transfer *transfer)
{
  const struct twist_scheme *scheme;
  const char *proxy;
  const char *noproxy;

  if (transfer == NULL)
    return NULL;
  if (transfer->proxy != NULL)
    {
      /* Given: "" is none, and is not overridden by the environment.  */
      proxy = transfer->proxy;
    }
  else
    {
      scheme = transfer->url != NULL && transfer->url->scheme != NULL
        ? twist_scheme_by_name (transfer->url->scheme) : NULL;
      if (scheme == NULL || (scheme->flags & TWIST_SCHEME_PROXY_OK) == 0)
        return NULL;
      proxy = env_proxy (transfer->url->scheme);
    }
  if (proxy == NULL || proxy[0] == 0)
    return NULL;
  noproxy = transfer->noproxy_set ? transfer->noproxy : NULL;
  if (!transfer->noproxy_set)
    {
      noproxy = twist_getenv_secure ("no_proxy");
      if (noproxy == NULL)
        noproxy = twist_getenv_secure ("NO_PROXY");
    }
  if (transfer->url != NULL
      && twist_noproxy_match (transfer->url->host, noproxy))
    return NULL;
  return proxy;
}
