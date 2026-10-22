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

#include <arpa/inet.h>
#include <ctype.h>
#include <netinet/in.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

/* A tunnel through a proxy: HTTP CONNECT, or SOCKS5.  The proxy gets the
   connection first and says when the tunnel is open; from then on the
   protocol of the transfer has it, and what the proxy has not used of what it
   was given is the tunnel's, not its own.  An SSH or an SMTP server speaks
   first, so its first bytes can arrive in the same read as the proxy's reply.

   A refusal has a status: 56 for a CONNECT that failed, 97 for SOCKS.  */

#define PX_MAX 16384		/* The longest reply from a proxy.  */

enum
{
  PX_START = 0,
  PX_HTTP,
  PX_SOCKS_GREET,
  PX_SOCKS_AUTH,		/* Send the credentials.  */
  PX_SOCKS_AUTHWAIT,
  PX_SOCKS_ASK,			/* Send the request.  */
  PX_SOCKS_CONNECT,
  PX_READY,
  PX_FAILED
};

struct twist_proxy
{
  int kind;
  int state;
  char *host;
  int port;
  char *target_host;
  int target_port;
  char *user;
  char *pass;
  void *inner_user;
  const struct twist_protocol_handler *inner;
  struct twist_endpoint *ep;
  struct twist_easy *easy;
  uint8_t *acc;
  size_t acc_len, acc_cap;
  char error[200];
  int status;
  struct twist_protocol_handler handler;
};

static void
swap_user (struct twist_proxy *p, int to_inner)
{
  if (p->ep == NULL)
    return;
  p->ep->user_data = to_inner ? p->inner_user : p;
}

/* The proxy said no.  The words and the status are kept, and the transfer
   is told.  */
static int
failed (struct twist_proxy *p, int status, const char *fmt, ...)
  __attribute__ ((format (printf, 3, 4)));

static int
failed (struct twist_proxy *p, int status, const char *fmt, ...)
{
  va_list ap;

  va_start (ap, fmt);
  vsnprintf (p->error, sizeof p->error, fmt, ap);
  va_end (ap);
  p->status = status;
  p->state = PX_FAILED;
  return TWIST_ERR_PROXY;
}

const char *
twist_proxy_error (const struct twist_proxy *p, int *status)
{
  if (p == NULL || p->error[0] == 0)
    return NULL;
  if (status != NULL)
    *status = p->status;
  return p->error;
}

/* The target as an address a proxy can be given: an IPv6 address has no
   zone, which means something only on this machine.  */
static void
target_address (const struct twist_proxy *p, char *out, size_t cap)
{
  const char *h = p->target_host != NULL ? p->target_host : "";
  size_t n = strcspn (h, "%");

  if (n >= cap)
    n = cap - 1;
  memcpy (out, h, n);
  out[n] = 0;
}

static void
proxy_connected (struct twist_endpoint *ep)
{
  struct twist_proxy *p = ep->user_data;
  uint8_t *out = NULL;
  size_t len = 0;

  p->ep = ep;
  if (twist_proxy_opening (p, &out, &len) == TWIST_OK && out != NULL)
    {
      twist_endpoint_send (ep, out, len);
      free (out);
    }
}

/* The proxy refused: the transfer gets the words, and an error.  */
static void
proxy_refused (struct twist_proxy *p, struct twist_endpoint *ep)
{
  if (p->easy != NULL && twist_easy_error (p->easy) == NULL)
    {
      twist_easy_set_error (p->easy, twist_strdup (p->error));
      p->easy->proto_status = p->status;
    }
  if (p->inner != NULL && p->inner->error != NULL)
    {
      swap_user (p, 1);
      p->inner->error (ep, TWIST_ERR_PROXY);
      swap_user (p, 0);
    }
}

static size_t
proxy_receive (struct twist_endpoint *ep, const uint8_t *data, size_t len)
{
  struct twist_proxy *p = ep->user_data;
  uint8_t *out = NULL;
  size_t out_len = 0, used = 0;
  int ready = 0;

  p->ep = ep;
  if (p->state == PX_READY && p->inner != NULL && p->inner->receive != NULL)
    {
      size_t n;

      swap_user (p, 1);
      n = p->inner->receive (ep, data, len);
      swap_user (p, 0);
      return n;
    }
  if (p->state == PX_FAILED)
    return len;
  if (twist_proxy_feed (p, data, len, &used, &ready) != TWIST_OK)
    {
      proxy_refused (p, ep);
      return len;
    }
  /* The credentials, or the request, are next.  */
  if (twist_proxy_opening (p, &out, &out_len) == TWIST_OK && out != NULL)
    {
      twist_endpoint_send (ep, out, out_len);
      free (out);
    }
  if (ready && p->inner != NULL && p->inner->connected != NULL)
    {
      swap_user (p, 1);
      p->inner->connected (ep);
      swap_user (p, 0);
    }
  /* Only what was the proxy's is taken; the rest is offered again, and goes
     to the transfer.  */
  return used;
}

static void
proxy_forward_disc (struct twist_endpoint *ep, int error)
{
  struct twist_proxy *p = ep->user_data;

  p->ep = ep;

  if (p->inner != NULL && p->inner->disconnected != NULL)
    {
      swap_user (p, 1);
      p->inner->disconnected (ep, error);
      swap_user (p, 0);
    }
}

static void
proxy_forward_sec (struct twist_endpoint *ep, const char *alpn, size_t n)
{
  struct twist_proxy *p = ep->user_data;

  p->ep = ep;

  if (p->inner != NULL && p->inner->security_established != NULL)
    {
      swap_user (p, 1);
      p->inner->security_established (ep, alpn, n);
      swap_user (p, 0);
    }
}

static void
proxy_forward_err (struct twist_endpoint *ep, int error)
{
  struct twist_proxy *p = ep->user_data;

  p->ep = ep;

  if (p->inner != NULL && p->inner->error != NULL)
    {
      swap_user (p, 1);
      p->inner->error (ep, error);
      swap_user (p, 0);
    }
}

/* Percent escapes undone; what is not one is left.  */
static char *
unescape (const char *s, size_t n)
{
  char *out = malloc (n + 1);
  size_t i, o = 0;

  if (out == NULL)
    return NULL;
  for (i = 0; i < n; i++)
    {
      if (s[i] == '%' && i + 2 < n
          && isxdigit ((unsigned char) s[i + 1])
          && isxdigit ((unsigned char) s[i + 2]))
        {
          char hex[3] = { s[i + 1], s[i + 2], 0 };

          out[o++] = (char) strtol (hex, NULL, 16);
          i += 2;
        }
      else
        out[o++] = s[i];
    }
  out[o] = 0;
  return out;
}

int
twist_proxy_parse (const char *s, int *kind, char **host, int *port,
                   char **user, char **pass)
{
  const char *p = s, *sep, *end, *at, *hp, *colon;
  int k = TWIST_PROXY_HTTP;
  int def = 8080;
  size_t alen;
  char *auth = NULL;

  if (s == NULL || kind == NULL || host == NULL || port == NULL)
    return TWIST_ERR_INVAL;
  *host = NULL;
  if (user != NULL)
    *user = NULL;
  if (pass != NULL)
    *pass = NULL;
  sep = strstr (s, "://");
  if (sep != NULL)
    {
      size_t sl = (size_t) (sep - s);

      if (sl == 4 && strncasecmp (s, "http", 4) == 0)
        ;
      else if ((sl == 6 && strncasecmp (s, "socks5", 6) == 0)
               || (sl == 7 && strncasecmp (s, "socks5h", 7) == 0))
        {
          k = TWIST_PROXY_SOCKS5;
          def = 1080;
        }
      else
        /* https (a proxy spoken to over TLS), socks4, anything else: not
           spoken here, and not to be taken for something that is.  */
        return TWIST_ERR_UNSUPPORTED;
      p = sep + 3;
    }
  end = p + strcspn (p, "/?#");
  alen = (size_t) (end - p);
  auth = malloc (alen + 1);
  if (auth == NULL)
    return TWIST_ERR_NOMEM;
  memcpy (auth, p, alen);
  auth[alen] = 0;
  at = strrchr (auth, '@');
  hp = at != NULL ? at + 1 : auth;
  if (at != NULL && (user != NULL || pass != NULL))
    {
      const char *c = memchr (auth, ':', (size_t) (at - auth));
      size_t ul = c != NULL ? (size_t) (c - auth) : (size_t) (at - auth);

      if (user != NULL)
        *user = unescape (auth, ul);
      if (pass != NULL)
        *pass = c != NULL ? unescape (c + 1, (size_t) (at - c - 1))
                          : twist_strdup ("");
      if ((user != NULL && *user == NULL) || (pass != NULL && *pass == NULL))
        goto nomem;
    }
  if (*hp == '[')
    {
      const char *close = strchr (hp, ']');

      if (close == NULL || close == hp + 1)
        goto bad;
      *host = unescape (hp + 1, (size_t) (close - hp - 1));
      colon = close[1] == ':' ? close + 1 : NULL;
      if (colon == NULL && close[1] != 0)
        goto bad;
    }
  else
    {
      colon = strchr (hp, ':');
      if (colon != NULL && strchr (colon + 1, ':') != NULL)
        goto bad;
      *host = colon != NULL ? twist_xmalloc ((size_t) (colon - hp) + 1)
                            : twist_strdup (hp);
      if (*host != NULL && colon != NULL)
        {
          memcpy (*host, hp, (size_t) (colon - hp));
          (*host)[colon - hp] = 0;
        }
    }
  if (*host == NULL)
    goto nomem;
  if ((*host)[0] == 0)
    goto bad;
  if (colon != NULL)
    {
      char *e = NULL;
      long v;

      if (colon[1] < '0' || colon[1] > '9')
        goto bad;
      v = strtol (colon + 1, &e, 10);
      if (*e != 0 || v < 1 || v > 65535)
        goto bad;
      *port = (int) v;
    }
  else
    *port = def;
  *kind = k;
  free (auth);
  return TWIST_OK;
bad:
  free (auth);
  free (*host);
  *host = NULL;
  if (user != NULL)
    {
      free (*user);
      *user = NULL;
    }
  if (pass != NULL)
    {
      free (*pass);
      *pass = NULL;
    }
  return TWIST_ERR_URL;
nomem:
  free (auth);
  free (*host);
  *host = NULL;
  if (user != NULL)
    {
      free (*user);
      *user = NULL;
    }
  if (pass != NULL)
    {
      free (*pass);
      *pass = NULL;
    }
  return TWIST_ERR_NOMEM;
}

struct twist_proxy *
twist_proxy_new (int kind, const char *host, int port,
                 const struct twist_protocol_handler *inner)
{
  struct twist_proxy *p = calloc (1, sizeof *p);

  if (p == NULL)
    return NULL;
  p->kind = kind;
  p->port = port;
  p->host = twist_strdup (host != NULL ? host : "");
  p->inner = inner;
  if (p->host == NULL)
    {
      free (p);
      return NULL;
    }
  p->handler.connected = proxy_connected;
  p->handler.receive = proxy_receive;
  p->handler.disconnected = proxy_forward_disc;
  p->handler.security_established = proxy_forward_sec;
  p->handler.error = proxy_forward_err;
  return p;
}

void
twist_proxy_free (struct twist_proxy *proxy)
{
  if (proxy == NULL)
    return;
  free (proxy->host);
  free (proxy->target_host);
  if (proxy->pass != NULL)
    {
      memset (proxy->pass, 0, strlen (proxy->pass));
      free (proxy->pass);
    }
  free (proxy->user);
  free (proxy->acc);
  free (proxy);
}

void
twist_proxy_set_target (struct twist_proxy *proxy, const char *host, int port)
{
  if (proxy == NULL)
    return;
  free (proxy->target_host);
  proxy->target_host = twist_strdup (host != NULL ? host : "");
  proxy->target_port = port;
}

void
twist_proxy_set_user (struct twist_proxy *proxy, void *user)
{
  if (proxy != NULL)
    proxy->inner_user = user;
}

void
twist_proxy_set_easy (struct twist_proxy *proxy, struct twist_easy *easy)
{
  if (proxy != NULL)
    proxy->easy = easy;
}

void
twist_proxy_set_credentials (struct twist_proxy *proxy, const char *user,
                             const char *pass)
{
  if (proxy == NULL)
    return;
  free (proxy->user);
  if (proxy->pass != NULL)
    {
      memset (proxy->pass, 0, strlen (proxy->pass));
      free (proxy->pass);
    }
  proxy->user = user != NULL ? twist_strdup (user) : NULL;
  proxy->pass = user != NULL ? twist_strdup (pass != NULL ? pass : "") : NULL;
}

void
twist_proxy_configure (struct twist_proxy *proxy, struct twist_easy *easy,
                       const char *user, const char *pass)
{
  if (proxy == NULL)
    return;
  proxy->easy = easy;
  if (user != NULL)
    twist_proxy_set_credentials (proxy, user, pass);
  else if (easy != NULL && easy->proxy_userpwd != NULL)
    {
      /* As given: -U is not percent-encoded.  */
      const char *c = strchr (easy->proxy_userpwd, ':');

      if (c == NULL)
        twist_proxy_set_credentials (proxy, easy->proxy_userpwd, "");
      else
        {
          char *u = twist_xmalloc ((size_t) (c - easy->proxy_userpwd) + 1);

          if (u == NULL)
            return;
          memcpy (u, easy->proxy_userpwd, (size_t) (c - easy->proxy_userpwd));
          u[c - easy->proxy_userpwd] = 0;
          twist_proxy_set_credentials (proxy, u, c + 1);
          free (u);
        }
    }
}

int
twist_proxy_opening (struct twist_proxy *proxy, uint8_t **out, size_t *len)
{
  if (proxy == NULL || out == NULL || len == NULL)
    return TWIST_ERR_INVAL;
  *out = NULL;
  *len = 0;
  if (proxy->kind == TWIST_PROXY_HTTP && proxy->state == PX_START)
    {
      char addr[256], auth[512] = "", line[1024];
      char *enc = NULL;
      const char *brk_l = "", *brk_r = "";
      int n;

      target_address (proxy, addr, sizeof addr);
      if (strchr (addr, ':') != NULL)
        {
          brk_l = "[";
          brk_r = "]";
        }
      if (proxy->user != NULL)
        {
          char cred[600];
          int cn = snprintf (cred, sizeof cred, "%s:%s", proxy->user,
                             proxy->pass != NULL ? proxy->pass : "");

          if (cn < 0 || (size_t) cn >= sizeof cred
              || twist_b64_encode ((const uint8_t *) cred, (size_t) cn, &enc)
                 != TWIST_OK)
            return TWIST_ERR_NOMEM;
          snprintf (auth, sizeof auth, "Proxy-Authorization: Basic %s\r\n",
                    enc);
          memset (cred, 0, sizeof cred);
          free (enc);
        }
      n = snprintf (line, sizeof line,
                    "CONNECT %s%s%s:%d HTTP/1.1\r\nHost: %s%s%s:%d\r\n%s\r\n",
                    brk_l, addr, brk_r, proxy->target_port,
                    brk_l, addr, brk_r, proxy->target_port, auth);
      if (n < 0 || (size_t) n >= sizeof line)
        return TWIST_ERR_CONNECT;
      *out = (uint8_t *) twist_strdup (line);
      if (*out == NULL)
        return TWIST_ERR_NOMEM;
      *len = (size_t) n;
      proxy->state = PX_HTTP;
      memset (auth, 0, sizeof auth);
      return TWIST_OK;
    }
  if (proxy->kind == TWIST_PROXY_SOCKS5 && proxy->state == PX_START)
    {
      /* "No authentication", and with credentials, "user and password".  */
      size_t n = proxy->user != NULL ? 4 : 3;

      *out = twist_xmalloc (n);
      if (*out == NULL)
        return TWIST_ERR_NOMEM;
      (*out)[0] = 5;
      (*out)[1] = (uint8_t) (n - 2);
      (*out)[2] = 0;
      if (n == 4)
        (*out)[3] = 2;
      *len = n;
      proxy->state = PX_SOCKS_GREET;
      return TWIST_OK;
    }
  if (proxy->kind == TWIST_PROXY_SOCKS5 && proxy->state == PX_SOCKS_AUTH)
    {
      size_t ul = strlen (proxy->user), pl = strlen (proxy->pass);
      uint8_t *buf;

      if (ul > 255 || pl > 255)
        return failed (proxy, 97, _("the proxy's user name or password is "
                                    "too long for SOCKS5"));
      buf = twist_xmalloc (3 + ul + pl);
      if (buf == NULL)
        return TWIST_ERR_NOMEM;
      buf[0] = 1;
      buf[1] = (uint8_t) ul;
      memcpy (buf + 2, proxy->user, ul);
      buf[2 + ul] = (uint8_t) pl;
      memcpy (buf + 3 + ul, proxy->pass, pl);
      *out = buf;
      *len = 3 + ul + pl;
      proxy->state = PX_SOCKS_AUTHWAIT;
      return TWIST_OK;
    }
  if (proxy->kind == TWIST_PROXY_SOCKS5 && proxy->state == PX_SOCKS_ASK)
    {
      char host[256];
      struct in_addr a4;
      struct in6_addr a6;
      uint8_t *buf;
      size_t n, hl;

      target_address (proxy, host, sizeof host);
      hl = strlen (host);
      if (inet_pton (AF_INET, host, &a4) == 1)
        {
          n = 10;
          buf = twist_xmalloc (n);
          if (buf == NULL)
            return TWIST_ERR_NOMEM;
          buf[3] = 1;
          memcpy (buf + 4, &a4, 4);
        }
      else if (inet_pton (AF_INET6, host, &a6) == 1)
        {
          n = 22;
          buf = twist_xmalloc (n);
          if (buf == NULL)
            return TWIST_ERR_NOMEM;
          buf[3] = 4;
          memcpy (buf + 4, &a6, 16);
        }
      else
        {
          if (hl > 255)
            return TWIST_ERR_CONNECT;
          n = 7 + hl;
          buf = twist_xmalloc (n);
          if (buf == NULL)
            return TWIST_ERR_NOMEM;
          buf[3] = 3;
          buf[4] = (uint8_t) hl;
          memcpy (buf + 5, host, hl);
        }
      buf[0] = 5;
      buf[1] = 1;
      buf[2] = 0;
      buf[n - 2] = (uint8_t) (proxy->target_port >> 8);
      buf[n - 1] = (uint8_t) proxy->target_port;
      *out = buf;
      *len = n;
      proxy->state = PX_SOCKS_CONNECT;
      return TWIST_OK;
    }
  return TWIST_ERR_AGAIN;
}

static int
http_status (const uint8_t *buf, size_t len)
{
  const char *p = (const char *) buf;
  const char *sp;

  if (len < 12 || strncmp (p, "HTTP/", 5) != 0)
    return -1;
  sp = memchr (p, ' ', len);
  if (sp == NULL || sp + 4 > p + len)
    return -1;
  if (sp[1] < '0' || sp[1] > '9')
    return -1;
  return (sp[1] - '0') * 100 + (sp[2] - '0') * 10 + (sp[3] - '0');
}

static int
acc_add (struct twist_proxy *p, uint8_t c)
{
  if (p->acc_len >= p->acc_cap)
    {
      size_t cap = p->acc_cap == 0 ? 256 : p->acc_cap * 2;
      uint8_t *grown = realloc (p->acc, cap);

      if (grown == NULL)
        return TWIST_ERR_NOMEM;
      p->acc = grown;
      p->acc_cap = cap;
    }
  p->acc[p->acc_len++] = c;
  return TWIST_OK;
}

/* Is the reply to the SOCKS5 request all here?  The length depends on the
   kind of address it carries.  */
static int
socks_reply_complete (const struct twist_proxy *p, int *bad)
{
  size_t need;

  *bad = 0;
  if (p->acc_len < 4)
    return 0;
  if (p->acc[3] == 1)
    need = 10;
  else if (p->acc[3] == 4)
    need = 22;
  else if (p->acc[3] == 3)
    {
      if (p->acc_len < 5)
        return 0;
      need = 7 + (size_t) p->acc[4];
    }
  else
    {
      *bad = 1;
      return 0;
    }
  return p->acc_len >= need;
}

int
twist_proxy_feed (struct twist_proxy *proxy, const uint8_t *data, size_t len,
                  size_t *used, int *ready)
{
  size_t i = 0;
  int done = 0, bad;

  if (used != NULL)
    *used = 0;
  if (ready != NULL)
    *ready = 0;
  if (proxy == NULL)
    return TWIST_ERR_INVAL;
  if (proxy->state == PX_FAILED)
    return TWIST_ERR_PROXY;
  if (proxy->state == PX_READY)
    {
      if (ready != NULL)
        *ready = 1;
      return TWIST_OK;
    }
  /* A byte at a time, so that what follows the end of the reply is not taken
     for part of it.  */
  while (i < len && !done)
    {
      int rc;

      /* The proxy has said all it will until it is spoken to again.  */
      if (proxy->state != PX_HTTP && proxy->state != PX_SOCKS_GREET
          && proxy->state != PX_SOCKS_AUTHWAIT
          && proxy->state != PX_SOCKS_CONNECT)
        return failed (proxy, proxy->kind == TWIST_PROXY_HTTP ? 56 : 97,
                       _("the proxy sent more than was asked for"));
      rc = acc_add (proxy, data[i++]);
      if (rc != TWIST_OK)
        return rc;
      switch (proxy->state)
        {
        case PX_HTTP:
          if (proxy->acc_len >= 4
              && memcmp (proxy->acc + proxy->acc_len - 4, "\r\n\r\n", 4) == 0)
            done = 1;
          else if (proxy->acc_len >= PX_MAX)
            return failed (proxy, 56, _("CONNECT tunnel failed, the reply is "
                                        "too long"));
          break;
        case PX_SOCKS_GREET:
        case PX_SOCKS_AUTHWAIT:
          done = proxy->acc_len >= 2;
          break;
        case PX_SOCKS_CONNECT:
          done = socks_reply_complete (proxy, &bad);
          if (bad)
            return failed (proxy, 97, _("the SOCKS5 reply is not one"));
          break;
        default:
          break;
        }
    }
  if (used != NULL)
    *used = i;
  if (!done)
    return TWIST_OK;
  switch (proxy->state)
    {
    case PX_HTTP:
      {
        int status = http_status (proxy->acc, proxy->acc_len - 4);

        if (status < 0)
          return failed (proxy, 56, _("CONNECT tunnel failed, the reply is "
                                      "not HTTP"));
        if (status < 200 || status > 299)
          return failed (proxy, 56, _("CONNECT tunnel failed, response %d"),
                         status);
        proxy->state = PX_READY;
        if (ready != NULL)
          *ready = 1;
        break;
      }
    case PX_SOCKS_GREET:
      if (proxy->acc[0] != 5)
        return failed (proxy, 97, _("the SOCKS5 reply is not one"));
      if (proxy->acc[1] == 0xff)
        return failed (proxy, 97,
                       _("No authentication method was acceptable."));
      if (proxy->acc[1] == 2 && proxy->user != NULL)
        proxy->state = PX_SOCKS_AUTH;
      else if (proxy->acc[1] == 0)
        proxy->state = PX_SOCKS_ASK;
      else
        return failed (proxy, 97, _("the SOCKS5 server chose a way of "
                                    "authenticating that was not offered"));
      break;
    case PX_SOCKS_AUTHWAIT:
      if (proxy->acc[1] != 0)
        return failed (proxy, 97,
                       _("User was rejected by the SOCKS5 server (%d %d)."),
                       proxy->acc[0], proxy->acc[1]);
      proxy->state = PX_SOCKS_ASK;
      break;
    case PX_SOCKS_CONNECT:
      if (proxy->acc[0] != 5)
        return failed (proxy, 97, _("the SOCKS5 reply is not one"));
      if (proxy->acc[1] != 0)
        return failed (proxy, 97,
                       _("Can't complete SOCKS5 connection to %s. (%d)"),
                       proxy->target_host != NULL ? proxy->target_host : "",
                       proxy->acc[1]);
      proxy->state = PX_READY;
      if (ready != NULL)
        *ready = 1;
      break;
    default:
      break;
    }
  proxy->acc_len = 0;
  return TWIST_OK;
}

int
twist_proxy_is_ready (const struct twist_proxy *proxy)
{
  return proxy != NULL && proxy->state == PX_READY;
}

const struct twist_protocol_handler *
twist_proxy_handler (struct twist_proxy *p)
{
  if (p == NULL)
    return NULL;
  return &p->handler;
}
