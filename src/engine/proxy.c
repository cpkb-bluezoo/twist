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
  PX_SOCKS4_WAIT,
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
  struct twist_transfer *transfer;
  uint8_t *acc;
  size_t acc_len, acc_cap;
  char error[200];
  int status;
  int err_code;			/* What the transfer's handler is told.  */
  /* The target is to be looked up here before the request can be made; the
     lookup under way, which cannot be cancelled, so it is told if the proxy
     goes first.  */
  int want_resolve;
  struct px_resolve *resolving;
  struct twist_protocol_handler handler;
};

struct px_resolve
{
  struct twist_proxy *p;
};

static int
kind_is5 (int kind)
{
  return kind == TWIST_PROXY_SOCKS5 || kind == TWIST_PROXY_SOCKS5H;
}

static int
kind_is4 (int kind)
{
  return kind == TWIST_PROXY_SOCKS4 || kind == TWIST_PROXY_SOCKS4A;
}

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
  p->err_code = TWIST_ERR_PROXY;
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

static void proxy_refused (struct twist_proxy *p, struct twist_endpoint *ep);
static void proxy_resolve_start (struct twist_proxy *p);

/* What the proxy sends next, if anything; or the lookup of the target that it
   waits for is begun.  */
static void
proxy_step (struct twist_proxy *p, struct twist_endpoint *ep)
{
  uint8_t *out = NULL;
  size_t len = 0;
  int rc = twist_proxy_opening (p, &out, &len);

  if (rc == TWIST_OK && out != NULL)
    {
      twist_endpoint_send (ep, out, len);
      free (out);
    }
  else if (rc != TWIST_OK && rc != TWIST_ERR_AGAIN && p->state == PX_FAILED)
    proxy_refused (p, ep);
  else if (p->want_resolve && p->resolving == NULL)
    proxy_resolve_start (p);
}

static void
proxy_connected (struct twist_endpoint *ep)
{
  struct twist_proxy *p = ep->user_data;

  p->ep = ep;
  proxy_step (p, ep);
}

/* The proxy refused: the transfer gets the words, and an error.  */
static void
proxy_refused (struct twist_proxy *p, struct twist_endpoint *ep)
{
  if (p->transfer != NULL && twist_transfer_error (p->transfer) == NULL)
    {
      twist_transfer_set_error (p->transfer, twist_strdup (p->error));
      p->transfer->proto_status = p->status;
    }
  if (p->inner != NULL && p->inner->error != NULL)
    {
      swap_user (p, 1);
      p->inner->error (ep, p->err_code != 0 ? p->err_code : TWIST_ERR_PROXY);
      swap_user (p, 0);
    }
}

/* The lookup of the target is over.  The proxy may have gone meanwhile.  */
static void
proxy_resolved (void *user, int err, const struct twist_dns_addr *addr)
{
  struct px_resolve *r = user;
  struct twist_proxy *p = r->p;

  free (r);
  if (p == NULL)
    return;
  p->resolving = NULL;
  p->want_resolve = 0;
  if (p->state == PX_FAILED || p->ep == NULL)
    return;
  if (err != TWIST_OK || addr == NULL)
    {
      snprintf (p->error, sizeof p->error, _("Could not resolve host: %s"),
                p->target_host != NULL ? p->target_host : "");
      p->status = 0;
      p->err_code = TWIST_ERR_RESOLVE;
      p->state = PX_FAILED;
      proxy_refused (p, p->ep);
      return;
    }
  if (kind_is4 (p->kind) && addr->family != 4)
    {
      failed (p, 97, _("SOCKS4 cannot reach an IPv6 address (%s)"),
              p->target_host != NULL ? p->target_host : "");
      proxy_refused (p, p->ep);
      return;
    }
  free (p->target_host);
  p->target_host = twist_strdup (addr->text);
  proxy_step (p, p->ep);
}

static void
proxy_resolve_start (struct twist_proxy *p)
{
  struct px_resolve *r;

  if (p->transfer == NULL || p->target_host == NULL)
    {
      failed (p, 97, _("the target cannot be looked up"));
      if (p->ep != NULL)
        proxy_refused (p, p->ep);
      return;
    }
  r = calloc (1, sizeof *r);
  if (r == NULL)
    {
      failed (p, 97, _("%s"), twist_strerror (TWIST_ERR_NOMEM));
      if (p->ep != NULL)
        proxy_refused (p, p->ep);
      return;
    }
  r->p = p;
  p->resolving = r;
  if (twist_dns_resolve_transfer (p->transfer, p->target_host, proxy_resolved,
                                  r) != TWIST_OK)
    {
      p->resolving = NULL;
      free (r);
      snprintf (p->error, sizeof p->error, _("Could not resolve host: %s"),
                p->target_host);
      p->status = 0;
      p->err_code = TWIST_ERR_RESOLVE;
      p->state = PX_FAILED;
      if (p->ep != NULL)
        proxy_refused (p, p->ep);
    }
}

static size_t
proxy_receive (struct twist_endpoint *ep, const uint8_t *data, size_t len)
{
  struct twist_proxy *p = ep->user_data;
  size_t used = 0;
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
  proxy_step (p, ep);
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
      else if (sl == 5 && strncasecmp (s, "https", 5) == 0)
        {
          /* TLS to the proxy, then CONNECT inside it: a tunnel (tunnel.c).  */
          k = TWIST_PROXY_HTTPS;
          def = 443;
        }
      else if (sl == 6 && strncasecmp (s, "socks5", 6) == 0)
        {
          k = TWIST_PROXY_SOCKS5;
          def = 1080;
        }
      else if (sl == 7 && strncasecmp (s, "socks5h", 7) == 0)
        {
          k = TWIST_PROXY_SOCKS5H;
          def = 1080;
        }
      else if (sl == 6 && strncasecmp (s, "socks4", 6) == 0)
        {
          k = TWIST_PROXY_SOCKS4;
          def = 1080;
        }
      else if (sl == 7 && strncasecmp (s, "socks4a", 7) == 0)
        {
          k = TWIST_PROXY_SOCKS4A;
          def = 1080;
        }
      else
        /* Anything else: not spoken here, and not to be taken for something
           that is.  */
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
  struct twist_proxy *p;

  /* An https proxy is a tunnel (tunnel.c), not this.  */
  if (kind == TWIST_PROXY_HTTPS)
    return NULL;
  p = calloc (1, sizeof *p);
  if (p == NULL)
    return NULL;
  p->kind = kind;
  p->err_code = TWIST_ERR_PROXY;
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
  if (proxy->resolving != NULL)
    proxy->resolving->p = NULL;
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
twist_proxy_set_transfer (struct twist_proxy *proxy,
                          struct twist_transfer *transfer)
{
  if (proxy != NULL)
    proxy->transfer = transfer;
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
twist_proxy_configure (struct twist_proxy *proxy,
                       struct twist_transfer *transfer,
                       const char *user, const char *pass)
{
  if (proxy == NULL)
    return;
  proxy->transfer = transfer;
  if (user != NULL)
    twist_proxy_set_credentials (proxy, user, pass);
  else if (transfer != NULL && transfer->proxy_userpwd != NULL)
    {
      /* As given: -U is not percent-encoded.  */
      const char *c = strchr (transfer->proxy_userpwd, ':');

      if (c == NULL)
        twist_proxy_set_credentials (proxy, transfer->proxy_userpwd, "");
      else
        {
          char *u = twist_xmalloc ((size_t) (c - transfer->proxy_userpwd) + 1);

          if (u == NULL)
            return;
          memcpy (u, transfer->proxy_userpwd,
                  (size_t) (c - transfer->proxy_userpwd));
          u[c - transfer->proxy_userpwd] = 0;
          twist_proxy_set_credentials (proxy, u, c + 1);
          free (u);
        }
    }
}

char *
twist_proxy_auth_header (const struct twist_proxy *proxy)
{
  static const char lead[] = "Proxy-Authorization: Basic ";
  size_t ul, pl;
  char *cred, *enc = NULL, *line;

  if (proxy == NULL || proxy->user == NULL)
    return NULL;
  ul = strlen (proxy->user);
  pl = proxy->pass != NULL ? strlen (proxy->pass) : 0;
  cred = twist_xmalloc (ul + pl + 2);
  if (cred == NULL)
    return NULL;
  memcpy (cred, proxy->user, ul);
  cred[ul] = ':';
  if (pl > 0)
    memcpy (cred + ul + 1, proxy->pass, pl);
  if (twist_b64_encode ((const uint8_t *) cred, ul + 1 + pl, &enc)
      != TWIST_OK)
    enc = NULL;
  memset (cred, 0, ul + pl + 2);
  free (cred);
  if (enc == NULL)
    return NULL;
  line = twist_xmalloc (sizeof lead + strlen (enc));
  if (line != NULL)
    {
      memcpy (line, lead, sizeof lead - 1);
      strcpy (line + sizeof lead - 1, enc);
    }
  memset (enc, 0, strlen (enc));
  free (enc);
  return line;
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
      char addr[256];
      char *enc = NULL;
      char *line;
      const char *brk_l = "", *brk_r = "";
      size_t cap;
      int n;
      int m;

      target_address (proxy, addr, sizeof addr);
      if (strchr (addr, ':') != NULL)
        {
          brk_l = "[";
          brk_r = "]";
        }
      /* Built to the length of what is in it.  A credential is as long as the
         user made it, and one cut off in a buffer took with it the end of the
         line and of the request, and the proxy then read what followed as
         more headers.  */
      if (proxy->user != NULL)
        {
          size_t ul = strlen (proxy->user);
          size_t pl = proxy->pass != NULL ? strlen (proxy->pass) : 0;
          char *cred = twist_xmalloc (ul + pl + 2);
          int rc;

          if (cred == NULL)
            return TWIST_ERR_NOMEM;
          memcpy (cred, proxy->user, ul);
          cred[ul] = ':';
          if (pl > 0)
            memcpy (cred + ul + 1, proxy->pass, pl);
          rc = twist_b64_encode ((const uint8_t *) cred, ul + 1 + pl, &enc);
          memset (cred, 0, ul + pl + 2);
          free (cred);
          if (rc != TWIST_OK)
            return rc;
        }
      cap = 2 * (strlen (addr) + 2 + 8) + 128
            + (enc != NULL ? strlen (enc) + 32 : 0);
      line = twist_xmalloc (cap);
      if (line == NULL)
        {
          free (enc);
          return TWIST_ERR_NOMEM;
        }
      n = snprintf (line, cap,
                    "CONNECT %s%s%s:%d HTTP/1.1\r\nHost: %s%s%s:%d\r\n",
                    brk_l, addr, brk_r, proxy->target_port,
                    brk_l, addr, brk_r, proxy->target_port);
      m = n < 0 ? -1 : snprintf (line + n, cap - (size_t) n,
                                 "%s%s%s\r\n",
                                 enc != NULL ? "Proxy-Authorization: Basic " : "",
                                 enc != NULL ? enc : "",
                                 enc != NULL ? "\r\n" : "");
      if (enc != NULL)
        {
          memset (enc, 0, strlen (enc));
          free (enc);
        }
      if (n < 0 || m < 0 || (size_t) n + (size_t) m >= cap)
        {
          free (line);
          return TWIST_ERR_CONNECT;
        }
      *out = (uint8_t *) line;
      *len = (size_t) n + (size_t) m;
      proxy->state = PX_HTTP;
      return TWIST_OK;
    }
  if (kind_is5 (proxy->kind) && proxy->state == PX_START)
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
  if (kind_is5 (proxy->kind) && proxy->state == PX_SOCKS_AUTH)
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
  if (kind_is4 (proxy->kind) && proxy->state == PX_START)
    {
      char host[256];
      struct in_addr a4;
      const char *user = proxy->user != NULL ? proxy->user : "";
      size_t ul = strlen (user), hl;
      uint8_t *buf;
      int is_ip;

      target_address (proxy, host, sizeof host);
      hl = strlen (host);
      is_ip = inet_pton (AF_INET, host, &a4) == 1;
      if (!is_ip && strchr (host, ':') != NULL)
        return failed (proxy, 97, _("SOCKS4 cannot reach an IPv6 address (%s)"),
                       host);
      if (!is_ip && proxy->kind == TWIST_PROXY_SOCKS4)
        {
          /* Looked up here, and the proxy is given the address.  */
          proxy->want_resolve = 1;
          return TWIST_ERR_AGAIN;
        }
      if (hl > 255 || ul > 255)
        return failed (proxy, 97, _("the name is too long for SOCKS4"));
      buf = twist_xmalloc (9 + ul + (is_ip ? 0 : hl + 1));
      if (buf == NULL)
        return TWIST_ERR_NOMEM;
      buf[0] = 4;
      buf[1] = 1;
      buf[2] = (uint8_t) (proxy->target_port >> 8);
      buf[3] = (uint8_t) proxy->target_port;
      if (is_ip)
        memcpy (buf + 4, &a4, 4);
      else
        {
          /* SOCKS4a: 0.0.0.x with x not 0, and the name after the user.  */
          buf[4] = buf[5] = buf[6] = 0;
          buf[7] = 1;
        }
      memcpy (buf + 8, user, ul + 1);
      *len = 9 + ul;
      if (!is_ip)
        {
          memcpy (buf + 9 + ul, host, hl + 1);
          *len += hl + 1;
        }
      *out = buf;
      proxy->state = PX_SOCKS4_WAIT;
      return TWIST_OK;
    }
  if (kind_is5 (proxy->kind) && proxy->state == PX_SOCKS_ASK)
    {
      char host[256];
      struct in_addr a4;
      struct in6_addr a6;
      uint8_t *buf;
      size_t n, hl;

      target_address (proxy, host, sizeof host);
      hl = strlen (host);
      if (proxy->kind == TWIST_PROXY_SOCKS5 && inet_pton (AF_INET, host, &a4) != 1
          && inet_pton (AF_INET6, host, &a6) != 1)
        {
          proxy->want_resolve = 1;
          return TWIST_ERR_AGAIN;
        }
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
  /* Three digits and then a space or the end of the line.  */
  if (sp + 4 < p + len && sp[4] != ' ' && sp[4] != '\r' && sp[4] != '\n')
    return -1;
  return twist_status_code (sp + 1);
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
          && proxy->state != PX_SOCKS_CONNECT
          && proxy->state != PX_SOCKS4_WAIT)
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
        case PX_SOCKS4_WAIT:
          done = proxy->acc_len >= 8;
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
    case PX_SOCKS4_WAIT:
      if (proxy->acc[0] != 0)
        return failed (proxy, 97, _("the SOCKS4 reply is not one"));
      if (proxy->acc[1] != 90)
        return failed (proxy, 97,
                       _("Can't complete SOCKS4 connection to %s. (%d)"),
                       proxy->target_host != NULL ? proxy->target_host : "",
                       proxy->acc[1]);
      proxy->state = PX_READY;
      if (ready != NULL)
        *ready = 1;
      break;
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
