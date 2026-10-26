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

#include <limits.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>

static char *
opt_strdup (const char *s)
{
  if (s == NULL)
    return NULL;
  return twist_strdup (s);
}

static void
replace (char **slot, const char *s)
{
  free (*slot);
  *slot = opt_strdup (s);
}

/* As replace, for a secret: the old one is wiped, not just freed.  */
static void
replace_secret (char **slot, const char *s)
{
  if (*slot != NULL)
    memset (*slot, 0, strlen (*slot));
  replace (slot, s);
}

twist_transfer *
twist_transfer_new (void)
{
  struct twist_transfer *transfer = calloc (1, sizeof *transfer);

  if (transfer == NULL)
    return NULL;
  transfer->maxredirs = 50;
  transfer->connect_timeout_ms = TWIST_DEFAULT_CONNECT_TIMEOUT_MS;
  transfer->verifypeer = 1;
  transfer->doh_verifypeer = 1;
  transfer->http_version = TWIST_HTTP_VERSION_NONE;
  transfer->auth = TWISTAUTH_BASIC;
  transfer->progress.hide = 1;
  transfer->infilesize = -1;
  transfer->proxy_verifypeer = 1;
  transfer->progress.lastshow = -1;
  transfer->telnet_input_fd = -1;
  transfer->pipewait = 1;
  return transfer;
}

struct twist_pool *
twist_transfer_pool (struct twist_transfer *transfer)
{
  if (transfer != NULL && transfer->runtime != NULL)
    return transfer->lane != NULL ? transfer->lane->pool
           : transfer->runtime->pool;
  return NULL;
}

/* Release the state of the transfer.  It owns the connection, which is
   released against the loop, so this must happen while the loop is alive:
   when the handle leaves its runtime, not when the handle is cleaned up.  */
void
twist_transfer_release (struct twist_transfer *transfer)
{
  void *state = transfer->state;
  void (*state_free) (void *) = transfer->state_free;

  /* Its timer is the loop's, which this handle is about to leave.  */
  twist_progress_release (transfer);

  transfer->state = NULL;
  transfer->state_free = NULL;
  if (state_free != NULL && state != NULL)
    state_free (state);
}

void
twist_transfer_chain (struct twist_transfer *transfer)
{
  const struct twist_scheme *scheme;
  void *state = transfer->state;
  void (*state_free) (void *) = transfer->state_free;
  int rc;

  /* The state, and not the progress: that goes on, with its counters for the
     next hop begun, as for a redirect within one handler.  */
  transfer->state = NULL;
  transfer->state_free = NULL;
  if (state_free != NULL && state != NULL)
    state_free (state);
  transfer->http_version_seen = 0;
  scheme = transfer->url != NULL ? twist_scheme_by_name (transfer->url->scheme)
                                 : NULL;
  if (scheme == NULL || (scheme->flags & TWIST_SCHEME_READY) == 0)
    {
      twist_transfer_finish (transfer, TWIST_ERR_UNSUPPORTED);
      return;
    }
  rc = scheme->attach (transfer);
  if (rc != TWIST_OK && !transfer->done)
    twist_transfer_finish (transfer, rc);
}

static void
transfer_clear (struct twist_transfer *transfer)
{
  twist_transfer_release (transfer);
  free (transfer->url_string);
  twist_url_free_int (transfer->url);
  free (transfer->method);
  free (transfer->useragent);
  free (transfer->username);
  if (transfer->password != NULL)
    {
      memset (transfer->password, 0, strlen (transfer->password));
      free (transfer->password);
    }
  if (transfer->bearer != NULL)
    {
      memset (transfer->bearer, 0, strlen (transfer->bearer));
      free (transfer->bearer);
    }
  free (transfer->proxy);
  free (transfer->unix_path);
  free (transfer->noproxy);
  free (transfer->capath);
  free (transfer->proxy_cainfo);
  free (transfer->proxy_template_udp);
  free (transfer->range);
  free (transfer->referer);
  free (transfer->cookie);
  if (transfer->proxy_userpwd != NULL)
    {
      memset (transfer->proxy_userpwd, 0, strlen (transfer->proxy_userpwd));
      free (transfer->proxy_userpwd);
    }
  free (transfer->mail_from);
  free (transfer->doh_url);
  free (transfer->doq_url);
  free (transfer->dot_url);
  free (transfer->accept_encoding);
  free (transfer->content_encoding);
  free (transfer->cainfo);
  free (transfer->ssh_knownhosts);
  free (transfer->ssh_agent_socket);
  free (transfer->ssh_hostpubsha256);
  if (transfer->keypasswd != NULL)
    {
      memset (transfer->keypasswd, 0, strlen (transfer->keypasswd));
      free (transfer->keypasswd);
    }
  free (transfer->sslcert);
  free (transfer->sslkey);
  free (transfer->effective_url);
  free (transfer->content_type);
  free (transfer->error);
  twist_origin_clear (transfer);
}

void
twist_transfer_set_error (struct twist_transfer *transfer, char *msg)
{
  if (transfer == NULL)
    {
      free (msg);
      return;
    }
  free (transfer->error);
  transfer->error = msg;
}

/* TLS was asked for, to be required, and could not be had.  The words say
   why; the code is the one for that.  */
int
twist_transfer_use_ssl_failed (struct twist_transfer *transfer,
                               const char *why)
{
  twist_transfer_set_error (transfer, twist_strdup (why));
  return TWIST_ERR_USE_SSL;
}

const char *
twist_transfer_error (const twist_transfer *transfer)
{
  if (transfer == NULL)
    return NULL;
  return transfer->error;
}

void
twist_transfer_free (twist_transfer *transfer)
{
  if (transfer == NULL)
    return;
  /* A handle in a runtime leaves it first, and is dropped without a
     call to its callback.  From a callback that is refused, and the handle is
     not freed: it is in use by the call that made the callback.  A handle that
     has been reported to its callback is in none, and is freed here.  */
  if (twist_runtime_detach (transfer) != TWIST_OK)
    return;
  transfer_clear (transfer);
  free (transfer);
}

int
twist_transfer_setopt (twist_transfer *transfer, int opt, ...)
{
  va_list ap;
  int rc = TWIST_OK;

  if (transfer == NULL)
    return TWIST_ERR_INVAL;
  va_start (ap, opt);
  switch (opt)
    {
    case TWISTOPT_URL:
      replace (&transfer->url_string, va_arg (ap, const char *));
      twist_url_free_int (transfer->url);
      transfer->url = NULL;
      break;
    case TWISTOPT_WRITEFUNCTION:
      transfer->write_cb = va_arg (ap, twist_write_callback);
      break;
    case TWISTOPT_WRITEDATA:
      transfer->write_data = va_arg (ap, void *);
      break;
    case TWISTOPT_READFUNCTION:
      transfer->read_cb = va_arg (ap, twist_read_callback);
      break;
    case TWISTOPT_READDATA:
      transfer->read_data = va_arg (ap, void *);
      break;
    case TWISTOPT_SEEKFUNCTION:
      transfer->seek_cb = va_arg (ap, twist_seek_callback);
      break;
    case TWISTOPT_SEEKDATA:
      transfer->seek_data = va_arg (ap, void *);
      break;
    case TWISTOPT_APPEND:
      transfer->append = va_arg (ap, long) != 0;
      break;
    case TWISTOPT_FORBID_REUSE:
      transfer->forbid_reuse = va_arg (ap, long) != 0;
      break;
    case TWISTOPT_FRESH_CONNECT:
      transfer->fresh_connect = va_arg (ap, long) != 0;
      break;
    case TWISTOPT_HTTPPROXYTUNNEL:
      transfer->proxy_tunnel = va_arg (ap, long) != 0;
      break;
    case TWISTOPT_HEADERFUNCTION:
      transfer->header_cb = va_arg (ap, twist_write_callback);
      break;
    case TWISTOPT_HEADERDATA:
      transfer->header_data = va_arg (ap, void *);
      break;
    case TWISTOPT_CUSTOMREQUEST:
      replace (&transfer->method, va_arg (ap, const char *));
      break;
    case TWISTOPT_HTTPHEADER:
      transfer->headers = va_arg (ap, struct twist_slist *);
      break;
    case TWISTOPT_POSTFIELDS:
      transfer->postfields = va_arg (ap, char *);
      break;
    case TWISTOPT_POSTFIELDSIZE:
      transfer->postfieldsize = va_arg (ap, long);
      transfer->postfieldsize_set = 1;
      break;
    case TWISTOPT_FOLLOWLOCATION:
      transfer->follow = va_arg (ap, long) != 0;
      break;
    case TWISTOPT_MAXREDIRS:
      transfer->maxredirs = va_arg (ap, long);
      break;
    case TWISTOPT_USERAGENT:
      replace (&transfer->useragent, va_arg (ap, const char *));
      break;
    case TWISTOPT_USERNAME:
      replace (&transfer->username, va_arg (ap, const char *));
      break;
    case TWISTOPT_PASSWORD:
      replace_secret (&transfer->password, va_arg (ap, const char *));
      break;
    case TWISTOPT_HTTPAUTH:
      transfer->auth = (unsigned) va_arg (ap, long);
      break;
    case TWISTOPT_SSL_VERIFYPEER:
      transfer->verifypeer = va_arg (ap, long) != 0;
      break;
    case TWISTOPT_CAINFO:
      replace (&transfer->cainfo, va_arg (ap, const char *));
      break;
    case TWISTOPT_UNIX_SOCKET:
    case TWISTOPT_ABSTRACT_UNIX_SOCKET:
      {
        const char *s = va_arg (ap, const char *);
        int abstract = opt == TWISTOPT_ABSTRACT_UNIX_SOCKET;
        struct sockaddr_un probe;

        if (s != NULL && s[0] == 0)
          s = NULL;
        /* The address has room for the path and its NUL, or for the NUL that
           starts an abstract name and the name.  */
        if (s != NULL && strlen (s) + (abstract ? 0 : 1) > sizeof probe.sun_path - (abstract ? 1 : 0))
          {
            rc = TWIST_ERR_INVAL;
            break;
          }
        replace (&transfer->unix_path, s);
        transfer->unix_abstract = s != NULL && abstract;
      }
      break;
    case TWISTOPT_USE_SSL:
      {
        long how = va_arg (ap, long);

        if (how < TWIST_USE_SSL_NONE || how > TWIST_USE_SSL_ALL)
          rc = TWIST_ERR_INVAL;
        else
          transfer->use_ssl = (int) how;
      }
      break;
    case TWISTOPT_TELNETOPTIONS:
      transfer->telnet_options = va_arg (ap, struct twist_slist *);
      break;
    case TWISTOPT_TELNET_INPUT_FD:
      {
        long fd = va_arg (ap, long);

        if (fd < -1 || fd > INT_MAX)
          rc = TWIST_ERR_INVAL;
        else
          transfer->telnet_input_fd = (int) fd;
      }
      break;
    case TWISTOPT_RESUME_FROM:
      transfer->resume_from = va_arg (ap, long long);
      break;
    case TWISTOPT_SSH_AGENT_SOCKET:
      replace (&transfer->ssh_agent_socket, va_arg (ap, const char *));
      break;
    case TWISTOPT_DIRLISTONLY:
      transfer->dirlistonly = va_arg (ap, long) != 0;
      break;
    case TWISTOPT_QUOTE:
      transfer->quote = va_arg (ap, struct twist_slist *);
      break;
    case TWISTOPT_POSTQUOTE:
      transfer->postquote = va_arg (ap, struct twist_slist *);
      break;
    case TWISTOPT_CREATE_MISSING_DIRS:
      transfer->create_missing_dirs = va_arg (ap, long) != 0;
      break;
    case TWISTOPT_SSH_KNOWNHOSTS:
    case TWISTOPT_SSH_HOST_PUBLIC_KEY_SHA256:
    case TWISTOPT_KEYPASSWD:
      {
        const char *s = va_arg (ap, const char *);
        char **slot = opt == TWISTOPT_SSH_KNOWNHOSTS
          ? &transfer->ssh_knownhosts
          : opt == TWISTOPT_KEYPASSWD ? &transfer->keypasswd
          : &transfer->ssh_hostpubsha256;

        if (s != NULL && s[0] == 0)
          s = NULL;
        replace (slot, s);
      }
      break;
    case TWISTOPT_SSLCERT:
      {
        const char *s = va_arg (ap, const char *);

        if (s != NULL && s[0] == 0)
          s = NULL;
        replace (&transfer->sslcert, s);
      }
      break;
    case TWISTOPT_SSLKEY:
      {
        const char *s = va_arg (ap, const char *);

        if (s != NULL && s[0] == 0)
          s = NULL;
        replace (&transfer->sslkey, s);
      }
      break;
    case TWISTOPT_TIMEOUT_MS:
      transfer->timeout_ms = va_arg (ap, long);
      break;
    case TWISTOPT_PROXY:
      replace (&transfer->proxy, va_arg (ap, const char *));
      break;
    case TWISTOPT_HTTP_VERSION:
      transfer->http_version = (int) va_arg (ap, long);
      break;
    case TWISTOPT_DNS_ORDER:
      {
        const char *s = va_arg (ap, const char *);
        int tmp[4];
        size_t n = 0;

        if (s == NULL || s[0] == 0)
          {
            transfer->dns_order_n = 0;
            break;
          }
        if (twist_dns_parse_order (s, tmp, 4, &n) != TWIST_OK)
          rc = TWIST_ERR_INVAL;
        else
          {
            memcpy (transfer->dns_order, tmp, n * sizeof tmp[0]);
            transfer->dns_order_n = (int) n;
          }
      }
      break;
    case TWISTOPT_XOAUTH2_BEARER:
      replace_secret (&transfer->bearer, va_arg (ap, const char *));
      break;
    case TWISTOPT_RANGE:
      replace (&transfer->range, va_arg (ap, const char *));
      break;
    case TWISTOPT_REFERER:
      replace (&transfer->referer, va_arg (ap, const char *));
      break;
    case TWISTOPT_NOBODY:
      transfer->nobody = va_arg (ap, long) != 0;
      break;
    case TWISTOPT_FAILONERROR:
      transfer->failonerror = va_arg (ap, long) != 0;
      break;
    case TWISTOPT_CONNECTTIMEOUT_MS:
      {
        long ms = va_arg (ap, long);

        transfer->connect_timeout_ms = ms > 0 ? ms : TWIST_DEFAULT_CONNECT_TIMEOUT_MS;
      }
      break;
    case TWISTOPT_USE_COOKIES:
      transfer->use_cookies = va_arg (ap, long) != 0;
      break;
    case TWISTOPT_USE_HSTS:
      transfer->use_hsts = va_arg (ap, long) != 0;
      break;
    case TWISTOPT_USE_ALTSVC:
      transfer->use_altsvc = va_arg (ap, long) != 0;
      break;
    case TWISTOPT_PIPEWAIT:
      transfer->pipewait = va_arg (ap, long) != 0;
      break;
    case TWISTOPT_PRIVATE:
      transfer->private_data = va_arg (ap, void *);
      break;
    case TWISTOPT_MAX_RECV_SPEED_LARGE:
      transfer->max_recv_speed = va_arg (ap, uint64_t);
      break;
    case TWISTOPT_MAX_SEND_SPEED_LARGE:
      transfer->max_send_speed = va_arg (ap, uint64_t);
      break;
    case TWISTOPT_COOKIE:
      replace (&transfer->cookie, va_arg (ap, const char *));
      break;
    case TWISTOPT_PROXYUSERPWD:
      {
        const char *s = va_arg (ap, const char *);

        replace (&transfer->proxy_userpwd, s != NULL && s[0] != 0 ? s : NULL);
      }
      break;
    case TWISTOPT_MAIL_FROM:
      replace (&transfer->mail_from, va_arg (ap, const char *));
      break;
    case TWISTOPT_MAIL_RCPT:
      transfer->mail_rcpt = va_arg (ap, struct twist_slist *);
      break;
    case TWISTOPT_DOH_URL:
      {
        const char *s = va_arg (ap, const char *);

        if (s != NULL && s[0] == 0)
          s = NULL;
        replace (&transfer->doh_url, s);
      }
      break;
    case TWISTOPT_DOQ_URL:
      {
        const char *s = va_arg (ap, const char *);

        if (s != NULL && s[0] == 0)
          s = NULL;
        replace (&transfer->doq_url, s);
      }
      break;
    case TWISTOPT_DOT_URL:
      {
        const char *s = va_arg (ap, const char *);

        if (s != NULL && s[0] == 0)
          s = NULL;
        replace (&transfer->dot_url, s);
      }
      break;
    case TWISTOPT_DOH_SSL_VERIFYPEER:
      transfer->doh_verifypeer = va_arg (ap, long) != 0;
      break;
    case TWISTOPT_NOPROXY:
      {
        const char *s = va_arg (ap, const char *);

        replace (&transfer->noproxy, s);
        transfer->noproxy_set = s != NULL;
      }
      break;
    case TWISTOPT_PROXY_CAINFO:
      {
        const char *s = va_arg (ap, const char *);

        replace (&transfer->proxy_cainfo, s != NULL && s[0] != 0 ? s : NULL);
      }
      break;
    case TWISTOPT_PROXY_TEMPLATE_UDP:
      {
        const char *s = va_arg (ap, const char *);
        char err[200];

        if (s != NULL && s[0] != 0
            && twist_template_check (s, err, sizeof err) != TWIST_OK)
          {
            twist_transfer_set_error (transfer, twist_strdup (err));
            rc = TWIST_ERR_INVAL;
          }
        else
          replace (&transfer->proxy_template_udp, s != NULL && s[0] != 0 ? s : NULL);
      }
      break;
    case TWISTOPT_PROXY_SSL_VERIFYPEER:
      transfer->proxy_verifypeer = va_arg (ap, long) != 0;
      break;
    case TWISTOPT_CAPATH:
      {
        const char *s = va_arg (ap, const char *);

        replace (&transfer->capath, s != NULL && s[0] != 0 ? s : NULL);
      }
      break;
    case TWISTOPT_INFILESIZE:
      transfer->infilesize = va_arg (ap, long long);
      break;
    case TWISTOPT_NOPROGRESS:
      transfer->progress.hide = va_arg (ap, long) != 0;
      break;
    case TWISTOPT_XFERINFOFUNCTION:
      transfer->progress.xferinfo = va_arg (ap, twist_xferinfo_callback);
      break;
    case TWISTOPT_XFERINFODATA:
      transfer->progress.xferinfo_data = va_arg (ap, void *);
      break;
    case TWISTOPT_STDERR:
      transfer->progress.err = va_arg (ap, FILE *);
      break;
    case TWISTOPT_ACCEPT_ENCODING:
      replace (&transfer->accept_encoding, va_arg (ap, const char *));
      break;
    case TWISTOPT_CONTENT_ENCODING:
      {
        const char *s = va_arg (ap, const char *);

        if (s != NULL && s[0] == 0)
          s = NULL;
        if (s != NULL && !twist_coding_known (s))
          rc = TWIST_ERR_UNSUPPORTED;
        else
          replace (&transfer->content_encoding, s);
      }
      break;
    default:
      rc = TWIST_ERR_UNSUPPORTED;
      break;
    }
  va_end (ap);
  return rc;
}

int
twist_transfer_getinfo (twist_transfer *transfer, int info, ...)
{
  va_list ap;

  if (transfer == NULL)
    return TWIST_ERR_INVAL;
  va_start (ap, info);
  switch (info)
    {
    case TWISTINFO_RESPONSE_CODE:
      *va_arg (ap, long *) = transfer->http_code;
      break;
    case TWISTINFO_EFFECTIVE_URL:
      *va_arg (ap, char **) = transfer->effective_url;
      break;
    case TWISTINFO_SIZE_DOWNLOAD:
      *va_arg (ap, size_t *) = transfer->size_download;
      break;
    case TWISTINFO_CONTENT_TYPE:
      *va_arg (ap, char **) = transfer->content_type;
      break;
    case TWISTINFO_PRIVATE:
      *va_arg (ap, void **) = transfer->private_data;
      break;
    case TWISTINFO_HTTP_VERSION:
      *va_arg (ap, long *) = transfer->http_version_seen;
      break;
    default:
      va_end (ap);
      return TWIST_ERR_UNSUPPORTED;
    }
  va_end (ap);
  return TWIST_OK;
}

int
twist_transfer_finish (struct twist_transfer *transfer, int result)
{
  if (transfer == NULL || transfer->done)
    return TWIST_OK;
  transfer->done = 1;
  transfer->result = result;
  twist_progress_end (transfer, result);
  /* The handler that is ending the transfer is still on the stack.  The
     program hears of it from the loop, when that has returned.  */
  return twist_runtime_finished (transfer);
}

int
twist_transfer_start (struct twist_transfer *transfer)
{
  const struct twist_scheme *scheme;
  int rc;

  twist_transfer_set_error (transfer, NULL);
  transfer->creds_stripped = 0;
  transfer->hop_timeout_ms = 0;
  if (transfer->url_string == NULL && transfer->url == NULL)
    {
      twist_transfer_finish (transfer, TWIST_ERR_URL);
      return TWIST_ERR_URL;
    }
  if (transfer->url == NULL)
    {
      rc = twist_url_parse_int (transfer->url_string, &transfer->url);
      if (rc != TWIST_OK)
        {
          twist_transfer_finish (transfer, rc);
          return rc;
        }
    }
  free (transfer->effective_url);
  transfer->effective_url = twist_url_effective (transfer->url);
  scheme = twist_scheme_by_name (transfer->url->scheme);
  if (scheme == NULL || (scheme->flags & TWIST_SCHEME_READY) == 0)
    {
      twist_transfer_finish (transfer, TWIST_ERR_UNSUPPORTED);
      return TWIST_ERR_UNSUPPORTED;
    }
  /* A Unix socket is the HTTP handler's, and another scheme would otherwise
     go to the host and port as if it had not been asked for.  */
  if (transfer->unix_path != NULL
      && strcmp (transfer->url->scheme, "http") != 0
      && strcmp (transfer->url->scheme, "https") != 0
      && strcmp (transfer->url->scheme, "ws") != 0
      && strcmp (transfer->url->scheme, "wss") != 0)
    {
      twist_transfer_set_error (transfer,
                                twist_strdup (_("a Unix socket is for http, "
                                                "https, ws and wss URLs "
                                                "only")));
      twist_transfer_finish (transfer, TWIST_ERR_UNSUPPORTED);
      return TWIST_ERR_UNSUPPORTED;
    }
  transfer->done = 0;
  twist_progress_begin (transfer);
  rc = scheme->attach (transfer);
  if (rc != TWIST_OK && !transfer->done)
    twist_transfer_finish (transfer, rc);
  return rc;
}
