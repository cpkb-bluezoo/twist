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

twist_easy *
twist_easy_init (void)
{
  struct twist_easy *easy = calloc (1, sizeof *easy);

  if (easy == NULL)
    return NULL;
  easy->maxredirs = 50;
  easy->connect_timeout_ms = TWIST_DEFAULT_CONNECT_TIMEOUT_MS;
  easy->verifypeer = 1;
  easy->doh_verifypeer = 1;
  easy->http_version = TWIST_HTTP_VERSION_NONE;
  easy->auth = TWISTAUTH_BASIC;
  easy->progress.hide = 1;
  easy->infilesize = -1;
  easy->proxy_verifypeer = 1;
  easy->progress.lastshow = -1;
  return easy;
}

struct twist_pool *
twist_easy_pool (struct twist_easy *easy)
{
  if (easy != NULL && easy->share != NULL && easy->share->pool != NULL)
    return easy->share->pool;
  if (easy != NULL && easy->multi != NULL)
    return easy->multi->pool;
  return NULL;
}

/* Release the state of the transfer.  It owns the connection, which is
   released against the loop, so this must happen while the loop is alive:
   when the handle leaves its multi, not when the handle is cleaned up.  */
void
twist_easy_release_transfer (struct twist_easy *easy)
{
  void *xfer = easy->xfer;
  void (*xfer_free) (void *) = easy->xfer_free;

  /* Its timer is the loop's, which this handle is about to leave.  */
  twist_progress_release (easy);

  easy->xfer = NULL;
  easy->xfer_free = NULL;
  if (xfer_free != NULL && xfer != NULL)
    xfer_free (xfer);
}

static void
easy_clear (struct twist_easy *easy)
{
  twist_easy_release_transfer (easy);
  free (easy->url_string);
  twist_url_free_int (easy->url);
  free (easy->method);
  free (easy->useragent);
  free (easy->username);
  if (easy->password != NULL)
    {
      memset (easy->password, 0, strlen (easy->password));
      free (easy->password);
    }
  if (easy->bearer != NULL)
    {
      memset (easy->bearer, 0, strlen (easy->bearer));
      free (easy->bearer);
    }
  free (easy->proxy);
  free (easy->unix_path);
  free (easy->noproxy);
  free (easy->capath);
  free (easy->proxy_cainfo);
  free (easy->proxy_template_udp);
  free (easy->range);
  free (easy->referer);
  free (easy->cookie);
  if (easy->proxy_userpwd != NULL)
    {
      memset (easy->proxy_userpwd, 0, strlen (easy->proxy_userpwd));
      free (easy->proxy_userpwd);
    }
  free (easy->mail_from);
  free (easy->doh_url);
  free (easy->doq_url);
  free (easy->dot_url);
  free (easy->accept_encoding);
  free (easy->content_encoding);
  free (easy->cainfo);
  free (easy->ssh_knownhosts);
  free (easy->ssh_agent_socket);
  free (easy->ssh_hostpubsha256);
  if (easy->keypasswd != NULL)
    {
      memset (easy->keypasswd, 0, strlen (easy->keypasswd));
      free (easy->keypasswd);
    }
  free (easy->sslcert);
  free (easy->sslkey);
  free (easy->effective_url);
  free (easy->content_type);
  free (easy->error);
  twist_origin_clear (easy);
}

void
twist_easy_set_error (struct twist_easy *easy, char *msg)
{
  if (easy == NULL)
    {
      free (msg);
      return;
    }
  free (easy->error);
  easy->error = msg;
}

/* TLS was asked for, to be required, and could not be had.  The words say
   why; the code is the one for that.  */
int
twist_easy_use_ssl_failed (struct twist_easy *easy, const char *why)
{
  twist_easy_set_error (easy, twist_strdup (why));
  return TWIST_ERR_USE_SSL;
}

const char *
twist_easy_error (const twist_easy *easy)
{
  if (easy == NULL)
    return NULL;
  return easy->error;
}

void
twist_easy_cleanup (twist_easy *easy)
{
  if (easy == NULL)
    return;
  /* A handle in a multi leaves it first, as curl's does.  From a callback
     that is refused, and the handle is not freed: it is in use by the call
     that made the callback.  */
  if (easy->multi != NULL
      && twist_multi_remove_handle (easy->multi, easy) != TWIST_OK)
    return;
  easy_clear (easy);
  free (easy);
}

int
twist_easy_setopt (twist_easy *easy, int opt, ...)
{
  va_list ap;
  int rc = TWIST_OK;

  if (easy == NULL)
    return TWIST_ERR_INVAL;
  va_start (ap, opt);
  switch (opt)
    {
    case TWISTOPT_URL:
      replace (&easy->url_string, va_arg (ap, const char *));
      twist_url_free_int (easy->url);
      easy->url = NULL;
      break;
    case TWISTOPT_WRITEFUNCTION:
      easy->write_cb = va_arg (ap, twist_write_callback);
      break;
    case TWISTOPT_WRITEDATA:
      easy->write_data = va_arg (ap, void *);
      break;
    case TWISTOPT_READFUNCTION:
      easy->read_cb = va_arg (ap, twist_read_callback);
      break;
    case TWISTOPT_READDATA:
      easy->read_data = va_arg (ap, void *);
      break;
    case TWISTOPT_HEADERFUNCTION:
      easy->header_cb = va_arg (ap, twist_write_callback);
      break;
    case TWISTOPT_HEADERDATA:
      easy->header_data = va_arg (ap, void *);
      break;
    case TWISTOPT_CUSTOMREQUEST:
      replace (&easy->method, va_arg (ap, const char *));
      break;
    case TWISTOPT_HTTPHEADER:
      easy->headers = va_arg (ap, struct twist_slist *);
      break;
    case TWISTOPT_POSTFIELDS:
      easy->postfields = va_arg (ap, char *);
      break;
    case TWISTOPT_POSTFIELDSIZE:
      easy->postfieldsize = va_arg (ap, long);
      easy->postfieldsize_set = 1;
      break;
    case TWISTOPT_FOLLOWLOCATION:
      easy->follow = va_arg (ap, long) != 0;
      break;
    case TWISTOPT_MAXREDIRS:
      easy->maxredirs = va_arg (ap, long);
      break;
    case TWISTOPT_USERAGENT:
      replace (&easy->useragent, va_arg (ap, const char *));
      break;
    case TWISTOPT_USERNAME:
      replace (&easy->username, va_arg (ap, const char *));
      break;
    case TWISTOPT_PASSWORD:
      replace_secret (&easy->password, va_arg (ap, const char *));
      break;
    case TWISTOPT_HTTPAUTH:
      easy->auth = (unsigned) va_arg (ap, long);
      break;
    case TWISTOPT_SSL_VERIFYPEER:
      easy->verifypeer = va_arg (ap, long) != 0;
      break;
    case TWISTOPT_CAINFO:
      replace (&easy->cainfo, va_arg (ap, const char *));
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
        replace (&easy->unix_path, s);
        easy->unix_abstract = s != NULL && abstract;
      }
      break;
    case TWISTOPT_USE_SSL:
      {
        long how = va_arg (ap, long);

        if (how < TWIST_USE_SSL_NONE || how > TWIST_USE_SSL_ALL)
          rc = TWIST_ERR_INVAL;
        else
          easy->use_ssl = (int) how;
      }
      break;
    case TWISTOPT_TELNETOPTIONS:
      easy->telnet_options = va_arg (ap, struct twist_slist *);
      break;
    case TWISTOPT_RESUME_FROM:
      easy->resume_from = va_arg (ap, long long);
      break;
    case TWISTOPT_SSH_AGENT_SOCKET:
      replace (&easy->ssh_agent_socket, va_arg (ap, const char *));
      break;
    case TWISTOPT_DIRLISTONLY:
      easy->dirlistonly = va_arg (ap, long) != 0;
      break;
    case TWISTOPT_QUOTE:
      easy->quote = va_arg (ap, struct twist_slist *);
      break;
    case TWISTOPT_POSTQUOTE:
      easy->postquote = va_arg (ap, struct twist_slist *);
      break;
    case TWISTOPT_CREATE_MISSING_DIRS:
      easy->create_missing_dirs = va_arg (ap, long) != 0;
      break;
    case TWISTOPT_SSH_KNOWNHOSTS:
    case TWISTOPT_SSH_HOST_PUBLIC_KEY_SHA256:
    case TWISTOPT_KEYPASSWD:
      {
        const char *s = va_arg (ap, const char *);
        char **slot = opt == TWISTOPT_SSH_KNOWNHOSTS ? &easy->ssh_knownhosts
          : opt == TWISTOPT_KEYPASSWD ? &easy->keypasswd
          : &easy->ssh_hostpubsha256;

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
        replace (&easy->sslcert, s);
      }
      break;
    case TWISTOPT_SSLKEY:
      {
        const char *s = va_arg (ap, const char *);

        if (s != NULL && s[0] == 0)
          s = NULL;
        replace (&easy->sslkey, s);
      }
      break;
    case TWISTOPT_TIMEOUT_MS:
      easy->timeout_ms = va_arg (ap, long);
      break;
    case TWISTOPT_PROXY:
      replace (&easy->proxy, va_arg (ap, const char *));
      break;
    case TWISTOPT_HTTP_VERSION:
      easy->http_version = (int) va_arg (ap, long);
      break;
    case TWISTOPT_DNS_ORDER:
      {
        const char *s = va_arg (ap, const char *);
        int tmp[4];
        size_t n = 0;

        if (s == NULL || s[0] == 0)
          {
            easy->dns_order_n = 0;
            break;
          }
        if (twist_dns_parse_order (s, tmp, 4, &n) != TWIST_OK)
          rc = TWIST_ERR_INVAL;
        else
          {
            memcpy (easy->dns_order, tmp, n * sizeof tmp[0]);
            easy->dns_order_n = (int) n;
          }
      }
      break;
    case TWISTOPT_XOAUTH2_BEARER:
      replace_secret (&easy->bearer, va_arg (ap, const char *));
      break;
    case TWISTOPT_RANGE:
      replace (&easy->range, va_arg (ap, const char *));
      break;
    case TWISTOPT_REFERER:
      replace (&easy->referer, va_arg (ap, const char *));
      break;
    case TWISTOPT_NOBODY:
      easy->nobody = va_arg (ap, long) != 0;
      break;
    case TWISTOPT_FAILONERROR:
      easy->failonerror = va_arg (ap, long) != 0;
      break;
    case TWISTOPT_CONNECTTIMEOUT_MS:
      {
        long ms = va_arg (ap, long);

        easy->connect_timeout_ms = ms > 0 ? ms : TWIST_DEFAULT_CONNECT_TIMEOUT_MS;
      }
      break;
    case TWISTOPT_SHARE:
      easy->share = va_arg (ap, struct twist_share *);
      break;
    case TWISTOPT_PRIVATE:
      easy->private_data = va_arg (ap, void *);
      break;
    case TWISTOPT_MAX_RECV_SPEED_LARGE:
      easy->max_recv_speed = va_arg (ap, uint64_t);
      break;
    case TWISTOPT_MAX_SEND_SPEED_LARGE:
      easy->max_send_speed = va_arg (ap, uint64_t);
      break;
    case TWISTOPT_COOKIE:
      replace (&easy->cookie, va_arg (ap, const char *));
      break;
    case TWISTOPT_PROXYUSERPWD:
      {
        const char *s = va_arg (ap, const char *);

        replace (&easy->proxy_userpwd, s != NULL && s[0] != 0 ? s : NULL);
      }
      break;
    case TWISTOPT_MAIL_FROM:
      replace (&easy->mail_from, va_arg (ap, const char *));
      break;
    case TWISTOPT_MAIL_RCPT:
      easy->mail_rcpt = va_arg (ap, struct twist_slist *);
      break;
    case TWISTOPT_DOH_URL:
      {
        const char *s = va_arg (ap, const char *);

        if (s != NULL && s[0] == 0)
          s = NULL;
        replace (&easy->doh_url, s);
      }
      break;
    case TWISTOPT_DOQ_URL:
      {
        const char *s = va_arg (ap, const char *);

        if (s != NULL && s[0] == 0)
          s = NULL;
        replace (&easy->doq_url, s);
      }
      break;
    case TWISTOPT_DOT_URL:
      {
        const char *s = va_arg (ap, const char *);

        if (s != NULL && s[0] == 0)
          s = NULL;
        replace (&easy->dot_url, s);
      }
      break;
    case TWISTOPT_DOH_SSL_VERIFYPEER:
      easy->doh_verifypeer = va_arg (ap, long) != 0;
      break;
    case TWISTOPT_NOPROXY:
      {
        const char *s = va_arg (ap, const char *);

        replace (&easy->noproxy, s);
        easy->noproxy_set = s != NULL;
      }
      break;
    case TWISTOPT_PROXY_CAINFO:
      {
        const char *s = va_arg (ap, const char *);

        replace (&easy->proxy_cainfo, s != NULL && s[0] != 0 ? s : NULL);
      }
      break;
    case TWISTOPT_PROXY_TEMPLATE_UDP:
      {
        const char *s = va_arg (ap, const char *);
        char err[200];

        if (s != NULL && s[0] != 0
            && twist_template_check (s, err, sizeof err) != TWIST_OK)
          {
            twist_easy_set_error (easy, twist_strdup (err));
            rc = TWIST_ERR_INVAL;
          }
        else
          replace (&easy->proxy_template_udp, s != NULL && s[0] != 0 ? s : NULL);
      }
      break;
    case TWISTOPT_PROXY_SSL_VERIFYPEER:
      easy->proxy_verifypeer = va_arg (ap, long) != 0;
      break;
    case TWISTOPT_CAPATH:
      {
        const char *s = va_arg (ap, const char *);

        replace (&easy->capath, s != NULL && s[0] != 0 ? s : NULL);
      }
      break;
    case TWISTOPT_INFILESIZE:
      easy->infilesize = va_arg (ap, long long);
      break;
    case TWISTOPT_NOPROGRESS:
      easy->progress.hide = va_arg (ap, long) != 0;
      break;
    case TWISTOPT_XFERINFOFUNCTION:
      easy->progress.xferinfo = va_arg (ap, twist_xferinfo_callback);
      break;
    case TWISTOPT_XFERINFODATA:
      easy->progress.xferinfo_data = va_arg (ap, void *);
      break;
    case TWISTOPT_STDERR:
      easy->progress.err = va_arg (ap, FILE *);
      break;
    case TWISTOPT_ACCEPT_ENCODING:
      replace (&easy->accept_encoding, va_arg (ap, const char *));
      break;
    case TWISTOPT_CONTENT_ENCODING:
      {
        const char *s = va_arg (ap, const char *);

        if (s != NULL && s[0] == 0)
          s = NULL;
        if (s != NULL && !twist_coding_known (s))
          rc = TWIST_ERR_UNSUPPORTED;
        else
          replace (&easy->content_encoding, s);
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
twist_easy_getinfo (twist_easy *easy, int info, ...)
{
  va_list ap;

  if (easy == NULL)
    return TWIST_ERR_INVAL;
  va_start (ap, info);
  switch (info)
    {
    case TWISTINFO_RESPONSE_CODE:
      *va_arg (ap, long *) = easy->http_code;
      break;
    case TWISTINFO_EFFECTIVE_URL:
      *va_arg (ap, char **) = easy->effective_url;
      break;
    case TWISTINFO_SIZE_DOWNLOAD:
      *va_arg (ap, size_t *) = easy->size_download;
      break;
    case TWISTINFO_CONTENT_TYPE:
      *va_arg (ap, char **) = easy->content_type;
      break;
    case TWISTINFO_PRIVATE:
      *va_arg (ap, void **) = easy->private_data;
      break;
    default:
      va_end (ap);
      return TWIST_ERR_UNSUPPORTED;
    }
  va_end (ap);
  return TWIST_OK;
}

static int
push_done (struct twist_multi *multi, struct twist_easy *easy, int result)
{
  if (multi->n_done == multi->done_cap)
    {
      size_t cap = multi->done_cap == 0 ? 4 : multi->done_cap * 2;
      struct twist_easy **e = realloc (multi->done, cap * sizeof *e);
      int *r = realloc (multi->done_result, cap * sizeof *r);

      if (e != NULL)
        multi->done = e;
      if (r != NULL)
        multi->done_result = r;
      if (e == NULL || r == NULL)
        return TWIST_ERR_NOMEM;
      multi->done_cap = cap;
    }
  multi->done[multi->n_done] = easy;
  multi->done_result[multi->n_done] = result;
  multi->n_done++;
  return TWIST_OK;
}

int
twist_easy_finish (struct twist_easy *easy, int result)
{
  if (easy == NULL || easy->done)
    return TWIST_OK;
  easy->done = 1;
  easy->result = result;
  twist_progress_end (easy, result);
  if (easy->multi != NULL)
    return push_done (easy->multi, easy, result);
  return TWIST_OK;
}

int
twist_transfer_start (struct twist_easy *easy)
{
  const struct twist_scheme *scheme;
  int rc;

  twist_easy_set_error (easy, NULL);
  if (easy->url_string == NULL && easy->url == NULL)
    {
      twist_easy_finish (easy, TWIST_ERR_URL);
      return TWIST_ERR_URL;
    }
  if (easy->url == NULL)
    {
      rc = twist_url_parse_int (easy->url_string, &easy->url);
      if (rc != TWIST_OK)
        {
          twist_easy_finish (easy, rc);
          return rc;
        }
    }
  free (easy->effective_url);
  easy->effective_url = twist_url_effective (easy->url);
  scheme = twist_scheme_by_name (easy->url->scheme);
  if (scheme == NULL || (scheme->flags & TWIST_SCHEME_READY) == 0)
    {
      twist_easy_finish (easy, TWIST_ERR_UNSUPPORTED);
      return TWIST_ERR_UNSUPPORTED;
    }
  /* A Unix socket is the HTTP handler's, and another scheme would otherwise
     go to the host and port as if it had not been asked for.  */
  if (easy->unix_path != NULL && strcmp (easy->url->scheme, "http") != 0
      && strcmp (easy->url->scheme, "https") != 0
      && strcmp (easy->url->scheme, "ws") != 0
      && strcmp (easy->url->scheme, "wss") != 0)
    {
      twist_easy_set_error (easy, twist_strdup (_("a Unix socket is for http, "
                                                  "https, ws and wss URLs "
                                                  "only")));
      twist_easy_finish (easy, TWIST_ERR_UNSUPPORTED);
      return TWIST_ERR_UNSUPPORTED;
    }
  easy->done = 0;
  twist_progress_begin (easy);
  rc = scheme->attach (easy);
  if (rc != TWIST_OK && !easy->done)
    twist_easy_finish (easy, rc);
  return rc;
}

/* Run EASY to its end on MULTI, which is left as it is for the next one: its
   loop, its pool of connections, its names.  */
int
twist_easy_perform_in (struct twist_multi *multi, twist_easy *easy)
{
  int rc;
  int running = 0;

  if (multi == NULL || easy == NULL || easy->multi != NULL)
    return TWIST_ERR_INVAL;
  /* Let the loop see what happened to the connections kept since the last
     transfer, so that one the server has closed is not taken.  */
  twist_multi_perform (multi, &running);
  rc = twist_multi_add_handle (multi, easy);
  if (rc != TWIST_OK)
    {
      twist_multi_remove_handle (multi, easy);
      return rc;
    }
  while (!easy->done)
    {
      rc = twist_multi_perform (multi, &running);
      if (rc == TWIST_OK && !easy->done && running > 0)
        rc = twist_loop_run_once (multi->loop);
      if (rc != TWIST_OK)
        {
          twist_easy_finish (easy, rc);
          break;
        }
      if (running == 0 && !easy->done)
        {
          twist_easy_finish (easy, TWIST_ERR_CONNECT);
          break;
        }
    }
  rc = easy->result;
  twist_multi_remove_handle (multi, easy);
  /* Nobody reads the completion messages of a handle run this way.  */
  multi->n_done = multi->done_off = 0;
  return rc;
}

int
twist_easy_perform (twist_easy *easy)
{
  struct twist_multi *multi;
  int rc;

  if (easy == NULL)
    return TWIST_ERR_INVAL;
  if (easy->multi != NULL)
    return TWIST_ERR_INVAL;
  multi = twist_multi_init ();
  if (multi == NULL)
    return TWIST_ERR_NOMEM;
  rc = twist_easy_perform_in (multi, easy);
  twist_multi_cleanup (multi);
  return rc;
}
