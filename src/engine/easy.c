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

#include <stdarg.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

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

twist_easy *
twist_easy_init (void)
{
  struct twist_easy *easy = calloc (1, sizeof *easy);

  if (easy == NULL)
    return NULL;
  easy->maxredirs = 50;
  easy->verifypeer = 1;
  easy->http_version = TWIST_HTTP_VERSION_NONE;
  easy->auth = TWISTAUTH_BASIC;
  return easy;
}

static void
easy_clear (struct twist_easy *easy)
{
  if (easy->xfer_free != NULL && easy->xfer != NULL)
    easy->xfer_free (easy->xfer);
  easy->xfer = NULL;
  easy->xfer_free = NULL;
  free (easy->url_string);
  twist_url_free_int (easy->url);
  free (easy->method);
  free (easy->useragent);
  free (easy->username);
  free (easy->password);
  free (easy->bearer);
  free (easy->proxy);
  free (easy->range);
  free (easy->referer);
  free (easy->cookie);
  free (easy->cainfo);
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
      replace (&easy->password, va_arg (ap, const char *));
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
      replace (&easy->bearer, va_arg (ap, const char *));
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
      easy->connect_timeout_ms = va_arg (ap, long);
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
  easy->effective_url = twist_url_format (easy->url);
  scheme = twist_scheme_by_name (easy->url->scheme);
  if (scheme == NULL || (scheme->flags & TWIST_SCHEME_READY) == 0)
    {
      twist_easy_finish (easy, TWIST_ERR_UNSUPPORTED);
      return TWIST_ERR_UNSUPPORTED;
    }
  easy->done = 0;
  rc = scheme->attach (easy);
  if (rc != TWIST_OK && !easy->done)
    twist_easy_finish (easy, rc);
  return rc;
}

int
twist_easy_perform (twist_easy *easy)
{
  struct twist_multi *multi;
  int rc;
  int running = 0;

  if (easy == NULL)
    return TWIST_ERR_INVAL;
  if (easy->multi != NULL)
    return TWIST_ERR_INVAL;
  multi = twist_multi_init ();
  if (multi == NULL)
    return TWIST_ERR_NOMEM;
  rc = twist_multi_add_handle (multi, easy);
  if (rc != TWIST_OK)
    {
      twist_multi_cleanup (multi);
      return rc;
    }
  while (!easy->done)
    {
      rc = twist_multi_perform (multi, &running);
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
  twist_multi_cleanup (multi);
  return rc;
}
