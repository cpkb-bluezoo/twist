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

#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

/* RTSP 1.0 (RFC 2326) as the curl tool uses it.  The tool sends one request,
   OPTIONS with the target "*" whatever the URL's path says, and writes the
   reply as the server sent it: the status line and the headers to the header
   callback, the body (only as long as Content-Length says) to the write
   callback.  The CSeq of the reply must be the request's.  An error status is
   not a failure unless -f asks for it, and a redirect is not followed.  The
   other methods of the protocol are libcurl's, through options the tool does
   not have, and are not here.  */

#define RTSP_LINE_MAX 65536

enum rtsp_state
{
  RTSP_STATUS,
  RTSP_HEADERS,
  RTSP_BODY
};

struct twist_rtsp
{
  struct twist_transfer *transfer;
  struct twist_endpoint *ep;
  struct twist_mail_link link;
  enum rtsp_state state;
  int sent;
  int finished;
  int saw_cseq;
  long cseq;
  int have_length;
  uint64_t length;
  uint64_t remaining;
  uint8_t *req;
  size_t req_len;
  size_t req_cap;
};

static void
rtsp_complete (struct twist_rtsp *r, int err)
{
  if (r == NULL || r->finished)
    return;
  r->finished = 1;
  twist_transfer_finish (r->transfer, err);
}

static int
req_add (struct twist_rtsp *r, const char *s, size_t n)
{
  if (r->req_len + n > r->req_cap)
    {
      size_t cap = r->req_cap != 0 ? r->req_cap : 256;
      uint8_t *grown;

      while (cap < r->req_len + n)
        cap *= 2;
      grown = realloc (r->req, cap);
      if (grown == NULL)
        return TWIST_ERR_NOMEM;
      r->req = grown;
      r->req_cap = cap;
    }
  memcpy (r->req + r->req_len, s, n);
  r->req_len += n;
  return TWIST_OK;
}

static int
req_line (struct twist_rtsp *r, const char *s)
{
  int rc = req_add (r, s, strlen (s));

  return rc != TWIST_OK ? rc : req_add (r, "\r\n", 2);
}

/* Whether LINE is a header of that NAME.  */
static int
header_name_is (const char *line, const char *name)
{
  size_t n = strlen (name);
  const char *p;

  if (strncasecmp (line, name, n) != 0)
    return 0;
  p = line + n;
  while (*p == ' ' || *p == '\t')
    p++;
  return *p == ':';
}

/* "Name:" on its own takes the header away, as it does for HTTP.  */
static int
header_empty (const char *line)
{
  const char *colon = strchr (line, ':');

  if (colon == NULL)
    return 0;
  for (colon++; *colon == ' ' || *colon == '\t'; colon++)
    ;
  return *colon == 0;
}

static int
build_request (struct twist_rtsp *r)
{
  struct twist_transfer *transfer = r->transfer;
  const struct twist_slist *scan;
  int own_agent = 0;
  int rc;

  if (transfer->url->host == NULL || transfer->url->host[0] == 0)
    return TWIST_ERR_URL;
  /* CSeq and Session belong to the protocol, and libcurl will not have them
     as headers of the caller's.  */
  for (scan = transfer->headers; scan != NULL; scan = scan->next)
    {
      if (scan->data == NULL)
        continue;
      if (header_name_is (scan->data, "CSeq"))
        return TWIST_ERR_RTSP_CSEQ;
      if (header_name_is (scan->data, "Session"))
        return TWIST_ERR_INVAL;
      if (header_name_is (scan->data, "User-Agent"))
        own_agent = 1;
    }
  rc = req_line (r, "OPTIONS * RTSP/1.0");
  if (rc == TWIST_OK)
    rc = req_line (r, "CSeq: 1");
  if (rc == TWIST_OK && !own_agent)
    {
      rc = req_add (r, "User-Agent: ", 12);
      if (rc == TWIST_OK)
        rc = req_line (r, transfer->useragent != NULL ? transfer->useragent
                                                      : "twist/0.1");
    }
  if (rc == TWIST_OK && transfer->username != NULL
      && (transfer->auth == 0 || (transfer->auth & TWISTAUTH_BASIC) != 0)
      && (transfer->auth & TWISTAUTH_DIGEST) == 0)
    {
      char *basic = NULL;

      rc = twist_auth_basic (transfer->username, transfer->password, &basic);
      if (rc == TWIST_OK)
        {
          rc = req_line (r, basic);
          free (basic);
        }
    }
  for (scan = transfer->headers; rc == TWIST_OK && scan != NULL;
       scan = scan->next)
    if (scan->data != NULL && !header_empty (scan->data))
      rc = req_line (r, scan->data);
  if (rc == TWIST_OK)
    rc = req_add (r, "\r\n", 2);
  return rc;
}

static int
flush_request (struct twist_rtsp *r)
{
  int rc;

  if (r->ep == NULL || r->sent)
    return TWIST_OK;
  rc = twist_endpoint_send (r->ep, r->req, r->req_len);
  if (rc != TWIST_OK)
    return rc;
  r->sent = 1;
  return TWIST_OK;
}

static void
emit_header (struct twist_rtsp *r, const char *line, size_t n)
{
  struct twist_transfer *transfer = r->transfer;
  char *copy;

  if (transfer->header_cb == NULL)
    return;
  copy = malloc (n + 2);
  if (copy == NULL)
    return;
  memcpy (copy, line, n);
  copy[n] = '\r';
  copy[n + 1] = '\n';
  transfer->header_cb (copy, 1, n + 2, transfer->header_data);
  free (copy);
}

static int
deliver (struct twist_rtsp *r, const uint8_t *data, size_t len)
{
  struct twist_transfer *transfer = r->transfer;
  size_t off = 0;

  if (transfer->write_cb == NULL || len == 0)
    {
      twist_transfer_downloaded (transfer, len);
      return TWIST_OK;
    }
  while (off < len)
    {
      char buf[512];
      size_t chunk = len - off;
      size_t n;

      if (chunk > sizeof buf)
        chunk = sizeof buf;
      memcpy (buf, data + off, chunk);
      n = transfer->write_cb (buf, 1, chunk, transfer->write_data);
      if (n < chunk)
        return TWIST_ERR_ABORTED;
      off += chunk;
    }
  twist_transfer_downloaded (transfer, len);
  return TWIST_OK;
}

/* The status line.  Anything that is not RTSP is a reply from a server that
   is not one, which curl calls an empty reply; RTSP of another version is
   a weird one.  */
static int
status_line (struct twist_rtsp *r, const char *line, size_t n)
{
  int code;

  if (n < 5 || strncmp (line, "RTSP/", 5) != 0)
    return TWIST_ERR_CLOSED;
  if (n < 9 || strncmp (line, "RTSP/1.0 ", 9) != 0)
    return TWIST_ERR_PROTOCOL;
  if (n < 12 || !isdigit ((unsigned char) line[9])
      || !isdigit ((unsigned char) line[10])
      || !isdigit ((unsigned char) line[11])
      || (n > 12 && line[12] != ' '))
    return TWIST_ERR_PROTOCOL;
  code = (line[9] - '0') * 100 + (line[10] - '0') * 10 + (line[11] - '0');
  r->transfer->http_code = code;
  emit_header (r, line, n);
  r->state = RTSP_HEADERS;
  return TWIST_OK;
}

static int
header_line (struct twist_rtsp *r, const char *line, size_t n)
{
  const char *colon = memchr (line, ':', n);
  size_t name_n;
  const char *value;
  size_t value_n;

  emit_header (r, line, n);
  if (colon == NULL)
    return TWIST_OK;
  name_n = (size_t) (colon - line);
  value = colon + 1;
  value_n = n - name_n - 1;
  while (value_n > 0 && (*value == ' ' || *value == '\t'))
    {
      value++;
      value_n--;
    }
  while (value_n > 0 && (value[value_n - 1] == ' '
                         || value[value_n - 1] == '\t'))
    value_n--;
  if (name_n == 4 && strncasecmp (line, "CSeq", 4) == 0)
    {
      char *end;
      char tmp[24];

      if (value_n == 0 || value_n >= sizeof tmp)
        return TWIST_OK;
      memcpy (tmp, value, value_n);
      tmp[value_n] = 0;
      r->cseq = strtol (tmp, &end, 10);
      r->saw_cseq = *end == 0;
    }
  else if (name_n == 14 && strncasecmp (line, "Content-Length", 14) == 0)
    {
      uint64_t v = 0;
      size_t i;

      if (value_n == 0)
        return TWIST_ERR_PROTOCOL;
      for (i = 0; i < value_n; i++)
        {
          unsigned d;

          if (!isdigit ((unsigned char) value[i]))
            return TWIST_ERR_PROTOCOL;
          d = (unsigned) (value[i] - '0');
          if (v > (UINT64_MAX - d) / 10)
            return TWIST_ERR_PROTOCOL;
          v = v * 10 + d;
        }
      r->have_length = 1;
      r->length = v;
    }
  return TWIST_OK;
}

/* The blank line: the reply is checked, and then there is a body to read or
   the transfer is over.  */
static void
headers_end (struct twist_rtsp *r)
{
  struct twist_transfer *transfer = r->transfer;

  if (!r->saw_cseq || r->cseq != 1)
    {
      rtsp_complete (r, TWIST_ERR_RTSP_CSEQ);
      return;
    }
  if (twist_http_status_result (transfer->failonerror,
                                (int) transfer->http_code) != TWIST_OK)
    {
      rtsp_complete (r, TWIST_ERR_HTTP);
      return;
    }
  if (transfer->nobody || !r->have_length || r->length == 0)
    {
      rtsp_complete (r, TWIST_OK);
      return;
    }
  r->remaining = r->length;
  r->state = RTSP_BODY;
}

const uint8_t *
twist_rtsp_request (const struct twist_rtsp *r, size_t *len)
{
  if (r == NULL)
    {
      if (len != NULL)
        *len = 0;
      return NULL;
    }
  if (len != NULL)
    *len = r->req_len;
  return r->req;
}

size_t
twist_rtsp_receive (struct twist_rtsp *r, const uint8_t *data, size_t len)
{
  size_t used = 0;

  if (r == NULL || r->finished)
    return len;
  while (used < len && !r->finished)
    {
      if (r->state == RTSP_BODY)
        {
          size_t take = len - used;
          int rc;

          if ((uint64_t) take > r->remaining)
            take = (size_t) r->remaining;
          rc = deliver (r, data + used, take);
          used += take;
          r->remaining -= take;
          if (rc != TWIST_OK)
            rtsp_complete (r, rc);
          else if (r->remaining == 0)
            rtsp_complete (r, TWIST_OK);
        }
      else
        {
          const uint8_t *nl = memchr (data + used, '\n', len - used);
          const char *line = (const char *) data + used;
          size_t n;
          size_t consumed;
          int rc = TWIST_OK;

          if (nl == NULL)
            {
              if (len - used > RTSP_LINE_MAX)
                {
                  rtsp_complete (r, TWIST_ERR_PROTOCOL);
                  return len;
                }
              return used;
            }
          consumed = (size_t) (nl - (data + used)) + 1;
          n = consumed - 1;
          if (n > 0 && line[n - 1] == '\r')
            n--;
          used += consumed;
          if (r->state == RTSP_STATUS)
            rc = status_line (r, line, n);
          else if (n == 0)
            headers_end (r);
          else
            rc = header_line (r, line, n);
          if (rc != TWIST_OK)
            rtsp_complete (r, rc);
        }
    }
  return used;
}

void
twist_rtsp_closed (struct twist_rtsp *r, int err)
{
  if (r == NULL || r->finished)
    return;
  if (err == TWIST_OK || err == TWIST_ERR_CLOSED)
    err = r->state == RTSP_BODY ? TWIST_ERR_PARTIAL : TWIST_ERR_CLOSED;
  rtsp_complete (r, err);
}

static void
rtsp_connected (struct twist_endpoint *ep)
{
  struct twist_rtsp *r = ep->user_data;
  int rc;

  r->ep = ep;
  rc = flush_request (r);
  if (rc != TWIST_OK)
    rtsp_complete (r, rc);
}

static size_t
rtsp_on_recv (struct twist_endpoint *ep, const uint8_t *data, size_t len)
{
  struct twist_rtsp *r = ep->user_data;

  r->ep = ep;
  return twist_rtsp_receive (r, data, len);
}

static void
rtsp_disconnected (struct twist_endpoint *ep, int error)
{
  twist_rtsp_closed (ep->user_data, error);
}

static void
rtsp_secure (struct twist_endpoint *ep, const char *alpn, size_t alpn_len)
{
  (void) ep;
  (void) alpn;
  (void) alpn_len;
}

static void
rtsp_error (struct twist_endpoint *ep, int error)
{
  twist_rtsp_closed (ep->user_data, error);
}

static void
rtsp_fail (void *user, int err)
{
  rtsp_complete (user, err);
}

static const struct twist_protocol_handler rtsp_handler = {
  rtsp_connected,
  rtsp_on_recv,
  rtsp_disconnected,
  rtsp_secure,
  rtsp_error,
  NULL,
  NULL
};

void
twist_rtsp_free (void *p)
{
  struct twist_rtsp *r = p;

  if (r == NULL)
    return;
  twist_mail_link_close (&r->link);
  free (r->req);
  free (r);
}

struct twist_rtsp *
twist_rtsp_new (struct twist_transfer *transfer, int live)
{
  struct twist_rtsp *r;
  int rc;

  (void) live;
  if (transfer == NULL || transfer->url == NULL)
    return NULL;
  r = calloc (1, sizeof *r);
  if (r == NULL)
    return NULL;
  r->transfer = transfer;
  transfer->state = r;
  transfer->state_free = twist_rtsp_free;
  rc = build_request (r);
  if (rc != TWIST_OK)
    rtsp_complete (r, rc);
  return r;
}

int
twist_rtsp_attach (struct twist_transfer *transfer)
{
  struct twist_rtsp *r;
  int rc;

  r = twist_rtsp_new (transfer, 1);
  if (r == NULL)
    return TWIST_ERR_NOMEM;
  if (r->finished)
    return transfer->result;
  rc = twist_mail_link_open (&r->link, transfer, &rtsp_handler, r, rtsp_fail);
  if (rc != TWIST_OK)
    rtsp_complete (r, rc);
  return transfer->done ? transfer->result : TWIST_OK;
}
