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

/* DICT (RFC 2229) in its URL form.  The path is one command.
   d:, define:, and lookup: are DEFINE.  m:, match:, and find: are
   MATCH.  Anything else is sent with ':' turned into a space, which is
   how SHOW DB and the other status commands are written.  The word is
   escaped the way RFC 2229 section 2.2 requires.  The query string is
   not part of the command.  The reply is a byte stream ended by the
   peer closing.  */

#define DICT_PATH_MAX 10000
#define DICT_REQ_MAX (64 + DICT_PATH_MAX * 2)

struct twist_dict
{
  struct twist_transfer *transfer;
  struct twist_endpoint *ep;
  struct twist_mail_link link;
  int sent;
  int saw;
  int finished;
  uint8_t req[DICT_REQ_MAX];
  size_t req_len;
};

static void
dict_complete (struct twist_dict *d, int err)
{
  if (d == NULL || d->finished)
    return;
  d->finished = 1;
  twist_transfer_finish (d->transfer, err);
}

static int
hex_nibble (int c)
{
  if (c >= '0' && c <= '9')
    return c - '0';
  if (c >= 'a' && c <= 'f')
    return c - 'a' + 10;
  if (c >= 'A' && c <= 'F')
    return c - 'A' + 10;
  return -1;
}

static int
decode_path (const char *in, char *out, size_t cap, size_t *out_n)
{
  size_t i = 0;
  size_t o = 0;
  size_t n = strlen (in);

  while (i < n)
    {
      unsigned char c = (unsigned char) in[i];

      if (c == '%')
        {
          int hi;
          int lo;

          if (i + 2 >= n)
            return TWIST_ERR_URL;
          hi = hex_nibble ((unsigned char) in[i + 1]);
          lo = hex_nibble ((unsigned char) in[i + 2]);
          if (hi < 0 || lo < 0)
            return TWIST_ERR_URL;
          c = (unsigned char) ((hi << 4) | lo);
          i += 3;
        }
      else
        i++;
      if (c < 32 || c == 127)
        return TWIST_ERR_URL;
      if (o >= cap)
        return TWIST_ERR_URL;
      out[o++] = (char) c;
    }
  out[o] = 0;
  *out_n = o;
  return TWIST_OK;
}

static int
prefix_ci (const char *s, const char *prefix)
{
  size_t i;

  for (i = 0; prefix[i] != 0; i++)
    {
      unsigned char a = (unsigned char) s[i];
      unsigned char b = (unsigned char) prefix[i];

      if (a == 0 || tolower (a) != tolower (b))
        return 0;
    }
  return 1;
}

static int
add_raw (struct twist_dict *d, const void *p, size_t n)
{
  if (n > DICT_REQ_MAX - d->req_len)
    return TWIST_ERR_URL;
  memcpy (d->req + d->req_len, p, n);
  d->req_len += n;
  return TWIST_OK;
}

static int
add_str (struct twist_dict *d, const char *s)
{
  return add_raw (d, s, strlen (s));
}

static int
needs_slash (unsigned char c)
{
  return c <= 32 || c == 127 || c == '\'' || c == '"' || c == '\\';
}

static int
add_word (struct twist_dict *d, const char *word)
{
  const unsigned char *p = (const unsigned char *) word;

  for (; *p != 0; p++)
    {
      if (needs_slash (*p) && add_raw (d, "\\", 1) != TWIST_OK)
        return TWIST_ERR_URL;
      if (add_raw (d, p, 1) != TWIST_OK)
        return TWIST_ERR_URL;
    }
  return TWIST_OK;
}

static const char *
or_word (const char *s)
{
  if (s == NULL || s[0] == 0)
    return "default";
  return s;
}

static const char *
or_db (const char *s)
{
  if (s == NULL || s[0] == 0)
    return "!";
  return s;
}

static const char *
or_strat (const char *s)
{
  if (s == NULL || s[0] == 0)
    return ".";
  return s;
}

static int
add_command (struct twist_dict *d, int match, const char *database,
             const char *strategy, const char *word)
{
  int rc;

  rc = add_str (d, "CLIENT twist " TWIST_VERSION_STRING "\r\n");
  if (rc != TWIST_OK)
    return rc;
  if (match)
    {
      rc = add_str (d, "MATCH ");
      if (rc != TWIST_OK)
        return rc;
      rc = add_str (d, or_db (database));
      if (rc != TWIST_OK)
        return rc;
      rc = add_str (d, " ");
      if (rc != TWIST_OK)
        return rc;
      rc = add_str (d, or_strat (strategy));
      if (rc != TWIST_OK)
        return rc;
      rc = add_str (d, " ");
      if (rc != TWIST_OK)
        return rc;
    }
  else
    {
      rc = add_str (d, "DEFINE ");
      if (rc != TWIST_OK)
        return rc;
      rc = add_str (d, or_db (database));
      if (rc != TWIST_OK)
        return rc;
      rc = add_str (d, " ");
      if (rc != TWIST_OK)
        return rc;
    }
  rc = add_word (d, or_word (word));
  if (rc != TWIST_OK)
    return rc;
  return add_str (d, "\r\nQUIT\r\n");
}

static int
build_request (struct twist_dict *d)
{
  struct twist_url *url = d->transfer->url;
  const char *path = url->path != NULL && url->path[0] != 0 ? url->path : "/";
  char decoded[DICT_PATH_MAX + 1];
  size_t n = 0;
  char *word;
  char *database;
  char *strategy;
  char *nth;
  char *slash;
  int rc;

  if (url->host == NULL || url->host[0] == 0)
    return TWIST_ERR_URL;
  rc = decode_path (path, decoded, DICT_PATH_MAX, &n);
  if (rc != TWIST_OK)
    return rc;
  if (prefix_ci (decoded, "/match:") || prefix_ci (decoded, "/m:")
      || prefix_ci (decoded, "/find:"))
    {
      word = strchr (decoded, ':');
      database = NULL;
      strategy = NULL;
      if (word != NULL)
        {
          word++;
          database = strchr (word, ':');
          if (database != NULL)
            {
              *database++ = 0;
              strategy = strchr (database, ':');
              if (strategy != NULL)
                {
                  *strategy++ = 0;
                  nth = strchr (strategy, ':');
                  if (nth != NULL)
                    *nth = 0;
                }
            }
        }
      return add_command (d, 1, database, strategy, word);
    }
  if (prefix_ci (decoded, "/define:") || prefix_ci (decoded, "/d:")
      || prefix_ci (decoded, "/lookup:"))
    {
      word = strchr (decoded, ':');
      database = NULL;
      if (word != NULL)
        {
          word++;
          database = strchr (word, ':');
          if (database != NULL)
            {
              *database++ = 0;
              nth = strchr (database, ':');
              if (nth != NULL)
                *nth = 0;
            }
        }
      return add_command (d, 0, database, NULL, word);
    }
  slash = strchr (decoded, '/');
  if (slash == NULL)
    return TWIST_OK;
  slash++;
  for (n = 0; slash[n] != 0; n++)
    if (slash[n] == ':')
      slash[n] = ' ';
  rc = add_str (d, "CLIENT twist " TWIST_VERSION_STRING "\r\n");
  if (rc != TWIST_OK)
    return rc;
  rc = add_str (d, slash);
  if (rc != TWIST_OK)
    return rc;
  return add_str (d, "\r\nQUIT\r\n");
}

static int
flush_request (struct twist_dict *d)
{
  int rc;

  if (d->ep == NULL || d->sent || d->req_len == 0)
    return TWIST_OK;
  rc = twist_endpoint_send (d->ep, d->req, d->req_len);
  if (rc != TWIST_OK)
    return rc;
  d->sent = 1;
  return TWIST_OK;
}

static int
deliver (struct twist_dict *d, const uint8_t *data, size_t len)
{
  struct twist_transfer *transfer = d->transfer;
  size_t off = 0;

  if (len > 0)
    d->saw = 1;
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

const uint8_t *
twist_dict_request (const struct twist_dict *d, size_t *len)
{
  if (d == NULL)
    {
      if (len != NULL)
        *len = 0;
      return NULL;
    }
  if (len != NULL)
    *len = d->req_len;
  return d->req;
}

size_t
twist_dict_receive (struct twist_dict *d, const uint8_t *data, size_t len)
{
  int rc;

  if (d == NULL || d->finished)
    return len;
  rc = deliver (d, data, len);
  if (rc != TWIST_OK)
    {
      dict_complete (d, rc);
      return len;
    }
  return len;
}

void
twist_dict_closed (struct twist_dict *d, int err)
{
  if (d == NULL || d->finished)
    return;
  if ((d->sent || d->saw) && (err == TWIST_OK || err == TWIST_ERR_CLOSED))
    dict_complete (d, TWIST_OK);
  else
    dict_complete (d, err != TWIST_OK ? err : TWIST_ERR_CLOSED);
}

static void
dict_connected (struct twist_endpoint *ep)
{
  struct twist_dict *d = ep->user_data;
  int rc;

  d->ep = ep;
  rc = flush_request (d);
  if (rc != TWIST_OK)
    dict_complete (d, rc);
}

static size_t
dict_on_recv (struct twist_endpoint *ep, const uint8_t *data, size_t len)
{
  struct twist_dict *d = ep->user_data;

  d->ep = ep;
  return twist_dict_receive (d, data, len);
}

static void
dict_disconnected (struct twist_endpoint *ep, int error)
{
  twist_dict_closed (ep->user_data, error);
}

static void
dict_error (struct twist_endpoint *ep, int error)
{
  twist_dict_closed (ep->user_data, error);
}

static void
dict_fail (void *user, int err)
{
  dict_complete (user, err);
}

static const struct twist_protocol_handler dict_handler = {
  dict_connected,
  dict_on_recv,
  dict_disconnected,
  NULL,
  dict_error,
  NULL,
  NULL
};

void
twist_dict_free (void *p)
{
  struct twist_dict *d = p;

  if (d == NULL)
    return;
  twist_mail_link_close (&d->link);
  free (d);
}

struct twist_dict *
twist_dict_new (struct twist_transfer *transfer, int live)
{
  struct twist_dict *d;
  int rc;

  (void) live;
  if (transfer == NULL || transfer->url == NULL)
    return NULL;
  d = calloc (1, sizeof *d);
  if (d == NULL)
    return NULL;
  d->transfer = transfer;
  transfer->state = d;
  transfer->state_free = twist_dict_free;
  rc = build_request (d);
  if (rc != TWIST_OK)
    dict_complete (d, rc);
  return d;
}

int
twist_dict_attach (struct twist_transfer *transfer)
{
  struct twist_dict *d;
  int rc;

  d = twist_dict_new (transfer, 1);
  if (d == NULL)
    return TWIST_ERR_NOMEM;
  if (d->finished)
    return transfer->result;
  rc = twist_mail_link_open (&d->link, transfer, &dict_handler, d, dict_fail);
  if (rc != TWIST_OK)
    dict_complete (d, rc);
  return transfer->done ? transfer->result : TWIST_OK;
}
