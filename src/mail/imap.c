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
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

/* IMAP client: CAPABILITY, SASL AUTHENTICATE, SELECT, UID FETCH or LIST.
   A FETCH literal is written as its octets arrive.  The literal count
   is the only memory of it.  */

enum
{
  I_GREET = 0,
  I_CAP,
  I_AUTH,
  I_BOX,
  I_FETCH
};

struct twist_imap
{
  struct twist_easy *easy;
  struct twist_mail_link link;
  struct twist_mail_sasl sasl;
  struct twist_endpoint *ep;
  int implicit_tls;
  int state;
  int finished;
  int tag;
  int uid;
  int in_fetch;
  size_t literal;
  char auth_adv[96];
  char box[256];
  char expect[16];
  char cmd[512];
};

static void imap_complete (struct twist_imap *m, int err);

static int
bad_token (const char *s)
{
  return s != NULL && (strchr (s, '\r') != NULL || strchr (s, '\n') != NULL);
}

static void
imap_complete (struct twist_imap *m, int err)
{
  if (m == NULL || m->finished)
    return;
  m->finished = 1;
  twist_easy_finish (m->easy, err);
}

static int
imap_send (struct twist_imap *m, const char *fmt, ...)
{
  va_list ap;
  int n;

  va_start (ap, fmt);
  n = vsnprintf (m->cmd, sizeof m->cmd, fmt, ap);
  va_end (ap);
  if (n < 0 || (size_t) n >= sizeof m->cmd)
    return TWIST_ERR_PROTOCOL;
  if (m->ep == NULL)
    return TWIST_OK;
  return twist_endpoint_send (m->ep, (const uint8_t *) m->cmd, (size_t) n);
}

static void
next_tag (struct twist_imap *m)
{
  m->tag++;
  snprintf (m->expect, sizeof m->expect, "A%d", m->tag);
}

int
twist_imap_mailbox (const char *box, char *out, size_t cap)
{
  const unsigned char *p;
  int atom = 1;
  size_t n;

  if (box == NULL || box[0] == 0 || out == NULL || cap == 0)
    return TWIST_ERR_URL;
  for (p = (const unsigned char *) box; *p != 0; p++)
    {
      if (*p == '\r' || *p == '\n' || *p == '"' || *p == '\\' || *p < 0x20
          || *p == 0x7f)
        return TWIST_ERR_URL;
      if (*p == '(' || *p == ')' || *p == '{' || *p == ' ' || *p == '%'
          || *p == '*' || *p == ']')
        atom = 0;
    }
  n = strlen (box);
  if (atom)
    {
      if (n + 1 > cap)
        return TWIST_ERR_URL;
      memcpy (out, box, n + 1);
      return TWIST_OK;
    }
  if (n + 3 > cap)
    return TWIST_ERR_URL;
  out[0] = '"';
  memcpy (out + 1, box, n);
  out[n + 1] = '"';
  out[n + 2] = 0;
  return TWIST_OK;
}

static int
parse_target (struct twist_imap *m)
{
  const char *path;
  const char *uid;
  size_t n;

  m->uid = 0;
  memcpy (m->box, "INBOX", 6);
  if (m->easy->url == NULL || m->easy->url->path == NULL)
    return TWIST_OK;
  path = m->easy->url->path;
  if (path[0] == '/')
    path++;
  uid = strstr (path, ";UID=");
  n = uid != NULL ? (size_t) (uid - path) : strlen (path);
  while (n > 0 && path[n - 1] == '/')
    n--;
  if (n > 0)
    {
      if (n >= sizeof m->box || bad_token (path))
        return TWIST_ERR_URL;
      memcpy (m->box, path, n);
      m->box[n] = 0;
    }
  if (uid != NULL)
    {
      char *end = NULL;
      long v = strtol (uid + 5, &end, 10);

      if (end == uid + 5 || v < 1)
        return TWIST_ERR_URL;
      m->uid = (int) v;
    }
  if (bad_token (m->box) || strchr (m->box, '"') != NULL)
    return TWIST_ERR_URL;
  return TWIST_OK;
}

static int
deliver (struct twist_imap *m, const uint8_t *data, size_t len)
{
  struct twist_easy *easy = m->easy;
  size_t n;

  if (len == 0)
    return TWIST_OK;
  if (easy->write_cb == NULL)
    {
      easy->size_download += len;
      return TWIST_OK;
    }
  {
    char buf[512];
    size_t off = 0;

    while (off < len)
      {
        size_t chunk = len - off;

        if (chunk > sizeof buf)
          chunk = sizeof buf;
        memcpy (buf, data + off, chunk);
        n = easy->write_cb (buf, 1, chunk, easy->write_data);
        if (n < chunk)
          return TWIST_ERR_ABORTED;
        off += chunk;
      }
  }
  easy->size_download += len;
  return TWIST_OK;
}

static int
start_box (struct twist_imap *m)
{
  char mailbox[300];
  int rc = parse_target (m);

  if (rc != TWIST_OK)
    return rc;
  rc = twist_imap_mailbox (m->box, mailbox, sizeof mailbox);
  if (rc != TWIST_OK)
    return rc;
  next_tag (m);
  m->state = I_BOX;
  if (m->uid > 0)
    return imap_send (m, "%s SELECT %s\r\n", m->expect, mailbox);
  return imap_send (m, "%s LIST \"\" %s\r\n", m->expect, mailbox);
}

static int
start_auth (struct twist_imap *m)
{
  const char *user = twist_mail_user (m->easy);
  const char *bearer = m->easy->bearer;
  char *b64 = NULL;
  int initial = 0;
  int rc;

  if ((user == NULL || user[0] == 0)
      && (bearer == NULL || bearer[0] == 0))
    return start_box (m);
  if (bad_token (user) || bad_token (twist_mail_pass (m->easy)))
    return TWIST_ERR_PROTOCOL;
  rc = twist_mail_sasl_start (&m->sasl, m->easy,
                              m->auth_adv[0] != 0 ? m->auth_adv : NULL,
                              &b64, &initial);
  if (rc != TWIST_OK)
    return rc;
  next_tag (m);
  m->state = I_AUTH;
  if (initial && b64 != NULL)
    rc = imap_send (m, "%s AUTHENTICATE %s %s\r\n", m->expect,
                    twist_sasl_name (m->sasl.mech), b64);
  else
    rc = imap_send (m, "%s AUTHENTICATE %s\r\n", m->expect,
                    twist_sasl_name (m->sasl.mech));
  free (b64);
  return rc;
}

static void
note_cap (struct twist_imap *m, const uint8_t *line, size_t n)
{
  const char *s = (const char *) line;
  const char *p;
  size_t i;

  if (n < 11)
    return;
  for (i = 0; i + 10 < n; i++)
    if (strncasecmp (s + i, "CAPABILITY", 10) == 0)
      break;
  if (i + 10 >= n)
    return;
  p = s + i + 10;
  while (p < s + n)
    {
      const char *e;

      while (p < s + n && *p == ' ')
        p++;
      if ((size_t) (s + n - p) >= 5 && strncasecmp (p, "AUTH=", 5) == 0)
        {
          p += 5;
          e = p;
          while (e < s + n && *e != ' ')
            e++;
          if (m->auth_adv[0] != 0 && strlen (m->auth_adv) + 1 < sizeof m->auth_adv)
            strcat (m->auth_adv, " ");
          if (strlen (m->auth_adv) + (size_t) (e - p) < sizeof m->auth_adv)
            strncat (m->auth_adv, p, (size_t) (e - p));
          p = e;
        }
      else
        {
          while (p < s + n && *p != ' ')
            p++;
        }
    }
}

static int
literal_len (const uint8_t *line, size_t n, size_t *out)
{
  size_t i;
  size_t v = 0;

  if (n < 3 || line[n - 1] != '}')
    return 0;
  i = n - 1;
  while (i > 0 && isdigit (line[i - 1]))
    i--;
  if (i == 0 || line[i - 1] != '{')
    return 0;
  for (i = i; i < n - 1; i++)
    v = v * 10 + (size_t) (line[i] - '0');
  *out = v;
  return 1;
}

static int
is_tagged (const struct twist_imap *m, const uint8_t *line, size_t n, int *ok)
{
  size_t tn = strlen (m->expect);

  if (n < tn + 1 || memcmp (line, m->expect, tn) != 0 || line[tn] != ' ')
    return 0;
  *ok = n >= tn + 3 && strncmp ((const char *) line + tn + 1, "OK", 2) == 0;
  return 1;
}

static void
on_line (struct twist_imap *m, const uint8_t *line, size_t n)
{
  int ok = 0;
  int rc = TWIST_OK;
  size_t lit = 0;

  if (m->finished || n == 0)
    return;
  if (line[0] == '*')
    {
      note_cap (m, line, n);
      if (m->state == I_BOX && m->uid == 0)
        {
          if (deliver (m, line, n) != TWIST_OK
              || deliver (m, (const uint8_t *) "\r\n", 2) != TWIST_OK)
            {
              imap_complete (m, TWIST_ERR_ABORTED);
              return;
            }
        }
    }
  if (m->state == I_GREET)
    {
      if (strncasecmp ((const char *) line, "* BYE", 5) == 0)
        {
          imap_complete (m, TWIST_ERR_PROTOCOL);
          return;
        }
      next_tag (m);
      m->state = I_CAP;
      if (imap_send (m, "%s CAPABILITY\r\n", m->expect) != TWIST_OK)
        imap_complete (m, TWIST_ERR_PROTOCOL);
      return;
    }
  if (m->state == I_AUTH && line[0] == '+')
    {
      char *b64 = NULL;

      rc = twist_mail_sasl_continue (&m->sasl, &b64);
      if (rc == TWIST_OK && b64 != NULL)
        rc = imap_send (m, "%s\r\n", b64);
      free (b64);
      if (rc != TWIST_OK)
        imap_complete (m, rc);
      return;
    }
  if (literal_len (line, n, &lit))
    {
      m->literal = lit;
      m->in_fetch = m->state == I_FETCH;
    }
  if (!is_tagged (m, line, n, &ok))
    return;
  if (!ok)
    {
      imap_complete (m, m->state == I_AUTH ? TWIST_ERR_AUTH : TWIST_ERR_PROTOCOL);
      return;
    }
  switch (m->state)
    {
    case I_CAP:
      rc = start_auth (m);
      break;
    case I_AUTH:
      rc = start_box (m);
      break;
    case I_BOX:
      if (m->uid > 0)
        {
          next_tag (m);
          m->state = I_FETCH;
          rc = imap_send (m, "%s UID FETCH %d BODY[]\r\n", m->expect, m->uid);
          break;
        }
      rc = imap_send (m, "A%d LOGOUT\r\n", m->tag + 1);
      if (rc == TWIST_OK)
        imap_complete (m, TWIST_OK);
      return;
    case I_FETCH:
      rc = imap_send (m, "A%d LOGOUT\r\n", m->tag + 1);
      if (rc == TWIST_OK)
        imap_complete (m, TWIST_OK);
      return;
    default:
      return;
    }
  if (rc != TWIST_OK)
    imap_complete (m, rc);
}

size_t
twist_imap_receive (struct twist_imap *m, const uint8_t *data, size_t len)
{
  size_t off = 0;

  if (m == NULL || data == NULL)
    return 0;
  while (off < len && !m->finished)
    {
      if (m->literal > 0)
        {
          size_t n = len - off;

          if (n > m->literal)
            n = m->literal;
          if (m->in_fetch && deliver (m, data + off, n) != TWIST_OK)
            {
              imap_complete (m, TWIST_ERR_ABORTED);
              return off;
            }
          m->literal -= n;
          off += n;
          continue;
        }
      {
        const uint8_t *line = NULL;
        size_t line_len = 0;
        int err = TWIST_OK;
        size_t used = twist_mail_line (data + off, len - off, &line, &line_len,
                                       &err);

        if (err != TWIST_OK)
          {
            imap_complete (m, err);
            return len;
          }
        if (used == 0)
          return off;
        on_line (m, line, line_len);
        off += used;
      }
    }
  return off;
}

const char *
twist_imap_command (const struct twist_imap *imap)
{
  return imap != NULL ? imap->cmd : "";
}

static void
imap_fail (void *user, int err)
{
  imap_complete (user, err);
}

static void
imap_connected (struct twist_endpoint *ep)
{
  struct twist_imap *m = ep->user_data;
  int rc;

  m->ep = ep;
  if (!m->implicit_tls)
    return;
  rc = twist_connection_start_tls (ep->conn, m->easy->url->host,
                                   m->easy->verifypeer, NULL, 0,
                                   m->easy->cainfo, m->easy->sslcert,
                                   m->easy->sslkey);
  if (rc != TWIST_OK)
    imap_complete (m, rc);
}

static size_t
imap_on_recv (struct twist_endpoint *ep, const uint8_t *data, size_t len)
{
  struct twist_imap *m = ep->user_data;

  m->ep = ep;
  return twist_imap_receive (m, data, len);
}

static void
imap_disconnected (struct twist_endpoint *ep, int error)
{
  struct twist_imap *m = ep->user_data;

  if (!m->finished)
    imap_complete (m, error != TWIST_OK ? error : TWIST_ERR_CLOSED);
}

static void
imap_error (struct twist_endpoint *ep, int error)
{
  struct twist_imap *m = ep->user_data;

  if (!m->finished && error != TWIST_OK && error != TWIST_ERR_CLOSED)
    imap_complete (m, error);
}

static const struct twist_protocol_handler imap_handler = {
  imap_connected,
  imap_on_recv,
  imap_disconnected,
  NULL,
  imap_error,
  NULL,
  NULL
};

void
twist_imap_free (void *p)
{
  struct twist_imap *m = p;

  if (m == NULL)
    return;
  twist_mail_sasl_close (&m->sasl);
  twist_mail_link_close (&m->link);
  free (m);
}

struct twist_imap *
twist_imap_new (struct twist_easy *easy, int live)
{
  struct twist_imap *m;

  (void) live;
  if (easy == NULL || easy->url == NULL)
    return NULL;
  m = calloc (1, sizeof *m);
  if (m == NULL)
    return NULL;
  m->easy = easy;
  m->implicit_tls = easy->url->scheme != NULL
                    && strcmp (easy->url->scheme, "imaps") == 0;
  twist_mail_sasl_init (&m->sasl);
  easy->xfer = m;
  easy->xfer_free = twist_imap_free;
  return m;
}

int
twist_imap_attach (struct twist_easy *easy)
{
  struct twist_imap *m;
  int rc;

  if (easy == NULL || easy->url == NULL || easy->loop == NULL)
    return TWIST_ERR_INVAL;
  m = twist_imap_new (easy, 1);
  if (m == NULL)
    return TWIST_ERR_NOMEM;
  rc = twist_mail_link_open (&m->link, easy, &imap_handler, m, imap_fail);
  if (rc != TWIST_OK)
    imap_complete (m, rc);
  return easy->done ? easy->result : TWIST_OK;
}
