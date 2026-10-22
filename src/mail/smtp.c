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

/* SMTP client: EHLO, SASL AUTH, MAIL FROM, RCPT TO, DATA.  The message
   is dot-stuffed and written as chunks.  It is not held as one buffer.  */

enum
{
  S_GREET = 0,
  S_EHLO,
  S_AUTH,
  S_MAIL,
  S_RCPT,
  S_DATA,
  S_SENT
};

struct twist_smtp
{
  struct twist_easy *easy;
  struct twist_mail_link link;
  struct twist_mail_sasl sasl;
  struct twist_endpoint *ep;
  struct twist_slist *rcpt;
  int implicit_tls;
  int state;
  int finished;
  int cont;
  char auth_adv[80];
  char cmd[2048];
  size_t cmdlen;
};

static void smtp_complete (struct twist_smtp *s, int err);
static int smtp_send (struct twist_smtp *s, const void *data, size_t n, int append);

static int
bad_token (const char *s)
{
  return s != NULL && (strchr (s, '\r') != NULL || strchr (s, '\n') != NULL);
}

static void
smtp_complete (struct twist_smtp *s, int err)
{
  if (s == NULL || s->finished)
    return;
  s->finished = 1;
  twist_easy_finish (s->easy, err);
}

static int
smtp_send (struct twist_smtp *s, const void *data, size_t n, int append)
{
  const uint8_t *p = data;

  if (!append)
    {
      if (n >= sizeof s->cmd)
        return TWIST_ERR_PROTOCOL;
      memcpy (s->cmd, p, n);
      s->cmdlen = n;
      s->cmd[n] = 0;
    }
  else if (s->cmdlen + n < sizeof s->cmd)
    {
      memcpy (s->cmd + s->cmdlen, p, n);
      s->cmdlen += n;
      s->cmd[s->cmdlen] = 0;
    }
  if (s->ep == NULL)
    return TWIST_OK;
  return twist_endpoint_send (s->ep, p, n);
}

static int
smtp_printf (struct twist_smtp *s, const char *fmt, ...)
{
  char buf[512];
  va_list ap;
  int n;

  va_start (ap, fmt);
  n = vsnprintf (buf, sizeof buf, fmt, ap);
  va_end (ap);
  if (n < 0 || (size_t) n >= sizeof buf)
    return TWIST_ERR_PROTOCOL;
  return smtp_send (s, buf, (size_t) n, 0);
}

static int
body_sink (void *user, const uint8_t *data, size_t len)
{
  return smtp_send (user, data, len, 1) == TWIST_OK ? 0 : 1;
}

static int
send_body (struct twist_smtp *s)
{
  struct twist_dotout dot;
  struct twist_easy *easy = s->easy;
  int rc;

  twist_dotout_init (&dot);
  s->cmdlen = 0;
  s->cmd[0] = 0;
  if (twist_easy_upload_size (easy) >= 0)
    twist_progress_ul_size (easy, twist_easy_upload_size (easy));
  if (easy->postfields != NULL)
    {
      const char *p = easy->postfields;
      size_t left = easy->postfieldsize_set && easy->postfieldsize >= 0
                    ? (size_t) easy->postfieldsize : strlen (p);

      while (left > 0)
        {
          size_t n = left > 512 ? 512 : left;

          rc = twist_dotout_write (&dot, (const uint8_t *) p, n, body_sink, s);
          if (rc != TWIST_OK)
            return rc;
          twist_progress_uploaded (easy, n);
          p += n;
          left -= n;
        }
    }
  else if (easy->read_cb != NULL)
    {
      char buf[512];

      for (;;)
        {
          size_t n = easy->read_cb (buf, 1, sizeof buf, easy->read_data);

          if (n == 0)
            break;
          if (n > sizeof buf)
            return TWIST_ERR_ABORTED;
          rc = twist_dotout_write (&dot, (const uint8_t *) buf, n, body_sink, s);
          if (rc != TWIST_OK)
            return rc;
          twist_progress_uploaded (easy, n);
        }
    }
  return twist_dotout_finish (&dot, body_sink, s);
}

static int
start_mail (struct twist_smtp *s)
{
  const char *from = s->easy->mail_from;

  if (bad_token (from))
    return TWIST_ERR_PROTOCOL;
  s->rcpt = s->easy->mail_rcpt;
  if (s->rcpt == NULL || s->rcpt->data == NULL)
    return TWIST_ERR_URL;
  s->state = S_MAIL;
  if (from == NULL || from[0] == 0)
    return smtp_printf (s, "MAIL FROM:<>\r\n");
  return smtp_printf (s, "MAIL FROM:<%s>\r\n", from);
}

static int
start_auth (struct twist_smtp *s)
{
  char *b64 = NULL;
  int initial = 0;
  int rc;
  const char *user = twist_mail_user (s->easy);
  const char *bearer = s->easy->bearer;

  if ((user == NULL || user[0] == 0)
      && (bearer == NULL || bearer[0] == 0))
    return start_mail (s);
  if (bad_token (user) || bad_token (twist_mail_pass (s->easy)))
    return TWIST_ERR_PROTOCOL;
  rc = twist_mail_sasl_start (&s->sasl, s->easy,
                              s->auth_adv[0] != 0 ? s->auth_adv : NULL,
                              &b64, &initial);
  if (rc != TWIST_OK)
    return rc;
  s->state = S_AUTH;
  if (initial && b64 != NULL)
    rc = smtp_printf (s, "AUTH %s %s\r\n", twist_sasl_name (s->sasl.mech), b64);
  else
    rc = smtp_printf (s, "AUTH %s\r\n", twist_sasl_name (s->sasl.mech));
  free (b64);
  return rc;
}

static void
note_auth (struct twist_smtp *s, const char *text, size_t n)
{
  if (n >= 5 && strncasecmp (text, "AUTH ", 5) == 0)
    {
      size_t c = n - 5;

      if (c >= sizeof s->auth_adv)
        c = sizeof s->auth_adv - 1;
      memcpy (s->auth_adv, text + 5, c);
      s->auth_adv[c] = 0;
    }
}

static int
parse_reply (const uint8_t *line, size_t n, int *code, int *dash,
             const uint8_t **text, size_t *text_len)
{
  if (n < 3 || !isdigit (line[0]) || !isdigit (line[1]) || !isdigit (line[2]))
    return 0;
  if (n > 3 && line[3] != ' ' && line[3] != '-')
    return 0;
  *code = (line[0] - '0') * 100 + (line[1] - '0') * 10 + (line[2] - '0');
  *dash = n > 3 && line[3] == '-';
  if (n <= 4)
    {
      *text = line;
      *text_len = 0;
    }
  else
    {
      *text = line + 4;
      *text_len = n - 4;
    }
  return 1;
}

static void
on_final (struct twist_smtp *s, int code)
{
  int rc = TWIST_OK;

  s->easy->http_code = code;
  switch (s->state)
    {
    case S_GREET:
      if (code != 220)
        {
          smtp_complete (s, TWIST_ERR_PROTOCOL);
          return;
        }
      s->state = S_EHLO;
      rc = smtp_printf (s, "EHLO twist\r\n");
      break;
    case S_EHLO:
      if (code / 100 != 2)
        {
          smtp_complete (s, TWIST_ERR_PROTOCOL);
          return;
        }
      rc = start_auth (s);
      break;
    case S_AUTH:
      if (code == 334)
        {
          char *b64 = NULL;

          rc = twist_mail_sasl_continue (&s->sasl, &b64);
          if (rc == TWIST_OK && b64 != NULL)
            rc = smtp_printf (s, "%s\r\n", b64);
          free (b64);
          break;
        }
      if (code / 100 != 2)
        {
          smtp_complete (s, TWIST_ERR_AUTH);
          return;
        }
      rc = start_mail (s);
      break;
    case S_MAIL:
      if (code / 100 != 2)
        {
          smtp_complete (s, TWIST_ERR_PROTOCOL);
          return;
        }
      if (bad_token (s->rcpt->data))
        {
          smtp_complete (s, TWIST_ERR_PROTOCOL);
          return;
        }
      s->state = S_RCPT;
      rc = smtp_printf (s, "RCPT TO:<%s>\r\n", s->rcpt->data);
      break;
    case S_RCPT:
      if (code / 100 != 2)
        {
          smtp_complete (s, TWIST_ERR_PROTOCOL);
          return;
        }
      s->rcpt = s->rcpt->next;
      if (s->rcpt != NULL)
        {
          if (bad_token (s->rcpt->data))
            {
              smtp_complete (s, TWIST_ERR_PROTOCOL);
              return;
            }
          rc = smtp_printf (s, "RCPT TO:<%s>\r\n", s->rcpt->data);
          break;
        }
      s->state = S_DATA;
      rc = smtp_printf (s, "DATA\r\n");
      break;
    case S_DATA:
      if (code != 354)
        {
          smtp_complete (s, TWIST_ERR_PROTOCOL);
          return;
        }
      s->state = S_SENT;
      rc = send_body (s);
      break;
    case S_SENT:
      if (code / 100 != 2)
        {
          smtp_complete (s, TWIST_ERR_PROTOCOL);
          return;
        }
      rc = smtp_printf (s, "QUIT\r\n");
      if (rc == TWIST_OK)
        smtp_complete (s, TWIST_OK);
      return;
    default:
      return;
    }
  if (rc != TWIST_OK)
    smtp_complete (s, rc);
}

static void
on_line (struct twist_smtp *s, const uint8_t *line, size_t n)
{
  int code = 0;
  int dash = 0;
  const uint8_t *text = line;
  size_t text_len = n;
  int parsed;

  if (s->finished)
    return;
  parsed = parse_reply (line, n, &code, &dash, &text, &text_len);
  if (!parsed)
    {
      smtp_complete (s, TWIST_ERR_PROTOCOL);
      return;
    }
  if (s->state == S_EHLO)
    note_auth (s, (const char *) text, text_len);
  if (dash)
    {
      s->cont = code;
      return;
    }
  if (s->cont != 0 && code != s->cont && s->state == S_EHLO)
    {
      smtp_complete (s, TWIST_ERR_PROTOCOL);
      return;
    }
  s->cont = 0;
  on_final (s, code);
}

size_t
twist_smtp_receive (struct twist_smtp *s, const uint8_t *data, size_t len)
{
  size_t off = 0;

  if (s == NULL || data == NULL)
    return 0;
  while (off < len && !s->finished)
    {
      const uint8_t *line = NULL;
      size_t line_len = 0;
      int err = TWIST_OK;
      size_t used = twist_mail_line (data + off, len - off, &line, &line_len,
                                     &err);

      if (err != TWIST_OK)
        {
          smtp_complete (s, err);
          return len;
        }
      if (used == 0)
        return off;
      on_line (s, line, line_len);
      off += used;
    }
  return off;
}

const char *
twist_smtp_command (const struct twist_smtp *smtp)
{
  return smtp != NULL ? smtp->cmd : "";
}

static void
smtp_fail (void *user, int err)
{
  smtp_complete (user, err);
}

static void
smtp_connected (struct twist_endpoint *ep)
{
  struct twist_smtp *s = ep->user_data;
  int rc;

  s->ep = ep;
  if (!s->implicit_tls)
    return;
  rc = twist_connection_start_tls (ep->conn, s->easy->url->host,
                                   s->easy->verifypeer, NULL, 0,
                                   s->easy->cainfo, s->easy->sslcert,
                                   s->easy->sslkey);
  if (rc != TWIST_OK)
    smtp_complete (s, rc);
}

static size_t
smtp_on_recv (struct twist_endpoint *ep, const uint8_t *data, size_t len)
{
  struct twist_smtp *s = ep->user_data;

  s->ep = ep;
  return twist_smtp_receive (s, data, len);
}

static void
smtp_disconnected (struct twist_endpoint *ep, int error)
{
  struct twist_smtp *s = ep->user_data;

  if (!s->finished)
    smtp_complete (s, error != TWIST_OK ? error : TWIST_ERR_CLOSED);
}

static void
smtp_error (struct twist_endpoint *ep, int error)
{
  struct twist_smtp *s = ep->user_data;

  if (!s->finished && error != TWIST_OK && error != TWIST_ERR_CLOSED)
    smtp_complete (s, error);
}

static const struct twist_protocol_handler smtp_handler = {
  smtp_connected,
  smtp_on_recv,
  smtp_disconnected,
  NULL,
  smtp_error,
  NULL,
  NULL
};

void
twist_smtp_free (void *p)
{
  struct twist_smtp *s = p;

  if (s == NULL)
    return;
  twist_mail_sasl_close (&s->sasl);
  twist_mail_link_close (&s->link);
  free (s);
}

struct twist_smtp *
twist_smtp_new (struct twist_easy *easy, int live)
{
  struct twist_smtp *s;

  if (easy == NULL || easy->url == NULL)
    return NULL;
  s = calloc (1, sizeof *s);
  if (s == NULL)
    return NULL;
  (void) live;
  s->easy = easy;
  s->implicit_tls = easy->url->scheme != NULL
                    && strcmp (easy->url->scheme, "smtps") == 0;
  twist_mail_sasl_init (&s->sasl);
  easy->xfer = s;
  easy->xfer_free = twist_smtp_free;
  return s;
}

int
twist_smtp_attach (struct twist_easy *easy)
{
  struct twist_smtp *s;
  int rc;

  if (easy == NULL || easy->url == NULL || easy->loop == NULL)
    return TWIST_ERR_INVAL;
  s = twist_smtp_new (easy, 1);
  if (s == NULL)
    return TWIST_ERR_NOMEM;
  rc = twist_mail_link_open (&s->link, easy, &smtp_handler, s, smtp_fail);
  if (rc != TWIST_OK)
    smtp_complete (s, rc);
  return easy->done ? easy->result : TWIST_OK;
}
