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

#include <ctype.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

/* POP3 client: CAPA, SASL AUTH or USER/PASS, then RETR or LIST.
   The message is unstuffed and written as it arrives.  */

enum
{
  P_GREET = 0,
  P_CAPA,
  P_AUTH,
  P_USER,
  P_PASS,
  P_XFER,
  P_QUIT,
  P_STLS,
  P_TLSWAIT
};

struct twist_pop3
{
  struct twist_transfer *transfer;
  struct twist_mail_link link;
  struct twist_mail_sasl sasl;
  struct twist_dotin dot;
  struct twist_endpoint *ep;
  int implicit_tls;
  /* TWISTOPT_USE_SSL, for a scheme that is not TLS already.  TLS_DONE: the
     connection was upgraded.  STLS_ADV: the server said it can, in its answer
     to CAPA.  */
  int use_ssl;
  int tls_done;
  int stls_adv;
  int state;
  int finished;
  int message;
  int in_body;
  char auth_adv[80];
  char cmd[512];
};

static void pop3_complete (struct twist_pop3 *p, int err);

static int
bad_token (const char *s)
{
  return s != NULL && (strchr (s, '\r') != NULL || strchr (s, '\n') != NULL);
}

static void
pop3_complete (struct twist_pop3 *p, int err)
{
  if (p == NULL || p->finished)
    return;
  p->finished = 1;
  twist_transfer_finish (p->transfer, err);
}

static int pop3_send (struct twist_pop3 *p, const char *fmt, ...)
  __attribute__ ((format (printf, 2, 3)));

static int
pop3_send (struct twist_pop3 *p, const char *fmt, ...)
{
  va_list ap;
  int n;

  va_start (ap, fmt);
  n = vsnprintf (p->cmd, sizeof p->cmd, fmt, ap);
  va_end (ap);
  if (n < 0 || (size_t) n >= sizeof p->cmd)
    return TWIST_ERR_PROTOCOL;
  if (p->ep == NULL)
    return TWIST_OK;
  return twist_endpoint_send (p->ep, (const uint8_t *) p->cmd, (size_t) n);
}

static int
ok_line (const uint8_t *line, size_t n)
{
  return n >= 3 && line[0] == '+' && (line[1] == 'O' || line[1] == 'o')
         && (line[2] == 'K' || line[2] == 'k');
}

static int
err_line (const uint8_t *line, size_t n)
{
  return n >= 4 && line[0] == '-' && strncasecmp ((const char *) line, "-ERR", 4) == 0;
}

static int
cont_line (const uint8_t *line, size_t n)
{
  return n >= 1 && line[0] == '+';
}

static int
message_number (const struct twist_pop3 *p)
{
  const char *path;
  char *end = NULL;
  long v;

  if (p->transfer->url == NULL || p->transfer->url->path == NULL)
    return 0;
  path = p->transfer->url->path;
  if (path[0] == '/')
    path++;
  if (path[0] == 0)
    return 0;
  v = strtol (path, &end, 10);
  if (end == path || v < 1 || v > 0x7fffffff)
    return -1;
  return (int) v;
}

static int
body_sink (void *user, const uint8_t *data, size_t len)
{
  struct twist_pop3 *p = user;
  struct twist_transfer *transfer = p->transfer;
  size_t n;

  if (transfer->write_cb == NULL || len == 0)
    {
      twist_transfer_downloaded (transfer, len);
      return 0;
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
        n = transfer->write_cb (buf, 1, chunk, transfer->write_data);
        if (n < chunk)
          return 1;
        off += chunk;
      }
  }
  twist_transfer_downloaded (transfer, len);
  return 0;
}

static int
start_transfer (struct twist_pop3 *p)
{
  int msg = message_number (p);

  /* The connection is up: what comes is the message.  */
  twist_mail_link_phase_end (&p->link);
  if (msg < 0)
    return TWIST_ERR_URL;
  p->message = msg;
  p->state = P_XFER;
  p->in_body = 0;
  twist_dotin_init (&p->dot);
  if (msg == 0)
    return pop3_send (p, "LIST\r\n");
  return pop3_send (p, "RETR %d\r\n", msg);
}

static int
start_auth (struct twist_pop3 *p)
{
  const char *user = twist_mail_user (p->transfer);
  const char *bearer = p->transfer->bearer;
  char *b64 = NULL;
  int initial = 0;
  int rc;

  if ((user == NULL || user[0] == 0)
      && (bearer == NULL || bearer[0] == 0))
    return start_transfer (p);
  if (bad_token (user) || bad_token (twist_mail_pass (p->transfer)))
    return TWIST_ERR_PROTOCOL;
  if (p->auth_adv[0] == 0 && bearer == NULL)
    {
      p->state = P_USER;
      return pop3_send (p, "USER %s\r\n", user);
    }
  rc = twist_mail_sasl_start (&p->sasl, p->transfer,
                              p->auth_adv[0] != 0 ? p->auth_adv : NULL,
                              &b64, &initial);
  if (rc != TWIST_OK)
    return rc;
  p->state = P_AUTH;
  if (initial && b64 != NULL)
    rc = pop3_send (p, "AUTH %s %s\r\n", twist_sasl_name (p->sasl.mech), b64);
  else
    rc = pop3_send (p, "AUTH %s\r\n", twist_sasl_name (p->sasl.mech));
  free (b64);
  return rc;
}

/* The capabilities have been answered, or CAPA was.  If TLS was asked for and
   the connection has not been upgraded, this is the place: before the login,
   so that the password is not sent where it can be read.  A server that has
   no CAPA cannot be asked whether it offers STLS, which counts as not
   offering it.  */
static int
after_capa (struct twist_pop3 *p)
{
  if (p->use_ssl != TWIST_USE_SSL_NONE && !p->tls_done)
    {
      if (p->stls_adv)
        {
          p->state = P_STLS;
          return pop3_send (p, "STLS\r\n");
        }
      if (p->use_ssl == TWIST_USE_SSL_ALL)
        return twist_transfer_use_ssl_failed (p->transfer,
                                              _("the server does not offer "
                                                "STLS"));
    }
  return start_auth (p);
}

/* The server has said yes to STLS: the handshake starts, and nothing is sent
   until it is done.  A test with no connection has none to start.  */
static int
begin_tls (struct twist_pop3 *p)
{
  p->state = P_TLSWAIT;
  if (p->ep == NULL)
    return TWIST_OK;
  return twist_connection_start_tls (p->ep->conn, p->transfer->url->host,
                                     p->transfer->verifypeer, NULL, 0,
                                     p->transfer->cainfo, p->transfer->capath,
                                     p->transfer->sslcert,
                                     p->transfer->sslkey);
}

static void
note_sasl (struct twist_pop3 *p, const uint8_t *line, size_t n)
{
  if (n == 4 && strncasecmp ((const char *) line, "STLS", 4) == 0)
    p->stls_adv = 1;
  if (n >= 5 && strncasecmp ((const char *) line, "SASL ", 5) == 0)
    {
      size_t c = n - 5;

      if (c >= sizeof p->auth_adv)
        c = sizeof p->auth_adv - 1;
      memcpy (p->auth_adv, line + 5, c);
      p->auth_adv[c] = 0;
    }
}

static void
on_status (struct twist_pop3 *p, const uint8_t *line, size_t n)
{
  int rc;

  if (p->state == P_CAPA && err_line (line, n))
    {
      /* No CAPA: no way to know that STLS is there.  */
      rc = after_capa (p);
      if (rc == TWIST_ERR_USE_SSL)
        pop3_complete (p, rc);
      else if (rc != TWIST_OK)
        pop3_complete (p, TWIST_ERR_AUTH);
      return;
    }
  if (p->state == P_STLS && err_line (line, n))
    {
      /* Refused: required, that is the end; wanted, go on as it is.  */
      if (p->use_ssl == TWIST_USE_SSL_ALL)
        {
          pop3_complete (p, twist_transfer_use_ssl_failed
                         (p->transfer, _("the server refused STLS")));
          return;
        }
      rc = start_auth (p);
      if (rc != TWIST_OK)
        pop3_complete (p, rc);
      return;
    }
  if (err_line (line, n))
    {
      pop3_complete (p, p->state == P_AUTH || p->state == P_USER
                     || p->state == P_PASS ? TWIST_ERR_AUTH : TWIST_ERR_PROTOCOL);
      return;
    }
  switch (p->state)
    {
    case P_GREET:
      if (!ok_line (line, n))
        {
          pop3_complete (p, TWIST_ERR_PROTOCOL);
          return;
        }
      p->state = P_CAPA;
      p->stls_adv = 0;
      p->auth_adv[0] = 0;
      rc = pop3_send (p, "CAPA\r\n");
      break;
    case P_CAPA:
      if (n == 1 && line[0] == '.')
        {
          rc = after_capa (p);
          break;
        }
      if (n == 4 && strncasecmp ((const char *) line, "STLS", 4) == 0)
        {
          p->stls_adv = 1;
          return;
        }
      if (ok_line (line, n))
        return;
      note_sasl (p, line, n);
      return;
    case P_STLS:
      rc = begin_tls (p);
      break;
    case P_AUTH:
      if (cont_line (line, n) && !ok_line (line, n))
        {
          char *b64 = NULL;

          rc = twist_mail_sasl_continue (&p->sasl, &b64);
          if (rc == TWIST_OK && b64 != NULL)
            rc = pop3_send (p, "%s\r\n", b64);
          free (b64);
          break;
        }
      if (!ok_line (line, n))
        {
          pop3_complete (p, TWIST_ERR_AUTH);
          return;
        }
      rc = start_transfer (p);
      break;
    case P_USER:
      if (!ok_line (line, n))
        {
          pop3_complete (p, TWIST_ERR_AUTH);
          return;
        }
      p->state = P_PASS;
      rc = pop3_send (p, "PASS %s\r\n", twist_mail_pass (p->transfer));
      break;
    case P_PASS:
      if (!ok_line (line, n))
        {
          pop3_complete (p, TWIST_ERR_AUTH);
          return;
        }
      rc = start_transfer (p);
      break;
    case P_XFER:
      if (!ok_line (line, n))
        {
          pop3_complete (p, TWIST_ERR_PROTOCOL);
          return;
        }
      p->in_body = 1;
      return;
    case P_QUIT:
      pop3_complete (p, ok_line (line, n) ? TWIST_OK : TWIST_ERR_PROTOCOL);
      return;
    default:
      return;
    }
  if (rc != TWIST_OK)
    pop3_complete (p, rc);
}

size_t
twist_pop3_receive (struct twist_pop3 *p, const uint8_t *data, size_t len)
{
  size_t off = 0;

  if (p == NULL || data == NULL)
    return 0;
  while (off < len && !p->finished)
    {
      if (p->in_body)
        {
          int done = 0;
          int err = TWIST_OK;
          size_t used = twist_dotin_pull (&p->dot, data + off, len - off,
                                          body_sink, p, &done, &err);

          off += used;
          if (err != TWIST_OK)
            {
              pop3_complete (p, err);
              return off;
            }
          if (done)
            {
              p->in_body = 0;
              p->state = P_QUIT;
              if (pop3_send (p, "QUIT\r\n") != TWIST_OK)
                pop3_complete (p, TWIST_ERR_PROTOCOL);
            }
          if (used == 0)
            return off;
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
            pop3_complete (p, err);
            return len;
          }
        if (used == 0)
          return off;
        on_status (p, line, line_len);
        off += used;
        /* A server that has agreed to start TLS says nothing more until the
           handshake is done.  Whatever else is in this buffer came in the
           clear, from whoever is on the path, and must not be taken for the
           encrypted session's.  */
        if (p->state == P_TLSWAIT && !p->finished && off < len)
          {
            pop3_complete (p, TWIST_ERR_PROTOCOL);
            return len;
          }
      }
    }
  return off;
}

const char *
twist_pop3_command (const struct twist_pop3 *pop3)
{
  return pop3 != NULL ? pop3->cmd : "";
}

static void
pop3_fail (void *user, int err)
{
  pop3_complete (user, err);
}

static void
pop3_connected (struct twist_endpoint *ep)
{
  struct twist_pop3 *p = ep->user_data;
  int rc;

  p->ep = ep;
  if (!p->implicit_tls)
    return;
  rc = twist_connection_start_tls (ep->conn, p->transfer->url->host,
                                   p->transfer->verifypeer, NULL, 0,
                                   p->transfer->cainfo, p->transfer->capath, p->transfer->sslcert,
                                   p->transfer->sslkey);
  if (rc != TWIST_OK)
    pop3_complete (p, rc);
}

/* The handshake is done, for pop3s as well as after STLS: only the second is
   waited for.  */
static void
pop3_security (struct twist_endpoint *ep, const char *alpn, size_t alpn_len)
{
  struct twist_pop3 *p = ep->user_data;

  (void) alpn;
  (void) alpn_len;
  p->ep = ep;
  twist_pop3_tls_done (p);
}

static size_t
pop3_on_recv (struct twist_endpoint *ep, const uint8_t *data, size_t len)
{
  struct twist_pop3 *p = ep->user_data;

  p->ep = ep;
  return twist_pop3_receive (p, data, len);
}

static void
pop3_disconnected (struct twist_endpoint *ep, int error)
{
  struct twist_pop3 *p = ep->user_data;

  if (!p->finished)
    pop3_complete (p, error != TWIST_OK ? error : TWIST_ERR_CLOSED);
}

static void
pop3_error (struct twist_endpoint *ep, int error)
{
  struct twist_pop3 *p = ep->user_data;

  if (!p->finished && error != TWIST_OK && error != TWIST_ERR_CLOSED)
    pop3_complete (p, error);
}

static const struct twist_protocol_handler pop3_handler = {
  pop3_connected,
  pop3_on_recv,
  pop3_disconnected,
  pop3_security,
  pop3_error,
  NULL,
  NULL
};

void
twist_pop3_free (void *pop)
{
  struct twist_pop3 *p = pop;

  if (p == NULL)
    return;
  twist_mail_sasl_close (&p->sasl);
  twist_mail_link_close (&p->link);
  free (p);
}

struct twist_pop3 *
twist_pop3_new (struct twist_transfer *transfer, int live)
{
  struct twist_pop3 *p;

  (void) live;
  if (transfer == NULL || transfer->url == NULL)
    return NULL;
  p = calloc (1, sizeof *p);
  if (p == NULL)
    return NULL;
  p->transfer = transfer;
  p->implicit_tls = transfer->url->scheme != NULL
                    && strcmp (transfer->url->scheme, "pop3s") == 0;
  p->use_ssl = p->implicit_tls ? TWIST_USE_SSL_NONE : transfer->use_ssl;
  twist_mail_sasl_init (&p->sasl);
  transfer->state = p;
  transfer->state_free = twist_pop3_free;
  return p;
}

int
twist_pop3_attach (struct twist_transfer *transfer)
{
  struct twist_pop3 *p;
  int rc;

  if (transfer == NULL || transfer->url == NULL || transfer->loop == NULL)
    return TWIST_ERR_INVAL;
  p = twist_pop3_new (transfer, 1);
  if (p == NULL)
    return TWIST_ERR_NOMEM;
  rc = twist_mail_link_open (&p->link, transfer, &pop3_handler, p, pop3_fail);
  if (rc != TWIST_OK)
    pop3_complete (p, rc);
  else
    /* Connected, through a proxy if there is one, greeted and logged in, in
       the time allowed for it.  */
    twist_mail_link_phase_begin (&p->link);
  return transfer->done ? transfer->result : TWIST_OK;
}

/* The handshake that followed STLS is done.  What the server said before is
   not to be trusted now, or kept: it was said in the clear.  The capabilities
   are asked for again, as RFC 2595 says.  */
void
twist_pop3_tls_done (struct twist_pop3 *p)
{
  if (p == NULL || p->finished || p->state != P_TLSWAIT)
    return;
  p->tls_done = 1;
  p->stls_adv = 0;
  p->auth_adv[0] = 0;
  p->state = P_CAPA;
  if (pop3_send (p, "CAPA\r\n") != TWIST_OK)
    pop3_complete (p, TWIST_ERR_PROTOCOL);
}
