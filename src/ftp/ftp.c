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

#include <arpa/inet.h>
#include <ctype.h>
#include <netinet/in.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

/* RFC 959 §4.2 reply lines.  A partial line is not copied: receive
   returns the offset of that tail and the connection keeps it.  The
   only state carried across chunks is the open multiline code.  */

#define FTP_LINE_MAX 4096

enum
{
  FR_READY = 0,
  FR_CONT,
  FR_ERROR
};

struct twist_ftp_parser
{
  struct twist_ftp_events ev;
  int state;
  int cont_code;
};

enum
{
  FTP_GREET = 0,
  FTP_USER,
  FTP_PASS,
  FTP_TYPE,
  FTP_EPSV,
  FTP_PASV,
  FTP_DIAL,
  FTP_RETR,
  FTP_WAIT
};

struct twist_ftp
{
  struct twist_easy *easy;
  struct twist_ftp_parser *parser;
  struct twist_connection *ctrl;
  struct twist_connection *data;
  struct twist_proxy *proxy;
  struct twist_endpoint *ep;
  struct twist_timer *timer;
  struct twist_dns_addr peer;
  struct twist_dns_addr data_addr;
  char *dial_host;
  int dial_port;
  int live;
  int implicit_tls;
  int state;
  int finished;
  int list;
  int retr_sent;
  int ctrl_done;
  int data_eof;
  int data_port;
  char data_host[64];
  char arg[1024];
  char cmd[512];
};

static void ftp_complete (struct twist_ftp *f, int err);
static void ftp_begin (struct twist_ftp *f);
static int ftp_send (struct twist_ftp *f, const char *fmt, ...);
static int ftp_send_transfer (struct twist_ftp *f);

static void
parser_fail (struct twist_ftp_parser *p, int err)
{
  if (p->state == FR_ERROR)
    return;
  p->state = FR_ERROR;
  if (p->ev.failure != NULL)
    p->ev.failure (p->ev.user, err);
}

static int
parse_code (const uint8_t *line, size_t n, int *code, int *dash,
            const uint8_t **text, size_t *text_len)
{
  if (n < 3
      || !isdigit ((unsigned char) line[0])
      || !isdigit ((unsigned char) line[1])
      || !isdigit ((unsigned char) line[2]))
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
emit_line (struct twist_ftp_parser *p, int code, int final,
           const uint8_t *text, size_t text_len)
{
  if (p->ev.reply != NULL)
    p->ev.reply (p->ev.user, code, final, (const char *) text, text_len);
}

static void
take_line (struct twist_ftp_parser *p, const uint8_t *line, size_t n)
{
  int code = 0;
  int dash = 0;
  const uint8_t *text = line;
  size_t text_len = n;
  int parsed;
  int final;

  if (n == 0)
    return;
  parsed = parse_code (line, n, &code, &dash, &text, &text_len);
  if (p->state == FR_CONT)
    {
      if (parsed && code == p->cont_code && !dash)
        {
          final = 1;
          p->state = FR_READY;
          p->cont_code = 0;
        }
      else if (parsed && code == p->cont_code && dash)
        final = 0;
      else
        {
          code = p->cont_code;
          text = line;
          text_len = n;
          final = 0;
        }
    }
  else if (!parsed)
    {
      parser_fail (p, TWIST_ERR_PROTOCOL);
      return;
    }
  else if (dash)
    {
      p->state = FR_CONT;
      p->cont_code = code;
      final = 0;
    }
  else
    final = 1;
  emit_line (p, code, final, text, text_len);
}

struct twist_ftp_parser *
twist_ftp_parser_new (const struct twist_ftp_events *ev)
{
  struct twist_ftp_parser *p = calloc (1, sizeof *p);

  if (p == NULL)
    return NULL;
  if (ev != NULL)
    p->ev = *ev;
  return p;
}

void
twist_ftp_parser_free (struct twist_ftp_parser *p)
{
  free (p);
}

size_t
twist_ftp_parser_receive (struct twist_ftp_parser *p, const uint8_t *data,
                          size_t len)
{
  size_t off = 0;

  if (p == NULL || data == NULL)
    return 0;
  if (p->state == FR_ERROR)
    return len;
  while (off < len && p->state != FR_ERROR)
    {
      size_t i;
      int saw_lf = 0;

      for (i = off; i < len; i++)
        {
          if (data[i] == '\n')
            {
              saw_lf = 1;
              break;
            }
          if (i - off >= FTP_LINE_MAX)
            {
              parser_fail (p, TWIST_ERR_PROTOCOL);
              return len;
            }
        }
      if (!saw_lf)
        {
          if (len - off > FTP_LINE_MAX)
            {
              parser_fail (p, TWIST_ERR_PROTOCOL);
              return len;
            }
          return off;
        }
      {
        size_t end = i;
        if (end > off && data[end - 1] == '\r')
          end--;
        take_line (p, data + off, end - off);
        off = i + 1;
      }
    }
  return off;
}

static const char *
find_byte (const char *s, size_t n, char c)
{
  size_t i;

  for (i = 0; i < n; i++)
    if (s[i] == c)
      return s + i;
  return NULL;
}

int
twist_ftp_pasv (const char *text, size_t len, char *host, size_t hostcap,
                int *port)
{
  const char *s;
  const char *end;
  int nums[6];
  int i;

  if (text == NULL || host == NULL || port == NULL || hostcap < 16)
    return TWIST_ERR_INVAL;
  s = find_byte (text, len, '(');
  if (s == NULL)
    return TWIST_ERR_PROTOCOL;
  s++;
  end = text + len;
  for (i = 0; i < 6; i++)
    {
      long v = 0;

      if (s >= end || *s < '0' || *s > '9')
        return TWIST_ERR_PROTOCOL;
      while (s < end && *s >= '0' && *s <= '9')
        {
          v = v * 10 + (*s - '0');
          if (v > 255)
            return TWIST_ERR_PROTOCOL;
          s++;
        }
      nums[i] = (int) v;
      if (i < 5)
        {
          if (s >= end || *s != ',')
            return TWIST_ERR_PROTOCOL;
          s++;
        }
    }
  if (nums[4] * 256 + nums[5] <= 0 || nums[4] * 256 + nums[5] > 65535)
    return TWIST_ERR_PROTOCOL;
  *port = nums[4] * 256 + nums[5];
  snprintf (host, hostcap, "%d.%d.%d.%d", nums[0], nums[1], nums[2], nums[3]);
  return TWIST_OK;
}

int
twist_ftp_data_addr (const struct twist_dns_addr *peer, int port,
                     struct twist_dns_addr *out)
{
  if (peer == NULL || out == NULL || peer->family == 0 || port <= 0
      || port > 65535)
    return TWIST_ERR_INVAL;
  *out = *peer;
  return TWIST_OK;
}

int
twist_ftp_epsv (const char *text, size_t len, int *port)
{
  const char *p;
  const char *s;
  const char *limit;
  const char *start;
  char d;
  int field;

  if (text == NULL || port == NULL)
    return TWIST_ERR_INVAL;
  p = find_byte (text, len, '(');
  if (p == NULL || (size_t) (p - text) + 2 > len)
    return TWIST_ERR_PROTOCOL;
  d = p[1];
  s = p + 2;
  start = s;
  limit = text + len;
  field = 0;
  for (; s < limit; s++)
    {
      if (*s != d)
        continue;
      if (field == 2)
        {
          long v = 0;
          const char *q;

          if (start == s)
            return TWIST_ERR_PROTOCOL;
          for (q = start; q < s; q++)
            {
              if (*q < '0' || *q > '9')
                return TWIST_ERR_PROTOCOL;
              v = v * 10 + (*q - '0');
              if (v > 65535)
                return TWIST_ERR_PROTOCOL;
            }
          if (v <= 0)
            return TWIST_ERR_PROTOCOL;
          *port = (int) v;
          return TWIST_OK;
        }
      field++;
      start = s + 1;
    }
  return TWIST_ERR_PROTOCOL;
}

static void
ftp_complete (struct twist_ftp *f, int err)
{
  if (f == NULL || f->finished)
    return;
  f->finished = 1;
  if (f->timer != NULL)
    {
      twist_timer_cancel (f->timer);
      f->timer = NULL;
    }
  twist_easy_finish (f->easy, err);
}

static int
bad_token (const char *s)
{
  return s != NULL && (strchr (s, '\r') != NULL || strchr (s, '\n') != NULL);
}

static const char *
ftp_user (struct twist_ftp *f)
{
  if (f->easy->username != NULL && f->easy->username[0] != 0)
    return f->easy->username;
  if (f->easy->url->user != NULL && f->easy->url->user[0] != 0)
    return f->easy->url->user;
  return "anonymous";
}

static const char *
ftp_pass (struct twist_ftp *f)
{
  if (f->easy->password != NULL && f->easy->password[0] != 0)
    return f->easy->password;
  if (f->easy->url->password != NULL && f->easy->url->password[0] != 0)
    return f->easy->url->password;
  return "twist@";
}

static void
prepare_arg (struct twist_ftp *f)
{
  const char *path = f->easy->url->path;
  size_t n;
  int dir;

  if (path == NULL)
    path = "";
  dir = path[0] == 0 || strcmp (path, "/") == 0
        || path[strlen (path) - 1] == '/' || f->easy->nobody;
  if (path[0] == '/')
    path++;
  n = strlen (path);
  while (n > 0 && path[n - 1] == '/')
    n--;
  if (n >= sizeof f->arg)
    n = sizeof f->arg - 1;
  memcpy (f->arg, path, n);
  f->arg[n] = 0;
  f->list = dir;
}

static int
ftp_send (struct twist_ftp *f, const char *fmt, ...)
{
  va_list ap;
  int n;

  va_start (ap, fmt);
  n = vsnprintf (f->cmd, sizeof f->cmd, fmt, ap);
  va_end (ap);
  if (n < 0 || (size_t) n >= sizeof f->cmd)
    return TWIST_ERR_PROTOCOL;
  if (f->ep == NULL)
    return TWIST_OK;
  return twist_endpoint_send (f->ep, (const uint8_t *) f->cmd, (size_t) n);
}

static int
ftp_send_transfer (struct twist_ftp *f)
{
  if (f->retr_sent)
    return TWIST_OK;
  if (bad_token (f->arg))
    return TWIST_ERR_PROTOCOL;
  f->retr_sent = 1;
  f->state = FTP_RETR;
  if (f->list)
    {
      if (f->arg[0] == 0)
        return ftp_send (f, "LIST\r\n");
      return ftp_send (f, "LIST %s\r\n", f->arg);
    }
  if (f->arg[0] == 0)
    return TWIST_ERR_URL;
  return ftp_send (f, "RETR %s\r\n", f->arg);
}

static int
dial_tcp (struct twist_ftp *f, struct twist_connection **slot,
          const struct twist_protocol_handler *handler, void *user,
          const struct twist_dns_addr *addr, int port)
{
  struct twist_connection *c;
  struct sockaddr_in sin;
  struct sockaddr_in6 sin6;
  const void *sa;
  size_t salen;
  int rc;

  c = twist_connection_new (f->easy->loop);
  if (c == NULL)
    return TWIST_ERR_NOMEM;
  *slot = c;
  twist_connection_endpoint (c)->user_data = user;
  twist_connection_set_handler (c, handler);
  if (addr->family == 6)
    {
      memset (&sin6, 0, sizeof sin6);
      sin6.sin6_family = AF_INET6;
      memcpy (&sin6.sin6_addr, addr->addr, 16);
      sin6.sin6_scope_id = addr->scope_id;
      sin6.sin6_port = htons ((uint16_t) port);
      sa = &sin6;
      salen = sizeof sin6;
    }
  else
    {
      memset (&sin, 0, sizeof sin);
      sin.sin_family = AF_INET;
      memcpy (&sin.sin_addr, addr->addr, 4);
      sin.sin_port = htons ((uint16_t) port);
      sa = &sin;
      salen = sizeof sin;
    }
  rc = twist_connection_connect (c, sa, salen,
                                 (uint64_t) f->easy->connect_timeout_ms);
  return rc;
}

static const struct twist_protocol_handler ftp_ctrl_handler;
static const struct twist_protocol_handler ftp_data_handler;

static void
dial_data (struct twist_ftp *f)
{
  int rc;

  f->state = FTP_DIAL;
  rc = dial_tcp (f, &f->data, &ftp_data_handler, f, &f->data_addr,
                 f->data_port);
  if (rc != TWIST_OK)
    ftp_complete (f, rc);
}

static void
open_data (struct twist_ftp *f, const char *text, size_t len, int epsv)
{
  int port = 0;
  int rc;

  if (epsv)
    rc = twist_ftp_epsv (text, len, &port);
  else
    rc = twist_ftp_pasv (text, len, f->data_host, sizeof f->data_host, &port);
  if (rc != TWIST_OK)
    {
      ftp_complete (f, rc);
      return;
    }
  f->data_port = port;
  if (epsv)
    {
      snprintf (f->data_host, sizeof f->data_host, "%s", f->peer.text);
      f->data_addr = f->peer;
    }
  else if (twist_ftp_data_addr (&f->peer, port, &f->data_addr) != TWIST_OK)
    {
      ftp_complete (f, TWIST_ERR_RESOLVE);
      return;
    }
  else
    snprintf (f->data_host, sizeof f->data_host, "%s", f->data_addr.text);
  if (!f->live)
    {
      if (ftp_send_transfer (f) != TWIST_OK)
        ftp_complete (f, TWIST_ERR_PROTOCOL);
      return;
    }
  dial_data (f);
}

static void
ftp_on_reply (void *user, int code, int final, const char *text, size_t len)
{
  struct twist_ftp *f = user;
  const char *user_name;
  const char *pass;

  if (!final || f->finished)
    return;
  f->easy->http_code = code;
  switch (f->state)
    {
    case FTP_GREET:
      if (code == 120)
        return;
      if (code != 220)
        {
          ftp_complete (f, TWIST_ERR_PROTOCOL);
          return;
        }
      user_name = ftp_user (f);
      if (bad_token (user_name))
        {
          ftp_complete (f, TWIST_ERR_PROTOCOL);
          return;
        }
      f->state = FTP_USER;
      if (ftp_send (f, "USER %s\r\n", user_name) != TWIST_OK)
        ftp_complete (f, TWIST_ERR_PROTOCOL);
      return;
    case FTP_USER:
      if (code == 230)
        {
          f->state = FTP_TYPE;
          if (ftp_send (f, "TYPE I\r\n") != TWIST_OK)
            ftp_complete (f, TWIST_ERR_PROTOCOL);
          return;
        }
      if (code != 331)
        {
          ftp_complete (f, TWIST_ERR_AUTH);
          return;
        }
      pass = ftp_pass (f);
      if (bad_token (pass))
        {
          ftp_complete (f, TWIST_ERR_PROTOCOL);
          return;
        }
      f->state = FTP_PASS;
      if (ftp_send (f, "PASS %s\r\n", pass) != TWIST_OK)
        ftp_complete (f, TWIST_ERR_PROTOCOL);
      return;
    case FTP_PASS:
      if (code / 100 != 2)
        {
          ftp_complete (f, TWIST_ERR_AUTH);
          return;
        }
      f->state = FTP_TYPE;
      if (ftp_send (f, "TYPE I\r\n") != TWIST_OK)
        ftp_complete (f, TWIST_ERR_PROTOCOL);
      return;
    case FTP_TYPE:
      if (code / 100 != 2)
        {
          ftp_complete (f, TWIST_ERR_PROTOCOL);
          return;
        }
      f->state = FTP_EPSV;
      if (ftp_send (f, "EPSV\r\n") != TWIST_OK)
        ftp_complete (f, TWIST_ERR_PROTOCOL);
      return;
    case FTP_EPSV:
      if (code >= 400)
        {
          f->state = FTP_PASV;
          if (ftp_send (f, "PASV\r\n") != TWIST_OK)
            ftp_complete (f, TWIST_ERR_PROTOCOL);
          return;
        }
      if (code != 229)
        {
          ftp_complete (f, TWIST_ERR_PROTOCOL);
          return;
        }
      open_data (f, text, len, 1);
      return;
    case FTP_PASV:
      if (code != 227)
        {
          ftp_complete (f, TWIST_ERR_PROTOCOL);
          return;
        }
      open_data (f, text, len, 0);
      return;
    case FTP_RETR:
    case FTP_WAIT:
      if (code == 125 || code == 150)
        {
          f->state = FTP_WAIT;
          return;
        }
      if (code == 226 || code == 250)
        {
          f->ctrl_done = 1;
          f->state = FTP_WAIT;
          if (f->data_eof)
            ftp_complete (f, TWIST_OK);
          return;
        }
      if (code >= 400)
        ftp_complete (f, TWIST_ERR_PROTOCOL);
      return;
    default:
      return;
    }
}

static void
ftp_on_fail (void *user, int err)
{
  ftp_complete (user, err);
}

static void
on_timeout (void *user)
{
  struct twist_ftp *f = user;

  f->timer = NULL;
  ftp_complete (f, TWIST_ERR_TIMEOUT);
}

static void
ftp_connected (struct twist_endpoint *ep)
{
  struct twist_ftp *f = ep->user_data;
  int rc;

  f->ep = ep;
  if (!f->implicit_tls)
    return;
  rc = twist_connection_start_tls (ep->conn, f->easy->url->host,
                                   f->easy->verifypeer, NULL, 0,
                                   f->easy->cainfo, f->easy->sslcert,
                                   f->easy->sslkey);
  if (rc != TWIST_OK)
    ftp_complete (f, rc);
}

static size_t
ftp_receive (struct twist_endpoint *ep, const uint8_t *data, size_t len)
{
  struct twist_ftp *f = ep->user_data;

  f->ep = ep;
  return twist_ftp_receive (f, data, len);
}

static void
ftp_disconnected (struct twist_endpoint *ep, int error)
{
  struct twist_ftp *f = ep->user_data;

  if (f->finished)
    return;
  if (f->ctrl_done && f->data_eof)
    ftp_complete (f, TWIST_OK);
  else
    ftp_complete (f, error != TWIST_OK ? error : TWIST_ERR_CLOSED);
}

static void
ftp_error (struct twist_endpoint *ep, int error)
{
  struct twist_ftp *f = ep->user_data;

  if (!f->finished && error != TWIST_OK && error != TWIST_ERR_CLOSED)
    ftp_complete (f, error);
}

static void
ftp_data_connected (struct twist_endpoint *ep)
{
  struct twist_ftp *f = ep->user_data;

  if (f->finished)
    return;
  if (ftp_send_transfer (f) != TWIST_OK)
    ftp_complete (f, TWIST_ERR_PROTOCOL);
}

static size_t
ftp_data_receive (struct twist_endpoint *ep, const uint8_t *data, size_t len)
{
  return twist_ftp_data (ep->user_data, data, len);
}

static void
ftp_data_disconnected (struct twist_endpoint *ep, int error)
{
  struct twist_ftp *f = ep->user_data;

  if (f->finished)
    return;
  if (error != TWIST_OK && error != TWIST_ERR_CLOSED && !f->retr_sent)
    ftp_complete (f, error);
  else
    twist_ftp_data_eof (f);
}

static void
ftp_data_error (struct twist_endpoint *ep, int error)
{
  struct twist_ftp *f = ep->user_data;

  if (!f->finished && error != TWIST_OK && error != TWIST_ERR_CLOSED
      && !f->retr_sent)
    ftp_complete (f, error);
}

static const struct twist_protocol_handler ftp_ctrl_handler = {
  ftp_connected,
  ftp_receive,
  ftp_disconnected,
  NULL,
  ftp_error,
  NULL,
  NULL
};

static const struct twist_protocol_handler ftp_data_handler = {
  ftp_data_connected,
  ftp_data_receive,
  ftp_data_disconnected,
  NULL,
  ftp_data_error,
  NULL,
  NULL
};

size_t
twist_ftp_receive (struct twist_ftp *f, const uint8_t *data, size_t len)
{
  if (f == NULL || f->parser == NULL)
    return len;
  if (f->finished)
    return len;
  return twist_ftp_parser_receive (f->parser, data, len);
}

size_t
twist_ftp_data (struct twist_ftp *f, const uint8_t *data, size_t len)
{
  size_t accepted;

  if (f == NULL || f->finished)
    return len;
  if (len == 0)
    return 0;
  if (f->easy->write_cb != NULL)
    {
      accepted = twist_write_bytes (f->easy->write_cb, f->easy->write_data,
                                    data, len);
      if (accepted < len)
        {
          f->easy->size_download += accepted;
          ftp_complete (f, TWIST_ERR_ABORTED);
          return len;
        }
    }
  f->easy->size_download += len;
  return len;
}

void
twist_ftp_data_eof (struct twist_ftp *f)
{
  if (f == NULL || f->finished)
    return;
  f->data_eof = 1;
  if (f->ctrl_done)
    ftp_complete (f, TWIST_OK);
}

const char *
twist_ftp_command (const struct twist_ftp *f)
{
  return f != NULL ? f->cmd : "";
}

int
twist_ftp_data_port (const struct twist_ftp *f)
{
  return f != NULL ? f->data_port : 0;
}

void
twist_ftp_set_peer (struct twist_ftp *f, const struct twist_dns_addr *peer)
{
  if (f != NULL && peer != NULL)
    f->peer = *peer;
}

const char *
twist_ftp_data_host (const struct twist_ftp *f)
{
  return f != NULL ? f->data_host : "";
}

static void
dial_control (struct twist_ftp *f)
{
  void *user = f;
  const struct twist_protocol_handler *handler = &ftp_ctrl_handler;
  int rc;

  if (f->proxy != NULL)
    {
      user = f->proxy;
      handler = twist_proxy_handler (f->proxy);
      twist_proxy_set_user (f->proxy, f);
    }
  rc = dial_tcp (f, &f->ctrl, handler, user, &f->peer, f->dial_port);
  if (rc != TWIST_OK)
    ftp_complete (f, rc);
}

static void
on_resolved (void *user, int err, const struct twist_dns_addr *addr)
{
  struct twist_ftp *f = user;

  if (f->finished)
    return;
  if (err != TWIST_OK || addr == NULL)
    {
      ftp_complete (f, err != TWIST_OK ? err : TWIST_ERR_RESOLVE);
      return;
    }
  f->peer = *addr;
  dial_control (f);
}

static void
ftp_begin (struct twist_ftp *f)
{
  struct twist_easy *easy = f->easy;
  struct twist_url *url = easy->url;
  const char *dial;
  int kind = TWIST_PROXY_NONE;
  char *phost = NULL, *puser = NULL, *ppass = NULL;
  int pport = 0;

  f->dial_port = url->port;
  dial = url->host;
  if (easy->proxy != NULL)
    {
      if (twist_proxy_parse (easy->proxy, &kind, &phost, &pport, &puser,
                             &ppass) != TWIST_OK)
        {
          ftp_complete (f, TWIST_ERR_URL);
          return;
        }
      f->proxy = twist_proxy_new (kind, phost, pport, &ftp_ctrl_handler);
      if (f->proxy == NULL)
        {
          free (phost);
          ftp_complete (f, TWIST_ERR_NOMEM);
          return;
        }
      twist_proxy_set_target (f->proxy, url->host, url->port);
      twist_proxy_configure (f->proxy, easy, puser, ppass);
      dial = phost;
      f->dial_port = pport;
    }
  f->dial_host = twist_strdup (dial != NULL ? dial : "");
  free (phost);
  free (puser);
  if (ppass != NULL)
    {
      memset (ppass, 0, strlen (ppass));
      free (ppass);
    }
  if (f->dial_host == NULL)
    {
      ftp_complete (f, TWIST_ERR_NOMEM);
      return;
    }
  if (easy->timeout_ms > 0)
    twist_loop_schedule (easy->loop,
                         twist_loop_now (easy->loop) + (uint64_t) easy->timeout_ms,
                         on_timeout, f, &f->timer);
  {
    int rc = twist_dns_resolve_easy (easy, f->dial_host, on_resolved, f);

    if (rc != TWIST_OK)
      ftp_complete (f, rc);
  }
}

void
twist_ftp_free (void *p)
{
  struct twist_ftp *f = p;

  if (f == NULL)
    return;
  if (f->timer != NULL)
    twist_timer_cancel (f->timer);
  twist_connection_free (f->ctrl);
  twist_connection_free (f->data);
  twist_proxy_free (f->proxy);
  twist_ftp_parser_free (f->parser);
  free (f->dial_host);
  free (f);
}

struct twist_ftp *
twist_ftp_new (struct twist_easy *easy, int live)
{
  struct twist_ftp *f;
  struct twist_ftp_events ev;

  if (easy == NULL || easy->url == NULL)
    return NULL;
  f = calloc (1, sizeof *f);
  if (f == NULL)
    return NULL;
  f->easy = easy;
  f->live = live;
  f->implicit_tls = easy->url->scheme != NULL
                    && strcmp (easy->url->scheme, "ftps") == 0;
  prepare_arg (f);
  memset (&ev, 0, sizeof ev);
  ev.user = f;
  ev.reply = ftp_on_reply;
  ev.failure = ftp_on_fail;
  f->parser = twist_ftp_parser_new (&ev);
  if (f->parser == NULL)
    {
      free (f);
      return NULL;
    }
  easy->xfer = f;
  easy->xfer_free = twist_ftp_free;
  return f;
}

int
twist_ftp_attach (struct twist_easy *easy)
{
  struct twist_ftp *f;

  if (easy == NULL || easy->url == NULL || easy->loop == NULL)
    return TWIST_ERR_INVAL;
  f = twist_ftp_new (easy, 1);
  if (f == NULL)
    return TWIST_ERR_NOMEM;
  ftp_begin (f);
  if (easy->done)
    return easy->result;
  return TWIST_OK;
}
