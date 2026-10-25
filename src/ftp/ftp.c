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
#include "gettext.h"

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
  FTP_PBSZ,
  FTP_PROT,
  FTP_TYPE,
  FTP_EPSV,
  FTP_PASV,
  FTP_DIAL,
  FTP_RETR,
  FTP_WAIT,
  FTP_AUTHTLS,
  FTP_TLSWAIT,
  FTP_SIZE,
  FTP_REST
};

struct twist_ftp
{
  struct twist_transfer *transfer;
  struct twist_ftp_parser *parser;
  struct twist_connection *ctrl;
  struct twist_connection *data;
  struct twist_race *race;      /* The control connection, being made.  */
  struct twist_proxy *proxy;
  /* The data connection's own tunnel through the same proxy.  */
  struct twist_proxy *data_proxy;
  struct twist_endpoint *ep;
  struct twist_timer *timer;
  /* The time allowed to be connected and logged in.  */
  struct twist_phase phase;
  struct twist_dns_addr peer;
  struct twist_dns_addr data_addr;
  char *dial_host;
  int dial_port;
  int live;
  int implicit_tls;
  /* TWISTOPT_USE_SSL, for a scheme that is not TLS already.  CTRL_TLS: the
     control connection is encrypted, from the first byte (ftps) or since AUTH
     TLS, and so the data connection is to be too.  */
  int use_ssl;
  int ctrl_tls;
  /* The server has agreed to PROT P: the data connection runs TLS.  */
  int prot_p;
  /* The handshake on the data connection is done, and the server has been
     verified as for the control connection.  */
  int data_secure;
  int state;
  int finished;
  int list;
  int retr_sent;
  int ctrl_done;
  int data_eof;
  /* The size the server said it would send, in its 150 reply, or -1; and what
     has come.  */
  long long expect;
  long long received;
  /* An upload: STOR, or APPE if it adds to the file or resumes at RESUME
     (REST for a download); -1 asks the server for the size first.  PREPARED:
     the SIZE or the REST has been answered.  GOT_GO: the server said 150 and
     the data may go; UP_STARTED: it does.  */
  int upload;
  int append;
  long long resume;
  int prepared;
  int got_go;
  int up_started;
  struct twist_timer *close_timer;
  int data_port;
  char data_host[64];
  char arg[1024];
  char cmd[512];
};

static void ftp_complete (struct twist_ftp *f, int err);
static void ftp_finish_ok (struct twist_ftp *f);
static void ftp_begin (struct twist_ftp *f);
static int ftp_send (struct twist_ftp *f, const char *fmt, ...)
  __attribute__ ((format (printf, 2, 3)));
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

/* The size a server gives in its reply to RETR: "(1234 bytes)".  -1 if it
   gives none.  */
static long long
reply_size (const char *text, size_t len)
{
  size_t i;

  for (i = 0; i < len; i++)
    {
      long long n = 0;
      size_t j = i + 1;

      if (text[i] != '(' || j >= len || !isdigit ((unsigned char) text[j]))
        continue;
      while (j < len && isdigit ((unsigned char) text[j]) && n < (1LL << 55))
        n = n * 10 + (text[j++] - '0');
      if (j + 6 <= len && memcmp (text + j, " bytes", 6) == 0)
        return n;
    }
  return -1;
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
  twist_phase_end (&f->phase);
  twist_transfer_finish (f->transfer, err);
}

static int
bad_token (const char *s)
{
  return s != NULL && (strchr (s, '\r') != NULL || strchr (s, '\n') != NULL);
}

static const char *
ftp_user (struct twist_ftp *f)
{
  if (!f->transfer->creds_stripped && f->transfer->username != NULL
      && f->transfer->username[0] != 0)
    return f->transfer->username;
  if (f->transfer->url->user != NULL && f->transfer->url->user[0] != 0)
    return f->transfer->url->user;
  return "anonymous";
}

static const char *
ftp_pass (struct twist_ftp *f)
{
  if (!f->transfer->creds_stripped && f->transfer->password != NULL
      && f->transfer->password[0] != 0)
    return f->transfer->password;
  if (f->transfer->url->password != NULL && f->transfer->url->password[0] != 0)
    return f->transfer->url->password;
  return "twist@";
}

static void
prepare_arg (struct twist_ftp *f)
{
  const char *path = f->transfer->url->path;
  size_t n;
  int dir;

  if (path == NULL)
    path = "";
  dir = path[0] == 0 || strcmp (path, "/") == 0
        || path[strlen (path) - 1] == '/' || f->transfer->nobody;
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
  if (f->upload)
    {
      if (f->list || f->arg[0] == 0)
        return TWIST_ERR_URL;
      /* Where the server is: the size it has of the file.  */
      if (f->resume < 0 && !f->prepared)
        {
          f->state = FTP_SIZE;
          return ftp_send (f, "SIZE %s\r\n", f->arg);
        }
      f->retr_sent = 1;
      f->state = FTP_RETR;
      return ftp_send (f, "%s %s\r\n",
                       f->append || f->resume > 0 ? "APPE" : "STOR", f->arg);
    }
  /* A download goes on at a byte: REST before RETR (RFC 3659, 5.1).  */
  if (!f->list && f->resume > 0 && !f->prepared)
    {
      f->state = FTP_REST;
      return ftp_send (f, "REST %lld\r\n", f->resume);
    }
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

  c = twist_connection_new (f->transfer->loop);
  if (c == NULL)
    return TWIST_ERR_NOMEM;
  twist_connection_limit (c, f->transfer);
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
                                 (uint64_t) f->transfer->connect_timeout_ms);
  return rc;
}

static const struct twist_protocol_handler ftp_ctrl_handler;
static const struct twist_protocol_handler ftp_data_handler;

/* The data connection is a connection of its own, and goes where the control
   connection goes: through the proxy, to the server and the port it named.
   Made directly it connects from the client's own address, past the proxy,
   which gives the client away if the proxy is there to hide it, and fails if
   the proxy is the only way out.  The server is named, not the address the
   server gave in its reply (which is ignored, as for the control peer), and
   the proxy looks it up as it did for the control connection.  */
static int
new_data_proxy (struct twist_ftp *f)
{
  int kind = TWIST_PROXY_NONE;
  char *phost = NULL;
  char *puser = NULL;
  char *ppass = NULL;
  int pport = 0;
  int rc = TWIST_OK;

  if (twist_proxy_parse (twist_transfer_proxy (f->transfer), &kind, &phost,
                         &pport,
                         &puser, &ppass) != TWIST_OK)
    return TWIST_ERR_URL;
  f->data_proxy = twist_proxy_new (kind, phost, pport, &ftp_data_handler);
  if (f->data_proxy == NULL)
    rc = TWIST_ERR_NOMEM;
  else
    {
      twist_proxy_set_target (f->data_proxy, f->transfer->url->host,
                              f->data_port);
      twist_proxy_configure (f->data_proxy, f->transfer, puser, ppass);
      twist_proxy_set_user (f->data_proxy, f);
    }
  free (phost);
  free (puser);
  if (ppass != NULL)
    {
      memset (ppass, 0, strlen (ppass));
      free (ppass);
    }
  return rc;
}

static void
dial_data (struct twist_ftp *f)
{
  int rc;

  f->state = FTP_DIAL;
  if (f->proxy != NULL)
    {
      /* f->peer is the proxy's address, and f->dial_port its port.  */
      rc = new_data_proxy (f);
      if (rc == TWIST_OK)
        rc = dial_tcp (f, &f->data, twist_proxy_handler (f->data_proxy),
                       f->data_proxy, &f->peer, f->dial_port);
    }
  else
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

/* Send the user name, which begins the login.  */
static void
ftp_begin_login (struct twist_ftp *f)
{
  const char *user_name = ftp_user (f);

  if (bad_token (user_name))
    {
      ftp_complete (f, TWIST_ERR_PROTOCOL);
      return;
    }
  f->state = FTP_USER;
  if (ftp_send (f, "USER %s\r\n", user_name) != TWIST_OK)
    ftp_complete (f, TWIST_ERR_PROTOCOL);
}

/* The connection is up: greeted, logged in and, on ftps, protected.  What
   comes is the transfer.  */
static void
ftp_up (struct twist_ftp *f)
{
  twist_phase_end (&f->phase);
}

static void
ftp_phase_fail (void *user, int err)
{
  ftp_complete (user, err);
}

/* The login is done.  On ftps the data connection is protected before
   anything is transferred (RFC 4217): PBSZ 0, then PROT P.  Left at the
   default, PROT C, the password would be encrypted and the file not.  */
static void
ftp_logged_in (struct twist_ftp *f)
{
  const char *cmd = "TYPE I\r\n";

  f->state = FTP_TYPE;
  if (f->ctrl_tls)
    {
      f->state = FTP_PBSZ;
      cmd = "PBSZ 0\r\n";
    }
  else
    ftp_up (f);
  if (ftp_send (f, "%s", cmd) != TWIST_OK)
    ftp_complete (f, TWIST_ERR_PROTOCOL);
}

/* A server that will not protect the data connection ends the transfer.  The
   file is not fetched in the clear instead: whoever is on the path could have
   made the server say no.  */
static void
ftp_protect_refused (struct twist_ftp *f)
{
  twist_transfer_set_error
    (f->transfer, twist_strdup (_("the server will not protect the data "
                                  "connection (PBSZ and PROT P)")));
  ftp_complete (f, TWIST_ERR_TLS);
}

/* The data of an upload is sent as the data connection can take it
   (twist_connection_stream): from memory, or from the application's read
   callback, a chunk at a time, and the connection is closed, which is how an
   FTP upload ends, when the last of it has been queued.  */
struct ftp_up
{
  struct twist_ftp *ftp;
  struct twist_transfer *transfer;
  const uint8_t *mem;
  size_t mem_left;
  int from_cb;
};

static size_t
ftp_up_read (void *user, uint8_t *buf, size_t cap)
{
  struct ftp_up *u = user;
  struct twist_transfer *t = u->transfer;
  size_t n;

  if (u->from_cb)
    {
      n = t->read_cb ((char *) buf, 1, cap, t->read_data);
      if (n == TWIST_READFUNC_ABORT || n > cap)
        return (size_t) -1;
    }
  else
    {
      n = u->mem_left > cap ? cap : u->mem_left;
      memcpy (buf, u->mem, n);
      u->mem += n;
      u->mem_left -= n;
    }
  if (n > 0)
    twist_progress_uploaded (t, n);
  return n;
}

static void
ftp_close_data (void *user)
{
  struct twist_ftp *f = user;

  f->close_timer = NULL;
  if (f->data == NULL || f->finished)
    return;
  /* The end of the data is the end of the connection's side of it; the
     server answers on the control connection when it has it all.  */
  twist_connection_half_close (f->data);
  f->data_eof = 1;
  if (f->ctrl_done)
    ftp_finish_ok (f);
}

/* All of it is queued: close after it, from the loop and not from inside the
   stream.  If the connection went first, the transfer's own end is
   what is waited for.  */
static void
ftp_up_end (void *user, int err)
{
  struct ftp_up *u = user;
  struct twist_ftp *f = u->ftp;

  if (err == TWIST_OK && !f->finished)
    twist_loop_schedule (f->transfer->loop, twist_loop_now (f->transfer->loop),
                         ftp_close_data, f, &f->close_timer);
  free (u);
}

/* The server has said it will take the data and, on a protected connection,
   the handshake is done: the data goes.  */
static void
ftp_start_upload (struct twist_ftp *f)
{
  struct twist_transfer *t = f->transfer;
  struct ftp_up *u;
  long long skip = f->resume > 0 ? f->resume : 0;
  long long total = -1;
  int rc;

  if (!f->upload || f->up_started || !f->got_go || f->data == NULL
      || (f->prot_p && !f->data_secure))
    return;
  f->up_started = 1;
  u = calloc (1, sizeof *u);
  if (u == NULL)
    {
      ftp_complete (f, TWIST_ERR_NOMEM);
      return;
    }
  u->ftp = f;
  u->transfer = t;
  if (t->postfields != NULL)
    {
      size_t n = t->postfieldsize_set && t->postfieldsize >= 0
                 ? (size_t) t->postfieldsize : strlen (t->postfields);

      if ((unsigned long long) skip > n)
        {
          free (u);
          twist_transfer_set_error
            (t, twist_strdup (_("the data to upload is shorter than the "
                                "offset to resume at")));
          ftp_complete (f, TWIST_ERR_RESUME);
          return;
        }
      u->mem = (const uint8_t *) t->postfields + skip;
      u->mem_left = n - (size_t) skip;
      total = (long long) u->mem_left;
    }
  else
    {
      u->from_cb = 1;
      if (skip > 0 && !(t->seek_cb != NULL && t->seek_cb (t->seek_data, skip, 0) == 0))
        {
          /* Read and throw away what the server has.  */
          uint8_t junk[4096];
          long long left = skip;

          while (left > 0)
            {
              size_t want = left > (long long) sizeof junk ? sizeof junk
                                                          : (size_t) left;
              size_t n = t->read_cb ((char *) junk, 1, want, t->read_data);

              if (n == 0 || n > want)
                {
                  free (u);
                  twist_transfer_set_error
                    (t, twist_strdup (_("the data to upload is shorter than "
                                        "the offset to resume at")));
                  ftp_complete (f, TWIST_ERR_RESUME);
                  return;
                }
              left -= (long long) n;
            }
        }
      if (t->infilesize >= 0)
        total = t->infilesize > skip ? t->infilesize - skip : 0;
    }
  if (total >= 0)
    twist_progress_ul_size (t, total);
  rc = twist_connection_stream (f->data, ftp_up_read, ftp_up_end, u);
  if (rc != TWIST_OK)
    {
      free (u);
      ftp_complete (f, rc);
    }
}

/* The server turned the upload down (a 4xx or 5xx to STOR or APPE).  */
static void
ftp_upload_refused (struct twist_ftp *f, int code, const char *text,
                    size_t len)
{
  char msg[400];
  int n = snprintf (msg, sizeof msg, _("the server would not take the upload "
                                       "(%d %.*s)"), code,
                    (int) (len > 200 ? 200 : len), text != NULL ? text : "");

  if (n > 0)
    twist_transfer_set_error (f->transfer, twist_strdup (msg));
  f->transfer->proto_status = 25;
  ftp_complete (f, TWIST_ERR_FILE);
}

static void
ftp_on_reply (void *user, int code, int final, const char *text, size_t len)
{
  struct twist_ftp *f = user;
  const char *pass;
  int user_ssl_rc;

  if (!final || f->finished)
    return;
  f->transfer->http_code = code;
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
      /* TLS first if it was asked for, so that the user name and the password
         do not go where they can be read.  An FTP server is not asked what it
         offers: AUTH TLS is tried, and a server that has no such thing says
         so.  */
      if (f->use_ssl != TWIST_USE_SSL_NONE && !f->ctrl_tls)
        {
          f->state = FTP_AUTHTLS;
          if (ftp_send (f, "AUTH TLS\r\n") != TWIST_OK)
            ftp_complete (f, TWIST_ERR_PROTOCOL);
          return;
        }
      ftp_begin_login (f);
      return;
    case FTP_AUTHTLS:
      if (code == 234)
        {
          /* The handshake starts, and nothing is sent until it is done.  A
             test with no connection has none to start.  */
          f->state = FTP_TLSWAIT;
          if (f->ep != NULL
              && (user_ssl_rc = twist_connection_start_tls
                  (f->ep->conn, f->transfer->url->host,
                   f->transfer->verifypeer, NULL, 0, f->transfer->cainfo,
                   f->transfer->capath, f->transfer->sslcert,
                   f->transfer->sslkey)) != TWIST_OK)
            ftp_complete (f, user_ssl_rc);
          return;
        }
      /* Refused: required, that is the end; wanted, go on as it is.  */
      if (f->use_ssl == TWIST_USE_SSL_ALL)
        {
          ftp_complete (f, twist_transfer_use_ssl_failed
                        (f->transfer, _("the server refused AUTH TLS")));
          return;
        }
      ftp_begin_login (f);
      return;
    case FTP_TLSWAIT:
      /* A reply behind the 234, before the handshake: it came in the clear.  */
      ftp_complete (f, TWIST_ERR_PROTOCOL);
      return;
    case FTP_USER:
      if (code == 230)
        {
          ftp_logged_in (f);
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
      ftp_logged_in (f);
      return;
    case FTP_PBSZ:
      if (code / 100 != 2)
        {
          ftp_protect_refused (f);
          return;
        }
      f->state = FTP_PROT;
      if (ftp_send (f, "PROT P\r\n") != TWIST_OK)
        ftp_complete (f, TWIST_ERR_PROTOCOL);
      return;
    case FTP_PROT:
      if (code / 100 != 2)
        {
          ftp_protect_refused (f);
          return;
        }
      f->prot_p = 1;
      ftp_up (f);
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
    case FTP_SIZE:
      /* The size of the file the server has, where the upload goes on.  */
      f->resume = 0;
      if (code == 213)
        {
          char *end = NULL;
          long long n = strtoll (text, &end, 10);

          if (end != text && n >= 0)
            f->resume = n;
        }
      f->prepared = 1;
      if (ftp_send_transfer (f) != TWIST_OK)
        ftp_complete (f, TWIST_ERR_PROTOCOL);
      return;
    case FTP_REST:
      if (code != 350)
        {
          twist_transfer_set_error
            (f->transfer, twist_strdup (_("the server will not resume (REST)")));
          ftp_complete (f, TWIST_ERR_RESUME);
          return;
        }
      f->prepared = 1;
      if (ftp_send_transfer (f) != TWIST_OK)
        ftp_complete (f, TWIST_ERR_PROTOCOL);
      return;
    case FTP_RETR:
    case FTP_WAIT:
      if (f->upload && (code == 125 || code == 150))
        {
          f->state = FTP_WAIT;
          f->got_go = 1;
          ftp_start_upload (f);
          return;
        }
      if (f->upload && code >= 400 && !f->ctrl_done && !f->data_eof)
        {
          ftp_upload_refused (f, code, text, len);
          return;
        }
      if (code == 125 || code == 150)
        {
          long long size = f->list ? -1 : reply_size (text, len);

          f->state = FTP_WAIT;
          f->expect = size;
          if (size >= 0)
            twist_progress_dl_size (f->transfer, size);
          return;
        }
      if (code == 226 || code == 250)
        {
          f->ctrl_done = 1;
          f->state = FTP_WAIT;
          if (f->data_eof)
            ftp_finish_ok (f);
          return;
        }
      if (code >= 400)
        ftp_complete (f, TWIST_ERR_PROTOCOL);
      return;
    default:
      return;
    }
}

/* The transfer ended well as far as the protocol goes.  If the server said how
   much it would send, and less came, it is not the file: a data connection
   closed early with a 226 after it was a success, and left a short file with
   a good status.  A listing has no size.  */
static void
ftp_finish_ok (struct twist_ftp *f)
{
  if (!f->list && f->expect >= 0 && f->received < f->expect)
    ftp_complete (f, TWIST_ERR_PARTIAL);
  else
    ftp_complete (f, TWIST_OK);
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
  /* The data connection goes where the control connection went.  */
  if (f->race != NULL)
    twist_race_peer (f->race, &f->peer);
  if (!f->implicit_tls)
    return;
  rc = twist_connection_start_tls (ep->conn, f->transfer->url->host,
                                   f->transfer->verifypeer, NULL, 0,
                                   f->transfer->cainfo, f->transfer->capath, f->transfer->sslcert,
                                   f->transfer->sslkey);
  if (rc != TWIST_OK)
    ftp_complete (f, rc);
}

/* The handshake is done, for ftps as well as after AUTH TLS: only the second
   is waited for.  */
static void
ftp_ctrl_secure (struct twist_endpoint *ep, const char *alpn, size_t alpn_len)
{
  struct twist_ftp *f = ep->user_data;

  (void) alpn;
  (void) alpn_len;
  f->ep = ep;
  twist_ftp_tls_done (f);
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
    ftp_finish_ok (f);
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

/* The data connection is up.  If it is to be protected, TLS starts on it
   here, and the transfer command is sent at once: a server takes the data
   connection when it gets the command, and starts its side of the handshake
   after its 150 reply, so waiting for the handshake first would be waiting
   for a command that is never sent.  Nothing is exposed by that.  The server
   cannot send the file but through TLS, and one that does not prove itself
   ends the transfer.  The name it must prove is the host of the URL, as for
   the control connection, and not the address of the data connection, which
   the server chose.  */
static void
ftp_data_connected (struct twist_endpoint *ep)
{
  struct twist_ftp *f = ep->user_data;
  int rc;

  if (f->finished)
    return;
  if (f->prot_p)
    {
      /* Resuming the session of the control connection, which servers
         commonly require of the data connection (vsftpd, ProFTPD and
         FileZilla Server do unless told not to).  */
      rc = twist_connection_start_tls_resuming (ep->conn, f->ctrl,
                                                f->transfer->url->host,
                                                f->transfer->verifypeer, NULL,
                                                0,
                                                f->transfer->cainfo,
                                                f->transfer->capath,
                                                f->transfer->sslcert,
                                                f->transfer->sslkey);
      if (rc != TWIST_OK)
        {
          ftp_complete (f, rc);
          return;
        }
    }
  if (ftp_send_transfer (f) != TWIST_OK)
    ftp_complete (f, TWIST_ERR_PROTOCOL);
}

static void
ftp_data_secure (struct twist_endpoint *ep, const char *alpn, size_t alpn_len)
{
  struct twist_ftp *f = ep->user_data;

  (void) alpn;
  (void) alpn_len;
  f->data_secure = 1;
  ftp_start_upload (f);
}

static size_t
ftp_data_receive (struct twist_endpoint *ep, const uint8_t *data, size_t len)
{
  struct twist_ftp *f = ep->user_data;

  /* An upload is not answered on the data connection.  */
  if (f->upload)
    return len;
  return twist_ftp_data (f, data, len);
}

static void
ftp_data_disconnected (struct twist_endpoint *ep, int error)
{
  struct twist_ftp *f = ep->user_data;

  if (f->finished)
    return;
  if (f->prot_p && !f->data_secure)
    {
      /* Gone before the handshake finished: nothing was received that was
         protected, so that is a failure to protect it, not an empty file.  */
      ftp_complete (f, error != TWIST_OK && error != TWIST_ERR_CLOSED
                       ? error : TWIST_ERR_TLS);
      return;
    }
  /* A close, or a close_notify, is the end of the data.  A reset or a TLS
     failure is not: what came is not the file.  Unless all that was promised
     had come, in which case how it ended does not matter.  */
  if (error != TWIST_OK && error != TWIST_ERR_CLOSED
      && !(!f->list && f->expect >= 0 && f->received >= f->expect))
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
  ftp_ctrl_secure,
  ftp_error,
  NULL,
  NULL
};

static const struct twist_protocol_handler ftp_data_handler = {
  ftp_data_connected,
  ftp_data_receive,
  ftp_data_disconnected,
  ftp_data_secure,
  ftp_data_error,
  NULL,
  NULL
};

size_t
twist_ftp_receive (struct twist_ftp *f, const uint8_t *data, size_t len)
{
  size_t used;

  if (f == NULL || f->parser == NULL)
    return len;
  if (f->finished)
    return len;
  used = twist_ftp_parser_receive (f->parser, data, len);
  /* A server that has agreed to start TLS says nothing more until the
     handshake is done.  Whatever else is in this buffer came in the clear,
     from whoever is on the path, and must not be taken for the encrypted
     session's.  */
  if (f->state == FTP_TLSWAIT && !f->finished && used < len)
    {
      ftp_complete (f, TWIST_ERR_PROTOCOL);
      return len;
    }
  return used;
}

size_t
twist_ftp_data (struct twist_ftp *f, const uint8_t *data, size_t len)
{
  size_t accepted;

  if (f == NULL || f->finished)
    return len;
  if (len == 0)
    return 0;
  f->received += (long long) len;
  if (f->transfer->write_cb != NULL)
    {
      accepted = twist_write_bytes (f->transfer->write_cb,
                                    f->transfer->write_data,
                                    data, len);
      if (accepted < len)
        {
          twist_transfer_downloaded (f->transfer, accepted);
          ftp_complete (f, TWIST_ERR_ABORTED);
          return len;
        }
    }
  twist_transfer_downloaded (f->transfer, len);
  return len;
}

void
twist_ftp_data_eof (struct twist_ftp *f)
{
  if (f == NULL || f->finished)
    return;
  f->data_eof = 1;
  if (f->ctrl_done)
    ftp_finish_ok (f);
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

int
twist_ftp_data_protected (const struct twist_ftp *f)
{
  return f != NULL && f->prot_p;
}

const char *
twist_ftp_data_host (const struct twist_ftp *f)
{
  return f != NULL ? f->data_host : "";
}

/* The name could not be had: nothing was tried.  */
static void
ftp_race_failed (void *user, int err)
{
  ftp_complete (user, err);
}

/* The control connection, made and given its handler, and then the name looked
   up and its addresses raced: the connection can be up before the lookup is
   over.  */
static void
dial_control (struct twist_ftp *f)
{
  void *user = f;
  const struct twist_protocol_handler *handler = &ftp_ctrl_handler;
  struct twist_connection *c;
  int rc;

  if (f->proxy != NULL)
    {
      user = f->proxy;
      handler = twist_proxy_handler (f->proxy);
      twist_proxy_set_user (f->proxy, f);
    }
  c = twist_connection_new (f->transfer->loop);
  if (c == NULL)
    {
      ftp_complete (f, TWIST_ERR_NOMEM);
      return;
    }
  f->ctrl = c;
  twist_connection_limit (c, f->transfer);
  twist_connection_endpoint (c)->user_data = user;
  twist_connection_set_handler (c, handler);
  rc = twist_race_dial (f->transfer, c, f->dial_host, f->dial_port,
                        ftp_race_failed, f, &f->race);
  if (rc != TWIST_OK)
    ftp_complete (f, rc);
}

static void
ftp_begin (struct twist_ftp *f)
{
  struct twist_transfer *transfer = f->transfer;
  struct twist_url *url = transfer->url;
  const char *dial;
  int kind = TWIST_PROXY_NONE;
  char *phost = NULL, *puser = NULL, *ppass = NULL;
  int pport = 0;

  f->dial_port = url->port;
  dial = url->host;
  if (twist_transfer_proxy (transfer) != NULL)
    {
      if (twist_proxy_parse (twist_transfer_proxy (transfer), &kind, &phost, &pport, &puser,
                             &ppass) != TWIST_OK)
        {
          ftp_complete (f, TWIST_ERR_URL);
          return;
        }
      if (kind == TWIST_PROXY_HTTPS)
        {
          /* The data connection has to go through it as well; not yet.  */
          free (phost);
          free (puser);
          free (ppass);
          twist_transfer_set_error (transfer,
                                    twist_strdup (_("an https proxy is not "
                                                    "supported for ftp; use "
                                                    "http:// or socks5://")));
          ftp_complete (f, TWIST_ERR_UNSUPPORTED);
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
      twist_proxy_configure (f->proxy, transfer, puser, ppass);
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
  if (transfer->timeout_ms > 0)
    twist_loop_schedule (transfer->loop,
                         twist_loop_now (transfer->loop)
                         + (uint64_t) (transfer->hop_timeout_ms > 0
                                       ? transfer->hop_timeout_ms
                                       : transfer->timeout_ms),
                         on_timeout, f, &f->timer);
  /* From the lookup to the login, in the time allowed for connecting.  */
  twist_phase_begin (&f->phase, transfer, ftp_phase_fail, f);
  dial_control (f);
}

void
twist_ftp_free (void *p)
{
  struct twist_ftp *f = p;

  if (f == NULL)
    return;
  if (f->timer != NULL)
    twist_timer_cancel (f->timer);
  if (f->close_timer != NULL)
    twist_timer_cancel (f->close_timer);
  twist_phase_end (&f->phase);
  twist_race_free (f->race);
  twist_connection_free (f->ctrl);
  twist_connection_free (f->data);
  twist_proxy_free (f->proxy);
  twist_proxy_free (f->data_proxy);
  twist_ftp_parser_free (f->parser);
  free (f->dial_host);
  free (f);
}

struct twist_ftp *
twist_ftp_new (struct twist_transfer *transfer, int live)
{
  struct twist_ftp *f;
  struct twist_ftp_events ev;

  if (transfer == NULL || transfer->url == NULL)
    return NULL;
  f = calloc (1, sizeof *f);
  if (f == NULL)
    return NULL;
  f->transfer = transfer;
  f->live = live;
  f->expect = -1;
  f->upload = !transfer->nobody
              && (transfer->postfields != NULL || transfer->read_cb != NULL);
  f->append = transfer->append;
  f->resume = transfer->resume_from;
  f->implicit_tls = transfer->url->scheme != NULL
                    && strcmp (transfer->url->scheme, "ftps") == 0;
  f->ctrl_tls = f->implicit_tls;
  f->use_ssl = f->implicit_tls ? TWIST_USE_SSL_NONE : transfer->use_ssl;
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
  transfer->state = f;
  transfer->state_free = twist_ftp_free;
  return f;
}

int
twist_ftp_attach (struct twist_transfer *transfer)
{
  struct twist_ftp *f;

  if (transfer == NULL || transfer->url == NULL || transfer->loop == NULL)
    return TWIST_ERR_INVAL;
  f = twist_ftp_new (transfer, 1);
  if (f == NULL)
    return TWIST_ERR_NOMEM;
  ftp_begin (f);
  if (transfer->done)
    return transfer->result;
  return TWIST_OK;
}

/* The handshake that followed AUTH TLS is done.  The login begins, encrypted,
   and the data connection is to be protected as on ftps.  */
void
twist_ftp_tls_done (struct twist_ftp *f)
{
  if (f == NULL || f->finished || f->state != FTP_TLSWAIT)
    return;
  f->ctrl_tls = 1;
  ftp_begin_login (f);
}
