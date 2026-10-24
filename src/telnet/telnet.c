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
#include <errno.h>
#include <poll.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>

/* Telnet (RFC 854) and its URL form.  The path of the URL is not used.  What
   the server sends is text, and the commands in it (IAC and what follows) are
   taken out: the server's offers to do and not to do an option are answered
   (RFC 1143), a few of the sub-negotiations (terminal type, X display,
   environment, window size) are given what they ask for, and the rest are
   ignored.  What is sent is the transfer's input, the read callback or the
   input descriptor, with each byte 255 doubled.

   A server that does not negotiate is not negotiated with: the options we
   want are asked for after the first command the server sends, and not
   before, so that a telnet URL can also be used for a service that is not
   telnet, such as a mail or an echo server.  Only options we ask for are
   accepted: the "ask to stop" half of RFC 1143 (and its queue) is not here,
   since nothing asks.  A server's request is answered at once, and the
   options we want that it has not asked for are asked for after the chunk of
   input that held its first command.

   The input is the read callback, or the descriptor that
   TWISTOPT_TELNET_INPUT_FD names, and the process's standard input is not
   assumed: the caller says.  It is watched as the transfer goes on.  Where
   the descriptor can be polled (a terminal, a pipe) the loop is woken when it
   has something, and a regular file or a read callback is read a chunk at a
   time between the loop's other work.  What is read waits for the connection when it has too
   much to write.  The end of the input does not end the transfer: that is for
   the server, which closes.  */

#define IAC 255
#define DONT 254
#define DO 253
#define WONT 252
#define WILL 251
#define SB 250
#define SE 240

#define OPT_BINARY 0
#define OPT_ECHO 1
#define OPT_SGA 3
#define OPT_TTYPE 24
#define OPT_NAWS 31
#define OPT_XDISPLOC 35
#define OPT_NEW_ENVIRON 39
/* The options below this are asked for, if wanted.  */
#define NOPTS 40

#define QUAL_IS 0
#define ENV_VAR 0
#define ENV_VALUE 1

/* The most of a sub-negotiation that is kept, and of an answer to one.  */
#define SUB_MAX 512
#define REPLY_MAX 2048

/* What is read from the input at once, and how much the connection may be
   behind with before the input waits.  */
#define IN_CHUNK 16384
#define OUT_HIGH (64u * 1024u)
#define OUT_CHUNK 4096

enum rx_state
{
  RX_DATA,
  RX_IAC,
  RX_WILL,
  RX_WONT,
  RX_DO,
  RX_DONT,
  RX_CR,
  RX_SB,
  RX_SE
};

/* The state of an option, for us or for the server (RFC 1143).  */
enum opt_state
{
  OPT_NO,
  OPT_YES,
  OPT_WANTYES
};

struct twist_telnet
{
  struct twist_transfer *transfer;
  struct twist_endpoint *ep;
  struct twist_mail_link link;
  int live;
  int finished;
  enum rx_state rx;
  /* The server has sent a command, so it negotiates; and we have then asked
     for what we want.  */
  int heard;
  int asked;
  uint8_t us[256];
  uint8_t him[256];
  uint8_t us_want[256];
  uint8_t him_want[256];
  /* Options to answer with a sub-negotiation as soon as they are agreed.  */
  uint8_t subneg[256];
  char ttype[32];
  char xdisploc[128];
  unsigned wsx;
  unsigned wsy;
  /* NAME,VALUE strings for the environment option.  */
  struct twist_slist *vars;
  uint8_t sub[SUB_MAX];
  size_t sub_len;
  /* What would have been sent, with no connection.  */
  uint8_t *sent;
  size_t sent_len;
  size_t sent_cap;
  /* The input.  IN watches a copy of the input descriptor; PUMP reads in steps,
     the read callback or what cannot be watched.  */
  struct twist_connection *in;
  int in_fd;
  int in_setup;
  int in_failed;
  int in_done;
  int stalled;
  struct twist_timer *pump;
};

/* Nothing more is read from the input once the session is over: what is
   read now would be lost, and is wanted by whoever reads the descriptor next.
   The watcher is paused, and not freed, as this may be called from inside it.  */
static void
input_stop (struct twist_telnet *t)
{
  t->in_done = 1;
  if (t->pump != NULL)
    {
      twist_timer_cancel (t->pump);
      t->pump = NULL;
    }
  if (t->in != NULL)
    twist_endpoint_pause_read (twist_connection_endpoint (t->in));
}

static void
telnet_complete (struct twist_telnet *t, int err)
{
  if (t == NULL || t->finished)
    return;
  t->finished = 1;
  input_stop (t);
  twist_transfer_finish (t->transfer, err);
}

/* ---- sending ---- */

static void
emit (struct twist_telnet *t, const uint8_t *data, size_t len)
{
  int rc = TWIST_OK;

  if (t->finished || len == 0)
    return;
  if (t->live)
    {
      if (t->ep == NULL)
        rc = TWIST_ERR_INVAL;
      else
        rc = twist_endpoint_send (t->ep, data, len);
    }
  else
    {
      if (t->sent_len + len > t->sent_cap)
        {
          size_t cap = t->sent_cap == 0 ? 256 : t->sent_cap;
          uint8_t *p;

          while (cap < t->sent_len + len)
            cap *= 2;
          p = realloc (t->sent, cap);
          if (p == NULL)
            rc = TWIST_ERR_NOMEM;
          else
            {
              t->sent = p;
              t->sent_cap = cap;
            }
        }
      if (rc == TWIST_OK)
        {
          memcpy (t->sent + t->sent_len, data, len);
          t->sent_len += len;
        }
    }
  if (rc != TWIST_OK)
    telnet_complete (t, rc);
}

const uint8_t *
twist_telnet_sent (const struct twist_telnet *t, size_t *len)
{
  if (len != NULL)
    *len = t != NULL ? t->sent_len : 0;
  return t != NULL ? t->sent : NULL;
}

void
twist_telnet_sent_clear (struct twist_telnet *t)
{
  if (t != NULL)
    t->sent_len = 0;
}

static void
send_cmd (struct twist_telnet *t, int cmd, int option)
{
  uint8_t b[3];

  b[0] = IAC;
  b[1] = (uint8_t) cmd;
  b[2] = (uint8_t) option;
  emit (t, b, sizeof b);
}

/* DATA with each 255 doubled, as at most OUT_CHUNK bytes at once.  */
static void
emit_escaped (struct twist_telnet *t, const uint8_t *data, size_t len)
{
  uint8_t buf[2 * OUT_CHUNK];

  while (len > 0 && !t->finished)
    {
      size_t n = len < OUT_CHUNK ? len : OUT_CHUNK;
      size_t o = 0;
      size_t i;

      for (i = 0; i < n; i++)
        {
          buf[o++] = data[i];
          if (data[i] == IAC)
            buf[o++] = IAC;
        }
      emit (t, buf, o);
      data += n;
      len -= n;
    }
}

void
twist_telnet_input (struct twist_telnet *t, const uint8_t *data, size_t len)
{
  if (t == NULL || t->finished || len == 0)
    return;
  emit_escaped (t, data, len);
  twist_progress_uploaded (t->transfer, len);
}

/* ---- options ---- */

/* The window size, as the server is told it: four bytes, each of them
   escaped.  */
static void
send_window (struct twist_telnet *t)
{
  uint8_t size[4];

  size[0] = (uint8_t) (t->wsx >> 8);
  size[1] = (uint8_t) (t->wsx & 0xff);
  size[2] = (uint8_t) (t->wsy >> 8);
  size[3] = (uint8_t) (t->wsy & 0xff);
  {
    uint8_t buf[3 + 2 * sizeof size + 2];
    size_t o = 0;
    size_t i;

    buf[o++] = IAC;
    buf[o++] = SB;
    buf[o++] = OPT_NAWS;
    for (i = 0; i < sizeof size; i++)
      {
        buf[o++] = size[i];
        if (size[i] == IAC)
          buf[o++] = IAC;
      }
    buf[o++] = IAC;
    buf[o++] = SE;
    emit (t, buf, o);
  }
}

/* What to send once an option we do is agreed.  */
static void
send_suboption (struct twist_telnet *t, int option)
{
  if (option == OPT_NAWS)
    send_window (t);
}

static void
ask_local (struct twist_telnet *t, int option)
{
  if (t->us[option] == OPT_NO)
    {
      t->us[option] = OPT_WANTYES;
      send_cmd (t, WILL, option);
    }
}

static void
ask_remote (struct twist_telnet *t, int option)
{
  if (t->him[option] == OPT_NO)
    {
      t->him[option] = OPT_WANTYES;
      send_cmd (t, DO, option);
    }
}

/* Ask for the options we want.  ECHO is left to the server: to ask for it
   can make it close the connection.  */
static void
negotiate (struct twist_telnet *t)
{
  int i;

  for (i = 0; i < NOPTS; i++)
    {
      if (i == OPT_ECHO)
        continue;
      if (t->us_want[i])
        ask_local (t, i);
      if (t->him_want[i])
        ask_remote (t, i);
    }
}

/* The server will do OPTION.  */
static void
rec_will (struct twist_telnet *t, int option)
{
  switch (t->him[option])
    {
    case OPT_NO:
      if (t->him_want[option])
        {
          t->him[option] = OPT_YES;
          send_cmd (t, DO, option);
        }
      else
        send_cmd (t, DONT, option);
      break;
    case OPT_WANTYES:
      t->him[option] = OPT_YES;
      break;
    default:
      break;
    }
}

/* The server will not, or will no longer.  */
static void
rec_wont (struct twist_telnet *t, int option)
{
  switch (t->him[option])
    {
    case OPT_YES:
      t->him[option] = OPT_NO;
      send_cmd (t, DONT, option);
      break;
    case OPT_WANTYES:
      t->him[option] = OPT_NO;
      break;
    default:
      break;
    }
}

/* The server asks us to do OPTION.  One we are to answer with a
   sub-negotiation is done even if we did not ask.  */
static void
rec_do (struct twist_telnet *t, int option)
{
  switch (t->us[option])
    {
    case OPT_NO:
      if (t->us_want[option] || t->subneg[option])
        {
          t->us[option] = OPT_YES;
          send_cmd (t, WILL, option);
          if (t->subneg[option])
            send_suboption (t, option);
        }
      else
        send_cmd (t, WONT, option);
      break;
    case OPT_WANTYES:
      t->us[option] = OPT_YES;
      if (t->subneg[option])
        send_suboption (t, option);
      break;
    default:
      break;
    }
}

/* The server asks us not to.  */
static void
rec_dont (struct twist_telnet *t, int option)
{
  switch (t->us[option])
    {
    case OPT_YES:
      t->us[option] = OPT_NO;
      send_cmd (t, WONT, option);
      break;
    case OPT_WANTYES:
      t->us[option] = OPT_NO;
      break;
    default:
      break;
    }
}

/* A sub-negotiation the server has sent, in SUB.  We answer the three that
   ask for something we have, whatever the qualifier says.  */
static void
suboption (struct twist_telnet *t)
{
  uint8_t reply[REPLY_MAX];
  size_t len = 0;
  const char *text = NULL;
  const struct twist_slist *v;

  if (t->sub_len == 0)
    return;
  switch (t->sub[0])
    {
    case OPT_TTYPE:
      text = t->ttype;
      break;
    case OPT_XDISPLOC:
      text = t->xdisploc;
      break;
    case OPT_NEW_ENVIRON:
      break;
    default:
      return;
    }
  reply[len++] = IAC;
  reply[len++] = SB;
  reply[len++] = t->sub[0];
  reply[len++] = QUAL_IS;
  if (text != NULL)
    {
      size_t n = strlen (text);

      memcpy (reply + len, text, n);
      len += n;
    }
  else
    for (v = t->vars; v != NULL; v = v->next)
      {
        size_t need = strlen (v->data) + 1;
        const char *comma;

        /* A variable that does not fit is left out.  */
        if (len + need >= sizeof reply - 6)
          continue;
        comma = strchr (v->data, ',');
        reply[len++] = ENV_VAR;
        if (comma == NULL)
          {
            memcpy (reply + len, v->data, need - 1);
            len += need - 1;
          }
        else
          {
            size_t nlen = (size_t) (comma - v->data);
            size_t vlen = strlen (comma + 1);

            memcpy (reply + len, v->data, nlen);
            len += nlen;
            reply[len++] = ENV_VALUE;
            memcpy (reply + len, comma + 1, vlen);
            len += vlen;
          }
      }
  reply[len++] = IAC;
  reply[len++] = SE;
  emit (t, reply, len);
}

/* ---- receiving ---- */

static void
sub_add (struct twist_telnet *t, int c)
{
  if (t->sub_len < sizeof t->sub)
    t->sub[t->sub_len++] = (uint8_t) c;
}

/* C follows an IAC.  1 if the pair is a data byte of 255.  */
static int
command (struct twist_telnet *t, int c)
{
  switch (c)
    {
    case WILL:
      t->rx = RX_WILL;
      break;
    case WONT:
      t->rx = RX_WONT;
      break;
    case DO:
      t->rx = RX_DO;
      break;
    case DONT:
      t->rx = RX_DONT;
      break;
    case SB:
      t->sub_len = 0;
      t->rx = RX_SB;
      break;
    case IAC:
      t->rx = RX_DATA;
      return 1;
    default:
      /* DM, NOP, GA and the others have nothing for us to do.  */
      t->rx = RX_DATA;
      break;
    }
  return 0;
}

static int
write_text (struct twist_telnet *t, uint8_t *data, size_t len)
{
  struct twist_transfer *transfer = t->transfer;

  if (len == 0)
    return TWIST_OK;
  if (transfer->write_cb != NULL
      && transfer->write_cb ((char *) data, 1, len,
                             transfer->write_data) < len)
    return TWIST_ERR_ABORTED;
  /* The text, not the commands in what came.  */
  twist_transfer_downloaded (transfer, len);
  return TWIST_OK;
}

size_t
twist_telnet_receive (struct twist_telnet *t, const uint8_t *data, size_t len)
{
  uint8_t out[OUT_CHUNK];
  size_t on = 0;
  size_t i;
  int rc = TWIST_OK;

  if (t == NULL || t->finished)
    return len;
  for (i = 0; i < len && rc == TWIST_OK && !t->finished; i++)
    {
      int c = data[i];
      int text = 0;

      /* A carriage return is followed by a line feed or by a NUL, which is
         not part of the text.  Anything else is as if it were not there.  */
      if (t->rx == RX_CR)
        {
          t->rx = RX_DATA;
          if (c == 0)
            continue;
        }
      switch (t->rx)
        {
        case RX_DATA:
          if (c == IAC)
            t->rx = RX_IAC;
          else
            {
              if (c == '\r')
                t->rx = RX_CR;
              text = 1;
            }
          break;
        case RX_IAC:
          text = command (t, c);
          break;
        case RX_WILL:
          t->heard = 1;
          rec_will (t, c);
          t->rx = RX_DATA;
          break;
        case RX_WONT:
          t->heard = 1;
          rec_wont (t, c);
          t->rx = RX_DATA;
          break;
        case RX_DO:
          t->heard = 1;
          rec_do (t, c);
          t->rx = RX_DATA;
          break;
        case RX_DONT:
          t->heard = 1;
          rec_dont (t, c);
          t->rx = RX_DATA;
          break;
        case RX_SB:
          if (c == IAC)
            t->rx = RX_SE;
          else
            sub_add (t, c);
          break;
        case RX_SE:
          if (c == SE)
            {
              suboption (t);
              t->rx = RX_DATA;
            }
          else if (c == IAC)
            {
              sub_add (t, IAC);
              t->rx = RX_SB;
            }
          else
            {
              /* Neither IAC IAC nor IAC SE: the IAC SE was left out, or
                 another command came into the sub-negotiation.  End it,
                 answer what there is, and take this as the command it is.  */
              suboption (t);
              text = command (t, c);
            }
          break;
        case RX_CR:
          break;
        }
      if (text)
        {
          out[on++] = (uint8_t) c;
          if (on == sizeof out)
            {
              rc = write_text (t, out, on);
              on = 0;
            }
        }
    }
  if (rc == TWIST_OK)
    rc = write_text (t, out, on);
  if (rc != TWIST_OK)
    {
      telnet_complete (t, rc);
      return len;
    }
  /* The server has begun to negotiate, so it is a telnet server.  */
  if (t->heard && !t->asked && !t->finished)
    {
      t->asked = 1;
      negotiate (t);
    }
  return len;
}

void
twist_telnet_closed (struct twist_telnet *t, int err)
{
  if (t == NULL || t->finished)
    return;
  /* The server closing is how a session ends.  */
  telnet_complete (t, err == TWIST_ERR_CLOSED ? TWIST_OK : err);
}

/* ---- the options of the transfer ---- */

static int
ascii_only (const char *s)
{
  for (; *s != 0; s++)
    if ((unsigned char) *s >= 0x80)
      return 0;
  return 1;
}

static int
add_var (struct twist_telnet *t, const char *text)
{
  struct twist_slist *list = twist_slist_append (t->vars, text);

  if (list == NULL)
    return TWIST_ERR_NOMEM;
  t->vars = list;
  t->us_want[OPT_NEW_ENVIRON] = 1;
  return TWIST_OK;
}

static int
bad_syntax (struct twist_telnet *t, const char *opt)
{
  char msg[512];

  snprintf (msg, sizeof msg, _("syntax error in telnet option: %s"), opt);
  twist_transfer_set_error (t->transfer, twist_strdup (msg));
  return TWIST_ERR_OPTION_SYNTAX;
}

static int
unknown_option (struct twist_telnet *t, const char *opt)
{
  char msg[512];

  snprintf (msg, sizeof msg, _("unknown telnet option %s"), opt);
  twist_transfer_set_error (t->transfer, twist_strdup (msg));
  return TWIST_ERR_UNKNOWN_OPTION;
}

/* One NAME=VALUE of TWISTOPT_TELNETOPTIONS.  */
static int
one_option (struct twist_telnet *t, const char *opt)
{
  const char *eq = strchr (opt, '=');
  const char *arg;
  size_t olen;

  if (eq == NULL)
    return bad_syntax (t, opt);
  olen = (size_t) (eq - opt);
  arg = eq + 1;
  if (!ascii_only (arg))
    return TWIST_OK;
  if (olen == 5 && strncasecmp (opt, "TTYPE", 5) == 0)
    {
      snprintf (t->ttype, sizeof t->ttype, "%s", arg);
      t->us_want[OPT_TTYPE] = 1;
    }
  else if (olen == 8 && strncasecmp (opt, "XDISPLOC", 8) == 0)
    {
      snprintf (t->xdisploc, sizeof t->xdisploc, "%s", arg);
      t->us_want[OPT_XDISPLOC] = 1;
    }
  else if (olen == 7 && strncasecmp (opt, "NEW_ENV", 7) == 0)
    return add_var (t, arg);
  else if (olen == 2 && strncasecmp (opt, "WS", 2) == 0)
    {
      char *p;
      unsigned long x = strtoul (arg, &p, 10);
      unsigned long y = 0;

      if (x != 0 && x <= 0xffff && tolower ((unsigned char) *p) == 'x')
        {
          y = strtoul (p + 1, NULL, 10);
          if (y != 0 && y <= 0xffff)
            {
              t->wsx = (unsigned) x;
              t->wsy = (unsigned) y;
              t->us_want[OPT_NAWS] = 1;
            }
        }
      if (y == 0)
        return bad_syntax (t, opt);
    }
  else if (olen == 6 && strncasecmp (opt, "BINARY", 6) == 0)
    {
      if (strtol (arg, NULL, 10) != 1)
        t->us_want[OPT_BINARY] = t->him_want[OPT_BINARY] = 0;
    }
  else
    return unknown_option (t, opt);
  return TWIST_OK;
}

static int
setup_options (struct twist_telnet *t)
{
  struct twist_transfer *transfer = t->transfer;
  const char *user = transfer->username != NULL ? transfer->username
                     : transfer->url->user;
  const struct twist_slist *o;
  int rc;

  t->us_want[OPT_SGA] = t->him_want[OPT_SGA] = 1;
  /* Bytes as they are, unless BINARY=0.  */
  t->us_want[OPT_BINARY] = t->him_want[OPT_BINARY] = 1;
  /* The server may echo, but is not asked to.  */
  t->him_want[OPT_ECHO] = 1;
  /* The window size is sent, as nothing, when the server asks.  */
  t->subneg[OPT_NAWS] = 1;
  if (user != NULL)
    {
      char var[256];

      if (!ascii_only (user))
        return TWIST_ERR_INVAL;
      snprintf (var, sizeof var, "USER,%s", user);
      rc = add_var (t, var);
      if (rc != TWIST_OK)
        return rc;
    }
  for (o = transfer->telnet_options; o != NULL; o = o->next)
    {
      rc = one_option (t, o->data);
      if (rc != TWIST_OK)
        return rc;
    }
  return TWIST_OK;
}

/* ---- the input ---- */

/* The input is read to its end, or something is wrong with it.  The server
   closing ends the transfer; the end of the input does not.  */
static void
input_ended (struct twist_telnet *t)
{
  t->in_done = 1;
}

/* More has been sent than the connection has written, so wait for it.  */
static int
congested (const struct twist_telnet *t)
{
  return t->ep != NULL && twist_endpoint_pending (t->ep) >= OUT_HIGH;
}

static void
pump_step (void *user);

/* Read again in DELAY_MS, 0 being as soon as the loop has done what else it
   has to.  */
static void
pump_schedule_after (struct twist_telnet *t, unsigned delay_ms)
{
  struct twist_loop *loop = t->transfer->loop;

  if (t->pump != NULL || t->finished || t->in_done || t->stalled)
    return;
  if (twist_loop_schedule (loop, twist_loop_now (loop) + delay_ms, pump_step, t,
                           &t->pump) != TWIST_OK)
    telnet_complete (t, TWIST_ERR_NOMEM);
}

static void
pump_schedule (struct twist_telnet *t)
{
  pump_schedule_after (t, 0);
}

/* How long to wait before looking again at a descriptor that had nothing.  */
#define POLL_RETRY_MS 20

/* One chunk of the read callback, or of the input descriptor where it cannot
   be watched.  */
static void
pump_step (void *user)
{
  struct twist_telnet *t = user;
  struct twist_transfer *transfer = t->transfer;
  uint8_t buf[IN_CHUNK];
  ssize_t n;

  t->pump = NULL;
  if (t->finished || t->in_done)
    return;
  if (transfer->read_cb != NULL)
    {
      size_t got = transfer->read_cb ((char *) buf, 1, sizeof buf,
                                      transfer->read_data);

      /* The callback says it cannot read (TWIST_READFUNC_ABORT), or
         it has given more than there was room for.  */
      if (got > sizeof buf)
        {
          telnet_complete (t, TWIST_ERR_ABORTED);
          return;
        }
      n = (ssize_t) got;
    }
  else
    {
      struct pollfd p;
      int r;

      /* A descriptor that could not be watched is a file, which is always
         ready, unless watching failed for another reason; one that is not
         ready is not read, since the read would wait for the whole loop.  */
      p.fd = transfer->telnet_input_fd;
      p.events = POLLIN;
      p.revents = 0;
      do
        r = poll (&p, 1, 0);
      while (r < 0 && errno == EINTR);
      if (r == 0)
        {
          pump_schedule_after (t, POLL_RETRY_MS);
          return;
        }
      do
        n = read (transfer->telnet_input_fd, buf, sizeof buf);
      while (n < 0 && errno == EINTR);
      if (n < 0)
        {
          /* A read that fails ends the transfer, as it has been done.  */
          input_ended (t);
          telnet_complete (t, TWIST_OK);
          return;
        }
    }
  if (n == 0)
    {
      input_ended (t);
      return;
    }
  twist_telnet_input (t, buf, (size_t) n);
  if (t->finished)
    return;
  if (congested (t))
    t->stalled = 1;
  else
    pump_schedule (t);
}

/* The connection has written all it had.  */
static void
telnet_drained (struct twist_endpoint *ep)
{
  struct twist_telnet *t = ep->user_data;

  if (t == NULL || !t->stalled || t->finished)
    return;
  t->stalled = 0;
  if (t->in != NULL)
    twist_endpoint_resume_read (twist_connection_endpoint (t->in));
  else
    pump_schedule (t);
}

/* A read of the watched descriptor that never waits: the loop said it was
   ready, but a read that follows one that took everything would wait, and the
   descriptor is the terminal's or a pipe's, which the transfer does not own,
   so it is not made non-blocking.  */
static ssize_t
input_read (void *user, uint8_t *buf, size_t len)
{
  struct twist_telnet *t = user;
  struct pollfd p;
  int r;

  p.fd = t->in_fd;
  p.events = POLLIN;
  p.revents = 0;
  do
    r = poll (&p, 1, 0);
  while (r < 0 && errno == EINTR);
  if (r < 0)
    return -1;
  if (r == 0)
    {
      errno = EAGAIN;
      return -1;
    }
  return read (t->in_fd, buf, len);
}

static size_t
input_receive (struct twist_endpoint *ep, const uint8_t *data, size_t len)
{
  struct twist_telnet *t = ep->user_data;

  twist_telnet_input (t, data, len);
  if (!t->finished && congested (t))
    {
      t->stalled = 1;
      twist_endpoint_pause_read (ep);
    }
  return len;
}

static void
input_error (struct twist_endpoint *ep, int err)
{
  struct twist_telnet *t = ep->user_data;

  if (err == TWIST_ERR_CLOSED)
    input_ended (t);
  else if (t->in_setup)
    t->in_failed = 1;
  else
    {
      input_ended (t);
      telnet_complete (t, TWIST_OK);
    }
}

static const struct twist_protocol_handler input_handler = {
  NULL,
  input_receive,
  NULL,
  NULL,
  input_error,
  NULL,
  NULL
};

/* Watch a copy of the input descriptor, so that the caller's is not closed
   with it.  Not every descriptor can be: a regular file and the null device
   cannot, and are read in steps instead.  */
static int
watch_input (struct twist_telnet *t)
{
  struct twist_connection *conn;
  int fd = dup (t->transfer->telnet_input_fd);

  if (fd < 0)
    return TWIST_ERR_INVAL;
  conn = twist_connection_new (t->transfer->loop);
  if (conn == NULL)
    {
      close (fd);
      return TWIST_ERR_NOMEM;
    }
  t->in = conn;
  t->in_fd = fd;
  twist_connection_endpoint (conn)->user_data = t;
  twist_connection_set_handler (conn, &input_handler);
  twist_connection_set_io (conn, input_read, NULL, t);
  t->in_setup = 1;
  twist_connection_set_fd (conn, fd);
  t->in_setup = 0;
  if (t->in_failed)
    {
      twist_connection_free (conn);
      t->in = NULL;
      t->in_failed = 0;
      return TWIST_ERR_CONNECT;
    }
  return TWIST_OK;
}

static void
input_start (struct twist_telnet *t)
{
  /* With neither a read callback nor a descriptor there is nothing to send;
     the session is the server's.  */
  if (t->transfer->read_cb == NULL && t->transfer->telnet_input_fd < 0)
    {
      input_ended (t);
      return;
    }
  if (t->transfer->read_cb == NULL && watch_input (t) == TWIST_OK)
    return;
  pump_schedule (t);
}

/* ---- the connection ---- */

static void
telnet_connected (struct twist_endpoint *ep)
{
  struct twist_telnet *t = ep->user_data;

  t->ep = ep;
  ep->on_write_ready = telnet_drained;
  input_start (t);
}

static size_t
telnet_on_recv (struct twist_endpoint *ep, const uint8_t *data, size_t len)
{
  struct twist_telnet *t = ep->user_data;

  t->ep = ep;
  return twist_telnet_receive (t, data, len);
}

static void
telnet_disconnected (struct twist_endpoint *ep, int error)
{
  twist_telnet_closed (ep->user_data, error);
}

static void
telnet_error (struct twist_endpoint *ep, int error)
{
  twist_telnet_closed (ep->user_data, error);
}

static void
telnet_fail (void *user, int err)
{
  telnet_complete (user, err);
}

static const struct twist_protocol_handler telnet_handler = {
  telnet_connected,
  telnet_on_recv,
  telnet_disconnected,
  NULL,
  telnet_error,
  NULL,
  NULL
};

void
twist_telnet_free (void *p)
{
  struct twist_telnet *t = p;

  if (t == NULL)
    return;
  if (t->pump != NULL)
    twist_timer_cancel (t->pump);
  twist_connection_free (t->in);
  twist_mail_link_close (&t->link);
  twist_slist_free_all (t->vars);
  free (t->sent);
  free (t);
}

struct twist_telnet *
twist_telnet_new (struct twist_transfer *transfer, int live)
{
  struct twist_telnet *t;
  int rc;

  if (transfer == NULL || transfer->url == NULL)
    return NULL;
  t = calloc (1, sizeof *t);
  if (t == NULL)
    return NULL;
  t->transfer = transfer;
  t->live = live;
  t->rx = RX_DATA;
  transfer->state = t;
  transfer->state_free = twist_telnet_free;
  rc = setup_options (t);
  if (rc != TWIST_OK)
    telnet_complete (t, rc);
  return t;
}

int
twist_telnet_attach (struct twist_transfer *transfer)
{
  struct twist_telnet *t;
  int rc;

  t = twist_telnet_new (transfer, 1);
  if (t == NULL)
    return TWIST_ERR_NOMEM;
  if (t->finished)
    return transfer->result;
  rc = twist_mail_link_open (&t->link, transfer, &telnet_handler, t,
                             telnet_fail);
  if (rc != TWIST_OK)
    telnet_complete (t, rc);
  return transfer->done ? transfer->result : TWIST_OK;
}
