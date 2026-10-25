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
#include "bar.h"
#include "meter.h"
#include "twist-int.h"

#include <ctype.h>
#include <errno.h>
#include <getopt.h>
#include <limits.h>
#include <locale.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <termios.h>

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

/* The body is written to standard output, or to -o.  Diagnostics go to
   standard error, or to --stderr.  A transfer's exit status is the code
   for that failure.  A bad command line exits 2.  --help and
   --version write to standard output and exit 0.  */

static FILE *err_fp;
static int silent;
static int show_error;
/* -#: the bar in place of the meter.  --no-progress-meter: neither.  Both
   are global.  */
static int progress_bar;
static int no_progress;
static int fail_early;
/* -Z: transfers run together, at most parallel_max of them.  All of these are
   global.  With --parallel-immediate a transfer does not wait for a
   connection that is being made; --parallel-max-host is the most connections
   to one host.  */
static int parallel;
static long parallel_max = 50;
static int parallel_immediate;
static long parallel_max_host;
static long threads = 1;    /* Loops of the runtime, --threads.  */

struct cli_item
{
  char *text;
  int remote;
  struct cli_item *next;
};

/* An option for the transfers of an operation: a number or a string, as
   twist_transfer_setopt takes them.  The string is the record's own.  */
struct cli_opt
{
  int opt;
  int is_str;
  long num;
  char *str;
  struct cli_opt *next;
};

struct cli_op
{
  struct cli_item *urls;
  struct cli_item *urls_tail;
  struct cli_item *outputs;
  struct cli_item *outputs_tail;
  struct cli_item *uploads;
  struct cli_item *uploads_tail;
  char *data;
  size_t data_len;
  int has_data;
  int form_next;
  char *method;
  int head;
  int head_given;		/* -I or --head was given.  */
  int no_head_given;		/* --no-head was.  */
  int get;
  int include;
  char *dump_header;
  char *writeout;
  struct twist_slist *headers;
  struct twist_slist *rcpts;
  struct twist_slist *quote;
  struct twist_slist *postquote;
  struct twist_slist *telnet;	/* -t, for telnet URLs.  */
  int ftp_create_dirs;
  uint64_t limit_rate;		/* Bytes a second; 0: none.  */
  int globoff;			/* -g: {} and [] in a URL are plain.  */
  char *mail_from;
  char *output_dir;
  int create_dirs;
  int resume_set;
  int resume_auto;
  long long resume_off;
  /* The options of the operation that go to every transfer it makes, in the
     order they were given.  */
  struct cli_opt *opts;
  struct cli_opt *opts_tail;
  struct cli_op *next;
};

struct cli_bytes
{
  char *p;
  size_t n;
  size_t cap;
};

static void
diag (const char *msg)
{
  fprintf (err_fp, _("%s: %s\n"), PACKAGE, msg);
}

static void
diag_code (int code, const char *msg)
{
  if (silent && !show_error)
    return;
  fprintf (err_fp, _("%s: (%d) %s\n"), PACKAGE, code, msg);
}

static void
suggest (void)
{
  fprintf (err_fp, _("try '%s --help' for more information.\n"), PACKAGE);
}

/* Whether an upload to URL is read as it is sent, and not first read whole
   into memory: the schemes that take their data from the read callback in
   chunks (every one that has an upload but mqtt, whose message is one packet
   of at most a few KiB, and ws).  */
static int
streams_upload (const char *url)
{
  static const char *const schemes[] = {
    "http:", "https:", "smtp:", "smtps:", "tftp:", "ftp:", "ftps:",
    "imap:", "imaps:"
  };
  size_t i;

  if (url == NULL)
    return 0;
  for (i = 0; i < sizeof schemes / sizeof schemes[0]; i++)
    if (strncasecmp (url, schemes[i], strlen (schemes[i])) == 0)
      return 1;
  return 0;
}

static int
cli_status (int err, const char *url)
{
  if (err == TWIST_ERR_FILE && url != NULL
      && strncmp (url, "tftp:", 5) == 0)
    return 68;
  switch (err)
    {
    case TWIST_OK:
      return 0;
    case TWIST_ERR_UNSUPPORTED:
      return 1;
    case TWIST_ERR_URL:
      return 3;
    case TWIST_ERR_RESOLVE:
      return 6;
    case TWIST_ERR_CONNECT:
      return 7;
    case TWIST_ERR_PROTOCOL:
      return 8;
    case TWIST_ERR_HTTP:
      return 22;
    case TWIST_ERR_NOMEM:
      return 27;
    case TWIST_ERR_TIMEOUT:
      return 28;
    case TWIST_ERR_TLS:
      return 35;
    case TWIST_ERR_FILE:
      return 37;
    case TWIST_ERR_ABORTED:
      return 42;
    case TWIST_ERR_INVAL:
      return 43;
    case TWIST_ERR_REDIRECT:
      return 47;
    case TWIST_ERR_CLOSED:
      return 52;
    case TWIST_ERR_RANGE:
      return 33;
    case TWIST_ERR_RESUME:
      return 36;
    case TWIST_ERR_QUOTE:
      return 21;
    case TWIST_ERR_PROXY:
      return 97;
    case TWIST_ERR_RECURSIVE:
      return 93;
    case TWIST_ERR_PARTIAL:
      return 18;
    case TWIST_ERR_USE_SSL:
      return 64;
    case TWIST_ERR_UNKNOWN_OPTION:
      return 48;
    case TWIST_ERR_OPTION_SYNTAX:
      return 49;
    case TWIST_ERR_HOSTKEY:
      return 60;
    case TWIST_ERR_ENCODING:
      return 61;
    case TWIST_ERR_AUTH:
      return 67;
    case TWIST_ERR_AGAIN:
      return 81;
    case TWIST_ERR_RTSP_CSEQ:
      return 85;
    case TWIST_ERR_REWIND:
      return 65;
    default:
      return 2;
    }
}

static void
usage (void)
{
  printf (_("Usage: %s [OPTION]... URL...\n"), PACKAGE);
  fputs (_("Transfer one or more URLs.\n\n"), stdout);
  fputs (_("  -o, --output FILE       write the body to FILE (- is stdout)\n"),
         stdout);
  fputs (_("  -O, --remote-name       write the body to the remote file name\n"),
         stdout);
  fputs (_("      --output-dir DIR    directory for -o and -O\n"), stdout);
  fputs (_("      --create-dirs       create missing directories for -o and -O\n"),
         stdout);
  fputs (_("  -X, --request METHOD    request method\n"), stdout);
  fputs (_("  -H, --header LINE       extra header\n"), stdout);
  fputs (_("  -d, --data DATA         request body (@file or @- reads input)\n"),
         stdout);
  fputs (_("      --data-binary DATA  request body, kept as given\n"), stdout);
  fputs (_("      --data-raw DATA     request body, @ is not a file\n"), stdout);
  fputs (_("      --data-urlencode D  form field, percent-encoded\n"), stdout);
  fputs (_("  -G, --get               put -d on the query string\n"), stdout);
  fputs (_("  -T, --upload-file FILE  upload FILE (- is stdin) with PUT; send it to telnet\n"),
         stdout);
  fputs (_("  -t, --telnet-option O=V set a telnet option: TTYPE, XDISPLOC, NEW_ENV, WS\n"
           "                          (80x24) or BINARY\n"),
         stdout);
  fputs (_("  -I, --head              fetch headers only\n"), stdout);
  fputs (_("  -i, --include           write response headers before the body\n"),
         stdout);
  fputs (_("  -D, --dump-header FILE  write response headers to FILE\n"), stdout);
  fputs (_("  -L, --location          follow redirects (http to http, https, ftp, ftps;\n"
           "                          https to https, ftps)\n"), stdout);
  fputs (_("      --proto-redir P     accepted, and ignored\n"), stdout);
  fputs (_("      --max-redirs N      redirect limit (default 50)\n"), stdout);
  fputs (_("  -f, --fail              fail on HTTP errors (400 and above)\n"),
         stdout);
  fputs (_("      --fail-early        stop at the first failed URL\n"), stdout);
  fputs (_("  -Z, --parallel          run the transfers together\n"), stdout);
  fputs (_("      --parallel-max N    at most N transfers at once (default 50, most 300)\n"),
         stdout);
  fputs (_("      --parallel-max-host N  at most N connections to one host\n"),
         stdout);
  fputs (_("      --threads N         run transfers on N threads (default 1, most 64)\n"),
         stdout);
  fputs (_("      --parallel-immediate  do not wait to share a connection\n"),
         stdout);
  fputs (_("      --no-parallel, --no-parallel-immediate\n"
           "                          undo the option\n"), stdout);
  fputs (_("      --compressed        request a compressed response (gzip, deflate or br)\n"),
         stdout);
  fputs (_("      --content-encoding C  compress the request body (gzip, deflate or br)\n"),
         stdout);
  fputs (_("  -k, --insecure          do not check the server's certificate; sftp and\n"
           "                          scp do not check the known_hosts file\n"),
         stdout);
  fputs (_("  -E, --cert FILE         client certificate (PEM)\n"), stdout);
  fputs (_("      --key FILE          private key for --cert (PEM), or for sftp and scp\n"),
         stdout);
  fputs (_("      --pass PHRASE       passphrase for the private key file\n"), stdout);
  fputs (_("      --hostpubsha256 H   SHA-256 of the sftp or scp host key (base64)\n"),
         stdout);
  fputs (_("      --cacert FILE       CA trust bundle (PEM)\n"), stdout);
  fputs (_("      --capath DIR        directory of CA certificates (PEM)\n"),
         stdout);
  fputs (_("      --noproxy LIST      hosts that do not go through a proxy\n"),
         stdout);
  fputs (_("      --ssl               upgrade ftp, imap, pop3 and smtp to TLS if offered\n"),
         stdout);
  fputs (_("      --ssl-reqd          the same, and fail if the server will not\n"),
         stdout);
  fputs (_("      --unix-socket PATH  connect to a Unix socket for http and https\n"),
         stdout);
  fputs (_("      --abstract-unix-socket NAME  the same, in the abstract namespace\n"),
         stdout);
  fputs (_("  -x, --proxy URL         proxy (http://, https://, socks4://, socks4a://, socks5:// or socks5h://), may hold\n"
           "                          user:password@\n"), stdout);
  fputs (_("      --proxy-cacert FILE CA bundle for an https proxy\n"), stdout);
  fputs (_("      --proxy-insecure    do not check the certificate of an https proxy\n"),
         stdout);
  fputs (_("      --proxy-template-udp T  URI template of a CONNECT-UDP proxy (HTTP/3)\n"),
         stdout);
  fputs (_("  -U, --proxy-user U:P    user and password for the proxy\n"), stdout);
  fputs (_("      --url URL           a URL to fetch\n"), stdout);
  fputs (_("      --variable N=TEXT   set a variable (N@FILE, %N for the environment)\n"),
         stdout);
  fputs (_("      --expand-OPTION P   OPTION with {{name}} in its parameter expanded\n"),
         stdout);
  fputs (_("  -A, --user-agent NAME   User-Agent\n"), stdout);
  fputs (_("  -u, --user USER[:PASS]  user and password\n"), stdout);
  fputs (_("  -e, --referer URL       Referer header\n"), stdout);
  fputs (_("  -r, --range RANGE       byte range\n"), stdout);
  fputs (_("  -a, --append            add to the remote file (ftp)\n"), stdout);
  fputs (_("  -p, --proxytunnel       tunnel (CONNECT) through an HTTP proxy for http:// too\n"),
         stdout);
  fputs (_("  -C, --continue-at N     resume at byte N, or - to find it (sftp, scp, ftp)\n"),
         stdout);
  fputs (_("  -l, --list-only         list names only, for a directory (sftp)\n"),
         stdout);
  fputs (_("  -Q, --quote CMD         run an sftp command before the transfer, or after\n"
           "                          it with a - before it; a * lets it fail\n"),
         stdout);
  fputs (_("      --ftp-create-dirs   make the directories of an sftp upload\n"),
         stdout);
  fputs (_("      --limit-rate SPEED  keep to SPEED bytes a second, with k, M, G\n"),
         stdout);
  fputs (_("  -b, --cookie DATA       Cookie header data\n"), stdout);
  fputs (_("      --oauth2-bearer T   Bearer token\n"), stdout);
  fputs (_("  -m, --max-time SECONDS  whole transfer limit\n"), stdout);
  fputs (_("      --connect-timeout S connect limit, in seconds\n"), stdout);
  fputs (_("  -s, --silent            hide the progress meter and the error message\n"),
         stdout);
  fputs (_("  -S, --show-error        show the error message with -s\n"),
         stdout);
  fputs (_("  -#, --progress-bar      show a bar in place of the progress meter\n"),
         stdout);
  fputs (_("      --no-progress-meter hide the progress meter, not the messages\n"),
         stdout);
  fputs (_("      --no-silent, --no-show-error, --no-progress-bar,\n"
           "      --progress-meter    undo the option\n"), stdout);
  fputs (_("      --no-OPTION         turn off a switch, such as --no-fail or\n"
           "                          --no-location; the last one given counts\n"),
         stdout);
  fputs (_("      --stderr FILE       diagnostics go to FILE (- is standard output)\n"),
         stdout);
  /* TRANSLATORS: The %{name} tokens are literal.  Keep the doubled
     percent signs.  */
  printf (_("  -w, --write-out FORMAT  print after the body (%%{http_code},\n"
            "                          %%{size_download}, %%{url_effective},\n"
            "                          %%{content_type}, %%{exitcode})\n"));
  fputs (_("  -g, --globoff           do not expand {a,b} and [1-9] in URLs\n"),
         stdout);
  fputs (_("  -q, --disable           accepted; no config file is read\n"),
         stdout);
  fputs (_("      --next              start a new URL; only -s, -S, -#, --stderr,\n"
           "                          --no-progress-meter, --fail-early, --threads\n"
           "                          and the parallel options carry over\n"),
         stdout);
  fputs (_("      --http1.0           use HTTP/1.0\n"), stdout);
  fputs (_("      --http1.1           use HTTP/1.1\n"), stdout);
  fputs (_("      --http2             use HTTP/2\n"), stdout);
  fputs (_("      --http2-prior-knowledge  HTTP/2 without upgrade\n"), stdout);
  fputs (_("      --http3             use HTTP/3 when it is discovered\n"),
         stdout);
  fputs (_("      --http3-only        fail unless HTTP/3 can be used\n"),
         stdout);
  fputs (_("      --dns-order LIST    DNS transports (default doq,dot,doh,udp)\n"),
         stdout);
  fputs (_("      --doh-url URL       resolve names with this HTTPS server\n"),
         stdout);
  fputs (_("      --doh-insecure      do not verify the DoH certificate\n"),
         stdout);
  fputs (_("      --doq-url URL       DNS-over-QUIC server (quic://host)\n"),
         stdout);
  fputs (_("      --dot-url URL       DNS-over-TLS server (tls://host)\n"),
         stdout);
  fputs (_("      --mail-from ADDR    SMTP sender\n"), stdout);
  fputs (_("      --mail-rcpt ADDR    SMTP recipient\n"), stdout);
  fputs (_("  -h, --help              display this help and exit\n"), stdout);
  fputs (_("      --version           output version information and exit\n"),
         stdout);
  printf (_("\nReport bugs to %s.\n"), PACKAGE_BUGREPORT);
}

static void
version (void)
{
  printf ("%s %s\n", PACKAGE, twist_version ());
  printf (_("Copyright (C) %s %s\n"), "2026", "Chris Burdess <dog@gnu.org>");
  printf (_("License GPLv3+: GNU GPL version 3 or later <%s>\n"),
          "https://www.gnu.org/licenses/gpl.html");
  fputs (_("This is free software: you are free to change and redistribute it.\n"),
         stdout);
  fputs (_("There is NO WARRANTY, to the extent permitted by law.\n"), stdout);
  /* What this build has that others may not.  */
  if (twist_coding_known ("br"))
    printf ("Features: brotli\n");
}

static int
bytes_add (struct cli_bytes *b, const void *data, size_t n)
{
  if (n == 0)
    return TWIST_OK;
  if (n > b->cap - b->n)
    {
      size_t cap = b->cap == 0 ? 64 : b->cap;
      char *p;

      while (cap - b->n < n)
        {
          if (cap > (size_t) -1 / 2)
            return TWIST_ERR_NOMEM;
          cap *= 2;
        }
      p = realloc (b->p, cap);
      if (p == NULL)
        return TWIST_ERR_NOMEM;
      b->p = p;
      b->cap = cap;
    }
  memcpy (b->p + b->n, data, n);
  b->n += n;
  return TWIST_OK;
}

static int
read_stream (FILE *fp, struct cli_bytes *b, int strip)
{
  int c;

  while ((c = fgetc (fp)) != EOF)
    {
      unsigned char ch;

      if (strip && (c == '\n' || c == '\r'))
        continue;
      ch = (unsigned char) c;
      if (bytes_add (b, &ch, 1) != TWIST_OK)
        return TWIST_ERR_NOMEM;
    }
  if (ferror (fp))
    return TWIST_ERR_FILE;
  return TWIST_OK;
}

static int
read_named (const char *name, struct cli_bytes *b, int strip)
{
  FILE *fp;
  int rc;
  int close_it;

  if (strcmp (name, "-") == 0)
    {
      fp = stdin;
      close_it = 0;
    }
  else
    {
      fp = fopen (name, "rb");
      close_it = 1;
    }
  if (fp == NULL)
    return TWIST_ERR_FILE;
  rc = read_stream (fp, b, strip);
  if (close_it)
    fclose (fp);
  return rc;
}

static int
op_add_bytes (struct cli_op *op, const char *data, size_t n, int form)
{
  if (form && op->form_next && op->data_len > 0)
    {
      char *grown = realloc (op->data, op->data_len + 1 + n + 1);

      if (grown == NULL)
        return 27;
      grown[op->data_len] = '&';
      memcpy (grown + op->data_len + 1, data, n);
      op->data = grown;
      op->data_len += 1 + n;
    }
  else
    {
      char *grown = realloc (op->data, op->data_len + n + 1);

      if (grown == NULL)
        return 27;
      memcpy (grown + op->data_len, data, n);
      op->data = grown;
      op->data_len += n;
    }
  op->data[op->data_len] = 0;
  op->has_data = 1;
  op->form_next = form;
  return 0;
}

static int
add_data (struct cli_op *op, const char *text, int kind)
{
  struct cli_bytes raw;
  const char *payload = text;
  size_t n;
  int rc;
  int form = kind != 1;

  memset (&raw, 0, sizeof raw);
  if (kind != 2 && text[0] == '@')
    {
      rc = read_named (text + 1, &raw, kind == 0);
      if (rc != TWIST_OK)
        {
          char msg[256];

          free (raw.p);
          snprintf (msg, sizeof msg, _("could not read %s"), text + 1);
          if (rc == TWIST_ERR_NOMEM)
            return 27;
          diag_code (26, msg);
          return 26;
        }
      payload = raw.p != NULL ? raw.p : "";
      n = raw.n;
    }
  else
    n = strlen (text);
  rc = op_add_bytes (op, payload, n, form);
  free (raw.p);
  return rc;
}

static int
form_escape (struct cli_bytes *b, const char *s, size_t n)
{
  static const char hex[] = "0123456789ABCDEF";
  size_t i;

  for (i = 0; i < n; i++)
    {
      unsigned char c = (unsigned char) s[i];
      char tmp[3];
      size_t tn;

      if (isalnum (c) || c == '-' || c == '.' || c == '_' || c == '~')
        {
          tmp[0] = (char) c;
          tn = 1;
        }
      else if (c == ' ')
        {
          tmp[0] = '+';
          tn = 1;
        }
      else
        {
          tmp[0] = '%';
          tmp[1] = hex[c >> 4];
          tmp[2] = hex[c & 0x0f];
          tn = 3;
        }
      if (bytes_add (b, tmp, tn) != TWIST_OK)
        return 27;
    }
  return 0;
}

static int
add_urlencode (struct cli_op *op, const char *text)
{
  const char *eq = strchr (text, '=');
  const char *at = strchr (text, '@');
  const char *name = NULL;
  size_t name_n = 0;
  struct cli_bytes raw;
  struct cli_bytes enc;
  const char *value;
  size_t value_n;
  int rc;

  memset (&raw, 0, sizeof raw);
  memset (&enc, 0, sizeof enc);
  if (eq != NULL && (at == NULL || eq < at))
    {
      name = text;
      name_n = (size_t) (eq - text);
      value = eq + 1;
      value_n = strlen (value);
    }
  else if (at != NULL)
    {
      if (at != text)
        {
          name = text;
          name_n = (size_t) (at - text);
        }
      if (read_named (at + 1, &raw, 0) != TWIST_OK)
        {
          char msg[256];

          snprintf (msg, sizeof msg, _("could not read %s"), at + 1);
          diag_code (26, msg);
          return 26;
        }
      value = raw.p != NULL ? raw.p : "";
      value_n = raw.n;
    }
  else
    {
      value = text;
      value_n = strlen (text);
    }
  rc = form_escape (&enc, value, value_n);
  free (raw.p);
  if (rc != 0)
    {
      free (enc.p);
      return rc;
    }
  if (name_n > 0)
    {
      struct cli_bytes field;

      memset (&field, 0, sizeof field);
      if (bytes_add (&field, name, name_n) != TWIST_OK
          || bytes_add (&field, "=", 1) != TWIST_OK
          || bytes_add (&field, enc.p != NULL ? enc.p : "", enc.n) != TWIST_OK)
        {
          free (field.p);
          free (enc.p);
          return 27;
        }
      rc = op_add_bytes (op, field.p, field.n, 1);
      free (field.p);
    }
  else
    rc = op_add_bytes (op, enc.p != NULL ? enc.p : "", enc.n, 1);
  free (enc.p);
  return rc;
}

/* A speed: digits, and a suffix that multiplies by a power
   of 1024 (k, m, g, t, p), in either case.  No fractions, no sign.  */
static int
parse_rate (const char *s, uint64_t *out)
{
  uint64_t v = 0;
  int shift = 0;

  if (*s < '0' || *s > '9')
    return -1;
  for (; *s >= '0' && *s <= '9'; s++)
    {
      unsigned d = (unsigned) (*s - '0');

      if (v > (UINT64_MAX - d) / 10)
        return -1;
      v = v * 10 + d;
    }
  switch (*s)
    {
    case 0:
      break;
    case 'k': case 'K':
      shift = 10;
      break;
    case 'm': case 'M':
      shift = 20;
      break;
    case 'g': case 'G':
      shift = 30;
      break;
    case 't': case 'T':
      shift = 40;
      break;
    case 'p': case 'P':
      shift = 50;
      break;
    default:
      return -1;
    }
  if (*s != 0 && s[1] != 0)
    return -1;
  if (shift > 0 && v > (UINT64_MAX >> shift))
    return -1;
  *out = v << shift;
  return 0;
}

/* A count: digits and nothing else, no sign.  A number past what a long holds
   is the greatest one.  */
static int
parse_count (const char *s, long *out)
{
  long v = 0;

  if (*s < '0' || *s > '9')
    return -1;
  for (; *s >= '0' && *s <= '9'; s++)
    {
      int d = *s - '0';

      v = v > (LONG_MAX - d) / 10 ? LONG_MAX : v * 10 + d;
    }
  if (*s != 0)
    return -1;
  *out = v;
  return 0;
}

static int
parse_ms (const char *s, long *ms)
{
  const char *p = s;
  unsigned long whole = 0;
  unsigned long frac = 0;
  int digits = 0;

  if (s == NULL || s[0] == 0)
    return -1;
  while (*p >= '0' && *p <= '9')
    {
      if (whole > 1000000ul)
        return -1;
      whole = whole * 10ul + (unsigned) (*p - '0');
      p++;
    }
  if (*p == '.')
    {
      p++;
      while (*p >= '0' && *p <= '9')
        {
          if (digits < 3)
            frac = frac * 10ul + (unsigned) (*p - '0');
          digits++;
          p++;
        }
    }
  if (*p != 0)
    return -1;
  while (digits < 3)
    {
      frac *= 10ul;
      digits++;
    }
  *ms = (long) (whole * 1000ul + frac);
  return 0;
}

static int
append_item (struct cli_item **head, struct cli_item **tail, const char *text,
             int remote)
{
  struct cli_item *it = calloc (1, sizeof *it);

  if (it == NULL)
    return 27;
  it->text = text != NULL ? twist_strdup (text) : NULL;
  if (text != NULL && it->text == NULL)
    {
      free (it);
      return 27;
    }
  it->remote = remote;
  if (*tail != NULL)
    (*tail)->next = it;
  else
    *head = it;
  *tail = it;
  return 0;
}

static char *
remote_file (const char *url)
{
  struct twist_url *u = NULL;
  const char *path;
  const char *slash;
  const char *base;
  char *name;
  size_t n;
  size_t i;
  size_t o;

  if (twist_url_parse_int (url, &u) != TWIST_OK || u->path == NULL)
    {
      twist_url_free_int (u);
      return NULL;
    }
  path = u->path;
  slash = strrchr (path, '/');
  base = slash != NULL ? slash + 1 : path;
  n = strlen (base);
  name = twist_xmalloc (n + 1);
  if (name == NULL)
    {
      twist_url_free_int (u);
      return NULL;
    }
  o = 0;
  for (i = 0; i < n; i++)
    {
      unsigned char c = (unsigned char) base[i];

      if (c == '%' && i + 2 < n && isxdigit ((unsigned char) base[i + 1])
          && isxdigit ((unsigned char) base[i + 2]))
        {
          int hi = base[i + 1];
          int lo = base[i + 2];

          hi = isdigit (hi) ? hi - '0' : tolower (hi) - 'a' + 10;
          lo = isdigit (lo) ? lo - '0' : tolower (lo) - 'a' + 10;
          c = (unsigned char) ((hi << 4) | lo);
          i += 2;
        }
      if (c == 0 || c == '/')
        {
          free (name);
          twist_url_free_int (u);
          return NULL;
        }
      name[o++] = (char) c;
    }
  name[o] = 0;
  twist_url_free_int (u);
  if (o == 0)
    {
      free (name);
      return NULL;
    }
  /* A last part of "-" names a file, as curl's -O does; "-" alone is the
     name that means standard output, for -o.  */
  if (o == 1 && name[0] == '-')
    {
      free (name);
      return twist_strdup ("./-");
    }
  return name;
}

static char *
output_path (const char *dir, const char *name)
{
  size_t dn;
  size_t nn;
  char *path;

  if (name == NULL || strcmp (name, "-") == 0)
    return NULL;
  if (dir == NULL || dir[0] == 0 || name[0] == '/')
    return twist_strdup (name);
  dn = strlen (dir);
  nn = strlen (name);
  path = twist_xmalloc (dn + 1 + nn + 1);
  if (path == NULL)
    return NULL;
  memcpy (path, dir, dn);
  path[dn] = '/';
  memcpy (path + dn + 1, name, nn + 1);
  return path;
}

/* A secret given on the command line is in the list of arguments that ps
   shows for as long as the process lives, so once it has been taken the
   argument is blanked, as curl does.  */
static void
scrub_arg (char *arg)
{
  if (arg != NULL)
    memset (arg, ' ', strlen (arg));
}

static int
ensure_dirs (const struct cli_op *op, const char *path)
{
  char *copy;
  size_t i;
  size_t n;

  if (!op->create_dirs || path == NULL)
    return 0;
  copy = twist_strdup (path);
  if (copy == NULL)
    {
      diag_code (27, twist_strerror (TWIST_ERR_NOMEM));
      return 27;
    }
  n = strlen (copy);
  for (i = 1; i < n; i++)
    {
      if (copy[i] != '/')
        continue;
      copy[i] = 0;
      /* 0750, as curl makes them: what a download makes is not for everyone,
         whatever the mask is.  */
      if (mkdir (copy, 0750) < 0 && errno != EEXIST)
        {
          char msg[256];

          snprintf (msg, sizeof msg, _("could not create directory %s"), copy);
          diag_code (23, msg);
          free (copy);
          return 23;
        }
      copy[i] = '/';
    }
  free (copy);
  return 0;
}

static char *
read_password (const char *user)
{
  FILE *tty;
  struct termios saved;
  struct termios off;
  int have_term = 0;
  char *buf = NULL;
  size_t n = 0;
  size_t cap = 0;
  int c;

  tty = fopen ("/dev/tty", "r+");
  if (tty == NULL)
    return twist_strdup ("");
  if (tcgetattr (fileno (tty), &saved) == 0)
    {
      off = saved;
      off.c_lflag &= ~(tcflag_t) ECHO;
      if (tcsetattr (fileno (tty), TCSAFLUSH, &off) == 0)
        have_term = 1;
    }
  fprintf (tty, _("Enter host password for user '%s': "), user);
  fflush (tty);
  while ((c = fgetc (tty)) != EOF && c != '\n')
    {
      if (n + 1 >= cap)
        {
          size_t ncap = cap == 0 ? 64 : cap * 2;
          char *p = realloc (buf, ncap);

          if (p == NULL)
            {
              free (buf);
              buf = NULL;
              break;
            }
          buf = p;
          cap = ncap;
        }
      if (buf != NULL)
        buf[n++] = (char) c;
    }
  if (have_term)
    tcsetattr (fileno (tty), TCSAFLUSH, &saved);
  fputc ('\n', tty);
  fclose (tty);
  if (buf == NULL)
    return twist_strdup ("");
  if (n > 0 && buf[n - 1] == '\r')
    n--;
  buf[n] = 0;
  return buf;
}

static void
emit_writeout (const char *fmt, twist_transfer *transfer, int code)
{
  const char *p;

  if (fmt == NULL)
    return;
  for (p = fmt; *p != 0; p++)
    {
      if (*p == '\\' && p[1] != 0)
        {
          p++;
          if (*p == 'n')
            fputc ('\n', stdout);
          else if (*p == 'r')
            fputc ('\r', stdout);
          else if (*p == 't')
            fputc ('\t', stdout);
          else
            {
              /* Not an escape: as written, with its backslash.  */
              fputc ('\\', stdout);
              fputc (*p, stdout);
            }
        }
      else if (*p == '%' && p[1] == '%')
        {
          fputc ('%', stdout);
          p++;
        }
      else if (*p == '%' && p[1] == '{')
        {
          const char *end = strchr (p + 2, '}');
          size_t n;
          long http = 0;
          size_t size = 0;
          char *effective = NULL;
          char *ctype = NULL;

          if (end == NULL)
            {
              fputc (*p, stdout);
              continue;
            }
          n = (size_t) (end - (p + 2));
          twist_transfer_getinfo (transfer, TWISTINFO_RESPONSE_CODE, &http);
          twist_transfer_getinfo (transfer, TWISTINFO_SIZE_DOWNLOAD, &size);
          twist_transfer_getinfo (transfer, TWISTINFO_EFFECTIVE_URL,
                                  &effective);
          twist_transfer_getinfo (transfer, TWISTINFO_CONTENT_TYPE, &ctype);
          if ((n == 9 && memcmp (p + 2, "http_code", 9) == 0)
              || (n == 13 && memcmp (p + 2, "response_code", 13) == 0))
            printf ("%ld", http);
          else if (n == 13 && memcmp (p + 2, "size_download", 13) == 0)
            printf ("%zu", size);
          else if (n == 13 && memcmp (p + 2, "url_effective", 13) == 0)
            fputs (effective != NULL ? effective : "", stdout);
          else if (n == 12 && memcmp (p + 2, "content_type", 12) == 0)
            fputs (ctype != NULL ? ctype : "", stdout);
          else if (n == 12 && memcmp (p + 2, "http_version", 12) == 0)
            {
              long version = 0;

              twist_transfer_getinfo (transfer, TWISTINFO_HTTP_VERSION,
                                      &version);
              fputs (version == TWIST_HTTP_VERSION_1_0 ? "1"
                     : version == TWIST_HTTP_VERSION_1_1 ? "1.1"
                     : version == TWIST_HTTP_VERSION_2_0 ? "2"
                     : version == TWIST_HTTP_VERSION_3 ? "3" : "0", stdout);
            }
          else if (n == 8 && memcmp (p + 2, "exitcode", 8) == 0)
            printf ("%d", code);
          else if (n == 8 && memcmp (p + 2, "errormsg", 8) == 0)
            {
              const char *detail = twist_transfer_error (transfer);

              if (code != 0)
                fputs (detail != NULL ? detail
                       : twist_strerror (transfer->result), stdout);
            }
          p = end;
        }
      else
        fputc (*p, stdout);
    }
}

struct cli_job;
static FILE *job_body (struct cli_job *job);

struct cli_headers
{
  struct cli_job *job;          /* Whose body -i puts the headers in.  */
  FILE *dump;
  int include;
  int saw;
  int short_write;
};

static size_t
write_header (char *ptr, size_t size, size_t nmemb, void *userdata)
{
  struct cli_headers *h = userdata;
  size_t n = size * nmemb;

  h->saw = 1;
  if (h->include && h->job != NULL)
    {
      FILE *body = job_body (h->job);

      if (body == NULL || fwrite (ptr, 1, n, body) < n)
        h->short_write = 1;
    }
  if (h->dump != NULL && fwrite (ptr, 1, n, h->dump) < n)
    h->short_write = 1;
  return h->short_write ? 0 : n;
}

static void
finish_headers (struct cli_headers *h)
{
  if (!h->saw)
    return;
  if (h->include && h->job != NULL)
    {
      FILE *body = job_body (h->job);

      if (body == NULL || fwrite ("\r\n", 1, 2, body) < 2)
        h->short_write = 1;
    }
  if (h->dump != NULL && fwrite ("\r\n", 1, 2, h->dump) < 2)
    h->short_write = 1;
  h->saw = 0;
}

static int
is_ssh_url (const char *url)
{
  return strncmp (url, "sftp://", 7) == 0 || strncmp (url, "scp://", 6) == 0;
}

static int
is_http_url (const char *url)
{
  return strncasecmp (url, "http://", 7) == 0
         || strncasecmp (url, "https://", 8) == 0;
}

static int
is_ftp_url (const char *url)
{
  return strncasecmp (url, "ftp://", 6) == 0
         || strncasecmp (url, "ftps://", 7) == 0;
}

/* A telnet session sends what is read from standard input, or from the file
   of -T, and nothing is a request: the data of -d is not sent, and the
   transfer is not a PUT.  */
static int
is_telnet_url (const char *url)
{
  return strncasecmp (url, "telnet://", 9) == 0;
}

/* The file being uploaded, for the schemes that take it as it is read.  */
struct cli_upload
{
  int fd;
  int failed;			/* A read failed.  */
};

/* Read straight from the descriptor: what a pipe has is what is given, and
   the transfer does not wait for a whole buffer of it.  A read that fails is
   not the end of the data.  */
static size_t
read_upload (char *ptr, size_t size, size_t nmemb, void *user)
{
  struct cli_upload *u = user;
  ssize_t n;

  do
    n = read (u->fd, ptr, size * nmemb);
  while (n < 0 && errno == EINTR);
  if (n < 0)
    {
      u->failed = 1;
      return TWIST_READFUNC_ABORT;
    }
  return (size_t) n;
}

/* Start the data again from the beginning: for a file.  */
static int
seek_upload (void *user, long long offset, int origin)
{
  struct cli_upload *u = user;

  return origin == SEEK_SET && lseek (u->fd, (off_t) offset, SEEK_SET)
         == (off_t) offset ? 0 : 1;
}

/* One URL being fetched: the transfer made for it, and everything the tool
   holds for as long as it runs.  A job is made by job_prepare, handed to the
   runtime, and freed by job_finish once the transfer has ended.  */
struct cli_job
{
  struct cli_run *run;
  struct cli_op *op;
  twist_transfer *transfer;
  struct cli_job *next;         /* In the run's list of jobs under way.  */
  char *url;                    /* As written, or as a glob made it.  */
  const char *use_url;          /* What the transfer is given.  */
  const char *upload;           /* The name given to -T, or NULL.  */
  char *up_owned;               /* UPLOAD, when a -T pattern made it.  */
  FILE *body;                   /* NULL until the file is made.  */
  char *out_path;               /* The file, while it is not.  */
  const char *out_mode;
  int out_failed;               /* It could not be made.  */
  FILE *dump;
  struct cli_headers hdrs;
  struct cli_bytes up;
  struct cli_upload ustream;
  int streaming;
  char *query_url;
  char *named_url;
  struct twist_bar bar;
  int bar_used;
  int body_short;               /* A write to the body came up short.  */
  int refuse_binary;            /* The body is on a terminal by default.  */
  size_t refused_len;           /* The write it was refused in.  */
  int reads_stdin;              /* The transfer reads standard input.  */
  int aborted;                  /* Ended because another failed.  */
  struct twist_meter_xfer xfer; /* What the run's meter knows of it.  */
  int meter_added;              /* The meter has it.  */
};

static size_t
write_body (char *ptr, size_t size, size_t nmemb, void *userdata)
{
  struct cli_job *job = userdata;
  size_t n = size * nmemb;
  size_t got;
  FILE *body;

  finish_headers (&job->hdrs);
  /* What is written to a terminal because nothing said where else, and has a
     NUL in it, is binary and would only mess the terminal up.  -o - says
     that it is wanted there.  Say so, unless told not to, and write nothing:
     the transfer fails as a write that did not go.  */
  if (job->refuse_binary && memchr (ptr, 0, n) != NULL)
    {
      if (!silent)
        {
          fputs (_("Warning: Binary output can mess up your terminal. "
                   "Use \"--output -\" to tell \n"), err_fp);
          fprintf (err_fp, _("Warning: %s to output it to your terminal "
                             "anyway, or consider \"--output \n"), PACKAGE);
          fputs (_("Warning: <FILE>\" to save to a file.\n"), err_fp);
        }
      job->refused_len = n;
      job->body_short = 1;
      return 0;
    }
  body = job_body (job);
  if (body == NULL)
    {
      job->body_short = 1;
      return 0;
    }
  got = fwrite (ptr, 1, n, body);
  if (got < n)
    job->body_short = 1;
  return got;
}

/* URL with the name of FILE added, if URL names a directory (it ends in a
   slash, or has no path) and no more than that: sftp://host/dir/ becomes
   sftp://host/dir/FILE.  The name is percent-encoded.  NULL if URL needs
   nothing, or FILE has no name.  */
static char *
with_file_name (const char *url, const char *file)
{
  const char *host = strstr (url, "://");
  const char *slash, *base;
  size_t ulen = strlen (url), blen, i, o;
  int add_slash;
  char *out;

  if (host == NULL || strpbrk (url, "?#") != NULL)
    return NULL;
  slash = strchr (host + 3, '/');
  if (slash != NULL && slash[strlen (slash) - 1] != '/')
    return NULL;
  base = strrchr (file, '/');
  base = base != NULL ? base + 1 : file;
  blen = strlen (base);
  if (blen == 0 || strcmp (file, "-") == 0)
    return NULL;
  add_slash = slash == NULL;
  out = twist_xmalloc (ulen + 1 + blen * 3 + 1);
  if (out == NULL)
    return NULL;
  memcpy (out, url, ulen);
  o = ulen;
  if (add_slash)
    out[o++] = '/';
  for (i = 0; i < blen; i++)
    {
      unsigned char c = (unsigned char) base[i];

      if (isalnum (c) || c == '-' || c == '.' || c == '_' || c == '~')
        out[o++] = (char) c;
      else
        o += (size_t) sprintf (out + o, "%%%02X", c);
    }
  out[o] = 0;
  return out;
}

/* The size of the file at PATH, or 0 if there is none.  -1 if it cannot be
   looked at.  */
static long long
size_of_file (const char *path)
{
  struct stat st;

  if (stat (path, &st) != 0)
    return errno == ENOENT ? 0 : -1;
  return (long long) st.st_size;
}

/* Whether a body is written for this transfer: a download, or an upload to
   HTTP, which answers.  A tty gets no progress meter in that case, as the
   meter would be mixed up with it.  */
static int
output_expected (const char *url, const char *upload)
{
  if (upload == NULL)
    return 1;
  return strncasecmp (url, "http://", 7) == 0
         || strncasecmp (url, "https://", 8) == 0
         || is_telnet_url (url);
}

/* The work of one invocation: the operations in order, and a cursor over the
   URLs of all of them.  URLs are taken one at a time, in the order they were
   given, and a pattern is expanded as its URLs are asked for.  A job is made
   for each, and at most CAP are under way at once; they share the one
   runtime, and so the connections, names and stores it keeps, for the whole
   command line.  */
struct cli_run
{
  struct twist_runtime *runtime;
  struct cli_op *op;            /* The operation being taken from.  */
  struct cli_op *next_op;       /* The one after it.  */
  struct cli_item *url;         /* The next URL of OP.  */
  struct cli_item *out;         /* The next -o of OP.  */
  struct cli_item *up;          /* The next -T of OP.  */
  struct twist_glob *glob;      /* The pattern being expanded, or NULL.  */
  int glob_yielded;             /* How many URLs it has given.  */
  /* The file given to -T is a pattern too: for each URL of GLOB, the files of
     UP_GLOB, the URL being CUR_URL.  The globs of the URL are numbered first
     and the file's after them.  */
  struct twist_glob *up_glob;
  char *cur_url;
  const char *item_output;      /* The -o of the pattern, or NULL.  */
  int item_remote;              /* ... is -O.  */
  const char *item_upload;      /* The -T of the pattern.  */
  struct cli_job *jobs;         /* Under way.  */
  int inflight;
  int cap;                      /* Jobs under way at most.  */
  int status;                   /* What the run exits with.  */
  int stop;                     /* No more are to be started.  */
  int parallel;                 /* -Z.  */
  int stdin_taken;              /* A job has been given standard input.  */
  int refused;                  /* A job was refused for want of it.  */
  int meter_on;                 /* The one line for the run is drawn.  */
  struct twist_meter meter;
};

/* What a URL of the cursor is: its text, the output name a pattern made for
   it (to be freed), the output as given, whether that is -O, and the
   upload.  */
struct cli_next
{
  char *url;
  char *name;
  char *dir;                    /* --output-dir with its #N made, or NULL.  */
  char *up_owned;               /* The file of a -T pattern, to free.  */
  const char *output;
  int remote;
  const char *upload;
};

/* End every transfer under way, and say of each that it was for another's
   failure.  */
static void
run_abort_all (struct cli_run *run)
{
  struct cli_job *job;

  for (job = run->jobs; job != NULL; job = job->next)
    {
      job->aborted = run->parallel;
      twist_runtime_cancel (run->runtime, job->transfer);
    }
}

/* Note how a transfer ended, or what failed before there was one.  Without
   -Z the exit status is the last one's.  With -Z it is the most recent
   failure, and a transfer that was aborted for another's only fills it while
   it is empty.  --fail-early stops the run at the first failure, and in a
   parallel run so does running out of memory; both end the transfers under
   way.  */
static void
run_note (struct cli_run *run, int code, int aborted)
{
  if (!run->parallel)
    run->status = code;
  else if (code != 0 && (!aborted || run->status == 0))
    run->status = code;
  if (code != 0 && !aborted
      && (fail_early || (run->parallel && code == 27)))
    {
      run->stop = 1;
      run_abort_all (run);
    }
}

/* Fill NEXT for URL (which is taken) and FILE, the file of a -T pattern (taken,
   or NULL): #N in the URL, the output name and --output-dir are made with the
   globs as they stand.  1; or 0 if there is no memory (and nothing is left
   in NEXT).  */
static int
make_next (struct cli_run *run, struct cli_next *next, char *url, char *file)
{
  if (run->up_glob != NULL)
    {
      char *made = twist_glob_name2 (run->glob, run->up_glob, url);

      free (url);
      url = made;
      if (url == NULL)
        goto nomem;
    }
  next->url = url;
  next->up_owned = file;
  next->upload = file != NULL ? file : run->item_upload;
  if (run->item_output != NULL && !run->item_remote)
    {
      next->name = twist_glob_name2 (run->glob, run->up_glob,
                                     run->item_output);
      if (next->name == NULL)
        goto nomem;
    }
  next->output = next->name != NULL ? next->name : run->item_output;
  next->remote = run->item_remote;
  if (run->op->output_dir != NULL && strchr (run->op->output_dir, '#') != NULL)
    {
      next->dir = twist_glob_name2 (run->glob, run->up_glob,
                                    run->op->output_dir);
      if (next->dir == NULL)
        goto nomem;
    }
  return 1;
nomem:
  free (next->url);
  free (next->up_owned);
  free (next->name);
  free (next->dir);
  memset (next, 0, sizeof *next);
  return 0;
}

/* The next URL, in order, across URLs and operations: 1, or 0 when there is
   none or the run is to stop.  Trouble in producing one (a pattern that is
   wrong, no URL, no memory) is told here and noted, and the cursor goes on.  */
static int
run_next_url (struct cli_run *run, struct cli_next *next)
{
  int rc;

  memset (next, 0, sizeof *next);
  for (;;)
    {
      if (run->stop)
        return 0;
      if (run->glob != NULL)
        {
          char *url = NULL;

          /* The files of -T for the URL the outer loop is at.  */
          if (run->up_glob != NULL)
            {
              char *file = NULL;

              rc = twist_glob_next (run->up_glob, &file);
              if (rc == 1)
                {
                  char *copy = twist_strdup (run->cur_url);

                  if (copy == NULL || !make_next (run, next, copy, file))
                    {
                      free (file);
                      diag_code (27, twist_strerror (TWIST_ERR_NOMEM));
                      run_note (run, 27, 0);
                      continue;
                    }
                  return 1;
                }
              twist_glob_free (run->up_glob);
              run->up_glob = NULL;
              free (run->cur_url);
              run->cur_url = NULL;
              if (rc < 0)
                {
                  diag_code (27, twist_strerror (TWIST_ERR_NOMEM));
                  run_note (run, 27, 0);
                }
              continue;
            }
          rc = twist_glob_next (run->glob, &url);
          if (rc == 1)
            {
              run->glob_yielded++;
              if (run->item_upload != NULL)
                {
                  char err[1200];
                  int prc = twist_glob_parse (run->item_upload, &run->up_glob,
                                              err, sizeof err);

                  if (prc != TWIST_OK)
                    {
                      /* The same pattern would fail with every URL.  */
                      free (url);
                      run->up_glob = NULL;
                      if (prc == TWIST_ERR_URL)
                        {
                          diag_code (3, err);
                          run_note (run, 3, 0);
                        }
                      else
                        {
                          diag_code (27, twist_strerror (prc));
                          run_note (run, 27, 0);
                        }
                      twist_glob_free (run->glob);
                      run->glob = NULL;
                      continue;
                    }
                  run->cur_url = url;
                  continue;
                }
              if (!make_next (run, next, url, NULL))
                {
                  diag_code (27, twist_strerror (TWIST_ERR_NOMEM));
                  run_note (run, 27, 0);
                  twist_glob_free (run->glob);
                  run->glob = NULL;
                  continue;
                }
              return 1;
            }
          if (rc < 0)
            {
              diag_code (27, twist_strerror (TWIST_ERR_NOMEM));
              run_note (run, 27, 0);
            }
          else if (run->glob_yielded == 0)
            run_note (run, 0, 0);
          twist_glob_free (run->glob);
          run->glob = NULL;
          continue;
        }
      if (run->url == NULL)
        {
          /* The operation is used up: on to the next.  */
          run->op = run->next_op;
          if (run->op == NULL)
            return 0;
          run->next_op = run->op->next;
          if (run->op->urls == NULL)
            {
              diag (_("no URL specified"));
              suggest ();
              run_note (run, 2, 0);
              continue;
            }
          run->url = run->op->urls;
          run->out = run->op->outputs;
          run->up = run->op->uploads;
          continue;
        }
      {
        struct cli_item *item = run->url;
        const char *output = NULL;
        int remote = 0;
        const char *upload = NULL;

        run->url = item->next;
        if (run->out != NULL)
          {
            output = run->out->remote ? NULL : run->out->text;
            remote = run->out->remote;
            run->out = run->out->next;
          }
        if (run->up != NULL)
          {
            upload = run->up->text;
            run->up = run->up->next;
          }
        if (run->op->globoff)
          {
            char *url = twist_strdup (item->text);

            if (url == NULL)
              {
                diag_code (27, twist_strerror (TWIST_ERR_NOMEM));
                run_note (run, 27, 0);
                continue;
              }
            next->url = url;
            next->output = output;
            next->remote = remote;
            next->upload = upload;
            return 1;
          }
        else
          {
            char err[1200];
            struct twist_glob *g = NULL;

            rc = twist_glob_parse (item->text, &g, err, sizeof err);
            if (rc == TWIST_ERR_URL)
              {
                diag_code (3, err);
                run_note (run, 3, 0);
              }
            else if (rc != TWIST_OK)
              {
                diag_code (27, twist_strerror (rc));
                run_note (run, 27, 0);
              }
            else
              {
                run->glob = g;
                run->glob_yielded = 0;
                run->item_output = output;
                run->item_remote = remote;
                run->item_upload = upload;
              }
          }
      }
    }
}

/* The file the body goes in is made when something is first to go in it,
   as the curl tool does: a transfer that fails before there is any body leaves
   no file, and does not empty one that was there.  NULL if it cannot be made.  */
static FILE *
job_body (struct cli_job *job)
{
  if (job->body == NULL && job->out_path != NULL && !job->out_failed)
    {
      job->body = fopen (job->out_path, job->out_mode);
      if (job->body == NULL)
        job->out_failed = 1;
    }
  return job->body;
}

static void
job_free (struct cli_job *job)
{
  if (job == NULL)
    return;
  free (job->out_path);
  if (job->body != NULL && job->body != stdout)
    fclose (job->body);
  if (job->dump != NULL && job->dump != stdout)
    fclose (job->dump);
  if (job->streaming && job->ustream.fd != STDIN_FILENO)
    close (job->ustream.fd);
  twist_transfer_free (job->transfer);
  free (job->up.p);
  free (job->query_url);
  free (job->named_url);
  free (job->url);
  free (job->up_owned);
  free (job);
}

/* Make the job for the URL NEXT gives, and set up its transfer: the options
   of the operation, then what is particular to this URL.  Returns 0 and the
   job, or the exit status of what went wrong, which has been told.  The URL
   is taken over.  */
static int
job_prepare (struct cli_run *run, struct cli_next *next, struct cli_job **out)
{
  struct cli_op *op = run->op;
  struct cli_job *job;
  struct cli_opt *opt;
  twist_transfer *transfer;
  const char *url;
  const char *output = next->output;
  const char *upload = next->upload;
  char *out_name = NULL;
  char *out_path = NULL;
  static char empty_body[] = "";
  char *payload = NULL;
  size_t payload_n = 0;
  const char *method = op->method;
  const char *body_mode = "wb";
  long long resume = 0;
  int hide_progress;
  int rc;

  *out = NULL;
  job = calloc (1, sizeof *job);
  if (job == NULL)
    {
      free (next->url);
      next->url = NULL;
      free (next->up_owned);
      next->up_owned = NULL;
      diag_code (27, twist_strerror (TWIST_ERR_NOMEM));
      return 27;
    }
  job->run = run;
  job->op = op;
  job->url = next->url;
  next->url = NULL;
  job->upload = upload;
  /* The file of a -T pattern is the job's now.  */
  job->up_owned = next->up_owned;
  next->up_owned = NULL;
  job->body = stdout;
  job->ustream.fd = -1;
  job->use_url = job->url;
  url = job->url;
  /* A transfer reads standard input when it is told to send it, or is a
     telnet session that is given nothing else to send.  */
  job->reads_stdin = (upload != NULL && strcmp (upload, "-") == 0)
                     || (upload == NULL && is_telnet_url (url));
  if (run->parallel && job->reads_stdin)
    {
      if (run->stdin_taken)
        {
          diag_code (2, _("only one transfer can read standard input "
                          "with --parallel"));
          run->refused = 1;
          rc = 2;
          goto fail;
        }
      run->stdin_taken = 1;
    }
  if (next->remote)
    {
      out_name = remote_file (url);
      if (out_name == NULL)
        {
          diag_code (23, _("remote file name has no length"));
          rc = 23;
          goto fail;
        }
    }
  else if (output != NULL)
    out_name = twist_strdup (output);
  out_path = output_path (next->dir != NULL ? next->dir : op->output_dir,
                          out_name);
  free (out_name);
  if (output != NULL && strcmp (output, "-") != 0 && out_path == NULL)
    {
      diag_code (27, twist_strerror (TWIST_ERR_NOMEM));
      rc = 27;
      goto fail;
    }
  if ((rc = ensure_dirs (op, out_path)) != 0)
    goto fail;
  if (op->limit_rate != 0 && strncmp (url, "tftp:", 5) == 0)
    {
      /* A limit that is not kept is worse than none.  */
      diag_code (2, _("--limit-rate does not work for tftp"));
      rc = 2;
      goto fail;
    }
  if (op->resume_set)
    {
      int sends = upload != NULL || (op->has_data && !op->get);

      if (!is_ssh_url (url) && !is_ftp_url (url))
        {
          diag_code (2, _("--continue-at works for sftp, scp, ftp and ftps only"));
          rc = 2;
          goto fail;
        }
      if (sends)
        resume = op->resume_auto ? -1 : op->resume_off;
      else
        {
          /* A download goes on at the end of what is in the file, which is
             opened to add to it.  */
          if (op->resume_auto)
            {
              if (out_path == NULL)
                {
                  diag_code (2, _("--continue-at - needs an output file"));
                  rc = 2;
                  goto fail;
                }
              resume = size_of_file (out_path);
              if (resume < 0)
                {
                  char msg[256];

                  snprintf (msg, sizeof msg, _("could not read %s"), out_path);
                  diag_code (23, msg);
                  rc = 23;
                  goto fail;
                }
            }
          else
            resume = op->resume_off;
          body_mode = "ab";
        }
    }
  if (out_path != NULL)
    {
      /* Made when there is something to put in it (job_body).  */
      job->body = NULL;
      job->out_path = out_path;
      job->out_mode = body_mode;
      out_path = NULL;
    }
  job->refuse_binary = job->body == stdout && output == NULL
                       && isatty (fileno (stdout));
  free (out_path);
  out_path = NULL;
  if (op->dump_header != NULL && strcmp (op->dump_header, "-") != 0)
    {
      job->dump = fopen (op->dump_header, "wb");
      if (job->dump == NULL)
        {
          char msg[256];

          snprintf (msg, sizeof msg, _("could not write %s"), op->dump_header);
          diag_code (23, msg);
          rc = 23;
          goto fail;
        }
    }
  else if (op->dump_header != NULL)
    job->dump = stdout;
  if (upload != NULL && is_telnet_url (url) && strcmp (upload, "-") == 0)
    {
      /* Standard input is what a telnet session reads when it is given
         nothing else, as it is watched and not read to its end first.  */
    }
  else if (upload != NULL && (is_ssh_url (url) || is_telnet_url (url)
                              || streams_upload (url)))
    {
      /* Sent as it is read, so that a large file, or a pipe, is not held in
         memory first.  */
      job->ustream.fd = strcmp (upload, "-") == 0 ? STDIN_FILENO
                        : open (upload, O_RDONLY);
      if (job->ustream.fd < 0)
        {
          char msg[256];

          snprintf (msg, sizeof msg, _("could not read %s"), upload);
          diag_code (26, msg);
          rc = 26;
          goto fail;
        }
      job->streaming = 1;
      if (method == NULL && !is_telnet_url (url))
        method = "PUT";
    }
  else if (upload != NULL)
    {
      if (read_named (upload, &job->up, 0) != TWIST_OK)
        {
          char msg[256];

          snprintf (msg, sizeof msg, _("could not read %s"), upload);
          diag_code (26, msg);
          rc = 26;
          goto fail;
        }
      payload = job->up.p != NULL ? job->up.p : empty_body;
      payload_n = job->up.n;
      if (method == NULL)
        method = "PUT";
    }
  else if (op->has_data && !op->get && !is_telnet_url (url))
    {
      payload = op->data != NULL ? op->data : empty_body;
      payload_n = op->data_len;
    }
  if (op->get && op->has_data)
    {
      const char *q = strchr (url, '?');
      size_t ulen = strlen (url);
      char *joined = twist_xmalloc (ulen + 1 + op->data_len + 1);

      if (joined == NULL)
        {
          diag_code (27, twist_strerror (TWIST_ERR_NOMEM));
          rc = 27;
          goto fail;
        }
      memcpy (joined, url, ulen);
      joined[ulen] = q != NULL ? '&' : '?';
      memcpy (joined + ulen + 1, op->data != NULL ? op->data : "", op->data_len);
      joined[ulen + 1 + op->data_len] = 0;
      job->query_url = joined;
      job->use_url = job->query_url;
      payload = NULL;
      /* The data goes in the URL; nothing is uploaded.  */
      if (job->streaming && job->ustream.fd != STDIN_FILENO)
        close (job->ustream.fd);
      job->streaming = 0;
    }
  job->hdrs.job = job;
  job->hdrs.dump = job->dump;
  job->hdrs.include = op->include;
  /* An upload to a directory goes to the file with the name it has here.  */
  if (upload != NULL && (is_ssh_url (job->use_url) || is_ftp_url (job->use_url)
                         || is_http_url (job->use_url)))
    {
      job->named_url = with_file_name (job->use_url, upload);
      if (job->named_url != NULL)
        job->use_url = job->named_url;
    }
  transfer = twist_transfer_new ();
  if (transfer == NULL)
    {
      diag_code (27, twist_strerror (TWIST_ERR_NOMEM));
      rc = 27;
      goto fail;
    }
  job->transfer = transfer;
  /* What the command line set for the operation, in the order it was given,
     and then what is particular to this URL.  */
  for (opt = op->opts; opt != NULL; opt = opt->next)
    {
      if (opt->is_str)
        twist_transfer_setopt (transfer, opt->opt, opt->str);
      else
        twist_transfer_setopt (transfer, opt->opt, opt->num);
    }
  twist_transfer_setopt (transfer, TWISTOPT_PIPEWAIT,
                         parallel_immediate ? 0L : 1L);
  twist_transfer_setopt (transfer, TWISTOPT_URL, job->use_url);
  twist_transfer_setopt (transfer, TWISTOPT_RESUME_FROM, resume);
  twist_transfer_setopt (transfer, TWISTOPT_CUSTOMREQUEST, method);
  twist_transfer_setopt (transfer, TWISTOPT_NOBODY, op->head ? 1L : 0L);
  twist_transfer_setopt (transfer, TWISTOPT_POSTFIELDS, payload);
  {
    /* What an upload from a file comes to, for the progress.  */
    struct stat ust;
    long long usize = -1;

    if (job->streaming && fstat (job->ustream.fd, &ust) == 0
        && S_ISREG (ust.st_mode))
      {
        usize = (long long) ust.st_size;
        /* A file can be read again from the start, as a redirect or a second
           request for authentication needs; a pipe cannot.  */
        twist_transfer_setopt (transfer, TWISTOPT_SEEKFUNCTION, seek_upload);
        twist_transfer_setopt (transfer, TWISTOPT_SEEKDATA, &job->ustream);
      }
    twist_transfer_setopt (transfer, TWISTOPT_INFILESIZE, usize);
  }
  /* The meter is drawn unless -s or --no-progress-meter says not, or the
     body is going to the terminal.  -# draws a bar instead.  Transfers that
     run together are drawn as one line for the run, which -# does not
     change, and which was decided on for all of them at the start.  */
  if (run->parallel)
    hide_progress = !run->meter_on;
  else
    hide_progress = silent || no_progress
                    || (job->body == stdout
                        && output_expected (job->use_url, upload)
                        && isatty (fileno (stdout)));
  twist_transfer_setopt (transfer, TWISTOPT_STDERR, err_fp);
  twist_transfer_setopt (transfer, TWISTOPT_NOPROGRESS,
                         hide_progress ? 1L : 0L);
  if (run->parallel && !hide_progress)
    {
      twist_transfer_setopt (transfer, TWISTOPT_XFERINFOFUNCTION,
                             twist_meter_callback);
      twist_transfer_setopt (transfer, TWISTOPT_XFERINFODATA, &job->xfer);
    }
  else if (progress_bar && !hide_progress)
    {
      twist_bar_init (&job->bar, err_fp, op->resume_set ? resume : 0);
      job->bar_used = 1;
      twist_transfer_setopt (transfer, TWISTOPT_XFERINFOFUNCTION,
                             twist_bar_callback);
      twist_transfer_setopt (transfer, TWISTOPT_XFERINFODATA, &job->bar);
    }
  else
    {
      twist_transfer_setopt (transfer, TWISTOPT_XFERINFOFUNCTION, NULL);
      twist_transfer_setopt (transfer, TWISTOPT_XFERINFODATA, NULL);
    }
  twist_transfer_setopt (transfer, TWISTOPT_READFUNCTION,
                         job->streaming ? read_upload : NULL);
  twist_transfer_setopt (transfer, TWISTOPT_READDATA,
                         job->streaming ? &job->ustream : NULL);
  if (payload != NULL)
    twist_transfer_setopt (transfer, TWISTOPT_POSTFIELDSIZE, (long) payload_n);
  twist_transfer_setopt (transfer, TWISTOPT_HTTPHEADER,
                         op->headers != NULL ? op->headers : NULL);
  twist_transfer_setopt (transfer, TWISTOPT_TELNETOPTIONS, op->telnet);
  /* A telnet session sends what is read from standard input, unless it is
     given a file to send.  The library takes no descriptor for granted.  */
  twist_transfer_setopt (transfer, TWISTOPT_TELNET_INPUT_FD,
                         is_telnet_url (job->use_url) && !job->streaming
                         ? (long) STDIN_FILENO : -1L);
  twist_transfer_setopt (transfer, TWISTOPT_MAIL_FROM, op->mail_from);
  twist_transfer_setopt (transfer, TWISTOPT_MAIL_RCPT, op->rcpts);
  twist_transfer_setopt (transfer, TWISTOPT_MAX_RECV_SPEED_LARGE,
                         op->limit_rate);
  twist_transfer_setopt (transfer, TWISTOPT_MAX_SEND_SPEED_LARGE,
                         op->limit_rate);
  /* Only an sftp URL takes them; to any other they mean nothing, so a command line of several kinds of URL works.  */
  twist_transfer_setopt (transfer, TWISTOPT_QUOTE,
                         strncmp (job->use_url, "sftp://",
                                  7) == 0 ? op->quote : NULL);
  twist_transfer_setopt (transfer, TWISTOPT_POSTQUOTE,
                         strncmp (job->use_url, "sftp://", 7) == 0
                         ? op->postquote : NULL);
  twist_transfer_setopt (transfer, TWISTOPT_CREATE_MISSING_DIRS,
                         op->ftp_create_dirs
                         && strncmp (job->use_url, "sftp://", 7) == 0
                         ? 1L : 0L);
  twist_transfer_setopt (transfer, TWISTOPT_WRITEFUNCTION, write_body);
  twist_transfer_setopt (transfer, TWISTOPT_WRITEDATA, job);
  if (op->include || job->dump != NULL)
    {
      twist_transfer_setopt (transfer, TWISTOPT_HEADERFUNCTION, write_header);
      twist_transfer_setopt (transfer, TWISTOPT_HEADERDATA, &job->hdrs);
    }
  else
    {
      twist_transfer_setopt (transfer, TWISTOPT_HEADERFUNCTION, NULL);
      twist_transfer_setopt (transfer, TWISTOPT_HEADERDATA, NULL);
    }
  *out = job;
  return 0;

fail:
  free (out_path);
  job_free (job);
  return rc;
}

/* The transfer of JOB has ended with RC: close what it used, say what went
   wrong, write out what -w asks for, and free the job.  Returns the exit
   status for it.  */
static int
job_finish (struct cli_job *job, int rc)
{
  struct cli_op *op = job->op;
  twist_transfer *transfer = job->transfer;
  int code;
  const char *detail;
  char refused[320];
  int write_failed;

  finish_headers (&job->hdrs);
  /* A transfer that worked and had no body still makes the file.  */
  if (job->body == NULL && job->out_path != NULL && rc == TWIST_OK
      && job_body (job) == NULL)
    job->body_short = 1;
  if (job->body == NULL)
    ;
  else if (job->body != stdout)
    {
      if (fclose (job->body) != 0 && rc == TWIST_OK)
        rc = TWIST_ERR_ABORTED;
    }
  else
    fflush (job->body);
  job->body = NULL;
  if (job->dump != NULL && job->dump != stdout)
    fclose (job->dump);
  job->dump = NULL;
  if (job->streaming && job->ustream.fd != STDIN_FILENO)
    close (job->ustream.fd);
  job->streaming = 0;
  code = cli_status (rc, job->use_url);
  if (transfer->proto_status != 0)
    code = transfer->proto_status;
  if (job->ustream.failed)
    {
      char msg[256];

      snprintf (msg, sizeof msg, _("could not read %s"), job->upload);
      diag_code (26, msg);
      emit_writeout (op->writeout, transfer, 26);
      if (job->bar_used)
        twist_bar_finish (&job->bar);
      job_free (job);
      return 26;
    }
  write_failed = (job->body_short || job->hdrs.short_write)
                 && (code == 0 || code == 42);
  if (write_failed)
    code = 23;
  if (code != 0)
    {
      detail = job->aborted ? NULL : twist_transfer_error (transfer);
      if (job->aborted)
        detail = _("Transfer aborted due to critical error in another "
                   "transfer");
      if (write_failed && detail == NULL && job->refused_len > 0)
        {
          snprintf (refused, sizeof refused,
                    _("client returned ERROR on write of %zu bytes"),
                    job->refused_len);
          detail = refused;
        }
      if (write_failed && detail == NULL && job->out_failed
          && job->out_path != NULL)
        {
          snprintf (refused, sizeof refused, _("could not write %s"),
                    job->out_path);
          detail = refused;
        }
      if (write_failed && detail == NULL)
        detail = _("failure writing output to destination");
      diag_code (code, detail != NULL ? detail : twist_strerror (rc));
    }
  emit_writeout (op->writeout, transfer, code);
  /* After the message: the bar's line ends last.  */
  if (job->bar_used)
    twist_bar_finish (&job->bar);
  job_free (job);
  return code;
}

/* The transfer of JOB has ended, or the loop failed under it.  */
static void
run_job_ended (struct cli_job *job, int rc)
{
  struct cli_run *run = job->run;
  struct cli_job **link;
  int aborted;

  for (link = &run->jobs; *link != NULL; link = &(*link)->next)
    if (*link == job)
      {
        *link = job->next;
        break;
      }
  run->inflight--;
  if (job->meter_added)
    twist_meter_done (&run->meter, &job->xfer);
  /* It was aborted only if that is how it ended.  */
  job->aborted = job->aborted && rc == TWIST_ERR_ABORTED;
  aborted = job->aborted;
  run_note (run, job_finish (job, rc), aborted);
}

/* Called from the loop, when the transfer has ended.  */
static void
job_done (twist_transfer *transfer, int result, void *user)
{
  (void) transfer;
  run_job_ended (user, result);
}

static void
run_start (struct cli_run *run, struct cli_job *job)
{
  int rc;

  job->next = run->jobs;
  run->jobs = job;
  run->inflight++;
  /* Let the loop see what happened to the connections kept since the last
     transfer, so that one the server has closed is not taken.  */
  twist_runtime_run_once (run->runtime, 0);
  if (run->stop)
    {
      /* A transfer that ended just now has stopped the run.  */
      job->aborted = 1;
      run_job_ended (job, TWIST_ERR_ABORTED);
      return;
    }
  if (run->meter_on)
    {
      twist_meter_add (&run->meter, &job->xfer);
      job->meter_added = 1;
    }
  rc = twist_runtime_start (run->runtime, job->transfer, job_done, job);
  if (rc != TWIST_OK)
    run_job_ended (job, rc);
}

/* Start jobs while there is room for them and URLs for them.  A URL that
   cannot be made into a job is told, noted, and passed over.  */
static void
run_fill (struct cli_run *run)
{
  struct cli_next next;

  while (!run->stop && run->inflight < run->cap && run_next_url (run, &next))
    {
      struct cli_job *job;
      int code = job_prepare (run, &next, &job);

      free (next.name);
      free (next.dir);
      free (next.up_owned);
      if (code != 0)
        run_note (run, code, 0);
      else
        run_start (run, job);
    }
}

/* The loop has failed with RC.  End every transfer, and let the loop report
   it if it can; what it cannot is ended here.  */
static void
run_loop_failed (struct cli_run *run, int rc)
{
  if (run->parallel)
    run->stop = 1;
  run_abort_all (run);
  twist_runtime_run_once (run->runtime, 0);
  while (run->jobs != NULL)
    run_job_ended (run->jobs, rc);
}

static uint64_t
clock_ms (void)
{
  struct timespec ts;

  clock_gettime (CLOCK_MONOTONIC, &ts);
  return (uint64_t) ts.tv_sec * 1000u + (uint64_t) ts.tv_nsec / 1000000u;
}

/* Whether some URL of the command line writes its body to a terminal: it has
   no file to go to, and is not an upload that sends nothing back.  The line
   for a parallel run would be mixed up with it.  */
static int
body_to_terminal (const struct cli_op *ops)
{
  const struct cli_op *op;

  if (!isatty (fileno (stdout)))
    return 0;
  for (op = ops; op != NULL; op = op->next)
    {
      const struct cli_item *url;
      const struct cli_item *out = op->outputs;
      const struct cli_item *up = op->uploads;

      for (url = op->urls; url != NULL; url = url->next)
        {
          int named = out != NULL
                      && (out->remote || strcmp (out->text, "-") != 0);
          const char *upload = up != NULL ? up->text : NULL;

          if (out != NULL)
            out = out->next;
          if (up != NULL)
            up = up->next;
          if (!named && output_expected (url->text, upload))
            return 1;
        }
    }
  return 0;
}

/* Run everything on the command line, and return the exit status.  */
static int
run_all (struct cli_op *ops)
{
  struct cli_run run;

  memset (&run, 0, sizeof run);
  run.next_op = ops;
  run.parallel = parallel;
  run.cap = parallel ? (int) parallel_max : 1;
  run.meter_on = parallel && !silent && !no_progress
                 && !body_to_terminal (ops);
  twist_meter_init (&run.meter, err_fp, clock_ms ());
  run.runtime = twist_runtime_new ();
  if (run.runtime == NULL)
    {
      diag_code (27, twist_strerror (TWIST_ERR_NOMEM));
      return 27;
    }
  if (threads > 1
      && twist_runtime_setopt (run.runtime, TWIST_RUNTIMEOPT_THREADS, threads)
         != TWIST_OK)
    {
      diag_code (27, twist_strerror (TWIST_ERR_NOMEM));
      twist_runtime_free (run.runtime);
      return 27;
    }
  if (parallel && parallel_max_host > 0)
    twist_runtime_setopt (run.runtime, TWIST_RUNTIMEOPT_MAX_HOST_CONNECTIONS,
                          parallel_max_host);
  for (;;)
    {
      int rc;

      run_fill (&run);
      if (run.inflight == 0)
        break;
      if (run.meter_on)
        twist_meter_draw (&run.meter, clock_ms (), 0);
      rc = twist_runtime_run_once (run.runtime, run.meter_on ? 500 : -1);
      if (rc != TWIST_OK)
        run_loop_failed (&run, rc);
    }
  if (run.meter_on && run.meter.started > 0)
    twist_meter_draw (&run.meter, clock_ms (), 1);
  twist_glob_free (run.glob);
  twist_glob_free (run.up_glob);
  free (run.cur_url);
  twist_runtime_free (run.runtime);
  /* A command line that asks for two readers of standard input is wrong,
     whatever else happened.  */
  return run.refused ? 2 : run.status;
}

static void
free_items (struct cli_item *it)
{
  while (it != NULL)
    {
      struct cli_item *next = it->next;

      free (it->text);
      free (it);
      it = next;
    }
}

static void
free_op (struct cli_op *op)
{
  free_items (op->urls);
  free_items (op->outputs);
  free_items (op->uploads);
  free (op->data);
  free (op->method);
  free (op->dump_header);
  free (op->writeout);
  free (op->mail_from);
  free (op->output_dir);
  twist_slist_free_all (op->headers);
  twist_slist_free_all (op->rcpts);
  twist_slist_free_all (op->quote);
  twist_slist_free_all (op->postquote);
  twist_slist_free_all (op->telnet);
  while (op->opts != NULL)
    {
      struct cli_opt *next = op->opts->next;

      /* It may be a password.  */
      if (op->opts->str != NULL)
        memset (op->opts->str, 0, strlen (op->opts->str));
      free (op->opts->str);
      free (op->opts);
      op->opts = next;
    }
  free (op);
}

static struct cli_op *
new_op (void)
{
  struct cli_op *op = calloc (1, sizeof *op);

  if (op == NULL)
    return NULL;
  return op;
}

/* A transfer that is never started.  An option is tried on it when the
   command line is read, so that one the library will not take is told then,
   and not when the first transfer is made.  What the library accepts for an
   option does not depend on any other, so one does for every operation.  */
static twist_transfer *validator;

/* Set the option for the transfers of OP.  Returns what the library says of
   it: an option it refuses is not kept.  */
static int
op_set_record (struct cli_op *op, int opt, int is_str, long num,
               const char *str)
{
  struct cli_opt *o;
  int rc;

  if (is_str)
    rc = twist_transfer_setopt (validator, opt, str);
  else
    rc = twist_transfer_setopt (validator, opt, num);
  if (rc != TWIST_OK)
    return rc;
  o = calloc (1, sizeof *o);
  if (o == NULL)
    return TWIST_ERR_NOMEM;
  o->opt = opt;
  o->is_str = is_str;
  o->num = num;
  if (is_str && str != NULL)
    {
      /* A copy now, as the caller scrubs the argument.  */
      o->str = twist_strdup (str);
      if (o->str == NULL)
        {
          free (o);
          return TWIST_ERR_NOMEM;
        }
    }
  if (op->opts_tail != NULL)
    op->opts_tail->next = o;
  else
    op->opts = o;
  op->opts_tail = o;
  return TWIST_OK;
}

static int
op_set_long (struct cli_op *op, int opt, long num)
{
  return op_set_record (op, opt, 0, num, NULL);
}

static int
op_set_str (struct cli_op *op, int opt, const char *str)
{
  return op_set_record (op, opt, 1, 0, str);
}

/* --expand-NAME is any option that takes a parameter, with variables expanded
   in it.  The table of long options gets a twin for each of those, whose value
   has this bit set.  */
#define EXPAND_BIT (1 << 16)

/* --no-NAME is the option that is a switch, turned off.  The table of long
   options has an entry for each, whose value has this bit set; the option
   itself is handled with it taken off, and NEGATE says it was there.  */
#define NEGATE_BIT (1 << 17)

static struct option *
expand_options (const struct option *longs)
{
  size_t n = 0, i, o = 0, names = 0;
  struct option *out;
  char *at;

  while (longs[n].name != NULL)
    {
      if (longs[n].has_arg == required_argument)
        names += strlen (longs[n].name) + sizeof "expand-";
      n++;
    }
  /* The table, and the names of the twins after it: one block to free.  */
  out = calloc (1, (2 * n + 1) * sizeof *out + names);
  if (out == NULL)
    return NULL;
  at = (char *) (out + 2 * n + 1);
  for (i = 0; i < n; i++)
    out[o++] = longs[i];
  for (i = 0; i < n; i++)
    if (longs[i].has_arg == required_argument)
      {
        size_t len = strlen (longs[i].name) + sizeof "expand-";

        snprintf (at, len, "expand-%s", longs[i].name);
        out[o].name = at;
        out[o].has_arg = required_argument;
        out[o].flag = NULL;
        out[o].val = longs[i].val | EXPAND_BIT;
        o++;
        at += len;
      }
  return out;
}

/* The long name of the option with this value.  */
static const char *
option_name (const struct option *longs, int val)
{
  size_t i;

  for (i = 0; longs[i].name != NULL; i++)
    if (longs[i].val == val)
      return longs[i].name;
  return "?";
}

int
main (int argc, char **argv)
{
  static const struct option longs[] = {
    { "output", required_argument, NULL, 'o' },
    { "remote-name", no_argument, NULL, 'O' },
    { "no-remote-name", no_argument, NULL, NEGATE_BIT | 'O' },
    { "output-dir", required_argument, NULL, 22 },
    { "create-dirs", no_argument, NULL, 23 },
    { "no-create-dirs", no_argument, NULL, NEGATE_BIT | 23 },
    { "request", required_argument, NULL, 'X' },
    { "header", required_argument, NULL, 'H' },
    { "data", required_argument, NULL, 'd' },
    { "data-binary", required_argument, NULL, 24 },
    { "data-raw", required_argument, NULL, 25 },
    { "data-urlencode", required_argument, NULL, 26 },
    { "get", no_argument, NULL, 'G' },
    { "no-get", no_argument, NULL, NEGATE_BIT | 'G' },
    { "upload-file", required_argument, NULL, 'T' },
    { "append", no_argument, NULL, 'a' },
    { "proxytunnel", no_argument, NULL, 'p' },
    { "no-proxytunnel", no_argument, NULL, NEGATE_BIT | 'p' },
    { "no-append", no_argument, NULL, NEGATE_BIT | 'a' },
    { "telnet-option", required_argument, NULL, 't' },
    { "head", no_argument, NULL, 'I' },
    { "no-head", no_argument, NULL, NEGATE_BIT | 'I' },
    { "include", no_argument, NULL, 'i' },
    { "no-include", no_argument, NULL, NEGATE_BIT | 'i' },
    { "dump-header", required_argument, NULL, 'D' },
    { "location", no_argument, NULL, 'L' },
    { "no-location", no_argument, NULL, NEGATE_BIT | 'L' },
    { "max-redirs", required_argument, NULL, 1 },
    { "fail", no_argument, NULL, 'f' },
    { "no-fail", no_argument, NULL, NEGATE_BIT | 'f' },
    { "fail-early", no_argument, NULL, 27 },
    { "no-fail-early", no_argument, NULL, NEGATE_BIT | 27 },
    { "parallel", no_argument, NULL, 'Z' },
    { "no-parallel", no_argument, NULL, 53 },
    { "parallel-max", required_argument, NULL, 54 },
    { "parallel-immediate", no_argument, NULL, 55 },
    { "no-parallel-immediate", no_argument, NULL, 56 },
    { "parallel-max-host", required_argument, NULL, 57 },
    { "threads", required_argument, NULL, 59 },
    { "proto-redir", required_argument, NULL, 60 },
    { "compressed", no_argument, NULL, 30 },
    { "no-compressed", no_argument, NULL, NEGATE_BIT | 30 },
    { "content-encoding", required_argument, NULL, 31 },
    { "insecure", no_argument, NULL, 'k' },
    { "no-insecure", no_argument, NULL, NEGATE_BIT | 'k' },
    { "cert", required_argument, NULL, 'E' },
    { "key", required_argument, NULL, 15 },
    { "pass", required_argument, NULL, 32 },
    { "hostpubsha256", required_argument, NULL, 33 },
    { "cacert", required_argument, NULL, 16 },
    { "capath", required_argument, NULL, 44 },
    { "proxy-cacert", required_argument, NULL, 46 },
    { "proxy-insecure", no_argument, NULL, 47 },
    { "no-proxy-insecure", no_argument, NULL, NEGATE_BIT | 47 },
    { "proxy-template-udp", required_argument, NULL, 48 },
    { "noproxy", required_argument, NULL, 45 },
    { "ssl", no_argument, NULL, 51 },
    { "no-ssl", no_argument, NULL, NEGATE_BIT | 51 },
    { "ftp-ssl", no_argument, NULL, 51 },
    { "ssl-reqd", no_argument, NULL, 52 },
    { "no-ssl-reqd", no_argument, NULL, NEGATE_BIT | 52 },
    { "ftp-ssl-reqd", no_argument, NULL, 52 },
    { "unix-socket", required_argument, NULL, 49 },
    { "abstract-unix-socket", required_argument, NULL, 50 },
    { "proxy", required_argument, NULL, 'x' },
    { "proxy-user", required_argument, NULL, 'U' },
    { "user-agent", required_argument, NULL, 'A' },
    { "user", required_argument, NULL, 'u' },
    { "referer", required_argument, NULL, 'e' },
    { "range", required_argument, NULL, 'r' },
    { "continue-at", required_argument, NULL, 'C' },
    { "list-only", no_argument, NULL, 'l' },
    { "no-list-only", no_argument, NULL, NEGATE_BIT | 'l' },
    { "quote", required_argument, NULL, 'Q' },
    { "ftp-create-dirs", no_argument, NULL, 34 },
    { "no-ftp-create-dirs", no_argument, NULL, NEGATE_BIT | 34 },
    { "limit-rate", required_argument, NULL, 43 },
    { "cookie", required_argument, NULL, 'b' },
    { "oauth2-bearer", required_argument, NULL, 29 },
    { "max-time", required_argument, NULL, 'm' },
    { "connect-timeout", required_argument, NULL, 19 },
    { "silent", no_argument, NULL, 's' },
    { "no-silent", no_argument, NULL, 38 },
    { "show-error", no_argument, NULL, 'S' },
    { "no-show-error", no_argument, NULL, 39 },
    { "progress-bar", no_argument, NULL, '#' },
    { "no-progress-bar", no_argument, NULL, 40 },
    { "progress-meter", no_argument, NULL, 41 },
    { "no-progress-meter", no_argument, NULL, 42 },
    { "stderr", required_argument, NULL, 21 },
    { "write-out", required_argument, NULL, 'w' },
    { "globoff", no_argument, NULL, 'g' },
    { "no-globoff", no_argument, NULL, NEGATE_BIT | 'g' },
    { "disable", no_argument, NULL, 'q' },
    { "no-disable", no_argument, NULL, NEGATE_BIT | 'q' },
    { "next", no_argument, NULL, 28 },
    { "http1.0", no_argument, NULL, 2 },
    { "http1.1", no_argument, NULL, 3 },
    { "http2", no_argument, NULL, 4 },
    { "http2-prior-knowledge", no_argument, NULL, 9 },
    { "http3", no_argument, NULL, 5 },
    { "http3-only", no_argument, NULL, 10 },
    { "dns-order", required_argument, NULL, 8 },
    { "doh-url", required_argument, NULL, 13 },
    { "doh-insecure", no_argument, NULL, 14 },
    { "no-doh-insecure", no_argument, NULL, NEGATE_BIT | 14 },
    { "doq-url", required_argument, NULL, 17 },
    { "dot-url", required_argument, NULL, 18 },
    { "mail-from", required_argument, NULL, 11 },
    { "mail-rcpt", required_argument, NULL, 12 },
    { "variable", required_argument, NULL, 36 },
    { "url", required_argument, NULL, 37 },
    { "help", no_argument, NULL, 'h' },
    { "version", no_argument, NULL, 7 },
    { NULL, 0, NULL, 0 }
  };
  struct cli_op *ops = NULL;
  struct cli_op *op = NULL;
  struct option *expandable = NULL;
  struct twist_vars *vars = NULL;
  char *expanded = NULL;
  int negate = 0;
  int proto_redir_given = 0;
  int c;
  int status = 0;

  err_fp = stderr;
  setlocale (LC_ALL, "");
  if (twist_global_init () != TWIST_OK)
    {
      diag_code (2, _("could not initialise"));
      return 2;
    }
  op = new_op ();
  ops = op;
  if (op == NULL)
    {
      diag_code (27, twist_strerror (TWIST_ERR_NOMEM));
      status = 27;
      goto done;
    }
  validator = twist_transfer_new ();
  vars = twist_vars_new ();
  expandable = expand_options (longs);
  if (validator == NULL || vars == NULL || expandable == NULL)
    {
      diag_code (27, twist_strerror (TWIST_ERR_NOMEM));
      status = 27;
      goto done;
    }
  opterr = 0;
  optind = 1;
  while (optind < argc)
    {
      if (strcmp (argv[optind], "--") == 0)
        {
          optind++;
          while (optind < argc)
            {
              status = append_item (&op->urls, &op->urls_tail, argv[optind], 0);
              if (status != 0)
                {
                  diag_code (status, twist_strerror (TWIST_ERR_NOMEM));
                  goto done;
                }
              optind++;
            }
          break;
        }
      if (argv[optind][0] != '-' || argv[optind][1] == 0)
        {
          status = append_item (&op->urls, &op->urls_tail, argv[optind], 0);
          if (status != 0)
            {
              diag_code (status, twist_strerror (TWIST_ERR_NOMEM));
              goto done;
            }
          optind++;
          continue;
        }
      c = getopt_long (argc, argv,
                       "+:o:X:H:d:Lkx:A:u:Iw:fE:hm:e:r:b:sS#OT:t:GgiD:qC:lQ:U:Zap",
                       expandable, NULL);
      if (c == -1)
        break;
      if (c > 0 && (c & EXPAND_BIT))
        {
          /* --expand-NAME: the parameter has its variables in it.  */
          char reason[300];

          c &= ~EXPAND_BIT;
          expanded = twist_vars_expand (vars, optarg, reason, sizeof reason);
          if (expanded == NULL)
            {
              char msg[420];

              snprintf (msg, sizeof msg, _("option --expand-%s: %s"),
                        option_name (longs, c), reason);
              diag (msg);
              suggest ();
              status = 2;
              goto done;
            }
          optarg = expanded;
        }
      negate = 0;
      if (c > 0 && (c & NEGATE_BIT))
        {
          negate = 1;
          c &= ~NEGATE_BIT;
        }
      switch (c)
        {
        case 36:
          {
            char reason[300];
            int rc = twist_vars_define (vars, optarg, reason, sizeof reason);

            if (rc != TWIST_OK)
              {
                char msg[420];

                snprintf (msg, sizeof msg, _("option --variable: %s"), reason);
                diag (msg);
                suggest ();
                status = rc == TWIST_ERR_FILE ? 26
                         : rc == TWIST_ERR_NOMEM ? 27 : 2;
              }
          }
          break;
        case 37:
          status = append_item (&op->urls, &op->urls_tail, optarg, 0);
          break;
        case 'o':
          status = append_item (&op->outputs, &op->outputs_tail, optarg, 0);
          break;
        case 'O':
          /* -O names the file of the URL it comes before, which --no-remote-name
             does not undo.  */
          if (!negate)
            status = append_item (&op->outputs, &op->outputs_tail, NULL, 1);
          break;
        case 22:
          free (op->output_dir);
          op->output_dir = twist_strdup (optarg);
          if (op->output_dir == NULL)
            status = 27;
          break;
        case 23:
          op->create_dirs = !negate;
          break;
        case 'X':
          free (op->method);
          op->method = twist_strdup (optarg);
          if (op->method == NULL)
            status = 27;
          break;
        case 'H':
          op->headers = twist_slist_append (op->headers, optarg);
          if (op->headers == NULL)
            status = 27;
          break;
        case 'd':
          status = add_data (op, optarg, 0);
          break;
        case 24:
          status = add_data (op, optarg, 1);
          break;
        case 25:
          status = add_data (op, optarg, 2);
          break;
        case 26:
          status = add_urlencode (op, optarg);
          break;
        case 'G':
          op->get = !negate;
          break;
        case 'T':
          status = append_item (&op->uploads, &op->uploads_tail, optarg, 0);
          break;
        case 'a':
          op_set_long (op, TWISTOPT_APPEND, negate ? 0L : 1L);
          break;
        case 'p':
          op_set_long (op, TWISTOPT_HTTPPROXYTUNNEL, negate ? 0L : 1L);
          break;
        case 't':
          op->telnet = twist_slist_append (op->telnet, optarg);
          if (op->telnet == NULL)
            status = 27;
          break;
        case 'I':
          /* -I and --no-head do not go together, in either order.  */
          if (negate ? op->head_given : op->no_head_given)
            {
              char msg[200];

              snprintf (msg, sizeof msg, _("option %s: is badly used here"),
                        argv[optind - 1][0] == '-' && argv[optind - 1][1] == '-'
                        ? argv[optind - 1] : "-I");
              diag (msg);
              suggest ();
              status = 2;
              break;
            }
          if (negate)
            op->no_head_given = 1;
          else
            {
              op->head_given = 1;
              op->head = 1;
              op->include = 1;
            }
          break;
        case 'i':
          op->include = !negate;
          break;
        case 'D':
          free (op->dump_header);
          op->dump_header = twist_strdup (optarg);
          if (op->dump_header == NULL)
            status = 27;
          break;
        case 'L':
          op_set_long (op, TWISTOPT_FOLLOWLOCATION, negate ? 0L : 1L);
          break;
        case 1:
          {
            char *end = NULL;
            long n = strtol (optarg, &end, 10);

            if (end == optarg || *end != 0)
              {
                diag (_("numerical parameter expected"));
                suggest ();
                status = 2;
              }
            else
              op_set_long (op, TWISTOPT_MAXREDIRS, n);
          }
          break;
        case 'f':
          op_set_long (op, TWISTOPT_FAILONERROR, negate ? 0L : 1L);
          break;
        case 27:
          fail_early = !negate;
          break;
        case 'Z':
          parallel = 1;
          break;
        case 53:
          parallel = 0;
          break;
        case 54:
        case 57:
          {
            long n;

            if (parse_count (optarg, &n) != 0)
              {
                diag (_("numerical parameter expected"));
                suggest ();
                status = 2;
              }
            else if (c == 54)
              /* More than 300 is 300, and none at all is the default.  */
              parallel_max = n > 300 ? 300 : n < 1 ? 50 : n;
            else
              parallel_max_host = n > 65535 ? 65535 : n;
          }
          break;
        case 59:
          {
            long n;

            if (parse_count (optarg, &n) != 0 || n < 1 || n > 64)
              {
                diag (_("--threads takes a number from 1 to 64"));
                suggest ();
                status = 2;
              }
            else
              threads = n;
          }
          break;
        case 55:
          parallel_immediate = 1;
          break;
        case 56:
          parallel_immediate = 0;
          break;
        case 30:
          op_set_str (op, TWISTOPT_ACCEPT_ENCODING, negate ? NULL : "");
          break;
        case 31:
          if (op_set_str (op, TWISTOPT_CONTENT_ENCODING, optarg)
              != TWIST_OK)
            {
              diag (_("unsupported content encoding"));
              suggest ();
              status = 2;
            }
          break;
        case 'k':
          op_set_long (op, TWISTOPT_SSL_VERIFYPEER, negate ? 1L : 0L);
          break;
        case 'E':
          op_set_str (op, TWISTOPT_SSLCERT, optarg);
          break;
        case 15:
          op_set_str (op, TWISTOPT_SSLKEY, optarg);
          break;
        case 16:
          op_set_str (op, TWISTOPT_CAINFO, optarg);
          break;
        case 44:
          op_set_str (op, TWISTOPT_CAPATH, optarg);
          break;
        case 45:
          op_set_str (op, TWISTOPT_NOPROXY, optarg);
          break;
        case 51:
          op_set_long (op, TWISTOPT_USE_SSL, negate ? (long) TWIST_USE_SSL_NONE
                       : (long) TWIST_USE_SSL_TRY);
          break;
        case 52:
          op_set_long (op, TWISTOPT_USE_SSL, negate ? (long) TWIST_USE_SSL_NONE
                       : (long) TWIST_USE_SSL_ALL);
          break;
        case 49:
        case 50:
          if (op_set_str (op, c == 49 ? TWISTOPT_UNIX_SOCKET
                          : TWISTOPT_ABSTRACT_UNIX_SOCKET, optarg)
              != TWIST_OK)
            {
              diag (_("the Unix socket name is too long"));
              suggest ();
              status = 2;
            }
          break;
        case 46:
          op_set_str (op, TWISTOPT_PROXY_CAINFO, optarg);
          break;
        case 47:
          op_set_long (op, TWISTOPT_PROXY_SSL_VERIFYPEER, negate ? 1L : 0L);
          break;
        case 48:
          {
            char why[200];

            if (optarg[0] != 0
                && twist_template_check (optarg, why, sizeof why) != TWIST_OK)
              {
                char msg[300];

                snprintf (msg, sizeof msg, _("option --proxy-template-udp: %s"),
                          why);
                diag (msg);
                suggest ();
                status = 2;
              }
            else
              op_set_str (op, TWISTOPT_PROXY_TEMPLATE_UDP, optarg);
          }
          break;
        case 32:
          op_set_str (op, TWISTOPT_KEYPASSWD, optarg);
          scrub_arg (optarg);
          break;
        case 33:
          op_set_str (op, TWISTOPT_SSH_HOST_PUBLIC_KEY_SHA256, optarg);
          break;
        case 34:
          op->ftp_create_dirs = !negate;
          break;
        case 43:
          if (parse_rate (optarg, &op->limit_rate) != 0)
            {
              diag (_("numerical parameter expected"));
              suggest ();
              status = 2;
            }
          break;
        case 'Q':
          /* A dash before it says after the transfer.  A plus is the FTP
             form that runs it in the directory; there is no FTP here yet, and
             ignoring it would be a surprise.  */
          if (optarg[0] == '+')
            {
              diag_code (2, _("--quote: a command cannot start with +"));
              status = 2;
            }
          else if (optarg[0] == '-')
            {
              op->postquote = twist_slist_append (op->postquote, optarg + 1);
              if (op->postquote == NULL)
                status = 27;
            }
          else
            {
              op->quote = twist_slist_append (op->quote, optarg);
              if (op->quote == NULL)
                status = 27;
            }
          break;
        case 'x':
          op_set_str (op, TWISTOPT_PROXY, optarg);
          break;
        case 'U':
          op_set_str (op, TWISTOPT_PROXYUSERPWD, optarg);
          scrub_arg (optarg);
          break;
        case 'A':
          op_set_str (op, TWISTOPT_USERAGENT, optarg);
          break;
        case 'u':
          {
            char *copy = twist_strdup (optarg);
            char *colon = copy != NULL ? strchr (copy, ':') : NULL;
            char *pass = NULL;

            if (copy == NULL)
              {
                status = 27;
                break;
              }
            if (colon != NULL)
              *colon++ = 0;
            else
              pass = read_password (copy);
            op_set_str (op, TWISTOPT_USERNAME, copy);
            op_set_str (op, TWISTOPT_PASSWORD,
                        colon != NULL ? colon : (pass != NULL ? pass : ""));
            if (pass != NULL)
              {
                memset (pass, 0, strlen (pass));
                free (pass);
              }
            memset (copy, 0, strlen (copy));
            if (colon != NULL)
              memset (colon, 0, strlen (colon));
            free (copy);
            scrub_arg (optarg);
          }
          break;
        case 'e':
          op_set_str (op, TWISTOPT_REFERER, optarg);
          break;
        case 'r':
          op_set_str (op, TWISTOPT_RANGE, optarg);
          break;
        case 'l':
          op_set_long (op, TWISTOPT_DIRLISTONLY, negate ? 0L : 1L);
          break;
        case 'C':
          if (strcmp (optarg, "-") == 0)
            {
              op->resume_set = 1;
              op->resume_auto = 1;
            }
          else
            {
              char *end;
              long long off;

              errno = 0;
              off = strtoll (optarg, &end, 10);
              if (optarg[0] < '0' || optarg[0] > '9' || *end != 0
                  || errno != 0)
                {
                  diag (_("numerical parameter expected"));
                  suggest ();
                  status = 2;
                }
              else
                {
                  op->resume_set = 1;
                  op->resume_auto = 0;
                  op->resume_off = off;
                }
            }
          break;
        case 'b':
          op_set_str (op, TWISTOPT_COOKIE, optarg);
          break;
        case 29:
          op_set_str (op, TWISTOPT_XOAUTH2_BEARER, optarg);
          scrub_arg (optarg);
          break;
        case 'm':
          {
            long ms = 0;

            if (parse_ms (optarg, &ms) != 0)
              {
                diag (_("numerical parameter expected"));
                suggest ();
                status = 2;
              }
            else
              op_set_long (op, TWISTOPT_TIMEOUT_MS, ms);
          }
          break;
        case 19:
          {
            long ms = 0;

            if (parse_ms (optarg, &ms) != 0)
              {
                diag (_("numerical parameter expected"));
                suggest ();
                status = 2;
              }
            else
              op_set_long (op, TWISTOPT_CONNECTTIMEOUT_MS, ms);
          }
          break;
        case 's':
          silent = 1;
          break;
        case 38:
          silent = 0;
          break;
        case 'S':
          show_error = 1;
          break;
        case 39:
          show_error = 0;
          break;
        case '#':
          progress_bar = 1;
          break;
        case 40:
          progress_bar = 0;
          break;
        case 41:
          no_progress = 0;
          break;
        case 42:
          no_progress = 1;
          break;
        case 21:
          /* The file, or standard output for "-": what would have gone to
             standard error, the errors and the meter, goes there.  */
          {
            FILE *fp = stdout;

            if (strcmp (optarg, "-") != 0)
              fp = fopen (optarg, "wb");
            if (fp == NULL)
              {
                char msg[256];

                snprintf (msg, sizeof msg, _("could not write %s"), optarg);
                diag_code (23, msg);
                status = 23;
              }
            else
              {
                if (err_fp != stderr && err_fp != stdout)
                  fclose (err_fp);
                err_fp = fp;
              }
          }
          break;
        case 'w':
          free (op->writeout);
          op->writeout = twist_strdup (optarg);
          if (op->writeout == NULL)
            status = 27;
          break;
        case 'g':
          op->globoff = !negate;
          break;
        case 'q':
          break;
        case 28:
          {
            struct cli_op *next;

            if (op->urls == NULL)
              {
                diag (_("missing URL before --next"));
                suggest ();
                status = 2;
                break;
              }
            next = new_op ();
            if (next == NULL)
              status = 27;
            else
              {
                op->next = next;
                op = next;
              }
          }
          break;
        case 2:
          op_set_long (op, TWISTOPT_HTTP_VERSION,
                       (long) TWIST_HTTP_VERSION_1_0);
          break;
        case 3:
          op_set_long (op, TWISTOPT_HTTP_VERSION,
                       (long) TWIST_HTTP_VERSION_1_1);
          break;
        case 4:
          op_set_long (op, TWISTOPT_HTTP_VERSION,
                       (long) TWIST_HTTP_VERSION_2_0);
          break;
        case 5:
          op_set_long (op, TWISTOPT_HTTP_VERSION,
                       (long) TWIST_HTTP_VERSION_3);
          break;
        case 9:
          op_set_long (op, TWISTOPT_HTTP_VERSION,
                       (long) TWIST_HTTP_VERSION_2_PRIOR_KNOWLEDGE);
          break;
        case 10:
          op_set_long (op, TWISTOPT_HTTP_VERSION,
                       (long) TWIST_HTTP_VERSION_3ONLY);
          break;
        case 11:
          free (op->mail_from);
          op->mail_from = twist_strdup (optarg);
          if (op->mail_from == NULL)
            status = 27;
          break;
        case 12:
          op->rcpts = twist_slist_append (op->rcpts, optarg);
          if (op->rcpts == NULL)
            status = 27;
          break;
        case 13:
          if (op_set_str (op, TWISTOPT_DOH_URL, optarg) != TWIST_OK)
            {
              diag (_("could not set the DoH server"));
              suggest ();
              status = 2;
            }
          break;
        case 14:
          op_set_long (op, TWISTOPT_DOH_SSL_VERIFYPEER, negate ? 1L : 0L);
          break;
        case 17:
          if (op_set_str (op, TWISTOPT_DOQ_URL, optarg) != TWIST_OK)
            {
              diag (_("could not set the DoQ server"));
              suggest ();
              status = 2;
            }
          break;
        case 18:
          if (op_set_str (op, TWISTOPT_DOT_URL, optarg) != TWIST_OK)
            {
              diag (_("could not set the DoT server"));
              suggest ();
              status = 2;
            }
          break;
        case 8:
          if (op_set_str (op, TWISTOPT_DNS_ORDER, optarg) != TWIST_OK)
            {
              diag (_("unrecognised DNS transport order"));
              suggest ();
              status = 2;
            }
          break;
        case 60:
          /* Where a redirect may go is not for an option to say; it is told
             of this when all the options are read, and -s may be among them.  */
          proto_redir_given = 1;
          break;
        case 'h':
          usage ();
          status = 0;
          goto done;
        case 7:
          version ();
          status = 0;
          goto done;
        case ':':
          {
            char msg[256];
            const char *name = optind > 0 ? argv[optind - 1] : "";

            snprintf (msg, sizeof msg, _("option %s: requires parameter"),
                      name);
            diag (msg);
            suggest ();
            status = 2;
          }
          break;
        case '?':
        default:
          if (optopt != 0)
            {
              char msg[64];

              snprintf (msg, sizeof msg, _("option -%c: is unknown"), optopt);
              diag (msg);
            }
          else if (optind > 0)
            {
              char msg[256];

              snprintf (msg, sizeof msg, _("option %s: is unknown"),
                        argv[optind - 1]);
              diag (msg);
            }
          else
            diag (_("unrecognised option"));
          suggest ();
          status = 2;
          break;
        }
      free (expanded);
      expanded = NULL;
      if (status == 27)
        diag_code (27, twist_strerror (TWIST_ERR_NOMEM));
      if (status != 0)
        goto done;
    }
  if (proto_redir_given && !silent)
    fputs (_("Warning: --proto-redir has no effect: a redirect goes by the "
             "scheme alone,\n"
             "Warning: from http to http, https, ftp or ftps, and from https "
             "to https or ftps.\n"), err_fp);
  status = run_all (ops);
done:
  twist_transfer_free (validator);
  validator = NULL;
  free (expanded);
  free (expandable);
  twist_vars_free (vars);
  while (ops != NULL)
    {
      struct cli_op *next = ops->next;

      free_op (ops);
      ops = next;
    }
  if (err_fp != NULL && err_fp != stderr && err_fp != stdout)
    fclose (err_fp);
  twist_global_cleanup ();
  return status;
}
