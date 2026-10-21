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
#include <getopt.h>
#include <locale.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>

#include <sys/stat.h>
#include <unistd.h>

/* The body is written to standard output, or to -o.  Diagnostics go to
   standard error, or to --stderr.  A transfer's exit status is curl's
   code for that failure.  A bad command line exits 2.  --help and
   --version write to standard output and exit 0.  */

static FILE *err_fp;
static int silent;
static int show_error = 1;
static int fail_early;

struct cli_item
{
  char *text;
  int remote;
  struct cli_item *next;
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
  int get;
  int include;
  char *dump_header;
  char *writeout;
  struct twist_slist *headers;
  struct twist_slist *rcpts;
  char *mail_from;
  char *output_dir;
  int create_dirs;
  twist_easy *easy;
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
    case TWIST_ERR_HOSTKEY:
      return 60;
    case TWIST_ERR_ENCODING:
      return 61;
    case TWIST_ERR_AUTH:
      return 67;
    case TWIST_ERR_AGAIN:
      return 81;
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
  fputs (_("  -T, --upload-file FILE  upload FILE (- is stdin) with PUT\n"),
         stdout);
  fputs (_("  -I, --head              fetch headers only\n"), stdout);
  fputs (_("  -i, --include           write response headers before the body\n"),
         stdout);
  fputs (_("  -D, --dump-header FILE  write response headers to FILE\n"), stdout);
  fputs (_("  -L, --location          follow redirects\n"), stdout);
  fputs (_("      --max-redirs N      redirect limit (default 50)\n"), stdout);
  fputs (_("  -f, --fail              fail on HTTP errors (400 and above)\n"),
         stdout);
  fputs (_("      --fail-early        stop at the first failed URL\n"), stdout);
  fputs (_("      --compressed        request a gzip or deflate response\n"),
         stdout);
  fputs (_("      --content-encoding C  gzip or deflate the request body\n"),
         stdout);
  fputs (_("  -k, --insecure          accepted; certificates are still checked;\n"
           "                          sftp and scp skip the known_hosts check\n"),
         stdout);
  fputs (_("  -E, --cert FILE         client certificate (PEM)\n"), stdout);
  fputs (_("      --key FILE          private key for --cert (PEM), or for sftp and scp\n"),
         stdout);
  fputs (_("      --pass PHRASE       passphrase for the private key file\n"), stdout);
  fputs (_("      --hostpubsha256 H   SHA-256 of the sftp or scp host key (base64)\n"),
         stdout);
  fputs (_("      --cacert FILE       CA trust bundle (PEM)\n"), stdout);
  fputs (_("  -x, --proxy URL         proxy (http:// or socks5://)\n"), stdout);
  fputs (_("  -A, --user-agent NAME   User-Agent\n"), stdout);
  fputs (_("  -u, --user USER[:PASS]  user and password\n"), stdout);
  fputs (_("  -e, --referer URL       Referer header\n"), stdout);
  fputs (_("  -r, --range RANGE       byte range\n"), stdout);
  fputs (_("  -b, --cookie DATA       Cookie header data\n"), stdout);
  fputs (_("      --oauth2-bearer T   Bearer token\n"), stdout);
  fputs (_("  -m, --max-time SECONDS  whole transfer limit\n"), stdout);
  fputs (_("      --connect-timeout S connect limit, in seconds\n"), stdout);
  fputs (_("  -s, --silent            hide the error message\n"), stdout);
  fputs (_("  -S, --show-error        show the error message with -s\n"),
         stdout);
  fputs (_("      --stderr FILE       diagnostics go to FILE\n"), stdout);
  /* TRANSLATORS: The %{name} tokens are literal.  Keep the doubled
     percent signs.  */
  printf (_("  -w, --write-out FORMAT  print after the body (%%{http_code},\n"
            "                          %%{size_download}, %%{url_effective},\n"
            "                          %%{content_type}, %%{exitcode})\n"));
  fputs (_("  -g, --globoff           accepted; URLs are never expanded\n"),
         stdout);
  fputs (_("  -q, --disable           accepted; no config file is read\n"),
         stdout);
  fputs (_("      --next              start a new URL; only -s, -S, --stderr\n"
           "                          and --fail-early carry over\n"),
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
  return name;
}

static char *
output_path (const struct cli_op *op, const char *name)
{
  size_t dn;
  size_t nn;
  char *path;

  if (name == NULL || strcmp (name, "-") == 0)
    return NULL;
  if (op->output_dir == NULL || op->output_dir[0] == 0 || name[0] == '/')
    return twist_strdup (name);
  dn = strlen (op->output_dir);
  nn = strlen (name);
  path = twist_xmalloc (dn + 1 + nn + 1);
  if (path == NULL)
    return NULL;
  memcpy (path, op->output_dir, dn);
  path[dn] = '/';
  memcpy (path + dn + 1, name, nn + 1);
  return path;
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
      if (mkdir (copy, 0777) < 0 && errno != EEXIST)
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
emit_writeout (const char *fmt, twist_easy *easy, int code)
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
            fputc (*p, stdout);
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
          twist_easy_getinfo (easy, TWISTINFO_RESPONSE_CODE, &http);
          twist_easy_getinfo (easy, TWISTINFO_SIZE_DOWNLOAD, &size);
          twist_easy_getinfo (easy, TWISTINFO_EFFECTIVE_URL, &effective);
          twist_easy_getinfo (easy, TWISTINFO_CONTENT_TYPE, &ctype);
          if ((n == 9 && memcmp (p + 2, "http_code", 9) == 0)
              || (n == 13 && memcmp (p + 2, "response_code", 13) == 0))
            printf ("%ld", http);
          else if (n == 13 && memcmp (p + 2, "size_download", 13) == 0)
            printf ("%zu", size);
          else if (n == 13 && memcmp (p + 2, "url_effective", 13) == 0)
            fputs (effective != NULL ? effective : "", stdout);
          else if (n == 12 && memcmp (p + 2, "content_type", 12) == 0)
            fputs (ctype != NULL ? ctype : "", stdout);
          else if (n == 8 && memcmp (p + 2, "exitcode", 8) == 0)
            printf ("%d", code);
          else if (n == 8 && memcmp (p + 2, "errormsg", 8) == 0)
            {
              const char *detail = twist_easy_error (easy);

              if (code != 0)
                fputs (detail != NULL ? detail : twist_strerror (easy->result),
                       stdout);
            }
          p = end;
        }
      else
        fputc (*p, stdout);
    }
}

struct cli_headers
{
  FILE *body;
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
  if (h->include && h->body != NULL
      && fwrite (ptr, 1, n, h->body) < n)
    h->short_write = 1;
  if (h->dump != NULL && fwrite (ptr, 1, n, h->dump) < n)
    h->short_write = 1;
  return h->short_write ? 0 : n;
}

static int body_short;

static size_t
write_body (char *ptr, size_t size, size_t nmemb, void *userdata)
{
  FILE *fp = userdata;
  size_t n = size * nmemb;
  size_t got;

  got = fwrite (ptr, 1, n, fp);
  if (got < n)
    body_short = 1;
  return got;
}

static void
finish_headers (struct cli_headers *h)
{
  if (!h->saw)
    return;
  if (h->include && h->body != NULL
      && fwrite ("\r\n", 1, 2, h->body) < 2)
    h->short_write = 1;
  if (h->dump != NULL && fwrite ("\r\n", 1, 2, h->dump) < 2)
    h->short_write = 1;
  h->saw = 0;
}

static int
run_one (twist_easy *easy, struct cli_op *op, const char *url,
         const char *output, int remote, const char *upload)
{
  char *out_name = NULL;
  char *out_path = NULL;
  FILE *body = stdout;
  FILE *dump = NULL;
  struct cli_bytes up;
  char *payload = NULL;
  size_t payload_n = 0;
  static char empty_body[] = "";
  const char *method = op->method;
  char *query_url = NULL;
  const char *use_url = url;
  struct cli_headers hdrs;
  int rc;
  int code;
  const char *detail;

  memset (&up, 0, sizeof up);
  memset (&hdrs, 0, sizeof hdrs);
  body_short = 0;
  easy->proto_status = 0;
  if (remote)
    {
      out_name = remote_file (url);
      if (out_name == NULL)
        {
          diag_code (23, _("remote file name has no length"));
          return 23;
        }
    }
  else if (output != NULL)
    out_name = twist_strdup (output);
  out_path = output_path (op, out_name);
  free (out_name);
  if (output != NULL && strcmp (output, "-") != 0 && out_path == NULL)
    {
      diag_code (27, twist_strerror (TWIST_ERR_NOMEM));
      return 27;
    }
  if ((rc = ensure_dirs (op, out_path)) != 0)
    {
      free (out_path);
      return rc;
    }
  if (out_path != NULL)
    {
      body = fopen (out_path, "wb");
      if (body == NULL)
        {
          char msg[256];

          snprintf (msg, sizeof msg, _("could not write %s"), out_path);
          diag_code (23, msg);
          free (out_path);
          return 23;
        }
    }
  free (out_path);
  if (op->dump_header != NULL && strcmp (op->dump_header, "-") != 0)
    {
      dump = fopen (op->dump_header, "wb");
      if (dump == NULL)
        {
          char msg[256];

          snprintf (msg, sizeof msg, _("could not write %s"), op->dump_header);
          diag_code (23, msg);
          if (body != stdout)
            fclose (body);
          return 23;
        }
    }
  else if (op->dump_header != NULL)
    dump = stdout;
  if (upload != NULL)
    {
      if (read_named (upload, &up, 0) != TWIST_OK)
        {
          char msg[256];

          snprintf (msg, sizeof msg, _("could not read %s"), upload);
          diag_code (26, msg);
          if (body != stdout)
            fclose (body);
          if (dump != NULL && dump != stdout)
            fclose (dump);
          free (up.p);
          return 26;
        }
      payload = up.p != NULL ? up.p : empty_body;
      payload_n = up.n;
      if (method == NULL)
        method = "PUT";
    }
  else if (op->has_data && !op->get)
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
          free (up.p);
          if (body != stdout)
            fclose (body);
          if (dump != NULL && dump != stdout)
            fclose (dump);
          diag_code (27, twist_strerror (TWIST_ERR_NOMEM));
          return 27;
        }
      memcpy (joined, url, ulen);
      joined[ulen] = q != NULL ? '&' : '?';
      memcpy (joined + ulen + 1, op->data != NULL ? op->data : "", op->data_len);
      joined[ulen + 1 + op->data_len] = 0;
      query_url = joined;
      use_url = query_url;
      payload = NULL;
    }
  hdrs.body = body;
  hdrs.dump = dump;
  hdrs.include = op->include;
  twist_easy_setopt (easy, TWISTOPT_URL, use_url);
  twist_easy_setopt (easy, TWISTOPT_CUSTOMREQUEST, method);
  twist_easy_setopt (easy, TWISTOPT_NOBODY, op->head ? 1L : 0L);
  twist_easy_setopt (easy, TWISTOPT_POSTFIELDS, payload);
  if (payload != NULL)
    twist_easy_setopt (easy, TWISTOPT_POSTFIELDSIZE, (long) payload_n);
  twist_easy_setopt (easy, TWISTOPT_HTTPHEADER,
                     op->headers != NULL ? op->headers : NULL);
  twist_easy_setopt (easy, TWISTOPT_MAIL_FROM, op->mail_from);
  twist_easy_setopt (easy, TWISTOPT_MAIL_RCPT, op->rcpts);
  twist_easy_setopt (easy, TWISTOPT_WRITEFUNCTION, write_body);
  twist_easy_setopt (easy, TWISTOPT_WRITEDATA, body);
  if (op->include || dump != NULL)
    {
      twist_easy_setopt (easy, TWISTOPT_HEADERFUNCTION, write_header);
      twist_easy_setopt (easy, TWISTOPT_HEADERDATA, &hdrs);
    }
  else
    {
      twist_easy_setopt (easy, TWISTOPT_HEADERFUNCTION, NULL);
      twist_easy_setopt (easy, TWISTOPT_HEADERDATA, NULL);
    }
  rc = twist_easy_perform (easy);
  finish_headers (&hdrs);
  if (body != stdout)
    {
      if (fclose (body) != 0 && rc == TWIST_OK)
        rc = TWIST_ERR_ABORTED;
    }
  else
    fflush (body);
  if (dump != NULL && dump != stdout)
    fclose (dump);
  code = cli_status (rc, use_url);
  if (easy->proto_status != 0)
    code = easy->proto_status;
  if ((body_short || hdrs.short_write) && (code == 0 || code == 42))
    code = 23;
  if (code != 0)
    {
      detail = twist_easy_error (easy);
      diag_code (code, detail != NULL ? detail : twist_strerror (rc));
    }
  emit_writeout (op->writeout, easy, code);
  free (up.p);
  free (query_url);
  return code;
}

static int
run_op (struct cli_op *op)
{
  struct cli_item *url;
  struct cli_item *out;
  struct cli_item *up;
  int status = 0;

  if (op->urls == NULL)
    {
      diag (_("no URL specified"));
      suggest ();
      return 2;
    }
  out = op->outputs;
  up = op->uploads;
  for (url = op->urls; url != NULL; url = url->next)
    {
      const char *output = NULL;
      int remote = 0;
      const char *upload = NULL;

      if (out != NULL)
        {
          output = out->remote ? NULL : out->text;
          remote = out->remote;
          out = out->next;
        }
      if (up != NULL)
        {
          upload = up->text;
          up = up->next;
        }
      status = run_one (op->easy, op, url->text, output, remote, upload);
      if (status != 0 && fail_early)
        return status;
    }
  return status;
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
  twist_easy_cleanup (op->easy);
  free (op);
}

static struct cli_op *
new_op (void)
{
  struct cli_op *op = calloc (1, sizeof *op);

  if (op == NULL)
    return NULL;
  op->easy = twist_easy_init ();
  if (op->easy == NULL)
    {
      free (op);
      return NULL;
    }
  return op;
}

int
main (int argc, char **argv)
{
  static const struct option longs[] = {
    { "output", required_argument, NULL, 'o' },
    { "remote-name", no_argument, NULL, 'O' },
    { "output-dir", required_argument, NULL, 22 },
    { "create-dirs", no_argument, NULL, 23 },
    { "request", required_argument, NULL, 'X' },
    { "header", required_argument, NULL, 'H' },
    { "data", required_argument, NULL, 'd' },
    { "data-binary", required_argument, NULL, 24 },
    { "data-raw", required_argument, NULL, 25 },
    { "data-urlencode", required_argument, NULL, 26 },
    { "get", no_argument, NULL, 'G' },
    { "upload-file", required_argument, NULL, 'T' },
    { "head", no_argument, NULL, 'I' },
    { "include", no_argument, NULL, 'i' },
    { "dump-header", required_argument, NULL, 'D' },
    { "location", no_argument, NULL, 'L' },
    { "max-redirs", required_argument, NULL, 1 },
    { "fail", no_argument, NULL, 'f' },
    { "fail-early", no_argument, NULL, 27 },
    { "compressed", no_argument, NULL, 30 },
    { "content-encoding", required_argument, NULL, 31 },
    { "insecure", no_argument, NULL, 'k' },
    { "cert", required_argument, NULL, 'E' },
    { "key", required_argument, NULL, 15 },
    { "pass", required_argument, NULL, 32 },
    { "hostpubsha256", required_argument, NULL, 33 },
    { "cacert", required_argument, NULL, 16 },
    { "proxy", required_argument, NULL, 'x' },
    { "user-agent", required_argument, NULL, 'A' },
    { "user", required_argument, NULL, 'u' },
    { "referer", required_argument, NULL, 'e' },
    { "range", required_argument, NULL, 'r' },
    { "cookie", required_argument, NULL, 'b' },
    { "oauth2-bearer", required_argument, NULL, 29 },
    { "max-time", required_argument, NULL, 'm' },
    { "connect-timeout", required_argument, NULL, 19 },
    { "silent", no_argument, NULL, 's' },
    { "show-error", no_argument, NULL, 'S' },
    { "stderr", required_argument, NULL, 21 },
    { "write-out", required_argument, NULL, 'w' },
    { "globoff", no_argument, NULL, 'g' },
    { "disable", no_argument, NULL, 'q' },
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
    { "doq-url", required_argument, NULL, 17 },
    { "dot-url", required_argument, NULL, 18 },
    { "mail-from", required_argument, NULL, 11 },
    { "mail-rcpt", required_argument, NULL, 12 },
    { "help", no_argument, NULL, 'h' },
    { "version", no_argument, NULL, 7 },
    { NULL, 0, NULL, 0 }
  };
  struct cli_op *ops = NULL;
  struct cli_op *op = NULL;
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
                       "+:o:X:H:d:Lkx:A:u:Iw:fE:hm:e:r:b:sSOT:GgiD:q",
                       longs, NULL);
      if (c == -1)
        break;
      switch (c)
        {
        case 'o':
          status = append_item (&op->outputs, &op->outputs_tail, optarg, 0);
          break;
        case 'O':
          status = append_item (&op->outputs, &op->outputs_tail, NULL, 1);
          break;
        case 22:
          free (op->output_dir);
          op->output_dir = twist_strdup (optarg);
          if (op->output_dir == NULL)
            status = 27;
          break;
        case 23:
          op->create_dirs = 1;
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
          op->get = 1;
          break;
        case 'T':
          status = append_item (&op->uploads, &op->uploads_tail, optarg, 0);
          break;
        case 'I':
          op->head = 1;
          break;
        case 'i':
          op->include = 1;
          break;
        case 'D':
          free (op->dump_header);
          op->dump_header = twist_strdup (optarg);
          if (op->dump_header == NULL)
            status = 27;
          break;
        case 'L':
          twist_easy_setopt (op->easy, TWISTOPT_FOLLOWLOCATION, 1L);
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
              twist_easy_setopt (op->easy, TWISTOPT_MAXREDIRS, n);
          }
          break;
        case 'f':
          twist_easy_setopt (op->easy, TWISTOPT_FAILONERROR, 1L);
          break;
        case 27:
          fail_early = 1;
          break;
        case 30:
          twist_easy_setopt (op->easy, TWISTOPT_ACCEPT_ENCODING, "");
          break;
        case 31:
          if (twist_easy_setopt (op->easy, TWISTOPT_CONTENT_ENCODING, optarg)
              != TWIST_OK)
            {
              diag (_("unsupported content encoding"));
              suggest ();
              status = 2;
            }
          break;
        case 'k':
          twist_easy_setopt (op->easy, TWISTOPT_SSL_VERIFYPEER, 0L);
          break;
        case 'E':
          twist_easy_setopt (op->easy, TWISTOPT_SSLCERT, optarg);
          break;
        case 15:
          twist_easy_setopt (op->easy, TWISTOPT_SSLKEY, optarg);
          break;
        case 16:
          twist_easy_setopt (op->easy, TWISTOPT_CAINFO, optarg);
          break;
        case 32:
          twist_easy_setopt (op->easy, TWISTOPT_KEYPASSWD, optarg);
          break;
        case 33:
          twist_easy_setopt (op->easy, TWISTOPT_SSH_HOST_PUBLIC_KEY_SHA256,
                             optarg);
          break;
        case 'x':
          twist_easy_setopt (op->easy, TWISTOPT_PROXY, optarg);
          break;
        case 'A':
          twist_easy_setopt (op->easy, TWISTOPT_USERAGENT, optarg);
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
            twist_easy_setopt (op->easy, TWISTOPT_USERNAME, copy);
            twist_easy_setopt (op->easy, TWISTOPT_PASSWORD,
                               colon != NULL ? colon : (pass != NULL ? pass : ""));
            free (pass);
            free (copy);
          }
          break;
        case 'e':
          twist_easy_setopt (op->easy, TWISTOPT_REFERER, optarg);
          break;
        case 'r':
          twist_easy_setopt (op->easy, TWISTOPT_RANGE, optarg);
          break;
        case 'b':
          twist_easy_setopt (op->easy, TWISTOPT_COOKIE, optarg);
          break;
        case 29:
          twist_easy_setopt (op->easy, TWISTOPT_XOAUTH2_BEARER, optarg);
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
              twist_easy_setopt (op->easy, TWISTOPT_TIMEOUT_MS, ms);
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
              twist_easy_setopt (op->easy, TWISTOPT_CONNECTTIMEOUT_MS, ms);
          }
          break;
        case 's':
          silent = 1;
          show_error = 0;
          break;
        case 'S':
          show_error = 1;
          break;
        case 21:
          if (strcmp (optarg, "-") != 0)
            {
              FILE *fp = fopen (optarg, "wb");

              if (fp == NULL)
                {
                  char msg[256];

                  snprintf (msg, sizeof msg, _("could not write %s"), optarg);
                  diag_code (23, msg);
                  status = 23;
                }
              else
                {
                  if (err_fp != stderr)
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
          twist_easy_setopt (op->easy, TWISTOPT_HTTP_VERSION,
                             (long) TWIST_HTTP_VERSION_1_0);
          break;
        case 3:
          twist_easy_setopt (op->easy, TWISTOPT_HTTP_VERSION,
                             (long) TWIST_HTTP_VERSION_1_1);
          break;
        case 4:
          twist_easy_setopt (op->easy, TWISTOPT_HTTP_VERSION,
                             (long) TWIST_HTTP_VERSION_2_0);
          break;
        case 5:
          twist_easy_setopt (op->easy, TWISTOPT_HTTP_VERSION,
                             (long) TWIST_HTTP_VERSION_3);
          break;
        case 9:
          twist_easy_setopt (op->easy, TWISTOPT_HTTP_VERSION,
                             (long) TWIST_HTTP_VERSION_2_PRIOR_KNOWLEDGE);
          break;
        case 10:
          twist_easy_setopt (op->easy, TWISTOPT_HTTP_VERSION,
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
          if (twist_easy_setopt (op->easy, TWISTOPT_DOH_URL, optarg) != TWIST_OK)
            {
              diag (_("could not set the DoH server"));
              suggest ();
              status = 2;
            }
          break;
        case 14:
          twist_easy_setopt (op->easy, TWISTOPT_DOH_SSL_VERIFYPEER, 0L);
          break;
        case 17:
          if (twist_easy_setopt (op->easy, TWISTOPT_DOQ_URL, optarg) != TWIST_OK)
            {
              diag (_("could not set the DoQ server"));
              suggest ();
              status = 2;
            }
          break;
        case 18:
          if (twist_easy_setopt (op->easy, TWISTOPT_DOT_URL, optarg) != TWIST_OK)
            {
              diag (_("could not set the DoT server"));
              suggest ();
              status = 2;
            }
          break;
        case 8:
          if (twist_easy_setopt (op->easy, TWISTOPT_DNS_ORDER, optarg) != TWIST_OK)
            {
              diag (_("unrecognised DNS transport order"));
              suggest ();
              status = 2;
            }
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
      if (status == 27)
        diag_code (27, twist_strerror (TWIST_ERR_NOMEM));
      if (status != 0)
        goto done;
    }
  {
    struct cli_op *cur;
    int last = 0;

    for (cur = ops; cur != NULL; cur = cur->next)
      {
        last = run_op (cur);
        if (last != 0 && fail_early)
          break;
      }
    status = last;
  }
done:
  while (ops != NULL)
    {
      struct cli_op *next = ops->next;

      free_op (ops);
      ops = next;
    }
  if (err_fp != NULL && err_fp != stderr)
    fclose (err_fp);
  twist_global_cleanup ();
  return status;
}
