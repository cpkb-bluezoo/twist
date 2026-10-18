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

#include <errno.h>
#include <getopt.h>
#include <locale.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static FILE *out_file;

static size_t
write_out (char *ptr, size_t size, size_t nmemb, void *userdata)
{
  FILE *fp = userdata != NULL ? userdata : stdout;
  size_t n = fwrite (ptr, size, nmemb, fp);

  (void) out_file;
  return n;
}

static void
usage (void)
{
  printf (_("Usage: %s [OPTION]... URL\n"), PACKAGE);
  fputs (_("Transfer a URL.\n\n"), stdout);
  fputs (_("  -o, --output FILE       write the body to FILE\n"), stdout);
  fputs (_("  -X, --request METHOD    request method\n"), stdout);
  fputs (_("  -H, --header LINE       extra header\n"), stdout);
  fputs (_("  -d, --data DATA         request body (implies POST)\n"), stdout);
  fputs (_("  -L, --location          follow redirects\n"), stdout);
  fputs (_("  -k, --insecure          accepted; certificates are still checked\n"),
         stdout);
  fputs (_("  -E, --cert FILE         client certificate (PEM)\n"), stdout);
  fputs (_("      --key FILE          private key for --cert (PEM)\n"), stdout);
  fputs (_("      --cacert FILE       CA trust bundle (PEM)\n"), stdout);
  fputs (_("  -x, --proxy URL         proxy (http:// or socks5://)\n"), stdout);
  fputs (_("  -A, --user-agent NAME   User-Agent\n"), stdout);
  fputs (_("  -u, --user USER:PASS    user and password\n"), stdout);
  fputs (_("  -I, --head              fetch headers only\n"), stdout);
  fputs (_("  -f, --fail              fail on HTTP errors (400 and above)\n"),
         stdout);
  /* TRANSLATORS: %{http_code} and %{size_download} are literal tokens.
     Keep the doubled percent signs.  */
  printf (_("  -w, --write-out FORMAT  print %%{http_code} or %%{size_download}\n"));
  fputs (_("      --max-redirs N      redirect limit (default 50)\n"), stdout);
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
  fputs (_("      --mail-from ADDR    SMTP sender\n"), stdout);
  fputs (_("      --mail-rcpt ADDR    SMTP recipient\n"), stdout);
  fputs (_("      --help              display this help and exit\n"), stdout);
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

static void
die (const char *msg)
{
  fprintf (stderr, _("%s: %s\n"), PACKAGE, msg);
}

static void
suggest_help (void)
{
  fprintf (stderr, _("Try '%s --help' for more information.\n"), PACKAGE);
}

int
main (int argc, char **argv)
{
  static const struct option longs[] = {
    { "output", required_argument, NULL, 'o' },
    { "request", required_argument, NULL, 'X' },
    { "header", required_argument, NULL, 'H' },
    { "data", required_argument, NULL, 'd' },
    { "location", no_argument, NULL, 'L' },
    { "insecure", no_argument, NULL, 'k' },
    { "cert", required_argument, NULL, 'E' },
    { "key", required_argument, NULL, 15 },
    { "cacert", required_argument, NULL, 16 },
    { "proxy", required_argument, NULL, 'x' },
    { "user-agent", required_argument, NULL, 'A' },
    { "user", required_argument, NULL, 'u' },
    { "head", no_argument, NULL, 'I' },
    { "fail", no_argument, NULL, 'f' },
    { "write-out", required_argument, NULL, 'w' },
    { "max-redirs", required_argument, NULL, 1 },
    { "http1.0", no_argument, NULL, 2 },
    { "http1.1", no_argument, NULL, 3 },
    { "http2", no_argument, NULL, 4 },
    { "http2-prior-knowledge", no_argument, NULL, 9 },
    { "http3", no_argument, NULL, 5 },
    { "http3-only", no_argument, NULL, 10 },
    { "dns-order", required_argument, NULL, 8 },
    { "doh-url", required_argument, NULL, 13 },
    { "doh-insecure", no_argument, NULL, 14 },
    { "mail-from", required_argument, NULL, 11 },
    { "mail-rcpt", required_argument, NULL, 12 },
    { "help", no_argument, NULL, 6 },
    { "version", no_argument, NULL, 7 },
    { NULL, 0, NULL, 0 }
  };
  twist_easy *easy;
  struct twist_slist *headers = NULL;
  struct twist_slist *rcpts = NULL;
  const char *url = NULL;
  const char *writeout = NULL;
  int c;
  int rc;

  setlocale (LC_ALL, "");
  if (twist_global_init () != TWIST_OK)
    {
      die (_("could not initialise"));
      return 1;
    }
  easy = twist_easy_init ();
  if (easy == NULL)
    {
      die (twist_strerror (TWIST_ERR_NOMEM));
      return 1;
    }
  while ((c = getopt_long (argc, argv, "o:X:H:d:Lkx:A:u:Iw:fE:", longs, NULL))
         != -1)
    {
      switch (c)
        {
        case 'o':
          out_file = fopen (optarg, "wb");
          if (out_file == NULL)
            {
              die (strerror (errno));
              return 1;
            }
          break;
        case 'X':
          twist_easy_setopt (easy, TWISTOPT_CUSTOMREQUEST, optarg);
          break;
        case 'H':
          headers = twist_slist_append (headers, optarg);
          break;
        case 'd':
          twist_easy_setopt (easy, TWISTOPT_POSTFIELDS, optarg);
          break;
        case 'L':
          twist_easy_setopt (easy, TWISTOPT_FOLLOWLOCATION, 1L);
          break;
        case 'k':
          twist_easy_setopt (easy, TWISTOPT_SSL_VERIFYPEER, 0L);
          break;
        case 'E':
          twist_easy_setopt (easy, TWISTOPT_SSLCERT, optarg);
          break;
        case 15:
          twist_easy_setopt (easy, TWISTOPT_SSLKEY, optarg);
          break;
        case 16:
          twist_easy_setopt (easy, TWISTOPT_CAINFO, optarg);
          break;
        case 'x':
          twist_easy_setopt (easy, TWISTOPT_PROXY, optarg);
          break;
        case 'A':
          twist_easy_setopt (easy, TWISTOPT_USERAGENT, optarg);
          break;
        case 'u':
          {
            char *copy = twist_strdup (optarg);
            char *colon = copy != NULL ? strchr (copy, ':') : NULL;
            if (colon != NULL)
              *colon++ = 0;
            twist_easy_setopt (easy, TWISTOPT_USERNAME, copy);
            twist_easy_setopt (easy, TWISTOPT_PASSWORD,
                               colon != NULL ? colon : "");
            free (copy);
          }
          break;
        case 'I':
          twist_easy_setopt (easy, TWISTOPT_NOBODY, 1L);
          break;
        case 'f':
          twist_easy_setopt (easy, TWISTOPT_FAILONERROR, 1L);
          break;
        case 'w':
          writeout = optarg;
          break;
        case 1:
          twist_easy_setopt (easy, TWISTOPT_MAXREDIRS, strtol (optarg, NULL, 10));
          break;
        case 2:
          twist_easy_setopt (easy, TWISTOPT_HTTP_VERSION,
                             (long) TWIST_HTTP_VERSION_1_0);
          break;
        case 3:
          twist_easy_setopt (easy, TWISTOPT_HTTP_VERSION,
                             (long) TWIST_HTTP_VERSION_1_1);
          break;
        case 4:
          twist_easy_setopt (easy, TWISTOPT_HTTP_VERSION,
                             (long) TWIST_HTTP_VERSION_2_0);
          break;
        case 5:
          twist_easy_setopt (easy, TWISTOPT_HTTP_VERSION,
                             (long) TWIST_HTTP_VERSION_3);
          break;
        case 9:
          twist_easy_setopt (easy, TWISTOPT_HTTP_VERSION,
                             (long) TWIST_HTTP_VERSION_2_PRIOR_KNOWLEDGE);
          break;
        case 10:
          twist_easy_setopt (easy, TWISTOPT_HTTP_VERSION,
                             (long) TWIST_HTTP_VERSION_3ONLY);
          break;
        case 11:
          twist_easy_setopt (easy, TWISTOPT_MAIL_FROM, optarg);
          break;
        case 12:
          rcpts = twist_slist_append (rcpts, optarg);
          break;
        case 13:
          if (twist_easy_setopt (easy, TWISTOPT_DOH_URL, optarg) != TWIST_OK)
            {
              die (_("could not set the DoH server"));
              return 1;
            }
          break;
        case 14:
          twist_easy_setopt (easy, TWISTOPT_DOH_SSL_VERIFYPEER, 0L);
          break;
        case 8:
          if (twist_easy_setopt (easy, TWISTOPT_DNS_ORDER, optarg) != TWIST_OK)
            {
              die (_("unrecognised DNS transport order"));
              return 1;
            }
          break;
        case 6:
          usage ();
          twist_easy_cleanup (easy);
          return 0;
        case 7:
          version ();
          twist_easy_cleanup (easy);
          return 0;
        default:
          die (_("unrecognised option"));
          suggest_help ();
          twist_easy_cleanup (easy);
          return 1;
        }
    }
  if (optind < argc)
    url = argv[optind];
  if (url == NULL)
    {
      die (_("no URL given"));
      suggest_help ();
      twist_easy_cleanup (easy);
      twist_slist_free_all (headers);
      twist_slist_free_all (rcpts);
      return 1;
    }
  twist_easy_setopt (easy, TWISTOPT_URL, url);
  twist_easy_setopt (easy, TWISTOPT_WRITEFUNCTION, write_out);
  twist_easy_setopt (easy, TWISTOPT_WRITEDATA, out_file != NULL ? out_file : stdout);
  if (headers != NULL)
    twist_easy_setopt (easy, TWISTOPT_HTTPHEADER, headers);
  if (rcpts != NULL)
    twist_easy_setopt (easy, TWISTOPT_MAIL_RCPT, rcpts);
  rc = twist_easy_perform (easy);
  if (rc != TWIST_OK)
    {
      const char *detail = twist_easy_error (easy);

      die (detail != NULL ? detail : twist_strerror (rc));
    }
  if (writeout != NULL)
    {
      long code = 0;
      size_t size = 0;
      twist_easy_getinfo (easy, TWISTINFO_RESPONSE_CODE, &code);
      twist_easy_getinfo (easy, TWISTINFO_SIZE_DOWNLOAD, &size);
      if (strstr (writeout, "%{http_code}") != NULL)
        printf ("%ld", code);
      else if (strstr (writeout, "%{size_download}") != NULL)
        printf ("%zu", size);
      else
        fputs (writeout, stdout);
    }
  twist_easy_cleanup (easy);
  twist_slist_free_all (headers);
  twist_slist_free_all (rcpts);
  if (out_file != NULL && out_file != stdout)
    fclose (out_file);
  twist_global_cleanup ();
  return rc == TWIST_OK ? 0 : 1;
}
