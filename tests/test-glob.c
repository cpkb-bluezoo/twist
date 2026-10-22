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

#include "check.h"
#include "twist-int.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* URL globbing: {a,b,c} and [1-10], [a-z], [01-10:2],
   the URLs they make in order with the last glob going fastest, a backslash
   to make a special character plain, and #1 in an output name for what the
   first glob was.  */

#define BASE "http://127.0.0.1:1/"

/* Every URL a pattern makes, after BASE if the pattern is not a whole URL,
   joined by spaces; or the error.  */
static const char *
all (const char *pattern)
{
  static char out[4096];
  struct twist_glob *g = NULL;
  char err[512], *url;
  size_t used = 0;
  char full[512];
  int rc;

  snprintf (full, sizeof full, "%s%s", strstr (pattern, "://") ? "" : BASE,
            pattern);
  out[0] = 0;
  rc = twist_glob_parse (full, &g, err, sizeof err);
  if (rc != TWIST_OK)
    {
      snprintf (out, sizeof out, "ERROR %s", err);
      return out;
    }
  while (twist_glob_next (g, &url) == 1)
    {
      const char *u = strstr (pattern, "://") ? url : url + strlen (BASE);

      /* snprintf says how long the text would have been, which is more than
         the room when it did not fit; adding that made the room, taken from
         the size of the buffer, a huge number.  What does not fit is dropped,
         and the buffer ends in its terminator.  */
      if (used < sizeof out - 1)
        {
          int w = snprintf (out + used, sizeof out - used, "%s%s",
                            used ? " " : "", u);

          if (w > 0)
            used += (size_t) w;
          if (used > sizeof out - 1)
            used = sizeof out - 1;
        }
      free (url);
    }
  twist_glob_free (g);
  return out;
}

static int
is (const char *pattern, const char *expect)
{
  const char *got = all (pattern);

  if (strcmp (got, expect) != 0)
    fprintf (stderr, "  %s -> [%s], wanted [%s]\n", pattern, got, expect);
  return strcmp (got, expect) == 0;
}

static int
fails (const char *pattern, const char *what)
{
  const char *got = all (pattern);

  if (strncmp (got, "ERROR ", 6) != 0 || strstr (got, what) == NULL)
    fprintf (stderr, "  %s -> [%s], wanted an error with [%s]\n", pattern, got,
             what);
  return strncmp (got, "ERROR ", 6) == 0 && strstr (got, what) != NULL;
}

static void
test_expansion (void)
{
  check (is ("{b,a}_[1-2]", "b_1 b_2 a_1 a_2"), "a set and a range: the last goes fastest");
  check (is ("[1-3]/{x,y}", "1/x 1/y 2/x 2/y 3/x 3/y"), "a range and a set");
  check (is ("[1-2][3-4][5-6]", "135 136 145 146 235 236 245 246"), "three ranges");
  check (is ("{a,b}{c,d}", "ac ad bc bd"), "two sets");
  check (is ("{a}", "a"), "a set of one");
  check (is ("{a,a}", "a a"), "a set is not made unique");
  check (is ("{a,,b}", "a  b"), "an empty element");
  check (is ("[08-11]", "08 09 10 11"), "a range padded to the width of its start");
  check (is ("[9-11]", "9 10 11"), "and not padded when it does not begin with a 0");
  check (is ("[001-003]", "001 002 003"), "padded to three");
  check (is ("[0-3]", "0 1 2 3"), "a lone 0 is not padding");
  check (is ("[00-3]", "00 01 02 03"), "two zeros are");
  check (is ("[1-1]", "1"), "a range of one");
  check (is ("[a-d]", "a b c d"), "letters");
  check (is ("[A-C]", "A B C"), "capitals");
  check (is ("[1-10:4]", "1 5 9"), "a step");
  check (is ("[a-g:3]", "a d g"), "a step in letters");
  check (is ("[1-3:2]x", "1x 3x"), "a step, and text after");
  check (is ("plain", "plain"), "no glob: one URL");
}

static void
test_escapes (void)
{
  check (is ("\\{a,b\\}", "{a,b}"), "a backslash makes a brace plain");
  check (is ("\\[1-2\\]", "[1-2]"), "and a bracket");
  check (is ("\\]x", "]x"), "a closing one");
  check (is ("\\x", "\\x"), "other backslashes stay");
  check (is ("a\\\\b", "a\\\\b"), "even two");
  check (is ("a\\,b", "a\\,b"), "a comma outside a set is a comma");
  check (is ("{a\\,b,c}", "a,b c"), "in a set a backslash escapes a comma");
  check (is ("{a\\}b}", "a}b"), "and a brace");
  check (is ("{a\\\\b,c}", "a\\b c"), "and a backslash");
  check (is ("{a\\xb}", "axb"), "and anything");
}

static void
test_errors (void)
{
  /* BASE is 19 characters, so a pattern starts at position 20.  */
  check (fails ("[3-1]", "bad range in URL position 25:"), "a range backwards");
  check (fails ("[b-a]", "bad range in URL position 25:"), "letters backwards");
  check (fails ("[a-C]", "bad range in URL position 25:"), "one of each");
  check (fails ("[1-]", "bad range in URL position 23:"), "no end");
  check (fails ("[1-3", "bad range in URL position 23:"), "no closing bracket");
  check (fails ("a[1-2", "bad range in URL position 24:"), "and after text");
  check (fails ("[1-3:0]", "bad range in URL position 27:"), "a step of 0");
  check (fails ("[1-3:x]", "bad range in URL position 25:"), "a step that is not one");
  check (fails ("[a-z:0]", "bad range in URL position 27:"), "a step of 0 in letters");
  check (fails ("[-1-2]", "bad range specification in URL position 21:"), "a sign");
  check (fails ("[[1-2]]", "bad range specification in URL position 21:"), "a bracket in a bracket");
  check (fails ("[1-99999999999999999999]", "bad range"), "a number too big");
  check (fails ("{a,b", "unmatched brace in URL position 20:"), "no closing brace");
  check (fails ("a{b", "unmatched brace in URL position 21:"), "and after text");
  check (fails ("{}", "empty string within braces in URL position 21:"), "an empty set");
  check (fails ("{a,{b,c}}", "nested brace in URL position 23:"), "a set in a set");
  check (fails ("{a[1-2]}", "nested brace in URL position 22:"), "a range in a set");
  check (fails ("]x", "unmatched close brace/bracket in URL position 20:"), "a stray bracket");
  check (fails ("}x", "unmatched close brace/bracket in URL position 20:"), "and a stray brace");
  /* The message shows the URL and where.  */
  {
    const char *m = all ("[3-1]");

    check (strstr (m, "\n" BASE "[3-1]\n") != NULL
           && strstr (m, "\n                        ^") != NULL,
           "the URL and a caret under the place");
  }
}

static void
test_ipv6 (void)
{
  check (is ("http://[::1]:1/{x,y}", "http://[::1]:1/x http://[::1]:1/y"),
         "an IPv6 address is not a range");
  check (is ("http://[fe80::1%25eth0]:1/[1-2]",
             "http://[fe80::1%25eth0]:1/1 http://[fe80::1%25eth0]:1/2"),
         "nor with a zone");
  check (is ("http://user@[2001:db8::7]/f", "http://user@[2001:db8::7]/f"),
         "nor after a user name");
  check (is ("http://[::1]/[a-b]", "http://[::1]/a http://[::1]/b"),
         "and a range after it is one");
}

static void
test_values (void)
{
  struct twist_glob *g = NULL;
  char err[256], *url, *name;
  int n = 0;

  check (twist_glob_parse ("http://h/{x,y}/[1-2]", &g, err, sizeof err)
         == TWIST_OK && twist_glob_count (g) == 2, "two globs");
  while (twist_glob_next (g, &url) == 1)
    {
      static const char *v1[] = { "x", "x", "y", "y" };
      static const char *v2[] = { "1", "2", "1", "2" };

      check (strcmp (twist_glob_value (g, 1), v1[n]) == 0
             && strcmp (twist_glob_value (g, 2), v2[n]) == 0,
             "what each glob is now");
      n++;
      free (url);
    }
  check (n == 4, "four URLs");
  check (twist_glob_value (g, 0) == NULL && twist_glob_value (g, 3) == NULL,
         "there is no glob 0 or 3");
  twist_glob_free (g);

  /* Names: #1 is the first glob, whatever it was.  */
  check (twist_glob_parse ("http://h/{x,y}/[01-02]", &g, err, sizeof err)
         == TWIST_OK, "parse");
  twist_glob_next (g, &url);
  free (url);
  twist_glob_next (g, &url);
  free (url);
  name = twist_glob_name (g, "out_#1_#2.txt");
  check (name != NULL && strcmp (name, "out_x_02.txt") == 0, "#1 and #2");
  free (name);
  name = twist_glob_name (g, "#2#2#1");
  check (name != NULL && strcmp (name, "02x" "") != 0
         && strcmp (name, "0202x") == 0, "in any order, more than once");
  free (name);
  name = twist_glob_name (g, "a#3b#0c#d#");
  check (name != NULL && strcmp (name, "a#3b#0c#d#") == 0,
         "a number that is no glob, and a # alone, are text");
  free (name);
  name = twist_glob_name (g, "esc\\#1");
  check (name != NULL && strcmp (name, "esc\\x") == 0,
         "a backslash does not escape it");
  free (name);
  twist_glob_free (g);
}

/* A great many URLs are not made at once.  */
static void
test_lazy (void)
{
  struct twist_glob *g = NULL;
  char err[256], *url;
  int i;

  check (twist_glob_parse ("http://h/[1-4000000000]/[1-4000000000]", &g, err,
                           sizeof err) == TWIST_OK, "a large product");
  for (i = 0; i < 3; i++)
    {
      check (twist_glob_next (g, &url) == 1, "the first few");
      if (i == 2)
        check (strcmp (url, "http://h/1/3") == 0, "in order");
      free (url);
    }
  twist_glob_free (g);
}

int
main (void)
{
  test_expansion ();
  test_escapes ();
  test_errors ();
  test_ipv6 ();
  test_values ();
  test_lazy ();
  return tests_finish ();
}
