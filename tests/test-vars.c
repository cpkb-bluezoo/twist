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
#include <unistd.h>

/* Variables as the curl documentation has them: --variable name=text,
   name@file, %name and %name=default for the environment; {{name}} in the
   parameter of an --expand- option, with the functions trim, json, url, b64
   and 64dec after colons.  Undefined is empty.  */

static struct twist_vars *vars;
static char err[256];

static void
def_ok (const char *spec, const char *what)
{
  err[0] = 0;
  check (twist_vars_define (vars, spec, err, sizeof err) == TWIST_OK, what);
}

static int
def_fails (const char *spec, int want, const char *text)
{
  int rc;

  err[0] = 0;
  rc = twist_vars_define (vars, spec, err, sizeof err);
  if (rc != want || (text != NULL && strstr (err, text) == NULL))
    fprintf (stderr, "  define [%s] -> %d [%s], wanted %d [%s]\n", spec, rc, err,
             want, text != NULL ? text : "");
  return rc == want && (text == NULL || strstr (err, text) != NULL);
}

static int
is (const char *text, const char *expect)
{
  char *out;
  int ok;

  err[0] = 0;
  out = twist_vars_expand (vars, text, err, sizeof err);
  ok = out != NULL && strcmp (out, expect) == 0;
  if (!ok)
    fprintf (stderr, "  expand [%s] -> [%s] (%s), wanted [%s]\n", text,
             out != NULL ? out : "(failed)", err, expect);
  free (out);
  return ok;
}

static int
fails (const char *text, const char *what)
{
  char *out;
  int ok;

  err[0] = 0;
  out = twist_vars_expand (vars, text, err, sizeof err);
  ok = out == NULL && strstr (err, what) != NULL;
  if (!ok)
    fprintf (stderr, "  expand [%s] -> [%s] (%s), wanted an error with [%s]\n",
             text, out != NULL ? out : "(failed)", err, what);
  free (out);
  return ok;
}

static void
write_file (const char *path, const void *data, size_t n)
{
  FILE *fp = fopen (path, "wb");

  if (fp != NULL)
    {
      fwrite (data, 1, n, fp);
      fclose (fp);
    }
}

static void
test_define (void)
{
  char path[200];

  def_ok ("v=hello", "name=content");
  check (is ("{{v}}", "hello"), "it is there");
  def_ok ("v=again", "again");
  check (is ("{{v}}", "again"), "the new content replaces the old");
  def_ok ("w=a=b", "a = in the content");
  check (is ("{{w}}", "a=b"), "is part of it");
  def_ok ("e=", "empty content");
  check (is ("[{{e}}]", "[]"), "is empty");
  def_ok ("a_B9=1", "letters, digits and underscore");
  def_ok ("9x=1", "a digit may start it");
  def_ok ("V=upper", "case");
  check (is ("{{V}}{{v}}", "upperagain"), "names are case sensitive");

  snprintf (path, sizeof path, "/tmp/twist-vars-%ld.txt", (long) getpid ());
  write_file (path, "  padded value \n", 16);
  {
    char spec[240];

    snprintf (spec, sizeof spec, "f@%s", path);
    def_ok (spec, "name@file");
    check (is ("[{{f}}]", "[  padded value \n]"), "the file as it is");
    snprintf (spec, sizeof spec, "g=@%s", path);
    def_ok (spec, "name=@file is text");
    {
      char want[240];

      snprintf (want, sizeof want, "@%s", path);
      check (is ("{{g}}", want), "an @ after = is part of the text");
    }
  }
  check (def_fails ("h@/nonexistent/file", TWIST_ERR_FILE, "/nonexistent/file"),
         "a file that is not there");

  /* Names.  */
  check (def_fails ("a-b=1", TWIST_ERR_INVAL, "a-b"), "a dash");
  check (def_fails ("=1", TWIST_ERR_INVAL, "name"), "no name");
  check (def_fails ("sp ace=1", TWIST_ERR_INVAL, "sp ace"), "a space");
  check (def_fails ("x.y=1", TWIST_ERR_INVAL, "x.y"), "a dot");
  check (def_fails ("\xc3\xa9=1", TWIST_ERR_INVAL, NULL), "a letter that is not ASCII");
  check (def_fails ("novalue", TWIST_ERR_INVAL, "novalue"),
         "a name and nothing to give it");
  check (def_fails ("", TWIST_ERR_INVAL, NULL), "nothing at all");
  check (def_fails ("@file", TWIST_ERR_INVAL, NULL), "@ first");
  check (def_fails ("%=x", TWIST_ERR_INVAL, NULL), "% and no name");
  unlink (path);
}

static void
test_environment (void)
{
  char path[200];

  setenv ("TWIST_TEST_VAR", "fromenv", 1);
  unsetenv ("TWIST_TEST_UNSET");
  def_ok ("%TWIST_TEST_VAR", "%name imports it");
  check (is ("{{TWIST_TEST_VAR}}", "fromenv"), "the environment's value");
  check (def_fails ("%TWIST_TEST_UNSET", TWIST_ERR_INVAL, "TWIST_TEST_UNSET"),
         "%name when it is not set is an error");
  def_ok ("%TWIST_TEST_UNSET=dflt", "%name=default");
  check (is ("{{TWIST_TEST_UNSET}}", "dflt"), "the default when it is not set");
  def_ok ("%TWIST_TEST_VAR=dflt", "a default when it is set");
  check (is ("{{TWIST_TEST_VAR}}", "fromenv"),
         "the environment's value wins, as the manual says");
  snprintf (path, sizeof path, "/tmp/twist-vars-env-%ld.txt", (long) getpid ());
  write_file (path, "from a file", 11);
  {
    char spec[240];

    snprintf (spec, sizeof spec, "%%TWIST_TEST_UNSET2@%s", path);
    unsetenv ("TWIST_TEST_UNSET2");
    def_ok (spec, "%name@file is the default");
    check (is ("{{TWIST_TEST_UNSET2}}", "from a file"), "from the file");
  }
  unlink (path);
  setenv ("TWIST_TEST_EMPTY", "", 1);
  def_ok ("%TWIST_TEST_EMPTY", "set and empty is set");
  check (is ("[{{TWIST_TEST_EMPTY}}]", "[]"), "and empty");
  check (def_fails ("%a-b", TWIST_ERR_INVAL, "a-b"), "a bad name after %");
}

static void
test_expansion (void)
{
  def_ok ("v=hello", "v");
  check (is ("[{{v}}]", "[hello]"), "one");
  check (is ("{{v}}{{v}}", "hellohello"), "twice");
  check (is ("x{{v}}y{{v}}z", "xhelloyhelloz"), "among text");
  check (is ("{{nothere}}", ""), "an undefined variable is empty");
  check (is ("no variables here", "no variables here"), "none");
  check (is ("", ""), "an empty string");
  check (is ("\\{{v}}", "{{v}}"), "a backslash makes {{ plain");
  check (is ("a\\{{v}}b{{v}}", "a{{v}}bhello"), "and only that one");
  check (is ("\\\\{{v}}", "\\{{v}}"), "a backslash before the backslash is not special");
  check (is ("{{v}", "{{v}"), "no closing");
  check (is ("{{", "{{"), "{{ at the end");
  check (is ("a{{", "a{{"), "and after text");
  check (is ("{{}}", "{{}}"), "nothing between");
  check (is ("{{ v }}", "{{ v }}"), "spaces");
  check (is ("{{bad-name}}", "{{bad-name}}"), "a name that is none");
  check (is ("{{:trim}}", "{{:trim}}"), "a function with no name");
  check (is ("{v}", "{v}"), "one brace");
  check (is ("}}", "}}"), "closing braces alone");
  check (is ("{{{v}}}", "{hello}"), "braces around");
  /* The content is not expanded again.  */
  def_ok ("a={{v}}", "a");
  check (is ("{{a}}", "{{v}}"), "content with {{ in it is text");
  check (is ("100%{{v}}%s", "100%hello%s"), "percent signs and the like");
}

static void
test_functions (void)
{
  const char nul[] = { 'a', 0, 'b' };
  char path[200];

  def_ok ("pad=  pad  ", "pad");
  check (is ("[{{pad:trim}}][{{pad}}]", "[pad][  pad  ]"), "trim");
  def_ok ("ws= \t\r\n\x0b\x0c x y \t\r\n", "ws");
  check (is ("[{{ws:trim}}]", "[x y]"), "all white space, both ends, not inside");
  def_ok ("blank=   ", "blank");
  check (is ("[{{blank:trim}}]", "[]"), "nothing left");

  def_ok ("j=he\"l\\lo", "j");
  check (is ("{{j:json}}", "he\\\"l\\\\lo"), "json quotes and backslashes");
  def_ok ("jc=a\tb\nc\rd\be\ff", "jc");
  check (is ("{{jc:json}}", "a\\tb\\nc\\rd\\be\\ff"), "json short escapes");
  def_ok ("jx=a\x01\x1f/\x7f", "jx");
  check (is ("{{jx:json}}", "a\\u0001\\u001f/\x7f"), "json control characters");
  def_ok ("ju=caf\xc3\xa9 \xe2\x82\xac", "ju");
  check (is ("{{ju:json}}", "caf\xc3\xa9 \xe2\x82\xac"), "UTF-8 is left");

  def_ok ("u=a b/c?d=e&f", "u");
  check (is ("{{u:url}}", "a%20b%2Fc%3Fd%3De%26f"), "url");
  def_ok ("ur=AZaz09-._~!*()' \xc3\xa9", "ur");
  check (is ("{{ur:url}}", "AZaz09-._~%21%2A%28%29%27%20%C3%A9"),
         "only the unreserved are left");

  def_ok ("b1=a", "b1");
  def_ok ("b2=ab", "b2");
  def_ok ("b3=abc", "b3");
  def_ok ("b4=abcd", "b4");
  check (is ("{{b1:b64}} {{b2:b64}} {{b3:b64}} {{b4:b64}} [{{e:b64}}]",
             "YQ== YWI= YWJj YWJjZA== []"), "b64 and its padding");

  def_ok ("enc=aGVsbG8=", "enc");
  check (is ("{{enc:64dec}}", "hello"), "64dec");
  def_ok ("encn=aGVsbG8", "encn");
  check (is ("{{encn:64dec}}", "hello"), "64dec without padding");
  def_ok ("bad=!!!", "bad");
  check (is ("{{bad:64dec}}", "[64dec-fail]"), "64dec of what is not base64");
  def_ok ("rt=\xc3\xa9 round/trip?", "rt");
  check (is ("{{rt:b64:64dec}}", "\xc3\xa9 round/trip?"), "b64 and back");

  /* Chains, left to right.  */
  def_ok ("c= hi ", "c");
  check (is ("{{c:trim:b64}}", "aGk="), "trim, then b64");
  check (is ("{{c:b64:trim}}", "IGhpIA=="), "b64, then trim");
  check (is ("{{c:trim,b64}}", "aGk="), "a comma between functions, as the manual says");
  check (is ("{{c:trim:url}}", "hi"), "trim and url");
  check (is ("{{nothere:b64}}", ""), "a function of nothing");

  check (fails ("{{v:nosuch}}", "nosuch"), "an unknown function");
  check (fails ("{{pad:}}", "function"), "a colon and no function");
  check (fails ("{{pad:trim:}}", "function"), "and after one");
  check (fails ("{{pad::trim}}", "function"), "and before one");
  check (fails ("{{x:y}}", "y"), "a name and an unknown function");

  /* Content with a NUL cannot be in a string: it must be encoded.  */
  snprintf (path, sizeof path, "/tmp/twist-vars-nul-%ld.bin", (long) getpid ());
  write_file (path, nul, sizeof nul);
  {
    char spec[240];

    snprintf (spec, sizeof spec, "n@%s", path);
    def_ok (spec, "a file with a NUL");
  }
  check (fails ("{{n}}", "NUL"), "a NUL not encoded is an error");
  check (fails ("{{n:trim}}", "NUL"), "trim does not encode it");
  check (is ("{{n:b64}}", "YQBi"), "b64 encodes it");
  check (is ("{{n:json}}", "a\\u0000b"), "json");
  check (is ("{{n:url}}", "a%00b"), "url");
  check (is ("{{n:b64:64dec:b64}}", "YQBi"),
         "a NUL in the middle of a chain is fine, only the end matters");
  check (fails ("{{n:b64:64dec}}", "NUL"), "64dec that makes a NUL is an error");
  unlink (path);
}

static void
test_limits (void)
{
  size_t n = 7600000;
  char *spec = malloc (n + 20);
  char *out;

  check (spec != NULL, "memory");
  memcpy (spec, "big=", 4);
  memset (spec + 4, 'x', n);
  spec[4 + n] = 0;
  def_ok (spec, "a content of seven and a half megabytes");
  free (spec);
  out = twist_vars_expand (vars, "{{big}}", err, sizeof err);
  check (out != NULL && strlen (out) == n, "it can be used");
  free (out);
  out = twist_vars_expand (vars, "{{big}}{{big}}", err, sizeof err);
  check (out == NULL && strstr (err, "large") != NULL,
         "twice would be over ten megabytes: refused");
  free (out);
  out = twist_vars_expand (vars, "{{big:b64}}", err, sizeof err);
  check (out == NULL && strstr (err, "large") != NULL,
         "so is a result that grows past it");
  free (out);
  out = twist_vars_expand (vars, "{{big:trim}}", err, sizeof err);
  check (out != NULL && strlen (out) == n, "one that does not is not");
  free (out);
}

int
main (void)
{
  vars = twist_vars_new ();
  check (vars != NULL, "a set");
  test_define ();
  test_environment ();
  test_expansion ();
  test_functions ();
  test_limits ();
  twist_vars_free (vars);
  return tests_finish ();
}
