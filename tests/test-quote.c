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
#include "ssh/ssh-int.h"

#include <stdlib.h>
#include <string.h>
#include <time.h>

/* The commands of --quote for sftp: the command
   is the word up to the first space, in any case; a parameter is a word, or
   text in double quotes in which \" and \\ stand for the character after the
   backslash.  Single quotes mean nothing.  */

static int
parse (const char *text, struct twist_quote *q, char *err, size_t cap)
{
  memset (q, 0, sizeof *q);
  err[0] = 0;
  return twist_quote_parse (text, q, err, cap);
}

static int
paths_are (const struct twist_quote *q, const char *a, const char *b)
{
  return (a == NULL ? q->a == NULL : q->a != NULL && strcmp (q->a, a) == 0)
         && (b == NULL ? q->b == NULL : q->b != NULL && strcmp (q->b, b) == 0);
}

static void
test_commands (void)
{
  struct twist_quote q;
  char err[200];

  check (parse ("mkdir /a/b", &q, err, sizeof err) == TWIST_OK
         && q.cmd == TWIST_Q_MKDIR && paths_are (&q, "/a/b", NULL)
         && !q.ignore, "mkdir");
  twist_quote_clear (&q);
  check (parse ("MkDir x", &q, err, sizeof err) == TWIST_OK
         && q.cmd == TWIST_Q_MKDIR, "the command in any case");
  twist_quote_clear (&q);
  check (parse ("*rm gone", &q, err, sizeof err) == TWIST_OK
         && q.cmd == TWIST_Q_RM && q.ignore && paths_are (&q, "gone", NULL),
         "* ignores an error from the server");
  twist_quote_clear (&q);
  check (parse ("rmdir d", &q, err, sizeof err) == TWIST_OK
         && q.cmd == TWIST_Q_RMDIR, "rmdir");
  twist_quote_clear (&q);
  check (parse ("rename old new", &q, err, sizeof err) == TWIST_OK
         && q.cmd == TWIST_Q_RENAME && paths_are (&q, "old", "new"), "rename");
  twist_quote_clear (&q);
  check (parse ("ln src dst", &q, err, sizeof err) == TWIST_OK
         && q.cmd == TWIST_Q_SYMLINK && paths_are (&q, "src", "dst"), "ln");
  twist_quote_clear (&q);
  check (parse ("symlink src dst", &q, err, sizeof err) == TWIST_OK
         && q.cmd == TWIST_Q_SYMLINK, "symlink is ln");
  twist_quote_clear (&q);
  check (parse ("pwd", &q, err, sizeof err) == TWIST_OK
         && q.cmd == TWIST_Q_PWD, "pwd");
  twist_quote_clear (&q);
  check (parse ("chmod 755 f", &q, err, sizeof err) == TWIST_OK
         && q.cmd == TWIST_Q_CHMOD && q.num == 0755 && paths_are (&q, "f", NULL),
         "chmod takes octal");
  twist_quote_clear (&q);
  check (parse ("chown 1000 f", &q, err, sizeof err) == TWIST_OK
         && q.cmd == TWIST_Q_CHOWN && q.num == 1000, "chown takes decimal");
  twist_quote_clear (&q);
  check (parse ("chgrp 20 f", &q, err, sizeof err) == TWIST_OK
         && q.cmd == TWIST_Q_CHGRP && q.num == 20, "chgrp");
  twist_quote_clear (&q);
}

static void
test_words (void)
{
  struct twist_quote q;
  char err[200];

  check (parse ("rename \"a b\" \"c d\"", &q, err, sizeof err) == TWIST_OK
         && paths_are (&q, "a b", "c d"), "double quotes hold spaces");
  twist_quote_clear (&q);
  check (parse ("mkdir \"he said \\\"hi\\\"\"", &q, err, sizeof err) == TWIST_OK
         && paths_are (&q, "he said \"hi\"", NULL), "\\\" in quotes");
  twist_quote_clear (&q);
  check (parse ("mkdir \"back\\\\slash\"", &q, err, sizeof err) == TWIST_OK
         && paths_are (&q, "back\\slash", NULL), "\\\\ in quotes");
  twist_quote_clear (&q);
  check (parse ("rename 'q one' 'q two'", &q, err, sizeof err) == TWIST_OK
         && paths_are (&q, "'q", "one'"), "single quotes are not quotes");
  twist_quote_clear (&q);
  check (parse ("mkdir   spaced   out", &q, err, sizeof err) == TWIST_OK
         && paths_are (&q, "spaced", NULL), "any number of spaces; the rest of "
         "the line past the parameters is not read");
  twist_quote_clear (&q);
  check (parse ("rename \"a\"\"b\"", &q, err, sizeof err) == TWIST_OK
         && paths_are (&q, "a", "b"), "quoted words need no space between");
  twist_quote_clear (&q);
}

static void
test_errors (void)
{
  struct twist_quote q;
  char err[200];

  check (parse ("frob x", &q, err, sizeof err) != TWIST_OK
         && strstr (err, "Unknown") != NULL, "an unknown command");
  check (parse ("*frob x", &q, err, sizeof err) != TWIST_OK,
         "* does not excuse an unknown command");
  check (parse ("mkdir\tx", &q, err, sizeof err) != TWIST_OK,
         "a tab does not end the command");
  check (parse ("", &q, err, sizeof err) != TWIST_OK, "an empty command");
  check (parse ("mkdir", &q, err, sizeof err) != TWIST_OK
         && strstr (err, "parameter") != NULL, "no parameter");
  check (parse ("rename a", &q, err, sizeof err) != TWIST_OK
         && strstr (err, "parameter") != NULL, "one parameter of two");
  check (parse ("mkdir \"unterminated", &q, err, sizeof err) != TWIST_OK
         && strstr (err, "first") != NULL, "an unterminated quote");
  check (parse ("rename a \"unterminated", &q, err, sizeof err) != TWIST_OK
         && strstr (err, "second") != NULL, "an unterminated second quote");
  check (parse ("chmod 99 f", &q, err, sizeof err) != TWIST_OK,
         "a mode that is not octal");
  check (parse ("chmod 17777777777 f", &q, err, sizeof err) != TWIST_OK,
         "a mode that is too big");
  check (parse ("chown abc f", &q, err, sizeof err) != TWIST_OK,
         "an owner that is not a number");
  check (parse ("chgrp -1 f", &q, err, sizeof err) != TWIST_OK,
         "a negative group");
  check (parse ("mkdir \"\"", &q, err, sizeof err) != TWIST_OK,
         "an empty path");
  /* Nothing is left to free after a failure.  */
  check (q.a == NULL && q.b == NULL, "a failed parse leaves nothing");
}

static void
test_dates (void)
{
  int64_t t = 0;

  setenv ("TZ", "UTC", 1);
  tzset ();
  check (twist_quote_date ("Thu, 02 Jan 2020 10:00:00 GMT", &t) == TWIST_OK
         && t == 1577959200, "a date as HTTP writes it");
  check (twist_quote_date ("2 Jan 2020 10:00:00 GMT", &t) == TWIST_OK
         && t == 1577959200, "without the day of the week");
  check (twist_quote_date ("Thu Jan  2 10:00:00 2020", &t) == TWIST_OK
         && t == 1577959200, "as asctime writes it (no zone: local time)");
  check (twist_quote_date ("02 Jan 2020 10:00:00 +0100", &t) == TWIST_OK
         && t == 1577955600, "a zone offset");
  check (twist_quote_date ("02 Jan 2020 10:00:00 -0530", &t) == TWIST_OK
         && t == 1577979000, "a negative zone offset");
  check (twist_quote_date ("Thu, 02 Jan 20 10:00:00 UTC", &t) == TWIST_OK
         && t == 1577959200, "a two digit year");
  check (twist_quote_date ("yesterday", &t) != TWIST_OK, "not a date");
  check (twist_quote_date ("", &t) != TWIST_OK, "no date");
  check (twist_quote_date ("32 Jan 2020 10:00:00 GMT", &t) != TWIST_OK,
         "day 32");
  check (twist_quote_date ("30 Feb 2020 10:00:00 GMT", &t) != TWIST_OK,
         "30 February");
  check (twist_quote_date ("02 Jan 2020 25:00:00 GMT", &t) != TWIST_OK,
         "hour 25");
  check (twist_quote_date ("02 Jan 1960 10:00:00 GMT", &t) != TWIST_OK,
         "before 1970: SFTP times are unsigned");
  check (twist_quote_date ("02 Jan 2200 10:00:00 GMT", &t) != TWIST_OK,
         "past what SFTP can hold");

  /* In a command.  */
  {
    struct twist_quote q;
    char err[200];

    check (parse ("mtime \"Thu, 02 Jan 2020 10:00:00 GMT\" f", &q, err,
                  sizeof err) == TWIST_OK
           && q.cmd == TWIST_Q_MTIME && q.when == 1577959200
           && paths_are (&q, "f", NULL), "mtime with a quoted date");
    twist_quote_clear (&q);
    check (parse ("atime \"Thu, 02 Jan 2020 10:00:00 GMT\" f", &q, err,
                  sizeof err) == TWIST_OK && q.cmd == TWIST_Q_ATIME,
           "atime");
    twist_quote_clear (&q);
    check (parse ("mtime today f", &q, err, sizeof err) != TWIST_OK
           && strstr (err, "date") != NULL, "mtime with a bad date");
  }
}

int
main (void)
{
  test_commands ();
  test_words ();
  test_errors ();
  test_dates ();
  return tests_finish ();
}
