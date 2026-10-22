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
#include "ssh/ssh-int.h"

#include <ctype.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>

/* The commands of --quote for sftp.  The
   command is the word up to the first space, in any case.  A parameter is a
   word up to a space, or text in double quotes in which a backslash before a
   double quote, a single quote or a backslash stands for that character.
   Single quotes mean nothing else.  What follows the parameters a command
   needs is not read.  An asterisk before the command says an error from the
   server does not stop the transfer; it does not excuse a command that cannot
   be read.  */

static const struct
{
  const char *name;
  enum twist_quote_cmd cmd;
  int params;
} commands[] = {
  { "atime", TWIST_Q_ATIME, 2 },
  { "mtime", TWIST_Q_MTIME, 2 },
  { "chgrp", TWIST_Q_CHGRP, 2 },
  { "chmod", TWIST_Q_CHMOD, 2 },
  { "chown", TWIST_Q_CHOWN, 2 },
  { "ln", TWIST_Q_SYMLINK, 2 },
  { "symlink", TWIST_Q_SYMLINK, 2 },
  { "mkdir", TWIST_Q_MKDIR, 1 },
  { "pwd", TWIST_Q_PWD, 0 },
  { "rename", TWIST_Q_RENAME, 2 },
  { "rm", TWIST_Q_RM, 1 },
  { "rmdir", TWIST_Q_RMDIR, 1 }
};

void
twist_quote_clear (struct twist_quote *q)
{
  free (q->a);
  free (q->b);
  q->a = q->b = NULL;
}

static void
say (char *err, size_t cap, const char *msg)
{
  if (err != NULL && cap > 0)
    snprintf (err, cap, "%s", msg);
}

/* The next parameter of *P, in a new string.  1: got one.  0: there is none.
   -1: a quote that is not closed (nothing is allocated), or no memory.  */
static int
next_word (const char **p, char **out)
{
  const char *s = *p;
  char *w;
  size_t n = 0;

  *out = NULL;
  while (*s == ' ')
    s++;
  if (*s == 0)
    {
      *p = s;
      return 0;
    }
  w = malloc (strlen (s) + 1);
  if (w == NULL)
    return -1;
  if (*s == '"')
    {
      s++;
      while (*s != 0 && *s != '"')
        {
          if (*s == '\\' && (s[1] == '"' || s[1] == '\\' || s[1] == '\''))
            s++;
          w[n++] = *s++;
        }
      if (*s != '"')
        {
          free (w);
          return -1;
        }
      s++;
    }
  else
    while (*s != 0 && *s != ' ')
      w[n++] = *s++;
  w[n] = 0;
  *p = s;
  /* An empty path names nothing.  */
  if (n == 0)
    {
      free (w);
      return 0;
    }
  *out = w;
  return 1;
}

static int
number (const char *s, int base, unsigned long max, uint32_t *out)
{
  char *end;
  unsigned long v;
  const char *d;

  /* Digits only: no sign, no space, no prefix.  */
  for (d = s; *d != 0; d++)
    if (!(base == 8 ? (*d >= '0' && *d <= '7') : isdigit ((unsigned char) *d)))
      return -1;
  if (*s == 0)
    return -1;
  v = strtoul (s, &end, base);
  if (*end != 0 || v > max)
    return -1;
  *out = (uint32_t) v;
  return 0;
}

/* ---- dates ---- */

static const char *const months[] = {
  "january", "february", "march", "april", "may", "june", "july", "august",
  "september", "october", "november", "december"
};

static const char *const weekdays[] = {
  "monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday"
};

/* Which of NAMES the word is, by its first three letters and, if it is longer,
   all of it; -1 if none.  */
static int
name_index (const char *w, const char *const *names, int n)
{
  size_t len = strlen (w);
  int i;

  if (len < 3)
    return -1;
  for (i = 0; i < n; i++)
    if (strncasecmp (w, names[i], 3) == 0
        && (len == 3 || strcasecmp (w, names[i]) == 0))
      return i;
  return -1;
}

static int
leap (int y)
{
  return (y % 4 == 0 && y % 100 != 0) || y % 400 == 0;
}

static int
month_days (int y, int m)
{
  static const int d[] = { 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 };

  return m == 1 && leap (y) ? 29 : d[m];
}

/* Days from 1970-01-01 to the day, in the proleptic Gregorian calendar.  */
static int64_t
days_from_civil (int64_t y, int m, int d)
{
  int64_t era, yoe, doy, doe;

  y -= m < 2;
  era = (y >= 0 ? y : y - 399) / 400;
  yoe = y - era * 400;
  doy = (153 * (m + (m > 1 ? -2 : 10)) + 2) / 5 + d - 1;
  doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
  return era * 146097 + doe - 719468;
}

/* A time of day: H:M or H:M:S.  */
static int
clock_time (const char *s, int *h, int *m, int *sec)
{
  char *e;
  long v[3] = { 0, 0, 0 };
  int i;

  for (i = 0; i < 3; i++)
    {
      if (!isdigit ((unsigned char) *s))
        return -1;
      v[i] = strtol (s, &e, 10);
      s = e;
      if (*s == ':' && i < 2)
        s++;
      else
        break;
    }
  if (*s != 0 || i < 1)
    return -1;
  if (v[0] > 23 || v[1] > 59 || v[2] > 59)
    return -1;
  *h = (int) v[0];
  *m = (int) v[1];
  *sec = (int) v[2];
  return 0;
}

int
twist_quote_date (const char *s, int64_t *out)
{
  char *copy = twist_strdup (s != NULL ? s : "");
  char *tok, *save = NULL;
  int day = 0, month = -1, year = -1, h = -1, mi = 0, sec = 0;
  int have_zone = 0, zone = 0, rc = -1;
  int64_t t;

  if (copy == NULL)
    return -1;
  for (tok = strtok_r (copy, " ,", &save); tok != NULL;
       tok = strtok_r (NULL, " ,", &save))
    {
      size_t n = strlen (tok);

      if (strchr (tok, ':') != NULL)
        {
          if (h >= 0 || clock_time (tok, &h, &mi, &sec) != 0)
            goto done;
        }
      else if ((tok[0] == '+' || tok[0] == '-') && n == 5
               && isdigit ((unsigned char) tok[1]))
        {
          int hh = (tok[1] - '0') * 10 + (tok[2] - '0');
          int mm = (tok[3] - '0') * 10 + (tok[4] - '0');

          if (have_zone || hh > 23 || mm > 59)
            goto done;
          zone = (hh * 60 + mm) * (tok[0] == '-' ? -1 : 1);
          have_zone = 1;
        }
      else if (isdigit ((unsigned char) tok[0]))
        {
          char *e;
          long v = strtol (tok, &e, 10);

          if (*e != 0)
            goto done;
          if (n >= 3)
            {
              if (year >= 0)
                goto done;
              year = (int) v;
            }
          else if (day == 0)
            day = (int) v;
          else if (year < 0)
            year = (int) (v < 70 ? 2000 + v : 1900 + v);
          else
            goto done;
        }
      else if (name_index (tok, months, 12) >= 0)
        {
          if (month >= 0)
            goto done;
          month = name_index (tok, months, 12);
        }
      else if (name_index (tok, weekdays, 7) >= 0)
        ;
      else if (strcasecmp (tok, "GMT") == 0 || strcasecmp (tok, "UTC") == 0
               || strcasecmp (tok, "UT") == 0 || strcasecmp (tok, "Z") == 0)
        have_zone = 1;
      else
        goto done;
    }
  if (day < 1 || month < 0 || year < 1970 || h < 0
      || day > month_days (year, month))
    goto done;
  if (have_zone)
    t = (days_from_civil (year, month, day) * 24 + h) * 3600 + mi * 60 + sec
        - (int64_t) zone * 60;
  else
    {
      struct tm tmv;
      time_t local;

      memset (&tmv, 0, sizeof tmv);
      tmv.tm_year = year - 1900;
      tmv.tm_mon = month;
      tmv.tm_mday = day;
      tmv.tm_hour = h;
      tmv.tm_min = mi;
      tmv.tm_sec = sec;
      tmv.tm_isdst = -1;
      local = mktime (&tmv);
      if (local == (time_t) -1)
        goto done;
      t = (int64_t) local;
    }
  /* SFTP v3 has 32 bits of unsigned seconds.  */
  if (t < 0 || t > (int64_t) UINT32_MAX)
    goto done;
  *out = t;
  rc = 0;
done:
  free (copy);
  return rc == 0 ? TWIST_OK : TWIST_ERR_INVAL;
}

/* ---- a command ---- */

int
twist_quote_parse (const char *text, struct twist_quote *q, char *err,
                   size_t cap)
{
  const char *p = text;
  char word[16];
  size_t n = 0, i;
  int params = -1, r;
  char *first = NULL, *second = NULL;

  memset (q, 0, sizeof *q);
  if (*p == '*')
    {
      q->ignore = 1;
      p++;
    }
  while (*p != 0 && *p != ' ' && n < sizeof word - 1)
    word[n++] = *p++;
  word[n] = 0;
  if (*p != 0 && *p != ' ')
    {
      /* A longer word than any command.  */
      say (err, cap, _("Unknown SFTP command"));
      return TWIST_ERR_INVAL;
    }
  for (i = 0; i < sizeof commands / sizeof commands[0]; i++)
    if (strcasecmp (word, commands[i].name) == 0)
      {
        q->cmd = commands[i].cmd;
        params = commands[i].params;
        break;
      }
  if (params < 0)
    {
      say (err, cap, _("Unknown SFTP command"));
      return TWIST_ERR_INVAL;
    }
  if (params >= 1)
    {
      r = next_word (&p, &first);
      if (r < 0)
        {
          say (err, cap, _("Syntax error: Bad first parameter"));
          return TWIST_ERR_INVAL;
        }
      if (r == 0)
        {
          say (err, cap, _("Syntax error in SFTP command. Supply "
                           "parameter(s)"));
          return TWIST_ERR_INVAL;
        }
    }
  if (params >= 2)
    {
      r = next_word (&p, &second);
      if (r < 0)
        {
          free (first);
          say (err, cap, _("Syntax error: Bad second parameter"));
          return TWIST_ERR_INVAL;
        }
      if (r == 0)
        {
          free (first);
          say (err, cap, _("Syntax error in SFTP command. Supply "
                           "parameter(s)"));
          return TWIST_ERR_INVAL;
        }
    }
  switch (q->cmd)
    {
    case TWIST_Q_CHMOD:
      if (number (first, 8, 07777, &q->num) != 0)
        {
          say (err, cap, _("the mode is not an octal number"));
          goto bad;
        }
      break;
    case TWIST_Q_CHOWN:
    case TWIST_Q_CHGRP:
      if (number (first, 10, UINT32_MAX, &q->num) != 0)
        {
          say (err, cap, _("the owner or group is not a number"));
          goto bad;
        }
      break;
    case TWIST_Q_ATIME:
    case TWIST_Q_MTIME:
      if (twist_quote_date (first, &q->when) != TWIST_OK)
        {
          say (err, cap, q->cmd == TWIST_Q_ATIME
               ? _("incorrect date format for atime")
               : _("incorrect date format for mtime"));
          goto bad;
        }
      break;
    default:
      break;
    }
  /* The commands with a number or a date have the path second.  */
  if (q->cmd == TWIST_Q_CHMOD || q->cmd == TWIST_Q_CHOWN
      || q->cmd == TWIST_Q_CHGRP || q->cmd == TWIST_Q_ATIME
      || q->cmd == TWIST_Q_MTIME)
    {
      free (first);
      q->a = second;
    }
  else
    {
      q->a = first;
      q->b = second;
    }
  return TWIST_OK;
bad:
  free (first);
  free (second);
  memset (q, 0, sizeof *q);
  return TWIST_ERR_INVAL;
}
