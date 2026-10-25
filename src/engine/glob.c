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
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* URL globbing:

     {a,b,c}      one of these; no set inside a set
     [1-10]       a range of numbers; [01-10] keeps the width of its start
     [a-z]        a range of letters, one case
     [1-10:3]     every third

   A pattern with several globs makes the product of them, with the last glob
   going fastest.  The URLs are made one at a time, so a product too large to
   hold is no trouble until it is used.  A backslash before a brace or bracket
   makes it plain text; in a set it escapes any character.  A bracket around an
   IPv6 address is the address and not a range.

   The errors say where in the URL, with the URL and a caret.  */

enum
{
  P_TEXT,
  P_SET,
  P_NUM,
  P_CHAR
};

struct part
{
  int kind;
  char *text;			/* P_TEXT.  */
  char **items;			/* P_SET.  */
  size_t nitems;
  unsigned long long lo, step;	/* P_NUM; for P_CHAR, the letters.  */
  size_t count;			/* How many values a glob has.  */
  int width;			/* P_NUM: pad with zeros to this.  */
  size_t pos;			/* Which value it is at.  */
  char val[24];			/* P_NUM and P_CHAR: the value as text.  */
};

struct twist_glob
{
  struct part *parts;
  size_t nparts, cap;
  size_t nglobs;
  int started, done;
};

/* Largest number in a range.  Counting the values must not overflow.  */
#define GLOB_MAX_NUMBER (UINT64_MAX / 4)

static void
part_clear (struct part *p)
{
  size_t i;

  free (p->text);
  for (i = 0; i < p->nitems; i++)
    free (p->items[i]);
  free (p->items);
}

void
twist_glob_free (struct twist_glob *g)
{
  size_t i;

  if (g == NULL)
    return;
  for (i = 0; i < g->nparts; i++)
    part_clear (&g->parts[i]);
  free (g->parts);
  free (g);
}

static struct part *
add_part (struct twist_glob *g, int kind)
{
  struct part *p;

  if (g->nparts == g->cap)
    {
      size_t cap = g->cap == 0 ? 8 : g->cap * 2;
      struct part *grown = realloc (g->parts, cap * sizeof *grown);

      if (grown == NULL)
        return NULL;
      g->parts = grown;
      g->cap = cap;
    }
  p = &g->parts[g->nparts++];
  memset (p, 0, sizeof *p);
  p->kind = kind;
  if (kind != P_TEXT)
    g->nglobs++;
  return p;
}

/* Growing text.  */
struct buf
{
  char *p;
  size_t n, cap;
};

static int
buf_add (struct buf *b, char c)
{
  if (b->n + 2 > b->cap)
    {
      size_t cap = b->cap == 0 ? 32 : b->cap * 2;
      char *grown = realloc (b->p, cap);

      if (grown == NULL)
        return -1;
      b->p = grown;
      b->cap = cap;
    }
  b->p[b->n++] = c;
  b->p[b->n] = 0;
  return 0;
}

static void
fail_at (const char *pattern, size_t pos, const char *what, char *err,
         size_t cap)
{
  size_t len = strlen (pattern);

  /* One past the end is a place: where a range that is not right is found
     to be so.  */
  if (pos > len + 1)
    pos = len + 1;
  if (pos < 1)
    pos = 1;
  snprintf (err, cap, "%s in URL position %zu:\n%s\n%*s^", what, pos, pattern,
            (int) (pos - 1), "");
}

/* Is the bracket at P the start of an IPv6 address?  It has a colon and
   nothing but what such an address (and its zone) is made of.  */
static size_t
ipv6_end (const char *p)
{
  size_t i;
  int colon = 0, zone = 0;

  for (i = 1; p[i] != 0 && p[i] != ']'; i++)
    {
      if (zone)
        {
          /* The name of an interface.  */
          if (!isalnum ((unsigned char) p[i]) && p[i] != '.' && p[i] != '_'
              && p[i] != '~' && p[i] != '-' && p[i] != '%')
            return 0;
        }
      else if (p[i] == '%')
        zone = 1;
      else if (p[i] == ':')
        colon = 1;
      else if (!isxdigit ((unsigned char) p[i]) && p[i] != '.')
        return 0;
    }
  return p[i] == ']' && colon ? i : 0;
}

static int
flush_text (struct twist_glob *g, struct buf *b)
{
  struct part *p;

  if (b->n == 0)
    return 0;
  p = add_part (g, P_TEXT);
  if (p == NULL)
    return -1;
  p->text = b->p;
  b->p = NULL;
  b->n = b->cap = 0;
  return 0;
}

static int
number (const char *s, size_t *i, unsigned long long *out, int *overflow)
{
  size_t j = *i;
  unsigned long long v = 0;

  if (!isdigit ((unsigned char) s[j]))
    return 0;
  for (; isdigit ((unsigned char) s[j]); j++)
    {
      unsigned d = (unsigned) (s[j] - '0');

      if (v > (GLOB_MAX_NUMBER - d) / 10)
        *overflow = 1;
      else
        v = v * 10 + d;
    }
  *out = v;
  *i = j;
  return 1;
}

/* A set: {a,b,c}.  *I is at the brace.  */
static int
parse_set (struct twist_glob *g, const char *pattern, size_t *i, char *err,
           size_t cap)
{
  size_t j = *i + 1;
  struct part *p;
  struct buf b = { NULL, 0, 0 };
  int commas = 0;

  p = add_part (g, P_SET);
  if (p == NULL)
    return TWIST_ERR_NOMEM;
  for (;;)
    {
      char c = pattern[j];

      if (c == 0)
        {
          free (b.p);
          fail_at (pattern, *i + 1, _("unmatched brace"), err, cap);
          return TWIST_ERR_URL;
        }
      if (c == '{' || c == '[')
        {
          free (b.p);
          fail_at (pattern, j + 1, _("nested brace"), err, cap);
          return TWIST_ERR_URL;
        }
      if (c == ',' || c == '}')
        {
          char **grown = realloc (p->items, (p->nitems + 1) * sizeof *grown);

          /* An element with nothing in it is the empty string.  */
          if (grown != NULL && b.p == NULL)
            b.p = twist_strdup ("");
          if (grown == NULL || b.p == NULL)
            {
              free (b.p);
              return TWIST_ERR_NOMEM;
            }
          p->items = grown;
          p->items[p->nitems++] = b.p;
          b.p = NULL;
          b.n = b.cap = 0;
          if (c == '}')
            break;
          commas = 1;
          j++;
          continue;
        }
      if (c == '\\' && pattern[j + 1] != 0)
        {
          j++;
          c = pattern[j];
        }
      if (buf_add (&b, c) != 0)
        {
          free (b.p);
          return TWIST_ERR_NOMEM;
        }
      j++;
    }
  if (p->nitems == 1 && !commas && p->items[0][0] == 0)
    {
      fail_at (pattern, j + 1, _("empty string within braces"), err, cap);
      return TWIST_ERR_URL;
    }
  p->count = p->nitems;
  *i = j + 1;
  return TWIST_OK;
}

/* A range: [1-10], [01-10:2], [a-z], [a-z:2].  *I is at the bracket.  */
static int
parse_range (struct twist_glob *g, const char *pattern, size_t *i, char *err,
             size_t cap)
{
  size_t j = *i + 1, start_digits;
  size_t len = strlen (pattern);
  unsigned long long lo = 0, hi = 0, step = 1;
  int letters = 0, overflow = 0, clo = 0, chi = 0, width = 0;
  struct part *p;

  if (isdigit ((unsigned char) pattern[j]))
    {
      start_digits = j;
      number (pattern, &j, &lo, &overflow);
      if (pattern[start_digits] == '0' && j - start_digits > 1)
        width = (int) (j - start_digits);
    }
  else if (isalpha ((unsigned char) pattern[j]))
    {
      letters = 1;
      clo = (unsigned char) pattern[j++];
    }
  else
    {
      fail_at (pattern, j + 1, _("bad range specification"), err, cap);
      return TWIST_ERR_URL;
    }
  if (pattern[j] != '-')
    {
      fail_at (pattern, j + 1 < len ? j + 1 : len, _("bad range"), err, cap);
      return TWIST_ERR_URL;
    }
  j++;
  if (letters)
    {
      if (!isalpha ((unsigned char) pattern[j]))
        {
          fail_at (pattern, j + 1 < len ? j + 1 : len, _("bad range"), err, cap);
          return TWIST_ERR_URL;
        }
      chi = (unsigned char) pattern[j++];
    }
  else if (!number (pattern, &j, &hi, &overflow))
    {
      fail_at (pattern, j + 1 < len ? j + 1 : len, _("bad range"), err, cap);
      return TWIST_ERR_URL;
    }
  if (pattern[j] == ':')
    {
      j++;
      if (!number (pattern, &j, &step, &overflow))
        {
          fail_at (pattern, j + 1 < len ? j + 1 : len, _("bad range"), err, cap);
          return TWIST_ERR_URL;
        }
    }
  if (pattern[j] != ']')
    {
      fail_at (pattern, j + 1 < len ? j + 1 : len, _("bad range"), err, cap);
      return TWIST_ERR_URL;
    }
  /* The ordering and the step are judged once the range is whole, and the
     place is just past it.  */
  if (overflow || step == 0
      || (letters ? (chi < clo || (isupper (clo) != 0) != (isupper (chi) != 0))
                  : hi < lo))
    {
      fail_at (pattern, j + 2, _("bad range"), err, cap);
      return TWIST_ERR_URL;
    }
  p = add_part (g, letters ? P_CHAR : P_NUM);
  if (p == NULL)
    return TWIST_ERR_NOMEM;
  p->lo = letters ? (unsigned long long) clo : lo;
  p->step = step;
  p->width = width;
  p->count = (size_t) (((letters ? (unsigned long long) chi : hi) - p->lo)
                       / step + 1);
  *i = j + 1;
  return TWIST_OK;
}

int
twist_glob_parse (const char *pattern, struct twist_glob **out, char *err,
                  size_t cap)
{
  struct twist_glob *g;
  struct buf b = { NULL, 0, 0 };
  size_t i = 0;
  int rc = TWIST_OK;

  if (out != NULL)
    *out = NULL;
  if (pattern == NULL || out == NULL)
    return TWIST_ERR_INVAL;
  if (err != NULL && cap > 0)
    err[0] = 0;
  g = calloc (1, sizeof *g);
  if (g == NULL)
    return TWIST_ERR_NOMEM;
  while (pattern[i] != 0 && rc == TWIST_OK)
    {
      char c = pattern[i];

      if (c == '\\' && (pattern[i + 1] == '{' || pattern[i + 1] == '}'
                        || pattern[i + 1] == '[' || pattern[i + 1] == ']'))
        {
          if (buf_add (&b, pattern[i + 1]) != 0)
            rc = TWIST_ERR_NOMEM;
          i += 2;
        }
      else if (c == '{' || (c == '[' && ipv6_end (pattern + i) == 0))
        {
          if (flush_text (g, &b) != 0)
            rc = TWIST_ERR_NOMEM;
          else if (c == '{')
            rc = parse_set (g, pattern, &i, err, cap);
          else
            rc = parse_range (g, pattern, &i, err, cap);
        }
      else if (c == '[')
        {
          size_t n = ipv6_end (pattern + i) + 1, k;

          for (k = 0; k < n && rc == TWIST_OK; k++)
            if (buf_add (&b, pattern[i + k]) != 0)
              rc = TWIST_ERR_NOMEM;
          i += n;
        }
      else if (c == '}' || c == ']')
        {
          fail_at (pattern, i + 1, _("unmatched close brace/bracket"), err, cap);
          rc = TWIST_ERR_URL;
        }
      else
        {
          if (buf_add (&b, c) != 0)
            rc = TWIST_ERR_NOMEM;
          i++;
        }
    }
  if (rc == TWIST_OK && flush_text (g, &b) != 0)
    rc = TWIST_ERR_NOMEM;
  free (b.p);
  if (rc != TWIST_OK)
    {
      twist_glob_free (g);
      return rc;
    }
  *out = g;
  return TWIST_OK;
}

size_t
twist_glob_count (const struct twist_glob *g)
{
  return g->nglobs;
}

/* The value the glob P is at now, as text.  */
static const char *
part_value (struct part *p)
{
  switch (p->kind)
    {
    case P_SET:
      return p->items[p->pos];
    case P_NUM:
      snprintf (p->val, sizeof p->val, "%0*llu", p->width,
                p->lo + (unsigned long long) p->pos * p->step);
      return p->val;
    case P_CHAR:
      p->val[0] = (char) (p->lo + (unsigned long long) p->pos * p->step);
      p->val[1] = 0;
      return p->val;
    default:
      return p->text;
    }
}

const char *
twist_glob_value (const struct twist_glob *g, size_t n)
{
  size_t i, k = 0;

  if (n < 1 || n > g->nglobs)
    return NULL;
  for (i = 0; i < g->nparts; i++)
    if (g->parts[i].kind != P_TEXT && ++k == n)
      return part_value (&g->parts[i]);
  return NULL;
}

/* Move to the next combination: the last glob goes first, and a glob that
   runs out starts again and moves the one before it.  0 when all have.  */
static int
advance (struct twist_glob *g)
{
  size_t i;

  for (i = g->nparts; i > 0; i--)
    {
      struct part *p = &g->parts[i - 1];

      if (p->kind == P_TEXT)
        continue;
      if (++p->pos < p->count)
        return 1;
      p->pos = 0;
    }
  return 0;
}

int
twist_glob_next (struct twist_glob *g, char **url)
{
  struct buf b = { NULL, 0, 0 };
  size_t i;

  *url = NULL;
  if (g->done)
    return 0;
  if (!g->started)
    g->started = 1;
  else if (!advance (g))
    {
      g->done = 1;
      return 0;
    }
  for (i = 0; i < g->nparts; i++)
    {
      const char *v = part_value (&g->parts[i]);

      for (; *v != 0; v++)
        if (buf_add (&b, *v) != 0)
          {
            free (b.p);
            return -1;
          }
    }
  if (b.p == NULL)
    b.p = twist_strdup ("");
  if (b.p == NULL)
    return -1;
  /* A pattern with no glob is one URL, once.  */
  if (g->nglobs == 0)
    g->done = 1;
  *url = b.p;
  return 1;
}

/* The value of glob N, counted over A's and then B's.  */
static const char *
value2 (const struct twist_glob *a, const struct twist_glob *b, size_t n)
{
  size_t na = a != NULL ? twist_glob_count (a) : 0;

  if (n >= 1 && n <= na)
    return twist_glob_value (a, n);
  if (b != NULL && n > na)
    return twist_glob_value (b, n - na);
  return NULL;
}

char *
twist_glob_name2 (const struct twist_glob *a, const struct twist_glob *b,
                  const char *tmpl)
{
  struct buf bf = { NULL, 0, 0 };
  size_t i = 0;

  while (tmpl[i] != 0)
    {
      if (tmpl[i] == '#' && isdigit ((unsigned char) tmpl[i + 1]))
        {
          size_t j = i + 1, n = 0;
          const char *v;

          while (isdigit ((unsigned char) tmpl[j]))
            {
              if (n < 1000000)
                n = n * 10 + (size_t) (tmpl[j] - '0');
              j++;
            }
          v = value2 (a, b, n);
          if (v != NULL)
            {
              for (; *v != 0; v++)
                if (buf_add (&bf, *v) != 0)
                  {
                    free (bf.p);
                    return NULL;
                  }
              i = j;
              continue;
            }
        }
      if (buf_add (&bf, tmpl[i++]) != 0)
        {
          free (bf.p);
          return NULL;
        }
    }
  if (bf.p == NULL)
    return twist_strdup ("");
  return bf.p;
}

char *
twist_glob_name (const struct twist_glob *g, const char *tmpl)
{
  return twist_glob_name2 (g, NULL, tmpl);
}
