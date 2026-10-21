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
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Variables.  --variable name=text, name@file, %name and %name=default give a
   name a content, which may be any bytes.  In the parameter of an option with
   --expand- before its name, {{name}} is the content, and {{name:fn:fn}} the
   content after the functions, left to right:

     trim    no white space at either end
     json    as the inside of a JSON string
     url     percent-encoded
     b64     base64
     64dec   from base64; "[64dec-fail]" if it is not

   A name that is not defined is empty.  The content is not expanded again.
   The result is a string, so content with a NUL in it must be encoded by
   a function (b64, json or url) before it is used, or it is an error.
   Nothing, content or result, is over ten megabytes.  */

#define VARS_MAX 10000000u

struct var
{
  char *name;
  uint8_t *data;
  size_t len;
};

struct twist_vars
{
  struct var *v;
  size_t n, cap;
};

/* Bytes, with a length.  */
struct bytes
{
  uint8_t *p;
  size_t n, cap;
};

static void say (char *err, size_t cap, const char *fmt, ...)
  __attribute__ ((format (printf, 3, 4)));

static void
say (char *err, size_t cap, const char *fmt, ...)
{
  va_list ap;

  if (err == NULL || cap == 0)
    return;
  va_start (ap, fmt);
  vsnprintf (err, cap, fmt, ap);
  va_end (ap);
}

struct twist_vars *
twist_vars_new (void)
{
  return calloc (1, sizeof (struct twist_vars));
}

void
twist_vars_free (struct twist_vars *vars)
{
  size_t i;

  if (vars == NULL)
    return;
  for (i = 0; i < vars->n; i++)
    {
      free (vars->v[i].name);
      if (vars->v[i].data != NULL)
        {
          memset (vars->v[i].data, 0, vars->v[i].len);
          free (vars->v[i].data);
        }
    }
  free (vars->v);
  free (vars);
}

/* Where NAME (N bytes) is in the set, or the size of the set.  */
static size_t
index_of (const struct twist_vars *vars, const char *name, size_t n)
{
  size_t i;

  for (i = 0; i < vars->n; i++)
    if (strlen (vars->v[i].name) == n && memcmp (vars->v[i].name, name, n) == 0)
      break;
  return i;
}

static const struct var *
find (const struct twist_vars *vars, const char *name, size_t n)
{
  size_t i = index_of (vars, name, n);

  return i < vars->n ? &vars->v[i] : NULL;
}

/* Give NAME (N bytes) the content, which becomes the set's.  */
static int
store (struct twist_vars *vars, const char *name, size_t n, uint8_t *data,
       size_t len)
{
  size_t at = index_of (vars, name, n);
  struct var *v;

  if (at == vars->n)
    {
      if (vars->n == vars->cap)
        {
          size_t cap = vars->cap == 0 ? 8 : vars->cap * 2;
          struct var *grown = realloc (vars->v, cap * sizeof *grown);

          if (grown == NULL)
            {
              free (data);
              return TWIST_ERR_NOMEM;
            }
          vars->v = grown;
          vars->cap = cap;
        }
      v = &vars->v[vars->n];
      v->name = malloc (n + 1);
      if (v->name == NULL)
        {
          free (data);
          return TWIST_ERR_NOMEM;
        }
      memcpy (v->name, name, n);
      v->name[n] = 0;
      v->data = NULL;
      vars->n++;
    }
  else
    v = &vars->v[at];
  free (v->data);
  v->data = data;
  v->len = len;
  return TWIST_OK;
}

static int
name_char (int c)
{
  return isalnum ((unsigned char) c) || c == '_';
}

/* All of PATH, or of standard input for "-", up to the limit.  A second read
   of standard input finds the end of it at once.  */
static int
read_all (const char *path, uint8_t **out, size_t *len, char *err, size_t cap)
{
  FILE *fp = strcmp (path, "-") == 0 ? stdin : fopen (path, "rb");
  uint8_t *buf = NULL;
  size_t n = 0, room = 0;

  if (fp == NULL)
    {
      say (err, cap, _("cannot read %s"), path);
      return TWIST_ERR_FILE;
    }
  for (;;)
    {
      size_t got;

      if (n + 4096 > room)
        {
          size_t want = room == 0 ? 4096 : room * 2;
          uint8_t *grown;

          if (want > VARS_MAX + 4096)
            want = VARS_MAX + 4096;
          grown = realloc (buf, want);
          if (grown == NULL)
            {
              free (buf);
              if (fp != stdin)
                fclose (fp);
              return TWIST_ERR_NOMEM;
            }
          buf = grown;
          room = want;
        }
      got = fread (buf + n, 1, room - n, fp);
      n += got;
      if (n > VARS_MAX)
        {
          free (buf);
          if (fp != stdin)
            fclose (fp);
          say (err, cap, _("%s is too large for a variable"), path);
          return TWIST_ERR_FILE;
        }
      if (got == 0)
        break;
    }
  if (ferror (fp))
    {
      free (buf);
      if (fp != stdin)
        fclose (fp);
      say (err, cap, _("cannot read %s"), path);
      return TWIST_ERR_FILE;
    }
  if (fp != stdin)
    fclose (fp);
  if (buf == NULL)
    buf = malloc (1);
  if (buf == NULL)
    return TWIST_ERR_NOMEM;
  *out = buf;
  *len = n;
  return TWIST_OK;
}

int
twist_vars_define (struct twist_vars *vars, const char *spec, char *err,
                   size_t cap)
{
  const char *p = spec, *name, *rest;
  size_t n;
  int env = 0, rc;
  uint8_t *data = NULL;
  size_t len = 0;
  char shown[96];

  if (*p == '%')
    {
      env = 1;
      p++;
    }
  name = p;
  while (name_char (*p))
    p++;
  n = (size_t) (p - name);
  rest = p;
  if (n == 0)
    {
      say (err, cap, _("no variable name"));
      return TWIST_ERR_INVAL;
    }
  if (*rest != 0 && *rest != '=' && *rest != '@')
    {
      /* Show the name as it was written, up to the = or @.  */
      size_t w = strcspn (name, "=@");

      if (w >= sizeof shown)
        w = sizeof shown - 1;
      memcpy (shown, name, w);
      shown[w] = 0;
      say (err, cap, _("bad variable name '%s': use letters, digits and "
                       "underscores"), shown);
      return TWIST_ERR_INVAL;
    }
  if (*rest == 0 && !env)
    {
      memcpy (shown, name, n < sizeof shown ? n : sizeof shown - 1);
      shown[n < sizeof shown ? n : sizeof shown - 1] = 0;
      say (err, cap, _("'%s' needs a value: name=text, name@file, or %%name "
                       "for the environment"), shown);
      return TWIST_ERR_INVAL;
    }
  if (env)
    {
      char key[96];
      const char *value;

      if (n >= sizeof key)
        {
          say (err, cap, _("the variable name is too long"));
          return TWIST_ERR_INVAL;
        }
      memcpy (key, name, n);
      key[n] = 0;
      value = getenv (key);
      if (value != NULL)
        {
          /* Set, even if empty: it is the environment's, and the default is
             for when it is not.  */
          len = strlen (value);
          if (len > VARS_MAX)
            {
              say (err, cap, _("the environment variable '%s' is too large"),
                   key);
              return TWIST_ERR_INVAL;
            }
          data = malloc (len + 1);
          if (data == NULL)
            return TWIST_ERR_NOMEM;
          memcpy (data, value, len);
          return store (vars, name, n, data, len);
        }
      if (*rest == 0)
        {
          say (err, cap, _("the environment variable '%s' is not set"), key);
          return TWIST_ERR_INVAL;
        }
    }
  if (*rest == '=')
    {
      len = strlen (rest + 1);
      if (len > VARS_MAX)
        {
          say (err, cap, _("the variable is too large"));
          return TWIST_ERR_INVAL;
        }
      data = malloc (len + 1);
      if (data == NULL)
        return TWIST_ERR_NOMEM;
      memcpy (data, rest + 1, len);
    }
  else
    {
      rc = read_all (rest + 1, &data, &len, err, cap);
      if (rc != TWIST_OK)
        return rc;
    }
  return store (vars, name, n, data, len);
}

/* ---- the functions ---- */

static int
grow (struct bytes *b, size_t more)
{
  if (more > VARS_MAX || b->n > VARS_MAX - more)
    return -2;
  if (b->n + more + 1 > b->cap)
    {
      size_t cap = b->cap == 0 ? 64 : b->cap;
      uint8_t *p;

      while (cap < b->n + more + 1)
        cap *= 2;
      p = realloc (b->p, cap);
      if (p == NULL)
        return -1;
      b->p = p;
      b->cap = cap;
    }
  return 0;
}

static int
add (struct bytes *b, const void *data, size_t n)
{
  int rc = grow (b, n);

  if (rc != 0)
    return rc;
  if (n > 0)
    memcpy (b->p + b->n, data, n);
  b->n += n;
  return 0;
}

static int
fn_trim (struct bytes *in, struct bytes *out)
{
  size_t a = 0, z = in->n;

  while (a < z && isspace (in->p[a]))
    a++;
  while (z > a && isspace (in->p[z - 1]))
    z--;
  return add (out, in->p + a, z - a);
}

static int
fn_json (struct bytes *in, struct bytes *out)
{
  size_t i;

  for (i = 0; i < in->n; i++)
    {
      uint8_t c = in->p[i];
      char esc[8];
      int rc;

      switch (c)
        {
        case '"':
          rc = add (out, "\\\"", 2);
          break;
        case '\\':
          rc = add (out, "\\\\", 2);
          break;
        case '\b':
          rc = add (out, "\\b", 2);
          break;
        case '\f':
          rc = add (out, "\\f", 2);
          break;
        case '\n':
          rc = add (out, "\\n", 2);
          break;
        case '\r':
          rc = add (out, "\\r", 2);
          break;
        case '\t':
          rc = add (out, "\\t", 2);
          break;
        default:
          if (c < 0x20)
            {
              snprintf (esc, sizeof esc, "\\u%04x", c);
              rc = add (out, esc, 6);
            }
          else
            rc = add (out, &c, 1);
        }
      if (rc != 0)
        return rc;
    }
  return 0;
}

static int
fn_url (struct bytes *in, struct bytes *out)
{
  size_t i;

  for (i = 0; i < in->n; i++)
    {
      uint8_t c = in->p[i];
      int rc;

      if (isalnum (c) || c == '-' || c == '.' || c == '_' || c == '~')
        rc = add (out, &c, 1);
      else
        {
          char esc[4];

          snprintf (esc, sizeof esc, "%%%02X", c);
          rc = add (out, esc, 3);
        }
      if (rc != 0)
        return rc;
    }
  return 0;
}

static const char b64tab[] =
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static int
fn_b64 (struct bytes *in, struct bytes *out)
{
  size_t i;

  /* Counted first, so that a large input is refused before it is made.  */
  if (in->n / 3 > VARS_MAX / 4)
    return -2;
  for (i = 0; i < in->n; i += 3)
    {
      unsigned v = (unsigned) in->p[i] << 16;
      char q[4];
      int rc;

      if (i + 1 < in->n)
        v |= (unsigned) in->p[i + 1] << 8;
      if (i + 2 < in->n)
        v |= in->p[i + 2];
      q[0] = b64tab[(v >> 18) & 63];
      q[1] = b64tab[(v >> 12) & 63];
      q[2] = i + 1 < in->n ? b64tab[(v >> 6) & 63] : '=';
      q[3] = i + 2 < in->n ? b64tab[v & 63] : '=';
      rc = add (out, q, 4);
      if (rc != 0)
        return rc;
    }
  return 0;
}

/* From base64, padding or not.  What is not base64 gives a marker and not an
   error, so that a pipeline of options does not stop for it.  */
static int
fn_64dec (struct bytes *in, struct bytes *out)
{
  unsigned acc = 0;
  int bits = 0, bad = 0;
  size_t i, end = in->n;
  struct bytes tmp = { NULL, 0, 0 };
  int rc = 0;

  while (end > 0 && in->p[end - 1] == '=')
    end--;
  if (in->n - end > 2 || end % 4 == 1)
    bad = 1;
  for (i = 0; i < end && !bad; i++)
    {
      const char *at = memchr (b64tab, in->p[i], 64);
      uint8_t byte;

      if (at == NULL || in->p[i] == 0)
        {
          bad = 1;
          break;
        }
      acc = (acc << 6) | (unsigned) (at - b64tab);
      bits += 6;
      if (bits >= 8)
        {
          bits -= 8;
          byte = (uint8_t) (acc >> bits);
          acc &= (1u << bits) - 1;
          rc = add (&tmp, &byte, 1);
          if (rc != 0)
            {
              free (tmp.p);
              return rc;
            }
        }
    }
  if (bad)
    rc = add (out, "[64dec-fail]", 12);
  else
    rc = add (out, tmp.p, tmp.n);
  free (tmp.p);
  return rc;
}

static const struct
{
  const char *name;
  int (*fn) (struct bytes *, struct bytes *);
} functions[] = {
  { "trim", fn_trim },
  { "json", fn_json },
  { "url", fn_url },
  { "b64", fn_b64 },
  { "64dec", fn_64dec }
};

/* Run the functions named in LIST (N bytes, separated by : or ,) over BUF,
   which is replaced.  0, -1 out of memory, -2 too large, -3 a function that
   is none, -4 an empty name.  */
static int
apply (struct bytes *buf, const char *list, size_t n, char *err, size_t cap)
{
  size_t i = 0;

  while (i <= n)
    {
      size_t j = i, k;
      struct bytes out = { NULL, 0, 0 };
      int rc = -3;

      while (j < n && list[j] != ':' && list[j] != ',')
        j++;
      if (j == i)
        {
          say (err, cap, _("a function name is missing"));
          return -4;
        }
      for (k = 0; k < sizeof functions / sizeof functions[0]; k++)
        if (strlen (functions[k].name) == j - i
            && memcmp (functions[k].name, list + i, j - i) == 0)
          {
            rc = functions[k].fn (buf, &out);
            break;
          }
      if (rc == -3)
        {
          char shown[48];
          size_t w = j - i < sizeof shown - 1 ? j - i : sizeof shown - 1;

          memcpy (shown, list + i, w);
          shown[w] = 0;
          say (err, cap, _("unknown function '%s'"), shown);
          return -3;
        }
      if (rc != 0)
        {
          free (out.p);
          return rc;
        }
      free (buf->p);
      *buf = out;
      if (buf->p == NULL)
        {
          buf->p = malloc (1);
          if (buf->p == NULL)
            return -1;
        }
      i = j + 1;
      if (j == n)
        break;
    }
  return 0;
}

char *
twist_vars_expand (const struct twist_vars *vars, const char *text, char *err,
                   size_t cap)
{
  struct bytes out = { NULL, 0, 0 };
  size_t i = 0, tl = strlen (text);
  int rc;

  if (err != NULL && cap > 0)
    err[0] = 0;
  while (i < tl)
    {
      if (text[i] == '\\' && text[i + 1] == '{' && text[i + 2] == '{')
        {
          rc = add (&out, "{{", 2);
          i += 3;
        }
      else if (text[i] == '{' && text[i + 1] == '{')
        {
          size_t j = i + 2, k = j;
          const char *end;
          const struct var *v;
          struct bytes cur;

          while (name_char (text[k]))
            k++;
          if (k == j || (text[k] != '}' && text[k] != ':')
              || (text[k] == '}' && text[k + 1] != '}')
              || (text[k] == ':' && strstr (text + k, "}}") == NULL))
            {
              /* Not a reference: the brace is text.  */
              rc = add (&out, "{", 1);
              i++;
              if (rc != 0)
                goto failed;
              continue;
            }
          end = text[k] == '}' ? text + k : strstr (text + k, "}}");
          v = find (vars, text + j, k - j);
          cur.n = v != NULL ? v->len : 0;
          cur.cap = cur.n + 1;
          cur.p = malloc (cur.cap);
          if (cur.p == NULL)
            {
              rc = -1;
              goto failed;
            }
          if (v != NULL && v->len > 0)
            memcpy (cur.p, v->data, v->len);
          if (text[k] == ':')
            {
              rc = apply (&cur, text + k + 1, (size_t) (end - (text + k + 1)),
                          err, cap);
              if (rc != 0)
                {
                  free (cur.p);
                  goto failed;
                }
            }
          if (cur.n > 0 && memchr (cur.p, 0, cur.n) != NULL)
            {
              char name[64];
              size_t w = k - j < sizeof name - 1 ? k - j : sizeof name - 1;

              memcpy (name, text + j, w);
              name[w] = 0;
              say (err, cap, _("the variable '%s' holds a NUL; use b64, json "
                               "or url on it"), name);
              free (cur.p);
              free (out.p);
              return NULL;
            }
          rc = add (&out, cur.p, cur.n);
          free (cur.p);
          i = (size_t) (end - text) + 2;
        }
      else
        {
          rc = add (&out, text + i, 1);
          i++;
        }
      if (rc != 0)
        goto failed;
    }
  rc = add (&out, "", 1);
  if (rc != 0)
    goto failed;
  return (char *) out.p;
failed:
  if (rc == -2)
    say (err, cap, _("the result is too large for a variable"));
  else if (rc == -1)
    say (err, cap, _("out of memory"));
  free (out.p);
  return NULL;
}
