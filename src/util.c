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

#include "twist-int.h"

#include <pwd.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#ifdef __linux__
# include <sys/auxv.h>
#endif

void *
twist_xmalloc (size_t n)
{
  void *p;

  if (n == 0)
    n = 1;
  p = malloc (n);
  return p;
}

int
twist_home_dir (char *out, size_t cap)
{
  const char *home = twist_getenv_secure ("HOME");
  struct passwd pw, *res = NULL;
  char buf[4096];

  if (home == NULL || home[0] == 0)
    {
      /* Several loops can ask at once, so the reentrant form.  */
      if (getpwuid_r (getuid (), &pw, buf, sizeof buf, &res) != 0
          || res == NULL || res->pw_dir == NULL || res->pw_dir[0] == 0)
        return 0;
      home = res->pw_dir;
    }
  if (strlen (home) >= cap)
    return 0;
  memcpy (out, home, strlen (home) + 1);
  return 1;
}

char *
twist_strdup (const char *s)
{
  size_t n;
  char *p;

  if (s == NULL)
    return NULL;
  n = strlen (s) + 1;
  p = twist_xmalloc (n);
  if (p == NULL)
    return NULL;
  memcpy (p, s, n);
  return p;
}

int
twist_has_ctl (const char *s)
{
  const unsigned char *p;

  if (s == NULL)
    return 0;
  for (p = (const unsigned char *) s; *p != 0; p++)
    if (*p == '\r' || *p == '\n')
      return 1;
  return 0;
}

int
twist_status_code (const char *s)
{
  if (s == NULL || s[0] < '1' || s[0] > '5' || s[1] < '0' || s[1] > '9'
      || s[2] < '0' || s[2] > '9')
    return -1;
  return (s[0] - '0') * 100 + (s[1] - '0') * 10 + (s[2] - '0');
}

static int privileged_override = -1;

void
twist_set_privileged (int how)
{
  privileged_override = how;
}

/* Whether the environment is not the process's own: it was started set-user-ID
   or set-group-ID (the real and effective IDs differ), or by the kernel with
   more rights than its user's (AT_SECURE, which covers file capabilities).  */
static int
privileged (void)
{
  if (privileged_override >= 0)
    return privileged_override;
  if (getuid () != geteuid () || getgid () != getegid ())
    return 1;
#ifdef __linux__
  return getauxval (AT_SECURE) != 0;
#else
  return 0;
#endif
}

const char *
twist_getenv_secure (const char *name)
{
  return privileged () ? NULL : getenv (name);
}

static int
name_is (const char *name, size_t n, const char *lit)
{
  return strlen (lit) == n && strncasecmp (name, lit, n) == 0;
}

int
twist_header_connection_specific (const char *name, size_t n, const char *value)
{
  size_t len;

  if (name_is (name, n, "connection") || name_is (name, n, "keep-alive")
      || name_is (name, n, "proxy-connection")
      || name_is (name, n, "transfer-encoding") || name_is (name, n, "upgrade"))
    return 1;
  if (name_is (name, n, "te"))
    {
      if (value == NULL)
        return 1;
      while (*value == ' ' || *value == '\t')
        value++;
      len = strlen (value);
      while (len > 0 && (value[len - 1] == ' ' || value[len - 1] == '\t'))
        len--;
      return !(len == 8 && strncasecmp (value, "trailers", 8) == 0);
    }
  return 0;
}

struct twist_slist *
twist_slist_append (struct twist_slist *list, const char *data)
{
  struct twist_slist *node;
  struct twist_slist *tail;

  node = twist_xmalloc (sizeof *node);
  if (node == NULL)
    return list;
  node->data = twist_strdup (data);
  node->next = NULL;
  if (node->data == NULL)
    {
      free (node);
      return list;
    }
  if (list == NULL)
    return node;
  tail = list;
  while (tail->next != NULL)
    tail = tail->next;
  tail->next = node;
  return list;
}

size_t
twist_write_bytes (twist_write_callback cb, void *user,
                   const void *data, size_t len)
{
  const uint8_t *p = data;
  size_t off = 0;

  if (cb == NULL || data == NULL || len == 0)
    return 0;
  while (off < len)
    {
      char buf[512];
      size_t n = len - off;
      size_t got;

      if (n > sizeof buf)
        n = sizeof buf;
      memcpy (buf, p + off, n);
      got = cb (buf, 1, n, user);
      off += got;
      if (got < n)
        break;
    }
  return off;
}

void
twist_slist_free_all (struct twist_slist *list)
{
  while (list != NULL)
    {
      struct twist_slist *next = list->next;
      free (list->data);
      free (list);
      list = next;
    }
}
