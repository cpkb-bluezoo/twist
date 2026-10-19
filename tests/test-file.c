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

static int file_body_calls;
static int file_hopped;

static size_t
file_body (char *ptr, size_t size, size_t nmemb, void *userdata)
{
  (void) ptr;
  (void) size;
  (void) nmemb;
  (void) userdata;
  file_body_calls++;
  return nmemb;
}

static void
file_hop_done (void *user)
{
  int *flag = user;

  *flag = 1;
}

static void
file_hop_work (void *arg)
{
  struct twist_loop *loop = arg;

  twist_loop_post (loop, file_hop_done, &file_hopped);
}

static void
test_file_pool (void)
{
  struct twist_easy *easy;
  struct twist_multi *multi;

  easy = twist_easy_init ();
  check (easy != NULL, "file easy");
  check (twist_easy_setopt (easy, TWISTOPT_URL, "file://example.com/a")
         == TWIST_OK, "file url");
  easy->write_cb = file_body;
  multi = twist_multi_init ();
  check (multi != NULL && multi->storage != NULL, "file pool");
  check (twist_multi_add_handle (multi, easy) == TWIST_ERR_URL, "file remote");
  check (easy->done && easy->result == TWIST_ERR_URL && file_body_calls == 0,
         "file remote done");
  twist_multi_cleanup (multi);
  twist_easy_cleanup (easy);

  file_hopped = 0;
  multi = twist_multi_init ();
  check (multi != NULL, "file hop multi");
  check (twist_storage_submit (multi->storage, file_hop_work, multi->loop,
                               NULL, NULL, NULL) == TWIST_OK, "file hop submit");
  check (twist_loop_run_once (multi->loop) == TWIST_OK && file_hopped == 1,
         "file hop");
  twist_multi_cleanup (multi);
}

static void
test_file_url (void)
{
  check (twist_file_check_url (NULL, "/etc/hostname", 1) == TWIST_OK, "file path");
  check (twist_file_check_url ("localhost", "/a", 1) == TWIST_OK, "localhost");
  check (twist_file_check_url ("127.0.0.1", "/a", 1) == TWIST_OK, "loopback");
  check (twist_file_check_url ("example.com", "/a", 1) == TWIST_ERR_URL,
         "remote file");
  check (twist_file_check_url ("localhost", "/", 0) == TWIST_ERR_URL,
         "no path");
  check (twist_file_check_url (NULL, NULL, 0) == TWIST_ERR_URL, "empty path");
  check (twist_file_check_url (NULL, "relative", 1) == TWIST_ERR_URL, "relative");
  {
    struct twist_url *url = NULL;

    check (twist_url_parse_int ("file://localhost", &url) == TWIST_OK,
           "parse host");
    check (url != NULL && !url->path_set, "host has no path");
    twist_url_free_int (url);
    url = NULL;
    check (twist_url_parse_int ("file:///etc/hostname", &url) == TWIST_OK,
           "parse path");
    check (url != NULL && url->path_set
           && strcmp (url->path, "/etc/hostname") == 0, "path set");
    twist_url_free_int (url);
  }
}

int
main (void)
{
  test_file_url ();
  test_file_pool ();
  return tests_finish ();
}
