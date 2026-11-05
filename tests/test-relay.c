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

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

/* An upload relayed to a connection: a source of one byte at a time, a peer
   that stalls, a clean end, a source that fails; the memory source; resuming
   at an offset; and the meter following what the connection has written.  */

static double
now_ms (void)
{
  struct timespec t;

  clock_gettime (CLOCK_MONOTONIC, &t);
  return (double) t.tv_sec * 1000.0 + (double) t.tv_nsec / 1e6;
}

static size_t
drain (struct twist_loop *loop, int fd, double ms)
{
  size_t seen = 0;
  double end = now_ms () + ms;

  while (now_ms () < end)
    {
      uint8_t in[65536];
      ssize_t n = read (fd, in, sizeof in);

      if (n > 0)
        seen += (size_t) n;
      twist_loop_run_once_ms (loop, 1);
    }
  return seen;
}

static int
pair (int sv[2])
{
  if (socketpair (AF_UNIX, SOCK_STREAM, 0, sv) != 0)
    return -1;
  fcntl (sv[0], F_SETFL, O_NONBLOCK);
  fcntl (sv[1], F_SETFL, O_NONBLOCK);
  return 0;
}

struct cb
{
  const uint8_t *data;
  size_t total, off, step, fail_at;
  int calls;
};

static size_t
cb_read (char *ptr, size_t size, size_t nmemb, void *user)
{
  struct cb *c = user;
  size_t n = size * nmemb;

  c->calls++;
  if (c->fail_at != 0 && c->off >= c->fail_at)
    return TWIST_READFUNC_ABORT;
  if (c->step != 0 && n > c->step)
    n = c->step;
  if (n > c->total - c->off)
    n = c->total - c->off;
  memcpy (ptr, c->data + c->off, n);
  c->off += n;
  return n;
}

struct end
{
  int ends;
  int err;
};

static void
on_end (void *user, int err)
{
  struct end *e = user;

  e->ends++;
  e->err = err;
}

static const struct twist_relay_ops plain = { NULL, NULL, on_end };

static uint8_t *
pattern (size_t n)
{
  uint8_t *b = malloc (n);
  size_t i;

  for (i = 0; i < n; i++)
    b[i] = (uint8_t) (i * 13 + i / 7);
  return b;
}

static void
test_clean (struct twist_loop *loop)
{
  int sv[2];
  struct twist_connection *c;
  struct twist_transfer *t = twist_transfer_new ();
  struct cb cb;
  struct end e;
  struct twist_upmeter m;
  uint8_t *data = pattern (5000);
  size_t seen;

  if (pair (sv) != 0)
    return;
  memset (&cb, 0, sizeof cb);
  memset (&e, 0, sizeof e);
  cb.data = data;
  cb.total = 5000;
  cb.step = 1;
  t->read_cb = cb_read;
  t->read_data = &cb;
  c = twist_connection_new (loop);
  twist_connection_set_fd (c, sv[0]);
  twist_upmeter_start (&m, t, c);
  check (twist_relay_start (c, NULL, twist_transfer_upload (t), 0, 1024,
                            &plain, &e, &m) == TWIST_OK, "a relay is started");
  seen = drain (loop, sv[1], 200);
  check (seen == 5000, "a source of one byte at a time arrives whole");
  check (e.ends == 1 && e.err == TWIST_OK, "and the end is called once");
  twist_upmeter_sync (&m);
  check (t->progress.uploaded == 5000LL, "the meter shows what was written");
  twist_connection_free (c);
  twist_transfer_free (t);
  free (data);
  close (sv[1]);
}

static void
test_stall (struct twist_loop *loop)
{
  int sv[2];
  struct twist_connection *c;
  struct twist_transfer *t = twist_transfer_new ();
  struct cb cb;
  struct end e;
  struct twist_upmeter m;
  uint8_t *data = pattern (8u * 1024u * 1024u);
  size_t seen, ahead;

  if (pair (sv) != 0)
    return;
  memset (&cb, 0, sizeof cb);
  memset (&e, 0, sizeof e);
  cb.data = data;
  cb.total = 8u * 1024u * 1024u;
  t->read_cb = cb_read;
  t->read_data = &cb;
  c = twist_connection_new (loop);
  twist_connection_set_fd (c, sv[0]);
  twist_upmeter_start (&m, t, c);
  twist_relay_start (c, NULL, twist_transfer_upload (t), 0, 16384, &plain, &e,
                     &m);
  drain (loop, -1, 150);
  ahead = cb.off;
  check (ahead < cb.total / 2 && e.ends == 0,
         "a peer that does not read does not make the source read ahead");
  check ((size_t) t->progress.uploaded < ahead,
         "and the meter shows less than was taken from the source");
  drain (loop, -1, 100);
  check (cb.off == ahead, "no further chunk is taken while it stalls");
  seen = drain (loop, sv[1], 6000);
  check (seen == cb.total && e.ends == 1 && e.err == TWIST_OK,
         "drained, all of it arrives and it ends");
  twist_connection_free (c);
  twist_transfer_free (t);
  free (data);
  close (sv[1]);
}

static void
test_fail (struct twist_loop *loop)
{
  int sv[2];
  struct twist_connection *c;
  struct twist_transfer *t = twist_transfer_new ();
  struct cb cb;
  struct end e;
  uint8_t *data = pattern (4000);

  if (pair (sv) != 0)
    return;
  memset (&cb, 0, sizeof cb);
  memset (&e, 0, sizeof e);
  cb.data = data;
  cb.total = 4000;
  cb.step = 100;
  cb.fail_at = 1000;
  t->read_cb = cb_read;
  t->read_data = &cb;
  c = twist_connection_new (loop);
  twist_connection_set_fd (c, sv[0]);
  twist_relay_start (c, NULL, twist_transfer_upload (t), 0, 1024, &plain, &e,
                     NULL);
  drain (loop, sv[1], 100);
  check (e.ends == 1 && e.err == TWIST_ERR_ABORTED,
         "a source that fails ends the relay with the error, once");
  twist_connection_free (c);
  twist_transfer_free (t);
  free (data);
  close (sv[1]);
}

static void
test_memory_skip (struct twist_loop *loop)
{
  int sv[2];
  struct twist_connection *c;
  struct end e;
  uint8_t *data = pattern (3000);
  uint8_t got[3000];
  struct twist_upload *up = twist_upload_from_memory (data, 3000);
  ssize_t n;
  size_t have = 0;
  double end;

  if (pair (sv) != 0)
    return;
  memset (&e, 0, sizeof e);
  check (twist_upload_skip (up, 1000) == TWIST_OK, "a memory source skips");
  c = twist_connection_new (loop);
  twist_connection_set_fd (c, sv[0]);
  twist_relay_start (c, NULL, up, 1, 512, &plain, &e, NULL);
  end = now_ms () + 200;
  while (now_ms () < end && have < sizeof got)
    {
      n = read (sv[1], got + have, sizeof got - have);
      if (n > 0)
        have += (size_t) n;
      twist_loop_run_once_ms (loop, 1);
    }
  check (have == 2000 && memcmp (got, data + 1000, 2000) == 0,
         "what follows the offset is sent");
  check (e.ends == 1 && e.err == TWIST_OK, "and ends");
  twist_connection_free (c);
  up = twist_upload_from_memory (data, 100);
  check (twist_upload_skip (up, 101) == TWIST_ERR_RESUME,
         "an offset past the end is a resume error");
  twist_upload_free (up);
  free (data);
  close (sv[1]);
}

int
main (void)
{
  struct twist_loop *loop = twist_loop_new (0);

  if (loop == NULL)
    return 77;
  test_clean (loop);
  test_stall (loop);
  test_fail (loop);
  test_memory_skip (loop);
  twist_loop_free (loop);
  return tests_finish ();
}
