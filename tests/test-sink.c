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

/* A write callback that says it is full: the bytes it was not given are held
   and given again, in order, when the transfer is resumed.  */

struct sink
{
  uint8_t got[16384];
  size_t n;
  int calls;
  int pause_on_call;		/* Return PAUSE on this call (0: never).  */
  int pause_again_on;		/* And on this one, after the first.  */
  int short_on_call;		/* Take only half on this call.  */
  int pauses, resumes;
};

static size_t
sink_write (char *ptr, size_t size, size_t nmemb, void *user)
{
  struct sink *s = user;
  size_t len = size * nmemb;

  s->calls++;
  if (s->calls == s->pause_on_call || s->calls == s->pause_again_on)
    return TWIST_WRITEFUNC_PAUSE;
  if (s->calls == s->short_on_call)
    len /= 2;
  if (s->n + len <= sizeof s->got)
    memcpy (s->got + s->n, ptr, len);
  s->n += len;
  return len;
}

static struct sink *the_sink;

static void
on_pause (struct twist_transfer *t)
{
  (void) t;
  the_sink->pauses++;
}

static void
on_resume (struct twist_transfer *t)
{
  (void) t;
  the_sink->resumes++;
}

static uint8_t *
pattern (size_t n)
{
  uint8_t *b = malloc (n);
  size_t i;

  for (i = 0; i < n; i++)
    b[i] = (uint8_t) (i * 13 + i / 7);
  return b;
}

static struct twist_transfer *
make (struct sink *s)
{
  struct twist_transfer *t = twist_transfer_new ();

  the_sink = s;
  t->write_cb = sink_write;
  t->write_data = s;
  t->pause_fn = on_pause;
  t->resume_fn = on_resume;
  return t;
}

static void
test_pause_resume (void)
{
  struct sink s;
  struct twist_transfer *t;
  uint8_t *data = pattern (3000);
  size_t first;

  memset (&s, 0, sizeof s);
  s.pause_on_call = 2;
  t = make (&s);
  check (twist_deliver (t, data, 3000) == 3000,
         "all of it is accepted, taken or held");
  first = s.n;
  check (first == 512 && s.pauses == 1 && t->sink_paused,
         "the callback that is full is paused once, after what it took");
  check (twist_deliver (t, data, 100) == 100 && s.n == first && s.calls == 2,
         "more that comes meanwhile is held, not given");
  check (twist_transfer_resume (t) == TWIST_OK, "resumed");
  check (s.resumes == 1 && !t->sink_paused, "the handler is told");
  check (s.n == 3100 && memcmp (s.got, data, 3000) == 0
         && memcmp (s.got + 3000, data, 100) == 0,
         "and the held bytes are given in order, the one it refused again");
  twist_transfer_free (t);

  /* Full again while it is being given back.  */
  memset (&s, 0, sizeof s);
  s.pause_on_call = 2;
  s.pause_again_on = 4;
  t = make (&s);
  twist_deliver (t, data, 3000);
  twist_transfer_resume (t);
  check (t->sink_paused && s.n < 3000 && s.n > 512,
         "paused again part way through what was held");
  twist_transfer_resume (t);
  check (!t->sink_paused && s.n == 3000 && memcmp (s.got, data, 3000) == 0,
         "and the rest comes on the next resume");
  twist_transfer_free (t);
  free (data);
}

/* The end of a transfer that succeeded waits for the body that was held: the
   program must not hear that it is done before it has the body.  */
static void
test_end_waits (void)
{
  struct sink s;
  struct twist_transfer *t;
  uint8_t *data = pattern (1500);

  memset (&s, 0, sizeof s);
  s.pause_on_call = 2;
  t = make (&s);
  twist_deliver (t, data, 1500);
  twist_transfer_finish (t, TWIST_OK);
  check (!t->done, "a transfer with body held is not over");
  twist_transfer_finish (t, TWIST_ERR_ABORTED);
  check (t->done && t->result == TWIST_ERR_ABORTED,
         "unless it failed, which does not wait");
  twist_transfer_free (t);

  memset (&s, 0, sizeof s);
  s.pause_on_call = 2;
  t = make (&s);
  twist_deliver (t, data, 1500);
  twist_transfer_finish (t, TWIST_OK);
  twist_transfer_resume (t);
  check (t->done && t->result == TWIST_OK && s.n == 1500,
         "it is over once the held body has been given");
  twist_transfer_free (t);
  free (data);
}

static void
test_short_and_bound (void)
{
  struct sink s;
  struct twist_transfer *t;
  uint8_t *data = pattern (3000);
  uint8_t *big = calloc (1, 5u * 1024u * 1024u);

  memset (&s, 0, sizeof s);
  s.short_on_call = 2;
  t = make (&s);
  check (twist_deliver (t, data, 3000) < 3000,
         "a callback that takes less than it was given stops the transfer");
  twist_transfer_free (t);

  memset (&s, 0, sizeof s);
  s.pause_on_call = 1;
  t = make (&s);
  check (twist_deliver (t, data, 100) == 100, "paused at once");
  check (twist_deliver (t, big, 5u * 1024u * 1024u) < 5u * 1024u * 1024u,
         "what is held is bounded");
  twist_transfer_free (t);
  free (data);
  free (big);
}

int
main (void)
{
  test_pause_resume ();
  test_end_waits ();
  test_short_and_bound ();
  return tests_finish ();
}
