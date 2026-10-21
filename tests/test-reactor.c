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
#include "reactor/atomic.h"
#include "reactor/cmdq.h"
#include <pthread.h>
#include <unistd.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static uint64_t clock_ms;

static uint64_t
fake_now (void *user)
{
  (void) user;
  return clock_ms;
}

static int timer_hits;

static void
timer_cb (void *user)
{
  int *flag = user;
  (*flag)++;
  timer_hits++;
}

static uint64_t
aux_deadline (void *user, uint64_t now_us)
{
  (void) user;
  (void) now_us;
  return 2500ull * 1000ull;
}

static int aux_fired;

static void
aux_fire (void *user, uint64_t now_us)
{
  (void) user;
  (void) now_us;
  aux_fired++;
}

static void
test_timer (void)
{
  struct twist_loop *loop = twist_loop_new (1);
  struct twist_timer *timer = NULL;
  int hits = 0;

  check (loop != NULL, "loop");
  twist_loop_set_now (loop, fake_now, NULL);
  clock_ms = 1000;
  check (twist_loop_schedule (loop, 5000, timer_cb, &hits, &timer) == TWIST_OK,
         "schedule");
  check (twist_loop_next_timeout (loop, clock_ms) == 4000, "heap timeout");
  twist_loop_set_aux_timeout (loop, aux_deadline, NULL);
  check (twist_loop_next_timeout (loop, clock_ms) == 1500, "aux earlier");
  clock_ms = 2500;
  twist_loop_set_aux_fire (loop, aux_fire);
  twist_loop_on_timer (loop, clock_ms);
  check (aux_fired == 1, "aux fire");
  check (hits == 0, "timer not yet");
  clock_ms = 5000;
  twist_loop_on_timer (loop, clock_ms);
  check (hits == 1, "timer fired");
  hits = 0;
  check (twist_loop_schedule (loop, 9000, timer_cb, &hits, &timer) == TWIST_OK,
         "schedule 2");
  twist_timer_cancel (timer);
  clock_ms = 9000;
  twist_loop_on_timer (loop, clock_ms);
  check (hits == 0, "cancelled");
  clock_ms = 1000;
  twist_loop_set_aux_timeout (loop, NULL, NULL);
  check (twist_loop_schedule (loop, 4000, timer_cb, &hits, &timer) == TWIST_OK,
         "schedule early");
  check (twist_loop_schedule (loop, 7000, timer_cb, &hits, NULL) == TWIST_OK,
         "schedule late");
  twist_timer_cancel (timer);
  check (twist_loop_next_timeout (loop, clock_ms) == 6000, "skip cancelled");
  twist_loop_free (loop);
}

static int cmd_order[4];
static int cmd_n;

static void
cmd_a (void *user)
{
  (void) user;
  cmd_order[cmd_n++] = 1;
}

static void
cmd_b (void *user)
{
  (void) user;
  cmd_order[cmd_n++] = 2;
}

/* The queue has several producers: the workers of the storage pool, the
   resolver and the loops post to the loop that consumes.  Each message is
   a token; it must run once, and the messages of one producer in the order
   they were posted.  A queue that recycles its nodes unsafely loses
   messages, runs some twice and mixes up the order, so this is run enough
   times to catch it nearly every time.  */
struct cq_run;

struct cq_token
{
  struct cq_run *run;
  unsigned producer;
  unsigned seq;			/* From 1.  */
};

struct cq_run
{
  struct twist_cmdq *q;
  unsigned nprod, per;
  struct cq_token *tokens;
  unsigned char *ran;
  unsigned *last;
  unsigned long done, twice, disordered;
  twist_atomic_int go;
  twist_atomic_int finished;
};

static void
cq_run_token (void *user)
{
  struct cq_token *t = user;
  struct cq_run *r = t->run;
  size_t idx = (size_t) t->producer * r->per + (t->seq - 1);

  if (r->ran[idx]++ != 0)
    r->twice++;
  if (t->seq != r->last[t->producer] + 1)
    r->disordered++;
  r->last[t->producer] = t->seq;
  r->done++;
}

static void *
cq_producer (void *arg)
{
  struct cq_token *first = arg;
  struct cq_run *r = first->run;
  unsigned i;

  while (!twist_atomic_load (&r->go))
    ;
  for (i = 0; i < r->per; i++)
    twist_cmdq_push (r->q, cq_run_token, &first[i]);
  __atomic_add_fetch (&r->finished, 1, __ATOMIC_RELEASE);
  return NULL;
}

/* One round: NPROD producers post PER messages each while this thread
   drains.  Returns 1 if every message ran exactly once and in order.  */
static int
cq_round (unsigned nprod, unsigned per)
{
  struct cq_run r;
  pthread_t th[8];
  unsigned i, j;
  unsigned long total = (unsigned long) nprod * per, lost = 0, k, before;
  int ok;

  memset (&r, 0, sizeof r);
  r.nprod = nprod;
  r.per = per;
  r.tokens = calloc (total, sizeof *r.tokens);
  r.ran = calloc (total, 1);
  r.last = calloc (nprod, sizeof *r.last);
  r.q = twist_cmdq_new ();
  if (r.tokens == NULL || r.ran == NULL || r.last == NULL || r.q == NULL)
    {
      check (0, "cmdq stress allocation");
      return 0;
    }
  for (i = 0; i < nprod; i++)
    for (j = 0; j < per; j++)
      {
        struct cq_token *t = &r.tokens[(size_t) i * per + j];

        t->run = &r;
        t->producer = i;
        t->seq = j + 1;
      }
  for (i = 0; i < nprod; i++)
    pthread_create (&th[i], NULL, cq_producer, &r.tokens[(size_t) i * per]);
  twist_atomic_store (&r.go, 1);
  /* Drain while they post.  */
  while (r.done < total && twist_atomic_load (&r.finished) < (int) nprod)
    twist_cmdq_drain (r.q);
  for (i = 0; i < nprod; i++)
    pthread_join (th[i], NULL);
  /* Everything posted is in the queue now: take what is left.  */
  do
    {
      before = r.done;
      twist_cmdq_drain (r.q);
    }
  while (r.done != before && r.done < total);
  for (k = 0; k < total; k++)
    if (!r.ran[k])
      lost++;
  ok = lost == 0 && r.twice == 0 && r.disordered == 0 && r.done == total;
  twist_cmdq_free (r.q);
  free (r.tokens);
  free (r.ran);
  free (r.last);
  return ok;
}

static void
test_cmdq_producers (void)
{
  int bad = 0, i;

  /* A hang is a failure too, not a stuck test run.  */
  alarm (120);
  for (i = 0; i < 6; i++)
    if (!cq_round (2, 100000))
      bad++;
  for (i = 0; i < 2; i++)
    if (!cq_round (4, 50000))
      bad++;
  alarm (0);
  check (bad == 0, "the command queue loses, repeats or reorders nothing");
}

static void
test_cmdq (void)
{
  struct twist_cmdq *q = twist_cmdq_new ();

  cmd_n = 0;
  check (q != NULL, "cmdq");
  check (twist_cmdq_push (q, cmd_a, NULL) == TWIST_OK, "push a");
  check (twist_cmdq_push (q, cmd_b, NULL) == TWIST_OK, "push b");
  twist_cmdq_drain (q);
  check (cmd_n == 2 && cmd_order[0] == 1 && cmd_order[1] == 2, "order");
  twist_cmdq_free (q);
}

static int echo_n;
static char echo[32];
static char written[32];
static size_t written_len;
static int watched;

static size_t
echo_receive (struct twist_endpoint *ep, const uint8_t *data, size_t len)
{
  size_t n = len > 0 ? 1 : 0;

  if (n == 0)
    return 0;
  if (echo_n + 1 < (int) sizeof echo)
    echo[echo_n++] = (char) data[0];
  twist_endpoint_send (ep, data, n);
  if (echo_n >= 2)
    return n;
  return n;
}

static ssize_t
capture_write (void *user, const uint8_t *buf, size_t len)
{
  (void) user;
  if (written_len + len < sizeof written)
    {
      memcpy (written + written_len, buf, len);
      written_len += len;
    }
  return (ssize_t) len;
}

static ssize_t
capture_read (void *user, uint8_t *buf, size_t len)
{
  (void) user;
  (void) buf;
  (void) len;
  return 0;
}

static void
on_watch (void *user, int fd, int interest)
{
  (void) user;
  (void) fd;
  watched = interest;
}

static const struct twist_protocol_handler echo_handler = {
  NULL,
  echo_receive,
  NULL,
  NULL,
  NULL,
  NULL,
  NULL
};

static void
test_connection (void)
{
  struct twist_loop *loop = twist_loop_new (1);
  struct twist_connection *c;
  struct twist_endpoint *ep;
  int fds[2];

  echo_n = 0;
  written_len = 0;
  watched = -1;
  check (pipe (fds) == 0, "pipe");
  c = twist_connection_new (loop);
  check (c != NULL, "conn");
  twist_loop_set_watch (loop, on_watch, NULL);
  twist_connection_set_fd (c, fds[0]);
  check ((watched & TWIST_INTEREST_READ) != 0, "read interest");
  twist_connection_set_io (c, capture_read, capture_write, NULL);
  twist_connection_set_handler (c, &echo_handler);
  ep = twist_connection_endpoint (c);
  ep->user_data = NULL;
  twist_connection_ingest (c, (const uint8_t *) "hi", 2);
  twist_connection_on_writable (c);
  check (echo_n == 2 && echo[0] == 'h' && echo[1] == 'i', "echo");
  check (written_len == 2 && written[0] == 'h' && written[1] == 'i', "wrote");
  twist_endpoint_pause_read (ep);
  check ((watched & TWIST_INTEREST_READ) == 0, "paused");
  twist_endpoint_resume_read (ep);
  check ((watched & TWIST_INTEREST_READ) != 0, "resumed");
  twist_connection_free (c);
  close (fds[1]);
  twist_loop_free (loop);
}

static int cap_err;
static size_t cap_got;

static size_t
cap_hold (struct twist_endpoint *ep, const uint8_t *data, size_t len)
{
  (void) ep;
  (void) data;
  (void) len;
  return 0;
}

static void
cap_error (struct twist_endpoint *ep, int err)
{
  (void) ep;
  cap_err = err;
}

static size_t
cap_take (struct twist_endpoint *ep, const uint8_t *data, size_t len)
{
  (void) ep;
  (void) data;
  cap_got += len;
  return len;
}

static const struct twist_protocol_handler cap_hold_handler = {
  NULL,
  cap_hold,
  NULL,
  NULL,
  cap_error,
  NULL,
  NULL
};

static const struct twist_protocol_handler cap_take_handler = {
  NULL,
  cap_take,
  NULL,
  NULL,
  cap_error,
  NULL,
  NULL
};

static void
test_inbound_ceiling (void)
{
  struct twist_loop *loop = twist_loop_new (1);
  struct twist_connection *c;
  uint8_t *blob;
  size_t i;

  blob = calloc (1, TWIST_IN_CEILING);
  check (blob != NULL && loop != NULL, "ceiling buf");
  c = twist_connection_new (loop);
  cap_err = 0;
  twist_connection_set_handler (c, &cap_hold_handler);
  twist_connection_ingest (c, blob, TWIST_IN_CEILING);
  check (cap_err == TWIST_ERR_PROTOCOL, "ceiling fails");
  twist_connection_free (c);

  c = twist_connection_new (loop);
  cap_err = 0;
  cap_got = 0;
  twist_connection_set_handler (c, &cap_take_handler);
  for (i = 0; i < 4; i++)
    twist_connection_ingest (c, blob, TWIST_IN_CEILING / 2);
  check (cap_err == 0, "stream no error");
  check (cap_got == TWIST_IN_CEILING * 2, "stream consumed");
  twist_connection_free (c);
  free (blob);
  twist_loop_free (loop);
}

int
main (void)
{
  test_timer ();
  test_cmdq ();
  test_cmdq_producers ();
  test_connection ();
  test_inbound_ceiling ();
  return tests_finish ();
}
