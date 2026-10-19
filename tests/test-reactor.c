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
#include "reactor/cmdq.h"
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
  test_connection ();
  test_inbound_ceiling ();
  return tests_finish ();
}
