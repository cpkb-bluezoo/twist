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

#ifndef TWIST_TEST_CHECK_H
#define TWIST_TEST_CHECK_H

struct twist_transfer;
struct twist_runtime;

extern int failed;

void check (int cond, const char *what);
int tests_finish (void);

/* The end of a transfer that was started with check_job_done as its callback:
   whether it has ended, how, and how many times the callback was called.  */
struct check_job
{
  int done;
  int result;
  int calls;
};

void check_job_done (struct twist_transfer *transfer, int result, void *user);

/* Run the loop, a little at a time, until JOB is done or MS milliseconds have
   passed.  Returns whether it is.  */
int check_pump (struct twist_runtime *runtime, struct check_job *job, int ms);

/* Run one transfer to its end and return its result.  The first makes a
   runtime of its own and frees it; the second runs on one that is given and
   leaves it, with its kept connections and names, for the next.  A test that
   needs to see the transfer while it runs drives the runtime itself.  */
int check_perform (struct twist_transfer *transfer);
int check_perform_in (struct twist_runtime *runtime,
                      struct twist_transfer *transfer);

#endif
