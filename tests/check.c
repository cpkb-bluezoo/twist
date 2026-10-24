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
#include <time.h>

int failed;

void
check (int cond, const char *what)
{
  if (!cond)
    {
      fprintf (stderr, "FAIL %s\n", what);
      failed = 1;
    }
}

void
check_job_done (struct twist_transfer *transfer, int result, void *user)
{
  struct check_job *job = user;

  (void) transfer;
  job->result = result;
  job->done = 1;
  job->calls++;
}

int
check_pump (struct twist_runtime *runtime, struct check_job *job, int ms)
{
  struct timespec t0, t1;

  clock_gettime (CLOCK_MONOTONIC, &t0);
  while (!job->done)
    {
      twist_runtime_run_once (runtime, 5);
      clock_gettime (CLOCK_MONOTONIC, &t1);
      if ((t1.tv_sec - t0.tv_sec) * 1000
          + (t1.tv_nsec - t0.tv_nsec) / 1000000 >= ms)
        break;
    }
  return job->done;
}

int
check_perform_in (struct twist_runtime *runtime,
                  struct twist_transfer *transfer)
{
  struct check_job job = { 0, TWIST_ERR_CONNECT, 0 };
  int rc;

  /* Let the loop see what happened to the connections kept since the last
     transfer, so that one the server has closed is not taken.  */
  twist_runtime_run_once (runtime, 0);
  rc = twist_runtime_start (runtime, transfer, check_job_done, &job);
  if (rc != TWIST_OK)
    return rc;
  while (!job.done)
    {
      rc = twist_runtime_run_once (runtime, -1);
      if (rc != TWIST_OK)
        {
          twist_runtime_cancel (runtime, transfer);
          twist_runtime_run_once (runtime, 0);
          if (!job.done)
            return rc;
        }
    }
  return job.result;
}

int
check_perform (struct twist_transfer *transfer)
{
  struct twist_runtime *runtime = twist_runtime_new ();
  int rc;

  if (runtime == NULL)
    return TWIST_ERR_NOMEM;
  rc = check_perform_in (runtime, transfer);
  twist_runtime_free (runtime);
  return rc;
}

int
tests_finish (void)
{
  if (failed)
    {
      fprintf (stderr, "unit tests failed\n");
      return 1;
    }
  return 0;
}
