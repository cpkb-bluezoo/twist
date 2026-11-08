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

/* The table of descriptors.  On Linux a process with threads that needs a
   bigger table waits for a grace period of the kernel's, some milliseconds,
   at 64, 128, 256 descriptors and so on; a transfer that opens its file (and
   duplicates it) for each of a few dozen parallel URLs met it on the loop's
   thread, in the middle of the handshake.  The runtime makes the table big
   before it makes a thread.  */

#include "check.h"
#include "twist-int.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>

/* The size of the table, from the kernel; -1 if it does not say.  */
static long
fdsize (void)
{
  FILE *f = fopen ("/proc/self/status", "r");
  char line[256];
  long n = -1;

  if (f == NULL)
    return -1;
  while (fgets (line, sizeof line, f) != NULL)
    if (strncmp (line, "FDSize:", 7) == 0)
      n = atol (line + 7);
  fclose (f);
  return n;
}

int
main (void)
{
  struct rlimit rl;
  long before = fdsize ();
  long want = 1024;
  twist_runtime *runtime;
  long after;

  if (before < 0)
    return 77;			/* Not Linux.  */
  if (getrlimit (RLIMIT_NOFILE, &rl) == 0 && rl.rlim_cur != RLIM_INFINITY
      && (long) rl.rlim_cur < want)
    want = (long) rl.rlim_cur;
  if (want < 256)
    return 77;			/* A limit too small to tell.  */
  check (before < want, "the table starts small");
  runtime = twist_runtime_new ();
  check (runtime != NULL, "a runtime is made");
  after = fdsize ();
  check (after >= want / 2,
         "and is big when the runtime has made its threads");
  twist_runtime_free (runtime);
  return tests_finish ();
}
