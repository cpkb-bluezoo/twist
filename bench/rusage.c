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

/* rusage OUTFILE COMMAND [ARGUMENT...]: run COMMAND, and write to OUTFILE one
   line: its exit status, the wall time in seconds, user and system CPU seconds,
   and peak resident set in bytes.  A small program of its own because the peak resident set of a child
   starts from that of the process that forked it, and a Python parent is not
   small.  */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/resource.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

int
main (int argc, char **argv)
{
  struct rusage ru;
  struct timespec t0, t1;
  double wall;
  int status;
  pid_t pid;
  FILE *out;
  long rss;

  if (argc < 3)
    return 2;
  clock_gettime (CLOCK_MONOTONIC, &t0);
  pid = fork ();
  if (pid < 0)
    return 2;
  if (pid == 0)
    {
      execvp (argv[2], argv + 2);
      _exit (127);
    }
  if (wait4 (pid, &status, 0, &ru) < 0)
    return 2;
  clock_gettime (CLOCK_MONOTONIC, &t1);
  wall = (double) (t1.tv_sec - t0.tv_sec) + (double) (t1.tv_nsec - t0.tv_nsec) / 1e9;
  rss = ru.ru_maxrss;
#ifndef __APPLE__
  rss *= 1024;			/* Kilobytes on Linux, bytes on macOS.  */
#endif
  out = fopen (argv[1], "w");
  if (out == NULL)
    return 2;
  fprintf (out, "%d %.6f %ld.%06ld %ld.%06ld %ld\n",
           WIFEXITED (status) ? WEXITSTATUS (status) : 128 + WTERMSIG (status),
           wall,
           (long) ru.ru_utime.tv_sec, (long) ru.ru_utime.tv_usec,
           (long) ru.ru_stime.tv_sec, (long) ru.ru_stime.tv_usec, rss);
  fclose (out);
  return 0;
}
