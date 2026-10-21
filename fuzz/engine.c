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

/* A small coverage-guided fuzzer, for when there is no libFuzzer or AFL.

   The library is built with gcc's -fsanitize-coverage=trace-pc, which calls
   __sanitizer_cov_trace_pc at the start of each basic block; this file keeps
   the edges seen in a bitmap.  An input that reaches an edge not seen before
   joins the corpus, and the next inputs are mutations of corpus entries.  A
   harness defines LLVMFuzzerTestOneInput, as for libFuzzer, so that with clang
   it can be built with -fsanitize=fuzzer instead and this file left out.

   usage: FUZZER [options] [FILE...]
     FILE...             run each file once, and stop (to reproduce a crash)
     -max_total_time=S   stop after S seconds (default: never)
     -runs=N             stop after N runs
     -seed=N             the random seed
     -max_len=N          the longest input (default 4096)
     -timeout=S          seconds one run may take (default 10)
     -corpus=DIR         read inputs from DIR, and write new ones to it
     -artifact_dir=DIR   where an input that crashes is written (default .)
     -leak_check=N       check for leaks every N runs (default 0: never)  */

#define _GNU_SOURCE
#include <errno.h>
#include <dirent.h>
#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

int LLVMFuzzerTestOneInput (const uint8_t *data, size_t size);
int LLVMFuzzerInitialize (int *argc, char ***argv) __attribute__ ((weak));
/* The harness may give seeds and a dictionary of tokens.  */
void fuzz_seeds (void (*add) (const void *data, size_t n))
  __attribute__ ((weak));
extern const char *const fuzz_tokens[] __attribute__ ((weak));

void __sanitizer_set_death_callback (void (*cb) (void)) __attribute__ ((weak));
int __lsan_do_recoverable_leak_check (void) __attribute__ ((weak));

/* The sanitizers stop the program by aborting, so that on_signal below can
   save the input that did it.  (Their exit does not call the death callback
   in the version of gcc's runtime that was tried.)  */
const char *__asan_default_options (void);
const char *__ubsan_default_options (void);

const char *
__asan_default_options (void)
{
  return "abort_on_error=1:handle_abort=0:detect_leaks=0:"
         "allocator_may_return_null=1";
}

const char *
__ubsan_default_options (void)
{
  return "abort_on_error=1:print_stacktrace=1";
}

/* ---- coverage ---- */

#define MAP_BITS 16
#define MAP_SIZE (1u << MAP_BITS)

void __sanitizer_cov_trace_pc (void);

static uint8_t cur_map[MAP_SIZE];
static uint8_t seen_map[MAP_SIZE];
static uint32_t hits[MAP_SIZE];
static uint32_t nhits;
static uintptr_t prev_loc;
static unsigned long edges_seen;

void
__sanitizer_cov_trace_pc (void)
{
  uintptr_t pc = (uintptr_t) __builtin_return_address (0);
  uintptr_t h = (pc >> 1) ^ (pc >> 11);
  uint32_t idx = (uint32_t) ((h ^ prev_loc) & (MAP_SIZE - 1));

  if (!cur_map[idx])
    {
      cur_map[idx] = 1;
      hits[nhits++] = idx;
    }
  prev_loc = h >> 1;
}

/* After a run: how many edges are new.  The map is cleared for the next.  */
static unsigned
coverage_new (void)
{
  unsigned fresh = 0;
  uint32_t i;

  for (i = 0; i < nhits; i++)
    {
      uint32_t idx = hits[i];

      if (!seen_map[idx])
        {
          seen_map[idx] = 1;
          fresh++;
          edges_seen++;
        }
      cur_map[idx] = 0;
    }
  nhits = 0;
  prev_loc = 0;
  return fresh;
}

/* ---- random numbers ---- */

static uint64_t rng_state = 88172645463325252ull;

static uint64_t
rnd (void)
{
  rng_state ^= rng_state << 13;
  rng_state ^= rng_state >> 7;
  rng_state ^= rng_state << 17;
  return rng_state;
}

static size_t
below (size_t n)
{
  return n == 0 ? 0 : (size_t) (rnd () % n);
}

/* ---- corpus ---- */

struct entry
{
  uint8_t *data;
  size_t len;
};

static struct entry *corpus;
static size_t ncorpus, cap_corpus;
static size_t max_len = 4096;
static const char *corpus_dir;
static const char *artifact_dir = ".";

static void
corpus_add (const void *data, size_t n)
{
  if (n > max_len)
    n = max_len;
  if (ncorpus == cap_corpus)
    {
      size_t cap = cap_corpus == 0 ? 64 : cap_corpus * 2;
      struct entry *grown = realloc (corpus, cap * sizeof *grown);

      if (grown == NULL)
        return;
      corpus = grown;
      cap_corpus = cap;
    }
  corpus[ncorpus].data = malloc (n + 1);
  if (corpus[ncorpus].data == NULL)
    return;
  if (n > 0)
    memcpy (corpus[ncorpus].data, data, n);
  corpus[ncorpus].len = n;
  ncorpus++;
}

static uint64_t
fnv1a (const uint8_t *p, size_t n)
{
  uint64_t h = 14695981039346656037ull;
  size_t i;

  for (i = 0; i < n; i++)
    {
      h ^= p[i];
      h *= 1099511628211ull;
    }
  return h;
}

static int
write_file (const char *dir, const char *prefix, const uint8_t *data, size_t n)
{
  char path[1024];
  int fd;
  size_t off = 0;

  snprintf (path, sizeof path, "%s/%s%016llx", dir, prefix,
            (unsigned long long) fnv1a (data, n));
  fd = open (path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
  if (fd < 0)
    return -1;
  while (off < n)
    {
      ssize_t w = write (fd, data + off, n - off);

      if (w <= 0)
        break;
      off += (size_t) w;
    }
  close (fd);
  return 0;
}

static void
load_dir (const char *dir)
{
  DIR *d = opendir (dir);
  struct dirent *e;

  if (d == NULL)
    return;
  while ((e = readdir (d)) != NULL)
    {
      char path[1024];
      struct stat st;
      FILE *fp;
      uint8_t *buf;
      size_t n;

      snprintf (path, sizeof path, "%s/%s", dir, e->d_name);
      if (stat (path, &st) != 0 || !S_ISREG (st.st_mode))
        continue;
      fp = fopen (path, "rb");
      if (fp == NULL)
        continue;
      buf = malloc ((size_t) st.st_size + 1);
      if (buf != NULL)
        {
          n = fread (buf, 1, (size_t) st.st_size, fp);
          corpus_add (buf, n);
          free (buf);
        }
      fclose (fp);
    }
  closedir (d);
}

/* ---- crashes ---- */

static const uint8_t *running;
static size_t running_len;
static const char *crash_prefix = "crash-";

static void
save_running (void)
{
  if (running != NULL)
    {
      write_file (artifact_dir, crash_prefix, running, running_len);
      fprintf (stderr, "fuzz: the input is saved as %s/%s%016llx\n",
               artifact_dir, crash_prefix,
               (unsigned long long) fnv1a (running, running_len));
    }
}

static void
on_death (void)
{
  save_running ();
}

static void
on_signal (int sig)
{
  if (sig == SIGALRM)
    crash_prefix = "timeout-";
  save_running ();
  signal (sig, SIG_DFL);
  raise (sig == SIGALRM ? SIGABRT : sig);
}

/* ---- mutation ---- */

static const int8_t interesting8[] = { -128, -1, 0, 1, 16, 32, 64, 100, 127 };
static const int16_t interesting16[] = { -32768, -129, 128, 255, 256, 512,
                                         1000, 1024, 4096, 32767 };
static const int32_t interesting32[] = { INT32_MIN, -100663046, -32769, 32768,
                                         65535, 65536, 100663045, INT32_MAX };

static size_t
mutate (uint8_t *buf, size_t len)
{
  int rounds = 1 + (int) below (4);

  while (rounds-- > 0)
    {
      switch (below (14))
        {
        case 0:		/* flip a bit */
          if (len > 0)
            buf[below (len)] ^= (uint8_t) (1u << below (8));
          break;
        case 1:		/* set a byte */
          if (len > 0)
            buf[below (len)] = (uint8_t) rnd ();
          break;
        case 2:		/* an interesting byte */
          if (len > 0)
            buf[below (len)] = (uint8_t) interesting8[below (sizeof interesting8)];
          break;
        case 3:		/* an interesting 16 bit value */
          if (len >= 2)
            {
              int16_t v = interesting16[below (sizeof interesting16 / 2)];
              size_t at = below (len - 1);

              memcpy (buf + at, &v, 2);
            }
          break;
        case 4:		/* an interesting 32 bit value */
          if (len >= 4)
            {
              int32_t v = interesting32[below (sizeof interesting32 / 4)];
              size_t at = below (len - 3);

              memcpy (buf + at, &v, 4);
            }
          break;
        case 5:		/* add or subtract */
          if (len > 0)
            {
              size_t at = below (len);
              int d = (int) below (35) + 1;

              buf[at] = (uint8_t) (below (2) ? buf[at] + d : buf[at] - d);
            }
          break;
        case 6:		/* delete a block */
          if (len > 1)
            {
              size_t n = 1 + below (len / 2 > 0 ? len / 2 : 1);
              size_t at = below (len - n + 1);

              memmove (buf + at, buf + at + n, len - at - n);
              len -= n;
            }
          break;
        case 7:		/* insert random bytes */
          {
            size_t n = 1 + below (16), at = below (len + 1), i;

            if (len + n <= max_len)
              {
                memmove (buf + at + n, buf + at, len - at);
                for (i = 0; i < n; i++)
                  buf[at + i] = (uint8_t) rnd ();
                len += n;
              }
          }
          break;
        case 8:		/* copy a block of the input into another place */
          if (len > 1)
            {
              size_t n = 1 + below (len > 32 ? 32 : len - 1);
              size_t from = below (len - n + 1), at = below (len + 1);

              if (len + n <= max_len)
                {
                  uint8_t tmp[32];

                  memcpy (tmp, buf + from, n);
                  memmove (buf + at + n, buf + at, len - at);
                  memcpy (buf + at, tmp, n);
                  len += n;
                }
            }
          break;
        case 9:		/* overwrite with a block of the input */
          if (len > 1)
            {
              size_t n = 1 + below (len > 32 ? 32 : len - 1);
              size_t from = below (len - n + 1), at = below (len - n + 1);

              memmove (buf + at, buf + from, n);
            }
          break;
        case 10:		/* splice with another entry */
          if (ncorpus > 1)
            {
              const struct entry *o = &corpus[below (ncorpus)];

              if (o->len > 0)
                {
                  size_t cut = below (len + 1), from = below (o->len);
                  size_t n = o->len - from;

                  if (cut + n > max_len)
                    n = max_len - cut;
                  memcpy (buf + cut, o->data + from, n);
                  len = cut + n;
                }
            }
          break;
        case 11:		/* a token */
        case 12:
          if (fuzz_tokens != NULL && fuzz_tokens[0] != NULL)
            {
              size_t nt = 0, at, n;
              const char *tok;

              while (fuzz_tokens[nt] != NULL)
                nt++;
              tok = fuzz_tokens[below (nt)];
              n = strlen (tok);
              at = below (len + 1);
              if (below (2) && len >= n)
                {
                  at = below (len - n + 1);
                  memcpy (buf + at, tok, n);
                }
              else if (len + n <= max_len)
                {
                  memmove (buf + at + n, buf + at, len - at);
                  memcpy (buf + at, tok, n);
                  len += n;
                }
            }
          break;
        default:		/* truncate */
          if (len > 1)
            len = 1 + below (len - 1);
          break;
        }
    }
  return len;
}

/* ---- running ---- */

static unsigned long runs_done;

static void
run_one (const uint8_t *data, size_t len, int leak_every)
{
  running = data;
  running_len = len;
  LLVMFuzzerTestOneInput (data, len);
  running = NULL;
  runs_done++;
  if (leak_every > 0 && runs_done % (unsigned long) leak_every == 0
      && __lsan_do_recoverable_leak_check != NULL)
    {
      running = data;
      if (__lsan_do_recoverable_leak_check ())
        {
          fprintf (stderr, "fuzz: a leak, after the input that is saved\n");
          save_running ();
          _exit (78);
        }
      running = NULL;
    }
}

static int
replay_file (const char *path)
{
  FILE *fp = fopen (path, "rb");
  uint8_t *buf;
  long n;

  if (fp == NULL)
    {
      fprintf (stderr, "fuzz: cannot read %s\n", path);
      return 1;
    }
  fseek (fp, 0, SEEK_END);
  n = ftell (fp);
  fseek (fp, 0, SEEK_SET);
  buf = malloc ((size_t) n + 1);
  if (buf == NULL || fread (buf, 1, (size_t) n, fp) != (size_t) n)
    {
      fclose (fp);
      free (buf);
      return 1;
    }
  fclose (fp);
  run_one (buf, (size_t) n, 0);
  free (buf);
  fprintf (stderr, "fuzz: ran %s (%ld bytes)\n", path, n);
  return 0;
}

static long
opt (const char *arg, const char *name)
{
  size_t n = strlen (name);

  if (strncmp (arg, name, n) == 0 && arg[n] == '=')
    return atol (arg + n + 1);
  return -1;
}

static const char *
optstr (const char *arg, const char *name)
{
  size_t n = strlen (name);

  if (strncmp (arg, name, n) == 0 && arg[n] == '=')
    return arg + n + 1;
  return NULL;
}

int
main (int argc, char **argv)
{
  long max_time = 0, max_runs = 0, timeout = 10, leak_every = 0;
  uint64_t seed = (uint64_t) time (NULL) * 2654435761u + (uint64_t) getpid ();
  int i, files = 0;
  time_t start, last_report;
  uint8_t *buf;
  struct sigaction sa;
  int rc = 0;

  setvbuf (stderr, NULL, _IOLBF, 0);
  if (LLVMFuzzerInitialize != NULL)
    LLVMFuzzerInitialize (&argc, &argv);
  for (i = 1; i < argc; i++)
    {
      const char *s;
      long v;

      if (argv[i][0] != '-')
        continue;
      if ((v = opt (argv[i] + 1, "max_total_time")) >= 0)
        max_time = v;
      else if ((v = opt (argv[i] + 1, "runs")) >= 0)
        max_runs = v;
      else if ((v = opt (argv[i] + 1, "seed")) >= 0)
        seed = (uint64_t) v;
      else if ((v = opt (argv[i] + 1, "max_len")) >= 0)
        max_len = (size_t) v;
      else if ((v = opt (argv[i] + 1, "timeout")) >= 0)
        timeout = v;
      else if ((v = opt (argv[i] + 1, "leak_check")) >= 0)
        leak_every = v;
      else if ((s = optstr (argv[i] + 1, "corpus")) != NULL)
        corpus_dir = s;
      else if ((s = optstr (argv[i] + 1, "artifact_dir")) != NULL)
        artifact_dir = s;
      else
        {
          fprintf (stderr, "fuzz: unknown option %s\n", argv[i]);
          return 2;
        }
    }
  rng_state ^= seed * 0x9e3779b97f4a7c15ull;
  if (rng_state == 0)
    rng_state = 1;

  if (__sanitizer_set_death_callback != NULL)
    __sanitizer_set_death_callback (on_death);
  memset (&sa, 0, sizeof sa);
  sa.sa_handler = on_signal;
  sigaction (SIGABRT, &sa, NULL);
  sigaction (SIGALRM, &sa, NULL);

  /* Files given: run them and stop.  */
  for (i = 1; i < argc; i++)
    if (argv[i][0] != '-')
      {
        files++;
        rc |= replay_file (argv[i]);
      }
  if (files > 0)
    return rc;

  if (fuzz_seeds != NULL)
    fuzz_seeds (corpus_add);
  if (corpus_dir != NULL)
    load_dir (corpus_dir);
  if (ncorpus == 0)
    corpus_add ("", 0);
  /* Everything the seeds reach is already known: run them to learn it.  */
  for (i = 0; (size_t) i < ncorpus; i++)
    {
      alarm ((unsigned) timeout);
      run_one (corpus[i].data, corpus[i].len, 0);
      coverage_new ();
    }
  alarm (0);
  fprintf (stderr, "fuzz: %zu seeds, %lu edges\n", ncorpus, edges_seen);

  buf = malloc (max_len + 64);
  if (buf == NULL)
    return 1;
  start = last_report = time (NULL);
  while ((max_time == 0 || time (NULL) - start < max_time)
         && (max_runs == 0 || runs_done < (unsigned long) max_runs))
    {
      /* Newer entries are more likely: they are where the edge was new.  */
      size_t pick = below (3) == 0 ? below (ncorpus)
                                   : ncorpus - 1 - below (ncorpus < 16 ? ncorpus : 16);
      size_t len = corpus[pick].len;

      memcpy (buf, corpus[pick].data, len);
      len = mutate (buf, len);
      alarm ((unsigned) timeout);
      run_one (buf, len, (int) leak_every);
      alarm (0);
      if (coverage_new () > 0)
        {
          corpus_add (buf, len);
          if (corpus_dir != NULL)
            write_file (corpus_dir, "", buf, len);
        }
      if (time (NULL) - last_report >= 5)
        {
          last_report = time (NULL);
          fprintf (stderr, "fuzz: %lu runs, %lu edges, corpus %zu, %lu runs/s\n",
                   runs_done, edges_seen, ncorpus,
                   runs_done / (unsigned long) (last_report - start + 1));
        }
    }
  fprintf (stderr, "fuzz: done: %lu runs, %lu edges, corpus %zu\n", runs_done,
           edges_seen, ncorpus);
  free (buf);
  return 0;
}
