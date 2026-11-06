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

#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

/* The body of an upload comes from a push source, and not from the
   application's read callback called by the handler.  First the source on its
   own; then HTTP/1 uploads, chunked and of a known length, against a server
   on the loopback.  */

struct cb
{
  const uint8_t *data;
  size_t total;
  size_t off;
  size_t step;			/* At most this much a call; 0: as asked.  */
  size_t stop_at;		/* End early here (0: no).  */
  int calls;
  int abort_at;			/* Return ABORT on this call (0: no).  */
  int seeks;
  int seek_fail;
};

static size_t
cb_read (char *ptr, size_t size, size_t nmemb, void *user)
{
  struct cb *c = user;
  size_t n = size * nmemb;
  size_t end = c->stop_at != 0 ? c->stop_at : c->total;

  c->calls++;
  if (c->abort_at != 0 && c->calls == c->abort_at)
    return TWIST_READFUNC_ABORT;
  if (c->step != 0 && n > c->step)
    n = c->step;
  if (n > end - c->off)
    n = end - c->off;
  memcpy (ptr, c->data + c->off, n);
  c->off += n;
  return n;
}

static int
cb_seek (void *user, long long off, int origin)
{
  struct cb *c = user;

  (void) origin;
  c->seeks++;
  if (c->seek_fail || off != 0)
    return 1;
  c->off = 0;
  return 0;
}

struct cons
{
  struct twist_upload *up;
  uint8_t got[200000];
  size_t n;
  int chunks;
  int ends;
  int end_err;
  int pause_after;		/* Pause the source after this many chunks.  */
  int freed_in_end;
};

static int
cons_chunk (void *user, const uint8_t *data, size_t len)
{
  struct cons *c = user;

  if (c->n + len <= sizeof c->got)
    memcpy (c->got + c->n, data, len);
  c->n += len;
  c->chunks++;
  if (c->pause_after != 0 && c->chunks == c->pause_after)
    twist_upload_pause (c->up);
  return TWIST_OK;
}

static void
cons_end (void *user, int err)
{
  struct cons *c = user;

  c->ends++;
  c->end_err = err;
}

static const struct twist_upload_consumer cons_ops = { cons_chunk, cons_end };

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
test_adapter (void)
{
  struct twist_transfer *t = twist_transfer_new ();
  struct cb c;
  struct cons k;
  uint8_t *data = pattern (50000);

  memset (&c, 0, sizeof c);
  memset (&k, 0, sizeof k);
  c.data = data;
  c.total = 50000;
  t->read_cb = cb_read;
  t->read_data = &c;
  t->seek_cb = cb_seek;
  t->seek_data = &c;
  k.up = twist_transfer_upload (t);
  check (k.up != NULL, "a transfer with a read callback has an upload");
  check (twist_transfer_upload (t) == k.up, "and the same one each time");
  check (twist_upload_attach (k.up, &cons_ops, &k, 4096) == TWIST_OK,
         "a consumer is attached");
  check (twist_upload_attach (k.up, &cons_ops, &k, 4096) != TWIST_OK,
         "and a second is refused");
  check (c.calls == 0, "the callback is not called until the consumer asks");
  k.pause_after = 2;
  twist_upload_resume (k.up);
  check (k.chunks == 2 && c.calls == 2,
         "a paused source is not read: no more calls to the callback");
  check (k.ends == 0, "and it is not over");
  k.pause_after = 0;
  twist_upload_resume (k.up);
  check (k.ends == 1 && k.end_err == TWIST_OK && k.n == 50000
         && memcmp (k.got, data, 50000) == 0,
         "resumed, it delivers all of it, in order, and ends once");
  check (k.chunks > 2 && k.chunks <= 50000 / 4096 + 2,
         "in chunks of no more than the consumer said");
  /* Again from the start.  */
  twist_upload_detach (k.up);
  check (twist_upload_restart (k.up) == TWIST_OK && c.seeks == 1,
         "a restart goes to the seek callback");
  memset (&k.n, 0, sizeof k.n);
  k.chunks = 0;
  k.ends = 0;
  twist_upload_attach (k.up, &cons_ops, &k, 4096);
  twist_upload_resume (k.up);
  check (k.ends == 1 && k.n == 50000 && memcmp (k.got, data, 50000) == 0,
         "and the source is read from the start again");
  twist_upload_detach (k.up);
  c.seek_fail = 1;
  check (twist_upload_restart (k.up) == TWIST_ERR_REWIND,
         "a source that cannot restart is a rewind error");
  t->seek_cb = NULL;
  twist_transfer_free (t);
  free (data);
}

static void
test_adapter_abort (void)
{
  struct twist_transfer *t = twist_transfer_new ();
  struct cb c;
  struct cons k;
  uint8_t *data = pattern (10000);

  memset (&c, 0, sizeof c);
  memset (&k, 0, sizeof k);
  c.data = data;
  c.total = 10000;
  c.step = 100;
  c.abort_at = 3;
  t->read_cb = cb_read;
  t->read_data = &c;
  k.up = twist_transfer_upload (t);
  twist_upload_attach (k.up, &cons_ops, &k, 4096);
  twist_upload_resume (k.up);
  check (k.ends == 1 && k.end_err == TWIST_ERR_ABORTED && k.n == 200,
         "a callback that stops ends the source with ABORTED, once");
  twist_upload_detach (k.up);
  check (twist_transfer_upload (twist_transfer_new ()) == NULL,
         "a transfer with no read callback has no upload");
  twist_transfer_free (t);
  free (data);
}

/* A source that has been detached from calls nothing.  */
static void
test_detach (void)
{
  struct twist_transfer *t = twist_transfer_new ();
  struct cb c;
  struct cons k;
  uint8_t *data = pattern (10000);

  memset (&c, 0, sizeof c);
  memset (&k, 0, sizeof k);
  c.data = data;
  c.total = 10000;
  c.step = 100;
  t->read_cb = cb_read;
  t->read_data = &c;
  k.up = twist_transfer_upload (t);
  twist_upload_attach (k.up, &cons_ops, &k, 4096);
  k.pause_after = 1;
  twist_upload_resume (k.up);
  twist_upload_detach (k.up);
  twist_upload_resume (k.up);
  check (k.chunks == 1 && c.calls == 1 && k.ends == 0,
         "nothing is read or delivered after the consumer is detached");
  twist_transfer_free (t);
  free (data);
}

/* A read callback that says to wait does not end the body: the callback is
   asked again after the transfer is resumed.  */
static int wait_calls;

static size_t
wait_read (char *ptr, size_t size, size_t nmemb, void *user)
{
  struct cb *c = user;

  (void) size;
  (void) nmemb;
  wait_calls++;
  if (wait_calls == 2)
    return TWIST_READFUNC_PAUSE;
  if (c->off >= c->total)
    return 0;
  ptr[0] = (char) c->data[c->off++];
  return 1;
}

static void
test_read_pause (void)
{
  struct twist_transfer *t = twist_transfer_new ();
  struct cb c;
  struct cons k;
  uint8_t data[10];

  memset (&c, 0, sizeof c);
  memset (&k, 0, sizeof k);
  memset (data, 'w', sizeof data);
  c.data = data;
  c.total = sizeof data;
  wait_calls = 0;
  t->read_cb = wait_read;
  t->read_data = &c;
  k.up = twist_transfer_upload (t);
  twist_upload_attach (k.up, &cons_ops, &k, 4096);
  twist_upload_resume (k.up);
  check (k.chunks == 1 && k.ends == 0 && wait_calls == 2,
         "a callback that says to wait is not asked again, and is not the end");
  check (twist_transfer_resume (t) == TWIST_OK, "the transfer is resumed");
  check (k.ends == 1 && k.end_err == TWIST_OK && k.n == 10,
         "and the body goes on to its end");
  twist_upload_detach (k.up);
  twist_transfer_free (t);
}

/* An upload the application pushes: refused when the transfer cannot take
   more, and the want-more callback says when it can.  */
static int wants;

static void
on_want (twist_transfer *t, void *user)
{
  (void) t;
  (void) user;
  wants++;
}

static void
test_push_api (void)
{
  struct twist_transfer *t = twist_transfer_new ();
  struct cons k;
  uint8_t data[300];
  size_t taken = 0;

  memset (&k, 0, sizeof k);
  memset (data, 'u', sizeof data);
  check (twist_transfer_upload_push (t, data, 1, &taken) != TWIST_OK,
         "a push to a transfer that has no pushed upload is refused");
  twist_transfer_setopt (t, TWISTOPT_UPLOAD_PUSH, 1L);
  twist_transfer_setopt (t, TWISTOPT_WANTFUNCTION, on_want);
  wants = 0;
  k.up = twist_transfer_upload (t);
  check (k.up != NULL, "a transfer with a pushed upload has one");
  twist_upload_attach (k.up, &cons_ops, &k, 100);
  twist_upload_resume (k.up);
  check (wants == 1, "the application is told it may push");
  /* The consumer takes a chunk and says to stop.  */
  k.pause_after = 1;
  check (twist_transfer_upload_push (t, data, sizeof data, &taken) == TWIST_OK
         && taken == 100 && k.n == 100,
         "a push is taken up to the pause, and no more");
  check (twist_transfer_upload_push (t, data, 50, &taken) == TWIST_ERR_AGAIN
         && taken == 0 && k.n == 100,
         "a push past the pause point is refused, and nothing is taken");
  k.pause_after = 0;
  twist_upload_resume (k.up);
  check (wants == 2, "and the application is told when it may push again");
  check (twist_transfer_upload_push (t, data + 100, 200, &taken) == TWIST_OK
         && taken == 200 && k.n == 300 && memcmp (k.got, data, 300) == 0,
         "then the rest is taken, in order");
  check (twist_transfer_upload_end (t, TWIST_OK) == TWIST_OK && k.ends == 1
         && k.end_err == TWIST_OK, "the end is passed on, once");
  check (twist_transfer_upload_end (t, TWIST_OK) == TWIST_OK && k.ends == 1,
         "and not again");
  twist_upload_detach (k.up);
  twist_transfer_free (t);

  /* An upload that fails.  */
  t = twist_transfer_new ();
  memset (&k, 0, sizeof k);
  twist_transfer_setopt (t, TWISTOPT_UPLOAD_PUSH, 1L);
  k.up = twist_transfer_upload (t);
  twist_upload_attach (k.up, &cons_ops, &k, 100);
  twist_upload_resume (k.up);
  twist_transfer_upload_end (t, TWIST_ERR_ABORTED);
  check (k.ends == 1 && k.end_err == TWIST_ERR_ABORTED,
         "an upload that fails says why");
  twist_upload_detach (k.up);
  twist_transfer_free (t);
}

/* ---- HTTP/1 against a server ---- */

struct srv
{
  int listen_fd;
  int port;
  int stall_ms;			/* Do not read for this long, after the head.  */
  pthread_t thread;
  /* What it saw.  */
  char head[4096];
  uint8_t *body;
  size_t body_n;
  int chunked;
  long long clen;
  int bad_framing;
  long long uploaded;		/* What the meter showed at the end.  */
  /* With a stall: what the source had given when the server began to read
     again, and how many body bytes it then counted.  */
  const size_t *probe;
  size_t read_ahead;
  size_t counted;
};

static void *
srv_main (void *arg)
{
  struct srv *s = arg;
  int fd = accept (s->listen_fd, NULL, NULL);
  size_t hn = 0;
  uint8_t *raw = malloc (4 * 1024 * 1024);
  size_t rn = 0;
  char *eoh;
  const char *p;

  if (fd < 0)
    return NULL;
  /* The head.  */
  for (;;)
    {
      ssize_t n = read (fd, s->head + hn, sizeof s->head - 1 - hn);

      if (n <= 0)
        goto out;
      hn += (size_t) n;
      s->head[hn] = 0;
      if ((eoh = strstr (s->head, "\r\n\r\n")) != NULL)
        break;
    }
  rn = hn - (size_t) (eoh + 4 - s->head);
  memcpy (raw, eoh + 4, rn);
  *eoh = 0;
  s->chunked = strcasestr (s->head, "transfer-encoding: chunked") != NULL;
  p = strcasestr (s->head, "content-length:");
  s->clen = p != NULL ? atoll (p + 15) : -1;
  if (s->stall_ms > 0)
    {
      usleep ((useconds_t) s->stall_ms * 1000);
      s->read_ahead = s->probe != NULL ? *s->probe : 0;
      s->counted = rn;
      while (s->clen >= 0 && s->counted < (size_t) s->clen)
        {
          uint8_t sink[65536];
          ssize_t n = read (fd, sink, sizeof sink);

          if (n <= 0)
            break;
          s->counted += (size_t) n;
        }
      s->body = NULL;
      goto reply;
    }
  s->body = malloc (4 * 1024 * 1024);
  for (;;)
    {
      if (s->chunked)
        {
          /* Walk the chunks that have arrived.  */
          size_t off = 0;
          int done = 0;

          s->body_n = 0;
          for (;;)
            {
              char *crlf = memchr (raw + off, '\r', rn - off);
              unsigned long len;

              if (crlf == NULL || (size_t) (crlf - (char *) raw) + 1 >= rn)
                break;
              len = strtoul ((char *) raw + off, NULL, 16);
              if (crlf[1] != '\n')
                {
                  s->bad_framing = 1;
                  goto reply;
                }
              off = (size_t) (crlf - (char *) raw) + 2;
              if (len == 0)
                {
                  done = rn - off >= 2;
                  break;
                }
              if (rn - off < len + 2)
                {
                  off = rn;
                  break;
                }
              if (raw[off + len] != '\r' || raw[off + len + 1] != '\n')
                {
                  s->bad_framing = 1;
                  goto reply;
                }
              memcpy (s->body + s->body_n, raw + off, len);
              s->body_n += len;
              off += len + 2;
            }
          if (done)
            break;
        }
      else if (s->clen >= 0 && rn >= (size_t) s->clen)
        {
          memcpy (s->body, raw, (size_t) s->clen);
          s->body_n = (size_t) s->clen;
          break;
        }
      {
        ssize_t n = read (fd, raw + rn, 4 * 1024 * 1024 - rn);

        if (n <= 0)
          break;
        rn += (size_t) n;
      }
    }
reply:
  {
    static const char reply[] = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n"
                                "Connection: close\r\n\r\nok";

    (void) !write (fd, reply, sizeof reply - 1);
  }
out:
  close (fd);
  free (raw);
  return NULL;
}

static int
srv_start (struct srv *s)
{
  struct sockaddr_in a;
  socklen_t len = sizeof a;
  int stall = s->stall_ms;
  const size_t *probe = s->probe;

  memset (s, 0, sizeof *s);
  s->stall_ms = stall;
  s->probe = probe;
  s->clen = -1;
  s->listen_fd = socket (AF_INET, SOCK_STREAM, 0);
  memset (&a, 0, sizeof a);
  a.sin_family = AF_INET;
  a.sin_addr.s_addr = htonl (INADDR_LOOPBACK);
  if (bind (s->listen_fd, (struct sockaddr *) &a, sizeof a) != 0
      || listen (s->listen_fd, 4) != 0
      || getsockname (s->listen_fd, (struct sockaddr *) &a, &len) != 0)
    return -1;
  s->port = ntohs (a.sin_port);
  return 0;
}

/* POST DATA from a callback that gives STEP at a time, as the length says
   (INFILESIZE, or -1 for chunked), and say what the server got.  */
static int
post (struct cb *c, long long infilesize, struct srv *s, int *result)
{
  struct twist_runtime *runtime = twist_runtime_new ();
  struct twist_transfer *t = twist_transfer_new ();
  struct check_job job = { 0, 0, 0 };
  char url[64];
  int rc;

  if (srv_start (s) != 0 || runtime == NULL || t == NULL)
    return -1;
  pthread_create (&s->thread, NULL, srv_main, s);
  snprintf (url, sizeof url, "http://127.0.0.1:%d/up", s->port);
  twist_transfer_setopt (t, TWISTOPT_URL, url);
  twist_transfer_setopt (t, TWISTOPT_CUSTOMREQUEST, "POST");
  twist_transfer_setopt (t, TWISTOPT_READFUNCTION, cb_read);
  twist_transfer_setopt (t, TWISTOPT_READDATA, c);
  if (infilesize >= 0)
    twist_transfer_setopt (t, TWISTOPT_INFILESIZE, infilesize);
  t->write_cb = NULL;
  rc = twist_runtime_start (runtime, t, check_job_done, &job);
  if (rc == TWIST_OK)
    check_pump (runtime, &job, 8000);
  *result = job.done ? job.result : -1;
  s->uploaded = t->progress.uploaded;
  close (s->listen_fd);
  pthread_join (s->thread, NULL);
  twist_runtime_free (runtime);
  twist_transfer_free (t);
  return 0;
}

static void
test_http_length (void)
{
  struct cb c;
  struct srv s;
  int result = 0;
  uint8_t *data = pattern (3000);

  memset (&s, 0, sizeof s);
  memset (&c, 0, sizeof c);
  c.data = data;
  c.total = 3000;
  c.step = 1;
  post (&c, 3000, &s, &result);
  check (result == TWIST_OK, "an upload of a known length is done");
  check (!s.chunked && s.clen == 3000 && s.body_n == 3000
         && memcmp (s.body, data, 3000) == 0,
         "with Content-Length, and the bytes, given one at a time");
  check (s.uploaded == 3000, "and the meter shows the body and no more");
  free (s.body);
  free (data);
}

static void
test_http_chunked (void)
{
  struct cb c;
  struct srv s;
  int result = 0;
  size_t total = 150000;
  uint8_t *data = pattern (total);

  memset (&s, 0, sizeof s);
  memset (&c, 0, sizeof c);
  c.data = data;
  c.total = total;
  c.step = 700;
  post (&c, -1, &s, &result);
  check (result == TWIST_OK, "an upload of no known length is done");
  check (s.chunked && !s.bad_framing && s.body_n == total
         && memcmp (s.body, data, total) == 0,
         "chunked, framed round whatever the source pushed");
  check (s.uploaded == (long long) total,
         "and the meter shows the body, not the chunk framing");
  free (s.body);
  /* And a source that gives a byte at a time.  */
  memset (&c, 0, sizeof c);
  c.data = data;
  c.total = 2000;
  c.step = 1;
  post (&c, -1, &s, &result);
  check (result == TWIST_OK && s.chunked && !s.bad_framing && s.body_n == 2000
         && memcmp (s.body, data, 2000) == 0,
         "chunked, with a chunk for each byte pushed");
  free (s.body);
  free (data);
}

/* A server that does not read for a while: the source is not read ahead
   without bound, and all of it arrives when the server does read.  */
static void
test_http_stall (void)
{
  struct cb c;
  struct srv s;
  int result = 0;
  size_t total = 48u * 1024u * 1024u;
  uint8_t *data = malloc (total);

  memset (data, 'z', total);
  memset (&c, 0, sizeof c);
  c.data = data;
  c.total = total;
  memset (&s, 0, sizeof s);
  s.stall_ms = 500;
  s.probe = &c.off;
  post (&c, (long long) total, &s, &result);
  check (result == TWIST_OK && s.counted == total,
         "a large upload arrives whole, whatever the connection took");
  check (s.read_ahead < total / 2,
         "and a server that does not read does not make the source read ahead");
  free (data);
}

static void
test_http_short (void)
{
  struct cb c;
  struct srv s;
  int result = 0;
  uint8_t *data = pattern (1000);

  memset (&s, 0, sizeof s);
  memset (&c, 0, sizeof c);
  c.data = data;
  c.total = 1000;
  c.stop_at = 500;
  post (&c, 1000, &s, &result);
  check (result == TWIST_ERR_ABORTED,
         "a source that ends before the length it was told fails the transfer");
  free (s.body);
  free (data);
}

/* POST the contents of a descriptor (TWISTOPT_READFD): a file, whose length
   is known, and a pipe, which is chunked.  The descriptor is not closed.  */
static void
test_http_readfd (void)
{
  char path[64];
  char opath[64];
  char reply[16] = { 0 };
  int ofd;
  size_t total = 200000;
  uint8_t *data = pattern (total);
  int fd;
  struct srv s;
  int result = 0;
  struct twist_runtime *runtime = twist_runtime_new ();
  struct twist_transfer *t = twist_transfer_new ();
  struct check_job job = { 0, 0, 0 };
  char url[64];

  snprintf (path, sizeof path, "/tmp/twist-test-upload-XXXXXX");
  fd = mkstemp (path);
  if (fd < 0 || write (fd, data, total) != (ssize_t) total
      || runtime == NULL || t == NULL)
    return;
  lseek (fd, 0, SEEK_SET);
  memset (&s, 0, sizeof s);
  if (srv_start (&s) != 0)
    return;
  pthread_create (&s.thread, NULL, srv_main, &s);
  snprintf (url, sizeof url, "http://127.0.0.1:%d/up", s.port);
  twist_transfer_setopt (t, TWISTOPT_URL, url);
  twist_transfer_setopt (t, TWISTOPT_CUSTOMREQUEST, "POST");
  twist_transfer_setopt (t, TWISTOPT_READFD, (long) fd);
  twist_transfer_setopt (t, TWISTOPT_INFILESIZE, (long long) total);
  /* And the reply goes to a file of its own, at its position.  */
  snprintf (opath, sizeof opath, "/tmp/twist-test-reply-XXXXXX");
  ofd = mkstemp (opath);
  (void) !write (ofd, "reply:", 6);
  twist_transfer_setopt (t, TWISTOPT_WRITEFD, (long) ofd);
  twist_runtime_start (runtime, t, check_job_done, &job);
  check_pump (runtime, &job, 8000);
  result = job.done ? job.result : -1;
  close (s.listen_fd);
  pthread_join (s.thread, NULL);
  check (result == TWIST_OK && s.body_n == total && !s.chunked
         && memcmp (s.body, data, total) == 0,
         "the contents of a file descriptor are uploaded");
  check (fcntl (fd, F_GETFD) != -1 && lseek (fd, 0, SEEK_CUR) == 0,
         "and the descriptor is neither closed nor moved");
  {
    FILE *fp = fopen (opath, "rb");

    if (fp != NULL)
      {
        size_t n = fread (reply, 1, sizeof reply - 1, fp);

        reply[n] = 0;
        fclose (fp);
      }
  }
  check (strcmp (reply, "reply:ok") == 0,
         "the reply is in the file given for it, written before the end");
  free (s.body);
  twist_runtime_free (runtime);
  twist_transfer_free (t);
  close (fd);
  close (ofd);
  unlink (path);
  unlink (opath);
  free (data);
}

/* An upload pushed from the thread that drives a runtime of several threads, to
   a transfer that runs on another: the bytes are queued and the transfer's own
   thread takes them, and the end is passed on.  */
static void
test_push_threads (void)
{
  struct twist_runtime *runtime = twist_runtime_new ();
  struct twist_transfer *t = twist_transfer_new ();
  struct check_job job = { 0, 0, 0 };
  struct srv s;
  char url[64];
  size_t total = 400000;
  uint8_t *data = pattern (total);
  size_t off = 0;
  int ended = 0;
  double end;
  struct timespec ts;

  memset (&s, 0, sizeof s);
  if (runtime == NULL || t == NULL
      || twist_runtime_setopt (runtime, TWIST_RUNTIMEOPT_THREADS, 2L) != TWIST_OK
      || srv_start (&s) != 0)
    return;
  pthread_create (&s.thread, NULL, srv_main, &s);
  snprintf (url, sizeof url, "http://127.0.0.1:%d/up", s.port);
  twist_transfer_setopt (t, TWISTOPT_URL, url);
  twist_transfer_setopt (t, TWISTOPT_CUSTOMREQUEST, "POST");
  twist_transfer_setopt (t, TWISTOPT_UPLOAD_PUSH, 1L);
  twist_transfer_setopt (t, TWISTOPT_INFILESIZE, (long long) total);
  runtime->rotate = 1;		/* Not the first lane, which is this thread's.  */
  twist_runtime_start (runtime, t, check_job_done, &job);
  check (twist_transfer_remote (t), "the transfer runs on a thread of its own");
  clock_gettime (CLOCK_MONOTONIC, &ts);
  end = (double) ts.tv_sec * 1000.0 + (double) ts.tv_nsec / 1e6 + 8000;
  while (!job.done)
    {
      size_t taken = 0;

      if (off < total)
        {
          int rc = twist_transfer_upload_push (t, data + off, total - off,
                                               &taken);

          if (rc == TWIST_OK || rc == TWIST_ERR_AGAIN)
            off += taken;
        }
      else if (!ended)
        {
          twist_transfer_upload_end (t, TWIST_OK);
          ended = 1;
        }
      twist_runtime_run_once (runtime, 1);
      clock_gettime (CLOCK_MONOTONIC, &ts);
      if ((double) ts.tv_sec * 1000.0 + (double) ts.tv_nsec / 1e6 > end)
        break;
    }
  if (!job.done)
    fprintf (stderr, "  pushed %zu of %zu, end %s\n", off, total,
             ended ? "pushed" : "not pushed");
  check (job.done && job.result == TWIST_OK, "the upload is done");
  close (s.listen_fd);
  pthread_join (s.thread, NULL);
  check (s.body_n == total && memcmp (s.body, data, total) == 0 && !s.chunked
         && s.clen == (long long) total,
         "and the server has all of it, in order, as pushed");
  free (s.body);
  twist_runtime_free (runtime);
  twist_transfer_free (t);
  free (data);
}

int
main (void)
{
  test_adapter ();
  test_adapter_abort ();
  test_detach ();
  test_read_pause ();
  test_push_api ();
  test_http_length ();
  test_http_chunked ();
  test_http_stall ();
  test_http_short ();
  test_http_readfd ();
  test_push_threads ();
  return tests_finish ();
}
