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

#include "poll.h"
#include "twist-int.h"

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#if defined __linux__
# include <sys/epoll.h>
# define TWIST_POLL_EPOLL 1
#elif defined __APPLE__ || defined __FreeBSD__ || defined __NetBSD__ \
  || defined __OpenBSD__ || defined __DragonFly__
# include <sys/event.h>
# include <sys/time.h>
# define TWIST_POLL_KQUEUE 1
#endif

struct twist_poll
{
  int fd;
};

struct twist_poll *
twist_poll_open (void)
{
  struct twist_poll *p;

  p = calloc (1, sizeof *p);
  if (p == NULL)
    return NULL;
#if defined TWIST_POLL_EPOLL
  p->fd = epoll_create1 (EPOLL_CLOEXEC);
#elif defined TWIST_POLL_KQUEUE
  p->fd = kqueue ();
  if (p->fd >= 0 && fcntl (p->fd, F_SETFD, FD_CLOEXEC) < 0)
    {
      close (p->fd);
      p->fd = -1;
    }
#else
  p->fd = -1;
#endif
  if (p->fd < 0)
    {
      free (p);
      return NULL;
    }
  return p;
}

void
twist_poll_close (struct twist_poll *p)
{
  if (p == NULL)
    return;
  if (p->fd >= 0)
    close (p->fd);
  free (p);
}

int
twist_poll_set (struct twist_poll *p, int fd, int interest, void *ptr)
{
#if defined TWIST_POLL_EPOLL
  struct epoll_event ev;
  int op;
  int rc;

  memset (&ev, 0, sizeof ev);
  ev.data.ptr = ptr;
  if (interest & TWIST_INTEREST_READ)
    ev.events |= EPOLLIN;
  if (interest & TWIST_INTEREST_WRITE)
    ev.events |= EPOLLOUT;
  if (interest == 0)
    {
      rc = epoll_ctl (p->fd, EPOLL_CTL_DEL, fd, &ev);
      if (rc < 0 && errno == ENOENT)
        return 0;
      return rc < 0 ? TWIST_ERR_CONNECT : TWIST_OK;
    }
  op = EPOLL_CTL_MOD;
  rc = epoll_ctl (p->fd, op, fd, &ev);
  if (rc < 0 && errno == ENOENT)
    rc = epoll_ctl (p->fd, EPOLL_CTL_ADD, fd, &ev);
  if (rc < 0 && (errno == EMFILE || errno == ENFILE))
    return TWIST_ERR_AGAIN;
  return rc < 0 ? TWIST_ERR_CONNECT : TWIST_OK;
#elif defined TWIST_POLL_KQUEUE
  struct kevent ev[2];
  int n = 0;
  unsigned short rflags;
  unsigned short wflags;

  rflags = (interest & TWIST_INTEREST_READ) ? EV_ADD : EV_DELETE;
  wflags = (interest & TWIST_INTEREST_WRITE) ? EV_ADD : EV_DELETE;
  EV_SET (&ev[n], fd, EVFILT_READ, rflags, 0, 0, ptr);
  n++;
  EV_SET (&ev[n], fd, EVFILT_WRITE, wflags, 0, 0, ptr);
  n++;
  if (kevent (p->fd, ev, n, NULL, 0, NULL) < 0)
    {
      int i;

      /* Taking away a filter that was never there is ENOENT, and it fails the
         whole call, including the filter that was to be added: a descriptor
         new to the queue that is wanted for reading only is that.  Do the
         changes one at a time, and let a delete of nothing be.  */
      if (errno != ENOENT)
        return TWIST_ERR_CONNECT;
      for (i = 0; i < n; i++)
        if (kevent (p->fd, &ev[i], 1, NULL, 0, NULL) < 0
            && !(ev[i].flags == EV_DELETE && errno == ENOENT))
          return TWIST_ERR_CONNECT;
    }
  return TWIST_OK;
#else
  (void) p;
  (void) fd;
  (void) interest;
  (void) ptr;
  return TWIST_ERR_UNSUPPORTED;
#endif
}

int
twist_poll_wait (struct twist_poll *p, struct twist_poll_event *ev, int max,
                 int timeout_ms)
{
#if defined TWIST_POLL_EPOLL
  struct epoll_event buf[TWIST_POLL_BATCH];
  int n;
  int i;
  int cap = max;

  if (cap > TWIST_POLL_BATCH)
    cap = TWIST_POLL_BATCH;
  if (cap < 1)
    cap = 1;
  n = epoll_wait (p->fd, buf, cap, timeout_ms);
  if (n < 0)
    {
      if (errno == EINTR)
        return 0;
      return -1;
    }
  for (i = 0; i < n; i++)
    {
      ev[i].fd = buf[i].data.fd;
      ev[i].ptr = buf[i].data.ptr;
      ev[i].readable = (buf[i].events & (EPOLLIN | EPOLLERR | EPOLLHUP)) != 0;
      ev[i].writable = (buf[i].events & EPOLLOUT) != 0;
      ev[i].error = (buf[i].events & (EPOLLERR | EPOLLHUP)) != 0;
    }
  return n;
#elif defined TWIST_POLL_KQUEUE
  struct kevent buf[TWIST_POLL_BATCH];
  struct timespec ts;
  struct timespec *tsp;
  int n;
  int i;
  int cap = max;

  if (cap > TWIST_POLL_BATCH)
    cap = TWIST_POLL_BATCH;
  if (cap < 1)
    cap = 1;
  if (timeout_ms < 0)
    tsp = NULL;
  else
    {
      ts.tv_sec = timeout_ms / 1000;
      ts.tv_nsec = (long) (timeout_ms % 1000) * 1000000L;
      tsp = &ts;
    }
  n = kevent (p->fd, NULL, 0, buf, cap, tsp);
  if (n < 0)
    {
      if (errno == EINTR)
        return 0;
      return -1;
    }
  for (i = 0; i < n; i++)
    {
      ev[i].fd = (int) buf[i].ident;
      ev[i].ptr = buf[i].udata;
      ev[i].readable = buf[i].filter == EVFILT_READ;
      ev[i].writable = buf[i].filter == EVFILT_WRITE;
      ev[i].error = (buf[i].flags & EV_ERROR) != 0;
    }
  return n;
#else
  (void) p;
  (void) ev;
  (void) max;
  (void) timeout_ms;
  return -1;
#endif
}
