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

#ifndef TWIST_POLL_H
#define TWIST_POLL_H

struct twist_poll;

struct twist_poll_event
{
  int fd;
  int readable;
  int writable;
  int error;
};

struct twist_poll *twist_poll_open (void);
void twist_poll_close (struct twist_poll *poll);
int twist_poll_set (struct twist_poll *poll, int fd, int interest);
int twist_poll_wait (struct twist_poll *poll, struct twist_poll_event *ev,
                     int max, int timeout_ms);

#endif
