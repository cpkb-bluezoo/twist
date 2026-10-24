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

#ifndef TWIST_TIMER_H
#define TWIST_TIMER_H

#include "twist-int.h"

struct twist_timer_heap;

struct twist_timer_heap *twist_timer_heap_new (void);
void twist_timer_heap_free (struct twist_timer_heap *heap);
int twist_timer_heap_push (struct twist_timer_heap *heap, uint64_t deadline,
                           void (*cb) (void *), void *user,
                           struct twist_timer **out);
uint64_t twist_timer_heap_deadline (struct twist_timer_heap *heap);
/* Run the timers that are due at NOW.  Returns how many ran.  */
int twist_timer_heap_fire (struct twist_timer_heap *heap, uint64_t now);

#endif
