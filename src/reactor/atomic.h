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

/* Cancel flags and the command-queue handoff.  __atomic is available
   to a C99 translation unit; <stdatomic.h> is not used.  */

#ifndef TWIST_ATOMIC_H
#define TWIST_ATOMIC_H

typedef int twist_atomic_int;

#define twist_atomic_store(p, v) \
  __atomic_store_n ((p), (v), __ATOMIC_RELEASE)
#define twist_atomic_load(p) __atomic_load_n ((p), __ATOMIC_ACQUIRE)

#endif /* TWIST_ATOMIC_H */
