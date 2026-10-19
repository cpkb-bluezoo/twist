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

#ifndef TWIST_TEST_FEED_H
#define TWIST_TEST_FEED_H

#include <stddef.h>
#include <stdint.h>

void feed_n (size_t (*recv) (void *, const uint8_t *, size_t), void *obj,
             const char *text, size_t split);
void feed_bin (size_t (*recv) (void *, const uint8_t *, size_t), void *obj,
               const uint8_t *data, size_t n, size_t split);
int has_bytes (const uint8_t *hay, size_t n, const void *needle, size_t m);

#endif
