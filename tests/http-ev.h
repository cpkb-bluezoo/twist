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

#ifndef TWIST_TEST_HTTP_EV_H
#define TWIST_TEST_HTTP_EV_H

#include "twist-int.h"

extern int saw_status;
extern int saw_done;
extern char body[64];
extern size_t body_len;
extern size_t body_total;
extern int slice_ok;
extern char hdr_name[64];
extern char hdr_value[64];

void reset_ev (void);
struct twist_h1_events test_events (void);
void feed_all (size_t (*recv) (void *, const uint8_t *, size_t), void *obj,
               const uint8_t *data, size_t len, size_t chunk);
void feed_remain (size_t (*recv) (void *, const uint8_t *, size_t), void *obj,
                  const uint8_t *data, size_t len, size_t chunk);
size_t h1_recv (void *obj, const uint8_t *data, size_t len);
size_t h2_recv (void *obj, const uint8_t *data, size_t len);
size_t h3_recv (void *obj, const uint8_t *data, size_t len);

#endif
