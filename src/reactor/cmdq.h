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

#ifndef TWIST_CMDQ_H
#define TWIST_CMDQ_H

struct twist_cmdq;

struct twist_cmdq *twist_cmdq_new (void);
void twist_cmdq_free (struct twist_cmdq *q);
int twist_cmdq_push (struct twist_cmdq *q, void (*fn) (void *), void *user);
void twist_cmdq_drain (struct twist_cmdq *q);

#endif
