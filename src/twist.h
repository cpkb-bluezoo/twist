/* twist.h - Header file for Twist

   Copyright (C) 2026 Chris

   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

#ifndef TWIST_H
#define TWIST_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Program version */
#define TWIST_VERSION PACKAGE_VERSION

/* Exit codes */
#define TWIST_EXIT_SUCCESS 0
#define TWIST_EXIT_FAILURE 1

/* Function declarations */
void twist_print_version(void);
void twist_print_help(void);
int twist_process_file(const char *filename);

#endif /* TWIST_H */
