/* twist.c - Twist HTTP client main source

   Copyright (C) 2026 Chris Burdess

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

#include "twist.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Main entry point */
int
main(int argc, char *argv[])
{
    (void)argc;
    (void)argv;

    /* TODO: Implement curl-compatible HTTP client */
    /* Using quickstep from ../quickstep for QUIC and TLS */
    /* Using GNU readline for interactive input */

    printf("Twist - HTTP client (skeleton)\n");
    printf("Using quickstep library for QUIC/TLS\n");
    printf("Using GNU readline\n");

    return EXIT_SUCCESS;
}
