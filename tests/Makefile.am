# Makefile for Twist tests directory
#
# Copyright (C) 2026 Chris
#
# This file is part of Twist.
#
# Twist is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Twist is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Twist.  If not, see <https://www.gnu.org/licenses/>.

# Test programs
check_PROGRAMS = test-twist

# Source files for test programs
test_twist_SOURCES = test-twist.c

# Compilation flags
test_twist_CPPFLAGS = -I$(top_srcdir)/src
AM_CFLAGS = -Wall -Wextra -Werror -pedantic $(test_twist_CPPFLAGS)

# Test suite
TESTS = $(check_PROGRAMS)
TESTS_ENVIRONMENT = \
	SRCDIR=$(srcdir); \
	export SRCDIR; \
	TOP_SRCDIR=$(top_srcdir); \
	export TOP_SRCDIR

# Clean files
CLEANFILES = *~ core
DISTCLEANFILES = Makefile.in
