# Makefile for Twist source directory
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

# The program to build
bin_PROGRAMS = twist

# Source files
twist_SOURCES = \
	twist.c \
	twist.h

# Compilation flags
twist_CPPFLAGS = -I$(top_srcdir)/src
AM_CFLAGS = -Wall -Wextra -Werror -pedantic $(twist_CPPFLAGS)

# Version info
twist_VERSION = 0.1

# Define the package name and version
AM_CPPFLAGS = \
	-DPACKAGE_NAME="\"@PACKAGE_NAME@\"" \
	-DPACKAGE_VERSION="\"@PACKAGE_VERSION@\"" \
	-DPACKAGE_BUGREPORT="\"@PACKAGE_BUGREPORT@\"" \
	-DPACKAGE_URL="\"@PACKAGE_URL@\""

# Installation directories
bindir = @bindir@

# Manual pages
man_MANS = twist.1

# Clean files
CLEANFILES = *~ core
DISTCLEANFILES = Makefile.in
