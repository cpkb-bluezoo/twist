# Makefile for Twist
#
# Copyright (C) 2026 Chris Burdess
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

# Subdirectories (none for skeleton)
SUBDIRS =

# The program to build
bin_PROGRAMS = twist

# Source files
twist_SOURCES = src/twist.c src/twist.h

# Compilation flags
twist_CPPFLAGS = -I$(top_srcdir)/src
AM_CFLAGS = -Wall -Wextra -Werror -pedantic -std=c11 $(twist_CPPFLAGS)

# Version info
twist_VERSION = 0.1

# Define package name and version
AM_CPPFLAGS = \
	-DPACKAGE_NAME="\"twist\"" \
	-DPACKAGE_VERSION="\"0.1\"" \
	-DPACKAGE_BUGREPORT="\"dog@gnu.org\""

# Installation directories
bindir = @bindir@

# Files to distribute
EXTRA_DIST = \
	README \
	AUTHORS \
	NEWS \
	ChangeLog \
	INSTALL \
	HACKING \
	THANKS \
	TODO \
	COPYING \
	bootstrap \
	config.h.in

# Clean files
DISTCLEANFILES = \
	config.status \
	config.cache \
	config.log \
	configure.lineno
