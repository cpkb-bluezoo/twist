# Process this file with autoconf to produce a configure script.
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

# Initialize autoconf
AC_PREREQ([2.71])
AC_INIT([twist], [0.1], [chris@localhost])
AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_SRCDIR([src/twist.c])
AM_INIT_AUTOMAKE([-Wall -Werror foreign])

# Specify the package version number
AC_SUBST([PACKAGE_VERSION], [0.1])

# Check for programs
AC_PROG_CC
AM_PROG_CC_C_O
AC_PROG_INSTALL
AC_PROG_MAKE_SET

# Set the default installation directories
AC_PREFIX_DEFAULT([/usr/local])

# Check for headers
AC_CHECK_HEADERS([stdlib.h string.h unistd.h])

# Check for functions
AC_CHECK_FUNCS([malloc realloc free])

# Configure files
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_FILES([
 Makefile
 src/Makefile
 doc/Makefile
 tests/Makefile
])
AC_OUTPUT

# Print configuration summary
echo ""
echo "Twist v$PACKAGE_VERSION has been configured successfully."
echo ""
echo "Type 'make' to compile the package."
echo "Type 'make install' to install the package."
echo ""
