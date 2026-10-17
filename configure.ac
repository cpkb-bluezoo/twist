# Process this file with autoconf to produce a configure script.
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

# Initialize autoconf
AC_PREREQ([2.71])
AC_INIT([twist], [0.1], [dog@gnu.org], [twist])
AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_SRCDIR([src/twist.c])
AM_INIT_AUTOMAKE([-Wall -Werror foreign])

# Set package information
AC_SUBST([PACKAGE_VERSION], [0.1])
AC_SUBST([PACKAGE_BUGREPORT], [dog@gnu.org])
AC_SUBST([PACKAGE_URL], [])

# Check for programs
AC_PROG_CC
AM_PROG_CC_C_O
AC_PROG_INSTALL
AC_PROG_MAKE_SET
AC_PROG_MKDIR_P

# Set default prefix
AC_PREFIX_DEFAULT([/usr/local])

# Check for headers
AC_CHECK_HEADERS([stdlib.h string.h unistd.h stdio.h stdarg.h stddef.h stdint.h inttypes.h])

# Check for types
AC_CHECK_TYPES([struct sockaddr_storage, struct addrinfo])

# Check for functions
AC_CHECK_FUNCS([malloc realloc free memset memcpy memmove strdup strerror getaddrinfo getnameinfo freeaddrinfo socket connect bind listen accept send recv select poll getsockopt setsockopt shutdown])

# Check for large file support
AC_SYS_LARGEFILE

# Check for thread support
ACX_PTHREAD([
    AC_DEFINE([HAVE_PTHREAD], [1], [Define if pthreads are available])
], [])

# Check for IPv6 support
AC_CHECK_IPV6

# Check for quickstep library (QUIC and TLS)
AC_ARG_WITH([quickstep],
    [AS_HELP_STRING([--with-quickstep=PATH], [use quickstep from PATH])],
    [quickstep_path="$withval"],
    [quickstep_path="../quickstep"])

# Check if quickstep source exists
if test -d "$quickstep_path"; then
    # Use the source directory directly
    CPPFLAGS="$CPPFLAGS -I$quickstep_path/include"
    AC_DEFINE([HAVE_QUICKSTEP], [1], [Define if quickstep is available])
    AC_MSG_NOTICE([Using quickstep from $quickstep_path for QUIC and TLS])
else
    AC_MSG_ERROR([quickstep library not found at $quickstep_path. Please provide the path with --with-quickstep or place it at ../quickstep])
fi

# Check for GNU readline
AC_ARG_WITH([readline],
    [AS_HELP_STRING([--with-readline=PATH], [use GNU readline from PATH])],
    [readline_path="$withval"],
    [readline_path=""])

if test -n "$readline_path"; then
    CPPFLAGS="$CPPFLAGS -I$readline_path/include"
    LDFLAGS="$LDFLAGS -L$readline_path/lib"
    LIBS="$LIBS -lreadline"
else
    # Try to find readline in standard locations
    AC_CHECK_LIB([readline], [readline], [have_readline=yes], [have_readline=no], [-lreadline])
    if test "$have_readline" = yes; then
        LIBS="$LIBS -lreadline"
        AC_DEFINE([HAVE_READLINE], [1], [Define if readline is available])
    else
        AC_MSG_ERROR([GNU readline not found. Please install it or provide the path with --with-readline])
    fi
fi

# Configure files
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_FILES([
 Makefile
 src/Makefile
])
AC_OUTPUT

# Print configuration summary
echo ""
echo "Twist v$PACKAGE_VERSION has been configured successfully."
echo ""
echo "Configuration summary:"
echo "  Prefix:        $prefix"
echo "  Quickstep:    $quickstep_path"
echo "  Readline:     $readline_path"
echo ""
echo "Type 'make' to compile the package."
echo "Type 'make install' to install the package."
echo ""
