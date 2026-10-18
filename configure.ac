dnl Process this file with autoconf to produce a configure script.
dnl
dnl Copyright (C) 2026 Chris Burdess <dog@gnu.org>
dnl
dnl This file is part of twist.
dnl
dnl twist is free software: you can redistribute it and/or modify it
dnl under the terms of the GNU General Public License as published
dnl by the Free Software Foundation, either version 3 of the License, or
dnl (at your option) any later version.
dnl
dnl twist is distributed in the hope that it will be useful, but
dnl WITHOUT ANY WARRANTY; without even the implied warranty of
dnl MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
dnl General Public License for more details.
dnl
dnl You should have received a copy of the GNU General Public
dnl License along with this program.  If not, see
dnl <https://www.gnu.org/licenses/>.

AC_PREREQ([2.71])
AC_INIT([twist], [0.1], [dog@gnu.org], [twist],
        [https://www.gnu.org/software/twist/])
AC_CONFIG_SRCDIR([src/util.c])
AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_MACRO_DIRS([m4])
AC_CONFIG_HEADERS([config.h])

AM_INIT_AUTOMAKE([1.16 -Wall -Werror subdir-objects
                  color-tests parallel-tests])
AM_SILENT_RULES([yes])

AC_PROG_CC
AC_USE_SYSTEM_EXTENSIONS

AC_MSG_CHECKING([whether $CC supports -std=c99])
tw_save_CFLAGS=$CFLAGS
CFLAGS="$CFLAGS -std=c99"
AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[
#if !defined __STDC_VERSION__ || __STDC_VERSION__ != 199901L
# error not C99
#endif
]])],
  [AC_MSG_RESULT([yes])],
  [AC_MSG_RESULT([no])
   AC_MSG_ERROR([a C99 compiler is required])])
CFLAGS=$tw_save_CFLAGS
STD_CFLAGS=-std=c99
AC_SUBST([STD_CFLAGS])
AM_PROG_AR
LT_INIT([win32-dll])

LIBTWIST_LTVERSION=0:0:0
AC_SUBST([LIBTWIST_LTVERSION])

AM_GNU_GETTEXT([external])
AM_GNU_GETTEXT_VERSION([0.21])

AC_ARG_WITH([quickstep],
  [AS_HELP_STRING([--with-quickstep=DIR],
     [quickstep source or build tree @<:@default=../quickstep@:>@])],
  [quickstep_path="$withval"],
  [quickstep_path="$srcdir/../quickstep"])
AS_IF([test -f "$quickstep_path/src/libquickstep.la"],
  [QUICKSTEP_CFLAGS="-I$quickstep_path/include"
   QUICKSTEP_LIBS="$quickstep_path/src/libquickstep.la"],
  [AC_MSG_ERROR([libquickstep.la not found under $quickstep_path; build quickstep first])])
AC_SUBST([QUICKSTEP_CFLAGS])
AC_SUBST([QUICKSTEP_LIBS])

AC_ARG_WITH([readline],
  [AS_HELP_STRING([--with-readline],
     [link the twist program with GNU Readline @<:@default=check@:>@])],
  [], [with_readline=check])
READLINE_LIBS=
AS_IF([test "x$with_readline" != xno],
  [AC_CHECK_LIB([readline], [readline],
     [READLINE_LIBS="-lreadline"
      AC_DEFINE([HAVE_READLINE], [1], [Define if GNU Readline is available])],
     [AS_IF([test "x$with_readline" = xyes],
        [AC_MSG_ERROR([GNU Readline not found])])])])
AC_SUBST([READLINE_LIBS])

AC_CHECK_HEADERS([sys/eventfd.h sys/epoll.h sys/event.h])
AC_CHECK_FUNCS([pipe2])

AC_ARG_ENABLE([warnings],
  [AS_HELP_STRING([--disable-warnings], [do not add extra compiler warnings])],
  [], [enable_warnings=yes])
WARN_CFLAGS=
AS_IF([test "x$enable_warnings" = xyes],
  [for flag in -Wall -Wextra -Wshadow -Wpointer-arith -Wstrict-prototypes \
               -Wmissing-prototypes -Wcast-qual -Wwrite-strings \
               -Wformat=2 -Wundef -pedantic; do
     TW_CHECK_CFLAG([$flag])
   done])
AC_SUBST([WARN_CFLAGS])

AC_CONFIG_FILES([Makefile
                 src/Makefile
                 po/Makefile.in
                 doc/Makefile
                 tests/Makefile
                 integration/Makefile
                 twist.pc])
AC_OUTPUT
