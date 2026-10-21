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

PKG_PROG_PKG_CONFIG
AS_IF([test -z "$PKG_CONFIG"],
  [AC_MSG_ERROR([pkg-config is required to find an installed quickstep])])
AC_ARG_WITH([quickstep],
  [AS_HELP_STRING([--with-quickstep=PREFIX],
     [installation prefix of quickstep])],
  [], [with_quickstep=yes])
AS_IF([test "x$with_quickstep" = xno],
  [AC_MSG_ERROR([quickstep is required])])
AS_IF([test "x$with_quickstep" != xyes],
  [tw_qs_pc=
   AS_IF([test -d "$with_quickstep/lib/pkgconfig"],
     [tw_qs_pc="$with_quickstep/lib/pkgconfig"])
   AS_IF([test -d "$with_quickstep/lib64/pkgconfig"],
     [tw_qs_pc="$with_quickstep/lib64/pkgconfig${tw_qs_pc:+:}$tw_qs_pc"])
   AS_IF([test -n "$tw_qs_pc"],
     [PKG_CONFIG_PATH="$tw_qs_pc${PKG_CONFIG_PATH:+:}$PKG_CONFIG_PATH"
      export PKG_CONFIG_PATH])])
PKG_CHECK_MODULES([QUICKSTEP], [quickstep], [],
  [AC_MSG_ERROR([quickstep is not installed.  pkg-config must see quickstep.pc])])

dnl foxtrot is the SSH engine under scp and sftp, installed beside quickstep.
dnl It needs libgcrypt 1.12.4 or later and refuses to start with an older
dnl one: before 1.12.3 a peer can make libgcrypt abort the process with an
dnl awkward Ed25519 key, and before 1.12.4 its ECDH does not check the peer's
dnl point.  The check is made three times because each fails differently:
dnl what pkg-config reports, the header the compiler finds first, and the
dnl library the loader gives a program (no RPATH is set, so that depends on
dnl the system's search order, and an older system copy can win).
AC_ARG_WITH([foxtrot],
  [AS_HELP_STRING([--with-foxtrot=PREFIX],
     [installation prefix of foxtrot])],
  [], [with_foxtrot=yes])
AS_IF([test "x$with_foxtrot" = xno],
  [AC_MSG_ERROR([foxtrot is required])])
AS_IF([test "x$with_foxtrot" != xyes],
  [tw_ft_pc=
   AS_IF([test -d "$with_foxtrot/lib/pkgconfig"],
     [tw_ft_pc="$with_foxtrot/lib/pkgconfig"])
   AS_IF([test -d "$with_foxtrot/lib64/pkgconfig"],
     [tw_ft_pc="$with_foxtrot/lib64/pkgconfig${tw_ft_pc:+:}$tw_ft_pc"])
   AS_IF([test -n "$tw_ft_pc"],
     [PKG_CONFIG_PATH="$tw_ft_pc${PKG_CONFIG_PATH:+:}$PKG_CONFIG_PATH"
      export PKG_CONFIG_PATH])])
PKG_CHECK_MODULES([FOXTROT], [foxtrot], [],
  [AC_MSG_ERROR([foxtrot is not installed.  pkg-config must see foxtrot.pc])])
PKG_CHECK_MODULES([LIBGCRYPT], [libgcrypt >= 1.12.4], [],
  [AC_MSG_ERROR([libgcrypt 1.12.4 or later is required by foxtrot.  Install it, for example under /usr/local, and make pkg-config see it])])
tw_save_CPPFLAGS=$CPPFLAGS
tw_save_LIBS=$LIBS
CPPFLAGS="$CPPFLAGS $LIBGCRYPT_CFLAGS"
LIBS="$LIBS $LIBGCRYPT_LIBS"
AC_MSG_CHECKING([that the libgcrypt header is 1.12.4 or later])
AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[#include <gcrypt.h>
#if GCRYPT_VERSION_NUMBER < 0x010c04
# error libgcrypt is older than 1.12.4
#endif
]], [[]])],
  [AC_MSG_RESULT([yes])],
  [AC_MSG_RESULT([no])
   AC_MSG_ERROR([the first gcrypt.h found is older than 1.12.4.  An older copy in /usr/include is ahead of the one pkg-config reports])])
AC_MSG_CHECKING([that the libgcrypt the loader finds is 1.12.4 or later])
AC_RUN_IFELSE([AC_LANG_PROGRAM([[#include <gcrypt.h>]],
  [[return gcry_check_version ("1.12.4") == NULL;]])],
  [AC_MSG_RESULT([yes])],
  [AC_MSG_RESULT([no])
   AC_MSG_ERROR([a program linked with libgcrypt loads a version older than 1.12.4 here.  The system's copy is found before the new one: put the new libdir ahead of it in /etc/ld.so.conf.d and run ldconfig, or remove the old copy from the search path])],
  [AC_MSG_RESULT([cross compiling, not checked])])
CPPFLAGS=$tw_save_CPPFLAGS
LIBS=$tw_save_LIBS

AC_CHECK_HEADER([zlib.h], [], [AC_MSG_ERROR([zlib.h is required])])
tw_save_LIBS=$LIBS
AC_CHECK_LIB([z], [inflate],
  [ZLIB_LIBS="-lz"],
  [AC_MSG_ERROR([zlib is required])])
LIBS=$tw_save_LIBS
AC_SUBST([ZLIB_LIBS])

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
                 fuzz/Makefile
                 twist.pc])
AC_OUTPUT
