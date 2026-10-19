## Copyright (C) 2026 Chris Burdess <dog@gnu.org>
##
## This file is part of twist.

AM_CPPFLAGS = -I$(top_srcdir)/include -I$(top_srcdir)/src $(QUICKSTEP_CFLAGS)
AM_CFLAGS = $(STD_CFLAGS) $(WARN_CFLAGS)

LDADD = $(top_builddir)/src/libtwist.la $(ZLIB_LIBS)

TESTS = test-unit test-coding
check_PROGRAMS = test-unit test-coding

test_unit_SOURCES = test-unit.c
test_coding_SOURCES = test-coding.c
