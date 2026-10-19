## Process this file with automake to produce Makefile.in
##
## Copyright (C) 2026 Chris Burdess <dog@gnu.org>
##
## This file is part of twist.
##
## twist is free software: you can redistribute it and/or modify it
## under the terms of the GNU General Public License as published
## by the Free Software Foundation, either version 3 of the License, or
## (at your option) any later version.
##
## twist is distributed in the hope that it will be useful, but
## WITHOUT ANY WARRANTY; without even the implied warranty of
## MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
## General Public License for more details.
##
## You should have received a copy of the GNU General Public
## License along with this program.  If not, see
## <https://www.gnu.org/licenses/>.

ACLOCAL_AMFLAGS = -I m4
SUBDIRS = po src doc tests
DIST_SUBDIRS = $(SUBDIRS) integration

include_HEADERS = include/twist.h

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = twist.pc

EXTRA_DIST = HACKING ARCHITECTURE.md TODO build-aux/config.rpath

.PHONY: check-integration
check-integration:
	cd integration && $(MAKE) $(AM_MAKEFLAGS) check
