# Makefile for Twist
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

# Subdirectories to build
SUBDIRS = src doc tests

# Files to distribute
EXTRA_DIST = \
	README \
	AUTHORS \
	NEWS \
	ChangeLog \
	INSTALL \
	COPYING

# Clean files
DISTCLEANFILES = \
	config.status \
	config.cache \
	config.log \
	configure.lineno

# Maintainer targets
.PHONY: maintainer-clean-docs
maintainer-clean-docs:
	-rm -rf doc/*.aux doc/*.cp doc/*.cps doc/*.dvi \
		doc/*.fn doc/*.fns doc/*.ky doc/*.kys doc/*.log \
		doc/*.pg doc/*.pgs doc/*.toc doc/*.tp doc/*.vr

# Ensure the build-aux directory exists
$(srcdir)/build-aux:
	mkdir -p $@
