## Copyright (C) 2026 Chris Burdess <dog@gnu.org>
##
## This file is part of twist.
##
## Network tests.  Not part of 'make check'.  Run 'make check-integration'
## from the top directory.  A missing peer skips with exit 77.

## quickstep and foxtrot are installed, and the dynamic linker may not search
## their libdirs.  The libtool wrapper only adds the uninstalled libtwist.
AM_TESTS_ENVIRONMENT = \
	LD_LIBRARY_PATH="`$(PKG_CONFIG) --variable=libdir quickstep`:`$(PKG_CONFIG) --variable=libdir foxtrot`:$$LD_LIBRARY_PATH"; \
	export LD_LIBRARY_PATH;

TESTS = skip-network.sh ssh-openssh.sh http-progress.sh env.sh
check_SCRIPTS = skip-network.sh ssh-openssh.sh http-progress.sh env.sh

EXTRA_DIST = skip-network.sh ssh-openssh.sh http-progress.sh env.sh proxy-peer.py
