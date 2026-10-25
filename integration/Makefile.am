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

TESTS = skip-network.sh ssh-openssh.sh http-progress.sh env.sh proxy-https.sh ftps.sh http-request.sh ftp.sh http-unix.sh starttls.sh telnet.sh rtsp.sh http-status.sh http-negate.sh connect-timeout.sh redirect.sh hosts.sh output-file.sh http3-zone.sh limit-rate.sh proxy-auth.sh large-post.sh large-mail.sh large-put.sh large-put-h2.sh large-ws.sh tftp-put.sh ftp-put.sh imap-append.sh upload-glob.sh
check_SCRIPTS = skip-network.sh ssh-openssh.sh http-progress.sh env.sh proxy-https.sh ftps.sh http-request.sh ftp.sh http-unix.sh starttls.sh telnet.sh rtsp.sh http-status.sh http-negate.sh connect-timeout.sh redirect.sh hosts.sh output-file.sh http3-zone.sh limit-rate.sh proxy-auth.sh large-post.sh large-mail.sh large-put.sh large-put-h2.sh large-ws.sh tftp-put.sh ftp-put.sh imap-append.sh upload-glob.sh

EXTRA_DIST = skip-network.sh ssh-openssh.sh http-progress.sh env.sh proxy-https.sh https-proxy.js proxy-peer.py ftps.sh http-request.sh ftp.sh http-unix.sh starttls.sh telnet.sh rtsp.sh http-status.sh http-negate.sh connect-timeout.sh redirect.sh hosts.sh output-file.sh http3-zone.sh limit-rate.sh proxy-auth.sh large-post.sh large-mail.sh large-put.sh large-put-h2.sh large-ws.sh tftp-put.sh ftp-put.sh imap-append.sh upload-glob.sh
