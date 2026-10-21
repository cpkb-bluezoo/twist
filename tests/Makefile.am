## Copyright (C) 2026 Chris Burdess <dog@gnu.org>
##
## This file is part of twist.
##
## In-process unit tests, one program per subsystem.  These are the only
## tests 'make check' runs.  Peers on the network live in ../integration
## and are started with 'make check-integration'.

AM_CPPFLAGS = -I$(top_srcdir)/include -I$(top_srcdir)/src $(QUICKSTEP_CFLAGS) \
	$(FOXTROT_CFLAGS)
AM_CFLAGS = $(STD_CFLAGS) $(WARN_CFLAGS)

LDADD = $(top_builddir)/src/libtwist.la $(ZLIB_LIBS)

## quickstep and foxtrot are installed, and the dynamic linker may not search
## their libdirs.  The libtool wrappers only add the uninstalled libtwist.
AM_TESTS_ENVIRONMENT = \
	LD_LIBRARY_PATH="`$(PKG_CONFIG) --variable=libdir quickstep`:`$(PKG_CONFIG) --variable=libdir foxtrot`:$$LD_LIBRARY_PATH"; \
	export LD_LIBRARY_PATH;

noinst_HEADERS = check.h http-ev.h feed.h body.h

PROGRAM_TESTS = test-reactor test-engine test-http test-auth test-dns \
	test-ftp test-mail test-mqtt test-ldap test-ws test-gopher test-dict \
	test-tftp test-file test-tls test-errors test-coding test-ssh \
	test-quote test-rate test-glob
## The tool itself, on local files.
SCRIPT_TESTS = cli-glob.sh
TESTS = $(PROGRAM_TESTS) $(SCRIPT_TESTS)
check_PROGRAMS = $(PROGRAM_TESTS)
EXTRA_DIST = cli-glob.sh

test_reactor_SOURCES = test-reactor.c check.c
test_engine_SOURCES = test-engine.c check.c
test_http_SOURCES = test-http.c check.c http-ev.c
test_auth_SOURCES = test-auth.c check.c
test_dns_SOURCES = test-dns.c check.c
test_ftp_SOURCES = test-ftp.c check.c
test_mail_SOURCES = test-mail.c check.c feed.c body.c
test_mqtt_SOURCES = test-mqtt.c check.c feed.c body.c
test_ldap_SOURCES = test-ldap.c check.c feed.c body.c
test_ws_SOURCES = test-ws.c check.c feed.c body.c http-ev.c
test_gopher_SOURCES = test-gopher.c check.c feed.c body.c
test_dict_SOURCES = test-dict.c check.c feed.c body.c
test_tftp_SOURCES = test-tftp.c check.c body.c
test_file_SOURCES = test-file.c check.c
test_tls_SOURCES = test-tls.c check.c
test_errors_SOURCES = test-errors.c check.c
test_coding_SOURCES = test-coding.c
test_ssh_SOURCES = test-ssh.c check.c
test_ssh_LDADD = $(LDADD) $(FOXTROT_LIBS)
test_glob_SOURCES = test-glob.c check.c
test_rate_SOURCES = test-rate.c check.c
test_quote_SOURCES = test-quote.c check.c
test_quote_LDADD = $(LDADD) $(FOXTROT_LIBS)
