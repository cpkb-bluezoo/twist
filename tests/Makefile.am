## Copyright (C) 2026 Chris Burdess <dog@gnu.org>
##
## This file is part of twist.
##
## In-process unit tests, one program per subsystem.  These are the only
## tests 'make check' runs.  Peers on the network live in ../integration
## and are started with 'make check-integration'.

AM_CPPFLAGS = -I$(top_srcdir)/include -I$(top_srcdir)/src $(QUICKSTEP_CFLAGS)
AM_CFLAGS = $(STD_CFLAGS) $(WARN_CFLAGS)

LDADD = $(top_builddir)/src/libtwist.la $(ZLIB_LIBS)

## quickstep is installed, and the dynamic linker may not search its
## libdir.  The libtool wrappers only add the uninstalled libtwist.
AM_TESTS_ENVIRONMENT = \
	LD_LIBRARY_PATH="`$(PKG_CONFIG) --variable=libdir quickstep`:$$LD_LIBRARY_PATH"; \
	export LD_LIBRARY_PATH;

noinst_HEADERS = check.h http-ev.h feed.h body.h

TESTS = test-reactor test-engine test-http test-auth test-dns test-ftp \
	test-mail test-mqtt test-ldap test-ws test-gopher test-dict \
	test-tftp test-file test-tls test-errors test-coding
check_PROGRAMS = $(TESTS)

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
