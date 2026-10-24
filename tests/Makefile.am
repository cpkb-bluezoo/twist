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

PROGRAM_TESTS = test-reactor test-engine test-http test-auth test-dns test-resolve \
	test-ftp test-mail test-mqtt test-ldap test-ws test-gopher test-rtsp test-dict test-telnet \
	test-tftp test-file test-tls test-errors test-coding test-ssh \
	test-quote test-rate test-glob test-vars test-progress test-bar test-meter test-origin test-runtime-threads test-proxyenv test-env test-template test-masque test-threads
## The tool itself, on local files.
SCRIPT_TESTS = cli-glob.sh cli-vars.sh cli-progress.sh cli-misc.sh cli-parallel.sh cli-output.sh cli-negate.sh
TESTS = $(PROGRAM_TESTS) $(SCRIPT_TESTS)
check_PROGRAMS = $(PROGRAM_TESTS)
EXTRA_DIST = cli-glob.sh cli-vars.sh cli-progress.sh cli-misc.sh cli-parallel.sh cli-output.sh cli-negate.sh

test_reactor_SOURCES = test-reactor.c check.c
test_engine_SOURCES = test-engine.c check.c
test_http_SOURCES = test-http.c check.c http-ev.c
test_auth_SOURCES = test-auth.c check.c
test_dns_SOURCES = test-dns.c check.c
test_resolve_SOURCES = test-resolve.c check.c
test_ftp_SOURCES = test-ftp.c check.c
test_mail_SOURCES = test-mail.c check.c feed.c body.c
test_mqtt_SOURCES = test-mqtt.c check.c feed.c body.c
test_ldap_SOURCES = test-ldap.c check.c feed.c body.c
test_ws_SOURCES = test-ws.c check.c feed.c body.c http-ev.c
test_gopher_SOURCES = test-gopher.c check.c feed.c body.c
test_rtsp_SOURCES = test-rtsp.c check.c feed.c body.c
test_dict_SOURCES = test-dict.c check.c feed.c body.c
test_telnet_SOURCES = test-telnet.c check.c feed.c
test_tftp_SOURCES = test-tftp.c check.c body.c
test_file_SOURCES = test-file.c check.c
test_tls_SOURCES = test-tls.c check.c
test_tls_LDADD = $(LDADD) $(QUICKSTEP_LIBS)
test_errors_SOURCES = test-errors.c check.c
test_coding_SOURCES = test-coding.c
test_ssh_SOURCES = test-ssh.c check.c
test_ssh_LDADD = $(LDADD) $(FOXTROT_LIBS)
test_glob_SOURCES = test-glob.c check.c
test_vars_SOURCES = test-vars.c check.c
test_rate_SOURCES = test-rate.c check.c
test_progress_SOURCES = test-progress.c check.c
test_proxyenv_SOURCES = test-proxyenv.c check.c
test_env_SOURCES = test-env.c check.c
test_template_SOURCES = test-template.c check.c
test_masque_SOURCES = test-masque.c check.c
test_threads_SOURCES = test-threads.c check.c
test_origin_SOURCES = test-origin.c check.c
test_runtime_threads_SOURCES = test-runtime-threads.c check.c
test_runtime_threads_LDADD = $(LDADD) -lpthread
test_origin_LDADD = $(LDADD) -lpthread
test_threads_LDADD = $(LDADD) -ldl
test_env_LDADD = $(LDADD) $(QUICKSTEP_LIBS)
test_bar_SOURCES = test-bar.c check.c ../src/bar.c
test_bar_CPPFLAGS = $(AM_CPPFLAGS)
test_bar_LDADD = $(LDADD) $(LIBM)
test_meter_SOURCES = test-meter.c check.c ../src/meter.c
test_meter_CPPFLAGS = $(AM_CPPFLAGS)
test_quote_SOURCES = test-quote.c check.c
test_quote_LDADD = $(LDADD) $(FOXTROT_LIBS)
