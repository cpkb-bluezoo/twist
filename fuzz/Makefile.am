## Copyright (C) 2026 Chris Burdess <dog@gnu.org>
##
## This file is part of twist.
##
## Fuzzing the parsers.  Nothing here is built by 'make' or run by 'make
## check'.  See fuzz.sh: it compiles the library again with sanitizers and
## coverage, and 'make check-fuzz' (from the top directory) runs the inputs
## that once found a bug.

EXTRA_DIST = fuzz.sh fuzz.h engine.c \
	harness-altsvc.c harness-coding.c harness-cookie.c harness-dict.c \
	harness-dns.c harness-ftp.c harness-glob.c harness-gopher.c \
	harness-h1.c harness-h2.c harness-h3.c harness-hpack.c harness-imap.c \
	harness-ldap.c harness-mailtext.c harness-mqtt.c harness-pop3.c \
	harness-proxy.c harness-quote.c harness-sasl.c harness-smtp.c \
	harness-tftp.c harness-url.c harness-vars.c harness-ws.c

dist-hook:
	cp -R $(srcdir)/regress $(distdir)/regress

.PHONY: check-fuzz
check-fuzz:
	$(srcdir)/fuzz.sh regress
