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

lib_LTLIBRARIES = libtwist.la
bin_PROGRAMS = twist

AM_CPPFLAGS = -I$(top_srcdir)/include -I$(top_srcdir)/src $(QUICKSTEP_CFLAGS) \
  $(FOXTROT_CFLAGS) -DLOCALEDIR=\"$(localedir)\"
AM_CFLAGS = $(STD_CFLAGS) $(WARN_CFLAGS)

libtwist_la_LDFLAGS = -version-info $(LIBTWIST_LTVERSION) -no-undefined
libtwist_la_LIBADD = $(QUICKSTEP_LIBS) $(FOXTROT_LIBS) $(ZLIB_LIBS) \
  $(LTLIBINTL)

## One library.  Sources are grouped by layer so a new scheme is a
## directory, not another file in a flat list.
##
##   reactor/  loop, connection, poll, timers, runtime, storage
##   engine/   url, easy/multi/share, proxy, scheme table
##   dns/      DNS client: message parser, transport order, resolver
##   auth/     SASL clients, HTTP Basic and Digest, MD5, SHA-256
##   http/     HTTP/1, HTTP/2, HTTP/3 and cookies
##   ftp/ file/ mail/ mqtt/ ldap/ ws/ gopher/ dict/ tftp/ ssh/  scheme handlers
##   mime/     streaming MIME writer
##   tls/      quickstep TLS and QUIC under the connection

libtwist_la_SOURCES = \
  gettext.h \
  i18n.c \
  init.c \
  strerror.c \
  twist-int.h \
  util.c \
  auth/b64.c \
  auth/basic.c \
  auth/digest.c \
  auth/md5.c \
  auth/sasl.c \
  auth/sha256.c \
  reactor/atomic.h \
  reactor/cmdq.c \
  reactor/cmdq.h \
  reactor/connection.c \
  reactor/loop.c \
  reactor/poll.c \
  reactor/poll.h \
  reactor/runtime.c \
  reactor/storage.c \
  reactor/timer.c \
  reactor/timer.h \
  engine/easy.c \
  engine/multi.c \
  engine/glob.c \
  engine/pool.c \
  engine/rate.c \
  engine/proxy.c \
  engine/vars.c \
  engine/scheme.c \
  engine/share.c \
  engine/url.c \
  dns/doh.c \
  dns/policy.c \
  dns/cache.c \
  dns/resolve.c \
  dns/wire.c \
  http/coding.c \
  http/cookie.c \
  http/h1.c \
  http/h2.c \
  http/h3.c \
  http/hpack.c \
  http/hpack_tab.h \
  http/http.c \
  http/qpack.c \
  http/qpack_tab.h \
  http/version.c \
  ftp/ftp.c \
  file/file.c \
  mail/auth.c \
  mail/dial.c \
  mail/imap.c \
  mail/pop3.c \
  mail/smtp.c \
  mail/wire.c \
  mime/writer.c \
  mqtt/mqtt.c \
  ldap/ldap.c \
  ws/ws.c \
  gopher/gopher.c \
  dict/dict.c \
  tftp/tftp.c \
  ssh/agent.c \
  ssh/hostkey.c \
  ssh/quote.c \
  ssh/sftp.c \
  ssh/ssh-int.h \
  ssh/ssh.c \
  tls/identity.c \
  tls/quic.c \
  tls/tls.c

twist_SOURCES = main.c
twist_LDADD = libtwist.la $(READLINE_LIBS)

## For fuzz/fuzz.sh, which compiles the library again with sanitizers and
## instrumentation: what to compile, and with what.
print-sources:
	@echo $(libtwist_la_SOURCES)
print-cflags:
	@echo $(DEFS) $(DEFAULT_INCLUDES) $(AM_CPPFLAGS) $(CPPFLAGS) $(AM_CFLAGS)
print-libs:
	@echo $(libtwist_la_LIBADD) $(LIBS)
