/* Copyright (C) 2026 Chris Burdess <dog@gnu.org>

   This file is part of twist.

   twist is free software: you can redistribute it and/or modify it
   under the terms of the GNU General Public License as published
   by the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.

   twist is distributed in the hope that it will be useful, but
   WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   General Public License for more details.

   You should have received a copy of the GNU General Public
   License along with this program.  If not, see
   <https://www.gnu.org/licenses/>.  */

/* libtwist, a transfer library.

   Transfers are scheme-neutral.  HTTP is the first scheme; the same
   transfer and runtime carry every later protocol.  A transfer is the job; a
   runtime runs many of them on one event loop and tells the program, from the
   loop, when each has ended.  Nothing blocks.  A runtime can also be a guest
   in the application's poll loop: twist_runtime_on_ready is "this fd is
   readable or writable", and the timer callback is the next deadline.  */

#ifndef TWIST_H
#define TWIST_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define TWIST_VERSION_MAJOR 0
#define TWIST_VERSION_MINOR 1
#define TWIST_VERSION_STRING "0.1"

enum twist_error
{
  TWIST_OK = 0,
  TWIST_ERR_NOMEM = 1,
  TWIST_ERR_INVAL = 2,
  TWIST_ERR_UNSUPPORTED = 3,
  TWIST_ERR_RESOLVE = 4,
  TWIST_ERR_CONNECT = 5,
  TWIST_ERR_TIMEOUT = 6,
  TWIST_ERR_PROTOCOL = 7,
  TWIST_ERR_TLS = 8,
  TWIST_ERR_CLOSED = 9,
  TWIST_ERR_AGAIN = 10,
  TWIST_ERR_AUTH = 11,
  TWIST_ERR_REDIRECT = 12,
  TWIST_ERR_URL = 13,
  TWIST_ERR_ABORTED = 14,
  TWIST_ERR_FILE = 15,
  TWIST_ERR_HTTP = 16,
  TWIST_ERR_ENCODING = 17,
  TWIST_ERR_HOSTKEY = 18,
  TWIST_ERR_RANGE = 19,
  TWIST_ERR_RESUME = 20,
  TWIST_ERR_QUOTE = 21,
  TWIST_ERR_PROXY = 22,
  /* The loop was run again from inside a callback (twist_runtime_run_once,
     twist_runtime_on_ready or twist_runtime_on_timer): it is in use by the
     call that made the callback.  Do it after that call returns.  */
  TWIST_ERR_RECURSIVE = 23,
  /* The transfer ended before all of what the server said it would send
     had come.  */
  TWIST_ERR_PARTIAL = 24,
  /* TLS was asked for with TWISTOPT_USE_SSL and could not be had: the
     server does not offer to upgrade the connection, or refused to.  */
  TWIST_ERR_USE_SSL = 25,
  /* A name in a list of options, such as TWISTOPT_TELNETOPTIONS, that the
     transfer does not have.  */
  TWIST_ERR_UNKNOWN_OPTION = 26,
  /* An option in such a list that is not written as it must be.  */
  TWIST_ERR_OPTION_SYNTAX = 27,
  /* The CSeq of an RTSP reply was not that of the request, or the caller
     tried to set CSeq as a header of its own.  */
  TWIST_ERR_RTSP_CSEQ = 28,
  /* The data of an upload had to be sent again (a redirect that keeps the
     body, an authentication that needs a second request, a connection that
     was lost) and the read callback could not be made to start from the
     beginning: there is no TWISTOPT_SEEKFUNCTION, or it failed.  */
  TWIST_ERR_REWIND = 29
};

const char *twist_strerror (int err);
const char *twist_version (void);

int twist_global_init (void);
void twist_global_cleanup (void);

struct twist_slist
{
  char *data;
  struct twist_slist *next;
};

struct twist_slist *twist_slist_append (struct twist_slist *list,
                                        const char *data);
void twist_slist_free_all (struct twist_slist *list);

typedef size_t (*twist_write_callback) (char *ptr, size_t size, size_t nmemb,
                                        void *userdata);
typedef size_t (*twist_read_callback) (char *ptr, size_t size, size_t nmemb,
                                       void *userdata);
/* A read callback returns the number of bytes it stored, and 0 at the end of
   the data.  Returning this instead says the data cannot be read; the
   transfer fails, where 0 would be taken as the end and send a short file as
   if it were whole.  sftp and scp honour it.  */
#define TWIST_READFUNC_ABORT ((size_t) 0x10000000)
/* Makes the data that the read callback gives start again at OFFSET from the
   beginning (ORIGIN is always SEEK_SET).  0 is done; anything else, it cannot.
   An upload that has to be sent again needs it (TWIST_ERR_REWIND).  */
typedef int (*twist_seek_callback) (void *userdata, long long offset,
                                    int origin);

/* The progress callback.  TOTAL is 0 where the size is not known.  Returning
   0 goes on and leaves the drawing to the callback; returning
   TWIST_PROGRESSFUNC_CONTINUE goes on and has the library draw its own
   meter as well; anything else stops the transfer with TWIST_ERR_ABORTED.  */
typedef int (*twist_xferinfo_callback) (void *clientp, long long dltotal,
                                        long long dlnow, long long ultotal,
                                        long long ulnow);
#define TWIST_PROGRESSFUNC_CONTINUE 0x10000001

typedef struct twist_transfer twist_transfer;
typedef struct twist_runtime twist_runtime;
typedef struct twist_url twist_url;

enum twist_http_version
{
  TWIST_HTTP_VERSION_NONE = 0,
  TWIST_HTTP_VERSION_1_0 = 1,
  TWIST_HTTP_VERSION_1_1 = 2,
  TWIST_HTTP_VERSION_2_0 = 3,
  TWIST_HTTP_VERSION_2TLS = 4,
  TWIST_HTTP_VERSION_3 = 5,
  TWIST_HTTP_VERSION_3ONLY = 6,
  TWIST_HTTP_VERSION_2_PRIOR_KNOWLEDGE = 7
};

#define TWISTAUTH_NONE 0u
#define TWISTAUTH_BASIC (1u << 0)
#define TWISTAUTH_DIGEST (1u << 1)
#define TWISTAUTH_BEARER (1u << 2)

enum twist_opt
{
  TWISTOPT_URL = 1,
  TWISTOPT_WRITEFUNCTION = 2,
  TWISTOPT_WRITEDATA = 3,
  TWISTOPT_READFUNCTION = 4,
  TWISTOPT_READDATA = 5,
  TWISTOPT_HEADERFUNCTION = 6,
  TWISTOPT_HEADERDATA = 7,
  TWISTOPT_CUSTOMREQUEST = 8,
  TWISTOPT_HTTPHEADER = 9,
  TWISTOPT_POSTFIELDS = 10,
  TWISTOPT_POSTFIELDSIZE = 11,
  TWISTOPT_FOLLOWLOCATION = 12,
  TWISTOPT_MAXREDIRS = 13,
  TWISTOPT_USERAGENT = 14,
  TWISTOPT_USERNAME = 15,
  TWISTOPT_PASSWORD = 16,
  TWISTOPT_HTTPAUTH = 17,
  TWISTOPT_SSL_VERIFYPEER = 18,
  /* A PEM bundle of certificate authorities.  Without this nor
     TWISTOPT_CAPATH the environment's are used (TWIST_CA_BUNDLE, or
     SSL_CERT_DIR and SSL_CERT_FILE), and then the system's.  */
  TWISTOPT_CAINFO = 19,
  TWISTOPT_TIMEOUT_MS = 20,
  /* A proxy URL.  "" is no proxy, even when the environment names one; NULL
     is the default, which is the environment's: http_proxy, HTTPS_PROXY and
     the like by scheme, then ALL_PROXY, unless TWISTOPT_NOPROXY or NO_PROXY
     names the host.  */
  TWISTOPT_PROXY = 21,
  TWISTOPT_HTTP_VERSION = 22,
  TWISTOPT_XOAUTH2_BEARER = 23,
  TWISTOPT_RANGE = 24,
  TWISTOPT_REFERER = 25,
  TWISTOPT_NOBODY = 26,
  TWISTOPT_FAILONERROR = 27,
  TWISTOPT_CONNECTTIMEOUT_MS = 28,
  TWISTOPT_PRIVATE = 30,
  TWISTOPT_MAX_RECV_SPEED_LARGE = 31,
  TWISTOPT_MAX_SEND_SPEED_LARGE = 32,
  TWISTOPT_COOKIE = 33,
  /* The name of a Unix socket in the abstract namespace (Linux), without the
     leading NUL, to connect to in place of the host and port of the URL.  See
     TWISTOPT_UNIX_SOCKET, which this replaces and is replaced by.  */
  TWISTOPT_ABSTRACT_UNIX_SOCKET = 34,
  /* Comma-separated DNS transports.  Default is doq,dot,doh,udp.  */
  TWISTOPT_DNS_ORDER = 35,
  TWISTOPT_MAIL_FROM = 36,
  TWISTOPT_MAIL_RCPT = 37,
  /* HTTPS URL of a DNS-over-HTTPS server.  Empty clears it.  */
  TWISTOPT_DOH_URL = 38,
  /* Non-zero verifies the DoH certificate.  Independent of
     TWISTOPT_SSL_VERIFYPEER.  */
  TWISTOPT_DOH_SSL_VERIFYPEER = 39,
  /* PEM client certificate, leaf first.  Empty clears it.  */
  TWISTOPT_SSLCERT = 40,
  /* PEM private key for TWISTOPT_SSLCERT.  Empty clears it.  */
  TWISTOPT_SSLKEY = 41,
  /* quic://host[:port] DNS-over-QUIC resolver.  Empty clears it.  */
  TWISTOPT_DOQ_URL = 42,
  /* tls://host[:port] DNS-over-TLS resolver.  Empty clears it.  */
  TWISTOPT_DOT_URL = 43,
  /* Response codings to accept.  Empty string means gzip and deflate.
     NULL does not advertise or decode.  */
  TWISTOPT_ACCEPT_ENCODING = 44,
  /* Compress the request body.  "gzip" or "deflate".  Empty clears it.  */
  TWISTOPT_CONTENT_ENCODING = 45,
  /* known_hosts file for sftp and scp.  Empty or unset: ~/.ssh/known_hosts.
     TWISTOPT_SSL_VERIFYPEER 0 skips the check.  */
  TWISTOPT_SSH_KNOWNHOSTS = 46,
  /* Base64 SHA-256 of the host key of an sftp or scp server, as ssh-keygen
     -l prints it (with or without "SHA256:" and the padding).  A key that
     matches is trusted, whatever known_hosts says; one that does not is
     refused, even with TWISTOPT_SSL_VERIFYPEER 0.  Empty clears it.  */
  TWISTOPT_SSH_HOST_PUBLIC_KEY_SHA256 = 47,
  /* Passphrase for the private key file (TWISTOPT_SSLKEY serves sftp and
     scp too).  Empty clears it.  */
  TWISTOPT_KEYPASSWD = 48,
  /* Where to continue, for sftp, scp and ftp; pass a long long.  A download
     starts at this byte of the file (the caller appends to what it has; ftp
     says REST).  An upload skips this many bytes of its data and appends at
     this offset of the remote file (ftp: APPE); -1 asks the server how much
     of the file it has (ftp: SIZE).  0 starts at the beginning.  */
  TWISTOPT_RESUME_FROM = 49,
  /* For sftp, list a directory by name only, one to a line, not in the
     server's long form.  */
  TWISTOPT_DIRLISTONLY = 50,
  /* The ssh-agent socket for sftp and scp.  Unset: the one named by the
     environment variable SSH_AUTH_SOCK.  An empty string: no agent.  An
     explicit private key (TWISTOPT_SSLKEY) is used alone, without the agent.  */
  TWISTOPT_SSH_AGENT_SOCKET = 51,
  /* Commands for an sftp server, as a twist_slist the caller keeps.  QUOTE
     runs before the transfer and POSTQUOTE after one that succeeded.  Each
     is a command line: chmod, chown, chgrp, atime,
     mtime, ln, symlink, mkdir, pwd, rename, rm, rmdir.  A "*" before it lets
     the server refuse it without ending the transfer.  A command that fails
     ends the transfer with TWIST_ERR_QUOTE.  Used with an sftp URL only.  */
  TWISTOPT_QUOTE = 52,
  TWISTOPT_POSTQUOTE = 53,
  /* An upload to a path whose directories are not there makes them (mode
     0755) and goes on.  A long, 0 or 1.  For sftp.  */
  TWISTOPT_CREATE_MISSING_DIRS = 54,
  /* "user:password" for the proxy (TWISTOPT_PROXY), if the proxy's URL has
     none.  Used to open a tunnel (CONNECT, or SOCKS5), as Basic credentials
     or the SOCKS5 user name and password.  Empty clears it.  */
  TWISTOPT_PROXYUSERPWD = 55,
  /* A long.  1, the default, shows no progress meter and calls no
     TWISTOPT_XFERINFOFUNCTION; 0 does both.  */
  TWISTOPT_NOPROGRESS = 56,
  /* A twist_xferinfo_callback, called as the transfer goes on when
     TWISTOPT_NOPROGRESS is 0.  NULL clears it.  */
  TWISTOPT_XFERINFOFUNCTION = 57,
  /* The pointer that is passed to TWISTOPT_XFERINFOFUNCTION.  */
  TWISTOPT_XFERINFODATA = 58,
  /* A FILE * that the progress meter is written to.  NULL, the default, is
     standard error.  Twist does not close it.  */
  TWISTOPT_STDERR = 59,
  /* A long long: how many bytes TWISTOPT_READFUNCTION will give, if the
     application knows.  It is for the progress only; no request carries it.
     -1, the default, is not known.  */
  TWISTOPT_INFILESIZE = 60,
  /* Comma-separated hosts that do not go through a proxy: a host name matches
     itself and the names under it, an address matches itself or a network as
     192.168.0.0/16, and * is all hosts.  "" is none.  Without this the
     environment's no_proxy or NO_PROXY is used.  */
  TWISTOPT_NOPROXY = 61,
  /* A directory of PEM files of certificate authorities, in addition to
     TWISTOPT_CAINFO.  */
  TWISTOPT_CAPATH = 62,
  /* A PEM bundle of the authorities that vouch for an https proxy.  Without
     it the proxy is checked against the same authorities as the target
     (TWISTOPT_CAINFO, TWISTOPT_CAPATH, the environment's, the system's).  */
  TWISTOPT_PROXY_CAINFO = 63,
  /* A long.  0 does not check the certificate of an https proxy; the default,
     1, does.  This is not TWISTOPT_SSL_VERIFYPEER: the target is checked or
     not as that says, and the proxy as this says.  */
  TWISTOPT_PROXY_SSL_VERIFYPEER = 64,
  /* The URI Template of a UDP proxy (RFC 9298), for HTTP/3 through it: an
     https URI with {target_host} and {target_port}, or the query form
     {?target_host,target_port}.  Its host and port are the proxy's, and may
     be other than TWISTOPT_PROXY's.  Without it an https proxy has
     https://HOST:PORT/.well-known/masque/udp/{target_host}/{target_port}/.
     A template that is not one is refused.  NULL or "" clears it.  */
  TWISTOPT_PROXY_TEMPLATE_UDP = 65,
  /* The path of a Unix socket to connect to in place of the host and port of
     the URL, for http, https, ws and wss.  The URL still gives the Host
     header, the request target and the name that TLS checks.  Proxies are not
     used, and HTTP/3 is not possible.  Another scheme fails with
     TWIST_ERR_UNSUPPORTED.  A path (or a name, see
     TWISTOPT_ABSTRACT_UNIX_SOCKET) too long for the socket address is
     TWIST_ERR_INVAL.  NULL or "" clears it, and clears an abstract name.  */
  TWISTOPT_UNIX_SOCKET = 66,
  /* A long: whether a connection that starts in the clear is to be upgraded
     to TLS, for ftp, imap, pop3 and smtp (AUTH TLS, STARTTLS and STLS), which
     the schemes with an s do from the first byte.  One of TWIST_USE_SSL_NONE,
     the default, which never asks, TWIST_USE_SSL_TRY, which asks and goes on
     in the clear if the server cannot, and TWIST_USE_SSL_ALL, which ends the
     transfer with TWIST_ERR_USE_SSL if it cannot be done.  A TRY that the
     server agrees to is as secure as ALL, and one that it does not is not:
     whoever is on the path can make a server seem not to offer TLS, so TRY
     protects against nobody who is.  The user name and password are sent only
     after the upgrade.  Other schemes ignore it.  */
  TWISTOPT_USE_SSL = 67,
  /* For telnet: a twist_slist the caller keeps, of options for the session,
     each written NAME=VALUE with the name in either case.  TTYPE=TYPE is the
     terminal type to give, XDISPLOC=DISPLAY the X display, NEW_ENV=NAME,VALUE
     an environment variable (it may be given any number of times, and
     NEW_ENV=NAME has none), WS=WIDTHxHEIGHT the size of the window in
     characters, and BINARY=1, the default, or 0 whether bytes are sent and
     taken as they are.  A name that is not one of these ends the transfer
     with TWIST_ERR_UNKNOWN_OPTION, and one without a value, or with a bad
     one, with TWIST_ERR_OPTION_SYNTAX.  A value with a byte above 0x7f is
     skipped.  A user name (TWISTOPT_USERNAME, or the URL's) is given as the
     USER variable.  NULL clears it.  Other schemes ignore it.

     What is sent to a telnet server is what TWISTOPT_READFUNCTION gives, and
     without one it is what is read from TWISTOPT_TELNET_INPUT_FD, which is
     watched for as long as the server keeps the connection.  With neither,
     nothing is sent.  TWISTOPT_POSTFIELDS is not sent.  */
  TWISTOPT_TELNETOPTIONS = 68,
  /* A long.  Non-zero has the transfer keep the cookies that responses set in
     the runtime's cookie jar and send them back.  A cookie is sent to the
     host that set it and to no other, whatever Domain it asked for (one for a
     domain that the host is not under is refused); to the paths under its
     Path; and over https only if it was marked Secure.  The jar lives as long as the runtime does and is shared by
     every transfer in it that asks for it.  A cookie given with
     TWISTOPT_COOKIE is sent in its place.  Only HTTP uses it.  */
  TWISTOPT_USE_COOKIES = 69,
  /* A long.  Non-zero has the transfer upgrade an http URL to https when the
     host is in the runtime's HSTS list, which is shared by every
     transfer in it that asks for it.  Only HTTP uses it.  */
  TWISTOPT_USE_HSTS = 70,
  /* A long.  Non-zero has the transfer keep the alternative services that
     servers offer, and use them, in the runtime's Alt-Svc list, which is
     shared by every transfer in it that asks for it.  Only HTTP uses it.  */
  TWISTOPT_USE_ALTSVC = 71,
  /* A long: for telnet, the descriptor that the session's input is read from
     when there is no TWISTOPT_READFUNCTION.  It is a terminal, a pipe or a
     file, it is the caller's, and the transfer does not close it or make it
     non-blocking: a descriptor that can be polled is read only when it is
     ready, and what is read from it waits for the connection when the
     connection is behind.  The end of the input does not end the session.
     -1, the default, is none.  Other schemes ignore it.  */
  TWISTOPT_TELNET_INPUT_FD = 72,
  /* A long.  Non-zero, the default, has an HTTP transfer that finds no
     connection it can share to its origin, but a connection to it that is
     still being made and may turn out to carry several transfers (HTTP/2 or
     HTTP/3), wait for that one, and use it if it does.  Zero has it make a
     connection of its own at once.  Only HTTP uses it.  */
  TWISTOPT_PIPEWAIT = 73,
  /* A twist_seek_callback: how to read the upload from its start again.  */
  TWISTOPT_SEEKFUNCTION = 74,
  /* The pointer that is passed to it.  */
  TWISTOPT_SEEKDATA = 75,
  /* A long.  Non-zero has an upload add to the remote file (ftp: APPE) and
     not replace it.  */
  TWISTOPT_APPEND = 76
};

/* Options of a runtime (twist_runtime_setopt).  */
enum twist_runtime_option
{
  /* A long: the most connections a runtime has open or being made to one
     origin (the scheme, host and port, and the proxy) for HTTP transfers,
     counting those kept idle for reuse.  A transfer that would make another
     waits until one is closed, or takes an idle one, and an idle one of
     another loop is closed to make room.  Streams that share an HTTP/2 or
     HTTP/3 connection are not connections.  0, the default, is no limit.  */
  TWIST_RUNTIMEOPT_MAX_HOST_CONNECTIONS = 1,
  /* A long, 1 to 64: how many event loops the runtime runs transfers on, each
     in a thread of its own but the first, which is the program's, driven by
     twist_runtime_run_once.  1, the default, is one loop and no thread.  The
     threads are started by the first twist_runtime_start.  A runtime made with
     twist_runtime_new_embedded refuses it.  */
  TWIST_RUNTIMEOPT_THREADS = 2
};

enum twist_use_ssl
{
  TWIST_USE_SSL_NONE = 0,
  TWIST_USE_SSL_TRY = 1,
  TWIST_USE_SSL_ALL = 2
};

enum twist_dns_transport
{
  TWIST_DNS_DOQ = 1,
  TWIST_DNS_DOT = 2,
  TWIST_DNS_DOH = 3,
  TWIST_DNS_UDP = 4
};

enum twist_info
{
  TWISTINFO_RESPONSE_CODE = 1,
  TWISTINFO_EFFECTIVE_URL = 2,
  TWISTINFO_SIZE_DOWNLOAD = 3,
  TWISTINFO_CONTENT_TYPE = 4,
  TWISTINFO_PRIVATE = 5,
  /* A long *: the HTTP version of the response, as TWIST_HTTP_VERSION_1_0,
     _1_1, _2_0 or _3, or TWIST_HTTP_VERSION_NONE until there is one.  */
  TWISTINFO_HTTP_VERSION = 6
};

twist_transfer *twist_transfer_new (void);
void twist_transfer_free (twist_transfer *transfer);
int twist_transfer_setopt (twist_transfer *transfer, int opt, ...);
int twist_transfer_getinfo (twist_transfer *transfer, int info, ...);
/* Detail for the last transfer, or NULL when only twist_strerror applies.  */
const char *twist_transfer_error (const twist_transfer *transfer);

#define TWIST_POLL_NONE 0
#define TWIST_POLL_IN 1
#define TWIST_POLL_OUT 2
#define TWIST_POLL_REMOVE 4

/* Called once, from the loop, when a transfer that was started has ended.
   RESULT is TWIST_OK or the code that ended it.  The transfer has let go of
   its connection and is in no runtime by then, so the callback may read
   what it learned with twist_transfer_getinfo, start it again, or free it.  */
typedef void (*twist_done_callback) (twist_transfer *transfer, int result,
                                     void *user);

/* What a runtime made with twist_runtime_new_embedded tells the program
   that owns the poll loop.  The first says that FD is to be polled for WHAT,
   TWIST_POLL_IN and TWIST_POLL_OUT or'd together, or is no longer wanted
   (TWIST_POLL_REMOVE).  The second says how long the loop may wait for the
   next deadline of the runtime, in milliseconds from now, 0 if it is
   due, or -1 for none.  Neither may call the runtime.  */
typedef void (*twist_watch_callback) (int fd, int what, void *user);
typedef void (*twist_timer_callback) (long timeout_ms, void *user);

/* A runtime runs transfers on one event loop and keeps what they can
   use again: connections, names, and the cookies, HSTS and Alt-Svc lists of
   the transfers that ask for them.  Nothing in it blocks.  This one has a
   poller of its own, and is driven with twist_runtime_run_once.  */
twist_runtime *twist_runtime_new (void);
/* One inside the program's own poll loop, which has no poller.  The program
   polls what WATCH says to, and calls twist_runtime_on_ready for what is
   ready and twist_runtime_on_timer when the deadline TIMER gave has
   passed.  */
twist_runtime *twist_runtime_new_embedded (twist_watch_callback watch,
                                           twist_timer_callback timer,
                                           void *user);
/* Free the handle.  A transfer in it is dropped without a call to its
   twist_done_callback.  From a callback this does nothing.  */
void twist_runtime_free (twist_runtime *runtime);

/* Wait up to TIMEOUT_MS (-1: for as long as it takes to have something to
   do, 0: not at all) for what is ready and for the timers that are due, and
   do it, once.  A transfer that ends has its callback called from here.
   TWIST_ERR_RECURSIVE from a callback, and TWIST_ERR_INVAL for an embedded
   handle.  */
int twist_runtime_run_once (twist_runtime *runtime, int timeout_ms);
/* For an embedded handle: FD is ready for EVENTS (TWIST_POLL_IN and
   TWIST_POLL_OUT), or the deadline has passed.  */
int twist_runtime_on_ready (twist_runtime *runtime, int fd, int events);
int twist_runtime_on_timer (twist_runtime *runtime);

/* Begin TRANSFER on RUNTIME.  It returns at once, and DONE (which may be
   NULL) is called when the transfer ends, whether it ran or could not begin,
   so there is one way to learn the result.  The transfer is the runtime's
   until then.  This may be called from a callback, to start the next
   transfer.  */
int twist_runtime_start (twist_runtime *runtime, twist_transfer *transfer,
                         twist_done_callback done, void *user);
/* End TRANSFER early.  Its callback is called with TWIST_ERR_ABORTED.  */
int twist_runtime_cancel (twist_runtime *runtime, twist_transfer *transfer);

/* Set an option of RUNTIME: OPTION is a twist_runtime_option, followed by its
   value.  TWIST_ERR_INVAL for an option that is not known or a value that is
   not right for it, and for any option once a transfer has been started in
   the runtime.  */
int twist_runtime_setopt (twist_runtime *runtime, int option, ...);

int twist_url_parse (const char *input, twist_url **out);
void twist_url_free (twist_url *url);
const char *twist_url_scheme (const twist_url *url);
const char *twist_url_host (const twist_url *url);
int twist_url_port (const twist_url *url);
const char *twist_url_path (const twist_url *url);
const char *twist_url_query (const twist_url *url);
int twist_url_resolve (const twist_url *base, const char *ref, twist_url **out);

#ifdef __cplusplus
}
#endif

#endif /* TWIST_H */
