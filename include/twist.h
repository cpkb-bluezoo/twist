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
   easy/multi/share API carries every later protocol.  The multi
   interface is a guest in the application's poll loop:
   twist_multi_socket_action is "this fd is readable or writable",
   and twist_multi_timeout is the next deadline.  */

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
  TWIST_ERR_PROXY = 22
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

/* The progress callback.  TOTAL is 0 where the size is not known.  Returning
   0 goes on and leaves the drawing to the callback; returning
   TWIST_PROGRESSFUNC_CONTINUE goes on and has the library draw its own
   meter as well; anything else stops the transfer with TWIST_ERR_ABORTED.  */
typedef int (*twist_xferinfo_callback) (void *clientp, long long dltotal,
                                        long long dlnow, long long ultotal,
                                        long long ulnow);
#define TWIST_PROGRESSFUNC_CONTINUE 0x10000001

typedef struct twist_easy twist_easy;
typedef struct twist_multi twist_multi;
typedef struct twist_share twist_share;
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
  TWISTOPT_SHARE = 29,
  TWISTOPT_PRIVATE = 30,
  TWISTOPT_MAX_RECV_SPEED_LARGE = 31,
  TWISTOPT_MAX_SEND_SPEED_LARGE = 32,
  TWISTOPT_COOKIE = 33,
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
  /* Where to continue, for sftp and scp; pass a long long.  A download
     starts at this byte of the file (the caller appends to what it has).  An
     upload skips this many bytes of its data and appends at this offset of
     the remote file; -1 asks the server how much of the file it has.  0
     starts at the beginning.  */
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
  TWISTOPT_PROXY_SSL_VERIFYPEER = 64
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
  TWISTINFO_PRIVATE = 5
};

twist_easy *twist_easy_init (void);
void twist_easy_cleanup (twist_easy *easy);
int twist_easy_setopt (twist_easy *easy, int opt, ...);
int twist_easy_perform (twist_easy *easy);
int twist_easy_getinfo (twist_easy *easy, int info, ...);
/* Detail for the last transfer, or NULL when only twist_strerror applies.  */
const char *twist_easy_error (const twist_easy *easy);

#define TWIST_SOCKET_TIMEOUT (-1)
#define TWIST_POLL_NONE 0
#define TWIST_POLL_IN 1
#define TWIST_POLL_OUT 2
#define TWIST_POLL_REMOVE 4

typedef int (*twist_socket_callback) (twist_easy *easy, int fd, int what,
                                      void *user, void *socketp);
typedef int (*twist_timer_callback) (twist_multi *multi, long timeout_ms,
                                     void *user);

enum twist_multi_opt
{
  TWISTMOPT_SOCKETFUNCTION = 1,
  TWISTMOPT_SOCKETDATA = 2,
  TWISTMOPT_TIMERFUNCTION = 3,
  TWISTMOPT_TIMERDATA = 4
};

twist_multi *twist_multi_init (void);
void twist_multi_cleanup (twist_multi *multi);
int twist_multi_add_handle (twist_multi *multi, twist_easy *easy);
int twist_multi_remove_handle (twist_multi *multi, twist_easy *easy);
int twist_multi_perform (twist_multi *multi, int *running);
int twist_multi_socket_action (twist_multi *multi, int fd, int ev,
                               int *running);
int twist_multi_timeout (twist_multi *multi, long *timeout_ms);
int twist_multi_setopt (twist_multi *multi, int opt, ...);
int twist_multi_info_read (twist_multi *multi, int *msgs_left,
                           twist_easy **easy, int *result);

#define TWIST_LOCK_DATA_COOKIE (1u << 0)
#define TWIST_LOCK_DATA_DNS (1u << 1)
#define TWIST_LOCK_DATA_CONNECT (1u << 2)
#define TWIST_LOCK_DATA_SSL_SESSION (1u << 3)
#define TWIST_LOCK_DATA_HSTS (1u << 4)
#define TWIST_LOCK_DATA_ALT_SVC (1u << 5)

twist_share *twist_share_init (void);
void twist_share_cleanup (twist_share *share);
int twist_share_setopt (twist_share *share, unsigned lock_data);

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
