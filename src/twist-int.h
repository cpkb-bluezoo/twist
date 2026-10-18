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

/* Internal faces.  Not installed.  Protocol handlers see Endpoint and
   never see ciphertext.  */

#ifndef TWIST_INT_H
#define TWIST_INT_H

#include <twist.h>

#include <quickstep/frame.h>

#include <sys/types.h>

#define TWIST_IN_CEILING (256u * 1024u)

struct twist_loop;
struct twist_connection;
struct twist_timer;
struct twist_runtime;
struct twist_storage;
struct twist_dns_addr;

#define TWIST_INTEREST_READ 1
#define TWIST_INTEREST_WRITE 2

struct twist_endpoint
{
  struct twist_connection *conn;
  void *user_data;
  int (*send) (struct twist_endpoint *ep, const uint8_t *data, size_t len);
  void (*close_fn) (struct twist_endpoint *ep);
  void (*pause_read) (struct twist_endpoint *ep);
  void (*resume_read) (struct twist_endpoint *ep);
  void (*on_write_ready) (struct twist_endpoint *ep);
};

struct twist_protocol_handler
{
  void (*connected) (struct twist_endpoint *ep);
  size_t (*receive) (struct twist_endpoint *ep, const uint8_t *data,
                     size_t len);
  void (*disconnected) (struct twist_endpoint *ep, int error);
  void (*security_established) (struct twist_endpoint *ep, const char *alpn,
                                size_t alpn_len);
  void (*error) (struct twist_endpoint *ep, int error);
  void (*read_finished) (struct twist_endpoint *ep);
  void (*datagram) (struct twist_endpoint *ep, const uint8_t *data,
                    size_t len);
};

struct twist_url
{
  char *scheme;
  char *user;
  char *password;
  char *host;
  char *path;
  char *query;
  char *fragment;
  int port;
  int port_set;
  int path_set;
};

struct twist_easy
{
  char *url_string;
  struct twist_url *url;
  struct twist_slist *headers;
  char *method;
  char *useragent;
  char *username;
  char *password;
  char *bearer;
  char *postfields;
  long postfieldsize;
  int postfieldsize_set;
  int follow;
  long maxredirs;
  long redirs;
  int verifypeer;
  char *cainfo;
  char *sslcert;
  char *sslkey;
  long timeout_ms;
  long connect_timeout_ms;
  char *proxy;
  int http_version;
  int dns_order[4];
  int dns_order_n;
  struct twist_origin_hint *origins;
  unsigned auth;
  char *range;
  char *referer;
  char *cookie;
  char *mail_from;
  struct twist_slist *mail_rcpt;
  char *doh_url;
  char *doq_url;
  char *dot_url;
  int doh_verifypeer;
  int nobody;
  int failonerror;
  twist_write_callback write_cb;
  void *write_data;
  twist_write_callback header_cb;
  void *header_data;
  twist_read_callback read_cb;
  void *read_data;
  struct twist_share *share;
  struct twist_multi *multi;
  struct twist_loop *loop;
  int own_loop;
  int done;
  int result;
  char *error;
  long http_code;
  char *effective_url;
  char *content_type;
  size_t size_download;
  uint64_t max_recv_speed;
  uint64_t max_send_speed;
  void *private_data;
  void *xfer;
  void (*xfer_free) (void *xfer);
  uint64_t recv_stamp_ms;
  uint64_t recv_bytes_window;
};

struct twist_multi
{
  struct twist_loop *loop;
  int own_loop;
  struct twist_easy **easies;
  size_t n_easies;
  size_t easies_cap;
  twist_socket_callback socket_cb;
  void *socket_user;
  twist_timer_callback timer_cb;
  void *timer_user;
  struct twist_easy **done;
  int *done_result;
  size_t n_done;
  size_t done_cap;
  size_t done_off;
  long last_timeout;
  struct twist_storage *storage;
};

/* ---- loop ---- */

struct twist_loop *twist_loop_new (int external);
void twist_loop_free (struct twist_loop *loop);
void twist_loop_set_now (struct twist_loop *loop, uint64_t (*now_ms) (void *),
                         void *user);
uint64_t twist_loop_now (struct twist_loop *loop);
int twist_loop_run_once (struct twist_loop *loop);
void twist_loop_on_readable (struct twist_loop *loop, int fd);
void twist_loop_on_writable (struct twist_loop *loop, int fd);
void twist_loop_on_timer (struct twist_loop *loop, uint64_t now_ms);
long twist_loop_next_timeout (struct twist_loop *loop, uint64_t now_ms);
void twist_loop_set_watch (struct twist_loop *loop,
                           void (*watch) (void *, int fd, int interest),
                           void *user);
void twist_loop_set_aux_timeout (struct twist_loop *loop,
                                 uint64_t (*deadline_us) (void *,
                                                          uint64_t now_us),
                                 void *user);
void twist_loop_set_aux_fire (struct twist_loop *loop,
                              void (*fire) (void *, uint64_t now_us));
int twist_loop_schedule (struct twist_loop *loop, uint64_t deadline_ms,
                         void (*cb) (void *), void *user,
                         struct twist_timer **out);
void twist_timer_cancel (struct twist_timer *timer);
int twist_loop_post (struct twist_loop *loop, void (*fn) (void *), void *user);
void twist_loop_watch_fd (struct twist_loop *loop, int fd, int interest,
                          struct twist_connection *conn);
void twist_loop_unwatch_fd (struct twist_loop *loop, int fd);
struct twist_multi *twist_loop_multi (struct twist_loop *loop);
void twist_loop_set_multi (struct twist_loop *loop, struct twist_multi *multi);
int twist_loop_waker (struct twist_loop *loop);

/* ---- connection ---- */

struct twist_connection *twist_connection_new (struct twist_loop *loop);
void twist_connection_free (struct twist_connection *conn);
struct twist_endpoint *twist_connection_endpoint (struct twist_connection *conn);
void twist_connection_set_handler (struct twist_connection *conn,
                                   const struct twist_protocol_handler *h);
void twist_connection_set_fd (struct twist_connection *conn, int fd);
void twist_connection_set_io (struct twist_connection *conn,
                              ssize_t (*read_fn) (void *, uint8_t *, size_t),
                              ssize_t (*write_fn) (void *, const uint8_t *,
                                                   size_t),
                              void *user);
void twist_connection_ingest (struct twist_connection *conn,
                              const uint8_t *data, size_t len);
int twist_connection_connect (struct twist_connection *conn,
                              const void *addr, size_t addrlen,
                              uint64_t timeout_ms);
void twist_connection_connected (struct twist_connection *conn);
void twist_connection_on_readable (struct twist_connection *conn);
void twist_connection_on_writable (struct twist_connection *conn);
int twist_connection_queue_out (struct twist_connection *conn,
                                const uint8_t *data, size_t len);
void twist_connection_deliver_app (struct twist_connection *conn,
                                   const uint8_t *data, size_t len);
void twist_connection_set_alpn (struct twist_connection *conn,
                                const char *alpn, size_t len);
void twist_connection_fail (struct twist_connection *conn, int err);
void twist_connection_set_tls (struct twist_connection *conn, void *tls,
                               void (*free_tls) (void *));
void *twist_connection_tls (struct twist_connection *conn);
int twist_endpoint_send (struct twist_endpoint *ep, const uint8_t *data,
                         size_t len);
void twist_endpoint_close (struct twist_endpoint *ep);
void twist_endpoint_pause_read (struct twist_endpoint *ep);
void twist_endpoint_resume_read (struct twist_endpoint *ep);
struct twist_loop *twist_endpoint_loop (struct twist_endpoint *ep);
int twist_connection_start_tls (struct twist_connection *conn,
                                const char *server_name, int verify,
                                const char *const *alpn, size_t n_alpn,
                                const char *cafile, const char *certfile,
                                const char *keyfile);
const char *twist_connection_alpn (struct twist_connection *conn,
                                   size_t *len);
void twist_connection_read_finished (struct twist_connection *conn);

/* Registered by tls.c / quic.c when those objects are linked.  */
struct twist_tls_want
{
  const char *server_name;
  int verify;
  const char *const *alpn;
  size_t n_alpn;
  const char *cafile;
  const char *certfile;
  const char *keyfile;
};

struct gq_tls_config;
struct gq_tls_info;
struct twist_client_auth;

int twist_pem_certificates (const char *text, size_t len, gq_slice *chain,
                            size_t cap, size_t *nchain, uint8_t **storage);
int twist_client_auth_load (struct twist_client_auth **out,
                            const char *certfile, const char *keyfile);
void twist_client_auth_free (struct twist_client_auth *auth);
void twist_client_auth_apply (const struct twist_client_auth *auth,
                              struct gq_tls_config *cfg);
int twist_client_auth_missing (const struct gq_tls_info *info);

extern int (*twist_tls_start_fn) (struct twist_connection *conn,
                                  const struct twist_tls_want *want);
extern int (*twist_tls_receive_fn) (struct twist_connection *conn,
                                    const uint8_t *data, size_t len);
extern int (*twist_tls_send_plain_fn) (struct twist_connection *conn,
                                       const uint8_t *data, size_t len);
extern int (*twist_quic_connect_fn) (struct twist_easy *easy,
                                     struct twist_connection **out);
int twist_quic_dial (struct twist_loop *loop, const char *server_name,
                     const char *alpn, const struct twist_dns_addr *addr,
                     int port, const char *cafile, const char *certfile,
                     const char *keyfile, struct twist_connection **out);
int twist_quic_open_stream (struct twist_connection *conn);

int twist_tls_register (void);
int twist_quic_register (void);
void twist_quic_hold_stream (struct twist_connection *conn);
int twist_quic_finish_stream (struct twist_connection *conn);

/* ---- runtime and storage ---- */

struct twist_runtime *twist_runtime_new (size_t nloops);
void twist_runtime_free (struct twist_runtime *rt);
struct twist_loop *twist_runtime_dial_loop (struct twist_runtime *rt);
size_t twist_runtime_next_worker (struct twist_runtime *rt);
struct twist_storage *twist_runtime_storage (struct twist_runtime *rt);

struct twist_storage *twist_storage_new (size_t threads, size_t bound);
void twist_storage_free (struct twist_storage *st);
int twist_storage_submit (struct twist_storage *st, void (*work) (void *),
                          void *arg, void (*done) (void *user, int err),
                          void *user, struct twist_loop *loop);
void twist_storage_set_inline (struct twist_storage *st, int inline_mode);

/* ---- url, scheme, dns, cache, proxy ---- */

int twist_url_parse_int (const char *input, struct twist_url **out);
void twist_url_free_int (struct twist_url *url);
int twist_url_resolve_int (const struct twist_url *base, const char *ref,
                           struct twist_url **out);
char *twist_url_format (const struct twist_url *url);
int twist_url_default_port (const char *scheme);

#define TWIST_SCHEME_TLS 1u
#define TWIST_SCHEME_DATAGRAM 2u
#define TWIST_SCHEME_MULTI 4u
#define TWIST_SCHEME_PROXY_OK 8u
#define TWIST_SCHEME_READY 16u

struct twist_scheme
{
  const char *name;
  int default_port;
  unsigned flags;
  int (*attach) (struct twist_easy *easy);
};

const struct twist_scheme *twist_scheme_by_name (const char *name);
int twist_scheme_unsupported (struct twist_easy *easy);
int twist_http_attach (struct twist_easy *easy);
int twist_file_attach (struct twist_easy *easy);
int twist_file_check_url (const char *host, const char *path, int path_set);
int twist_ftp_attach (struct twist_easy *easy);
int twist_smtp_attach (struct twist_easy *easy);
int twist_pop3_attach (struct twist_easy *easy);
int twist_imap_attach (struct twist_easy *easy);

struct twist_ftp;
struct twist_ftp *twist_ftp_new (struct twist_easy *easy, int live);
void twist_ftp_free (void *ftp);
size_t twist_ftp_receive (struct twist_ftp *ftp, const uint8_t *data, size_t len);
size_t twist_ftp_data (struct twist_ftp *ftp, const uint8_t *data, size_t len);
void twist_ftp_data_eof (struct twist_ftp *ftp);
const char *twist_ftp_command (const struct twist_ftp *ftp);
int twist_ftp_data_port (const struct twist_ftp *ftp);
const char *twist_ftp_data_host (const struct twist_ftp *ftp);

/* A complete control line.  text is a slice of the chunk passed to
   receive and is not retained.  final is 1 on the last line of a
   reply.  A short return leaves the unconsumed tail with the caller.  */
struct twist_ftp_events
{
  void *user;
  void (*reply) (void *user, int code, int final, const char *text,
                 size_t len);
  void (*failure) (void *user, int err);
};

struct twist_ftp_parser;
struct twist_ftp_parser *twist_ftp_parser_new (const struct twist_ftp_events *ev);
void twist_ftp_parser_free (struct twist_ftp_parser *parser);
size_t twist_ftp_parser_receive (struct twist_ftp_parser *parser,
                                 const uint8_t *data, size_t len);
int twist_ftp_pasv (const char *text, size_t len, char *host, size_t hostcap,
                    int *port);
int twist_ftp_epsv (const char *text, size_t len, int *port);

struct twist_dns_addr
{
  int family;
  unsigned char addr[16];
  char text[64];
};

struct twist_dns_events
{
  void *user;
  void (*address) (void *user, const struct twist_dns_addr *addr);
  void (*https_alpn) (void *user, const char *id, size_t len);
  void (*https_port) (void *user, int port);
  void (*https_rr) (void *user);
  /* One call per ALPN id.  port 0 means the transport default.  hint is
     the first address hint, or NULL when the record has none.  */
  void (*svcb) (void *user, const char *target, const char *alpn,
                size_t alpn_len, int port, int hint_family,
                const uint8_t *hint);
  void (*truncated) (void *user);
  void (*failure) (void *user, int err);
};

/* TCP, DoT, and DoQ framing: a 16-bit length then one message.
   A short return means the length or the message is not here yet.  */
size_t twist_dns_stream_receive (const uint8_t *data, size_t len,
                                 const struct twist_dns_events *ev);
/* UDP and a DoH body: one message, no length prefix.  */
size_t twist_dns_datagram_receive (const uint8_t *data, size_t len,
                                   const struct twist_dns_events *ev);
int twist_dns_encode_query (const char *name, int qtype, uint16_t id,
                            uint8_t **out, size_t *len);
/* Two-byte length prefix.  zero_id clears the DNS id (DoQ).  */
int twist_dns_frame_stream (const uint8_t *msg, size_t len, int zero_id,
                            uint8_t **out, size_t *outlen);
int twist_dns_decode (const uint8_t *msg, size_t len, int qtype,
                      struct twist_dns_addr **out, size_t *n);
int twist_dns_parse_order (const char *text, int *out, size_t cap, size_t *n);
int twist_dns_transport_plan (const int *user, size_t nuser, int *out,
                              size_t cap, size_t *n);

struct twist_dns_service
{
  struct twist_dns_addr addr;
  int nalpn;
  char alpn[4][16];
  int port;
  int have_https;
};

int twist_dns_resolve (struct twist_loop *loop, const char *host,
                       const int *order, size_t norder,
                       void (*cb) (void *user, int err,
                                   const struct twist_dns_addr *addr),
                       void *user);
int twist_dns_resolve_service (struct twist_loop *loop, const char *host,
                               const int *order, size_t norder,
                               void (*cb) (void *user, int err,
                                           const struct twist_dns_service *svc),
                               void *user);
int twist_dns_resolve_easy (struct twist_easy *easy, const char *host,
                            void (*cb) (void *user, int err,
                                        const struct twist_dns_addr *addr),
                            void *user);
int twist_dns_resolve_service_easy (struct twist_easy *easy, const char *host,
                                    void (*cb) (void *user, int err,
                                                const struct twist_dns_service *svc),
                                    void *user);
int twist_dns_plan_for (const int *user, size_t nuser, int have_doh,
                        int *out, size_t cap, size_t *n);
int twist_dns_bootstrap_plan (const int *user, size_t nuser, int *out,
                              size_t cap, size_t *n);

struct twist_doh;

struct twist_doh *twist_doh_new (void (*done) (void *user, int err,
                                               const uint8_t *msg, size_t len),
                                 void *user);
void twist_doh_reset (struct twist_doh *d);
void twist_doh_free (struct twist_doh *d);
size_t twist_doh_receive (struct twist_doh *d, const uint8_t *data, size_t len);
int twist_doh_encode_url (const char *url, const uint8_t *msg, size_t msg_len,
                          uint8_t **out, size_t *out_len);

enum
{
  TWIST_DISC_H3 = 1,
  TWIST_DISC_ALPN,
  TWIST_DISC_H2_PRIOR,
  TWIST_DISC_H2C,
  TWIST_DISC_H1
};

struct twist_origin_hint;

int twist_http_discover (int pinned, int https, int rr, int rr_h3, int cached,
                         int *how);
int twist_alt_svc_h3 (const char *value, size_t len, int *port, int *clear);
void twist_origin_clear (struct twist_easy *easy);
int twist_origin_h3 (struct twist_easy *easy, const char *host, int *port);
void twist_origin_set_h3 (struct twist_easy *easy, const char *host, int yes,
                          int port);
int twist_origin_http_minor (struct twist_easy *easy, const char *host);
void twist_origin_set_http_minor (struct twist_easy *easy, const char *host,
                                  int minor);

struct twist_pool;
struct twist_pool *twist_pool_new (void);
void twist_pool_free (struct twist_pool *pool);
int twist_pool_take (struct twist_pool *pool, const char *key,
                     struct twist_connection **out);
int twist_pool_put (struct twist_pool *pool, const char *key,
                    struct twist_connection *conn);

enum twist_proxy_kind
{
  TWIST_PROXY_NONE = 0,
  TWIST_PROXY_HTTP,
  TWIST_PROXY_SOCKS5
};

int twist_proxy_parse (const char *s, int *kind, char **host, int *port);
struct twist_proxy *twist_proxy_new (int kind, const char *host, int port,
                                     const struct twist_protocol_handler *inner);
void twist_proxy_free (struct twist_proxy *proxy);
void twist_proxy_set_target (struct twist_proxy *proxy, const char *host,
                             int port);
void twist_proxy_set_user (struct twist_proxy *proxy, void *user);
int twist_proxy_opening (struct twist_proxy *proxy, uint8_t **out, size_t *len);
int twist_proxy_feed (struct twist_proxy *proxy, const uint8_t *data,
                      size_t len, int *ready);
int twist_proxy_is_ready (const struct twist_proxy *proxy);
const struct twist_protocol_handler *twist_proxy_handler (struct twist_proxy *p);

/* ---- http codecs ---- */

struct twist_h1;
struct twist_h1_events
{
  void *user;
  void (*status_line) (void *user, int code, const char *reason, size_t n);
  void (*header) (void *user, const char *name, size_t name_len,
                  const char *value, size_t value_len);
  void (*body) (void *user, const uint8_t *data, size_t len);
  void (*message_done) (void *user);
  void (*failure) (void *user, int err);
  void (*version) (void *user, int major, int minor);
  /* Return 1 to stop parsing: the rest of the connection is no longer
     HTTP/1 (h2c 101).  */
  int (*switching) (void *user);
};

struct twist_h1 *twist_h1_new (const struct twist_h1_events *ev);
void twist_h1_free (struct twist_h1 *parser);
size_t twist_h1_receive (struct twist_h1 *parser, const uint8_t *data,
                         size_t len);
int twist_h1_write_request (const char *method, const char *target,
                            const char *host, int http10,
                            const struct twist_slist *extra,
                            const uint8_t *body, size_t body_len,
                            uint8_t **out, size_t *out_len);

struct twist_hpack;
struct twist_hpack *twist_hpack_new (void);
void twist_hpack_free (struct twist_hpack *hp);
int twist_hpack_decode (struct twist_hpack *hp, const uint8_t *data,
                        size_t len, struct twist_h1_events *ev);
int twist_hpack_encode_request (struct twist_hpack *hp, const char *method,
                                const char *scheme, const char *authority,
                                const char *path,
                                const struct twist_slist *extra,
                                uint8_t **out, size_t *out_len);
int twist_huff_decode (const uint8_t *in, size_t in_len, uint8_t **out,
                       size_t *out_len);

struct twist_h2;
struct twist_h2 *twist_h2_new (const struct twist_h1_events *ev);
void twist_h2_free (struct twist_h2 *h2);
int twist_h2_client_preface (uint8_t **out, size_t *len);
size_t twist_h2_receive (struct twist_h2 *h2, const uint8_t *data, size_t len);
int twist_h2_preface (uint8_t **out, size_t *out_len);
int twist_h2_request (struct twist_h2 *h2, const char *method,
                      const char *scheme, const char *authority,
                      const char *path, const struct twist_slist *extra,
                      const uint8_t *body, size_t body_len, int keep_open,
                      uint8_t **out, size_t *out_len);

struct twist_ws;
int twist_ws_accept (const char *key, char **out);
int twist_ws_key (char key[25]);
int twist_ws_validate (const char *key, const char *upgrade,
                       const char *connection, const char *accept);
struct twist_ws *twist_ws_new (struct twist_easy *easy,
                               int (*send) (void *user, const uint8_t *data,
                                            size_t len),
                               void *send_user,
                               void (*done) (void *user, int err),
                               void *done_user);
void twist_ws_free (struct twist_ws *ws);
size_t twist_ws_receive (struct twist_ws *ws, const uint8_t *data, size_t len);
int twist_ws_send (struct twist_ws *ws, int opcode, int fin,
                   const uint8_t *data, size_t len);

struct twist_h3;
struct twist_h3 *twist_h3_new (const struct twist_h1_events *ev);
void twist_h3_free (struct twist_h3 *h3);
size_t twist_h3_receive (struct twist_h3 *h3, const uint8_t *data, size_t len);
int twist_h3_request (struct twist_h3 *h3, const char *method,
                      const char *scheme, const char *authority,
                      const char *path, const struct twist_slist *extra,
                      const uint8_t *body, size_t body_len, uint8_t **out,
                      size_t *out_len);

int twist_http_should_redirect (int status, const char *method, int follow,
                                long redirs, long maxredirs, int *use_get);
int twist_http_status_result (int failonerror, int status);

/* ---- cookies, auth, share ---- */

struct twist_jar *twist_jar_new (void);
void twist_jar_free (struct twist_jar *jar);
int twist_jar_store (struct twist_jar *jar, const char *set_cookie,
                     const char *host, const char *path, int https);
int twist_jar_header (struct twist_jar *jar, const char *host,
                      const char *path, int https, char **out);

int twist_auth_basic (const char *user, const char *pass, char **out);
int twist_auth_digest (const char *challenge, const char *method,
                       const char *uri, const char *user, const char *pass,
                       unsigned nc, const char *cnonce, char **out);
int twist_md5 (const void *data, size_t len, uint8_t out[16]);
int twist_sha256 (const void *data, size_t len, uint8_t out[32]);
int twist_b64_encode (const uint8_t *in, size_t len, char **out);

/* Client SASL.  Responses are raw bytes; the protocol encodes them.  */
enum
{
  TWIST_SASL_PLAIN = 1,
  TWIST_SASL_LOGIN,
  TWIST_SASL_XOAUTH2
};

struct twist_sasl_client;
int twist_sasl_from_name (const char *name);
const char *twist_sasl_name (int mech);
struct twist_sasl_client *twist_sasl_client_new (int mech, const char *user,
                                                 const char *pass,
                                                 const char *token);
void twist_sasl_client_free (struct twist_sasl_client *client);
int twist_sasl_has_initial (const struct twist_sasl_client *client);
int twist_sasl_step (struct twist_sasl_client *client,
                     const uint8_t *challenge, size_t len, uint8_t **out,
                     size_t *out_len, int *done);

/* Streaming MIME writer.  Events and body chunks are written to the
   sink as they arrive.  The writer keeps one fixed buffer.  */
struct twist_mime;
struct twist_mime *twist_mime_new (int (*sink) (void *user, const uint8_t *data,
                                                size_t len),
                                   void *user);
void twist_mime_free (struct twist_mime *mime);
int twist_mime_begin (struct twist_mime *mime, const char *subtype);
int twist_mime_part (struct twist_mime *mime);
int twist_mime_header (struct twist_mime *mime, const char *name,
                       const char *value);
int twist_mime_body (struct twist_mime *mime, const uint8_t *data, size_t len);
int twist_mime_body_b64 (struct twist_mime *mime, const uint8_t *data,
                         size_t len);
int twist_mime_finish (struct twist_mime *mime);

#define TWIST_MAIL_LINE_MAX 4096

size_t twist_mail_line (const uint8_t *data, size_t len, const uint8_t **line,
                        size_t *line_len, int *err);

struct twist_dotout
{
  int bol;
};

struct twist_dotin
{
  int state;
};

void twist_dotout_init (struct twist_dotout *dot);
int twist_dotout_write (struct twist_dotout *dot, const uint8_t *data,
                        size_t len,
                        int (*sink) (void *user, const uint8_t *data, size_t len),
                        void *user);
int twist_dotout_finish (struct twist_dotout *dot,
                         int (*sink) (void *user, const uint8_t *data, size_t len),
                         void *user);
void twist_dotin_init (struct twist_dotin *dot);
size_t twist_dotin_pull (struct twist_dotin *dot, const uint8_t *data,
                         size_t len,
                         int (*sink) (void *user, const uint8_t *data, size_t len),
                         void *user, int *done, int *err);

struct twist_mail_sasl
{
  struct twist_sasl_client *client;
  int mech;
  int done;
};

void twist_mail_sasl_init (struct twist_mail_sasl *sasl);
void twist_mail_sasl_close (struct twist_mail_sasl *sasl);
int twist_mail_sasl_start (struct twist_mail_sasl *sasl, struct twist_easy *easy,
                           const char *advertised, char **b64, int *initial);
int twist_mail_sasl_continue (struct twist_mail_sasl *sasl, char **b64);
const char *twist_mail_user (const struct twist_easy *easy);
const char *twist_mail_pass (const struct twist_easy *easy);

struct twist_mail_link
{
  struct twist_easy *easy;
  struct twist_connection *conn;
  struct twist_proxy *proxy;
  struct twist_timer *timer;
  char *dial_host;
  int dial_port;
  const struct twist_protocol_handler *handler;
  void *user;
  void (*fail) (void *user, int err);
};

int twist_mail_link_open (struct twist_mail_link *link, struct twist_easy *easy,
                          const struct twist_protocol_handler *handler,
                          void *user, void (*fail) (void *user, int err));
void twist_mail_link_close (struct twist_mail_link *link);

struct twist_smtp;
struct twist_smtp *twist_smtp_new (struct twist_easy *easy, int live);
void twist_smtp_free (void *smtp);
size_t twist_smtp_receive (struct twist_smtp *smtp, const uint8_t *data,
                           size_t len);
const char *twist_smtp_command (const struct twist_smtp *smtp);

struct twist_pop3;
struct twist_pop3 *twist_pop3_new (struct twist_easy *easy, int live);
void twist_pop3_free (void *pop3);
size_t twist_pop3_receive (struct twist_pop3 *pop3, const uint8_t *data,
                           size_t len);
const char *twist_pop3_command (const struct twist_pop3 *pop3);

struct twist_imap;
struct twist_imap *twist_imap_new (struct twist_easy *easy, int live);
void twist_imap_free (void *imap);
size_t twist_imap_receive (struct twist_imap *imap, const uint8_t *data,
                           size_t len);
const char *twist_imap_command (const struct twist_imap *imap);

struct twist_mqtt;
struct twist_mqtt *twist_mqtt_new (struct twist_easy *easy, int live);
void twist_mqtt_free (void *mqtt);
size_t twist_mqtt_receive (struct twist_mqtt *mqtt, const uint8_t *data,
                           size_t len);
const uint8_t *twist_mqtt_command (const struct twist_mqtt *mqtt, size_t *len);
int twist_mqtt_attach (struct twist_easy *easy);

struct twist_ldap;
struct twist_ldap *twist_ldap_new (struct twist_easy *easy, int live);
void twist_ldap_free (void *ldap);
size_t twist_ldap_receive (struct twist_ldap *ldap, const uint8_t *data,
                           size_t len);
const uint8_t *twist_ldap_command (const struct twist_ldap *ldap, size_t *len);
int twist_ldap_attach (struct twist_easy *easy);

struct twist_gopher;
struct twist_gopher *twist_gopher_new (struct twist_easy *easy, int live);
void twist_gopher_free (void *gopher);
const uint8_t *twist_gopher_request (const struct twist_gopher *gopher,
                                     size_t *len);
size_t twist_gopher_receive (struct twist_gopher *gopher, const uint8_t *data,
                             size_t len);
void twist_gopher_closed (struct twist_gopher *gopher, int err);
int twist_gopher_attach (struct twist_easy *easy);

struct twist_share
{
  unsigned locks;
  struct twist_jar *jar;
  struct twist_pool *pool;
  struct twist_hsts *hsts;
  struct twist_altsvc *altsvc;
};

struct twist_hsts *twist_hsts_new (void);
void twist_hsts_free (struct twist_hsts *h);
int twist_hsts_note (struct twist_hsts *h, const char *host, uint64_t expiry);
int twist_hsts_upgrade (struct twist_hsts *h, const char *host, uint64_t now);

struct twist_altsvc *twist_altsvc_new (void);
void twist_altsvc_free (struct twist_altsvc *a);
int twist_altsvc_note (struct twist_altsvc *a, const char *origin,
                       const char *alt);
const char *twist_altsvc_lookup (struct twist_altsvc *a, const char *origin);

char *twist_strdup (const char *s);
void *twist_xmalloc (size_t n);

void twist_i18n_init (void);

void twist_easy_set_error (struct twist_easy *easy, char *msg);
int twist_easy_finish (struct twist_easy *easy, int result);
int twist_transfer_start (struct twist_easy *easy);

#endif /* TWIST_INT_H */
