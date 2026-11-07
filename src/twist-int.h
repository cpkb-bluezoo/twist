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

#include <pthread.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/types.h>

#define TWIST_IN_CEILING (256u * 1024u)
/* How much a connection is to hold that has been sent on it and not yet
   written: about a chunk, which is a TLS record.  The kernel's send buffer
   does the queuing; this holds only what it would not take.  A producer that
   sees twist_endpoint_full after a send stops producing and holds nothing but
   the chunk it has, and goes on from the endpoint's on_write_ready, which is
   called when the queue has been written.  */
#define TWIST_OUT_HIGH (16u * 1024u)

struct twist_loop;
struct twist_connection;
struct twist_timer;

/* How long making a connection may take, if nothing else is said: five
   minutes.  */
#define TWIST_DEFAULT_CONNECT_TIMEOUT_MS 300000L
struct twist_storage;
struct twist_upload;
struct twist_jar;
struct twist_hsts;
struct twist_altsvc;
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
  void *write_user;		/* Whose on_write_ready it is, if not user_data.  */
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

/* Seconds of history the "current speed" looks back over, plus one.  */
#define TWIST_PROGRESS_HISTORY 6

/* The counters of one transfer, and what the meter needs
   to draw itself.  src/engine/progress.c.  */
struct twist_progress
{
  int hide;			/* TWISTOPT_NOPROGRESS; 1 by default.  */
  FILE *err;			/* NULL: standard error.  */
  twist_xferinfo_callback xferinfo;
  void *xferinfo_data;
  int begun;			/* Between begin and end.  */
  int headers_out;		/* The two heading lines are written.  */
  int shown;			/* The meter has drawn at least once.  */
  int aborted;			/* The callback said stop.  */
  uint64_t start_ms;
  long long size_dl;
  long long size_ul;
  int dl_known;
  int ul_known;
  long long downloaded;
  long long uploaded;
  long long dlspeed;		/* Average, bytes a second.  */
  long long ulspeed;
  long long current_speed;	/* Over the last few seconds.  */
  long long timespent_us;
  long long lastshow;		/* The second of the last drawing; -1: none.  */
  unsigned draws;		/* Lines drawn since the counters began.  */
  long long hist_bytes[TWIST_PROGRESS_HISTORY];	/* Moved, at each draw.  */
  uint64_t hist_ms[TWIST_PROGRESS_HISTORY];
  struct twist_timer *tick;
  uint64_t tick_due;		/* A second after the last update.  */
};

struct twist_transfer
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
  char *ssh_knownhosts;
  char *ssh_hostpubsha256;
  char *keypasswd;
  long long resume_from;
  int dirlistonly;
  struct twist_slist *quote;	/* Borrowed: the caller's.  */
  struct twist_slist *postquote;
  struct twist_slist *telnet_options;	/* Borrowed too.  */
  int telnet_input_fd;		/* TWISTOPT_TELNET_INPUT_FD; -1: none.  */
  int create_missing_dirs;
  char *ssh_agent_socket;
  long timeout_ms;
  long connect_timeout_ms;
  char *proxy;
  /* Connect to this Unix socket, and not to the host and port of the URL: a
     path, or with unix_abstract a name in the abstract namespace.  */
  char *unix_path;
  int unix_abstract;
  /* TWISTOPT_USE_SSL.  */
  int use_ssl;
  int http_version;
  int dns_order[4];
  int dns_order_n;
  struct twist_origin_hint *origins;
  unsigned auth;
  char *range;
  char *referer;
  char *cookie;
  char *proxy_userpwd;
  char *noproxy;
  int noproxy_set;
  char *capath;
  char *proxy_cainfo;		/* For an https proxy; else cainfo.  */
  char *proxy_template_udp;
  int proxy_verifypeer;
  char *mail_from;
  struct twist_slist *mail_rcpt;
  char *doh_url;
  char *doq_url;
  char *dot_url;
  char *accept_encoding;
  char *content_encoding;
  int doh_verifypeer;
  int nobody;
  int append;
  int proxy_tunnel;
  int forbid_reuse;
  int fresh_connect;
  int failonerror;
  twist_write_callback write_cb;
  void *write_data;
  twist_write_callback header_cb;
  void *header_data;
  twist_read_callback read_cb;
  void *read_data;
  twist_seek_callback seek_cb;
  void *seek_data;
  /* The upload as a push source (twist_transfer_upload): made from read_cb
     when a handler first needs it, or set by whoever pushes.  */
  struct twist_upload *upload;
  /* The body going to the application can be paused (TWIST_WRITEFUNC_PAUSE):
     what comes meanwhile is held, and given again on resume.  PAUSE_FN and
     RESUME_FN are the handler's, to stop the peer where it can.  */
  int sink_paused;
  uint8_t *held;
  size_t held_len;
  size_t held_cap;
  void (*pause_fn) (struct twist_transfer *);
  void (*resume_fn) (struct twist_transfer *);
  /* The upload as the application pushes it, and the descriptors it gave.  */
  int push_upload;
  struct push_src *push_src;
  twist_want_callback want_cb;
  void *want_data;
  int read_fd;
  int write_fd;
  struct fd_wsink *wsink;
  /* The multipart body, and the boundary its Content-Type names.  */
  struct twist_form *form;
  char form_boundary[48];
  /* Bytes pushed to the upload from another thread than the one that runs the
     transfer, and the end, until the transfer's thread takes them.  */
  pthread_mutex_t xmu;
  uint8_t *xq;
  size_t xq_len;
  size_t xq_cap;
  int xq_posted;
  int xq_wanted;
  int xq_end;
  int xq_end_err;
  /* The end of the transfer waits for the body to be given and written.  */
  int gated;
  int gated_result;
  /* Whether the transfer uses the runtime's cookie jar, HSTS list and Alt-Svc
     list (TWISTOPT_USE_COOKIES, _USE_HSTS and _USE_ALTSVC).  */
  int use_cookies;
  int use_hsts;
  int use_altsvc;
  int pipewait;  /* TWISTOPT_PIPEWAIT.  */
  struct twist_runtime *runtime;
  struct twist_loop *loop;
  /* The loop's lane, and what a lane other than the first is told of the
     transfer: its place in the runtime's list, and the command that reports
     its end to the program (runtime.c).  */
  struct twist_lane *lane;
  unsigned long serial;
  struct twist_cmd *deliver_node;
  void *deliver;
  /* Told the result when the transfer ends (twist_runtime_start); and the
     timer that does it, from the loop, once the handler is out of the way.  */
  twist_done_callback done_cb;
  void *done_user;
  struct twist_timer *reap;
  /* In the list of a runtime because twist_runtime_start put it there.  A
     handler can be driven with the handle attached by hand, as a test does,
     and then the runtime has nothing to report.  */
  int started;
  int done;
  int result;
  int proto_status;
  char *error;
  long http_code;
  /* Set when a redirect took the transfer to a handler other than the one it
     began in: the credentials that were given for the first request are not
     to be sent, and the time left of --max-time is what is left.  */
  int creds_stripped;
  long hop_timeout_ms;
  int http_version_seen;	/* TWIST_HTTP_VERSION_* of the response.  */
  char *effective_url;
  char *content_type;
  size_t size_download;
  uint64_t max_recv_speed;
  uint64_t max_send_speed;
  void *private_data;
  void *state;
  void (*state_free) (void *state);
  uint64_t recv_stamp_ms;
  uint64_t recv_bytes_window;
  long long infilesize;		/* TWISTOPT_INFILESIZE; -1: not known.  */
  struct twist_progress progress;
};

struct twist_cmd;
struct twist_lane_live;
struct tunnel_hub;

/* One event loop of a runtime and what belongs to it alone: the connections it
   keeps and the sessions on them, which only its own thread touches.  The
   first lane is the program's, driven by twist_runtime_run_once; the others
   have a thread each.  */
struct twist_lane
{
  struct twist_runtime *runtime;
  int index;
  struct twist_loop *loop;
  struct twist_pool *pool;
  struct twist_session *sessions;
  struct tunnel_hub *hubs;	/* Connections to https proxies (tunnel.c).  */
  int in_call;			/* Of a lane but the first.  */
  pthread_t thread;
  int threaded;
  int stop;
  struct twist_cmd *stop_node;	/* Made with the lane, so that it can be sent.  */
  long load;			/* Transfers on it; the driving thread's.  */
  /* The transfers running on it, by serial: the lane thread's.  */
  struct twist_lane_live *live;
  size_t n_live;
  size_t live_cap;
};

/* A transfer that was started in a runtime, and what is to be told when it
   ends.  */
struct twist_started
{
  struct twist_transfer *transfer;
  unsigned long serial;
  twist_done_callback done_cb;
  void *done_user;
  char *place_key;
  int lane;
};

struct twist_runtime
{
  struct twist_loop *loop;
  /* Whether the program polls (twist_runtime_new_embedded): the loop then has
     no poller, and reports its descriptors and its deadline to these.  */
  int embedded;
  twist_watch_callback watch_cb;
  twist_timer_callback timer_cb;
  void *hook_user;
  struct twist_started *transfers;
  size_t n_transfers;
  size_t transfers_cap;
  unsigned long next_serial;
  long long last_deadline;
  /* How many calls into the application (write, header, progress, done and
     hook callbacks) are under way from this handle's loop.  While there is
     one, the loop is in use by the code that made it, and a transfer's own
     state may be, so the calls that run or free them are refused
     (TWIST_ERR_RECURSIVE).  Starting and cancelling transfers is not: it
     touches only the transfer.  */
  int in_call;
  struct twist_storage *storage;
  /* Reads and writes of regular files for transfers (twist_fio).  Apart from
     STORAGE, which loads keys and known_hosts, so that a read that does not
     return cannot hold up those loads.  Built as it is, and grown with it.  */
  struct twist_storage *xfer;
  /* A pool of its own for writers: a read waits for a write to give room, and
     a pool the two shared could be all readers, with the writers behind.  */
  struct twist_storage *xfer_w;
  struct twist_pool *pool;	/* The first lane's.  */
  struct twist_dns_cache *dns;
  /* The lanes, the first of which is the one above, and how many threads were
     asked for.  The others exist once a transfer has been started.  */
  struct twist_lane **lanes;
  size_t n_lanes;
  long threads;
  size_t rotate;		/* Where the search for a lane begins.  */
  int closing;
  /* What transfers that ask for them share: the cookies that servers set,
     the hosts that want https only, and the alternative services that
     servers offer.  */
  struct twist_jar *jar;
  struct twist_hsts *hsts;
  struct twist_altsvc *altsvc;
  /* What is known of each origin, and the limit on connections to one.  */
  struct twist_origintab *origintab;
  int started_any;		/* A transfer has been started in it.  */
};

struct twist_session_user;

struct twist_session
{
  char *key;
  struct twist_loop *loop;
  struct twist_connection *conn;
  struct twist_h2 *h2;
  int preface;
  struct twist_runtime *runtime;
  char *slot_key;		/* The connection it holds, against the limit.  */
  int closed;			/* The connection is gone.  */
  struct twist_session_user *users_head;	/* Those on it (http.c).  */
  struct twist_session *next;
};

struct twist_session *twist_session_add (struct twist_runtime *runtime,
                                         const char *key,
                                         struct twist_loop *loop,
                                         struct twist_connection *conn,
                                         struct twist_h2 *h2);
struct twist_session *twist_session_find (struct twist_runtime *runtime,
                                          const char *key,
                                          struct twist_loop *loop);
void twist_session_release (struct twist_session *session);
void twist_session_free_all (struct twist_runtime *runtime);
struct twist_lane *twist_lane_of_loop (struct twist_runtime *runtime,
                                       struct twist_loop *loop);
/* The connections to https proxies that tunnels share, at the end of the
   runtime.  */
void twist_tunnel_free_all (struct twist_runtime *runtime);

/* ---- origins ---- */

/* A transfer, or a session, that waits for an origin: either for a
   connection that is being made to it to say whether several transfers can
   share it (TWIST_WAIT_SESSION), or for room under the limit on connections
   to it (TWIST_WAIT_SLOT).  When what it waits for has come, RESUME is called
   with USER and the reason: the connection settled, or it was given a
   connection to make (which it then holds until it gives it back with
   twist_origintab_release), or a stream of a session is free and it may
   use that instead.  */
enum
{
  TWIST_WAIT_NONE = 0,
  TWIST_WAIT_SESSION,
  TWIST_WAIT_SLOT,
  TWIST_WAIT_GRANTED
};

enum
{
  TWIST_RESUME_SETTLED,
  TWIST_RESUME_GRANTED,
  TWIST_RESUME_WOKEN
};

/* The loop it waits on, and a command to post there, are the waiter's own, so
   that the callback needs nothing else.  */
struct twist_origin_waiter
{
  struct twist_origin_waiter *next;
  struct twist_origintab *tab;
  char *key;
  void (*resume) (void *user, int why);
  void *user;
  int state;
  struct twist_loop *loop;
  struct twist_cmd *node;
};

/* How a connection that was being made to an origin turned out.  */
enum
{
  TWIST_SETTLE_SHARED,		/* It carries several transfers.  */
  TWIST_SETTLE_H1,		/* It carries one at a time.  */
  TWIST_SETTLE_UNKNOWN		/* It failed, or was given up.  */
};

struct twist_origintab;

/* The key of the origin TRANSFER is going to: its loop, a bar, and then what
   twist_transfer_origin_okey makes, the scheme, host, port, and the proxy or
   Unix socket it goes through.  */
int twist_transfer_origin_key (struct twist_transfer *transfer, char *buf,
                               size_t cap);
int twist_transfer_origin_okey (struct twist_transfer *transfer, char *buf,
                                size_t cap);
/* Whether the transfer may share a connection with others to its origin
   (HTTP/2 or HTTP/3 may be had), from its options and URL alone.  */
int twist_http_may_multiplex (struct twist_transfer *transfer);
struct twist_origintab *twist_origintab_new (void);
void twist_origintab_free (struct twist_origintab *tab);
void twist_origintab_set_cap (struct twist_origintab *tab, long cap);
/* A connection that may carry several transfers is being made to KEY.  */
int twist_origintab_lead (struct twist_origintab *tab, const char *key);
/* False if a connection made to KEY has been found to carry one at a time, so
   that the next need not be waited for.  */
int twist_origintab_may_lead (struct twist_origintab *tab, const char *key);
/* Wait for the connection being made to KEY, if there is one: 1, and W is
   called when it settles; 0 if there is none.  */
int twist_origintab_park (struct twist_origintab *tab, const char *key,
                          struct twist_origin_waiter *w);
/* One such connection has settled: everyone who waits for KEY is told.  */
void twist_origintab_settle (struct twist_origintab *tab, const char *key,
                             int how);
/* Take a connection to KEY: 1 if it is given, 0 if W waits for one (at the
   head of the queue if FRONT), or an error.  */
int twist_origintab_acquire (struct twist_origintab *tab, const char *key,
                             struct twist_origin_waiter *w, int front);
/* Give a connection back.  */
void twist_origintab_release (struct twist_origintab *tab, const char *key);
/* The loop of the transfer that is next to be given a connection to KEY, if
   there is one that waits.  */
int twist_origintab_next_waiter (struct twist_origintab *tab, const char *key,
                                 struct twist_loop **loop);
/* A connection that holds a place is kept idle by LOOP, or is no longer idle
   (taken, or closed).  A transfer that has to wait for a place asks the table's
   evict callback to have one of the idle connections closed.  */
void twist_origintab_idle_add (struct twist_origintab *tab, const char *key,
                               struct twist_loop *loop);
void twist_origintab_idle_del (struct twist_origintab *tab, const char *key,
                               struct twist_loop *loop);
void twist_origintab_set_evict (struct twist_origintab *tab,
                                void (*evict) (void *user,
                                               struct twist_loop *loop,
                                               const char *key), void *user);
/* A stream of a session has ended: the first that waits for room may now
   have it.  */
void twist_origintab_wake (struct twist_origintab *tab, const char *key);
/* W stops waiting, or gives back what it was granted and did not take.  */
void twist_origintab_cancel (struct twist_origintab *tab,
                             struct twist_origin_waiter *w);
/* The key of a granted W, which it holds; W is then idle.  Free it.  */
char *twist_origin_waiter_take (struct twist_origin_waiter *w);
/* Which loop transfers to the origin OKEY that may share a connection go on:
   1 and *LANE if one has been chosen (and the transfer is counted on it); 0 if
   none has; -1 if the origin has been found not to share, so that its
   transfers go where they like.  twist_origintab_pin_set records a choice for
   a transfer, and unpin says that one is over.  */
int twist_origintab_pin (struct twist_origintab *tab, const char *okey,
                         int *lane);
int twist_origintab_pin_set (struct twist_origintab *tab, const char *okey,
                             int lane);
void twist_origintab_unpin (struct twist_origintab *tab, const char *okey);
/* A session to the origin of the per-loop KEY is opened (DELTA 1) or lost
   (-1); its origin stays on its loop while one is open.  */
void twist_origintab_session (struct twist_origintab *tab, const char *key,
                              int delta);

/* ---- loop ---- */

struct twist_loop *twist_loop_new (int external);
void twist_loop_free (struct twist_loop *loop);
/* One thing a user of the loop keeps on it (the ring of the file I/O), and how
   to free it when the loop is freed.  */
void *twist_loop_ext (struct twist_loop *loop);
void twist_loop_set_ext (struct twist_loop *loop, void *ext,
                         void (*ext_free) (void *));
void twist_loop_set_now (struct twist_loop *loop, uint64_t (*now_ms) (void *),
                         void *user);
uint64_t twist_loop_now (struct twist_loop *loop);
int twist_loop_run_once (struct twist_loop *loop);
int twist_loop_run_once_ms (struct twist_loop *loop, int wait_ms);
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
struct twist_cmd;
struct twist_cmd *twist_loop_cmd_new (void (*fn) (void *), void *user);
void twist_loop_cmd_post (struct twist_loop *loop, struct twist_cmd *cmd);
void twist_loop_cmd_free (struct twist_cmd *cmd);
void twist_loop_drain (struct twist_loop *loop);
/* Watch FD for INTEREST for CONN.  0, or an error if it cannot be watched: the
   poll set has no room, or FD is not a descriptor.  */
int twist_loop_watch_fd (struct twist_loop *loop, int fd, int interest,
                          struct twist_connection *conn);
void twist_loop_unwatch_fd (struct twist_loop *loop, int fd);
struct twist_runtime *twist_loop_runtime (struct twist_loop *loop);
void twist_loop_set_runtime (struct twist_loop *loop,
                             struct twist_runtime *runtime);
/* The count of calls into the program that this loop's work is part of.  */
void twist_loop_set_in_call (struct twist_loop *loop, int *in_call);
int twist_loop_waker (struct twist_loop *loop);
uint8_t *twist_loop_take_rbuf (struct twist_loop *loop);
void twist_loop_give_rbuf (struct twist_loop *loop, uint8_t *buf);

/* ---- connection ---- */

struct twist_connection *twist_connection_new (struct twist_loop *loop);
void twist_connection_free (struct twist_connection *conn);
struct twist_endpoint *twist_connection_endpoint (struct twist_connection *conn);
void twist_connection_set_handler (struct twist_connection *conn,
                                   const struct twist_protocol_handler *h);
void twist_connection_set_fd (struct twist_connection *conn, int fd);
/* A connection carried by something else, such as a tunnel through a proxy,
   has an owner: FREE_FN is called when the connection is freed (it must not
   free the connection), and RESUME_FN when the application resumes reading
   after pausing, so that what was held back can be given again.  */
void twist_connection_set_owner (struct twist_connection *conn, void *owner,
                                 void (*free_fn) (void *),
                                 void (*resume_fn) (void *));
int twist_connection_paused (const struct twist_connection *conn);
/* What half_close does on a connection with no descriptor (a tunnel): it is
   called, with the io user, once all that was queued has been written.  */
void twist_connection_set_shutdown (struct twist_connection *conn,
                                    void (*fn) (void *));
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
void twist_connection_hold_read (struct twist_connection *conn, int hold);
/* The most this connection reads and writes, in bytes a second, on average
   (0: no limit).  The limit is the connection's, not the transfer's: it is
   kept for as long as the connection is, by whatever uses it.  */
void twist_connection_set_rate (struct twist_connection *conn,
                                uint64_t recv_limit, uint64_t send_limit);
/* The limits that the transfer was given (--limit-rate), on a connection that
   is made for it.  */
static inline void
twist_connection_limit (struct twist_connection *conn,
                        const struct twist_transfer *transfer)
{
  twist_connection_set_rate (conn, transfer->max_recv_speed,
                             transfer->max_send_speed);
}
void twist_connection_force_write (struct twist_connection *conn, int force);
int twist_connection_queue_out (struct twist_connection *conn,
                                const uint8_t *data, size_t len);
int twist_connection_send_parts (struct twist_connection *conn,
                                 const uint8_t *a, size_t an,
                                 const uint8_t *b, size_t bn);
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
/* For tests: the most any connection has held of what was sent on it and not
   written, since the last reset.  */
size_t twist_connection_peak_out (void);
void twist_connection_peak_reset (void);
/* Whether EP's connection holds as much as it should (TWIST_OUT_HIGH) of what
   was sent on it and has not been written: the producer waits for on_write_ready
   before it sends more.  */
int twist_endpoint_full (const struct twist_endpoint *ep);
/* Send a body that is produced as it is wanted, and not all at once: the
   producer's side of the backpressure, for a source that is one stream of
   bytes.  READ is called for up to CAP bytes (a chunk) only when less than
   TWIST_OUT_HIGH is queued, so a peer that does not read does not make it
   read ahead, and returns how many it put in BUF; 0 is the end, and
   (size_t) -1 is a failure.  END is called exactly once when the stream is
   over: with TWIST_OK after the last byte is queued (not written), or with why
   it did not get that far (the connection failed, or was freed, first); if
   READ fails, END is called and then the connection is failed
   (TWIST_ERR_ABORTED), as for any error.  The handler
   sends nothing else on the connection meanwhile: what it has to send after
   the body it sends from END.  One stream at a time.  END must not free the
   connection.  */
typedef size_t (*twist_stream_read_fn) (void *user, uint8_t *buf, size_t cap);
typedef void (*twist_stream_end_fn) (void *user, int err);
int twist_connection_stream (struct twist_connection *conn,
                             twist_stream_read_fn read,
                             twist_stream_end_fn end, void *user);
/* A source the producer pushes into.  The producer calls twist_connection_push
   for each chunk and twist_connection_push_end when there is no more; it does
   not wait to be asked.  The connection calls PAUSE when it holds
   TWIST_OUT_HIGH of what has not been written, and RESUME from the write path
   once it holds less; between the two the producer pushes nothing more (one
   chunk that was already under way is taken, and the connection holds no more
   than a chunk past TWIST_OUT_HIGH).  END is called exactly once, whoever
   ends it: with TWIST_OK when the producer ended it after the last chunk was
   queued (not written), or with why it did not get that far (the producer
   failed, or the connection failed or was freed first).  END must not free the
   connection.  RESTART begins the source again from the first byte; it may be
   NULL, or fail, and then twist_connection_source_restart reports
   TWIST_ERR_REWIND.  PAUSE and RESUME may push (RESUME usually does).  One
   source, or one twist_connection_stream, at a time.  */
struct twist_source_ops
{
  void (*pause) (void *user);
  void (*resume) (void *user);
  int (*restart) (void *user);
  void (*end) (void *user, int err);
};
int twist_connection_attach_source (struct twist_connection *conn,
                                    const struct twist_source_ops *ops,
                                    void *user);
/* Queue CHUNK as body.  RELEASE, if not NULL, is called with REL_USER once the
   connection no longer needs CHUNK; the connection is free to call it before
   this returns, and the producer reuses the buffer only after it.  */
int twist_connection_push (struct twist_connection *conn, const uint8_t *chunk,
                           size_t len, void (*release) (void *),
                           void *rel_user);
/* As twist_connection_push, with framing before and after CHUNK that is not
   body (a chunk header and trailer): all of it is queued before the source is
   paused or not.  */
int twist_connection_push_framed (struct twist_connection *conn,
                                  const uint8_t *head, size_t head_len,
                                  const uint8_t *chunk, size_t len,
                                  const uint8_t *tail, size_t tail_len);
void twist_connection_push_end (struct twist_connection *conn, int err);
/* Begin the attached source again.  TWIST_ERR_REWIND if it cannot.  */
int twist_connection_source_restart (struct twist_connection *conn);
/* Whether the attached source has been told to pause and not resumed.  */
int twist_connection_source_paused (const struct twist_connection *conn);
/* As twist_endpoint_send, for bytes that are body: the connection counts them
   apart from framing (chunk headers, protocol commands), which are sent with
   twist_endpoint_send.  */
int twist_connection_send_body (struct twist_connection *conn,
                                const uint8_t *data, size_t len);
/* How many body bytes the socket has accepted: not those still queued, and no
   framing.  On a connection that encrypts, a record that is partly written
   counts in proportion.  */
uint64_t twist_connection_body_written (const struct twist_connection *conn);

/* A sink that takes a slice and may pause.  TAKE is given DATA and LEN and
   returns how many bytes it used; fewer than LEN is a pause, and it calls
   twist_sink_resume when it can take more.  A handler gives what it has
   received to twist_sink_feed and returns that count from receive.  The
   connection holds the tail and presents it again on resume.  HTTP/2 and
   HTTP/3 pause one stream and do not use this.  */
struct twist_sink
{
  size_t (*take) (void *user, const uint8_t *data, size_t len);
  void *user;
  struct twist_endpoint *ep;
  int paused;
};
size_t twist_sink_feed (struct twist_sink *sink, struct twist_endpoint *ep,
                        const uint8_t *data, size_t len);
void twist_sink_resume (struct twist_sink *sink);

/* ---- descriptors that can be waited for ----
   A pipe, a socket or a terminal can be polled; a regular file cannot, and
   goes through the file pipeline (twist_fio) instead.  A descriptor that was
   inherited is not twist's to make non-blocking, because it shares its open
   file description with whoever else holds it.  So these watch a duplicate,
   which freeing does not close the caller's descriptor with, and never
   set O_NONBLOCK: a read is made only after poll has said, with a zero
   timeout, that there is something to read, and a write only after it has said
   there is room, and of no more than PIPE_BUF bytes, which POSIX guarantees
   can be written without waiting.

   None of these is to be freed from inside one of its own callbacks: pause it,
   and free it after.  */

/* One read of FD or one write to it that never waits: -1 with EAGAIN if
   poll says it would (or EPIPE for a write when the other end has gone).  */
ssize_t twist_fd_read_nowait (int fd, uint8_t *buf, size_t len);
ssize_t twist_fd_write_nowait (int fd, const uint8_t *data, size_t len);

/* A source: what arrives is given to CHUNK, which returns how many bytes it
   used.  Fewer than LEN is a pause (as for twist_sink), and the source goes on
   from twist_fd_source_resume.  END is called once: with TWIST_OK when the
   descriptor reaches its end, and otherwise with why it failed.  */
struct twist_fd_source;
struct twist_fd_source_ops
{
  size_t (*chunk) (void *user, const uint8_t *data, size_t len);
  void (*end) (void *user, int err);
};
int twist_fd_source_new (struct twist_loop *loop, int fd,
                         const struct twist_fd_source_ops *ops, void *user,
                         struct twist_fd_source **out);
void twist_fd_source_pause (struct twist_fd_source *s);
void twist_fd_source_resume (struct twist_fd_source *s);
void twist_fd_source_free (struct twist_fd_source *s);

/* A sink: bytes written are held and go out as the descriptor takes them.
   twist_fd_sink_full says when about a chunk (TWIST_OUT_HIGH) is held, and
   the writer waits for READY, which is called when all that was held has gone.
   ERROR is called if the descriptor fails (such as the reader having gone).  */
struct twist_fd_sink;
struct twist_fd_sink_ops
{
  void (*ready) (void *user);
  void (*error) (void *user, int err);
};
int twist_fd_sink_new (struct twist_loop *loop, int fd,
                       const struct twist_fd_sink_ops *ops, void *user,
                       struct twist_fd_sink **out);
int twist_fd_sink_write (struct twist_fd_sink *s, const uint8_t *data,
                         size_t len);
int twist_fd_sink_full (const struct twist_fd_sink *s);
size_t twist_fd_sink_pending (const struct twist_fd_sink *s);
void twist_fd_sink_free (struct twist_fd_sink *s);

/* ---- the upload of a transfer ----
   What a handler sends as the body of an upload comes from a push source:
   the producer pushes chunks, the handler (the consumer) takes them and may
   pause the producer while it cannot send, then resume it.  The handler never
   calls the application's read callback itself.  Where the application gave a
   read callback (TWISTOPT_READFUNCTION) the transfer's source is an adapter
   that calls it, on the loop's thread, only while the consumer has not paused
   it, so that a callback that returns at once behaves as it always has.

   The consumer's CHUNK is given a slice that is valid for the call; it takes
   it, or returns an error, which ends the source with it.  END is called once,
   with TWIST_OK after the last chunk, or why the source failed (TWIST_ERR_ABORTED
   where the read callback said to stop).  A chunk may arrive once after PAUSE,
   if the producer was already under way.  The consumer sets the most it will
   take at once (MAX) and the producer pushes no more than that.  */
struct twist_upload_consumer
{
  int (*chunk) (void *user, const uint8_t *data, size_t len);
  void (*end) (void *user, int err);
};
struct twist_upload_producer
{
  void (*resume) (void *user);	/* Push while not paused.  */
  void (*pause) (void *user);
  int (*restart) (void *user);	/* From the first byte; 0 or an error.  */
  void (*release) (void *user);
  /* Advance past the first N bytes without pushing them (to resume an upload
     at an offset): 0, or an error if the source is shorter.  May be NULL.  */
  int (*skip) (void *user, long long n);
  /* The consumer has gone (the transfer ended, or failed): stop reading, so
     that a reader waiting to hand over a chunk is let go.  May be NULL.  */
  void (*stop) (void *user);
};
struct twist_upload *twist_upload_new (const struct twist_upload_producer *p,
                                       void *user);
void twist_upload_free (struct twist_upload *up);
/* The producer's calls.  */
int twist_upload_push (struct twist_upload *up, const uint8_t *data,
                       size_t len);
void twist_upload_finish (struct twist_upload *up, int err);
/* The consumer's calls.  attach fails if a consumer is attached; detach is
   that consumer going, and nothing is called back after it.  */
int twist_upload_attach (struct twist_upload *up,
                         const struct twist_upload_consumer *c, void *user,
                         size_t max);
void twist_upload_detach (struct twist_upload *up);
void twist_upload_pause (struct twist_upload *up);
void twist_upload_resume (struct twist_upload *up);
size_t twist_upload_max (const struct twist_upload *up);
/* Whether a consumer is attached and has not paused the source or seen it
   end: the producer may push.  */
int twist_upload_active (const struct twist_upload *up);
/* Begin the source again from the first byte: TWIST_ERR_REWIND if it cannot.  */
int twist_upload_restart (struct twist_upload *up);
/* Advance the upload past its first N bytes, before anything is pushed.  A
   source that cannot do it, or is shorter, is TWIST_ERR_RESUME.  */
int twist_upload_skip (struct twist_upload *up, long long n);
/* A source over memory, which is not copied and is to outlive it.  */
struct twist_upload *twist_upload_from_memory (const uint8_t *data, size_t len);

/* What an upload to a connection has taken to the meter: the body bytes the
   connection has written since the upload began, which is what the meter
   shows, and not the framing or what is still queued.  */
struct twist_upmeter
{
  struct twist_transfer *transfer;
  struct twist_connection *conn;
  uint64_t base;
  uint64_t reported;
};
void twist_upmeter_start (struct twist_upmeter *m, struct twist_transfer *t,
                        struct twist_connection *conn);
void twist_upmeter_sync (struct twist_upmeter *m);
/* For the connection: whom to tell the last count when it is freed.  */
void twist_connection_set_meter (struct twist_connection *conn,
                                 struct twist_upmeter *m);

/* An upload sent over a connection as it is pushed, with the source paused
   while the connection is full.  CHUNK, if not NULL, replaces the plain
   queueing of a chunk (a handler that transforms or frames it); it sends with
   twist_relay_push.  FINISH is called after the last chunk, before the end is
   queued (a trailer).  END is called once, with TWIST_OK when all was queued
   and with why it did not, and the relay is gone after it.  A failure of the
   connection ends the relay without notice to the caller beyond END.  With no
   connection (a handler driven by a test) EP, if not NULL, is sent to.  */
struct twist_relay;
struct twist_relay_ops
{
  int (*chunk) (void *user, struct twist_relay *r, const uint8_t *data,
                size_t len);
  int (*finish) (void *user, struct twist_relay *r);
  void (*end) (void *user, int err);
};
int twist_relay_start (struct twist_connection *conn, struct twist_endpoint *ep,
                       struct twist_upload *up, int own_up, size_t max,
                       const struct twist_relay_ops *ops, void *user,
                       struct twist_upmeter *meter);
int twist_relay_push (struct twist_relay *r, const uint8_t *data, size_t len);
/* From CHUNK or FINISH: the upload is complete now (no more is wanted from the
   source), or has failed for ERR.  The relay is gone after either, and the
   operation returns at once.  An operation that returns an error, as when a
   push has failed, also leaves the relay gone.  */
void twist_relay_done (struct twist_relay *r);
void twist_relay_abort (struct twist_relay *r, int err);

/* The transfer's upload: the one set, or an adapter over its read callback
   (made once).  NULL if there is neither.  */
struct twist_upload *twist_transfer_upload (struct twist_transfer *transfer);

/* Tell the peer there is no more to come: the write side is shut once all that
   was queued has been written, and the connection stays open for what the
   peer still says.  */
void twist_connection_half_close (struct twist_connection *conn);
/* Whether a stream is under way on CONN: the body of a request is not all
   sent, so the connection is not one to keep for another request.  */
int twist_connection_streaming (const struct twist_connection *conn);
/* How many bytes sent on EP the connection has not yet written.  A handler
   that sends without limit, such as one that copies standard input, stops when
   this is large and goes on from EP's on_write_ready.  */
size_t twist_endpoint_pending (const struct twist_endpoint *ep);
void twist_endpoint_close (struct twist_endpoint *ep);
void twist_endpoint_pause_read (struct twist_endpoint *ep);
void twist_endpoint_resume_read (struct twist_endpoint *ep);
struct twist_loop *twist_endpoint_loop (struct twist_endpoint *ep);
int twist_connection_start_tls (struct twist_connection *conn,
                                const char *server_name, int verify,
                                const char *const *alpn, size_t n_alpn,
                                const char *cafile, const char *capath,
                                const char *certfile, const char *keyfile);
/* Before TLS starts on CONN: the server's certificate must be valid for NAME
   as well as for the name TLS is started with.  NULL clears it.  */
int twist_connection_require_name (struct twist_connection *conn,
                                   const char *name);
/* As twist_connection_start_tls, offering the TLS session of SESSION_FROM,
   if it has one, so that the handshake resumes it.  The peer authenticated
   in that session is the one authenticated here, so it is for the same
   server name only.  */
int twist_connection_start_tls_resuming (struct twist_connection *conn,
                                         struct twist_connection *session_from,
                                         const char *server_name, int verify,
                                         const char *const *alpn, size_t n_alpn,
                                         const char *cafile, const char *capath,
                                         const char *certfile,
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
  const char *capath;
  const char *certfile;
  const char *keyfile;
  /* A connection whose TLS session is offered for resumption, if it has one
     (a data connection that resumes the session of its control connection,
     which FTPS servers commonly insist on).  NULL: a full handshake.  */
  struct twist_connection *resume_from;
  /* A second name the certificate must be valid for: the address of the
     resolver that a DoT or DoQ resolver was discovered from (RFC 9462,
     section 4.2).  NULL: only SERVER_NAME.  */
  const char *also_name;
};

struct gq_tls_config;
struct gq_tls_info;
struct gq_trust;

/* The certificate authorities for a connection: CAFILE and CAPATH, or the
   environment's, or the system's (tls/trust.c).  */
int twist_trust_load (struct gq_trust *trust, const char *cafile,
                      const char *capath, int verify);
/* SSLKEYLOGFILE: whether it is set, and the callback that writes a line to it
   (gq_tls_config.keylog).  */
/* Accepts any chain (gq_tlsconn_events.verify_peer, gq_conn_events.verify_peer):
   for -k, which is not to check the peer.  */
int twist_verify_accept (void *user, const gq_slice *chain, size_t n,
                         const char *server_name);
/* Whether CHAIN (N DER certificates, leaf first) is valid against TRUST for
   NAME and, if ALSO is not NULL, for ALSO as well (a DNS name, or an IP
   address as text).  0 if so, nonzero if not.  The callback of a handshake
   that has to prove two identities, as a resolver found by discovery does.  */
int twist_verify_chain_names (const struct gq_trust *trust,
                              const gq_slice *chain, size_t n,
                              const char *name, const char *also);
int twist_keylog_wanted (void);
void twist_keylog_write (void *user, const char *line);
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
                                       const uint8_t *data, size_t len);/* The transport reached end of file on a connection that runs TLS.  TWIST_OK
   if the peer closed it with a close_notify, and TWIST_ERR_TLS if not: what
   was read is then not known to be all of it, since a FIN can be forged
   (RFC 8446, section 6.1).  */
extern int (*twist_tls_eof_fn) (struct twist_connection *conn);
/* A QUIC connection for the transfer TRANSFER to the address ADDR and PORT,
   which a lookup gave.  The certificate is checked against the host of the
   URL, not against ADDR.  */
extern int (*twist_quic_connect_fn) (struct twist_transfer *transfer,
                                     const struct twist_dns_addr *addr,
                                     int port, struct twist_connection **out);
/* What a QUIC connection can be asked for besides the usual.  DATAGRAMS: DATAGRAM
   frames (RFC 9221) are accepted, and HTTP/3 says H3_DATAGRAM (RFC 9297).  SEND:
   the UDP datagrams do not go to a socket but to this, which is a carrier such
   as a CONNECT-UDP tunnel (masque.c); the connection has no descriptor, and the
   datagrams that come back are given to twist_quic_feed.  */
struct twist_quic_opts
{
  /* A second name the certificate must be valid for (RFC 9462, section 4.2),
     or NULL.  */
  const char *also_name;
  int datagrams;
  int (*send) (void *user, const uint8_t *data, size_t len);
  void *send_user;
};

int twist_quic_dial (struct twist_loop *loop, const char *server_name,
                     const char *alpn, const struct twist_dns_addr *addr,
                     int port, const char *cafile, const char *capath,
                     const char *certfile, const char *keyfile, int verify,
                     const struct twist_quic_opts *opts,
                     struct twist_connection **out);
/* Datagrams of a QUIC connection made with opts->datagrams: send one, the
   largest that can be sent now (0: not allowed yet), and who is given the
   ones that arrive.  */
uint64_t twist_quic_stream_id (struct twist_connection *conn);
const char *twist_quic_server_name (struct twist_connection *conn);
/* What is to be done with data on the stream ID of a QUIC connection that this
   side is the client of, when KNOWN is whether a stream was opened for it
   here.  0: it is a stream of the transfer, as ever.  1: ignore it: a
   unidirectional stream of the server (its control stream, QPACK's).  2: the
   connection is to be closed with H3_STREAM_CREATION_ERROR (RFC 9114, section
   6.1): a bidirectional stream opened by the server, which HTTP/3 does not
   have.  */
int twist_quic_stream_action (uint64_t id, int known);
int twist_quic_datagram_send (struct twist_connection *conn,
                              const uint8_t *data, size_t len);
size_t twist_quic_datagram_max (struct twist_connection *conn);
void twist_quic_on_datagram (struct twist_connection *conn,
                             void (*cb) (void *user, const uint8_t *data,
                                         size_t len),
                             void *user);
/* A datagram that came from the carrier of a connection made with
   opts->send; it is a copy, since QUIC decrypts in place.  */
void twist_quic_feed (struct twist_connection *conn, const uint8_t *data,
                      size_t len);
int twist_quic_open_stream (struct twist_connection *conn);
int twist_quic_can_open (struct twist_connection *conn);
/* Whether the current stream holds as much as it should (TWIST_OUT_HIGH) of
   what was sent on it and the flow control has not yet taken; and who to tell
   (CB, once the stream has written it) so that the producer goes on.  */
int twist_quic_stream_full (struct twist_connection *conn);
void twist_quic_on_drained (struct twist_connection *conn, void (*cb) (void *),
                            void *user);
void twist_quic_bind (struct twist_connection *conn,
                      size_t (*on_data) (void *, const uint8_t *, size_t, int),
                      void *user);

int twist_tls_register (void);
int twist_quic_register (void);
void twist_quic_hold_stream (struct twist_connection *conn);
/* Withhold the receive credit of one stream: the peer stops on it, and the
   connection and its other streams go on.  TWIST_ERR_UNSUPPORTED if the QUIC
   library has no way.  */
int twist_quic_hold_recv (struct twist_connection *conn, uint64_t id, int hold);
int twist_quic_finish_stream (struct twist_connection *conn);

/* ---- storage ---- */


struct twist_storage *twist_storage_new (size_t threads, size_t bound);
void twist_storage_free (struct twist_storage *st);
int twist_storage_submit (struct twist_storage *st, void (*work) (void *),
                          void *arg, void (*done) (void *user, int err),
                          void *user, struct twist_loop *loop);
size_t twist_storage_threads (const struct twist_storage *st);
/* How many jobs are waiting for a thread.  */
size_t twist_storage_queued (struct twist_storage *st);

/* ---- regular files on the storage pool ----
   A regular file cannot be polled (it is always ready, and O_NONBLOCK does
   nothing), so its reads and writes are jobs on a pool.  One job is a worker
   for the life of the transfer.  It moves chunks of TWIST_FIO_CHUNK with at
   most TWIST_FIO_PIPELINE unacknowledged: a chunk is acknowledged when the
   loop has finished with it, and a worker that has that many outstanding
   waits.  Everything the worker has to say goes to the loop as a command.  A
   twist_fio is used on the loop's thread only.

   twist_fio_free returns at once and does not join the worker, whose read may
   never return.  Nothing is called back after it.  The record is freed by
   whichever of the loop and the worker is the last to be done with it.  There
   is no cancellation of a read that is under way; it holds a worker of the
   pool until it returns.  A full queue fails the submit at once.  */
#define TWIST_FIO_CHUNK 16384
#define TWIST_FIO_PIPELINE 4
struct twist_fio;

/* Reading.  OPEN runs on the worker, and gives the descriptor, the offset to
   start at and how many bytes to read (-1: to the end); *OWN is set if the
   reader is to close the descriptor; MSG may be set to a message for the
   transfer (it is owned by the reader from then).  CHUNK, SIZE and END run
   on the loop.  SIZE is called once, before the first chunk, if the length is
   known.  DATA is the callee's to use for the call (it may be written to).  A CHUNK
   that returns an error ends the read with it.  END is called
   once, after the last chunk, with MSG owned by the callee (or NULL).  */
struct twist_fio_read_ops
{
  int (*open) (void *user, int *fd, int *own, long long *start,
               long long *length, char **msg);
  void (*size) (void *user, long long size);
  int (*chunk) (void *user, uint8_t *data, size_t len);
  void (*end) (void *user, int err, char *msg);
  /* The record is done with: called once, from whichever thread is last to
     be, never when the read could not be begun.  USER is freed here.  */
  void (*release) (void *user);
};
int twist_fio_read_new (struct twist_loop *loop, struct twist_storage *st,
                        const struct twist_fio_read_ops *ops, void *user,
                        struct twist_fio **out);
/* Hold back chunks (they stay unacknowledged, so the worker stops after
   TWIST_FIO_PIPELINE of them) and deliver them again on resume.  */
void twist_fio_pause (struct twist_fio *f);
void twist_fio_resume (struct twist_fio *f);

/* Writing.  The file at PATH is created, and truncated or (APPEND) appended
   to, on the worker.  CREDIT is called when a chunk has been written and
   there is room for another.  END is called once, when the file is closed
   after twist_fio_write_end or when the write has failed, with MSG owned by
   the callee (or NULL).  */
struct twist_fio_write_ops
{
  void (*credit) (void *user);
  void (*end) (void *user, int err, char *msg);
  void (*release) (void *user);	/* As for reading.  */
};
int twist_fio_write_new (struct twist_loop *loop, struct twist_storage *st,
                         const char *path, int append,
                         const struct twist_fio_write_ops *ops, void *user,
                         struct twist_fio **out);
int twist_fio_write_fd_new (struct twist_loop *loop, struct twist_storage *st,
                            int fd, long long at,
                            const struct twist_fio_write_ops *ops, void *user,
                            struct twist_fio **out);
/* Queue LEN (at most TWIST_FIO_CHUNK) bytes, copied: TWIST_OK, 1 if there is
   no room (CREDIT says when there is), or why the write has failed.  */
int twist_fio_write (struct twist_fio *f, const uint8_t *data, size_t len);
/* No more will be written; the file is closed once what was queued is.  */
void twist_fio_write_end (struct twist_fio *f);

void twist_fio_free (struct twist_fio *f);

/* The same calls through io_uring (reactor/uringio.c), which the ones above
   dispatch to for a loop that can have a ring (liburing, Linux, and a kernel
   and sandbox that allow it; TWIST_NO_URING in the environment says no).  A
   twist_fio of that kind begins with TWIST_UIO_MAGIC, and is freed before its
   loop.  There is no worker: the open of a file to read is one short job of the
   pool, and the rest is the loop's thread and the kernel.  */
#define TWIST_UIO_MAGIC 0x75696f01
int twist_uio_usable (struct twist_loop *loop, struct twist_storage *st);
int twist_uio_is (const struct twist_fio *f);
int twist_uio_read_new (struct twist_loop *loop, struct twist_storage *st,
                        const struct twist_fio_read_ops *ops, void *user,
                        struct twist_fio **out);
int twist_uio_write_fd_new (struct twist_loop *loop, struct twist_storage *st,
                            int fd, long long at,
                            const struct twist_fio_write_ops *ops, void *user,
                            struct twist_fio **out);
int twist_uio_write (struct twist_fio *f, const uint8_t *data, size_t len);
void twist_uio_write_end (struct twist_fio *f);
void twist_uio_pause (struct twist_fio *f);
void twist_uio_resume (struct twist_fio *f);
int twist_uio_inflight (struct twist_fio *f);
void twist_uio_free (struct twist_fio *f);
/* For tests: how many chunks are unacknowledged.  */
int twist_fio_inflight (struct twist_fio *f);

/* ---- url, scheme, dns, cache, proxy ---- */

int twist_url_parse_int (const char *input, struct twist_url **out);
void twist_url_free_int (struct twist_url *url);
int twist_url_resolve_int (const struct twist_url *base, const char *ref,
                           struct twist_url **out);
char *twist_url_format (const struct twist_url *url);
char *twist_url_effective (const struct twist_url *url);
/* The host of URL as it is written in a URL or a Host header: an IPv6
   address in brackets.  WITH_ZONE keeps the interface of a link-local address
   (encoded, as RFC 6874 has it), and a Host header does not name one.  */
int twist_url_host_text (const struct twist_url *url, int with_zone, char *buf,
                         size_t cap);
/* Absolute-form request target without userinfo.  */
int twist_url_proxy_target (const struct twist_url *url, char *buf, size_t cap);
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
  int (*attach) (struct twist_transfer *transfer);
};

const struct twist_scheme *twist_scheme_by_name (const char *name);
int twist_scheme_unsupported (struct twist_transfer *transfer);
int twist_http_attach (struct twist_transfer *transfer);
int twist_file_attach (struct twist_transfer *transfer);
int twist_file_check_url (const char *host, const char *path, int path_set);
int twist_ftp_attach (struct twist_transfer *transfer);
int twist_smtp_attach (struct twist_transfer *transfer);
int twist_pop3_attach (struct twist_transfer *transfer);
int twist_imap_attach (struct twist_transfer *transfer);

struct twist_ftp;
struct twist_ftp *twist_ftp_new (struct twist_transfer *transfer, int live);
void twist_ftp_free (void *ftp);
size_t twist_ftp_receive (struct twist_ftp *ftp, const uint8_t *data, size_t len);
size_t twist_ftp_data (struct twist_ftp *ftp, const uint8_t *data, size_t len);
void twist_ftp_data_eof (struct twist_ftp *ftp);
const char *twist_ftp_command (const struct twist_ftp *ftp);
void twist_ftp_tls_done (struct twist_ftp *ftp);
int twist_ftp_data_port (const struct twist_ftp *ftp);
const char *twist_ftp_data_host (const struct twist_ftp *ftp);
/* Whether the data connection is to be protected (PROT P, RFC 4217): the
   server has agreed, so the data connection runs TLS before any transfer
   command is sent on the control connection.  */
int twist_ftp_data_protected (const struct twist_ftp *ftp);

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
  /* The interface a link-local IPv6 address is reached by, from a zone
     (fe80::1%eth0); 0 for any other address.  */
  unsigned scope_id;
};

/* Data connection uses the control peer.  port is the 227 port.  */
int twist_ftp_data_addr (const struct twist_dns_addr *peer, int port,
                         struct twist_dns_addr *out);
void twist_ftp_set_peer (struct twist_ftp *ftp, const struct twist_dns_addr *peer);

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
  void (*ttl) (void *user, uint32_t ttl);
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
/* QR set, id matches, and the first question name matches.  */
int twist_dns_response_ok (const uint8_t *msg, size_t len, uint16_t id,
                           const char *name);
/* Two-byte length prefix.  zero_id clears the DNS id (DoQ).  */
int twist_dns_frame_stream (const uint8_t *msg, size_t len, int zero_id,
                            uint8_t **out, size_t *outlen);
int twist_dns_decode (const uint8_t *msg, size_t len, int qtype,
                      struct twist_dns_addr **out, size_t *n);
int twist_dns_parse_order (const char *text, int *out, size_t cap, size_t *n);
int twist_dns_transport_plan (const int *user, size_t nuser, int *out,
                              size_t cap, size_t *n);

/* The hosts file, which a name is looked for in before any DNS is asked: one
   address and one or more names a line, # to the end of the line a comment.
   The first IPv4 address a name has is its answer, or else the first IPv6
   one; an address with a zone (fe80::1%lo0) is taken if the interface is
   there.  Returns 1 and fills OUT, or 0: the name is not in it, or there is
   no file.  The file is read again when it changes.  PATH is the file, or NULL
   for the resolver's: /etc/hosts, or what twist_dns_set_hosts_file says (which
   is for tests).  */
int twist_hosts_lookup (const char *path, const char *host,
                        struct twist_dns_addr *out);
/* 1 and the address in OUT if HOST is one (an IPv4 address, or an IPv6 one
   with or without a zone that is an interface of this machine), else 0.  */
int twist_dns_literal (const char *host, struct twist_dns_addr *out);
/* As twist_hosts_lookup, but both of the name's addresses if it has them: the
   IPv6 one first.  Returns how many (0 to 2).  */
int twist_hosts_lookup_all (const char *path, const char *host,
                            struct twist_dns_addr out[2]);
/* As twist_dns_local_name, but ::1 and then 127.0.0.1.  */
int twist_dns_local_addrs (const char *host, struct twist_dns_addr out[2]);
void twist_dns_set_hosts_file (const char *path);
/* "localhost" and any name under it are the loopback (RFC 6761), and are not
   looked up anywhere else.  Returns 1 and fills OUT, or 0.  */
int twist_dns_local_name (const char *host, struct twist_dns_addr *out);

struct twist_dns_service
{
  struct twist_dns_addr addr;
  int nalpn;
  char alpn[4][16];
  int port;
  int have_https;
};

/* A name is asked for and the answers are given as they come, by callbacks
   that are called one after another, a call for each record, as gumdrop's
   BatchQueryCallback is: not a list at the end, but the first address as soon
   as it can be used, and the rest as they arrive.  The queries (AAAA, A, and
   HTTPS if it is wanted) go out together as separate queries in one flight, so
   all of it takes one round trip; how they are carried is not visible here.
   RFC 8305, section 3 says when:

   address    An address to try, an A or AAAA record's (family says which), one
              call each, in the order to try them in.  The first is given when
              it can be: at once when an AAAA answer has addresses, and, when an
              A answer has and no AAAA answer has come, once the resolution
              delay (50 ms) has passed since it.  When both are there at that
              time the families take turns, IPv6 first.  What comes later is
              given when it comes, after what has been given.
   https      The HTTPS record: its ALPN ids and port, once, when it is wanted
              and there is one.
   type_error One of the types (1, 28, 65) gave nothing: err is why.  The others
              go on, and a name with only IPv6 addresses is one where A did.
   complete   Last, once.  err is TWIST_OK if an address was given, and else the
              reason there was none.  Nothing is called after it.  */
struct twist_dns_sink
{
  void *user;
  void (*address) (void *user, const struct twist_dns_addr *addr);
  void (*https) (void *user, const struct twist_dns_service *svc);
  void (*type_error) (void *user, int qtype, int err);
  void (*complete) (void *user, int err);
};

struct twist_dns_cache;

/* Ask for HOST.  TWIST_OK means the callbacks will be called (some before this
   returns: an address, the hosts file, localhost).  Anything else, none will.
   SINK is copied.  The transfer's variant uses its DNS options, its cache and
   its timeout.  */
int twist_dns_resolve_sink (struct twist_loop *loop, const char *host,
                            const int *order, size_t norder, int want_https,
                            struct twist_dns_cache *cache,
                            const struct twist_dns_sink *sink);
int twist_dns_resolve_sink_transfer (struct twist_transfer *transfer,
                                     const char *host, int want_https,
                                     const struct twist_dns_sink *sink);
/* A connection made by racing the addresses of a name (RFC 8305, section 5).
   The first address is tried at once; the next after the connection attempt
   delay (250 ms), or at once if the attempt before it fails, without giving up
   the earlier ones; the first to connect is the connection, and the others are
   closed.  Addresses can be added as they are found (a late AAAA answer), in
   the order they are to be tried in.  When all are tried and none connected the
   TARGET connection fails as a connection that could not be made does, with
   TWIST_ERR_CONNECT, or with TWIST_ERR_TIMEOUT when the transfer's connect
   timeout passes first.  The winner's socket is given to TARGET, whose
   handler is then told it is connected.

   twist_race_free must be called before TARGET is freed, and may be called
   from any callback: what it frees is freed later, from the loop.  */
struct twist_race;
typedef void (*twist_race_fail_fn) (void *user, int err);
struct twist_race *twist_race_new (struct twist_transfer *transfer,
                                   struct twist_connection *target, int port);
int twist_race_add (struct twist_race *race, const struct twist_dns_addr *addr);
/* No more addresses are coming.  */
void twist_race_end (struct twist_race *race);
/* Resolve HOST (the sink, with its resolution delay) and race what it gives.
   *SLOT is the race, set before anything can happen, since the target can be
   connected, and its handler run, before this returns.  If the name gives
   nothing, FAIL is called with why, later, and TARGET is not touched.  The
   return is TWIST_OK, or why the lookup could not be begun (no race, then).  */
int twist_race_dial (struct twist_transfer *transfer,
                     struct twist_connection *target, const char *host,
                     int port, twist_race_fail_fn fail, void *user,
                     struct twist_race **slot);
void twist_race_free (struct twist_race *race);
/* The address the connection was made to: 1 and OUT filled once TARGET has
   connected (and its handler can ask), else 0.  */
int twist_race_peer (struct twist_race *race, struct twist_dns_addr *out);
/* For tests: the connection attempt delay in ms (0 restores 250), and a
   predicate that says which addresses hang: an attempt to one is made, takes
   its place, and never completes, as a connect to a place that drops the
   packets does (NULL restores real ones).  Loopback cannot be made to hang.  */
void twist_race_set_delay (long ms);
void twist_race_set_stall (int (*stall) (const struct twist_dns_addr *addr));
/* Give SRC's socket, which has connected, to DST, which is told it is
   connected.  SRC is left with none.  */
int twist_connection_adopt (struct twist_connection *dst,
                            struct twist_connection *src);

/* IPv6 first, then IPv4 and IPv6 taking turns, each family in the order it
   was given: the order addresses are tried in.  Returns N.  */
size_t twist_dns_sort (struct twist_dns_addr *addrs, size_t n);

/* For tests: the nameserver to ask (IP and port) in place of resolv.conf's
   (NULL restores it), and the resolution delay and how long to wait for the
   rest after the first answer (0 restores the 50 ms and 2 s).  */
void twist_dns_set_nameserver (const char *ip, int port);
/* For the tests: the first wait before a UDP query that has had no answer is
   sent again, in milliseconds (0: the default), and forget what was learned
   about designated resolvers.  */
void twist_dns_set_retry (long first_ms);
void twist_dns_ddr_forget (void);
void twist_dns_set_timing (long resolution_delay_ms, long linger_ms);

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
int twist_dns_resolve_transfer (struct twist_transfer *transfer,
                                const char *host,
                                void (*cb) (void *user, int err,
                                            const struct twist_dns_addr *addr),
                                void *user);
int twist_dns_resolve_service_transfer (struct twist_transfer *transfer,
                                        const char *host,
                                        void (*cb) (void *user, int err,
                                                    const struct twist_dns_service *svc),
                                        void *user);
int twist_dns_plan_for (const int *user, size_t nuser, int have_doh,
                        int have_doq, int have_dot,
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
void twist_origin_clear (struct twist_transfer *transfer);
int twist_origin_h3 (struct twist_transfer *transfer, const char *host,
                     int *port);
void twist_origin_set_h3 (struct twist_transfer *transfer, const char *host,
                          int yes,
                          int port);
int twist_origin_http_minor (struct twist_transfer *transfer,
                             const char *host);
void twist_origin_set_http_minor (struct twist_transfer *transfer,
                                  const char *host,
                                  int minor);

/* Keeping a transfer to a rate on average.  The first question about a
   transfer starts its clock.  A chunk may go when everything before it has
   been earned, so a transfer is ahead by at most one chunk, and the chunk is
   made small when the limit is.  */
struct twist_rate
{
  uint64_t limit;		/* Bytes a second; 0: none.  */
  uint64_t start_ms;
  uint64_t bytes;		/* Counted so far.  */
  int started;
};

void twist_rate_init (struct twist_rate *r, uint64_t limit);
/* Milliseconds to wait before another N bytes may go; 0: now.  */
uint64_t twist_rate_wait (struct twist_rate *r, uint64_t now_ms, size_t n);
void twist_rate_note (struct twist_rate *r, uint64_t n);
/* How much to ask for or send at a time: MAX, or half a second's worth of the
   limit if that is less, and at least 1.  */
size_t twist_rate_chunk (const struct twist_rate *r, size_t max);

/* URL globbing.  A pattern is a URL with {a,b,c}
   (one of these), [1-10] and [a-z] (a range; [01-10] keeps its width, [1-10:3]
   steps) in it.  The URLs it makes come one at a time, in order, the last glob
   going fastest, so a great many of them cost nothing until they are asked
   for.  A backslash makes a brace or bracket plain.  [ ] around an IPv6
   address is not a range.  */
struct twist_glob;
/* On an error ERR holds the reason, the URL and a caret under the place, and
   TWIST_ERR_URL is returned.  A pattern with no glob makes one URL.  */
int twist_glob_parse (const char *pattern, struct twist_glob **out, char *err,
                      size_t cap);
/* The next URL, in a new string: 1; 0 when there are no more; -1 if out of
   memory.  */
int twist_glob_next (struct twist_glob *g, char **url);
/* How many globs the pattern has, and what the Nth (from 1) is in the URL
   last made; NULL for a number that is none.  */
size_t twist_glob_count (const struct twist_glob *g);
const char *twist_glob_value (const struct twist_glob *g, size_t n);
/* TEMPLATE with #N, N from 1 to the number of globs, replaced by the Nth
   glob's value in the URL last made.  Anything else, #0 or #3 of two, a #
   with no number, stays as it is.  A new string.  */
char *twist_glob_name (const struct twist_glob *g, const char *tmpl);
/* As twist_glob_name for two sets of globs numbered one after the other: A's,
   and then B's (either may be NULL): the globs of a URL and of the file given
   to -T.  */
char *twist_glob_name2 (const struct twist_glob *a, const struct twist_glob *b,
                        const char *tmpl);
void twist_glob_free (struct twist_glob *g);

/* Variables (the tool's --variable and
   the --expand- options).  A set holds names that are letters, digits and
   underscores, and content that may be any bytes.  */
struct twist_vars;
struct twist_vars *twist_vars_new (void);
void twist_vars_free (struct twist_vars *vars);
/* Define from a --variable parameter: "name=text", "name@file" ("-" is
   standard input), "%name" (the environment's; it must be set), and
   "%name=text" or "%name@file" (the default for when it is not).  A name or
   a parameter that is wrong, or an environment variable that is not set, is
   TWIST_ERR_INVAL; a file that cannot be read, TWIST_ERR_FILE.  ERR says what.  */
int twist_vars_define (struct twist_vars *vars, const char *spec, char *err,
                       size_t cap);
/* TEXT with each {{name}} replaced by the content, empty if there is none, and
   each {{name:fn:fn}} by the content after the functions (trim, json, url,
   b64, 64dec), left to right.  \{{ is {{.  Anything that is not a reference
   stays as it is.  A function that is not one, or content with a NUL that is
   not encoded, or a result of over ten megabytes, is an error: NULL, and ERR
   says why.  A new string.  */
char *twist_vars_expand (const struct twist_vars *vars, const char *text,
                         char *err, size_t cap);

struct twist_pool;
struct twist_pool *twist_pool_new (void);
void twist_pool_free (struct twist_pool *pool);
int twist_pool_take (struct twist_pool *pool, const char *key,
                     struct twist_connection **out);
int twist_pool_put (struct twist_pool *pool, const char *key,
                    struct twist_connection *conn);
int twist_pool_put_idle (struct twist_pool *pool, const char *key,
                         struct twist_connection *conn, uint64_t now_ms);
int twist_pool_take_held (struct twist_pool *pool, const char *key,
                          struct twist_connection **out, int *held);
int twist_pool_put_held (struct twist_pool *pool, const char *key,
                         struct twist_connection *conn);
void twist_pool_set_discard (struct twist_pool *pool,
                             void (*cb) (void *user, const char *key),
                             void *user);
int twist_pool_evict_one (struct twist_pool *pool, const char *key);
int twist_pool_take_payload (struct twist_pool *pool, const char *key,
                             struct twist_connection **out, void **payload);
int twist_pool_put_idle_payload (struct twist_pool *pool, const char *key,
                                 struct twist_connection *conn,
                                 uint64_t now_ms, void *payload,
                                 void (*payload_free) (void *));
/* What is said on a parked connection that is dropped, before it is closed
   (it has been idle too long, or the pool is being freed): FAREWELL is called
   with the payload and the connection.  Set after the put.  Not called for a
   connection that is taken.  */
void twist_pool_set_farewell (struct twist_pool *pool,
                              struct twist_connection *conn,
                              void (*farewell) (void *payload,
                                                struct twist_connection *conn));
int twist_pool_put_payload (struct twist_pool *pool, const char *key,
                            struct twist_connection *conn, void *payload,
                            void (*payload_free) (void *));
/* The pool a transfer parks its connection in and looks for one in: its
   runtime's.  NULL for a transfer that is not in one.  */
struct twist_pool *twist_transfer_pool (struct twist_transfer *transfer);
size_t twist_pool_count (struct twist_pool *pool);
void twist_runtime_notify_timer (struct twist_runtime *runtime);
/* TRANSFER has ended: have the loop report it.  */
int twist_runtime_finished (struct twist_transfer *transfer);
/* Take TRANSFER out of its runtime, silently, releasing its connection;
   TWIST_ERR_RECURSIVE from a callback.  OK for a handle in none.  */
int twist_runtime_detach (struct twist_transfer *transfer);

enum twist_proxy_kind
{
  TWIST_PROXY_NONE = 0,
  TWIST_PROXY_HTTP,
  TWIST_PROXY_SOCKS5,		/* The target is looked up here.  */
  TWIST_PROXY_HTTPS,
  TWIST_PROXY_SOCKS5H,		/* The proxy looks the target up.  */
  TWIST_PROXY_SOCKS4,		/* Looked up here, and IPv4 only.  */
  TWIST_PROXY_SOCKS4A		/* The proxy looks the target up.  */
};

/* A proxy that is spoken to as SOCKS, of either version.  */
#define TWIST_PROXY_IS_SOCKS(kind) \
  ((kind) == TWIST_PROXY_SOCKS5 || (kind) == TWIST_PROXY_SOCKS5H \
   || (kind) == TWIST_PROXY_SOCKS4 || (kind) == TWIST_PROXY_SOCKS4A)

/* Read a proxy URL: http://, https://, socks5://, socks5h://, socks4:// or
   socks4a://, with an optional user and password, which are returned decoded,
   and an optional port.  With socks5h and socks4a the name of the target is
   given to the proxy to look up; with socks5 and socks4 it is looked up here,
   and the proxy is given an address (which for socks4 can only be IPv4).  A
   scheme that is not one of these is TWIST_ERR_UNSUPPORTED, and is not taken
   for a proxy of another kind.  USER and PASS are NULL, or a string to free.  */
int twist_proxy_parse (const char *s, int *kind, char **host, int *port,
                       char **user, char **pass);
struct twist_proxy *twist_proxy_new (int kind, const char *host, int port,
                                     const struct twist_protocol_handler *inner);
void twist_proxy_free (struct twist_proxy *proxy);
void twist_proxy_set_target (struct twist_proxy *proxy, const char *host,
                             int port);
void twist_proxy_set_user (struct twist_proxy *proxy, void *user);
int twist_proxy_opening (struct twist_proxy *proxy, uint8_t **out, size_t *len);
/* The proxy is given what arrived.  *USED is how much of it was the proxy's
   own; the rest, such as the first bytes of an SSH server that came with the
   proxy's reply, belongs to the tunnel.  *READY is set when the tunnel is
   open.  A refusal is TWIST_ERR_PROXY, and twist_proxy_error says why.  */
int twist_proxy_feed (struct twist_proxy *proxy, const uint8_t *data,
                      size_t len, size_t *used, int *ready);
/* The reason for a refusal, and the exit status of the tool for it (56 for a
   CONNECT, 97 for SOCKS); NULL if there has been none.  */
const char *twist_proxy_error (const struct twist_proxy *proxy, int *status);
void twist_proxy_set_credentials (struct twist_proxy *proxy, const char *user,
                                  const char *pass);
/* "Proxy-Authorization: Basic ..." for the proxy's user and password, to
   free; NULL if there are none (or no memory).  For a request sent to the
   proxy itself, as a plain http:// URL through an HTTP proxy is.  */
char *twist_proxy_auth_header (const struct twist_proxy *proxy);
/* The transfer a refusal is reported to.  */
void twist_proxy_set_transfer (struct twist_proxy *proxy,
                               struct twist_transfer *transfer);
/* Everything a transfer tells a new proxy: where to report, and who to be.
   USER and PASS are from the proxy's URL; without a user, the transfer's
   TWISTOPT_PROXYUSERPWD is used.  */
void twist_proxy_configure (struct twist_proxy *proxy,
                            struct twist_transfer *transfer,
                            const char *user, const char *pass);
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
int twist_h1_keep (const struct twist_h1 *parser);
/* Whether the next response is to a HEAD request, and so has no body whatever
   its headers say (RFC 9112, 6.3).  Set before the response, for each.  */
void twist_h1_set_head (struct twist_h1 *parser, int head);
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
int twist_h2_can_open (const struct twist_h2 *h2);
void twist_h2_set_next_owner (struct twist_h2 *h2,
                              const struct twist_h1_events *ev);
void twist_h2_drop_user (struct twist_h2 *h2, void *user);
void twist_h2_set_emit (struct twist_h2 *h2,
                        int (*emit) (void *, const uint8_t *, size_t),
                        void *user);
int twist_h2_preface (uint8_t **out, size_t *out_len);
/* A tunnel on a stream (CONNECT, RFC 9113 section 8.5).  The request for it
   is twist_h2_request with no scheme and no path and the stream left open; the
   stream is then twist_h2_last_stream.  send_data sends as much of DATA as the
   windows and the frame size allow, and returns how much; the rest is the
   caller's to send when the writable callback says the windows have grown.  END
   closes the stream when all of DATA has gone.  */
uint32_t twist_h2_last_stream (const struct twist_h2 *h2);
size_t twist_h2_send_data (struct twist_h2 *h2, uint32_t id,
                           const uint8_t *data, size_t len, int end);
void twist_h2_set_writable (struct twist_h2 *h2, void (*cb) (void *),
                            void *user);
/* The body of a request is sent by the caller, a chunk at a time, on the
   stream the request (with KEEP_OPEN, and no body) opened.  SEND_BODY is as
   send_data, and the END of the request is the end of the stream, after which
   the response is awaited; it returns (size_t) -1 if the stream is not there
   (the server answered, or reset it) and no more is to be sent.  While it is
   sent the session is HELD: no other request is begun on it.  CANCEL ends a
   stream whose body will not be sent in full.  */
size_t twist_h2_send_body (struct twist_h2 *h2, uint32_t id,
                           const uint8_t *data, size_t len, int end);
void twist_h2_hold (struct twist_h2 *h2, int hold);
/* While HOLD is non-zero the receive window of stream ID is not given back as
   data arrives, so the peer stops when it has used it: a consumer that cannot
   take more yet does not have to buffer without limit.  Letting go gives
   back what was withheld.  */
void twist_h2_hold_stream (struct twist_h2 *h2, uint32_t id, int hold);
void twist_h2_cancel (struct twist_h2 *h2, uint32_t id);
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
struct twist_ws *twist_ws_new (struct twist_transfer *transfer,
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
/* A DATA frame (RFC 9114, 7.2.1) of N bytes of DATA, written to OUT, which
   holds CAP; returns its size, or 0 if it does not fit.  */
size_t twist_h3_data_frame (uint8_t *out, size_t cap, const uint8_t *data,
                            size_t n);
void twist_h3_free (struct twist_h3 *h3);
size_t twist_h3_receive (struct twist_h3 *h3, const uint8_t *data, size_t len);
int twist_h3_request (struct twist_h3 *h3, const char *method,
                      const char *scheme, const char *authority,
                      const char *path, const struct twist_slist *extra,
                      const uint8_t *body, size_t body_len, uint8_t **out,
                      size_t *out_len);

int twist_qpack_decode (const uint8_t *data, size_t len,
                        struct twist_h1_events *ev);
int twist_qpack_encode_request (const char *method, const char *scheme,
                                const char *authority, const char *path,
                                const struct twist_slist *extra,
                                uint8_t **out, size_t *out_len);

struct twist_coding;
int twist_coding_known (const char *name);
int twist_coding_open (struct twist_coding **out, const char *name);
/* Decoded data goes to a sink in pieces of at most TWIST_CODING_PIECE bytes,
   as it is produced, and is not accumulated: what a small input expands to is
   the peer's choice, and memory must not follow it.  The sink returns 0 to go
   on; anything else stops the decoding with TWIST_ERR_ABORTED.  */
#define TWIST_CODING_PIECE 16384
typedef int (*twist_coding_sink) (void *user, const uint8_t *data, size_t len);
int twist_coding_feed (struct twist_coding *c, const uint8_t *data, size_t len,
                       twist_coding_sink sink, void *user);
int twist_coding_finish (struct twist_coding *c, twist_coding_sink sink,
                         void *user);
void twist_coding_free (struct twist_coding *c);
int twist_coding_encode (const char *name, const uint8_t *in, size_t n,
                         uint8_t **out, size_t *out_n);

/* Whether a redirect may go from a URL of scheme FROM to one of scheme TO, by
   the scheme alone.  From http: to http, https, ftp and ftps.  From https: to
   https and ftps, so that a transfer that was encrypted is never carried to a
   place that is not.  From anything else, nowhere: a WebSocket handshake is not
   redirected, and nothing that was not asked for as a download is made to
   happen by a Location (file, gopher, smtp...).  The case of the schemes does
   not matter.  There is no option to change this.  */
int twist_http_redirect_ok (const char *from, const char *to);
int twist_http_should_redirect (int status, const char *method, int follow,
                                long redirs, long maxredirs, int *use_get);
/* 1 when a redirect must not replay credentials or a body.  */
int twist_http_redirect_sensitive (const char *from_host, int from_https,
                                   const char *to_host, int to_https);
int twist_http_status_result (int failonerror, int status);

/* ---- cookies, auth ---- */

struct twist_jar *twist_jar_new (void);
/* How many cookies the jar holds.  */
size_t twist_jar_count (struct twist_jar *jar);
void twist_jar_free (struct twist_jar *jar);
/* For tests: the time the jar takes to be now, in seconds since the epoch
   (0: the clock).  */
void twist_jar_set_time (struct twist_jar *jar, int64_t now);
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
int twist_sha512 (const void *data, size_t len, uint8_t out[64]);
int twist_cmac_aes128 (const uint8_t key[16], const void *data, size_t len,
                       uint8_t out[16]);

/* The key derivation of MS-SMB2 3.1.4.2 (SP800-108, counter mode, HMAC-SHA256).
   LABEL and CONTEXT are given as SMB defines them, with the label's NUL; BITS
   is 128 or 256 and OUT holds that many bits.  */
int twist_smb_kdf (const uint8_t *key, size_t keylen,
                   const void *label, size_t labellen,
                   const void *context, size_t contextlen,
                   unsigned bits, uint8_t *out);

/* BER and DER (src/asn1/asn1.c), shared by LDAP and SPNEGO.  Tags are one
   byte; lengths are definite, in at most three bytes.  */

/* The writer encodes into BUF, which the caller owns.  An element that does
   not fit sets err and nothing more is written.  A constructed element is
   opened with twist_der_begin and closed with twist_der_end on its mark.  In
   BER mode (DER 0) its length takes three bytes whatever it is; in DER mode
   it takes the fewest, as DER requires.  */
struct twist_der_writer
{
  uint8_t *buf;
  size_t cap, n;
  int err;
  int der;
};
void twist_der_writer_init (struct twist_der_writer *w, uint8_t *buf,
                            size_t cap, int der);
void twist_der_put (struct twist_der_writer *w, uint8_t tag,
                    const void *data, size_t n);
void twist_der_put_int (struct twist_der_writer *w, uint8_t tag, int v);
size_t twist_der_begin (struct twist_der_writer *w, uint8_t tag);
void twist_der_end (struct twist_der_writer *w, size_t mark);

/* The reader.  start and end bracket a constructed element and prim carries
   a primitive one, whole: val is a slice of the scratch buffer given to
   twist_der_reader_init (its size is the longest primitive taken) and is not
   kept after the call.  A callback returns TWIST_OK, an error, or
   TWIST_DER_STOP, after which the reader consumes nothing more.  An error
   from a callback, or from the encoding, is reported once through failure,
   and receive then takes all it is given.  */
#define TWIST_DER_DEPTH 12
#define TWIST_DER_STOP (-1)

struct twist_der_events
{
  void *user;
  int (*start) (void *user, uint8_t tag, size_t len);
  int (*end) (void *user, uint8_t tag);
  int (*prim) (void *user, uint8_t tag, const uint8_t *val, size_t len);
  void (*failure) (void *user, int err);
};

/* Strict is DER: a tag is a single byte, and a length is in the short form
   below 128 and otherwise the fewest bytes.  Indefinite lengths, lengths of
   more than three bytes, nesting deeper than TWIST_DER_DEPTH and an element
   longer than max_len are errors in both modes.  max_len is 1 MiB unless
   the caller changes it.  */
struct twist_der_reader
{
  const struct twist_der_events *ev;
  uint8_t *val;
  size_t cap, max_len;
  int strict;
  int st;
  uint8_t tag;
  size_t len, got;
  int len_left, len_first;
  struct
  {
    uint8_t tag;
    size_t left;
  } stk[TWIST_DER_DEPTH];
  int depth;
  int failed, stopped;
};
void twist_der_reader_init (struct twist_der_reader *r,
                            const struct twist_der_events *ev, uint8_t *val,
                            size_t cap, int strict);
size_t twist_der_receive (struct twist_der_reader *r, const uint8_t *data,
                          size_t len);
/* Between top-level elements, with nothing open and nothing half read.  */
int twist_der_idle (const struct twist_der_reader *r);

/* NTLMv2 (src/auth/ntlm.c) for SMB, a codec with no I/O.  The caller makes
   the client, gets the NEGOTIATE bytes, feeds the server's CHALLENGE (whole
   or in pieces, then twist_ntlm_challenge_end; twist_ntlm_challenge does both),
   and gets the AUTHENTICATE bytes and the exported session key.  The
   signature calls make and check the message signature of the session, which
   SPNEGO uses for mechListMIC.  Every error is TWIST_ERR_AUTH, or
   TWIST_ERR_INVAL for a call made out of order.  RAND is a hook for the two
   random values, the client challenge and then the exported session key; with
   none, gq_random is used.  */
struct twist_ntlm;
struct twist_ntlm_rand
{
  int (*fill) (void *user, void *buf, size_t len);	/* 0 or an error.  */
  void *user;
};
struct twist_ntlm *twist_ntlm_new (const char *domain, const char *user,
                                   const char *password, const char *host,
                                   const struct twist_ntlm_rand *rnd);
void twist_ntlm_free (struct twist_ntlm *n);
int twist_ntlm_negotiate (struct twist_ntlm *n, uint8_t *out, size_t cap,
                          size_t *len);
int twist_ntlm_feed (struct twist_ntlm *n, const uint8_t *data, size_t len);
int twist_ntlm_challenge_end (struct twist_ntlm *n);
int twist_ntlm_challenge (struct twist_ntlm *n, const uint8_t *data,
                          size_t len);
int twist_ntlm_authenticate (struct twist_ntlm *n, uint8_t *out, size_t cap,
                             size_t *len);
int twist_ntlm_session_key (const struct twist_ntlm *n, uint8_t key[16]);
int twist_ntlm_sign (struct twist_ntlm *n, const void *msg, size_t len,
                     uint8_t out[16]);
int twist_ntlm_verify (struct twist_ntlm *n, const void *msg, size_t len,
                       const uint8_t signature[16]);

/* A SPNEGO initiator (RFC 4178) with NTLMSSP as its only mechanism
   (src/auth/spnego.c), for the GSS-API tokens of SMB2 SESSION_SETUP.  It owns
   an NTLM client made from the same arguments as twist_ntlm_new.  twist_
   spnego_start gives the first token.  Each token from the server is fed whole
   or in pieces with twist_spnego_feed and ended with twist_spnego_finish,
   which gives the token to send back, or sets *DONE when the server's last
   token has been accepted; twist_spnego_step does both for a whole token.
   Anything a server sends that is not the NTLMSSP exchange, a reject, or a
   bad mechListMIC, is TWIST_ERR_AUTH and ends the exchange.  The exported
   session key is there once the AUTHENTICATE has gone.  */
struct twist_spnego;
struct twist_spnego *twist_spnego_new (const char *domain, const char *user,
                                       const char *password, const char *host,
                                       const struct twist_ntlm_rand *rnd);
void twist_spnego_free (struct twist_spnego *s);
int twist_spnego_start (struct twist_spnego *s, uint8_t *out, size_t cap,
                        size_t *len);
int twist_spnego_feed (struct twist_spnego *s, const uint8_t *data,
                       size_t len);
int twist_spnego_finish (struct twist_spnego *s, uint8_t *out, size_t cap,
                         size_t *outlen, int *done);
int twist_spnego_step (struct twist_spnego *s, const uint8_t *in, size_t inlen,
                       uint8_t *out, size_t cap, size_t *outlen, int *done);
int twist_spnego_session_key (const struct twist_spnego *s, uint8_t key[16]);

/* SMB2 (src/smb/), as the client speaks it over a direct TCP connection or a
   QUIC stream.  The parser takes the server's bytes and returns how many it
   consumed; it builds no message and keeps nothing it delivers.  What it
   keeps across calls is a fixed scratch (the 64-byte header, a fixed body, one
   negotiate context or one directory entry) with a hard maximum, and those
   bytes are counted as consumed.  Offsets are forward only: a buffer may
   start after the fixed part, past a few bytes of padding, and may not
   overlap or leave the message.  A length above the limit, a compound
   response, a structure of the wrong size, an offset that goes back or out,
   a response that does not say it is from the server: all are
   TWIST_ERR_PROTOCOL, reported once through failure.

   Offsets in the events are positions in the stream the parser has been
   given, so that the session layer can keep or hash exactly the bytes it
   chose to.  A message that is encrypted is reported by its transform header
   with the extent of its ciphertext, which is skipped; the session layer
   decrypts it and gives the plaintext to twist_smb_parser_message.  */
#define TWIST_SMB_HEADER 64
#define TWIST_SMB_TRANSFORM_HEADER 52
#define TWIST_SMB_ENTRY_MAX 1024	/* One directory entry.  */
#define TWIST_SMB_CTX_MAX 512		/* The data of one negotiate context.  */

enum twist_smb_command
{
  TWIST_SMB_NEGOTIATE = 0,
  TWIST_SMB_SESSION_SETUP = 1,
  TWIST_SMB_LOGOFF = 2,
  TWIST_SMB_TREE_CONNECT = 3,
  TWIST_SMB_TREE_DISCONNECT = 4,
  TWIST_SMB_CREATE = 5,
  TWIST_SMB_CLOSE = 6,
  TWIST_SMB_READ = 8,
  TWIST_SMB_WRITE = 9,
  TWIST_SMB_QUERY_DIRECTORY = 14,
  TWIST_SMB_QUERY_INFO = 16
};

#define TWIST_SMB_FLAG_SERVER_TO_REDIR 0x00000001u
#define TWIST_SMB_FLAG_ASYNC 0x00000002u
#define TWIST_SMB_FLAG_SIGNED 0x00000008u

#define TWIST_SMB_STATUS_SUCCESS 0x00000000u
#define TWIST_SMB_STATUS_PENDING 0x00000103u
#define TWIST_SMB_STATUS_BUFFER_OVERFLOW 0x80000005u
#define TWIST_SMB_STATUS_NO_MORE_FILES 0x80000006u
#define TWIST_SMB_STATUS_MORE_PROCESSING 0xC0000016u

/* Negotiate contexts.  */
#define TWIST_SMB_CTX_PREAUTH 1
#define TWIST_SMB_CTX_ENCRYPTION 2
#define TWIST_SMB_CTX_COMPRESSION 3
#define TWIST_SMB_CTX_SIGNING 8
#define TWIST_SMB_HASH_SHA512 1
#define TWIST_SMB_CIPHER_AES128_CCM 1
#define TWIST_SMB_CIPHER_AES128_GCM 2
#define TWIST_SMB_CIPHER_AES256_CCM 3
#define TWIST_SMB_CIPHER_AES256_GCM 4
#define TWIST_SMB_SIGN_HMAC_SHA256 0
#define TWIST_SMB_SIGN_AES_CMAC 1
#define TWIST_SMB_SIGN_AES_GMAC 2
#define TWIST_SMB_DIALECT_311 0x0311

struct twist_smb_header
{
  uint16_t credit_charge, command, credits;
  uint32_t status, flags, next_command;
  uint64_t message_id, async_id, session_id;
  uint32_t tree_id;
  uint8_t signature[16];
};

struct twist_smb_transform
{
  uint8_t signature[16], nonce[16];
  uint32_t original_size;
  uint16_t flags;
  uint64_t session_id;
  uint64_t ciphertext_offset;	/* In the stream.  */
  size_t ciphertext_len;
};

struct twist_smb_negotiate
{
  uint16_t security_mode, dialect, context_count;
  uint8_t server_guid[16];
  uint32_t capabilities, max_transact, max_read, max_write;
  uint64_t system_time, server_start_time;
};

/* One negotiate context.  For the pre-authentication, encryption and signing
   contexts, count and algs are the identifiers the context lists (at most
   eight) and, for the first, salt is its salt; data is the whole of it.  */
struct twist_smb_context
{
  uint16_t type;
  const uint8_t *data;
  size_t len;
  unsigned count;
  uint16_t algs[8];
  const uint8_t *salt;
  size_t salt_len;
};

struct twist_smb_tree_connect
{
  uint8_t share_type;
  uint32_t share_flags, capabilities, maximal_access;
};

struct twist_smb_create
{
  uint8_t oplock_level, flags;
  uint32_t action;
  uint64_t creation_time, last_access_time, last_write_time, change_time;
  uint64_t allocation_size, end_of_file;
  uint32_t attributes;
  uint8_t file_id[16];
  uint32_t contexts_len;
};

struct twist_smb_close
{
  uint16_t flags;
  uint64_t creation_time, last_access_time, last_write_time, change_time;
  uint64_t allocation_size, end_of_file;
  uint32_t attributes;
};

/* The variable data that is delivered in slices as it arrives.  */
enum twist_smb_data
{
  TWIST_SMB_DATA_SECURITY = 1,
  TWIST_SMB_DATA_READ,
  TWIST_SMB_DATA_INFO,
  TWIST_SMB_DATA_CREATE_CONTEXTS,
  TWIST_SMB_DATA_ERROR
};

/* The events return TWIST_OK, or an error that ends the parse.  data returns
   how much of the slice it took: a short count stops the parser there, the
   rest is presented again by the caller's next call to receive, and nothing
   further is delivered until then.  Slices point into the bytes given to
   receive (or into the parser's scratch for entry and context) and are not
   kept.  */
struct twist_smb_events
{
  void *user;
  int (*message_begin) (void *user, uint64_t offset, size_t len);
  int (*header) (void *user, const struct twist_smb_header *h);
  int (*transform) (void *user, const struct twist_smb_transform *t);
  int (*negotiate) (void *user, const struct twist_smb_negotiate *r);
  int (*context) (void *user, const struct twist_smb_context *c);
  int (*session_setup) (void *user, uint16_t session_flags);
  int (*tree_connect) (void *user, const struct twist_smb_tree_connect *r);
  int (*create) (void *user, const struct twist_smb_create *r);
  int (*close) (void *user, const struct twist_smb_close *r);
  int (*read) (void *user, uint32_t data_length, uint32_t data_remaining);
  int (*write) (void *user, uint32_t count, uint32_t remaining);
  int (*query_info) (void *user, uint32_t output_len);
  int (*query_directory) (void *user, uint32_t output_len);
  int (*empty) (void *user, uint16_t command);	/* LOGOFF, TREE_DISCONNECT.  */
  int (*error) (void *user, uint32_t status, unsigned context_count,
                uint32_t byte_count);
  int (*pending) (void *user, uint64_t async_id);
  size_t (*data) (void *user, enum twist_smb_data kind, const uint8_t *p,
                  size_t n);
  int (*entry) (void *user, const uint8_t *p, size_t n);
  int (*message_end) (void *user, uint64_t offset);
  void (*failure) (void *user, int err);
};

struct twist_smb_parser;
struct twist_smb_parser *twist_smb_parser_new (const struct twist_smb_events *ev);
void twist_smb_parser_free (struct twist_smb_parser *p);
/* The largest frame (the SMB2 message or its transform) accepted; 128 KiB until
   set from what was negotiated.  */
void twist_smb_parser_set_limit (struct twist_smb_parser *p, size_t max_frame);
size_t twist_smb_parser_receive (struct twist_smb_parser *p,
                                 const uint8_t *data, size_t len);
/* One whole message with no framing, such as the plaintext of one that was
   encrypted.  TWIST_OK, or the error also given to failure.  */
int twist_smb_parser_message (struct twist_smb_parser *p, const uint8_t *msg,
                              size_t len);
/* The same with the message fed by receive, which may stop and be offered
   the rest again; twist_smb_parser_done says the message has ended.  */
int twist_smb_parser_begin_message (struct twist_smb_parser *p, size_t len);
int twist_smb_parser_done (const struct twist_smb_parser *p);
int twist_smb_parser_failed (const struct twist_smb_parser *p);

/* The requests a client sends (src/smb/writer.c), each made into OUT as a
   whole frame: the four-byte direct TCP header, the 64-byte header and the
   body.  The header is as the caller sets it; the signature is zero.  A buffer
   too small is TWIST_ERR_INVAL.  Strings are UTF-8 and go out as UTF-16LE.
   For a WRITE the data stays with the caller: the frame made covers the
   header and fixed body, its length field counts the DATA_LEN bytes that
   follow, and the data is sent after it.  */
struct twist_smb_req
{
  uint16_t credit_charge, credits;
  uint32_t flags;
  uint64_t message_id, session_id;
  uint32_t tree_id;
};

struct twist_smb_negotiate_req
{
  uint16_t security_mode;
  uint32_t capabilities;
  uint8_t client_guid[16];
  unsigned n_dialects;
  uint16_t dialects[8];
  unsigned n_hashes;		/* Pre-authentication integrity, if any.  */
  uint16_t hashes[4];
  uint8_t salt[64];
  unsigned salt_len;
  unsigned n_ciphers;
  uint16_t ciphers[4];
  unsigned n_signing;
  uint16_t signing[4];
};

int twist_smb_w_negotiate (uint8_t *out, size_t cap, size_t *len,
                           const struct twist_smb_req *h,
                           const struct twist_smb_negotiate_req *r);
int twist_smb_w_session_setup (uint8_t *out, size_t cap, size_t *len,
                               const struct twist_smb_req *h,
                               uint8_t security_mode, uint64_t previous_session,
                               const uint8_t *blob, size_t blob_len);
int twist_smb_w_logoff (uint8_t *out, size_t cap, size_t *len,
                        const struct twist_smb_req *h);
int twist_smb_w_tree_connect (uint8_t *out, size_t cap, size_t *len,
                              const struct twist_smb_req *h, const char *path);
int twist_smb_w_tree_disconnect (uint8_t *out, size_t cap, size_t *len,
                                 const struct twist_smb_req *h);

struct twist_smb_create_req
{
  uint32_t desired_access, file_attributes, share_access, disposition, options;
  const char *name;		/* Below the share, with backslashes.  */
};

int twist_smb_w_create (uint8_t *out, size_t cap, size_t *len,
                        const struct twist_smb_req *h,
                        const struct twist_smb_create_req *r);
int twist_smb_w_close (uint8_t *out, size_t cap, size_t *len,
                       const struct twist_smb_req *h, const uint8_t file_id[16]);
int twist_smb_w_read (uint8_t *out, size_t cap, size_t *len,
                      const struct twist_smb_req *h, const uint8_t file_id[16],
                      uint32_t length, uint64_t offset);
int twist_smb_w_write (uint8_t *out, size_t cap, size_t *len,
                       const struct twist_smb_req *h, const uint8_t file_id[16],
                       uint32_t data_len, uint64_t offset);
int twist_smb_w_query_info (uint8_t *out, size_t cap, size_t *len,
                            const struct twist_smb_req *h,
                            const uint8_t file_id[16], uint8_t info_type,
                            uint8_t info_class, uint32_t output_len);
int twist_smb_w_query_directory (uint8_t *out, size_t cap, size_t *len,
                                 const struct twist_smb_req *h,
                                 const uint8_t file_id[16], uint8_t info_class,
                                 uint8_t flags, const char *pattern,
                                 uint32_t output_len);

/* The SMB 3.1.1 session layer (src/smb/session.c): the state machine that takes
   a connection from NEGOTIATE through authentication and key derivation to an
   encrypted tree connect, and that seals and opens every message after it.  It
   is the only place that holds a message whole.

   The profile is narrow.  Dialect 0x0311 only; pre-authentication integrity
   with SHA-512; AES-256-GCM or AES-128-GCM, as offered in that order, and no
   other cipher; AES-GMAC or AES-CMAC for signing, with CMAC when the server
   sends no signing context; no compression; signing and encryption both
   required; a guest or null session refused.  The final SESSION_SETUP response
   must be signed, and its signature is the check on the negotiate exchange.
   After setup every request is encrypted and a response that is not is
   refused.  A server whose answer breaks the profile, or whose message fails
   its tag, is TWIST_ERR_PROTOCOL; a refused login is TWIST_ERR_AUTH.  An
   error here ends the session, and the failure operation is called once.

   The caller feeds the connection's bytes to twist_smb_session_receive.  An
   encrypted message is received whole (up to the negotiated size, with the
   limit of TWIST_SMB_FRAME_MAX), its tag is checked before any of it is
   read, and the plaintext is then given to the parser; events reach the
   caller's twist_smb_events.  If its data operation takes less than it is
   offered, the session keeps the message and receive takes nothing more until
   twist_smb_session_resume.  Requests are made with the twist_smb_w_
   functions from a header given by twist_smb_session_request, which counts the
   credits, and sent with twist_smb_session_send.  The random values (client
   GUID, salt, nonce start, and the NTLM client challenge and session key, in
   that order) come from RND, or gq_random.  */
#define TWIST_SMB_FRAME_MAX (65536 + 4096)

struct twist_smb_session;

struct twist_smb_session_ops
{
  void *user;
  /* One whole frame, with its four-byte header, to write to the connection.  */
  int (*send) (void *user, const uint8_t *data, size_t len);
  /* The tree is connected; requests may be made.  */
  void (*established) (void *user, uint32_t tree_id);
  void (*failure) (void *user, int err);
};

struct twist_smb_session_config
{
  const char *domain, *user, *password;
  const char *host;		/* The name in the target and the share path.  */
  const char *share;
  const struct twist_ntlm_rand *rnd;
};

struct twist_smb_session_info
{
  uint16_t cipher, signing;
  uint32_t max_read, max_write, max_transact;
  uint64_t session_id;
  uint32_t tree_id;
  /* The NT status of the last error response the server sent, or 0.  */
  uint32_t status;
};

struct twist_smb_session *
twist_smb_session_new (const struct twist_smb_session_config *cfg,
                       const struct twist_smb_session_ops *ops,
                       const struct twist_smb_events *up);
void twist_smb_session_free (struct twist_smb_session *s);
int twist_smb_session_start (struct twist_smb_session *s);
size_t twist_smb_session_receive (struct twist_smb_session *s,
                                  const uint8_t *data, size_t len);
void twist_smb_session_resume (struct twist_smb_session *s);
const struct twist_smb_session_info *
twist_smb_session_info (const struct twist_smb_session *s);
/* Credits and message ids: a header for a request of CHARGE credits, or
   TWIST_ERR_AGAIN when there are not that many.  */
int twist_smb_session_request (struct twist_smb_session *s, unsigned charge,
                               struct twist_smb_req *h);
unsigned twist_smb_session_credits (const struct twist_smb_session *s);
/* Seal and send a request made by a twist_smb_w_ function (FRAME, with its
   four-byte header) and the data of a WRITE that goes with it, if any.  */
int twist_smb_session_send (struct twist_smb_session *s, const uint8_t *frame,
                            size_t len, const uint8_t *data, size_t data_len);
/* Send LOGOFF; the keys are wiped when its response arrives.  */
int twist_smb_session_logoff (struct twist_smb_session *s);

/* The pieces of NTLMv2 that MS-NLMP 4.2.4 gives worked examples of, and the
   text conversion SMB shares: UTF-8 to UTF-16LE, upper-casing Latin, Greek
   and Cyrillic letters if UPPER; invalid UTF-8 is TWIST_ERR_INVAL.  */
int twist_ntlm_ntowfv2 (const char *user, const char *domain,
                        const char *password, uint8_t key[16]);
int twist_ntlm_v2_response (const uint8_t respkey[16],
                            const uint8_t server_chal[8], const uint8_t *temp,
                            size_t templen, uint8_t proof[16],
                            uint8_t base_key[16]);
int twist_ntlm_session_keys (const uint8_t session_key[16], uint8_t sign_c[16],
                             uint8_t seal_c[16], uint8_t sign_s[16],
                             uint8_t seal_s[16]);
int twist_utf16le_from_utf8 (const char *s, size_t slen, int upper,
                             uint8_t *out, size_t cap, size_t *outlen);

/* For NTLM (src/auth/ntlm.c) and nothing else.  MD4 makes the NT hash of a
   password, RC4 carries the exported session key and seals a signature's
   checksum, and HMAC-MD5 does the rest.  They are not part of twist.h.  */
int twist_md4 (const void *data, size_t len, uint8_t out[16]);
int twist_hmac_md5 (const void *key, size_t keylen, const void *data,
                    size_t len, uint8_t out[16]);
struct twist_rc4
{
  uint8_t s[256];
  uint8_t i, j;
};
int twist_rc4_init (struct twist_rc4 *c, const uint8_t *key, size_t keylen);
void twist_rc4_crypt (struct twist_rc4 *c, const uint8_t *in, uint8_t *out,
                      size_t len);
void twist_rc4_wipe (struct twist_rc4 *c);
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
/* The boundary of the message begun, for the Content-Type header of the
   caller: multipart/mixed; boundary=...  It is new for each message, and
   not guessable, so that no part can contain it.  NULL before begin.  */
const char *twist_mime_boundary (const struct twist_mime *mime);
int twist_mime_part (struct twist_mime *mime);
int twist_mime_header (struct twist_mime *mime, const char *name,
                       const char *value);
int twist_mime_body (struct twist_mime *mime, const uint8_t *data, size_t len);
int twist_mime_body_b64 (struct twist_mime *mime, const uint8_t *data,
                         size_t len);
int twist_mime_finish (struct twist_mime *mime);

/* A writer that pushes: TAKE is given what is held and says how much it took
   (TAKEN), returning non-zero only for a failure.  If it took less than it
   was given, the writer is paused: the rest stays in its buffer (it keeps no
   more than the 4 KiB it always had), and a caller that goes on only after
   twist_mime_ready (true when it is not paused and has room for a header line
   or TWIST_MIME_PIECE bytes of body) does not overflow it.  twist_mime_resume
   offers what is held again; twist_mime_pending is how much is.  After
   twist_mime_finish the message is out when nothing is pending.  Strict is
   for a body that is not text with CRLF line ends: a delimiter always has a
   CRLF before it, as multipart/form-data needs.  twist_mime_reset starts the
   message over with its boundary.  */
#define TWIST_MIME_PIECE 512
struct twist_mime *twist_mime_new_push (int (*take) (void *user,
                                                     const uint8_t *data,
                                                     size_t len,
                                                     size_t *taken),
                                        void *user);
void twist_mime_set_strict (struct twist_mime *mime, int strict);
int twist_mime_ready (const struct twist_mime *mime);
size_t twist_mime_pending (const struct twist_mime *mime);
int twist_mime_paused (const struct twist_mime *mime);
int twist_mime_resume (struct twist_mime *mime);
void twist_mime_reset (struct twist_mime *mime);

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
int twist_mail_sasl_start (struct twist_mail_sasl *sasl, struct twist_transfer *transfer,
                           const char *advertised, char **b64, int *initial);
int twist_mail_sasl_continue (struct twist_mail_sasl *sasl, char **b64);
const char *twist_mail_user (const struct twist_transfer *transfer);
const char *twist_mail_pass (const struct twist_transfer *transfer);

/* The time a protocol has to be connected in: the transfer's connect timeout,
   from the start of the dial to the moment the protocol says it is up (see
   twist_mail_link_phase_begin).  FAIL is called with TWIST_ERR_TIMEOUT, and the
   transfer is given the words for it, if it has none.  A protocol that dials
   for itself has one of these.  */
struct twist_phase
{
  struct twist_transfer *transfer;
  struct twist_timer *timer;
  void (*fail) (void *user, int err);
  void *user;
};
void twist_phase_begin (struct twist_phase *phase,
                        struct twist_transfer *transfer,
                        void (*fail) (void *user, int err), void *user);
void twist_phase_end (struct twist_phase *phase);

struct twist_mail_link
{
  struct twist_transfer *transfer;
  struct twist_connection *conn;
  struct twist_proxy *proxy;
  struct twist_timer *timer;
  /* The time to be connected in, from the start: see
     twist_mail_link_phase_begin.  */
  struct twist_phase phase;
  /* The race for the connection, while there is one.  Freed before the
     connection.  */
  struct twist_race *race;
  char *dial_host;
  int dial_port;
  int tls_tunnel;		/* Through an https proxy: tunnel.c.  */
  char *tun_user;
  char *tun_pass;
  const struct twist_protocol_handler *handler;
  void *user;
  void (*fail) (void *user, int err);
};

int twist_mail_link_open (struct twist_mail_link *link, struct twist_transfer *transfer,
                          const struct twist_protocol_handler *handler,
                          void *user, void (*fail) (void *user, int err));
void twist_mail_link_close (struct twist_mail_link *link);
/* Making the connection has a time limit (the transfer's connect timeout)
   that runs from the start of the dial to the moment the protocol says it is
   up: the lookup, the TCP connect, a proxy, and a protocol's greeting and
   login.  The protocol that wants it calls begin once the dial has started and
   end when it is up; one that never calls begin has only the TCP connect's.  */
void twist_mail_link_phase_begin (struct twist_mail_link *link);
void twist_mail_link_phase_end (struct twist_mail_link *link);
/* Give up the connection without closing it, to keep it for another
   transfer.  The timer for this one is cancelled.  */
struct twist_connection *twist_mail_link_detach (struct twist_mail_link *link);
/* Take CONN back for TRANSFER's transfer: the handler and the timer.  */
void twist_mail_link_attach (struct twist_mail_link *link,
                             struct twist_transfer *transfer,
                             struct twist_connection *conn);

struct twist_smtp;
struct twist_smtp *twist_smtp_new (struct twist_transfer *transfer, int live);
void twist_smtp_free (void *smtp);
size_t twist_smtp_receive (struct twist_smtp *smtp, const uint8_t *data,
                           size_t len);
const char *twist_smtp_command (const struct twist_smtp *smtp);
/* The TLS handshake that STARTTLS began is done.  The connection tells the
   handler; a test with no connection says so itself.  Likewise for the others:
   twist_pop3_tls_done (STLS), twist_imap_tls_done (STARTTLS) and
   twist_ftp_tls_done (AUTH TLS).  */
void twist_smtp_tls_done (struct twist_smtp *smtp);

struct twist_pop3;
struct twist_pop3 *twist_pop3_new (struct twist_transfer *transfer, int live);
void twist_pop3_free (void *pop3);
size_t twist_pop3_receive (struct twist_pop3 *pop3, const uint8_t *data,
                           size_t len);
const char *twist_pop3_command (const struct twist_pop3 *pop3);
void twist_pop3_tls_done (struct twist_pop3 *pop3);

struct twist_imap;
struct twist_imap *twist_imap_new (struct twist_transfer *transfer, int live);
void twist_imap_free (void *imap);
size_t twist_imap_receive (struct twist_imap *imap, const uint8_t *data,
                           size_t len);
const char *twist_imap_command (const struct twist_imap *imap);
void twist_imap_tls_done (struct twist_imap *imap);
int twist_imap_mailbox (const char *box, char *out, size_t cap);

struct twist_mqtt;
struct twist_mqtt *twist_mqtt_new (struct twist_transfer *transfer, int live);
void twist_mqtt_free (void *mqtt);
size_t twist_mqtt_receive (struct twist_mqtt *mqtt, const uint8_t *data,
                           size_t len);
const uint8_t *twist_mqtt_command (const struct twist_mqtt *mqtt, size_t *len);
int twist_mqtt_attach (struct twist_transfer *transfer);

struct twist_ldap;
struct twist_ldap *twist_ldap_new (struct twist_transfer *transfer, int live);
void twist_ldap_free (void *ldap);
size_t twist_ldap_receive (struct twist_ldap *ldap, const uint8_t *data,
                           size_t len);
const uint8_t *twist_ldap_command (const struct twist_ldap *ldap, size_t *len);
/* The handshake that followed STARTTLS is done; as twist_imap_tls_done.  */
void twist_ldap_tls_done (struct twist_ldap *ldap);
int twist_ldap_attach (struct twist_transfer *transfer);

/* smb:// (src/smb/smb.c): one file from a share, over the session layer.  The
   test seam: with no connection the frames the handler sends go to SEND
   instead, and twist_smb_receive is what the connection would call.  */
struct twist_smb;
struct twist_smb *twist_smb_new (struct twist_transfer *transfer, int live);
void twist_smb_free (void *smb);
int twist_smb_attach (struct twist_transfer *transfer);
/* smbs://: the same over QUIC.  */
int twist_smbs_attach (struct twist_transfer *transfer);
/* The QUIC handshake is done, with ALPN (for the tests).  */
void twist_smb_test_secure (struct twist_smb *x, struct twist_endpoint *ep,
                            const char *alpn, size_t alpn_len);
void twist_smb_test_seam (struct twist_smb *x,
                          int (*send) (void *user, const uint8_t *data,
                                       size_t len),
                          int (*full) (void *user), void *user);
/* The connection has written what it held (its on_write_ready).  */
void twist_smb_drained (struct twist_smb *x);
/* The random values of the next sessions made (the tests fix them); NULL for
   the system's.  */
void twist_smb_set_test_rnd (const struct twist_ntlm_rand *rnd);
/* The time listings are shown against (0: the clock's).  */
void twist_smb_set_test_now (time_t now);
int twist_smb_start (struct twist_smb *x);
size_t twist_smb_receive (struct twist_smb *x, const uint8_t *data, size_t len);

struct twist_gopher;
struct twist_gopher *twist_gopher_new (struct twist_transfer *transfer,
                                       int live);
void twist_gopher_free (void *gopher);
const uint8_t *twist_gopher_request (const struct twist_gopher *gopher,
                                     size_t *len);
size_t twist_gopher_receive (struct twist_gopher *gopher, const uint8_t *data,
                             size_t len);
void twist_gopher_closed (struct twist_gopher *gopher, int err);
int twist_gopher_attach (struct twist_transfer *transfer);

struct twist_rtsp;
struct twist_rtsp *twist_rtsp_new (struct twist_transfer *transfer, int live);
void twist_rtsp_free (void *rtsp);
const uint8_t *twist_rtsp_request (const struct twist_rtsp *rtsp, size_t *len);
size_t twist_rtsp_receive (struct twist_rtsp *rtsp, const uint8_t *data,
                           size_t len);
void twist_rtsp_closed (struct twist_rtsp *rtsp, int err);
int twist_rtsp_attach (struct twist_transfer *transfer);

/* Telnet (RFC 854).  twist_telnet_receive takes what the server sent and
   writes the text in it to the transfer's write callback, answering the
   server's negotiation.  twist_telnet_input takes what is to be sent, and
   escapes it.  With LIVE zero there is no connection and what would be sent
   is kept, for twist_telnet_sent; the input is then given by the caller, and
   LIVE nonzero reads it (standard input, or the read callback).  */
struct twist_telnet;
struct twist_telnet *twist_telnet_new (struct twist_transfer *transfer,
                                       int live);
void twist_telnet_free (void *telnet);
size_t twist_telnet_receive (struct twist_telnet *telnet, const uint8_t *data,
                             size_t len);
void twist_telnet_input (struct twist_telnet *telnet, const uint8_t *data,
                         size_t len);
const uint8_t *twist_telnet_sent (const struct twist_telnet *telnet,
                                  size_t *len);
void twist_telnet_sent_clear (struct twist_telnet *telnet);
void twist_telnet_closed (struct twist_telnet *telnet, int err);
int twist_telnet_attach (struct twist_transfer *transfer);

struct twist_dict;
struct twist_dict *twist_dict_new (struct twist_transfer *transfer, int live);
void twist_dict_free (void *dict);
const uint8_t *twist_dict_request (const struct twist_dict *dict, size_t *len);
size_t twist_dict_receive (struct twist_dict *dict, const uint8_t *data,
                           size_t len);
void twist_dict_closed (struct twist_dict *dict, int err);
int twist_dict_attach (struct twist_transfer *transfer);

/* scp and sftp: an SSH session (foxtrot) on a TCP endpoint.  The output
   of a handler built with twist_ssh_new (transfer, 0) goes to the sink set
   with twist_ssh_set_sink, and its clock is set with twist_ssh_set_time
   (microseconds), so that it can be driven in-process.  twist_ssh_start
   sends our identification and begins the key exchange.  */
struct twist_ssh;
struct twist_ssh *twist_ssh_new (struct twist_transfer *transfer, int live);
void twist_ssh_free (void *ssh);
void twist_ssh_set_sink (struct twist_ssh *ssh,
                         int (*sink) (void *user, const uint8_t *data,
                                      size_t len),
                         void *user);
void twist_ssh_set_time (struct twist_ssh *ssh, uint64_t now_us);
int twist_ssh_start (struct twist_ssh *ssh);
size_t twist_ssh_receive (struct twist_ssh *ssh, const uint8_t *data,
                          size_t len);
void twist_ssh_timeout (struct twist_ssh *ssh);
uint64_t twist_ssh_deadline (const struct twist_ssh *ssh);
int twist_ssh_attach (struct twist_transfer *transfer);

struct twist_tftp;
struct twist_tftp *twist_tftp_new (struct twist_transfer *transfer, int live);
void twist_tftp_free (void *tftp);
const uint8_t *twist_tftp_packet (const struct twist_tftp *tftp, size_t *len);
size_t twist_tftp_receive (struct twist_tftp *tftp, const uint8_t *data,
                           size_t len);
void twist_tftp_timeout (struct twist_tftp *tftp);
/* The request goes to ADDR and PORT, and the first reply from that address
   fixes the port the rest is exchanged with.  twist_tftp_accept_source says
   whether a datagram from FROM is that peer's, and is false for any other.  */
void twist_tftp_set_dest (struct twist_tftp *tftp,
                          const struct twist_dns_addr *addr, int port);
int twist_tftp_accept_source (struct twist_tftp *tftp,
                              const struct sockaddr *from, socklen_t flen);
int twist_tftp_attach (struct twist_transfer *transfer);

/* The stores of the runtime that a transfer has asked to use, or NULL
   for a transfer that has not, or that is in no runtime.  */
struct twist_jar *twist_transfer_jar (struct twist_transfer *transfer);
struct twist_hsts *twist_transfer_hsts (struct twist_transfer *transfer);
struct twist_altsvc *twist_transfer_altsvc (struct twist_transfer *transfer);

struct twist_dns_cache;

struct twist_dns_cache *twist_dns_cache_new (void);
/* The addresses cached for NAME of QTYPE (1 or 28), at most MAX: how many, 0 if
   it was kept that there are none, or -1 if nothing is kept.  */
int twist_dns_cache_list (struct twist_dns_cache *cache, const char *name,
                          int qtype, struct twist_dns_addr *out, int max,
                          uint64_t now_ms);
/* Keep N addresses (0: that there are none) for NAME of QTYPE.  */
void twist_dns_cache_keep (struct twist_dns_cache *cache, const char *name,
                           int qtype, const struct twist_dns_addr *addrs,
                           int n, uint32_t ttl_sec, uint64_t now_ms);
/* The HTTPS record of NAME, kept with the addresses.  SVC NULL keeps that
   there is none.  twist_dns_cache_https gives 1 with the record, 0 for kept as
   none, -1 for nothing kept.  */
void twist_dns_cache_keep_https (struct twist_dns_cache *cache,
                                 const char *name,
                                 const struct twist_dns_service *svc,
                                 uint32_t ttl_sec, uint64_t now_ms);
int twist_dns_cache_https (struct twist_dns_cache *cache, const char *name,
                           struct twist_dns_service *out, uint64_t now_ms);
void twist_dns_cache_free (struct twist_dns_cache *cache);
int twist_dns_cache_put_msg (struct twist_dns_cache *cache, const char *name,
                             int qtype, const uint8_t *msg, size_t len,
                             uint64_t now_ms);
int twist_dns_cache_get (struct twist_dns_cache *cache, const char *name,
                         int qtype, struct twist_dns_addr *out,
                         uint64_t now_ms);
/* 0 owns the query, 1 waits for it, 2 filled HIT.  */
int twist_dns_cache_begin (struct twist_dns_cache *cache,
                           struct twist_loop *loop, const char *name, int qtype,
                           void (*cb) (void *, int,
                                       const struct twist_dns_addr *),
                           void *user, uint64_t now_ms,
                           struct twist_dns_addr *hit);
void twist_dns_cache_end (struct twist_dns_cache *cache,
                          struct twist_loop *loop, const char *name, int qtype,
                          int err, const struct twist_dns_addr *addr,
                          uint32_t ttl_sec, uint64_t now_ms);

struct twist_hsts *twist_hsts_new (void);
void twist_hsts_free (struct twist_hsts *h);
int twist_hsts_note (struct twist_hsts *h, const char *host, uint64_t expiry);
int twist_hsts_upgrade (struct twist_hsts *h, const char *host, uint64_t now);

struct twist_altsvc *twist_altsvc_new (void);
void twist_altsvc_free (struct twist_altsvc *a);
int twist_altsvc_note (struct twist_altsvc *a, const char *origin,
                       const char *alt);
/* The alternative service noted for ORIGIN, copied to OUT (CAP bytes): 0, or
   -1 if there is none.  */
int twist_altsvc_lookup (struct twist_altsvc *a, const char *origin, char *out,
                         size_t cap);

char *twist_strdup (const char *s);
size_t twist_text_sanitize (uint8_t *out, const uint8_t *in, size_t n);
/* UTF-16LE to UTF-8 (src/auth/ntlm.c, with the other direction): an unpaired
   surrogate or an odd length is TWIST_ERR_INVAL.  OUT has room for CAP bytes,
   and 3 for each unit is enough.  */
int twist_utf8_from_utf16le (const uint8_t *in, size_t n, char *out, size_t cap,
                             size_t *outlen);
/* The user's home directory: $HOME if it is set and not empty, else the one
   in the password file.  Copied to OUT (CAP bytes); returns 1, or 0 if there
   is none or it does not fit.  */
int twist_home_dir (char *out, size_t cap);
int twist_has_ctl (const char *s);
/* The environment variable NAME, or NULL if it is not set, or if the process
   is privileged (set-user-ID or set-group-ID, or a binary with capabilities):
   there the environment is the invoking user's, who is not to choose the
   trust store, the files that secrets are logged to, the proxy or the agent.
   TWIST_PRIVILEGED overrides the test for the tests: 1 treats the process as
   privileged, 0 as not, -1 asks the system.  */
const char *twist_getenv_secure (const char *name);
void twist_set_privileged (int how);
/* The status code in the first three bytes of S: -1 unless they are three
   digits, from 100 to 599.  */
int twist_status_code (const char *s);
/* Whether the header field NAME (N bytes, any case) with VALUE is one that
   HTTP/2 and HTTP/3 do not send: Connection, Keep-Alive, Proxy-Connection,
   Transfer-Encoding and Upgrade, and TE with anything but "trailers" (RFC
   9113, section 8.2.2; RFC 9114, section 4.2).  They describe an HTTP/1
   connection, and a request that has one is malformed.  */
int twist_header_connection_specific (const char *name, size_t n,
                                      const char *value);
void *twist_xmalloc (size_t n);
/* Give DATA to the application's write callback, a piece at a time.  It
   returns LEN when all of it is taken or held for a transfer that is paused,
   and fewer when the callback has said to stop.  The data is the caller's
   again at once.  */
size_t twist_deliver (struct twist_transfer *transfer, const void *data,
                      size_t len);
/* Set up the descriptors the application gave (TWISTOPT_WRITEFD) for a
   transfer that is starting: the body goes to a callback of the transfer's own.
   The upload from TWISTOPT_READFD is made when the handler asks for it.  */
int twist_transfer_fds_setup (struct twist_transfer *transfer);
/* The end of a transfer that succeeded waits for the body to reach the
   application (what is held while its callback was full) and its descriptor.
   Returns 1 if RESULT is put off; twist_sink_gate_check ends it when it can.  */
int twist_sink_gate (struct twist_transfer *transfer, int result);
void twist_sink_gate_check (struct twist_transfer *transfer);
struct twist_upload *twist_fd_upload_new (struct twist_transfer *transfer);
void twist_wsink_free (struct twist_transfer *transfer);
int twist_wsink_busy (struct twist_transfer *transfer);
void twist_wsink_close (struct twist_transfer *transfer);
/* Free what is held.  */
void twist_sink_clear (struct twist_transfer *transfer);
/* Whether the application gave the transfer an upload to send: a read
   callback, a descriptor, or one it pushes.  */
static inline int
twist_transfer_has_source (const struct twist_transfer *t)
{
  return t->read_cb != NULL || t->upload != NULL || t->push_upload
         || t->read_fd >= 0 || t->form != NULL;
}

/* The form of a transfer (engine/form.c): the upload that sends it, made
   with its boundary and the length of the message if every part's is known
   (set as the transfer's INFILESIZE), and the release of the transfer's
   reference to it.  */
struct twist_upload *twist_form_upload_new (struct twist_transfer *transfer);
void twist_form_unref (struct twist_form *form);
struct twist_form *twist_form_ref (struct twist_form *form);
/* Resume on the thread that runs the transfer.  */
int twist_transfer_resume_local (struct twist_transfer *transfer);
/* Run the upload's producer if the consumer has not paused it (it is
   asleep because the application said to wait).  */
void twist_upload_kick (struct twist_upload *up);
/* Whether the caller is on another thread than the one that runs TRANSFER, and
   so must hand its call over.  POST_OP asks the transfer's thread to run
   twist_transfer_xdrain (OP_DRAIN) or twist_transfer_resume_local (OP_RESUME).  */
enum { TWIST_XOP_DRAIN = 1, TWIST_XOP_RESUME = 2 };
int twist_transfer_remote (struct twist_transfer *transfer);
int twist_transfer_post_op (struct twist_transfer *transfer, int op);
void twist_transfer_xdrain (struct twist_transfer *transfer);
int twist_transfer_upload_push_local (struct twist_transfer *transfer,
                                      const uint8_t *data, size_t len,
                                      size_t *taken);
int twist_transfer_upload_end_local (struct twist_transfer *transfer,
                                     int result);
size_t twist_write_bytes (twist_write_callback cb, void *user,
                          const void *data, size_t len);

void twist_i18n_init (void);

void twist_transfer_set_error (struct twist_transfer *transfer, char *msg);
int twist_transfer_use_ssl_failed (struct twist_transfer *transfer,
                                   const char *why);
int twist_transfer_finish (struct twist_transfer *transfer, int result);
void twist_transfer_release (struct twist_transfer *transfer);
/* Carry the transfer on in the handler of its URL, which a redirect has
   changed to another scheme.  The state of the handler that has it is let go
   (not on the loop's stack: from a command posted for it), the progress it has
   counted is kept, and the other handler is attached.  If that cannot be, the
   transfer ends.  */
void twist_transfer_chain (struct twist_transfer *transfer);
int twist_transfer_start (struct twist_transfer *transfer);

/* ---- the URI Template of a UDP proxy (engine/template.c) ---- */

/* RFC 9298, section 2: an absolute https URI with the variables target_host
   and target_port, written {name} or, as a query, {?name,name} (RFC 6570).
   twist_template_check says if TEMPLATE is one, and why not in ERR.
   twist_template_expand makes the URI for HOST and PORT, with the host's
   characters percent-encoded (the colons of an IPv6 address too).
   twist_template_default is the template of a proxy that is given as a host
   and a port: https://HOST:PORT/.well-known/masque/udp/{target_host}/
   {target_port}/.  OUT is to be freed.  */
int twist_template_check (const char *tmpl, char *err, size_t errcap);
int twist_template_expand (const char *tmpl, const char *host, int port,
                           char **out);
int twist_template_default (const char *proxy_host, int proxy_port, char **out);

/* ---- CONNECT-UDP (engine/masque.c) ---- */

struct twist_masque_spec
{
  const char *proxy_host;	/* The host and port to dial.  */
  int proxy_port;
  const char *user;		/* From the proxy's URL, or NULL: then -U.  */
  const char *pass;
  const char *tmpl;		/* NULL: the default for the proxy.  */
  const char *host;		/* The target: its name and port.  */
  int port;
  const char *alpn;		/* To the target; NULL is h3.  */
  int no_cert;			/* Present no client certificate to it.  */
};

/* The plan for a transfer over QUIC: see engine/masque.c.  */
int twist_masque_plan (struct twist_transfer *transfer, const char *what,
                       char **phost, int *pport, char **puser, char **ppass,
                       char **tmpl);

/* An HTTP/3 connection to the target through an HTTP/3 proxy that does
   CONNECT-UDP (RFC 9298): QUIC to the proxy at PROXY_ADDR, an extended CONNECT
   on a request stream of it, and the target's QUIC packets in HTTP Datagrams
   on that stream.  OUT is the QUIC connection to the target, for HANDLER and
   USER as one made directly; the proxy's name for the target is the target's
   own, which the proxy looks up.  The connection is the caller's to free,
   which ends the tunnel.  */
size_t twist_masque_wrap (uint64_t qsid, const uint8_t *payload, size_t len,
                          uint8_t *out, size_t cap);
int twist_masque_unwrap (uint64_t qsid, const uint8_t *data, size_t len,
                         const uint8_t **payload, size_t *plen);
int twist_masque_connect (struct twist_transfer *transfer,
                          const struct twist_masque_spec *spec,
                          const struct twist_dns_addr *proxy_addr,
                          const struct twist_protocol_handler *handler,
                          void *user, struct twist_connection **out);

/* ---- tunnels through an https proxy (engine/tunnel.c) ---- */

struct twist_tunnel_spec
{
  const char *proxy_host;	/* To name in TLS, and for the Host.  */
  int proxy_port;
  const char *user;		/* From the proxy's URL, or NULL: then -U.  */
  const char *pass;
  const char *host;		/* The target.  */
  int port;
};

/* Make a tunnel to the target through the https proxy at PROXY_ADDR (already
   looked up) and give back a connection, OUT, that is the tunnel: the
   protocol uses it as it would a socket to the target.  HANDLER and USER are
   its; HANDLER->connected is called when the proxy has said yes, and an error
   when it has not.  The connection is the caller's to free, which ends the
   tunnel.  If this fails OUT is still set, and is to be freed.

   Tunnels to one proxy share a connection when it speaks HTTP/2: each is a
   stream of it, and the connection is kept a while when the last has gone.  */
int twist_tunnel_connect (struct twist_transfer *transfer,
                          const struct twist_tunnel_spec *spec,
                          const struct twist_dns_addr *proxy_addr,
                          const struct twist_protocol_handler *handler,
                          void *user, struct twist_connection **out);

/* ---- the proxy to use ---- */

/* The proxy URL this transfer goes through, or NULL for none: the one given
   with TWISTOPT_PROXY ("" is none), or else the environment's for the URL's
   scheme (http_proxy, https_proxy, ftp_proxy... in lower case or upper, then
   all_proxy), unless the host is on the TWISTOPT_NOPROXY list or the
   environment's no_proxy.  It is worked out each time it is asked, so a
   redirect to another host is looked at again.  The string is the transfer
   handle's or the environment's: it is not to be freed.  */
const char *twist_transfer_proxy (const struct twist_transfer *transfer);
/* Whether HOST is on a no_proxy LIST.  */
int twist_noproxy_match (const char *host, const char *list);
/* Whether the URL's host is on the list of those that go direct.  */
int twist_transfer_noproxy (const struct twist_transfer *transfer);

/* ---- the route to the target ---- */

/* How a transfer reaches its target, as three separate things.

   ROLE is what the intermediary does for it:
     DIRECT      there is none.
     FORWARD     a proxy in the sense of RFC 9110, 3.7: the request, for an
                 http:// target, is addressed to it and it acts on it (the
                 absolute form on HTTP/1, :scheme and :authority on HTTP/2).
     TCP_TUNNEL  an opaque pipe to host:port, for any protocol (CONNECT, or
                 SOCKS), the target's own protocol running inside it.
     UDP_TUNNEL  an opaque flow of datagrams, for QUIC (CONNECT-UDP, RFC 9298).
   HOP is how the intermediary is reached: TCP, TLS (an https proxy, which
   negotiates HTTP/2 or HTTP/1.1 with ALPN), or QUIC.
   NEG is what is said to it to get the role: nothing for FORWARD, else CONNECT,
   a version of SOCKS, or CONNECT-UDP.

   A forward is chosen for an http:// (or ws://) target through an HTTP or https
   proxy, and a tunnel for every other target, as curl does; the transfer's
   TWISTOPT_HTTPPROXYTUNNEL makes it a tunnel for those too, and a proxy that
   has been found not to forward (twist_route_remember) is tunnelled to.  */
enum
{
  TWIST_ROUTE_DIRECT = 0,
  TWIST_ROUTE_FORWARD,
  TWIST_ROUTE_TCP_TUNNEL,
  TWIST_ROUTE_UDP_TUNNEL
};
enum
{
  TWIST_HOP_TCP = 0,
  TWIST_HOP_TLS,
  TWIST_HOP_QUIC
};
enum
{
  TWIST_NEG_NONE = 0,
  TWIST_NEG_CONNECT,
  TWIST_NEG_SOCKS4,
  TWIST_NEG_SOCKS4A,
  TWIST_NEG_SOCKS5,
  TWIST_NEG_SOCKS5H,
  TWIST_NEG_CONNECT_UDP
};
struct twist_route
{
  int role;
  int hop;
  int neg;
  int kind;			/* TWIST_PROXY_*, of the proxy URL.  */
  char *host;			/* The intermediary, and its credentials from
				   the proxy URL; NULL for DIRECT.  */
  int port;
  char *user;
  char *pass;
};
/* Work out the route of TRANSFER to a target of SCHEME (the URL's scheme, in
   lower case).  UDP is non-zero for a target reached over QUIC (HTTP/3).
   TWIST_OK, or why there is none: TWIST_ERR_URL for a proxy URL that is not
   one, TWIST_ERR_UNSUPPORTED for a kind of proxy that is not spoken or HTTP/3
   through one that is not an https proxy.  OUT is to be freed with
   twist_route_free, also after a failure.  */
int twist_route_plan (struct twist_transfer *transfer, const char *scheme,
                      int udp, struct twist_route *out);
void twist_route_free (struct twist_route *route);
/* Just the role: -1 if there is no route.  */
int twist_route_role (struct twist_transfer *transfer, const char *scheme,
                      int udp);
/* The proxy of ROUTE was found not to forward: from now on, for as long as the
   runtime lives, transfers through it are tunnelled.  */
void twist_route_remember_no_forward (struct twist_transfer *transfer,
                                      const struct twist_route *route);
/* The runtime's memory of the proxies that do not forward, by a key made of
   the proxy's host, port and hop.  */
void twist_origintab_note_noforward (struct twist_origintab *tab,
                                     const char *key);
int twist_origintab_noforward (struct twist_origintab *tab, const char *key);

/* ---- progress ---- */

/* A transfer calls begin once,
   end once, and in between says what it has learned: the size of what it will
   download or upload, and the bytes as they go.  Each of those draws the meter
   or calls the callback if the second has changed.  A redirect is a hop: the
   line is finished, the sizes are forgotten and the counters start again.  */
void twist_progress_begin (struct twist_transfer *transfer);
void twist_progress_end (struct twist_transfer *transfer, int result);
void twist_progress_hop (struct twist_transfer *transfer);
void twist_progress_dl_size (struct twist_transfer *transfer, long long size);
void twist_progress_ul_size (struct twist_transfer *transfer, long long size);
void twist_progress_downloaded (struct twist_transfer *transfer, size_t n);
/* N bytes of the body have been given to the application: counted for
   TWISTINFO_SIZE_DOWNLOAD, and for the progress.  */
void twist_transfer_downloaded (struct twist_transfer *transfer, size_t n);
/* How much the transfer will upload, from the postfields or the application
   (TWISTOPT_INFILESIZE); -1 if that is not known.  */
long long twist_transfer_upload_size (const struct twist_transfer *transfer);
void twist_progress_uploaded (struct twist_transfer *transfer, size_t n);
int twist_progress_update (struct twist_transfer *transfer);
void twist_progress_release (struct twist_transfer *transfer);
/* The pieces, for the tests.  BUF takes 6 bytes, and 10.  */
char *twist_progress_max5 (long long bytes, char *buf);
char *twist_progress_time2str (long long seconds, char *buf);

#endif /* TWIST_INT_H */
