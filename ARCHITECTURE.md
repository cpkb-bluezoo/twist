# Twist Architecture

## Overview

Twist is a transfer client library and command-line tool for the GNU system,
mostly compatible with curl on the command line. The architecture
follows the patterns established by **Gumdrop** (Java) and **Hopf** (Rust),
which share a common design philosophy:

> The contract around the sockets, not a from-scratch epoll implementation

This means we use the kernel's readiness API (epoll/kqueue/IOCP) through a
thin wrapper, while building our own reactor loop, connection management, and
protocol handlers on top.

## Core Design Principle

**quickstep** already provides the layer that sits underneath: it owns the crypto
state machine (TLS, DTLS, QUIC) but **does not own sockets, threads, or timers**.
The caller (Twist) feeds datagrams, pulls datagrams, and calls timeout. This is
exactly the slot Hopf fills with `hopf-core::tls` and `hopf-quic`, and Gumdrop
fills with `TcpEndpoint` plus `QuicEngine`.

## Architecture Layers

```
+----------------------------------------------+
| CLI (twist) / Application                    |
+----------------------------------------------+
| libtwist - Public API                        |
| - twist_global_init()                        |
| - twist_transfer_*  (the job)                |
| - twist_runtime_*   (runs transfers)         |
| - twist_url_*                                |
| - scheme table (not only HTTP)               |
+----------------------------------------------+
| Runtime                                      |
| - One loop                                   |
| - Kept connections, names, sessions          |
| - Cookie jar, HSTS and Alt-Svc lists         |
| - Storage pool (bounded blocking work)       |
| - Completion callbacks, from the loop        |
+----------------------------------------------+
| Loop (single-threaded, no hidden threads)   |
| - Owns connections                           |
| - Timer heap                                 |
| - Command queue                              |
| - Buffer pool                                |
| - Exposes: on_readable, on_writable,         |
|             on_timer, next_timeout            |
+----------------------------------------------+
| Poll Backend (thin wrapper)                  |
| - Linux: epoll                              |
| - BSD/macOS: kqueue                          |
| - Windows: IOCP or wepoll                   |
| - Later: io_uring                           |
+----------------------------------------------+
| quickstep Library                            |
| - gq_conn, gq_endpoint (stateless)           |
| - gq_tlsconn (TLS state machine)             |
| - No sockets, threads, or timers             |
| - Caller feeds datagrams, calls timeout      |
+----------------------------------------------+
```

## Connection Model

A connection is a **plaintext pipe** with the following interface:

```c
struct twist_endpoint {
    // Send data
    int (*send)(struct twist_endpoint *ep, const uint8_t *data, size_t len);

    // Close connection
    void (*close)(struct twist_endpoint *ep);

    // Flow control
    void (*pause_read)(struct twist_endpoint *ep);
    void (*resume_read)(struct twist_endpoint *ep);

    // Callbacks
    void (*on_write_ready)(struct twist_endpoint *ep);
    int (*execute)(struct twist_endpoint *ep, void *task);
    void (*schedule_timer)(struct twist_endpoint *ep, uint64_t deadline_ms);

    // User data
    void *user_data;
};
```

### Protocol Handler Interface

The protocol handler is a **state machine** that processes bytes:

```c
struct twist_protocol_handler {
    // Connection established
    void (*connected)(struct twist_endpoint *ep);

    // Receive data (compact buffer semantics)
    // Returns: number of bytes consumed
    size_t (*receive)(struct twist_endpoint *ep, const uint8_t *data, size_t len);

    // Connection closed
    void (*disconnected)(struct twist_endpoint *ep, int error);

    // Security established (TLS handshake complete)
    void (*security_established)(struct twist_endpoint *ep);

    // Error occurred
    void (*error)(struct twist_endpoint *ep, int error);
};
```

**Compact buffer semantics**: The `receive` callback receives a buffer, consumes
what it needs, and returns the number of bytes consumed. The suffix stays for
the next call. Parsers are push-based and never ask the connection to hold a
slice across calls beyond that suffix.

## Reactor Components

### Loop (Single-Threaded)

Each loop owns:
- A set of connections (pinned for life)
- A timer heap
- A command queue (MPSC)
- A waker (eventfd on Linux, pipe on macOS)
- A buffer pool

The loop exposes:
- `on_readable(fd, events)` - Socket is readable
- `on_writable(fd, events)` - Socket is writable
- `on_timer(now)` - Timer fired
- `next_timeout()` - Next timer deadline

**Critical**: The loop does NOT start its own thread. It's a passive component
that the runtime pumps, or that the application's own poll loop drives. A
runtime told to use several loops (`TWIST_RUNTIMEOPT_THREADS`) starts a thread
for each loop but the first, which is still the application's.

### Runtime

The runtime is what the application holds. It owns one loop, pumped by the
application or by the runtime's own poller, and what the transfers on it keep
for each other:

- the pool of connections kept for reuse
- the cache of DNS answers
- the HTTP/2 and HTTP/3 sessions
- the cookie jar, the HSTS list and the Alt-Svc list, which a transfer uses
  only if it asks (`TWISTOPT_USE_COOKIES`, `_USE_HSTS`, `_USE_ALTSVC`)
- a bounded storage pool for blocking work

```c
struct twist_runtime {
    struct twist_loop *loop;
    struct twist_transfer **transfers;  /* started, not yet reported */
    struct twist_pool *pool;
    struct twist_dns_cache *dns;
    struct twist_session *sessions;
    struct twist_jar *jar;
    struct twist_hsts *hsts;
    struct twist_altsvc *altsvc;
    struct twist_storage *storage;
    /* The hooks of an embedded runtime */
};
```

A runtime has one loop, the application's, or with `TWIST_RUNTIMEOPT_THREADS`
several, each a lane: the loop, its pool of idle connections and its sessions.
The application calls the runtime from one thread; everything that crosses to
another lane is a command in that lane's queue. The first lane runs the done
callbacks. The stores that lanes share (DNS answers, cookies, HSTS, Alt-Svc, the
table of origins) each have a lock held for their own memory only. A transfer is
placed when it starts and stays: those that can share a connection (HTTP/2,
HTTP/3) go to the lane their origin was put on, the rest to the least loaded.

A runtime is made in one of two forms. `twist_runtime_new` has a poller of its
own and is driven with `twist_runtime_run_once`. `twist_runtime_new_embedded`
has no poller: its loop is the external kind, and the watch and timer hooks it
was given say what to poll and when the next deadline is
(see External Driver Support).

#### Completion

A transfer ends by calling `twist_transfer_finish` from whatever handler had it.
That records the result and schedules one timer on the loop for now. The timer
is what tells the program: it releases the transfer's state, which returns the
connection to the pool or closes it, takes the transfer out of the runtime, and
only then calls the `twist_done_callback`. So the program is told from the
loop and never from inside a protocol handler, with the connection already
dealt with, and may do anything to the transfer, including free it or start it
again. The loop does not wait for events after running a timer, so a program
that is waiting for the callback gets control back at once.

A transfer that cannot begin (no URL, a scheme that is not implemented) ends
the same way. There is one place to learn how a transfer ended.

From a callback a program may start and cancel transfers. Running the loop
again, or freeing a runtime, a transfer that is still in one, is refused: the
call that made the callback may be running on it.

#### Connection Lifecycle

1. **Dial**: a transfer's handler takes a kept connection from the pool, or
   dials a new one on the loop
2. **Pin**: a connection stays on its loop for life
3. **Park**: when a transfer ends well, a connection that can be used again goes
   back to the pool under a key that says who it is for; otherwise it is closed
4. **No migration**: Connections never migrate between loops

#### Cross-Thread Communication

- **MPSC command queue**: Multiple producers, single consumer
- **Waker**: Wakes the loop when new commands arrive
- **Commands**: register, task, with_conn, shutdown

The loop drains the command queue at the top of every iteration.

### Storage Pool

- **Bounded queue** for blocking work
- **Submit when full**: Fails immediately
- **The reactor thread never blocks**
- Results come back through `Endpoint.execute()`
- **Two pools**: one loads SSH keys and `known_hosts`; the other (`xfer`) is
  for the reads and writes of regular files in transfers, so that a read that
  does not return cannot hold up those loads. Both are two threads, or one for
  each loop.

### Upload Sources

- The upload of a transfer is a push source: `twist_transfer_upload` is the one
  that was set, or an adapter over `TWISTOPT_READFUNCTION`.
- The handler is the consumer. It takes a chunk, and pauses the producer while
  it cannot send; it never calls the read callback itself.
- HTTP/1 frames the chunks (chunked encoding, or a known length that is never
  sent past) and pushes them into the connection, which pauses the producer at
  `TWIST_OUT_HIGH` and resumes it from the write path. The meter follows the
  body bytes the connection has written.
- The HTTP/2, HTTP/3 and WebSocket pumps hold one chunk, ask for the next when
  the stream can send, and pause the producer between.
- A restart goes to the producer; one that cannot restart fails the transfer
  with `TWIST_ERR_REWIND`.
- FTP, SMTP and IMAP send the upload through a **relay** (`twist_relay_start`):
  the producer's chunks are queued on the connection (SMTP dot-stuffs them on
  the way, IMAP stops at the size the literal said) and the producer is paused
  while the connection is full. The meter follows the body bytes written.
- TFTP sends a block when the source has given a whole one, or has ended; a
  block is counted when the server acknowledges it. MQTT collects the payload
  up to 16 KiB, because the length goes first. SFTP keeps one chunk from the
  source at a time and counts a write when the server acknowledges it.

### Pausing One Stream

- A slow consumer of one HTTP/2 stream must not stop the others on the
  connection, so the connection is not paused. The stream's `WINDOW_UPDATE` is
  withheld (`twist_h2_hold_stream`), the server stops when it has used the
  window, and what was already on its way is held by the handler, bounded, and
  given on resume.
- On HTTP/1 the connection belongs to the transfer, and the read is paused.
- An HTTP/3 stream is paused the same way, by withholding the QUIC stream's
  credit (`MAX_STREAM_DATA`) with `gq_conn_stream_hold`, which needs a quickstep
  that has it. Without it, `twist_http_pause_body` reports
  `TWIST_ERR_UNSUPPORTED` on HTTP/3.
- An upload on HTTP/2 or HTTP/3 already waits for the stream's send window and
  for room in the connection's queue, and pauses its source while it waits;
  it never pauses the connection's read.

### The Application's Side of Upload and Download

- **Write pause.** A write callback returns `TWIST_WRITEFUNC_PAUSE` when it
  cannot take more. It takes none of what it was given; the transfer holds that
  and what follows (at most 4 MiB, then it stops with an error), and gives it
  again, in order, on `twist_transfer_resume`. The handler's pause function
  stops the peer where it can: an HTTP/2 stream's window, an HTTP/3 stream's
  credit, a TCP read, the file pipeline. The end of a transfer that succeeded
  waits for the held body, so the program never hears of the end before it has
  the body.
- **Read pause.** A read callback returns `TWIST_READFUNC_PAUSE` for "not yet";
  the body does not end, and the callback is asked again after the resume.
- **Pushed upload.** `TWISTOPT_UPLOAD_PUSH` makes the upload a producer the
  application feeds with `twist_transfer_upload_push`. A push is taken up to the
  consumer's pause point; past it, none of it is taken and the want-more
  callback says when to try again. From a thread other than the one that runs
  the transfer the bytes are queued, up to 64 KiB, and the transfer's thread
  takes them.
- **Descriptors.** `TWISTOPT_READFD` and `TWISTOPT_WRITEFD` use the file pipeline
  for a regular file and a descriptor source or sink for anything else. The
  descriptor is the application's: it is neither closed nor made non-blocking,
  and a file's position is not moved. A file can be read again for a restart; a
  pipe cannot (`TWIST_ERR_REWIND`). A transfer written to a descriptor is not
  over until the body has been written to it.

### Regular-file Pipeline

- A regular file cannot be polled, so its reads and writes are jobs on the
  transfer pool (`reactor/fileio.c`). The job is a worker for the life of the
  transfer.
- Chunks are 16 KiB with four in flight. The worker posts each to the loop,
  and the loop acknowledges it once it is done with it; a worker with four
  unacknowledged chunks waits. A paused consumer holds chunks
  unacknowledged, which stops the worker.
- The same pipeline writes: the loop gives the worker chunks (`twist_fio_write`
  says when there is no room), and the worker acknowledges each once written.
- Letting go of a transfer does not join the worker. Whichever of the loop and
  the worker is last to be done with the record frees it. There is no
  cancellation; a read that never returns holds one worker until the process
  exits.
- `file://` is the first user.

### Push Sources and Sinks

- A **source** is pushed into the connection by its producer: `push` for each
  chunk, `push_end` when it is over. The connection pauses it while
  `TWIST_OUT_HIGH` (16 KiB) is queued and resumes it from the write path.
- The end callback runs exactly once, whoever ends the source (the producer,
  or the connection failing or being freed).
- A source can be restarted; one that cannot fails the transfer with
  `TWIST_ERR_REWIND`.
- The connection counts the body bytes the socket has accepted, apart from
  framing and from what is still queued (`twist_connection_body_written`).
- A **sink** takes a slice and may take less. The connection then pauses the
  read and presents the tail again on resume. HTTP/2 and HTTP/3 pause a
  stream, not the connection.
- `twist_connection_stream` is an adapter that pulls from a read callback on
  the loop thread. Until the handlers have moved to push sources, the command
  line keeps its current behaviour.

### Descriptor Sources and Sinks

- A pipe, a socket or a terminal can be polled. A descriptor that was
  inherited is not twist's to make non-blocking, because it shares its open
  file description with the caller, so nothing here sets `O_NONBLOCK`.
- Each watches a **duplicate** of the descriptor, so freeing it does not close
  the caller's.
- A **read** is made only after `poll` with a zero timeout has said there is
  something to read; a **write** only after it has said there is room, and of
  no more than `PIPE_BUF` bytes, which POSIX guarantees can be written without
  waiting. A write to a pipe whose reader has gone fails with `EPIPE`, and
  does not raise `SIGPIPE`.
- A source whose consumer takes less than it was given is paused, and goes on
  when resumed. A sink says when it holds about a chunk, and when it has
  written what it held.
- A regular file never takes this path: it is always ready, and goes through
  the file pipeline.

### Timer Queue

- **Binary heap** on the loop
- `poll`'s timeout is the earlier of:
  1. Next heap deadline
  2. Next quickstep timeout
- **Cancel**: Atomic flag the heap entry checks when it pops

## quickstep Integration

quickstep provides:
- `gq_conn` / `gq_endpoint`: Stateless connection state machines
- `gq_tlsconn`: TLS state machine (byte stream)
- **No socket ownership**: The caller (Twist) owns the socket
- **No thread ownership**: The caller owns the thread
- **No timer ownership**: The caller calls timeout

### QUIC Integration

- A QUIC socket is **one UDP fd on one reactor**
- Readable means `recvmmsg`
- Then `gq_endpoint_recv`
- Then `gq_endpoint_send` until it yields nothing
- Then `sendmmsg`
- The reactor's poll timeout is `gq_endpoint_timeout`
- Each QUIC stream is then an **Endpoint** for the protocol handler above it

### TLS Integration

- TCP TLS is the same sandwich:
  - Socket bytes into `gq_tlsconn_receive`
  - Write callback appends to connection's outbound buffer
  - Write interest is set only while outbound buffer is non-empty

## C Implementation Details

### Handler Struct

```c
struct twist_handler {
    struct twist_protocol_handler ops;
    void *user_data;
};
```

### Interest Model

- **Level-triggered**: Read interest drops when handler pauses or inbound
  buffer hits ceiling
- **Write interest**: Set only while net_out is non-empty
- **Edge trigger**: Can wait (not required)

## External Driver Support

An external driver uses the same `Loop` from the application's poller:

```c
// Application provides:
void on_readable(int fd, int events);
void on_writable(int fd, int events);
void on_timer(uint64_t now);

// Loop registers callbacks:
twist_loop_watch(loop, fd, TWIST_READABLE, on_readable);
twist_loop_watch(loop, fd, TWIST_WRITABLE, on_writable);
```

The embedded runtime (`twist_runtime_new_embedded`) is this model. The watch
hook is told which descriptors to poll and for what, and the timer hook is told
how long the application may wait for the next deadline. The application
answers with `twist_runtime_on_ready` for a descriptor that is ready and
`twist_runtime_on_timer` when the deadline has passed. A deadline that is due
is told every time, since what ran in between may have made another due.

## Platform Support

### Poll Backends

- **Linux**: epoll
- **BSD/macOS**: kqueue
- **Windows**: IOCP or wepoll's epoll emulation
- **Future**: io_uring

**Nothing above Loop mentions epoll_event**. The connection and handler stay on
the readiness model so quickstep's pull API doesn't have to change when a
completion queue shows up underneath.

## DNS Strategy

- **Not getaddrinfo on reactor thread** - This is the bug both Gumdrop and
  Hopf avoid
- **DNS queries are UDP sockets** on the destination reactor
- **In-tree resolver** as another datagram handler
- **DoH** (DNS over HTTPS) as a future protocol
- **c-ares** as a reasonable temporary implementation

## Implementation Notes

### What Gumdrop and Hopf Share

- **SelectorLoop** (Gumdrop) / **Reactor** (Hopf): One thread, one selector/poll,
  a connection pinned to that thread for life
- **Accept loop** with admission control and round-robin (AcceptSelectorLoop,
  Hopf AcceptLoop). Twist is a client and has none.
- **Outbound dial round-robin** (Runtime::connect). Twist has one loop to dial
  on.
- **Per-reactor timer queue**: Hopf keeps it on the reactor thread and passes
  the next deadline into poll. Gumdrop's per-loop ScheduledTimer is a second
  thread that hops callbacks back.
- **Cross-thread command queue plus waker**: Hopf (ReactorCmd and mio Waker),
  Gumdrop (ConcurrentLinkedQueue and Selector.wakeup)
- **Bounded storage pool** for blocking work: Submitting when the queue is
  full fails immediately. The reactor thread never blocks, and the result
  comes back through Endpoint.execute / ConnHandle.
- **Buffer pool** owned by the reactor thread, because a connection's buffers
  are never touched from another thread.

### Protocol Face

Two types:
1. **Endpoint**: The plaintext pipe (send, close, pause_read/resume_read,
   on_write_ready, execute, schedule_timer)
2. **ProtocolHandler**: The state machine (connected, receive, disconnected,
   security_established, error)

**receive** uses compact-buffer semantics: the handler advances past the bytes
it consumed, and the suffix stays for the next call. TLS, DTLS, and QUIC sit
under that face, so a handler never sees ciphertext.

### Listen and Dial Symmetry

Listen and dial are the same operation: register a stream on a reactor and
keep it there. A client library wants that symmetry even more than a
server does.

## Transfer engine

The loop and the endpoint do not know which protocol they carry. A transfer is
the unit of work. It is the job and its result, and a runtime runs it:

- It parses a URL and looks the scheme up in a table.
- It may own several endpoints, all pinned to the same loop (an HTTP
  request is one connection; FTP is a control connection plus a data
  connection; HTTP/2 and HTTP/3 are many streams on one session).
- `twist_transfer_setopt` writes a transfer configuration. Each scheme reads
  the fields it understands. An option the scheme does not implement
  fails for that transfer.
- Redirects and the proxy wrapper live in the engine. The connection cache,
  cookies, HSTS and alt-svc are the runtime's, so a later scheme reuses them
  instead of growing a second I/O stack.

The proxy wrapper is a protocol handler that runs before the scheme
handler. When the tunnel is up it calls the inner handler's `connected`.
HTTP CONNECT and SOCKS5 are that wrapper (SOCKS4 and an https proxy are
refused, not guessed at). SOCKS is not copied into every protocol.

The wrapper takes only the bytes that were the proxy's own: an SSH or SMTP
server speaks first, so its banner can arrive in the same read as the reply, and
`twist_proxy_feed` says how much of what it was given it used. The rest is
offered again by the connection, and goes to the transfer. A refusal is
reported to the transfer with the proxy's words (`CONNECT tunnel failed,
response 403`, status 56; the SOCKS5 reasons, status 97) through
`twist_proxy_set_transfer`, and the transfer gets an error. Credentials come from
the proxy's URL or `TWISTOPT_PROXYUSERPWD`. An SSH session through a proxy is
kept in the pool like any other, under a key that holds the proxy and its
credentials; once the tunnel is open the proxy is out of the path.

The connection cache is keyed by scheme, authority, proxy, TLS identity
and loop. The TLS identity is a digest of the settings a connection is made
under: whether the server is verified, the CA file and directory, the client
certificate and key, and, for a proxy spoken to in TLS, the same for the proxy,
and the proxy's credentials. A transfer with the defaults has none, so its key
is what it would be without. A connection is used only by a transfer whose
identity is the same, and the same key counts the connections to an origin
against the limit, so transfers with other settings count apart. Idle endpoints
are never migrated.

`FILE` is not a socket. It is a job on the storage pool, and the result
comes back through `execute`. TFTP and DNS are datagram handlers on the
loop. QUIC is one UDP registration on the loop; each stream is then an
endpoint. DoH is the HTTP scheme used as a resolver, not a special case
in the poll backend.

`telnet` is the one handler that reads a second descriptor, its input. The
handler does not assume it is the process's standard input: the caller names it
with `TWISTOPT_TELNET_INPUT_FD` (the tool names descriptor 0), and with that
and no read callback there is no input at all. The input is a push source: the
transfer's upload where there is a read callback; a descriptor source
(`reactor/fdio.c`, below) for a terminal or a pipe, which watches a duplicate so
that freeing it does not close the caller's; or the file pipeline for a regular
file, read at an offset from where the descriptor is. The null device and the
like have nothing to read. The handler pauses the input when the connection is
behind (`twist_endpoint_pending`) and resumes it from the endpoint's
`on_write_ready`, so a large input is not held in memory. The end of the input
does not end the transfer; the server closing does.

## Scheme table

Every URL scheme twist knows has a row. HTTP is the first row with a real
handler. The others stay in the table so the URL parser, the runtime
interface and the CLI accept them and so the implementation that lands
later is a new `attach` function, not a new reactor.

| Scheme | Kind of handler | Where the state machine already exists |
| --- | --- | --- |
| http, https | TCP endpoint, TLS under it, H1/H2/H3 | hopf-http, gumdrop HttpClient |
| ws, wss | HTTP upgrade on that endpoint | hopf-websocket |
| ftp, ftps | control plus a same-loop data endpoint | hopf-ftp, gumdrop FtpClient |
| smtp, smtps, imap, imaps, pop3, pop3s | TCP, STARTTLS via `start_client_tls` | hopf and gumdrop clients |
| mqtt | TCP endpoint | hopf-mqtt, gumdrop MqttClient |
| ldap, ldaps | TCP endpoint | hopf-ldap, gumdrop LdapClient |
| dict, gopher, gophers, telnet, rtsp | TCP endpoint | new, small |
| tftp | datagram handler | new |
| file | storage pool | new |
| scp, sftp | TCP endpoint, SSH session (foxtrot) on it, SFTP on a channel | foxtrot |
| smb, smbs, rtmp, rtmps | TCP endpoint | new, large |

`scp` and `sftp` are one handler. foxtrot is an I/O-free SSH engine
(transport, authentication, channels, SFTP v3) in the same style as
quickstep: the endpoint feeds bytes to `gf_session_receive`, the session's
`write` callback goes to `twist_endpoint_send`, and its deadline is armed
on the loop. The SCP wire protocol is not implemented. `scp://` runs over
SFTP, as OpenSSH's own `scp` has since 9.0, so a server with no `sftp`
subsystem fails with an error that says so. The two schemes differ only in
what the URL may mean: `scp://` names one file and never lists a
directory, and shell wildcards are rejected, not expanded.

Host keys are checked against `~/.ssh/known_hosts` by default. A key that is missing or changed fails the transfer, there
is no accept-new mode, and turning off peer verification (`-k`) skips the
check. A pinned SHA-256 of the host key is the other way to trust a host.
Fuzzing (`fuzz/`) rebuilds the library with AddressSanitizer, UBSan and edge
coverage (gcc's `trace-pc`, which calls a function at each basic block) and
links each harness with `fuzz/engine.c`, a coverage-guided fuzzer of about 600
lines: a bitmap of edges, a corpus of the inputs that reached a new one,
mutations (bits, bytes, interesting values, blocks, splices, dictionary
tokens), an alarm for hangs, and the sanitizers set to abort so that the input
that did it is saved. A harness feeds the parser in pieces of any size, with a
fresh exact-size copy for each call so that a read past the end is found, and
frees everything, so that the leak check (every few hundred runs) is exact.
The first pass found a signed overflow in the HTTP/2 flow-control windows, a
read past the QPACK static table, and in HPACK a table that counted entries
and not bytes, no handling of size updates, and leaks on error paths.

An https proxy is a tunnel (`src/engine/tunnel.c`), not the proxy state machine
that wraps one connection: TLS is made twice, to the proxy and then to the
target, and a connection holds one TLS layer. So the tunnel has two: an outer
connection to the proxy (TCP, TLS with ALPN, then CONNECT, in a stream of
HTTP/2 when the proxy speaks it, using `twist_h2_send_data` and its windows),
and an inner one, without a descriptor, that the protocol is given as if it were
a socket to the target. The inner connection's `write_fn` is the tunnel, what
the tunnel receives is `twist_connection_ingest`ed, and the tunnel is its
owner (`twist_connection_set_owner`): freed with it, told when the protocol
resumes after pausing so that what was held can go on. A connection with an
owner and no descriptor writes at once what TLS queues. The three places that
dial (`http.c`, `mail/dial.c`, `ftp.c`) call `twist_tunnel_connect` in place of
making a TCP connection when the proxy is https.

HTTP/3 through an https proxy is CONNECT-UDP (`src/engine/masque.c`). A QUIC
connection to the target is made with no socket: `twist_quic_dial` takes a
`twist_quic_opts` whose `send` is the carrier for its UDP datagrams, and what
comes back is given to `twist_quic_feed`. The carrier is a second QUIC
connection, to the proxy, with DATAGRAM frames (RFC 9221) and the HTTP/3
setting H3_DATAGRAM (RFC 9297). On it one request stream does an extended
CONNECT (`:protocol connect-udp`, from the URI Template: `template.c`), and
each packet of the inner connection is a datagram of the quarter stream ID,
context ID 0 and the packet (`twist_masque_wrap`, `twist_masque_unwrap`).
Packets are held until the proxy has said yes and its datagrams hold them
(the inner Initial is 1200 bytes, and the outer path starts at about that), and
sent again every 10 ms. The inner connection asks for packets of no more than
1200 bytes. `http.c` picks it (`masque_plan`) for HTTP/3 when there is an https
proxy or `--proxy-template-udp`, and then does not look up the target.

The environment is read in three places, and only there. `twist_transfer_proxy`
(`src/engine/noproxy.c`) is the proxy a transfer uses: the one it was given,
or else the environment's for the scheme (`http_proxy` in lower case only, the
others in either, then `all_proxy`), unless the host is on the no-proxy list,
the transfer's or `no_proxy`; every handler that dials asks it when it dials,
so a redirect is looked at again. `twist_trust_load` (`src/tls/trust.c`) fills
the trust store for TLS and QUIC alike from the file and the directory it was
given, or the environment's, or the system's. The key log and the qlog are
callbacks that quickstep offers and does not use by itself: `SSLKEYLOGFILE` is
appended to a line at a time, and `QLOGDIR` gets a file for each QUIC
connection, named for the connection ID. The command line reads `COLUMNS`
for the bar; `HOME` and `SSH_AUTH_SOCK` are read by the SSH code. The manual's
Environment chapter is the list.

The progress meter (`src/engine/progress.c`) is made of counters of what has
been downloaded and uploaded, the sizes that are known, and an update that runs whenever any of those change. The update takes the
average speeds, and once a second (when the second on the loop's clock
changes) the speed over the last five seconds, then calls the application's
`TWISTOPT_XFERINFOFUNCTION` and, if that returns `TWIST_PROGRESSFUNC_CONTINUE`
or there is none, writes the meter line. `TWISTOPT_NOPROGRESS` is 1 until the
application says otherwise, so a library user sees nothing. A handler says what
it knows with `twist_progress_dl_size`, `twist_progress_ul_size`,
`twist_transfer_downloaded` and `twist_progress_uploaded`; the engine calls
`twist_progress_begin` when a transfer starts and `twist_progress_end` when it
finishes, and HTTP calls `twist_progress_hop` for a redirect. A timer, which
does the update after a second with no event, is not set again for each event:
the due time is moved and the timer, when it fires early, sets itself again.
The tool's bar (`src/bar.c`) is a callback in this interface, and returns 0 so that the meter is not drawn as well; it takes its clock as an
argument so that the spaceship can be tested. The tool decides which of them
there is: neither with `-s`, or when the body is written to a terminal.

Variables (`src/engine/vars.c`): `--variable` defines a name
in a table of byte strings (to ten megabytes), from text, a file, or the
environment. For each long option that takes a parameter the command line adds
a twin called `expand-NAME` to the `getopt_long` table, whose value carries a
marker bit; when one comes back the parameter is expanded with the variables
as they are at that point, so order on the command line matters. A function
chain (`trim`, `json`, `url`, `b64`, `64dec`) is run over a copy of the
content; the result is a string, so a NUL that has not been encoded is an
error, and a result over the limit is refused before it is built. Globbing is
done after, on the expanded URL.

URL globbing (`src/engine/glob.c`): a pattern is parsed once
into text, sets and ranges, and the URLs come from an odometer one at a time,
the last glob going fastest, so a range of billions costs nothing until used.
The command line pairs an `-o` with the URL as written and gives each URL the
name with `#N` filled in; the transfers are ordinary ones on the operation's
loop, so SFTP URLs on one server share a session. Errors carry the URL and a
caret under the place.

A form (`src/engine/form.c`, `TWISTOPT_FORM`) is a multipart/form-data body
made as it is sent. Its upload is a push source: the MIME writer
(`src/mime/writer.c`) turns part headers and body pieces into bytes, and its
sink, which may take only some, is the upload, so the writer pauses and keeps
its 4 KiB buffer while the connection is full and goes on when it is resumed.
A part of data is fed to the writer in pieces as it is ready; a file part is
read by the file pipeline and a pipe or terminal by the descriptor source, so
the loop reads no part, and each is held while the writer is. The writer runs
strict for a form, so a delimiter always has a CRLF before it (a body that ends
in a newline is not mistaken for a line end). The length is the headers, counted
by running the writer with empty bodies, plus the sizes of the bodies, and is
the transfer's `INFILESIZE` if every part's is known; otherwise HTTP/1 is
chunked. The form is made before the request head, which names its boundary
and length.

The command line does no I/O of its own on the loop's thread for a body or an
upload. `-T` (and a file for the schemes that stream) gives the transfer
`TWISTOPT_READFD`; `-o` and standard output give it `TWISTOPT_WRITEFD`. A file
for `-o` is opened when the job is made, without emptying it, and cut to what
was written when the transfer ends (a file made for a transfer that wrote
nothing is removed), so a transfer that fails before any body leaves what was
there. Standard output as a regular file is advanced by what was written, and a
parallel run keeps it on stdio, since transfers that start together would all
begin at one offset. Headers (`-i`, `-D`) are written by the tool, in order
with the body, so a transfer that has them, and a body on a terminal, which is
looked at for NULs first, keep the write callback.

The connect timeout is one budget for the whole of making a connection. The mail link (the shared dialer) arms a phase timer for a protocol that
asks (`twist_mail_link_phase_begin`), and the protocol ends it when it is up;
for SSH that is the login, so a long transfer is not cut off and a kept session
never starts one. The key exchange is given the same time (`kex_timeout_us`)
in place of foxtrot's 60 seconds. The default is five minutes, and a name is
looked up within the connect timeout or the total time, whichever is less.

An IPv6 literal is stored without its brackets, and a zone (`fe80::1%eth0`,
written `%25eth0` in a URL, RFC 6874) stays in the host, as ssh keeps it for
known_hosts. `twist_url_host_text` writes a host back with brackets (and with
the zone encoded, or without it for a Host header). The resolver treats text
with a colon as an address or an error, never as a name to look up, and turns
a zone into the interface index in the address (`scope_id`); the places that
build a `sockaddr_in6` pass it on, because a link-local address needs it.

A rate limit (`src/engine/rate.c`) is a pacer: a chunk may go when the bytes
before it have been earned at the limit since the transfer's first chunk, so the
transfer is ahead by at most one chunk, and the chunk is made no bigger than
half a second of the limit. The SFTP pumps ask before they issue a read or fill
a write; when the answer is to wait, a loop timer calls the pump again, and the
call is made between `twist_ssh_enter` and `twist_ssh_leave` like any call into
the session from the loop. Only SFTP asks so far; the command line refuses
`--limit-rate` for other URLs rather than ignore it.

Quote commands (`-Q`) and the directories of an upload are requests of the
SFTP client run in sequence: each is sent when the one before has been
answered, tagged so that its answer is told from the transfer's. The command
lines are read by `quote.c`, and a command that
changes only half of a pair of attributes (the owner or the group, the access
or modification time) asks for the file's first and sends both. Commands for
before run when the SFTP client is ready, those for after on the answer to the
close of the file, so a transfer that fails runs none. Making directories for
an upload happens on the open's NO_SUCH_FILE: each directory from the top is
made without looking at the answer, and the open is tried once more.

A key file may have a certificate beside it (`KEY-cert.pub`, as ssh finds it).
The job that reads the key reads that too, pairs it with the key
(`gf_key_with_certificate`), checks its dates and that it names the user, and
offers the certificate before the plain key. One that fails a check is left
out and the reason is kept for the error message, since a server only refuses;
the plain key is still offered. Which CAs to trust is the server's business.
The ssh-agent is a Unix socket opened as an endpoint on the loop, with the
protocol (framing, requests, replies, and the session-bind that tells the
agent which server this is) in foxtrot, which does no I/O. The session needs
the list of keys when it is made, so the agent is asked what it holds as the
transfer starts, alongside the job that reads the files, and the session starts
when both have come. An answer for a signature comes back later, from the
loop, to the session. A key named with --key is used alone and the agent is
not contacted; otherwise the agent's keys come before the files'. The agent is
never fatal: a missing socket, no answer within ten seconds for the list, a
refusal or nonsense leave a note that is said if authentication then fails, and
the other keys and the password are tried.

Work that can block stays off the loop: the ssh-agent socket is an ordinary
non-blocking fd on the loop, and reading the key files and known_hosts is a job
on the storage pool whose result comes back through the loop's post queue.
There is no token I/O in twist (no libfido2): a security key works through an
ssh-agent, which does it.

Known limitation: passphrase-protected OpenSSH-format private keys (what
`ssh-keygen` writes by default) cannot be used, because their key
derivation, bcrypt-pbkdf, is not in libgcrypt. twist will not take it from
another source, to keep the licensing of the program clear. The limitation
ends when libgcrypt provides it. Keys held by an ssh-agent are unaffected,
and so are unencrypted keys and the encrypted formats foxtrot reads
without bcrypt (PKCS#8 under PBES2, PuTTY version 3).

The key files and the known_hosts file are read, and parsed, by one job on
the storage pool before the session is made: a read can wait on a slow disk,
and a passphrase-protected key can ask for millions of rounds of key
derivation. The job works on a copy of what it needs and touches nothing of
the transfer, which may be gone before it is done. The loop adopts the
result, or drops it if the transfer is gone; the transfer never waits for it.

A session that a transfer leaves logged in, with its SFTP channel open and no
request outstanding, is kept for the next URL. The whole handler is parked
in the connection pool, which already holds HTTP connections: the pool keeps
the TCP connection and owns the handler as a payload, and a server that
sends or closes anything while it is parked makes the pool discard both. The
key is the loop, the host, the port, the user, and a SHA-256 of the options
that make the session what it is (password, key and its passphrase,
known_hosts, a pin, the agent, and whether the host key is checked), so that a
handle with other terms cannot borrow a login made under looser ones; a
session made with -k is not used for a transfer that verifies. Only a
successful transfer parks, and only with nothing in flight: foxtrot's
`gf_sftp_client_pending` is the bytes queued for sending, not the requests
unanswered, so twist counts those itself, and a late answer that reached the
next transfer would carry a tag for a transfer already freed. Taking the
handler out of the pool binds it to the new handle (its transfer pointer, its
link, its total-time timer) and starts at the request for the file; the
channel and client are the old ones. The agent connection is closed when the
session is parked, since it was only for logging in. The command line keeps
one runtime for the URLs of an operation, so that it is there to find.

foxtrot needs libgcrypt 1.12.4 or later (earlier ones abort on some Ed25519
keys a peer can send), which twist accepts as a dependency.

DNS is not a URL scheme the transfer dials for its own sake. It is
the resolver the dialer uses, implemented as a datagram handler, with
DoH as a later HTTP transfer.

## GNU package

Twist is a GNU package. Automake `gnu` strictness, Libtool, gettext,
a Texinfo manual, GPLv3+ headers, ISO C99, and the GNU coding style are
part of the build, not a later pass. See HACKING.

## Why Not Other Approaches

### Not: Implementing epoll/kqueue from scratch

These backends are a few hundred lines each, and the bugs that matter
(partial reads, EAGAIN, EMFILE backoff, the waker fd, level-triggered interest
updates) are well known. Hopf's reactor.rs is small because mio already did
that part. The code that is actually the architecture is the connection object:
inbound compact buffer, outbound queue, TLS sink, interest bits, pause/resume,
dial-in-progress, write-ready callback. That is most of connection.rs, and it
has nothing to do with which poll syscall you use.

### Not: Using libuv, libevent's bufferevents, or an async runtime

These libraries want to own the buffer, the callback vocabulary, and often
a thread pool. That collides with the split you already have: quickstep owns
the crypto state machine, the protocol handler owns the grammar, and only
the connection owns the socket buffers.

libuv can host one loop per thread, so thread-per-core is possible on top of
it, but you would spend the time translating Endpoint into uv_poll_t and
uv_timer_t and then working around uv_queue_work.

A storage pool with a bounded queue and an explicit hop back is a different
contract from that thread pool.

libevent or libev are closer to mio, if you use only the poll and the timer
and ignore bufferevents. For a library whose reason to exist is this I/O
model, that dependency does not buy much once the poll backend is isolated.

### Not: libevent or libev

The dependency surface that matches Gumdrop and Hopf is pthreads plus the
kernel readiness API. Crypto stays in quickstep.

### Process Ownership

Hopf owns the process. A library often does not: the application already
has a poll loop, and the library is a guest in it. The embedded runtime exists
for that (twist_runtime_on_ready tells the library a socket became readable;
the library does not call epoll itself).

## Design Decision: Loop vs Runtime

- **Loop**: Holds the connections, the timer heap, and the command queue. It
  exposes on_readable, on_writable, on_timer(now), and next_timeout. It does
  not start a thread.
- **Runtime**: One loop, and what transfers keep for each other: the pool, the
  names, the sessions, the cookie jar, the HSTS and Alt-Svc lists, and a
  storage pool. The CLI uses one for the URLs of an operation. Hopf's
  arrangement of N loops on N threads with an accept loop and a dial
  round-robin was set aside: Twist is a client, and a program that wants
  threads makes a runtime for each, which share nothing.
- **Embedded**: The same Loop, without a poller, driven from the application's
  own poll loop, the way nginx or a GUI main loop would drive it.

Socket registration is a callback (watch(fd, read, write) / unwatch), not
a hidden epoll_ctl. Protocol handlers see Endpoint in both modes. They
cannot tell who called poll. That is what keeps the CLI a thin executable:
it makes a Runtime, starts transfers, and holds a latch until they have all
been reported.

The same shape as Gumdrop and Hopf is kept at the top: one model, explicitly
asynchronous and non-blocking, with the protocol handlers matching the wire
protocols. There is no blocking call in the library. The latch in the command
line tool is the one place anything waits: it counts the transfers in flight,
and runs the loop until the count is zero.

## Thread Model

- **One thread per runtime**; runtimes share nothing
- A connection is born on one loop and stays there
- Another thread holds a handle (reactor index plus token) and can only
  enqueue a command and write the waker
- There is no connection migration
- No shared buffer pool lock

Hopf's comment on BufferPool is the rule: every acquire and release happens
on the thread that owns the connection.

## C Implementation Shape

### Handler

```c
struct twist_handler {
    struct twist_protocol_handler ops;
    void *user_data;
};
```

Same style as gq_conn_events and gq_tlsconn_events.

### Receive

```c
size_t (*receive)(struct twist_endpoint *ep, const uint8_t *data, size_t len);
```

Takes `const uint8_t *data, size_t len` and returns how many bytes it consumed.
The connection memmoves the suffix, or keeps an offset, and presents it again
next time.

### Interest

Level-triggered. Read interest drops when the handler pauses or the inbound
buffer hits its ceiling, which is how TCP backpressure reaches the peer.
Write interest is set only while net_out is non-empty. Edge trigger can wait.

### Timers

Binary heap on the loop. poll's timeout is the earlier of the next heap deadline
and the next quickstep timeout. Cancel is an atomic flag the heap entry checks
when it pops, which is what Hopf's TimerQueue does, including skipping
compaction until cancelled entries are worth sweeping.

### Cross-thread work

MPSC queue of commands (register, task, with_conn, shutdown) and a waker:
eventfd on Linux, a pipe on macOS. The loop drains the queue at the top of
every iteration, which is Hopf's drain_commands before poll.

### Blocking work

Two legal places:
1. Name resolution and filesystem reads go to the storage pool
2. Completion is an execute back onto the owning loop

DNS queries themselves are UDP sockets on the destination reactor, the way
Hopf treats the resolver as runtime substrate. getaddrinfo on a reactor
thread is the bug both codebases are built to avoid.

A transfer client will grow DoH and its own DNS anyway, so an in-tree
resolver that is just another datagram handler ages better than adopting
c-ares as architecture. c-ares is a reasonable temporary implementation of
that same callback, sitting on the storage pool or on the loop's UDP path.

### Windows Support

Third poll backend (IOCP, or wepoll's epoll emulation) behind the same
on_readable / on_writable methods. Nothing above Loop mentions epoll_event.

### io_uring Support

Later backend, which is also Hopf's stated direction. The connection and the
handler stay on the readiness model so quickstep's pull API does not have to
change when a completion queue shows up underneath.
