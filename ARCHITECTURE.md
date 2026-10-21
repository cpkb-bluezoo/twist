# Twist Architecture

## Overview

Twist is a curl-compatible HTTP client library and CLI tool. The architecture
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
| libtwist - Public API                       |
| - twist_global_init()                       |
| - twist_easy_* / twist_multi_*              |
| - twist_share_* / twist_url_*               |
| - scheme table (not only HTTP)              |
+----------------------------------------------+
| Runtime                                      |
| - N loops on N threads                      |
| - Accept loop with admission control         |
| - Dial round-robin                           |
| - Storage pool (bounded blocking work)       |
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
that the runtime or external driver pumps.

### Runtime

The runtime is a policy for how loops are pumped. It contains:
- N loops on N threads (thread-per-core)
- An accept loop with admission control
- A dial round-robin
- A bounded storage pool for blocking work

```c
struct twist_runtime {
    size_t num_loops;
    struct twist_loop **loops;
    struct twist_accept_loop *accept;
    struct twist_storage_pool *storage;
};
```

#### Connection Lifecycle

1. **Accept**: Accept loop applies admission control, round-robins new sockets
   onto workers
2. **Dial**: Separate round-robin for outbound connections
3. **Pin**: Once assigned to a loop, a connection stays there for life
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

This is the same model as libcurl's multi interface
(`curl_multi_socket_action`).

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
  Hopf AcceptLoop)
- **Outbound dial round-robin** (Runtime::connect)
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
keep it there. A curl-shaped library wants that symmetry even more than a
server does.

## Transfer engine

The loop and the endpoint do not know which protocol they carry. A transfer
(one easy handle) is the curl-shaped unit of work:

- It parses a URL and looks the scheme up in a table.
- It may own several endpoints, all pinned to the same loop (an HTTP
  request is one connection; FTP is a control connection plus a data
  connection; HTTP/2 and HTTP/3 are many streams on one session).
- `twist_easy_setopt` writes a transfer configuration. Each scheme reads
  the fields it understands. An option the scheme does not implement
  fails for that transfer.
- Redirects, the connection cache, the proxy wrapper, cookies, HSTS and
  alt-svc live here, so a later scheme reuses them instead of growing a
  second I/O stack.

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
`twist_proxy_set_easy`, and the transfer gets an error. Credentials come from
the proxy's URL or `TWISTOPT_PROXYUSERPWD`. An SSH session through a proxy is
kept in the pool like any other, under a key that holds the proxy and its
credentials; once the tunnel is open the proxy is out of the path.

The connection cache is keyed by scheme, authority, proxy, TLS identity
and loop. Idle endpoints are never migrated.

`FILE` is not a socket. It is a job on the storage pool, and the result
comes back through `execute`. TFTP and DNS are datagram handlers on the
loop. QUIC is one UDP registration on the loop; each stream is then an
endpoint. DoH is the HTTP scheme used as a resolver, not a special case
in the poll backend.

## Scheme table

Every libcurl scheme has a row. HTTP is the first row with a real
handler. The others stay in the table so the URL parser, the multi
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

Host keys are checked against `~/.ssh/known_hosts` by default, as the
curl tool does. A key that is missing or changed fails the transfer, there
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

Variables (`src/engine/vars.c`) are the curl tool's. `--variable` defines a name
in a table of byte strings (to ten megabytes), from text, a file, or the
environment. For each long option that takes a parameter the command line adds
a twin called `expand-NAME` to the `getopt_long` table, whose value carries a
marker bit; when one comes back the parameter is expanded with the variables
as they are at that point, so order on the command line matters. A function
chain (`trim`, `json`, `url`, `b64`, `64dec`) is run over a copy of the
content; the result is a string, so a NUL that has not been encoded is an
error, and a result over the limit is refused before it is built. Globbing is
done after, on the expanded URL.

URL globbing (`src/engine/glob.c`) is the curl tool's: a pattern is parsed once
into text, sets and ranges, and the URLs come from an odometer one at a time,
the last glob going fastest, so a range of billions costs nothing until used.
The command line pairs an `-o` with the URL as written and gives each URL the
name with `#N` filled in; the transfers are ordinary ones on the operation's
loop, so SFTP URLs on one server share a session. Errors carry the URL and a
caret under the place, as curl's do.

The connect timeout is one budget for the whole of making a connection, as in
curl. The mail link (the shared dialer) arms a phase timer for a protocol that
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
lines are read by `quote.c` as the curl tool reads them, and a command that
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
handler out of the pool binds it to the new handle (its easy pointer, its
link, its total-time timer) and starts at the request for the file; the
channel and client are the old ones. The agent connection is closed when the
session is parked, since it was only for logging in. The command line keeps
one multi handle for the URLs of an operation (`twist_easy_perform_in`), so
that it is there to find; `twist_easy_perform` still makes one for each call.

foxtrot needs libgcrypt 1.12.4 or later (earlier ones abort on some Ed25519
keys a peer can send), which twist accepts as a dependency.

DNS is not a URL scheme the easy handle dials for its own sake. It is
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
curl itself grew its own multi loop for the same reason.

### Not: libevent or libev

The dependency surface that matches Gumdrop and Hopf is pthreads plus the
kernel readiness API. Crypto stays in quickstep.

### Process Ownership

Hopf owns the process. A libcurl-shaped library often does not: the
application already has a poll loop, and the library is a guest in it.
curl's multi interface exists for that (curl_multi_socket_action tells the
library a socket became readable; the library does not call epoll itself).

## Design Decision: Loop vs Runtime

- **Loop**: Holds the connections, the timer heap, and the command queue. It
  exposes on_readable, on_writable, on_timer(now), and next_timeout. It does
  not start a thread.
- **Runtime**: The Hopf arrangement: N loops on N threads, an accept loop, a
  dial round-robin, a storage pool. The CLI uses this.
- **External driver**: Uses the same Loop from the application's poller, the
  way nginx or a GUI main loop would drive libcurl.

Socket registration is a callback (watch(fd, read, write) / unwatch), not
a hidden epoll_ctl. Protocol handlers see Endpoint in both modes. They
cannot tell who called poll. That is what keeps the CLI a thin executable:
it starts a Runtime, registers transfers, and waits.

## Thread Model

- **Thread-per-core** applies inside Runtime
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

A curl replacement will grow DoH and its own DNS anyway, so an in-tree
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
