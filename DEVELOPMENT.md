# Twist Development Plan

## Overview

This document outlines the implementation roadmap for Twist, following the
architecture described in ARCHITECTURE.md. The development order is designed
to build the framework first, then add protocols on top.

## Phase 0: Project Setup (COMPLETED)

- [x] Create repository with GNU project conventions
- [x] Rename LICENSE to COPYING
- [x] Create standard GNU files (README, AUTHORS, HACKING, INSTALL, etc.)
- [x] Set up autotools build system (configure.ac, Makefile.am, bootstrap)
- [x] Configure git with correct author information
- [x] Create skeleton source files (twist.c, twist.h)

## Phase 1: Core Loop Implementation

Build the foundation: a single Loop with a basic poll backend.

### Milestone 1.1: Loop Structure

- [ ] Implement `struct twist_loop` with:
  - Connection set
  - Timer heap (binary heap)
  - Command queue (MPSC)
  - Waker (eventfd/pipe)
  - Buffer pool
- [ ] Implement loop lifecycle: create, destroy, run
- [ ] Implement `next_timeout()` calculation
- [ ] Implement command queue drain at iteration start

### Milestone 1.2: Poll Backend - epoll

- [ ] Implement epoll-based poll backend for Linux
- [ ] Implement `on_readable(fd, events)` callback registration
- [ ] Implement `on_writable(fd, events)` callback registration
- [ ] Implement interest management (level-triggered)
- [ ] Handle EAGAIN, partial reads, EMFILE backoff

### Milestone 1.3: Poll Backend - kqueue

- [ ] Implement kqueue-based poll backend for BSD/macOS
- [ ] Share loop interface with epoll backend
- [ ] Abstract platform differences

### Milestone 1.4: Basic Connection

- [ ] Implement `struct twist_connection`
- [ ] Implement inbound compact buffer
- [ ] Implement outbound queue
- [ ] Implement pause/resume flow control
- [ ] Implement write-ready callback
- [ ] TCP socket management

### Milestone 1.5: Echo Handler Test

- [ ] Create echo protocol handler
- [ ] Test with internal epoll backend
- [ ] Test with external on_readable driver

## Phase 2: Connection Features

Add essential connection-level functionality.

### Milestone 2.1: Non-blocking Connect

- [ ] Implement non-blocking connect with timeout
- [ ] Handle connection errors
- [ ] Connection state tracking

### Milestone 2.2: Flow Control

- [ ] Implement read interest drop on pause
- [ ] Implement read interest drop on buffer ceiling
- [ ] Implement write interest management
- [ ] Test backpressure propagation

### Milestone 2.3: Timer Integration

- [ ] Integrate quickstep timeout with loop timer
- [ ] Implement timer cancelation with atomic flags
- [ ] Test timer accuracy

## Phase 3: Threading Model

Add multi-threaded runtime support.

### Milestone 3.1: Single Reactor Thread

- [ ] Implement waker (eventfd/pipe)
- [ ] Implement execute callback
- [ ] Test cross-thread command enqueue

### Milestone 3.2: Storage Pool

- [ ] Implement bounded queue for blocking work
- [ ] Implement submit with immediate failure on full
- [ ] Implement completion callback via execute
- [ ] Test that reactor thread never blocks

### Milestone 3.3: Runtime with N Loops

- [ ] Implement Runtime struct with N loops on N threads
- [ ] Implement accept loop with admission control
- [ ] Implement round-robin for new sockets
- [ ] Implement dial round-robin
- [ ] Test connection pinning (no migration)

## Phase 4: quickstep Integration

Integrate quickstep for TLS support.

### Milestone 4.1: TLS Connection

- [ ] Wrap gq_tlsconn in connection
- [ ] Socket bytes into gq_tlsconn_receive
- [ ] Write callback appends to outbound buffer
- [ ] Write interest only while outbound non-empty
- [ ] Test TLS handshake and data transfer

### Milestone 4.2: Echo Handler with TLS

- [ ] Update echo handler to work with TLS
- [ ] Test plaintext reception through TLS layer
- [ ] Verify security_established callback

## Phase 5: QUIC Support

Add HTTP/3 support via QUIC.

### Milestone 5.1: QUIC Socket

- [ ] One UDP fd on one reactor
- [ ] Readable means recvmmsg
- [ ] Implement gq_endpoint_recv integration
- [ ] Implement gq_endpoint_send integration
- [ ] Reactor poll timeout from gq_endpoint_timeout

### Milestone 5.2: QUIC Streams as Endpoints

- [ ] Each QUIC stream as Endpoint for protocol handler
- [ ] Test multiple streams on one QUIC connection

## Phase 6: HTTP Protocol Implementation

Implement HTTP protocol handlers.

### Milestone 6.1: HTTP/1.1 Handler

- [ ] Implement HTTP/1.1 protocol state machine
- [ ] Request formatting
- [ ] Response parsing (compact buffer)
- [ ] Chunked encoding support
- [ ] Connection keep-alive

### Milestone 6.2: HTTP/2 Handler

- [ ] Implement HTTP/2 protocol state machine
- [ ] Frame parsing and generation
- [ ] Stream multiplexing
- [ ] Flow control (window updates)
- [ ] Priority handling

### Milestone 6.3: HTTP/3 Handler

- [ ] Implement HTTP/3 protocol state machine
- [ ] QUIC stream management
- [ ] Frame parsing on QUIC streams
- [ ] Integration with QUIC layer

## Phase 7: curl Compatibility

Implement curl-compatible CLI and library API.

### Milestone 7.1: CLI Skeleton

- [ ] Parse curl-style command line arguments
- [ ] Support basic options (-X, -H, -d, etc.)
- [ ] Output formatting

### Milestone 7.2: Library API

- [ ] Implement libcurl-compatible API
- [ ] easy interface (twist_easy_init, twist_easy_setopt, etc.)
- [ ] multi interface for external polling
- [ ] Error handling

### Milestone 7.3: Full curl Compatibility

- [ ] Support all major curl options
- [ ] Compatibility testing with existing curl scripts
- [ ] Performance parity

## Phase 8: Additional Features

### Milestone 8.1: DNS

- [ ] In-tree resolver as datagram handler
- [ ] UDP sockets on destination reactor
- [ ] DoH (DNS over HTTPS) support
- [ ] c-ares as temporary implementation (optional)

### Milestone 8.2: Proxy Support

- [ ] HTTP proxy
- [ ] HTTPS proxy (CONNECT)
- [ ] SOCKS proxy

### Milestone 8.3: Authentication

- [ ] Basic auth
- [ ] Digest auth
- [ ] Bearer tokens
- [ ] TLS client certificates

### Milestone 8.4: FTP Backend (Future)

- [ ] FTP protocol handler
- [ ] FTPS support

## Platform Support

### Milestone P.1: Windows Backend

- [ ] IOCP poll backend
- [ ] wepoll epoll emulation alternative
- [ ] Windows-specific waker implementation

### Milestone P.2: io_uring Backend

- [ ] io_uring poll backend
- [ ] Completion queue integration
- [ ] Maintain readiness model for quickstep compatibility

## Testing Strategy

1. **Unit tests**: Individual components (loop, connection, handlers)
2. **Integration tests**: Protocol stacks (TLS, HTTP/1.1, HTTP/2, HTTP/3)
3. **Interop tests**: Test against public servers
4. **Compatibility tests**: Compare with curl behavior
5. **Performance tests**: Benchmark against curl

## Build and CI

- [ ] Set up continuous integration
- [ ] Test on Linux (epoll)
- [ ] Test on macOS (kqueue)
- [ ] Test on Windows (IOCP/wepoll)
- [ ] Test with various quickstep versions
- [ ] Test with GNU readline

## Documentation

- [ ] Complete man pages
- [ ] Library API documentation
- [ ] Architecture documentation (this file)
- [ ] Contribution guidelines
- [ ] Tutorial examples

## Dependencies

Current approved dependencies:
- **quickstep** - QUIC and TLS library (required)
- **GNU readline** - Interactive input (required)

All other dependencies require explicit approval before adding.

## What to Build First

Following the architecture document's guidance:

1. **A single Loop** - Foundation of the entire system
2. **A TCP connection** - Basic connectivity
3. **An echo handler** - Simple protocol to test with
4. **Internal epoll/kqueue backend** - Native polling
5. **External on_readable driver** - External polling support
6. **Non-blocking connect with timeout** - Connection establishment
7. **pause/resume** - Flow control
8. **write-ready callback** - Write notification
9. **One reactor thread with waker and execute** - Basic threading
10. **gq_tlsconn under connection** - TLS support
11. **QUIC as datagram registration** - HTTP/3 foundation

This sequence produces the framework. The protocols (HTTP/1.1, HTTP/2, HTTP/3)
and the CLI sit on Endpoint after it.
