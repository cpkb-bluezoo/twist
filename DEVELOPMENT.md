# Twist Development Plan

## Overview

Twist is a GNU package and a protocol-neutral client. The reactor, the
transfer engine and the scheme table come first. HTTP/1.1, HTTP/2 and
HTTP/3 are the first schemes plugged into that table. Every other
libcurl scheme is a later `attach` function on the same endpoint face.

The order below matches ARCHITECTURE.md. Do not start a protocol by
adding a special case to the loop.

## Phase 0: Project skeleton (done)

- [x] GNU project files (README, AUTHORS, NEWS, INSTALL, HACKING, COPYING)
- [x] Autotools skeleton
- [x] quickstep named as the TLS and QUIC dependency

## Phase 1: GNU package shape and the loop

- [x] Automake `gnu` strictness, Libtool, gettext, Texinfo, `twist.pc`
- [x] ISO C99, GNU indentation, `twist_` / `TWIST_` exports
- [x] `struct twist_loop`: connections, timer heap, command queue, waker,
      buffer pool, `next_timeout`
- [x] epoll backend; kqueue behind the same poll operations
- [x] External driver: `on_readable`, `on_writable`, `on_timer`
- [x] `struct twist_connection`: compact inbound buffer, outbound queue,
      pause/resume, write-ready, non-blocking connect
- [x] Echo handler driven without a socket in `make check`

## Phase 2: Runtime, storage, quickstep

- [x] One reactor thread, waker, `execute`
- [x] Bounded storage pool; submit fails when full; completion via `execute`
- [x] Runtime: N loops, dial round-robin, accept round-robin, no migration
- [x] `gq_tlsauto` under the connection (plaintext `receive` only)
- [x] `gq_endpoint` on the same loop; QUIC streams are endpoints

## Phase 3: Transfer engine

- [x] URL parser and relative resolution
- [x] Scheme table covering every libcurl scheme
- [x] easy, multi (`socket_action` maps onto the loop), share
- [x] DNS datagram codec and resolver (no `getaddrinfo` on the reactor)
- [x] Connection cache pinned to a loop
- [x] Proxy wrapper slot (HTTP CONNECT, SOCKS5) in front of the scheme
- [x] A transfer may own several endpoints on one loop

## Phase 4: HTTP schemes

- [x] HTTP/1.0 and HTTP/1.1 push parser (chunked, trailers, keep-alive)
- [x] HTTP/2 frames, HPACK, streams, flow-control windows
- [x] HTTP/3 frames and QPACK on a QUIC stream endpoint
- [x] Redirects, cookies, Basic, Digest, Bearer
- [x] CLI: GNU `--help` and `--version`, plus the curl options those
      transfers need
- [x] CLI: curl exit status, standard streams, and the options the
      library already implements
- [x] gzip and deflate request compression and response decompression

## Phase 5: Remaining schemes

Each item is a new row in the scheme table. The loop does not change.

- [x] FTP/FTPS (control reply lines, same-loop data connection)
- [x] SMTP/SMTPS, IMAP/IMAPS, POP3/POP3S
- [x] MQTT/MQTTS, LDAP/LDAPS
- [x] WebSocket (`ws` / `wss`): HTTP/1 upgrade, HTTP/2 and HTTP/3 extended CONNECT
- [x] GOPHER/GOPHERS
- [x] DICT
- [ ] TELNET, RTSP
- [x] TFTP as a datagram handler
- [x] FILE through the storage pool
- [ ] SCP/SFTP, SMB/SMBS, RTMP/RTMPS
- [x] DoH as an HTTP transfer used by the resolver
- [x] DoQ and DoT, discovered with DDR when no resolver URL is set
- [ ] NTLM and Negotiate, only after an explicit dependency decision

## Tests and release

- `make check` is in-process: parsers are fed at several chunk sizes,
  including 1-byte splits. No sockets, files or wall clock.
- [ ] Split `tests/test-unit.c` into one program per subsystem.  New
      tests go in their own file.  `tests/test-coding.c` is the first.
- `make check-integration` dials a peer and skips with exit 77 when the
  peer is absent.
- [ ] Decide how integration peers are provided.  A podman lab is one
      candidate and is not chosen yet.
- `make distcheck` is the release gate.

## Dependencies

Approved:

- quickstep (required, installed, found by pkg-config)
- zlib (required)
- GNU readline (CLI only)

Nothing else is added without an explicit approval. MD5 for Digest
authentication is the HTTP Digest function, not a general crypto
library. SHA-256 for Digest uses `gq_hash_compute`.
