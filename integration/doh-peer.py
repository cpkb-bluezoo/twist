#!/usr/bin/env python3
# Copyright (C) 2026 Chris Burdess <dog@gnu.org>
#
# This file is part of twist.
#
# twist is free software: you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published
# by the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# twist is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public
# License along with this program.  If not, see
# <https://www.gnu.org/licenses/>.

# A DNS-over-HTTPS resolver (RFC 8484) for dns-doh.sh, over HTTP/2 that is
# spoken here by hand, which is little: the requests' headers are not read, only
# their bodies, which are the queries.
#
#   doh-peer.py CERT KEY PORT LOG READY DELAY_MS ALPN [TLSVERSION]
#
# ALPN is h2 or http/1.1, what the resolver offers, and TLSVERSION 1.2 or 1.3
# the only TLS version it speaks (the default is both).  Each query is answered
# DELAY_MS after it arrives: 127.0.0.1 for an A query, nothing for any other
# type.  What happens is written to LOG, one line each:
#   alpn NAME          what was agreed
#   query TYPE         a whole query has arrived
#   answer TYPE SEEN   it is answered, SEEN queries having arrived by then

import asyncio, ssl, struct, sys

cert, key, port, log, ready, delay, offer = sys.argv[1:8]
tlsonly = sys.argv[8] if len(sys.argv) > 8 else ""
delay = int(delay) / 1000.0
seen = 0
PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"


def note(text):
    with open(log, "a") as f:
        f.write(text + "\n")


def frame(kind, flags, stream, payload=b""):
    return struct.pack(">I", len(payload))[1:] + bytes([kind, flags]) \
        + struct.pack(">I", stream) + payload


def reply(msg):
    pos = 12
    while msg[pos] != 0:
        pos += 1 + msg[pos]
    qname = msg[12:pos + 1]
    qtype = struct.unpack(">H", msg[pos + 1:pos + 3])[0]
    body = b""
    if qtype == 1:
        body = b"\xc0\x0c" + struct.pack(">HHIH", 1, 1, 30, 4) + bytes([127, 0, 0, 1])
    head = struct.pack(">HHHHHH", struct.unpack(">H", msg[:2])[0], 0x8180, 1,
                       1 if body else 0, 0, 0)
    return qtype, head + qname + struct.pack(">HH", qtype, 1) + body


async def h2(reader, writer):
    global seen
    pre = await reader.readexactly(len(PREFACE))
    if pre != PREFACE:
        writer.close()
        return
    writer.write(frame(4, 0, 0))
    bodies = {}
    loop = asyncio.get_running_loop()

    def answer(stream, msg):
        qtype, out = reply(msg)
        note("answer %d %d" % (qtype, seen))
        head = bytes([0x88]) + b"\x00" + bytes([12]) + b"content-type" \
            + bytes([23]) + b"application/dns-message"
        writer.write(frame(1, 4, stream, head) + frame(0, 1, stream, out))

    try:
        while True:
            hdr = await reader.readexactly(9)
            n = int.from_bytes(hdr[:3], "big")
            kind, flags = hdr[3], hdr[4]
            stream = struct.unpack(">I", hdr[5:])[0] & 0x7fffffff
            payload = await reader.readexactly(n) if n else b""
            if kind == 4 and not flags & 1:
                writer.write(frame(4, 1, 0))
            elif kind == 6 and not flags & 1:
                writer.write(frame(6, 1, 0, payload))
            elif kind in (0, 1) and stream:
                if kind == 0:
                    if flags & 8:
                        payload = payload[1:len(payload) - payload[0]]
                    bodies[stream] = bodies.get(stream, b"") + payload
                else:
                    bodies.setdefault(stream, b"")
                if flags & 1:
                    msg = bodies.pop(stream)
                    seen += 1
                    note("query %d" % reply(msg)[0])
                    loop.call_later(delay, answer, stream, msg)
            await writer.drain()
    except (asyncio.IncompleteReadError, ConnectionError):
        pass


async def h1(reader, writer):
    global seen
    try:
        while True:
            head = await reader.readuntil(b"\r\n\r\n")
            n = 0
            for line in head.split(b"\r\n"):
                if line.lower().startswith(b"content-length:"):
                    n = int(line.split(b":")[1])
            msg = await reader.readexactly(n)
            seen += 1
            note("query %d" % reply(msg)[0])
            await asyncio.sleep(delay)
            qtype, out = reply(msg)
            note("answer %d %d" % (qtype, seen))
            writer.write(b"HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\n"
                         b"Content-Length: %d\r\n\r\n" % len(out) + out)
            await writer.drain()
    except (asyncio.IncompleteReadError, ConnectionError):
        pass


async def handle(reader, writer):
    proto = writer.get_extra_info("ssl_object").selected_alpn_protocol()
    note("alpn %s" % proto)
    await (h2 if proto == "h2" else h1)(reader, writer)


async def main():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    if tlsonly:
        v = ssl.TLSVersion.TLSv1_2 if tlsonly == "1.2" else ssl.TLSVersion.TLSv1_3
        ctx.minimum_version = v
        ctx.maximum_version = v
    ctx.load_cert_chain(cert, key)
    ctx.set_alpn_protocols(["h2", "http/1.1"] if offer == "h2" else ["http/1.1"])
    server = await asyncio.start_server(handle, "127.0.0.1", int(port), ssl=ctx)
    open(ready, "w").write("ok")
    await server.serve_forever()


asyncio.run(main())
