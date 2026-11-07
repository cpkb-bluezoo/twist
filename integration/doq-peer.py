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

# A DNS-over-QUIC resolver (RFC 9250) for dns-doq.sh, on aioquic:
#
#   doq-peer.py CERT KEY PORT LOG READY DELAY_MS
#
# Each query arrives on a stream of its own, and is answered DELAY_MS later on
# the same stream: 127.0.0.1 for an A query, and nothing for any other type.
# What happens is written to LOG, one line each:
#   connection         a connection was made
#   query TYPE STREAM  a whole query has arrived, on the stream STREAM
#   answer TYPE SEEN   it is answered, SEEN queries having arrived by then
#   bad                a query that was not one stream and one message

import asyncio, struct, sys

from aioquic.asyncio import QuicConnectionProtocol, serve
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import StreamDataReceived

cert, key, port, log, ready, delay = sys.argv[1:7]
delay = int(delay) / 1000.0
seen = 0


def note(text):
    with open(log, "a") as f:
        f.write(text + "\n")


def question(msg):
    pos = 12
    while msg[pos] != 0:
        pos += 1 + msg[pos]
    return msg[12:pos + 1], struct.unpack(">H", msg[pos + 1:pos + 3])[0]


def reply(msg, qname, qtype):
    flags = 0x8180
    body = b""
    if qtype == 1:
        body = qname_ptr() + struct.pack(">HHIH", 1, 1, 30, 4) + bytes([127, 0, 0, 1])
    head = struct.pack(">HHHHHH", struct.unpack(">H", msg[:2])[0], flags, 1,
                       1 if body else 0, 0, 0)
    return head + qname + struct.pack(">HH", qtype, 1) + body


def qname_ptr():
    return b"\xc0\x0c"


class Peer(QuicConnectionProtocol):
    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        self._buf = {}
        note("connection")

    def quic_event_received(self, event):
        global seen
        if not isinstance(event, StreamDataReceived):
            return
        buf = self._buf.get(event.stream_id, b"") + event.data
        self._buf[event.stream_id] = buf
        if not event.end_stream:
            return
        n = struct.unpack(">H", buf[:2])[0] if len(buf) >= 2 else -1
        if n != len(buf) - 2:
            note("bad")
            return
        msg = buf[2:]
        qname, qtype = question(msg)
        seen += 1
        note("query %d %d" % (qtype, event.stream_id))
        asyncio.get_running_loop().call_later(
            delay, self.answer, event.stream_id, msg, qname, qtype)

    def answer(self, stream_id, msg, qname, qtype):
        note("answer %d %d" % (qtype, seen))
        out = reply(msg, qname, qtype)
        self._quic.send_stream_data(stream_id, struct.pack(">H", len(out)) + out,
                                    end_stream=True)
        self.transmit()


async def main():
    config = QuicConfiguration(is_client=False, alpn_protocols=["doq"])
    config.load_cert_chain(cert, key)
    await serve("127.0.0.1", int(port), configuration=config, create_protocol=Peer)
    open(ready, "w").write("ok")
    await asyncio.Event().wait()


asyncio.run(main())
