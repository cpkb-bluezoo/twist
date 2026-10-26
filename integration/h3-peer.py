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

# An HTTP/3 peer for h3-masque.sh, on aioquic (QUIC and HTTP/3 in Python):
#
#   h3-peer.py origin CERT KEY PORT LOG READY
#       Answers GET with "h3 ok".  GET /bidi first opens a stream of its own
#       that is bidirectional, which a server may not do in HTTP/3 (RFC 9114,
#       section 6.1).  The close of each connection is written to LOG as
#       "closed 0xCODE".
#   h3-peer.py proxy CERT KEY PORT LOG READY [REFUSED]
#       A proxy for CONNECT-UDP (RFC 9298): a CONNECT with :protocol
#       connect-udp to /.well-known/masque/udp/HOST/PORT/ is 200, and the
#       HTTP Datagrams of the stream are UDP to and from HOST:PORT.  A PORT
#       equal to REFUSED is 403.  Each tunnel opened is written to LOG as
#       "tunnel HOST PORT".

import asyncio, sys

from aioquic.asyncio import QuicConnectionProtocol, serve
from aioquic.h3.connection import H3_ALPN, H3Connection
from aioquic.h3.events import DatagramReceived, HeadersReceived
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import ConnectionTerminated, ProtocolNegotiated

mode, cert, key, port, log, ready = sys.argv[1:7]
refused = sys.argv[7] if len(sys.argv) > 7 else None


def note(text):
    with open(log, "a") as f:
        f.write(text + "\n")


class Peer(QuicConnectionProtocol):
    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        self._h3 = None
        self._udp = {}

    def quic_event_received(self, event):
        if isinstance(event, ProtocolNegotiated) and event.alpn_protocol in H3_ALPN:
            self._h3 = H3Connection(self._quic, enable_webtransport=(mode == "proxy"))
        elif isinstance(event, ConnectionTerminated):
            note("closed 0x%x" % event.error_code)
        if self._h3 is not None:
            for e in self._h3.handle_event(event):
                self.h3_event(e)

    def h3_event(self, event):
        if isinstance(event, HeadersReceived):
            headers = dict(event.headers)
            if mode == "origin":
                self.origin_request(event.stream_id, headers)
            else:
                self.proxy_request(event.stream_id, headers)
        elif isinstance(event, DatagramReceived) and mode == "proxy":
            transport = self._udp.get(event.stream_id)
            if transport is not None and event.data[:1] == b"\0":
                transport.sendto(event.data[1:])

    def origin_request(self, stream_id, headers):
        note("request %s" % headers.get(b":path", b"").decode())
        if headers.get(b":path") == b"/bidi":
            # Stream 1 is the first the server may open that is bidirectional.
            self._quic._remote_max_streams_bidi = max(
                self._quic._remote_max_streams_bidi, 4)
            sid = self._quic.get_next_available_stream_id()
            self._quic.send_stream_data(sid, b"not for you", end_stream=False)
        self._h3.send_headers(stream_id, [
            (b":status", b"200"), (b"content-length", b"5")])
        self._h3.send_data(stream_id, b"h3 ok", end_stream=True)
        self.transmit()

    def proxy_request(self, stream_id, headers):
        parts = headers.get(b":path", b"").decode().strip("/").split("/")
        if (headers.get(b":method") != b"CONNECT"
                or headers.get(b":protocol") != b"connect-udp"
                or len(parts) != 5 or parts[:3] != [".well-known", "masque", "udp"]):
            self._h3.send_headers(stream_id, [(b":status", b"404")], end_stream=True)
            self.transmit()
            return
        host, tport = parts[3], parts[4]
        if tport == refused:
            self._h3.send_headers(stream_id, [(b":status", b"403")], end_stream=True)
            self.transmit()
            return
        note("tunnel %s %s" % (host, tport))
        peer = self

        class Udp(asyncio.DatagramProtocol):
            def datagram_received(self, data, addr):
                try:
                    peer._h3.send_datagram(stream_id, b"\0" + data)
                    peer.transmit()
                except Exception as e:
                    note("reply of %d bytes failed: %r" % (len(data), e))

        async def open_flow():
            transport, _ = await asyncio.get_running_loop().create_datagram_endpoint(
                Udp, remote_addr=(host, int(tport)))
            self._udp[stream_id] = transport

        asyncio.ensure_future(open_flow())
        self._h3.send_headers(stream_id, [
            (b":status", b"200"), (b"capsule-protocol", b"?1")])
        self.transmit()


async def main():
    # A proxy carries QUIC packets of 1200 bytes (the Initial of the target's
    # peer is padded to that) in its own, so its own must be larger.
    config = QuicConfiguration(is_client=False, alpn_protocols=H3_ALPN,
                               max_datagram_frame_size=65536,
                               max_datagram_size=1452 if mode == "proxy" else 1280)
    config.load_cert_chain(cert, key)
    await serve("127.0.0.1", int(port), configuration=config, create_protocol=Peer)
    open(ready, "w").write("ok")
    await asyncio.Event().wait()


asyncio.run(main())
