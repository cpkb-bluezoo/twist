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

# A nameserver for dns-ddr.sh: UDP on 127.0.0.1:53 and DNS over TLS on a port
# of its own.  It tells (RFC 9462) of a DoT resolver at resolver.test, port
# TLSPORT, address 127.0.0.1, and answers www.test with 127.0.0.1 on both.
# Each query that is answered is written to LOG as "udp|dot TYPE NAME".
#
#   dns-peer.py CERT KEY TLSPORT LOG READY

import socket, ssl, struct, sys, threading

cert, key, tlsport, log, ready = sys.argv[1:6]
tlsport = int(tlsport)
lock = threading.Lock()


def note(how, qtype, qname):
    with lock:
        with open(log, "a") as f:
            f.write("%s %d %s\n" % (how, qtype, qname))


def wire_name(name):
    out = b""
    for label in name.strip(".").split("."):
        out += bytes([len(label)]) + label.encode()
    return out + b"\0"


def parse_query(msg):
    qid = msg[:2]
    i = 12
    labels = []
    while msg[i]:
        labels.append(msg[i + 1:i + 1 + msg[i]].decode())
        i += msg[i] + 1
    qtype = struct.unpack("!H", msg[i + 1:i + 3])[0]
    return qid, ".".join(labels), qtype, msg[12:i + 5]


def answer(msg, how):
    qid, qname, qtype, question = parse_query(msg)
    note(how, qtype, qname)
    rdata = None
    if qname == "_dns.resolver.arpa" and qtype == 64:
        rdata = (struct.pack("!H", 1) + wire_name("resolver.test")
                 + struct.pack("!HH", 1, 4) + b"\x03dot"
                 + struct.pack("!HHH", 3, 2, tlsport)
                 + struct.pack("!HH", 4, 4) + bytes([127, 0, 0, 1]))
    elif qname == "www.test" and qtype == 1:
        rdata = bytes([127, 0, 0, 1])
    answers = b""
    if rdata is not None:
        answers = (b"\xc0\x0c" + struct.pack("!HHIH", qtype, 1, 60, len(rdata))
                   + rdata)
    head = qid + struct.pack("!HHHHH", 0x8180, 1, 1 if rdata else 0, 0, 0)
    return head + question + answers


def udp():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", 53))
    return s


def serve_udp(s):
    while True:
        msg, addr = s.recvfrom(4096)
        try:
            s.sendto(answer(msg, "udp"), addr)
        except (IndexError, struct.error):
            pass


def recv_exact(c, n):
    data = b""
    while len(data) < n:
        d = c.recv(n - len(data))
        if not d:
            raise OSError("closed")
        data += d
    return data


def serve_dot(c):
    try:
        while True:
            n = struct.unpack("!H", recv_exact(c, 2))[0]
            reply = answer(recv_exact(c, n), "dot")
            c.sendall(struct.pack("!H", len(reply)) + reply)
    except (OSError, ssl.SSLError, IndexError, struct.error):
        pass
    finally:
        c.close()


u = udp()
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.minimum_version = ssl.TLSVersion.TLSv1_2
ctx.load_cert_chain(cert, key)
t = socket.socket()
t.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
t.bind(("127.0.0.1", tlsport))
t.listen(8)
threading.Thread(target=serve_udp, args=(u,), daemon=True).start()
open(ready, "w").write("ok")
while True:
    c, _ = t.accept()
    try:
        c = ctx.wrap_socket(c, server_side=True)
    except (OSError, ssl.SSLError):
        continue
    threading.Thread(target=serve_dot, args=(c,), daemon=True).start()
