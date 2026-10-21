#!/usr/bin/env python3
# Copyright (C) 2026 Chris Burdess <dog@gnu.org>
#
#    This file is part of twist.
#
#    twist is free software: you can redistribute it and/or modify it
#    under the terms of the GNU General Public License as published
#    by the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    twist is distributed in the hope that it will be useful, but
#    WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
#    General Public License for more details.
#
#    You should have received a copy of the GNU General Public
#    License along with this program.  If not, see
#    <https://www.gnu.org/licenses/>.

"""A proxy to test twist against, for integration/ssh-openssh.sh.

usage: proxy-peer.py http|socks|silent|banner MODE PORTFILE LOGFILE

Listens on the loopback, writes its port to PORTFILE, and writes one line to
LOGFILE for each thing it is asked.  The kinds silent and banner are not
proxies: they take the connection and say nothing, or only an SSH banner, and
never go on (MODE is not used).  For a proxy MODE is one of:

  ok          open any tunnel
  coalesce    send the server's first bytes in the same write as the reply
  bigheader   (http) a reply with three thousand bytes of header
  403         (http) refuse CONNECT with 403
  refuse      (socks) refuse the request with code 5
  auth        want the user name pxuser and the password pxpass
"""
import base64
import select
import socket
import struct
import sys
import threading

kind, mode, portfile, logfile = sys.argv[1:5]
log = open(logfile, "a", buffering=1)
lock = threading.Lock()


def say(text):
    with lock:
        log.write(text + "\n")


def relay(a, b):
    socks = [a, b]
    while True:
        r, _, _ = select.select(socks, [], [], 30)
        if not r:
            return
        for s in r:
            d = s.recv(65536)
            if not d:
                return
            (b if s is a else a).sendall(d)


def upstream(host, port):
    for res in socket.getaddrinfo(host, port, type=socket.SOCK_STREAM):
        try:
            u = socket.socket(res[0], res[1], res[2])
            u.connect(res[4])
            return u
        except OSError:
            pass
    return None


def first_bytes(u):
    if mode in ("coalesce", "bigheader"):
        r, _, _ = select.select([u], [], [], 1)
        if r:
            return u.recv(65536)
    return b""


def http(c):
    buf = b""
    while b"\r\n\r\n" not in buf:
        d = c.recv(4096)
        if not d:
            return
        buf += d
    lines = buf.decode("latin1").split("\r\n")
    say("CONNECT " + lines[0].split()[1])
    if mode == "403":
        c.sendall(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
        return
    if mode == "auth":
        want = "Basic " + base64.b64encode(b"pxuser:pxpass").decode()
        got = [l.split(":", 1)[1].strip() for l in lines
               if l.lower().startswith("proxy-authorization:")]
        if got != [want]:
            say("407")
            c.sendall(b"HTTP/1.1 407 Proxy Authentication Required\r\n"
                      b"Proxy-Authenticate: Basic realm=\"x\"\r\n"
                      b"Content-Length: 0\r\n\r\n")
            return
    host, port = lines[0].split()[1].rsplit(":", 1)
    u = upstream(host.strip("[]"), int(port))
    if u is None:
        c.sendall(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
        return
    head = b"HTTP/1.1 200 Connection established\r\n"
    if mode == "bigheader":
        head += b"X-Pad: " + b"a" * 3000 + b"\r\n"
    c.sendall(head + b"\r\n" + first_bytes(u))
    relay(c, u)


def socks(c):
    g = c.recv(262)
    if len(g) < 3 or g[0] != 5:
        return
    if mode == "auth":
        if 2 not in g[2:2 + g[1]]:
            say("no method")
            c.sendall(b"\x05\xff")
            return
        c.sendall(b"\x05\x02")
        a = c.recv(600)
        user, pw = a[2:2 + a[1]], a[3 + a[1]:3 + a[1] + a[2 + a[1]]]
        if (user, pw) != (b"pxuser", b"pxpass"):
            say("rejected")
            c.sendall(b"\x01\x01")
            return
        c.sendall(b"\x01\x00")
    else:
        c.sendall(b"\x05\x00")
    r = c.recv(600)
    if r[3] == 1:
        host = socket.inet_ntoa(r[4:8])
        port = struct.unpack(">H", r[8:10])[0]
    elif r[3] == 4:
        host = socket.inet_ntop(socket.AF_INET6, r[4:20])
        port = struct.unpack(">H", r[20:22])[0]
    else:
        n = r[4]
        host = r[5:5 + n].decode()
        port = struct.unpack(">H", r[5 + n:7 + n])[0]
    say("CONNECT atyp%d %s:%d" % (r[3], host, port))
    if mode == "refuse":
        c.sendall(b"\x05\x05\x00\x01\x00\x00\x00\x00\x00\x00")
        return
    u = upstream(host, port)
    if u is None:
        c.sendall(b"\x05\x04\x00\x01\x00\x00\x00\x00\x00\x00")
        return
    c.sendall(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00" + first_bytes(u))
    relay(c, u)


def stall(c):
    if kind == "banner":
        c.sendall(b"SSH-2.0-stall_1\r\n")
    select.select([], [], [], 600)


def handle(c):
    try:
        {"http": http, "socks": socks}.get(kind, stall)(c)
    except OSError:
        pass
    finally:
        c.close()


s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", 0))
s.listen(8)
with open(portfile, "w") as f:
    f.write("%d\n" % s.getsockname()[1])
while True:
    c, _ = s.accept()
    threading.Thread(target=handle, args=(c,), daemon=True).start()
