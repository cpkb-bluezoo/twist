#!/bin/sh
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

# Tunnels through an https proxy that speaks HTTP/2 are streams of one
# connection to it, not a connection each: the proxy (a small HTTP/2 CONNECT
# proxy of python's, which logs the connection and the stream of each CONNECT)
# is given several tunnels at once (-Z) and one after the other, and sees one
# connection.  What goes through is whole (3 MiB, past the flow-control windows).
# A proxy that speaks only HTTP/1.1 cannot share one: it gets a connection for
# each, as it did.  Skips, with status 77, without python3 with TLS 1.3, openssl
# or twist.

TWIST=${TWIST:-../src/twist}
skip ()
{
  echo "tunnel-share: $1; skipping" >&2
  exit 77
}
command -v python3 >/dev/null 2>&1 || skip "no python3"
python3 -c 'import ssl; raise SystemExit(0 if ssl.HAS_TLSv1_3 else 1)' \
  || skip "python3 has no TLS 1.3"
command -v openssl >/dev/null 2>&1 || skip "no openssl"
[ -x "$TWIST" ] || skip "twist is not built ($TWIST)"

work=$(mktemp -d "${TMPDIR:-/tmp}/twist-tunnel-share.XXXXXX") || skip "no temp dir"
pids=
cleanup ()
{
  for p in $pids; do kill "$p" 2>/dev/null; done
  rm -rf "$work"
}
trap cleanup EXIT INT TERM

fail=0
check ()
{
  if [ "$1" = ok ]; then :; else echo "FAIL $2" >&2; fail=1; fi
}

openssl req -x509 -newkey rsa:2048 -nodes -keyout "$work/key.pem" \
  -out "$work/cert.pem" -days 2 -subj /CN=localhost >/dev/null 2>&1 \
  || skip "openssl could not make a certificate"

cat > "$work/origin.py" <<'PY'
import http.server, sys

class H(http.server.BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'
    def do_GET(self):
        body = b'x' * 3145728 if self.path == '/big' else ('origin' + self.path).encode()
        self.send_response(200)
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *a):
        pass

s = http.server.ThreadingHTTPServer(('127.0.0.1', 0), H)
open(sys.argv[1], 'w').write(str(s.server_address[1]))
s.serve_forever()
PY

# A CONNECT proxy over TLS: ALPN is h2 or http/1.1 as the first argument says.
# The HTTP/2 one reads the header blocks twist sends (no Huffman coding) and
# keeps to the windows.  Each CONNECT is logged with a number for the
# connection it came on and the stream.
cat > "$work/proxy.py" <<'PY'
import socket, ssl, struct, sys, threading

alpn, cert, key, log, portfile = sys.argv[1:6]
lock = threading.Lock()
conn_no = [0]

def note(line):
    with lock:
        with open(log, 'a') as f:
            f.write(line + '\n')

def frame(t, flags, sid, payload=b''):
    return struct.pack('>I', len(payload))[1:] + bytes([t, flags]) + struct.pack('>I', sid) + payload

def read_exact(s, n):
    buf = b''
    while len(buf) < n:
        d = s.recv(n - len(buf))
        if not d:
            raise EOFError
        buf += d
    return buf

def hpack_int(b, i, prefix):
    mask = (1 << prefix) - 1
    v = b[i] & mask
    i += 1
    if v == mask:
        m = 0
        while True:
            v += (b[i] & 0x7f) << m
            m += 7
            i += 1
            if not b[i - 1] & 0x80:
                break
    return v, i

def hpack_str(b, i):
    n, i = hpack_int(b, i, 7)
    return b[i:i + n].decode(), i + n

STATIC = {1: ':authority', 2: ':method', 3: ':method', 4: ':path', 5: ':path',
          6: ':scheme', 7: ':scheme'}

def parse_block(b):
    h = {}
    i = 0
    while i < len(b):
        c = b[i]
        if c & 0x80:
            idx, i = hpack_int(b, i, 7)
            continue
        if c & 0x40:
            idx, i = hpack_int(b, i, 6)
        elif c & 0x20:
            _, i = hpack_int(b, i, 5)
            continue
        else:
            idx, i = hpack_int(b, i, 4)
        name = STATIC.get(idx) if idx else None
        if idx == 0:
            name, i = hpack_str(b, i)
        value, i = hpack_str(b, i)
        if name:
            h[name] = value
    return h

class H2Conn:
    def __init__(self, s, no):
        self.s, self.no = s, no
        self.wl = threading.Lock()
        self.cv = threading.Condition()
        self.conn_win = 65535
        self.init = 65535
        self.win = {}
        self.up = {}
    def send(self, data):
        with self.wl:
            self.s.sendall(data)
    def reader(self, sid, up):
        try:
            while True:
                d = up.recv(16384)
                if not d:
                    break
                off = 0
                while off < len(d):
                    with self.cv:
                        while self.conn_win <= 0 or self.win.get(sid, 0) <= 0:
                            self.cv.wait(1)
                            if sid not in self.up:
                                return
                        n = min(len(d) - off, self.conn_win, self.win[sid], 16384)
                        self.conn_win -= n
                        self.win[sid] -= n
                    self.send(frame(0, 0, sid, d[off:off + n]))
                    off += n
            self.send(frame(0, 1, sid))
        except (OSError, EOFError):
            pass
    def run(self):
        s = self.s
        if read_exact(s, 24) != b'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n':
            return
        self.send(frame(4, 0, 0))
        while True:
            hdr = read_exact(s, 9)
            n = int.from_bytes(hdr[:3], 'big')
            t, fl = hdr[3], hdr[4]
            sid = struct.unpack('>I', hdr[5:])[0] & 0x7fffffff
            p = read_exact(s, n) if n else b''
            if t == 4 and not fl:
                self.send(frame(4, 1, 0))
                for k in range(0, len(p), 6):
                    if struct.unpack('>H', p[k:k + 2])[0] == 4:
                        with self.cv:
                            self.init = struct.unpack('>I', p[k + 2:k + 6])[0]
            elif t == 6 and not fl:
                self.send(frame(6, 1, 0, p))
            elif t == 8:
                inc = struct.unpack('>I', p)[0]
                with self.cv:
                    if sid == 0:
                        self.conn_win += inc
                    else:
                        self.win[sid] = self.win.get(sid, self.init) + inc
                    self.cv.notify_all()
            elif t == 1:
                h = parse_block(p)
                if h.get(':method') != 'CONNECT':
                    self.send(frame(1, 5, sid, b'\x8d'))
                    continue
                host, _, port = h[':authority'].rpartition(':')
                note('conn=%d stream=%d CONNECT %s' % (self.no, sid, h[':authority']))
                up = socket.create_connection((host, int(port)))
                with self.cv:
                    self.up[sid] = up
                    self.win[sid] = self.init
                self.send(frame(1, 4, sid, b'\x88'))
                threading.Thread(target=self.reader, args=(sid, up), daemon=True).start()
            elif t == 0:
                up = self.up.get(sid)
                if up is not None and p:
                    up.sendall(p)
                    self.send(frame(8, 0, 0, struct.pack('>I', len(p)))
                              + frame(8, 0, sid, struct.pack('>I', len(p))))
                if fl & 1 and up is not None:
                    try:
                        up.shutdown(socket.SHUT_WR)
                    except OSError:
                        pass
            elif t == 3:
                up = self.up.pop(sid, None)
                if up is not None:
                    up.close()

def pipe(a, b):
    try:
        while True:
            d = a.recv(65536)
            if not d:
                break
            b.sendall(d)
    except OSError:
        pass
    try:
        b.shutdown(socket.SHUT_WR)
    except OSError:
        pass

def serve(c, no):
    try:
        if c.selected_alpn_protocol() == 'h2':
            H2Conn(c, no).run()
            return
        data = b''
        while b'\r\n\r\n' not in data:
            d = c.recv(65536)
            if not d:
                return
            data += d
        line = data.split(b'\r\n')[0].decode()
        method, target, _ = line.split(' ', 2)
        note('conn=%d stream=0 %s %s' % (no, method, target))
        host, _, port = target.rpartition(':')
        up = socket.create_connection((host, int(port)))
        c.sendall(b'HTTP/1.1 200 Connection established\r\n\r\n')
        t = threading.Thread(target=pipe, args=(up, c), daemon=True)
        t.start()
        pipe(c, up)
        t.join(2)
    except (OSError, EOFError, ssl.SSLError):
        pass
    finally:
        c.close()

ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain(cert, key)
ctx.set_alpn_protocols(['h2', 'http/1.1'] if alpn == 'h2' else ['http/1.1'])
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('127.0.0.1', 0))
s.listen(16)
open(portfile, 'w').write(str(s.getsockname()[1]))
while True:
    c, _ = s.accept()
    conn_no[0] += 1
    try:
        tc = ctx.wrap_socket(c, server_side=True)
    except (OSError, ssl.SSLError):
        continue
    threading.Thread(target=serve, args=(tc, conn_no[0]), daemon=True).start()
PY

python3 "$work/origin.py" "$work/oport" &
pids="$pids $!"
for m in h2 h1; do
  : > "$work/$m.log"
  python3 "$work/proxy.py" $m "$work/cert.pem" "$work/key.pem" "$work/$m.log" "$work/$m.port" &
  pids="$pids $!"
done
n=0
while { [ ! -s "$work/oport" ] || [ ! -s "$work/h2.port" ] || [ ! -s "$work/h1.port" ]; } \
      && [ $n -lt 50 ]; do sleep 0.1; n=$((n + 1)); done
[ -s "$work/h1.port" ] || skip "the servers did not start"
o=127.0.0.1:$(cat "$work/oport")
px () { echo "https://localhost:$(cat "$work/$1.port")"; }
conns () { sed -n 's/^conn=\([0-9]*\) .*/\1/p' "$work/$1.log" | sort -u | wc -l | tr -d ' '; }
tunnels () { wc -l < "$work/$1.log" | tr -d ' '; }
fresh () { : > "$work/$1.log"; }
get () { "$TWIST" -s -p --proxy-insecure "$@" 2>/dev/null; }

# One tunnel works, over HTTP/2 and over HTTP/1.1.
fresh h2
out=$(get -x "$(px h2)" "http://$o/a")
check "$([ "$out" = origin/a ] && [ "$(tunnels h2)" -eq 1 ] && echo ok)" "a tunnel over HTTP/2 ($out)"
fresh h1
out=$(get -x "$(px h1)" "http://$o/a")
check "$([ "$out" = origin/a ] && [ "$(tunnels h1)" -eq 1 ] && echo ok)" "a tunnel over HTTP/1.1 ($out)"

# Several at once share the connection, over HTTP/2 ...
fresh h2
get -Z -x "$(px h2)" "http://$o/a" -o "$work/o1" "http://$o/b" -o "$work/o2" \
  "http://$o/c" -o "$work/o3" "http://$o/d" -o "$work/o4"
check "$([ "$(cat "$work/o1" "$work/o2" "$work/o3" "$work/o4" | tr -d '\n')" = origin/aorigin/borigin/corigin/d ] && echo ok)" \
  "four tunnels at once, whole"
check "$([ "$(tunnels h2)" -eq 4 ] && [ "$(conns h2)" -eq 1 ] && echo ok)" \
  "on one connection to the proxy ($(conns h2) connections, $(tunnels h2) tunnels)"

# ... and one after the other.
fresh h2
get -x "$(px h2)" "http://$o/a" "http://$o/b" "http://$o/c" > "$work/seq"
check "$([ "$(tr -d '\n' < "$work/seq")" = origin/aorigin/borigin/c ] && [ "$(conns h2)" -eq 1 ] && echo ok)" \
  "three in turn on one ($(conns h2) connections)"

# ... but not over HTTP/1.1, which has one tunnel to a connection.
fresh h1
get -Z -x "$(px h1)" "http://$o/a" -o "$work/p1" "http://$o/b" -o "$work/p2" \
  "http://$o/c" -o "$work/p3"
check "$([ "$(cat "$work/p1" "$work/p2" "$work/p3" | tr -d '\n')" = origin/aorigin/borigin/c ] && [ "$(conns h1)" -eq 3 ] && echo ok)" \
  "HTTP/1.1: a connection each ($(conns h1))"

# A body that is larger than the windows is whole, and two at once.
fresh h2
get -Z -x "$(px h2)" "http://$o/big" -o "$work/big1" "http://$o/big" -o "$work/big2"
check "$([ "$(wc -c < "$work/big1")" -eq 3145728 ] && [ "$(wc -c < "$work/big2")" -eq 3145728 ] && [ "$(conns h2)" -eq 1 ] && echo ok)" \
  "3 MiB, twice at once, through the windows"

exit $fail
