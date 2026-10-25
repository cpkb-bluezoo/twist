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

# What an HTTP proxy is asked to do for an http:// URL: forward it (the request
# is addressed to the proxy, in the absolute form) or open a tunnel for it
# (CONNECT), which -p/--proxytunnel asks for.  A proxy that will not forward
# (it answers 405 or 501 to the absolute form) is tunnelled to, once for a
# request that is safe to repeat, and from then on for every request through
# that proxy; a request that is not safe to repeat is not sent twice; and
# -p is a tunnel, with no second try if the proxy refuses it.  Three proxies
# of python's, logging what they are asked, in front of an origin of
# python's.  Skips, with status 77, without python3 or twist.

TWIST=${TWIST:-../src/twist}
skip ()
{
  echo "proxy-role: $1; skipping" >&2
  exit 77
}
command -v python3 >/dev/null 2>&1 || skip "no python3"
[ -x "$TWIST" ] || skip "twist is not built ($TWIST)"

work=$(mktemp -d "${TMPDIR:-/tmp}/twist-proxy-role.XXXXXX") || skip "no temp dir"
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

cat > "$work/origin.py" <<'PY'
import http.server, sys

class H(http.server.BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'
    def reply(self):
        n = int(self.headers.get('Content-Length', 0))
        self.rfile.read(n)
        body = b'origin'
        self.send_response(200)
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    do_GET = do_POST = reply
    def log_message(self, *a):
        pass

s = http.server.ThreadingHTTPServer(('127.0.0.1', 0), H)
open(sys.argv[1], 'w').write(str(s.server_address[1]))
s.serve_forever()
PY

# A proxy: MODE is normal, noforward (501 to the absolute form) or noconnect
# (405 to CONNECT).  Each request line it is given is logged.
cat > "$work/proxy.py" <<'PY'
import socket, sys, threading, urllib.parse

mode, log, portfile = sys.argv[1], sys.argv[2], sys.argv[3]

def note(line):
    with open(log, 'a') as f:
        f.write(line + '\n')

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

def say(c, code, text, extra=b''):
    body = text.encode()
    c.sendall(b'HTTP/1.1 %d %s\r\nContent-Length: %d\r\nConnection: close\r\n%s\r\n'
              % (code, text.encode(), len(body), extra) + body)

def serve(c):
    data = b''
    while b'\r\n\r\n' not in data:
        d = c.recv(65536)
        if not d:
            c.close()
            return
        data += d
    head, _, rest = data.partition(b'\r\n\r\n')
    line = head.split(b'\r\n')[0].decode()
    method, target, _ = line.split(' ', 2)
    note('%s %s' % (method, target))
    if method == 'CONNECT':
        if mode == 'noconnect':
            say(c, 405, 'Method Not Allowed')
            c.close()
            return
        host, _, port = target.rpartition(':')
        up = socket.create_connection((host, int(port)))
        c.sendall(b'HTTP/1.1 200 Connection established\r\n\r\n')
        if rest:
            up.sendall(rest)
        t = threading.Thread(target=pipe, args=(up, c), daemon=True)
        t.start()
        pipe(c, up)
        t.join(2)
        c.close()
        return
    if mode == 'noforward':
        say(c, 501, 'Not Implemented')
        c.close()
        return
    u = urllib.parse.urlsplit(target)
    up = socket.create_connection((u.hostname, u.port or 80))
    path = (u.path or '/') + ('?' + u.query if u.query else '')
    lines = head.split(b'\r\n')[1:]
    lines = [l for l in lines if not l.lower().startswith(b'connection:')]
    up.sendall(('%s %s HTTP/1.1\r\n' % (method, path)).encode()
               + b'\r\n'.join(lines) + b'\r\nConnection: close\r\n\r\n' + rest)
    t = threading.Thread(target=pipe, args=(c, up), daemon=True)
    t.start()
    pipe(up, c)
    c.close()

s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('127.0.0.1', 0))
s.listen(16)
open(portfile, 'w').write(str(s.getsockname()[1]))
while True:
    c, _ = s.accept()
    threading.Thread(target=serve, args=(c,), daemon=True).start()
PY

python3 "$work/origin.py" "$work/oport" &
pids="$pids $!"
for m in normal noforward noconnect; do
  : > "$work/$m.log"
  python3 "$work/proxy.py" $m "$work/$m.log" "$work/$m.port" &
  pids="$pids $!"
done
n=0
while { [ ! -s "$work/oport" ] || [ ! -s "$work/normal.port" ] \
        || [ ! -s "$work/noforward.port" ] || [ ! -s "$work/noconnect.port" ]; } \
      && [ $n -lt 50 ]; do sleep 0.1; n=$((n + 1)); done
[ -s "$work/noconnect.port" ] || skip "the servers did not start"
o=127.0.0.1:$(cat "$work/oport")
px () { echo "http://127.0.0.1:$(cat "$work/$1.port")"; }
lines () { cat "$work/$1.log" 2>/dev/null | tr '\n' ' '; }
fresh () { : > "$work/$1.log"; }
get () { "$TWIST" -s "$@" 2>/dev/null; }

# Forwarded: the proxy is asked for the whole URL.
fresh normal
out=$(get -x "$(px normal)" "http://$o/a")
check "$([ "$out" = origin ] && [ "$(lines normal)" = "GET http://$o/a " ] && echo ok)" \
  "an http URL is forwarded ($out, $(lines normal))"

# -p: a tunnel is opened for it.
fresh normal
out=$(get -p -x "$(px normal)" "http://$o/a")
check "$([ "$out" = origin ] && [ "$(lines normal)" = "CONNECT $o " ] && echo ok)" \
  "-p: CONNECT ($out, $(lines normal))"
fresh normal
out=$(get --proxytunnel -x "$(px normal)" "http://$o/a")
check "$([ "$out" = origin ] && [ "$(lines normal)" = "CONNECT $o " ] && echo ok)" \
  "--proxytunnel"

# A proxy that will not forward: tunnelled to, after one try.
fresh noforward
out=$(get -x "$(px noforward)" "http://$o/a")
check "$([ "$out" = origin ] && [ "$(lines noforward)" = "GET http://$o/a CONNECT $o " ] && echo ok)" \
  "a 501 to the forward is a CONNECT next ($out, $(lines noforward))"

# ... and remembered: the second URL of the command goes straight to CONNECT.
fresh noforward
out=$(get -x "$(px noforward)" "http://$o/a" "http://$o/b")
check "$([ "$out" = originorigin ] && [ "$(lines noforward)" = "GET http://$o/a CONNECT $o CONNECT $o " ] && echo ok)" \
  "and the proxy is remembered ($out, $(lines noforward))"

# A request that is not safe to repeat is not sent twice.
fresh noforward
out=$(get -x "$(px noforward)" -d x "http://$o/a")
check "$([ "$out" = 'Not Implemented' ] && [ "$(lines noforward)" = "POST http://$o/a " ] && echo ok)" \
  "a POST is not tried again ($out, $(lines noforward))"

# -p is what was asked for: a proxy that refuses it is not forwarded to.
fresh noconnect
"$TWIST" -s -p -x "$(px noconnect)" "http://$o/a" >/dev/null 2>&1
rc=$?
check "$([ $rc -eq 56 ] && [ "$(lines noconnect)" = "CONNECT $o " ] && echo ok)" \
  "-p to a proxy that refuses CONNECT is status 56, no second try ($rc, $(lines noconnect))"

exit $fail
