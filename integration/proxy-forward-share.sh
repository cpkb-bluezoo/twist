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

# Forwarded requests share the connection to the proxy, whatever their
# origin: the request names the origin (the absolute form, or :authority), so
# the connection is the proxy's and not the origin's.  nghttpx is the proxy,
# behind a relay of python's that counts the connections made to it (it passes
# the TLS through, so ALPN is nghttpx's), in front of two origins (nghttpx sends all to the first, which echoes the
# request target, so what matters is the count).  Over HTTP/2
# several origins at once or in turn are one connection; over HTTP/1.1 they
# are one in turn (kept alive) and as many as there are at once.  Skips, with
# status 77, without nghttpx, openssl, python3 or twist.

TWIST=${TWIST:-../src/twist}
skip ()
{
  echo "proxy-forward-share: $1; skipping" >&2
  exit 77
}
command -v nghttpx >/dev/null 2>&1 || skip "no nghttpx"
command -v openssl >/dev/null 2>&1 || skip "no openssl"
command -v python3 >/dev/null 2>&1 || skip "no python3"
[ -x "$TWIST" ] || skip "twist is not built ($TWIST)"

work=$(mktemp -d "${TMPDIR:-/tmp}/twist-proxy-forward-share.XXXXXX") || skip "no temp dir"
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
        body = ('%s%s' % (sys.argv[2], self.path)).encode()
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
cat > "$work/relay.py" <<'PY'
import socket, sys, threading

target, log, portfile = int(sys.argv[1]), sys.argv[2], sys.argv[3]

def pipe(a, b):
    try:
        while True:
            d = a.recv(65536)
            if not d:
                break
            b.sendall(d)
    except OSError:
        pass
    for x in (a, b):
        try:
            x.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass

s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('127.0.0.1', 0))
s.listen(16)
open(portfile, 'w').write(str(s.getsockname()[1]))
while True:
    c, _ = s.accept()
    with open(log, 'a') as f:
        f.write('conn\n')
    u = socket.create_connection(('127.0.0.1', target))
    threading.Thread(target=pipe, args=(c, u), daemon=True).start()
    threading.Thread(target=pipe, args=(u, c), daemon=True).start()
PY
python3 "$work/origin.py" "$work/aport" A &
pids="$pids $!"
python3 "$work/origin.py" "$work/bport" B &
pids="$pids $!"
n=0
while { [ ! -s "$work/aport" ] || [ ! -s "$work/bport" ]; } && [ $n -lt 50 ]; do sleep 0.1; n=$((n + 1)); done
[ -s "$work/bport" ] || skip "the origins did not start"
a=127.0.0.1:$(cat "$work/aport")
b=127.0.0.1:$(cat "$work/bport")

pport=$((20000 + $$ % 20000))
nghttpx -s --add-x-forwarded-for -f"127.0.0.1,$pport" \
  -b"127.0.0.1,$(cat "$work/aport");;no-tls" "$work/key.pem" "$work/cert.pem" \
  >"$work/nx.log" 2>&1 &
pids="$pids $!"
sleep 1
kill -0 "${pids##* }" 2>/dev/null || skip "nghttpx did not start"
: > "$work/relay.log"
python3 "$work/relay.py" $pport "$work/relay.log" "$work/rport" &
pids="$pids $!"
n=0
while [ ! -s "$work/rport" ] && [ $n -lt 50 ]; do sleep 0.1; n=$((n + 1)); done
[ -s "$work/rport" ] || skip "the relay did not start"
px=https://localhost:$(cat "$work/rport")
conns () { wc -l < "$work/relay.log" | tr -d ' '; }
fresh () { : > "$work/relay.log"; }
get () { "$TWIST" -s --proxy-insecure -x "$px" "$@" 2>/dev/null; }

# Two origins in turn, over HTTP/2: one connection to the proxy.
fresh
out=$(get "http://$a/1" "http://$b/2")
check "$([ "$out" = "Ahttp://$a/1Ahttp://$b/2" ] && [ "$(conns)" -eq 1 ] && echo ok)" \
  "two origins in turn, HTTP/2: one connection ($out, $(conns))"

# Several at once, over HTTP/2: one connection.
fresh
get -Z "http://$a/1" -o "$work/o1" "http://$b/2" -o "$work/o2" \
  "http://$a/3" -o "$work/o3" "http://$b/4" -o "$work/o4"
out=$(cat "$work/o1" "$work/o2" "$work/o3" "$work/o4")
check "$([ "$out" = "Ahttp://$a/1Ahttp://$b/2Ahttp://$a/3Ahttp://$b/4" ] && [ "$(conns)" -eq 1 ] && echo ok)" \
  "four at once, two origins, HTTP/2: one connection ($out, $(conns))"

# Over HTTP/1.1 they are in turn on a kept connection.
fresh
out=$(get --http1.1 "http://$a/1" "http://$b/2" "http://$a/3")
check "$([ "$out" = "Ahttp://$a/1Ahttp://$b/2Ahttp://$a/3" ] && [ "$(conns)" -eq 1 ] && echo ok)" \
  "three in turn, HTTP/1.1: one connection ($out, $(conns))"

exit $fail
