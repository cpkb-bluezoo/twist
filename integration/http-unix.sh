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

# HTTP over a Unix socket (--unix-socket, --abstract-unix-socket), against a
# server of python's on a socket in a temporary directory and one in the
# abstract namespace: the URL gives the Host header and the request target, a
# proxy in the environment is not used, a redirect to another host goes to the
# same socket, https is checked against the URL's name, and a socket that is
# not there is status 7.  Skips, with status 77, without python3, openssl or
# twist.

TWIST=${TWIST:-../src/twist}
skip ()
{
  echo "http-unix: $1; skipping" >&2
  exit 77
}
command -v python3 >/dev/null 2>&1 || skip "no python3"
command -v openssl >/dev/null 2>&1 || skip "no openssl"
[ -x "$TWIST" ] || skip "twist is not built ($TWIST)"

work=$(mktemp -d "${TMPDIR:-/tmp}/twist-http-unix.XXXXXX") || skip "no temp dir"
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
  if [ "$1" = ok ]; then
    :
  else
    echo "FAIL $2" >&2
    fail=1
  fi
}
is () { [ "$1" = "$2" ] && echo ok; }

openssl req -x509 -newkey rsa:2048 -nodes -keyout "$work/key.pem" \
  -out "$work/cert.pem" -days 2 -subj "/CN=unix.example" \
  -addext "subjectAltName=DNS:unix.example" \
  -addext "basicConstraints=critical,CA:TRUE" >/dev/null 2>&1 \
  || skip "openssl cannot make a certificate"

cat > "$work/server.py" <<'PY'
import http.server, os, socketserver, ssl, sys
class H(http.server.BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'
    def log_message(self, *a): pass
    def address_string(self): return 'unix'
    def do_GET(self):
        if self.path.startswith('/redir'):
            self.send_response(302)
            self.send_header('Location', 'http://other.example/landed')
            self.send_header('Content-Length', '0')
            self.end_headers()
            return
        body = ('%s %s\n' % (self.path, self.headers.get('Host'))).encode()
        self.send_response(200)
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)
class S(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True
addr, tls = sys.argv[1], sys.argv[2:]
if addr.startswith('@'):
    addr = '\0' + addr[1:]
elif os.path.exists(addr):
    os.unlink(addr)
srv = S(addr, H)
if tls:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(tls[0], tls[1])
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
print('ready', flush=True)
srv.serve_forever()
PY
start ()
{
  python3 -I "$work/server.py" "$@" > "$work/ready.$$" 2>/dev/null &
  pids="$pids $!"
  i=0
  while [ ! -s "$work/ready.$$" ] && [ $i -lt 50 ]; do sleep 0.1; i=$((i + 1)); done
  [ -s "$work/ready.$$" ] || skip "the server did not start"
  rm -f "$work/ready.$$"
}
start "$work/plain.sock"
start "@twist-unix-test-$$"
start "$work/tls.sock" "$work/cert.pem" "$work/key.pem"

for v in http_proxy HTTP_PROXY https_proxy HTTPS_PROXY all_proxy ALL_PROXY \
         no_proxy NO_PROXY; do
  unset $v
done
get () { timeout 20 "$TWIST" -s -S "$@" 2>/dev/null; }

check "$(is "$(get --unix-socket "$work/plain.sock" http://host.example/x)" "/x host.example")" \
  "a request goes to the socket, with the URL's Host and path"
check "$(is "$(get --abstract-unix-socket "twist-unix-test-$$" http://abs.example/y)" "/y abs.example")" \
  "and to an abstract one"
check "$(is "$(get --unix-socket "$work/plain.sock" http://host.example:8080/p?q=1)" "/p?q=1 host.example:8080")" \
  "a port in the URL is for the Host header only"

# Two requests in one run, on one socket.
out=$(get --unix-socket "$work/plain.sock" http://host.example/a --next \
        --unix-socket "$work/plain.sock" http://host.example/b | tr '\n' ' ')
check "$(is "$out" "/a host.example /b host.example ")" "two URLs, one after the other"

# A proxy, from the environment or the command line, is not used: this one is
# not there, and a request that went to it would fail.
out=$(http_proxy=http://127.0.0.1:1 get --unix-socket "$work/plain.sock" http://host.example/z)
check "$(is "$out" "/z host.example")" "a proxy in the environment is not used"
out=$(get -x http://127.0.0.1:1 --unix-socket "$work/plain.sock" http://host.example/z)
check "$(is "$out" "/z host.example")" "nor one on the command line"

# A redirect to another host goes to the same socket.
out=$(get -L --unix-socket "$work/plain.sock" http://host.example/redir)
check "$(is "$out" "/landed other.example")" "a redirect to another host stays on the socket"

# https: the socket is the transport and the URL's name is what is checked.
out=$(get --cacert "$work/cert.pem" --unix-socket "$work/tls.sock" https://unix.example/s)
check "$(is "$out" "/s unix.example")" "https over the socket, checked against the URL's name"
timeout 20 "$TWIST" -s --cacert "$work/cert.pem" --unix-socket "$work/tls.sock" \
  https://wrong.example/s >/dev/null 2>&1
check "$(is $? 35)" "a name the certificate does not have is status 35"
timeout 20 "$TWIST" -s --unix-socket "$work/tls.sock" https://unix.example/s >/dev/null 2>&1
check "$(is $? 35)" "and so is a certificate that is not trusted"

# What does not work.
timeout 20 "$TWIST" -s --unix-socket "$work/none.sock" http://host.example/ >/dev/null 2>&1
check "$(is $? 7)" "a socket that is not there is status 7"
timeout 20 "$TWIST" -s --unix-socket "$work/plain.sock" ftp://host.example/x >/dev/null 2>&1
check "$(is $? 1)" "another scheme is status 1, and is not sent over TCP"
timeout 20 "$TWIST" -s --http3-only --unix-socket "$work/tls.sock" https://unix.example/ >/dev/null 2>&1
check "$(is $? 1)" "HTTP/3 is status 1"
long=$(head -c 200 /dev/zero | tr '\0' 'a')
timeout 20 "$TWIST" -s --unix-socket "$work/$long" http://host.example/ >/dev/null 2>&1
check "$(is $? 2)" "a path too long for the address is a usage error"

[ $fail -eq 0 ]
