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
# <https://www.gnu.org/licenses/>.

# Tunnels through an https proxy: TLS to the proxy and CONNECT in it, over
# HTTP/2 and over HTTP/1.1, to a plain origin and to a TLS one (TLS inside
# TLS), with the proxy's certificate checked and not, credentials, a refusal,
# and bodies large enough to need the HTTP/2 windows to be opened.  The proxy is
# a program of node's (https-proxy.js) and the origin one of python's.  Skips,
# with status 77, without node, python3, openssl or twist.

TWIST=${TWIST:-../src/twist}
here=$(cd "$(dirname "$0")" && pwd)
skip ()
{
  echo "proxy-https: $1; skipping" >&2
  exit 77
}
command -v node >/dev/null 2>&1 || skip "no node"
command -v python3 >/dev/null 2>&1 || skip "no python3"
command -v openssl >/dev/null 2>&1 || skip "no openssl"
[ -x "$TWIST" ] || skip "twist is not built ($TWIST)"

work=$(mktemp -d "${TMPDIR:-/tmp}/twist-proxy-https.XXXXXX") || skip "no temp dir"
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

mkcert ()
{
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
    -keyout "$work/$1-key.pem" -out "$work/$1-cert.pem" -days 2 \
    -subj "/CN=127.0.0.1" -addext "subjectAltName=IP:127.0.0.1" \
    >/dev/null 2>&1 || skip "openssl cannot make a certificate"
}
mkcert origin
mkcert proxy
cat "$work/origin-cert.pem" "$work/proxy-cert.pem" > "$work/both.pem"

cat > "$work/origin.py" <<'PY'
import http.server, socketserver, ssl, sys, threading
class H(http.server.BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'
    def log_message(self, *a): pass
    def reply(self, body):
        self.send_response(200)
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def do_GET(self):
        if self.path == '/big':
            self.reply(b'y' * 4000000)
        else:
            self.reply(b'direct')
    def do_POST(self):
        n = int(self.headers.get('Content-Length', 0))
        got = 0
        while got < n:
            chunk = self.rfile.read(min(65536, n - got))
            if not chunk: break
            got += len(chunk)
        self.reply(('got%d' % got).encode())
class S(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True
plain = S(('127.0.0.1', 0), H)
tls = S(('127.0.0.1', 0), H)
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain(sys.argv[1], sys.argv[2])
tls.socket = ctx.wrap_socket(tls.socket, server_side=True)
print(plain.server_address[1], tls.server_address[1], flush=True)
threading.Thread(target=tls.serve_forever, daemon=True).start()
plain.serve_forever()
PY
python3 -I "$work/origin.py" "$work/origin-cert.pem" "$work/origin-key.pem" \
  > "$work/ports" 2>/dev/null &
pids="$pids $!"
i=0
while [ ! -s "$work/ports" ] && [ $i -lt 50 ]; do sleep 0.1; i=$((i + 1)); done
read -r port tport < "$work/ports"
[ -n "$port" ] && [ -n "$tport" ] || skip "the origin did not start"

# A proxy: MODE, then credentials and a refused port if any.
start_proxy ()
{
  rm -f "$work/pp"
  node "$here/https-proxy.js" "$@" > "$work/pp" 2>/dev/null &
  proxy_pid=$!
  pids="$pids $proxy_pid"
  i=0
  while [ ! -s "$work/pp" ] && [ $i -lt 50 ]; do sleep 0.1; i=$((i + 1)); done
  proxy_port=$(cat "$work/pp")
}

for v in http_proxy HTTP_PROXY https_proxy HTTPS_PROXY all_proxy ALL_PROXY \
         no_proxy NO_PROXY SSL_CERT_FILE SSL_CERT_DIR TWIST_CA_BUNDLE; do
  unset $v
done
get () { timeout 30 "$TWIST" -s -S "$@" 2>/dev/null; }
status () { timeout 30 "$TWIST" -s -o /dev/null "$@" 2>/dev/null; echo $?; }
u="http://127.0.0.1:$port/x"
tu="https://127.0.0.1:$tport/x"

for mode in h2 h1; do
  start_proxy "$mode" "$work/proxy-cert.pem" "$work/proxy-key.pem"
  [ -n "$proxy_port" ] || { echo "FAIL the $mode proxy did not start" >&2; fail=1; continue; }
  px="https://127.0.0.1:$proxy_port"
  c="--proxy-cacert $work/proxy-cert.pem"

  check "$(is "$(get -x "$px" $c "$u")" direct)" "$mode: a plain origin through the proxy"
  check "$(is "$(get -x "$px" $c --cacert "$work/origin-cert.pem" "$tu")" direct)" "$mode: TLS inside the tunnel"
  check "$(is "$(ALL_PROXY=$px get $c --cacert "$work/origin-cert.pem" "$tu")" direct)" "$mode: from ALL_PROXY"
  check "$(is "$(https_proxy=$px get $c --cacert "$work/origin-cert.pem" "$tu")" direct)" "$mode: from https_proxy"

  # The proxy's certificate is checked.
  check "$([ "$(status -x "$px" "$u")" != 0 ] && echo ok)" "$mode: a proxy nobody trusts is refused"
  check "$(is "$(get -x "$px" --proxy-insecure "$u")" direct)" "$mode: --proxy-insecure"
  check "$([ "$(status -x "$px" -k "$u")" != 0 ] && echo ok)" "$mode: -k does not stop the proxy being checked"
  check "$([ "$(status -x "$px" --cacert "$work/origin-cert.pem" "$u")" != 0 ] && echo ok)" "$mode: the target's authority is not the proxy's"

  # One bundle for both: without --proxy-cacert the proxy is checked against
  # --cacert, and the environment's.
  check "$(is "$(get -x "$px" --cacert "$work/both.pem" "$tu")" direct)" "$mode: --cacert for both"
  check "$(is "$(SSL_CERT_FILE=$work/both.pem get -x "$px" "$tu")" direct)" "$mode: SSL_CERT_FILE for both"
  # A proxy that is not there.
  check "$([ "$(status -x https://127.0.0.1:1 $c "$u")" = 7 ] && echo ok)" "$mode: no proxy listening is 7"

  # Large bodies, up and down.
  head -c 3000000 /dev/zero | tr '\0' 'z' > "$work/up.bin"
  # -p: the proxy only tunnels, and a POST is not tried on it first.
  check "$(is "$(get -p -x "$px" $c -d @"$work/up.bin" "$u")" got3000000)" "$mode: 3 MB up through the tunnel"
  check "$(is "$(get -x "$px" $c --cacert "$work/origin-cert.pem" -d @"$work/up.bin" "$tu")" got3000000)" "$mode: 3 MB up, TLS inside"
  n=$(timeout 60 "$TWIST" -s -S -x "$px" $c "$(echo "$u" | sed 's|/x$|/big|')" 2>/dev/null | wc -c)
  check "$(is "$n" 4000000)" "$mode: 4 MB down (got $n)"
  # Several URLs, a tunnel for each.
  check "$(is "$(get -x "$px" $c "$u" "$u")" directdirect)" "$mode: two URLs"
  kill "$proxy_pid" 2>/dev/null
done

# Credentials, over HTTP/2 and HTTP/1.1.
for mode in h2 h1; do
  start_proxy "$mode" "$work/proxy-cert.pem" "$work/proxy-key.pem" alice:secret
  [ -n "$proxy_port" ] || { echo "FAIL the $mode proxy did not start" >&2; fail=1; continue; }
  px="https://127.0.0.1:$proxy_port"
  c="--proxy-cacert $work/proxy-cert.pem"
  check "$([ "$(status -x "$px" $c "$u")" = 56 ] && echo ok)" "$mode: no credentials is 56"
  check "$(is "$(get -x "$px" $c -U alice:secret "$u")" direct)" "$mode: -U"
  check "$(is "$(get -x "https://alice:secret@127.0.0.1:$proxy_port" $c "$u")" direct)" "$mode: credentials in the URL"
  check "$([ "$(status -x "$px" $c -U alice:wrong "$u")" = 56 ] && echo ok)" "$mode: the wrong password is 56"
  e=$(timeout 30 "$TWIST" -S -o /dev/null -x "$px" $c "$u" 2>&1)
  check "$(case "$e" in (*"CONNECT tunnel failed, response 407"*) echo ok;; esac)" "$mode: the refusal is told: $e"
  kill "$proxy_pid" 2>/dev/null
done

# A refusal of the target.
for mode in h2 h1; do
  start_proxy "$mode" "$work/proxy-cert.pem" "$work/proxy-key.pem" "" "$port"
  [ -n "$proxy_port" ] || { echo "FAIL the $mode proxy did not start" >&2; fail=1; continue; }
  px="https://127.0.0.1:$proxy_port"
  c="--proxy-cacert $work/proxy-cert.pem"
  check "$([ "$(status -x "$px" $c "$u")" = 56 ] && echo ok)" "$mode: a refused target is 56"
  e=$(timeout 30 "$TWIST" -S -o /dev/null -x "$px" $c "$u" 2>&1)
  check "$(case "$e" in (*"response 403"*) echo ok;; esac)" "$mode: and says 403: $e"
  check "$(is "$(get -x "$px" $c --cacert "$work/origin-cert.pem" "$tu")" direct)" "$mode: another target is let through"
  kill "$proxy_pid" 2>/dev/null
done

[ $fail -eq 0 ] || exit 1
exit 0
