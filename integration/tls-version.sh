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

# --tlsv1.2, --tlsv1.3 and --tls-max, against a server of python's that speaks
# only TLS 1.2 and one that speaks only TLS 1.3.  Skips, with status 77,
# without python3, openssl or twist.

TWIST=${TWIST:-../src/twist}
skip ()
{
  echo "tls-version: $1; skipping" >&2
  exit 77
}
command -v python3 >/dev/null 2>&1 || skip "no python3"
command -v openssl >/dev/null 2>&1 || skip "no openssl"
[ -x "$TWIST" ] || skip "twist is not built ($TWIST)"

work=$(mktemp -d "${TMPDIR:-/tmp}/twist-tlsver.XXXXXX") || skip "no temp dir"
pids=
cleanup ()
{
  for p in $pids; do kill "$p" 2>/dev/null; done
  rm -rf "${work:?}"
}
trap cleanup EXIT INT TERM
exec < /dev/null

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
isnt () { [ "$1" != "$2" ] && echo ok; }

openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
  -keyout "$work/key.pem" -out "$work/cert.pem" -days 2 \
  -subj "/CN=127.0.0.1" -addext "subjectAltName=IP:127.0.0.1" >/dev/null 2>&1 \
  || skip "openssl cannot make a certificate"

cat > "$work/server.py" <<'PY'
import socketserver, ssl, sys
cert, key, version, readyfile = sys.argv[1:5]
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
v = ssl.TLSVersion.TLSv1_2 if version == "1.2" else ssl.TLSVersion.TLSv1_3
ctx.minimum_version = v
ctx.maximum_version = v
ctx.load_cert_chain(cert, key)
class H(socketserver.StreamRequestHandler):
    def handle(self):
        try:
            while self.rfile.readline().strip():
                pass
            self.wfile.write(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n"
                             b"Connection: close\r\n\r\nok")
        except Exception:
            pass
class S(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    def get_request(self):
        sock, addr = self.socket.accept()
        try:
            return ctx.wrap_socket(sock, server_side=True), addr
        except Exception:
            sock.close()
            raise
    def handle_error(self, request, client_address):
        pass
s = S(("127.0.0.1", 0), H)
open(readyfile, "w").write(str(s.server_address[1]))
s.serve_forever()
PY
server ()
{
  python3 -I "$work/server.py" "$work/cert.pem" "$work/key.pem" "$1" "$work/p$1" \
    >"$work/s$1.out" 2>&1 &
  pids="$pids $!"
  n=0
  while [ ! -s "$work/p$1" ] && [ $n -lt 50 ]; do sleep 0.1; n=$((n + 1)); done
  [ -s "$work/p$1" ] || skip "the TLS $1 server did not start ($(head -c 300 "$work/s$1.out"))"
}
server 1.2
server 1.3
p12=$(cat "$work/p1.2")
p13=$(cat "$work/p1.3")

for v in http_proxy HTTP_PROXY https_proxy HTTPS_PROXY all_proxy ALL_PROXY \
         no_proxy NO_PROXY SSL_CERT_DIR TWIST_CA_BUNDLE; do
  unset $v
done
export SSL_CERT_FILE="$work/cert.pem"

# get PORT OPTION...: the body, and the status in $status.
get ()
{
  port=$1
  shift
  out=$(timeout 20 "$TWIST" -s -S --max-time 10 "$@" "https://127.0.0.1:$port/" \
          2> "$work/err")
  status=$?
  err=$(cat "$work/err")
}

get "$p12"
check "$(is "$status:$out" "0:ok")" "TLS 1.2 server, no option ($status $err)"
get "$p13"
check "$(is "$status:$out" "0:ok")" "TLS 1.3 server, no option ($status $err)"
get "$p12" --tlsv1.2
check "$(is "$status:$out" "0:ok")" "TLS 1.2 server, --tlsv1.2 ($status $err)"
get "$p13" --tlsv1.2
check "$(is "$status:$out" "0:ok")" "TLS 1.3 server, --tlsv1.2 ($status $err)"
get "$p12" --tls-max 1.2
check "$(is "$status:$out" "0:ok")" "TLS 1.2 server, --tls-max 1.2 ($status $err)"
get "$p12" --tlsv1.3
check "$(isnt "$status" 0)" "TLS 1.2 server, --tlsv1.3 fails ($status $out)"
get "$p13" --tlsv1.3
check "$(is "$status:$out" "0:ok")" "TLS 1.3 server, --tlsv1.3 ($status $err)"
get "$p13" --tls-max 1.2
check "$(isnt "$status" 0)" "TLS 1.3 server, --tls-max 1.2 fails ($status $out)"
get "$p13" --tls-max 1.3
check "$(is "$status:$out" "0:ok")" "TLS 1.3 server, --tls-max 1.3 ($status $err)"
get "$p12" --tls-max 1.3
check "$(is "$status:$out" "0:ok")" "TLS 1.2 server, --tls-max 1.3 ($status $err)"

get "$p13" --tlsv1.3 --tls-max 1.2
check "$(is "$status" 2)" "a floor above the ceiling is status 2 ($status $err)"
get "$p13" --tlsv1.0
check "$(is "$status" 2)" "--tlsv1.0 is status 2 ($status $err)"
check "$(printf '%s' "$err" | grep -q '1\.2' && echo ok)" "--tlsv1.0 says the floor is 1.2 ($err)"
get "$p13" --tlsv1.1
check "$(is "$status" 2)" "--tlsv1.1 is status 2 ($status $err)"
get "$p13" --tls-max 1.1
check "$(is "$status" 2)" "--tls-max 1.1 is status 2 ($status $err)"
get "$p13" --tls-max 1.0
check "$(is "$status" 2)" "--tls-max 1.0 is status 2 ($status $err)"

# HTTP/3 is TLS 1.3: with a ceiling of 1.2 it is not used.
get "$p12" --http3-only --tls-max 1.2
check "$(isnt "$status" 0)" "--http3-only with --tls-max 1.2 fails ($status $out)"
check "$(printf '%s' "$err" | grep -q 'TLS 1.3' && echo ok)" "and says why ($err)"
get "$p12" --http3 --tls-max 1.2
check "$(is "$status:$out" "0:ok")" "--http3 with --tls-max 1.2 goes on over TCP ($status $err)"

check "$("$TWIST" --help all 2>&1 | grep -q -- '--tls-max' && echo ok)" "--help lists --tls-max"
check "$("$TWIST" --help all 2>&1 | grep -q -- '--tlsv1.3' && echo ok)" "--help lists --tlsv1.3"

exit $fail
