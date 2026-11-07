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

# Lookups over DNS-over-QUIC (RFC 9250), against a resolver of aioquic's
# (doq-peer.py) that answers each query half a second after it arrives: the
# queries of one lookup (A, AAAA and HTTPS) are each on a stream of their own,
# and are all out before the first is answered, so the lookup takes one round
# trip and not three.  Skips, with status 77, without python3 and its aioquic
# module, openssl or twist.

TWIST=${TWIST:-../src/twist}
here=$(cd "$(dirname "$0")" && pwd)
skip ()
{
  echo "dns-doq: $1; skipping" >&2
  exit 77
}
command -v python3 >/dev/null 2>&1 || skip "no python3"
python3 -c 'import aioquic' >/dev/null 2>&1 || skip "no aioquic"
command -v openssl >/dev/null 2>&1 || skip "no openssl"
[ -x "$TWIST" ] || skip "twist is not built ($TWIST)"

work=$(mktemp -d "${TMPDIR:-/tmp}/twist-doq.XXXXXX") || skip "no temp dir"
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

openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
  -keyout "$work/key.pem" -out "$work/cert.pem" -days 2 \
  -subj "/CN=127.0.0.1" -addext "subjectAltName=IP:127.0.0.1" >/dev/null 2>&1 \
  || skip "openssl cannot make a certificate"

# The origin that the name www.test is for.
cat > "$work/origin.py" <<'PY'
import http.server, sys
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200); self.send_header("Content-Length", "6")
        self.end_headers(); self.wfile.write(b"origin")
    def log_message(self, *a): pass
s = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
open(sys.argv[1], "w").write(str(s.server_address[1]))
s.serve_forever()
PY
python3 -I "$work/origin.py" "$work/port" >/dev/null 2>&1 &
pids="$pids $!"
n=0
while [ ! -s "$work/port" ] && [ $n -lt 50 ]; do sleep 0.1; n=$((n + 1)); done
[ -s "$work/port" ] || skip "the origin did not start"
port=$(cat "$work/port")

: > "$work/log"
python3 -I "$here/doq-peer.py" "$work/cert.pem" "$work/key.pem" 18854 \
  "$work/log" "$work/ready" 500 >"$work/peer.out" 2>&1 &
pids="$pids $!"
n=0
while [ ! -s "$work/ready" ] && [ $n -lt 100 ]; do sleep 0.1; n=$((n + 1)); done
[ -s "$work/ready" ] || skip "the resolver did not start ($(head -c 200 "$work/peer.out"))"

for v in http_proxy HTTP_PROXY https_proxy HTTPS_PROXY all_proxy ALL_PROXY \
         no_proxy NO_PROXY SSL_CERT_DIR TWIST_CA_BUNDLE; do
  unset $v
done

out=$(SSL_CERT_FILE="$work/cert.pem" timeout 20 "$TWIST" -s -S --max-time 15 \
        --doq-url quic://127.0.0.1:18854 "http://www.test:$port/" 2> "$work/err")
status=$?
err=$(cat "$work/err")
log=$(tr '\n' ';' < "$work/log")
check "$(is "$status:$out" "0:origin")" "the transfer ($status $out $err; $log)"
check "$(grep -c '^query ' "$work/log" | grep -q '^3$' && echo ok)" "three queries ($log)"
check "$(grep '^answer ' "$work/log" | head -n 1 | grep -q ' 3$' && echo ok)" \
  "all three queries are in before the first is answered ($log)"
check "$(grep -q '^bad' "$work/log" || echo ok)" "each query is one message on one stream ($log)"

exit $fail
