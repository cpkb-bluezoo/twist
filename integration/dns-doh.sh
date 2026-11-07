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

# Lookups over DNS-over-HTTPS (RFC 8484), against a resolver (doh-peer.py) that
# answers each query half a second after it arrives.  Where it offers HTTP/2 the
# queries of one lookup (A, AAAA and HTTPS) are each on a stream of their own,
# and are all out before the first is answered, so the lookup takes one round
# trip and not three.  Where it offers only HTTP/1.1 they go one after another,
# and the lookup works all the same.  Skips, with status 77, without python3,
# openssl or twist.

TWIST=${TWIST:-../src/twist}
here=$(cd "$(dirname "$0")" && pwd)
skip ()
{
  echo "dns-doh: $1; skipping" >&2
  exit 77
}
command -v python3 >/dev/null 2>&1 || skip "no python3"
command -v openssl >/dev/null 2>&1 || skip "no openssl"
[ -x "$TWIST" ] || skip "twist is not built ($TWIST)"

work=$(mktemp -d "${TMPDIR:-/tmp}/twist-doh.XXXXXX") || skip "no temp dir"
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

for v in http_proxy HTTP_PROXY https_proxy HTTPS_PROXY all_proxy ALL_PROXY \
         no_proxy NO_PROXY SSL_CERT_DIR TWIST_CA_BUNDLE; do
  unset $v
done

# run OFFER: a resolver that offers OFFER, a transfer of http://www.test/ with
# it as the resolver, and what it says it was asked and answered.
run ()
{
  : > "$work/log"
  rm -f "$work/ready"
  python3 -I "$here/doh-peer.py" "$work/cert.pem" "$work/key.pem" 18855 \
    "$work/log" "$work/ready" 500 "$1" >"$work/peer.out" 2>&1 &
  peer=$!
  pids="$pids $peer"
  n=0
  while [ ! -s "$work/ready" ] && [ $n -lt 100 ]; do sleep 0.1; n=$((n + 1)); done
  [ -s "$work/ready" ] || skip "the resolver did not start ($(head -c 200 "$work/peer.out"))"
  out=$(SSL_CERT_FILE="$work/cert.pem" timeout 20 "$TWIST" -s -S --max-time 15 \
          --doh-url https://127.0.0.1:18855/dns-query "http://www.test:$port/" \
          2> "$work/err")
  status=$?
  err=$(cat "$work/err")
  log=$(tr '\n' ';' < "$work/log")
  kill "$peer" 2>/dev/null
  wait "$peer" 2>/dev/null
}

run h2
check "$(is "$status:$out" "0:origin")" "HTTP/2: the transfer ($status $out $err; $log)"
check "$(grep -q '^alpn h2$' "$work/log" && echo ok)" "HTTP/2 was agreed ($log)"
check "$(grep -c '^query ' "$work/log" | grep -q '^3$' && echo ok)" "HTTP/2: three queries ($log)"
check "$(grep '^answer ' "$work/log" | head -n 1 | grep -q ' 3$' && echo ok)" \
  "HTTP/2: all three queries are in before the first is answered ($log)"

run http/1.1
check "$(is "$status:$out" "0:origin")" "HTTP/1.1: the transfer ($status $out $err; $log)"
check "$(grep -q '^alpn http/1.1$' "$work/log" && echo ok)" "HTTP/1.1 was agreed ($log)"
check "$(grep '^answer ' "$work/log" | head -n 1 | grep -q ' 1$' && echo ok)" \
  "HTTP/1.1: the queries go one at a time ($log)"

exit $fail
