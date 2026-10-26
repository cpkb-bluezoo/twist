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


# A resolver found by DDR (RFC 9462): twist asks the nameserver of
# /etc/resolv.conf for _dns.resolver.arpa, is told of a DoT resolver at
# resolver.test, and uses it if its certificate is valid for that name and
# also for the address the question went to (127.0.0.1).  A certificate for
# the name alone is refused, and the lookup goes on over UDP.  The nameserver
# is a program of python's (dns-peer.py) on UDP port 53 of the loopback, which
# only the lab (see HACKING) can offer, and /etc/resolv.conf is replaced while
# the test runs.  Skips, with status 77, without python3, openssl or twist, or
# where that file cannot be written or the port cannot be had.

TWIST=${TWIST:-../src/twist}
here=$(cd "$(dirname "$0")" && pwd)
skip ()
{
  echo "dns-ddr: $1; skipping" >&2
  exit 77
}
command -v python3 >/dev/null 2>&1 || skip "no python3"
command -v openssl >/dev/null 2>&1 || skip "no openssl"
[ -x "$TWIST" ] || skip "twist is not built ($TWIST)"
[ -w /etc/resolv.conf ] || skip "/etc/resolv.conf cannot be written"

work=$(mktemp -d "${TMPDIR:-/tmp}/twist-ddr.XXXXXX") || skip "no temp dir"
cp /etc/resolv.conf "$work/resolv.conf.orig" 2>/dev/null || : > "$work/resolv.conf.orig"
pids=
cleanup ()
{
  for p in $pids; do kill "$p" 2>/dev/null; done
  cat "$work/resolv.conf.orig" > /etc/resolv.conf 2>/dev/null
  rm -rf "$work"
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

# Two certificates for resolver.test: one that also names the address of the
# nameserver that was asked, and one that does not.
mkcert ()
{
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
    -keyout "$work/$1-key.pem" -out "$work/$1-cert.pem" -days 2 \
    -subj "/CN=resolver.test" -addext "subjectAltName=$2" >/dev/null 2>&1
}
mkcert both "DNS:resolver.test,IP:127.0.0.1" || skip "openssl cannot make a certificate"
mkcert name "DNS:resolver.test" || skip "openssl cannot make a certificate"

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
tlsport=18853

# run NAME: the nameserver with the certificate NAME, a transfer of
# http://www.test/, and what the nameserver says it answered.
run ()
{
  rm -f "$work/ready" "$work/log"
  : > "$work/log"
  python3 -I "$here/dns-peer.py" "$work/$1-cert.pem" "$work/$1-key.pem" \
    $tlsport "$work/log" "$work/ready" >/dev/null 2>&1 &
  peer=$!
  pids="$pids $peer"
  n=0
  while [ ! -s "$work/ready" ] && [ $n -lt 50 ]; do sleep 0.1; n=$((n + 1)); done
  [ -s "$work/ready" ] || skip "the nameserver did not start (port 53?)"
  echo "nameserver 127.0.0.1" > /etc/resolv.conf
  out=$(SSL_CERT_FILE="$work/$1-cert.pem" timeout 20 "$TWIST" -s -S \
          --max-time 15 "http://www.test:$port/" 2> "$work/err")
  status=$?
  err=$(cat "$work/err")
  kill "$peer" 2>/dev/null
  wait "$peer" 2>/dev/null
  sleep 0.3
}

run both
check "$(is "$status:$out" "0:origin")" "a certificate for the name and the address: the transfer ($status $out $err)"
check "$(grep -q '^dot 1 www.test$' "$work/log" && echo ok)" "a certificate for the name and the address: the lookup was over DoT ($(tr '\n' ';' < "$work/log"))"

run name
check "$(grep -q '^dot 1 www.test$' "$work/log" || echo ok)" "a certificate for the name alone: no lookup was over DoT ($(tr '\n' ';' < "$work/log"))"
check "$(grep -q '^udp 1 www.test$' "$work/log" && echo ok)" "a certificate for the name alone: the lookup went on over UDP ($(tr '\n' ';' < "$work/log"))"

exit $fail
