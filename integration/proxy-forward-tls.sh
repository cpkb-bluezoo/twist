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

# An http:// URL through an https proxy is forwarded to it, as it is through
# an http proxy: TLS to the proxy, and then the request addressed to it (the
# absolute form on HTTP/1.1; :scheme http and :authority on HTTP/2, which
# the proxy and twist negotiate with ALPN) and not a CONNECT.  nghttpx is the
# proxy, in front of an origin of python's that says whether the request came
# by way of a proxy (the X-Forwarded-For that nghttpx adds).  Skips, with
# status 77, without nghttpx, openssl, python3 or twist.

TWIST=${TWIST:-../src/twist}
skip ()
{
  echo "proxy-forward-tls: $1; skipping" >&2
  exit 77
}
command -v nghttpx >/dev/null 2>&1 || skip "no nghttpx"
command -v openssl >/dev/null 2>&1 || skip "no openssl"
command -v python3 >/dev/null 2>&1 || skip "no python3"
[ -x "$TWIST" ] || skip "twist is not built ($TWIST)"

work=$(mktemp -d "${TMPDIR:-/tmp}/twist-proxy-forward-tls.XXXXXX") || skip "no temp dir"
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
        body = ('xff=%s' % self.headers.get('X-Forwarded-For', '-')).encode()
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
python3 "$work/origin.py" "$work/oport" &
pids="$pids $!"
n=0
while [ ! -s "$work/oport" ] && [ $n -lt 50 ]; do sleep 0.1; n=$((n + 1)); done
[ -s "$work/oport" ] || skip "the origin did not start"
o=127.0.0.1:$(cat "$work/oport")

pport=$((20000 + $$ % 20000))
nghttpx -s --add-x-forwarded-for -f"127.0.0.1,$pport" \
  -b"127.0.0.1,$(cat "$work/oport");;no-tls" "$work/key.pem" "$work/cert.pem" \
  >"$work/nx.log" 2>&1 &
pids="$pids $!"
sleep 1
kill -0 "${pids##* }" 2>/dev/null || skip "nghttpx did not start"
px=https://localhost:$pport

out=$("$TWIST" -s --proxy-insecure -x "$px" "http://$o/a" 2>/dev/null)
check "$([ "$out" = 'xff=127.0.0.1' ] && echo ok)" \
  "forwarded over TLS, HTTP/2 by ALPN ($out)"

out=$("$TWIST" -s --http1.1 --proxy-insecure -x "$px" "http://$o/a" 2>/dev/null)
check "$([ "$out" = 'xff=127.0.0.1' ] && echo ok)" \
  "forwarded over TLS, HTTP/1.1 (absolute form) ($out)"

out=$("$TWIST" -s --proxy-insecure -x "$px" "http://$o/a" "http://$o/b" 2>/dev/null)
check "$([ "$out" = 'xff=127.0.0.1xff=127.0.0.1' ] && echo ok)" "two URLs ($out)"

# The proxy's certificate is checked, as for a tunnel.
"$TWIST" -s -x "$px" "http://$o/a" >/dev/null 2>&1
rc=$?
check "$([ $rc -eq 60 ] || [ $rc -eq 35 ] && echo ok)" "an untrusted proxy is refused ($rc)"
out=$("$TWIST" -s --proxy-cacert "$work/cert.pem" -x "$px" "http://$o/a" 2>/dev/null)
check "$([ "$out" = 'xff=127.0.0.1' ] && echo ok)" "and trusted with --proxy-cacert ($out)"

exit $fail
