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

# --limit-rate is kept on the connection, for a download and for an upload,
# over plain HTTP against a server of python's: 30000 bytes at 20000 a second
# takes about a second (chunks of half a second's worth go at 0, 0.5 and 1.0),
# and without the limit hardly any time.  A limit is refused for tftp, and
# --http3-only fails with it, since it cannot be kept over HTTP/3.  Skips, with
# status 77, without python3 or twist.

TWIST=${TWIST:-../src/twist}
skip ()
{
  echo "limit-rate: $1; skipping" >&2
  exit 77
}
command -v python3 >/dev/null 2>&1 || skip "no python3"
[ -x "$TWIST" ] || skip "twist is not built ($TWIST)"

work=$(mktemp -d "${TMPDIR:-/tmp}/twist-limit-rate.XXXXXX") || skip "no temp dir"
server_pid=
cleanup ()
{
  [ -n "$server_pid" ] && kill "$server_pid" 2>/dev/null
  rm -rf "$work"
}
trap cleanup EXIT INT TERM

fail=0
check ()
{
  if [ "$1" = ok ]; then :; else echo "FAIL $2" >&2; fail=1; fi
}

cat > "$work/server.py" <<'PY'
import http.server, sys, time

class H(http.server.BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'
    def do_GET(self):
        body = b'x' * 30000
        self.send_response(200)
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def do_POST(self):
        n = int(self.headers.get('Content-Length', 0))
        got = 0
        t = time.time()
        while got < n:
            d = self.rfile.read(min(4096, n - got))
            if not d:
                break
            got += len(d)
        body = ('%d %.2f' % (got, time.time() - t)).encode()
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
python3 "$work/server.py" "$work/port" &
server_pid=$!
n=0
while [ ! -s "$work/port" ] && [ $n -lt 50 ]; do sleep 0.1; n=$((n + 1)); done
[ -s "$work/port" ] || skip "the server did not start"
url=http://127.0.0.1:$(cat "$work/port")/

secs ()
{
  python3 -c 'import time; print(time.time())'
}
longer ()
{
  python3 -c "import sys; sys.exit(0 if $1 - $2 >= $3 else 1)" && echo ok
}
shorter ()
{
  python3 -c "import sys; sys.exit(0 if $1 - $2 < $3 else 1)" && echo ok
}

t0=$(secs)
"$TWIST" -s --limit-rate 20000 -o "$work/d1" "$url" 2>/dev/null
t1=$(secs)
check "$([ "$(wc -c < "$work/d1")" -eq 30000 ] && echo ok)" "a limited download is whole"
check "$(longer "$t1" "$t0" 0.9)" "a download keeps to the limit"
check "$(shorter "$t1" "$t0" 3)" "and is not held much longer"

t0=$(secs)
"$TWIST" -s -o "$work/d2" "$url" 2>/dev/null
t1=$(secs)
check "$(shorter "$t1" "$t0" 0.5)" "without the limit it is quick"

head -c 30000 /dev/zero > "$work/up"
out=$("$TWIST" -s --limit-rate 20000 --data-binary @"$work/up" "$url" 2>/dev/null)
got=${out%% *}
took=${out#* }
check "$([ "$got" = 30000 ] && echo ok)" "a limited upload is whole ($out)"
check "$(python3 -c "print('ok' if float('$took') >= 0.9 else '')")" "an upload keeps to the limit ($took s)"

"$TWIST" -s --limit-rate 1000 tftp://127.0.0.1:1/x 2>/dev/null
check "$([ $? -eq 2 ] && echo ok)" "tftp is refused"
"$TWIST" -s --http3-only -k --limit-rate 1000 https://127.0.0.1:1/ 2>/dev/null
check "$([ $? -ne 0 ] && echo ok)" "HTTP/3 only fails"

exit $fail
