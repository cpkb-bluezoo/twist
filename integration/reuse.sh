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

# A connection is kept for the next transfer to the same server, unless
# --forbid-reuse says it is not to be, and a transfer takes one that is kept
# unless --fresh-connect says it is not to.  A server of python's that logs
# each connection it accepts.  Skips, with status 77, without python3 or twist.

TWIST=${TWIST:-../src/twist}
skip ()
{
  echo "reuse: $1; skipping" >&2
  exit 77
}
command -v python3 >/dev/null 2>&1 || skip "no python3"
[ -x "$TWIST" ] || skip "twist is not built ($TWIST)"

work=$(mktemp -d "${TMPDIR:-/tmp}/twist-reuse.XXXXXX") || skip "no temp dir"
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

cat > "$work/server.py" <<'PY'
import http.server, socketserver, sys

log, portfile = sys.argv[1], sys.argv[2]

class H(http.server.BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'
    def setup(self):
        with open(log, 'a') as f:
            f.write('conn\n')
        super().setup()
    def do_GET(self):
        body = b'ok'
        self.send_response(200)
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *a):
        pass

s = http.server.ThreadingHTTPServer(('127.0.0.1', 0), H)
open(portfile, 'w').write(str(s.server_address[1]))
s.serve_forever()
PY
: > "$work/log"
python3 "$work/server.py" "$work/log" "$work/port" &
pids="$pids $!"
n=0
while [ ! -s "$work/port" ] && [ $n -lt 50 ]; do sleep 0.1; n=$((n + 1)); done
[ -s "$work/port" ] || skip "the server did not start"
u=http://127.0.0.1:$(cat "$work/port")
conns () { wc -l < "$work/log" | tr -d ' '; }
fresh () { : > "$work/log"; }
get () { "$TWIST" -s "$@" 2>/dev/null; }

fresh
out=$(get "$u/a" "$u/b")
check "$([ "$out" = okok ] && [ "$(conns)" -eq 1 ] && echo ok)" \
  "two in turn share a connection ($out, $(conns))"

fresh
out=$(get --forbid-reuse "$u/a" "$u/b")
check "$([ "$out" = okok ] && [ "$(conns)" -eq 2 ] && echo ok)" \
  "--forbid-reuse: a connection each ($out, $(conns))"

fresh
out=$(get --fresh-connect "$u/a" "$u/b")
check "$([ "$out" = okok ] && [ "$(conns)" -eq 2 ] && echo ok)" \
  "--fresh-connect: a connection each ($out, $(conns))"

fresh
out=$(get --forbid-reuse --no-forbid-reuse "$u/a" "$u/b")
check "$([ "$out" = okok ] && [ "$(conns)" -eq 1 ] && echo ok)" \
  "--no-forbid-reuse turns it off ($out, $(conns))"

exit $fail
