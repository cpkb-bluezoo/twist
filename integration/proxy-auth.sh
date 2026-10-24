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

# A plain http:// URL through an HTTP proxy is sent to the proxy in its
# absolute form, and the proxy's credentials go with it as Proxy-Authorization
# (Basic), from -U or from the proxy URL; a Proxy-Authorization header of the
# user's own is sent instead.  The "proxy" is a server of python's that
# answers with the header it was given.  Skips, with status 77, without
# python3 or twist.

TWIST=${TWIST:-../src/twist}
skip ()
{
  echo "proxy-auth: $1; skipping" >&2
  exit 77
}
command -v python3 >/dev/null 2>&1 || skip "no python3"
[ -x "$TWIST" ] || skip "twist is not built ($TWIST)"

work=$(mktemp -d "${TMPDIR:-/tmp}/twist-proxy-auth.XXXXXX") || skip "no temp dir"
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
is () { [ "$1" = "$2" ] && echo ok; }

cat > "$work/server.py" <<'PY'
import http.server, sys

class H(http.server.BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'
    def do_GET(self):
        body = ('%s|%s' % (self.path, self.headers.get('Proxy-Authorization', '-'))).encode()
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
px=127.0.0.1:$(cat "$work/port")
target=http://localhost/x

# What the proxy was sent as Proxy-Authorization: the part after the bar.
get () { out=$("$TWIST" -s "$@" 2>/dev/null); echo "${out#*|}"; }

# eDpw is x:p, cHg6cHc= is px:pw.
check "$(is "$(get -x "http://$px" "$target")" "-")" \
  "no credentials, no header"
check "$(is "$(get -x "http://$px" -U px:pw "$target")" "Basic cHg6cHc=")" \
  "-U"
check "$(is "$(get -x "http://px:pw@$px" "$target")" "Basic cHg6cHc=")" \
  "credentials in the proxy URL"
check "$(is "$(get -x "http://$px" -U px:pw -H 'Proxy-Authorization: Bearer z' "$target")" "Bearer z")" \
  "a header of the user's own is the one sent"

exit $fail
