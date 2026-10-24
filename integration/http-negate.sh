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

# --no-OPTION against a server of python's: what turning a switch off again
# does to a request, and that the last of the switch and its --no- form is the
# one that counts.  -f fails on a 404, -L follows a redirect, -i and -I write
# the headers, -G puts -d on the query, and --compressed asks for a coding.
# The ones that need no server are in tests/cli-negate.sh.  Skips, with status
# 77, without python3 or twist.

TWIST=${TWIST:-../src/twist}
skip ()
{
  echo "http-negate: $1; skipping" >&2
  exit 77
}
command -v python3 >/dev/null 2>&1 || skip "no python3"
[ -x "$TWIST" ] || skip "twist is not built ($TWIST)"

tmp=${TMPDIR:-/tmp}
work=$(mktemp -d "${tmp%/}/twist-http-negate.XXXXXX") || skip "no temp dir"
srv_pid=
cleanup ()
{
  [ -n "$srv_pid" ] && kill "$srv_pid" 2>/dev/null
  rm -rf "$work"
}
trap 'cleanup' EXIT INT TERM
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

cat > "$work/server.py" <<'PY'
import http.server, sys
class H(http.server.BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'
    def log_message(self, *a): pass
    def send(self, code, body, extra=()):
        data = body.encode()
        self.send_response(code)
        for k, v in extra:
            self.send_header(k, v)
        self.send_header('Content-Length', str(len(data)))
        self.end_headers()
        if self.command != 'HEAD':
            self.wfile.write(data)
    def handle_any(self):
        length = int(self.headers.get('Content-Length') or 0)
        body = self.rfile.read(length).decode() if length else ''
        if self.path == '/404':
            self.send(404, 'missing')
        elif self.path == '/redir':
            self.send(302, '', [('Location', '/ok')])
        elif self.path == '/ae':
            self.send(200, self.headers.get('Accept-Encoding') or 'none')
        elif self.path.startswith('/echo'):
            self.send(200, '%s %s [%s]' % (self.command, self.path, body))
        else:
            self.send(200, 'ok')
    do_GET = do_POST = do_HEAD = handle_any
srv = http.server.HTTPServer(('127.0.0.1', 0), H)
open(sys.argv[1], 'w').write(str(srv.server_address[1]))
srv.serve_forever()
PY
python3 -I "$work/server.py" "$work/port" > /dev/null 2>&1 &
srv_pid=$!
n=0
while [ ! -s "$work/port" ] && [ $n -lt 100 ]; do
  sleep 0.1
  n=$((n + 1))
done
[ -s "$work/port" ] || skip "the server did not start"
base="http://127.0.0.1:$(cat "$work/port")"
# run ARGS... URL-PATH: the status and the output.
run ()
{
  path=$1
  shift
  out=$("$TWIST" -s --max-time 5 "$@" "$base$path" 2>/dev/null)
  status=$?
}

# -f fails on a 404, and --no-fail takes it back; the last one counts.
run /404 -f
check "$(is "$status" 22)" "-f: 404 is 22 ($status)"
run /404 -f --no-fail
check "$(is "$status:$out" "0:missing")" "-f --no-fail: it is not ($status $out)"
run /404 --no-fail -f
check "$(is "$status" 22)" "--no-fail -f: it is ($status)"

# -L follows a redirect.
run /redir -L
check "$(is "$status:$out" "0:ok")" "-L follows ($status $out)"
run /redir -L --no-location -w '[%{http_code}]'
check "$(is "$status:$out" "0:[302]")" "-L --no-location: it does not ($status $out)"
run /redir --no-location -L
check "$(is "$status:$out" "0:ok")" "--no-location -L: it does ($status $out)"

# -i writes the headers before the body, and -I writes the headers alone.
run /ok -i
check "$(case "$out" in ("HTTP/1.1 200"*) echo ok;; esac)" "-i: the status line first"
run /ok -i --no-include
check "$(is "$out" ok)" "-i --no-include: the body alone ($out)"
run /ok --no-include -i
check "$(case "$out" in ("HTTP/1.1 200"*) echo ok;; esac)" "--no-include -i: the headers"
run /ok -I
check "$(case "$out" in ("HTTP/1.1 200"*) echo ok;; esac)" "-I: the headers"
check "$(is "$status" 0)" "-I: and it ends, though the headers promise a body ($status)"
run /ok -I --no-include
check "$(is "$status:$out" "0:")" "-I --no-include: nothing ($status $out)"

# -G puts what -d says on the query; without it the data is a POST.
run /echo -G -d a=b
check "$(is "$out" "GET /echo?a=b []")" "-G: on the query ($out)"
run /echo -G -d a=b --no-get
check "$(is "$out" "POST /echo [a=b]")" "-G --no-get: a POST ($out)"
run /echo --no-get -G -d a=b
check "$(is "$out" "GET /echo?a=b []")" "--no-get -G: on the query ($out)"

# --compressed asks for a coding, and --no-compressed takes it back.
run /ae
check "$(is "$out" none)" "no coding is asked for by default ($out)"
run /ae --compressed
check "$(case "$out" in (*gzip*) echo ok;; esac)" "--compressed: gzip is asked for ($out)"
run /ae --compressed --no-compressed
check "$(is "$out" none)" "--compressed --no-compressed: none ($out)"
run /ae --no-compressed --compressed
check "$(case "$out" in (*gzip*) echo ok;; esac)" "--no-compressed --compressed: gzip ($out)"

exit $fail
