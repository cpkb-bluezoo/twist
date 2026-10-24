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

# The progress meter and the bar over HTTP, against a server of Python's on a
# loopback port: the sizes of downloads and uploads, a body of unknown size, a
# redirect, a connection that is refused, and a transfer that waits.  What is
# expected is what curl 8.5 shows for the same requests.  Skips, with status 77,
# without python3 or twist.

TWIST=${TWIST:-../src/twist}
skip ()
{
  echo "http-progress: $1; skipping" >&2
  exit 77
}
command -v python3 >/dev/null 2>&1 || skip "no python3"
[ -x "$TWIST" ] || skip "twist is not built ($TWIST)"

work=$(mktemp -d "${TMPDIR:-/tmp}/twist-http-progress.XXXXXX") || skip "no temp dir"
srv_pid=
cleanup ()
{
  [ -n "$srv_pid" ] && kill "$srv_pid" 2>/dev/null
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

head -c 5000 /dev/zero | tr '\0' 'x' > "$work/five"

cat > "$work/server.py" <<'PY'
import http.server, socketserver, sys, time
class H(http.server.BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'
    def log_message(self, *a): pass
    def reply(self, body, extra=()):
        self.send_response(200)
        self.send_header('Content-Length', str(len(body)))
        for k, v in extra: self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)
    def do_GET(self):
        if self.path == '/five':
            self.reply(b'x' * 5000)
        elif self.path == '/empty':
            self.reply(b'')
        elif self.path == '/redirect':
            self.send_response(302); self.send_header('Location', '/five')
            self.send_header('Content-Length', '0'); self.end_headers()
        elif self.path == '/chunked':
            self.send_response(200); self.send_header('Transfer-Encoding', 'chunked')
            self.end_headers()
            self.wfile.write(b'1388\r\n' + b'x' * 5000 + b'\r\n0\r\n\r\n')
        elif self.path == '/stall':
            # Headers and a little, then nothing for 3.5 seconds.
            self.send_response(200); self.send_header('Transfer-Encoding', 'chunked')
            self.end_headers()
            self.wfile.write(b'5\r\nhello\r\n'); self.wfile.flush()
            time.sleep(3.5)
            self.wfile.write(b'0\r\n\r\n')
        else:
            self.send_response(404); self.send_header('Content-Length', '0'); self.end_headers()
    def do_POST(self):
        n = int(self.headers.get('Content-Length', 0)); self.rfile.read(n)
        self.reply(b'ok')
    do_PUT = do_POST
class S(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True
srv = S(('127.0.0.1', 0), H)
print(srv.server_address[1], flush=True)
srv.serve_forever()
PY
python3 -I "$work/server.py" > "$work/port" 2>/dev/null &
srv_pid=$!
i=0
while [ ! -s "$work/port" ] && [ $i -lt 50 ]; do sleep 0.1; i=$((i + 1)); done
port=$(cat "$work/port")
[ -n "$port" ] || skip "the server did not start"
u="http://127.0.0.1:$port"

unset COLUMNS
# Standard error, as lines: the carriage returns are line ends.
meter () { "$TWIST" "$@" 2>&1 >/dev/null | tr '\r' '\n' | grep -v '^$'; }
last () { tail -n 1; }
heading='  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current'

# A download of a known size.
e=$(meter -o /dev/null "$u/five")
check "$(case "$(printf '%s\n' "$e" | head -n 1)" in ("$heading") echo ok;; esac)" "the heading"
check "$(case "$(printf '%s\n' "$e" | last)" in ('100  5000  100  5000    0     0 '*) echo ok;; esac)" "a download of 5000: $(printf '%s\n' "$e" | last)"
check "$(case "$(printf '%s\n' "$e" | sed -n 3p)" in ('  0     0    0     0    0     0      0      0 '*) echo ok;; esac)" "it starts at 0"

# An empty body: 0, and no division by it.
e=$(meter -o /dev/null "$u/empty")
check "$(case "$(printf '%s\n' "$e" | last)" in ('  0     0    0     0    0     0 '*) echo ok;; esac)" "an empty body: $(printf '%s\n' "$e" | last)"

# A body of a size that is not said: the total is what has come.
e=$(meter -o /dev/null "$u/chunked")
check "$(case "$(printf '%s\n' "$e" | last)" in ('100  5000    0  5000    0     0 '*) echo ok;; esac)" "chunked: $(printf '%s\n' "$e" | last)"

# Uploads: -d, and -T with the file read whole.
e=$(meter -o /dev/null -d 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' "$u/x")
check "$(case "$(printf '%s\n' "$e" | last)" in ('100    46  100     2  100    44 '*) echo ok;; esac)" "a POST of 44: $(printf '%s\n' "$e" | last)"
e=$(meter -o /dev/null -T "$work/five" "$u/x")
check "$(case "$(printf '%s\n' "$e" | last)" in ('100  5002  100     2  100  5000 '*) echo ok;; esac)" "a PUT of 5000: $(printf '%s\n' "$e" | last)"

# A redirect ends the first response's line and starts the next at 0, under
# the same heading.
all=$("$TWIST" -L -o /dev/null "$u/redirect" 2>&1 >/dev/null)
check "$([ "$(printf '%s' "$all" | grep -c '% Total')" = 1 ] && echo ok)" "one heading with a redirect"
e=$(printf '%s' "$all" | tr '\r' '\n' | grep -v '^$')
check "$(case "$(printf '%s\n' "$e" | last)" in ('100  5000  100  5000    0     0 '*) echo ok;; esac)" "the redirect's target: $(printf '%s\n' "$e" | last)"
raw=$(printf '%s' "$all" | tr '\r\n' '@#')
check "$(case "$raw" in (*'#@100  5000  100  5000'*) echo ok;; esac)" "a newline ends the redirect's line"
e=$(meter -o /dev/null "$u/redirect")
check "$(case "$(printf '%s\n' "$e" | last)" in ('  0     0    0     0    0     0 '*) echo ok;; esac)" "a redirect that is not followed has no body: $(printf '%s\n' "$e" | last)"

# The bar: the width given and the percentage.
e=$(COLUMNS=40 "$TWIST" -# -o /dev/null "$u/five" 2>&1 >/dev/null | tr '\r' '\n' | grep -v '^$' | tail -n 1)
check "$([ "$e" = '################################# 100.0%' ] && echo ok)" "the bar: $e"
e=$(COLUMNS=40 "$TWIST" -# -o /dev/null -d x=1 "$u/x" 2>&1 >/dev/null | tr '\r' '\n' | grep -v '^$' | tail -n 1)
check "$([ "$e" = '################################# 100.0%' ] && echo ok)" "the bar for a POST: $e"

# A connection that is refused: the line is closed before the message.
"$TWIST" -o /dev/null "http://127.0.0.1:1/" 2> "$work/refused"
check "$([ $? -eq 7 ] && echo ok)" "a refused connection is 7"
check "$(tail -n 1 "$work/refused" | grep -q '^twist: (7)' && echo ok)" "and told after the meter"
check "$(grep -q '% Total' "$work/refused" && echo ok)" "with the heading"

# A transfer that waits is drawn each second: the data come after 3.5 s.
e=$(meter -o /dev/null "$u/stall")
n=$(printf '%s\n' "$e" | grep -c '^100     5    0     5 ')
check "$([ "$n" -ge 3 ] && echo ok)" "a line each second while it waits ($n)"
check "$(printf '%s\n' "$e" | grep -q ' 0:00:03 ' && echo ok)" "up to the third second"
# And so does a spaceship.
e=$(COLUMNS=40 "$TWIST" -# -o /dev/null "$u/stall" 2>&1 >/dev/null | tr '\r' '\n' | grep -c .)
check "$([ "$e" -ge 3 ] && echo ok)" "the spaceship flies while it waits ($e)"

[ $fail -eq 0 ] || exit 1
exit 0
