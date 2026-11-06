#!/bin/sh
# Copyright (C) 2026 Chris Burdess <dog@gnu.org>
#
#    This file is part of twist.
#
#    twist is free software: you can redistribute it and/or modify it
#    under the terms of the GNU General Public License as published
#    by the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    twist is distributed in the hope that it will be useful, but
#    WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
#    General Public License for more details.
#
#    You should have received a copy of the GNU General Public
#    License along with this program.  If not, see
#    <https://www.gnu.org/licenses/>.
#
# The tool reads an upload, and writes a body, off the thread of the loop: a
# transfer that waits for a pipe does not stop another.  Two transfers run
# together against a server on this machine (it needs python).

TWIST=${TWIST:-../src/twist}
[ -x "$TWIST" ] || { echo "cli-fdio: twist is not built ($TWIST); skipping" >&2; exit 77; }
command -v python3 >/dev/null 2>&1 || { echo "cli-fdio: no python; skipping" >&2; exit 77; }
TWIST=$(cd "$(dirname "$TWIST")" && pwd)/$(basename "$TWIST")

tmp=${TMPDIR:-/tmp}
work=$(mktemp -d "${tmp%/}/twist-fdio.XXXXXX") || exit 77
pids=
cleanup ()
{
  for p in $pids; do kill "$p" 2>/dev/null; done
  rm -rf "$work"
}
trap cleanup EXIT INT TERM
# A hung transfer fails the test and does not hold up the build.
( sleep 90; kill $$ ) >/dev/null 2>&1 &
pids="$pids $!"

cat > "$work/server.py" <<'PY'
import sys, http.server, socketserver

class H(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    def log_message(self, *a):
        pass
    def reply(self, body):
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def do_GET(self):
        if self.path == "/big":
            self.reply(b"x" * (8 << 20))
        else:
            self.reply(b"small")
    def do_PUT(self):
        if self.headers.get("Transfer-Encoding", "") == "chunked":
            while True:
                n = int(self.rfile.readline().split(b";")[0], 16)
                if n == 0:
                    while self.rfile.readline() not in (b"\r\n", b""):
                        pass
                    break
                self.rfile.read(n + 2)
        else:
            n = int(self.headers.get("Content-Length", "0"))
            self.rfile.read(n)
        self.reply(b"stored")

class S(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True

s = S(("127.0.0.1", 0), H)
print(s.server_address[1], flush=True)
s.serve_forever()
PY
python3 "$work/server.py" > "$work/port" 2>/dev/null &
pids="$pids $!"
i=0
while [ ! -s "$work/port" ] && [ $i -lt 50 ]; do sleep 0.1; i=$((i + 1)); done
port=$(cat "$work/port")
[ -n "$port" ] || { echo "cli-fdio: no server; skipping" >&2; exit 77; }
base="http://127.0.0.1:$port"

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
# Wait until FILE has SIZE bytes, for at most five seconds.
size_of ()
{
  if [ -f "$1" ]; then wc -c < "$1"; else echo 0; fi
}
wait_size ()
{
  i=0
  while [ "$(size_of "$1")" -lt "$2" ] && [ $i -lt 50 ]
  do
    sleep 0.1
    i=$((i + 1))
  done
  [ "$(size_of "$1")" -ge "$2" ] && echo ok
}

# An upload from a pipe that has nothing yet does not hold up another
# transfer: the second one is done while the first still waits for its data,
# and the first goes on when the data comes.
{ sleep 4; printf 'hello'; } | "$TWIST" -s --parallel -T - "$base/up" \
  -o "$work/up.out" --next -o "$work/second" "$base/small" &
tw=$!
pids="$pids $tw"
check "$(wait_size "$work/second" 5)" \
  "a transfer is done while another waits on a pipe with no data"
kill -0 "$tw" 2>/dev/null
check "$([ $? -eq 0 ] && echo ok)" "the transfer waiting for data has not ended"
wait "$tw"
check "$([ "$(cat "$work/up.out")" = stored ] && echo ok)" \
  "and it ends when the pipe does, with the reply ($(cat "$work/up.out"))"

# A body for a pipe that is not being read does not hold up another transfer
# either, and is all there once the pipe is read.
"$TWIST" -s --parallel "$base/big" --next -o "$work/small" "$base/small" \
  | { sleep 4; cat > "$work/got"; } &
tw=$!
pids="$pids $tw"
check "$(wait_size "$work/small" 5)" \
  "a transfer is done while the stdout pipe is full"
kill -0 "$tw" 2>/dev/null
check "$([ $? -eq 0 ] && echo ok)" "the transfer with the full pipe is still going"
wait "$tw"
size=$(size_of "$work/got")
check "$([ "$size" -eq 8388608 ] && echo ok)" \
  "the whole body is there when the pipe is read ($size)"

# A file for -o is what was written, whatever was in it.
printf 'old old old old old old old' > "$work/over"
"$TWIST" -s -o "$work/over" "$base/small"
check "$([ "$(cat "$work/over")" = small ] && echo ok)" \
  "-o replaces a longer file ($(cat "$work/over"))"
printf 'keep' > "$work/keep"
"$TWIST" -s -o "$work/keep" "http://127.0.0.1:1/" 2>/dev/null
check "$([ "$(cat "$work/keep")" = keep ] && echo ok)" \
  "a transfer that fails before a body leaves the file as it was"
"$TWIST" -s -o "$work/none" "http://127.0.0.1:1/" 2>/dev/null
check "$([ ! -e "$work/none" ] && echo ok)" \
  "and makes none"

exit $fail
