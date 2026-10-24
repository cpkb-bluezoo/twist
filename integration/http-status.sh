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

# The status line of a response and its version, as the curl tool writes
# them.  An HTTP/1 status line is written as the server sent it, reason
# phrase and all; an HTTP/2 response has the status line "HTTP/2 200 " (with
# its trailing space) and not the pseudo-header ":status: 200"; and
# -w %{http_version} is 1 for HTTP/1.0, 1.1 for HTTP/1.1, 2 for HTTP/2, and 0
# when there was no HTTP response.  HTTP/1 is tried against a server of
# python's that sends what it is told to, HTTP/2 against nghttpd.  Skips,
# with status 77, without python3 or twist; the HTTP/2 part also without
# nghttpd.

TWIST=${TWIST:-../src/twist}
skip ()
{
  echo "http-status: $1; skipping" >&2
  exit 77
}
command -v python3 >/dev/null 2>&1 || skip "no python3"
[ -x "$TWIST" ] || skip "twist is not built ($TWIST)"

work=$(mktemp -d "${TMPDIR:-/tmp}/twist-http-status.XXXXXX") || skip "no temp dir"
nghttpd_pid=
cleanup ()
{
  [ -n "$nghttpd_pid" ] && kill "$nghttpd_pid" 2>/dev/null
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
is () { [ "$1" = "$2" ] && echo ok; }
nl='
'

cat > "$work/server.py" <<'PY'
import socket, sys, time
port_file, reply = sys.argv[1], sys.argv[2]
reply = reply.encode().decode('unicode_escape').encode('latin1')
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('127.0.0.1', 0))
s.listen(1)
with open(port_file, 'w') as f:
    f.write(str(s.getsockname()[1]))
s.settimeout(10)
c, _ = s.accept()
c.settimeout(1)
data = b''
try:
    while b'\r\n\r\n' not in data:
        chunk = c.recv(4096)
        if not chunk:
            break
        data += chunk
except Exception:
    pass
c.sendall(reply)
time.sleep(0.3)
c.close()
PY

# h1 REPLY ARGS...: the reply sent for one request, and the output.
h1 ()
{
  reply=$1
  shift
  rm -f "$work/port"
  python3 -I "$work/server.py" "$work/port" "$reply" &
  srv=$!
  n=0
  while [ ! -s "$work/port" ] && [ $n -lt 100 ]; do
    sleep 0.1
    n=$((n + 1))
  done
  [ -s "$work/port" ] || skip "the server did not start"
  "$TWIST" -s --max-time 5 "$@" "http://127.0.0.1:$(cat "$work/port")/" \
    > "$work/out" 2> "$work/err"
  status=$?
  kill $srv 2>/dev/null
  wait $srv 2>/dev/null
  out=$(sed 's/\r$/<CR>/' "$work/out")
}

h1 'HTTP/1.1 200 Fine  Thing\r\nContent-Length: 2\r\n\r\nhi' -i
check "$(is "$out" "HTTP/1.1 200 Fine  Thing<CR>${nl}Content-Length: 2<CR>${nl}<CR>${nl}hi")" \
  "a reason phrase is kept: $out"
h1 'HTTP/1.0 301 Moved\r\nContent-Length: 0\r\n\r\n' -i
check "$(is "$out" "HTTP/1.0 301 Moved<CR>${nl}Content-Length: 0<CR>${nl}<CR>")" \
  "and an HTTP/1.0 one: $out"
h1 'HTTP/1.1 204\r\nX: y\r\n\r\n' -i
check "$(is "$out" "HTTP/1.1 204<CR>${nl}X: y<CR>${nl}<CR>")" \
  "no reason phrase, no trailing space: $out"

h1 'HTTP/1.0 200 OK\r\nContent-Length: 0\r\n\r\n' -o /dev/null -w '%{http_version}'
check "$(is "$out" 1)" "http_version of HTTP/1.0: $out"
h1 'HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n' -o /dev/null -w '%{http_version}'
check "$(is "$out" 1.1)" "http_version of HTTP/1.1: $out"
echo hi > "$work/f"
out=$("$TWIST" -s -o /dev/null -w '%{http_version}' "file://$work/f")
check "$(is "$out" 0)" "http_version of a file: $out"
out=$("$TWIST" -s -o /dev/null -w '%{http_version}' "http://127.0.0.1:1/")
check "$(is "$out" 0)" "http_version when the connection is refused: $out"

# HTTP/2, cleartext with prior knowledge.
if command -v nghttpd >/dev/null 2>&1; then
  mkdir "$work/www"
  echo hello > "$work/www/f.txt"
  port=$(python3 -I -c 'import socket; s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])')
  nghttpd --no-tls -a 127.0.0.1 -d "$work/www" "$port" \
    > "$work/nghttpd.out" 2>&1 < /dev/null &
  nghttpd_pid=$!
  n=0
  while [ $n -lt 50 ] && ! python3 -I -c "import socket; socket.create_connection(('127.0.0.1', $port), 1)" 2>/dev/null; do
    sleep 0.1
    n=$((n + 1))
  done
  h2="$TWIST -s --max-time 5 --http2-prior-knowledge"
  u="http://127.0.0.1:$port/f.txt"
  out=$($h2 -i "$u" | sed 's/\r$/<CR>/' | head -1)
  check "$(is "$out" "HTTP/2 200 <CR>")" "the HTTP/2 status line: $out"
  out=$($h2 -i "$u" | grep -c ':status')
  check "$(is "$out" 0)" "the pseudo-header :status is not written"
  out=$($h2 -D - -o /dev/null "$u" | head -1 | sed 's/\r$/<CR>/')
  check "$(is "$out" "HTTP/2 200 <CR>")" "-D writes it too: $out"
  out=$($h2 -o /dev/null -w '%{http_version} %{http_code}' \
          "http://127.0.0.1:$port/missing")
  check "$(is "$out" "2 404")" "http_version of HTTP/2: $out"
else
  echo "http-status: no nghttpd; HTTP/2 is not tried" >&2
fi

exit $fail
