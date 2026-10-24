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

# rtsp:// as the curl tool does it, against a server of python's that sends
# one reply and writes down the request it was sent: what the request is, what
# is written to the output, and the exit status, for the replies that matter.
# The numbers are the ones curl 8 gives.  Skips, with status 77, without
# python3 or twist.

TWIST=${TWIST:-../src/twist}
skip ()
{
  echo "rtsp: $1; skipping" >&2
  exit 77
}
command -v python3 >/dev/null 2>&1 || skip "no python3"
[ -x "$TWIST" ] || skip "twist is not built ($TWIST)"

work=$(mktemp -d "${TMPDIR:-/tmp}/twist-rtsp.XXXXXX") || skip "no temp dir"
cleanup ()
{
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

cat > "$work/server.py" <<'PY'
import socket, sys, time
port_file, req_file, reply = sys.argv[1], sys.argv[2], sys.argv[3]
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
with open(req_file, 'wb') as f:
    f.write(data)
if reply:
    c.sendall(reply)
time.sleep(0.3)
c.close()
PY

# scenario REPLY ARGS...: leaves the output in $out, the status in $status and
# the request in $req (with CR written as \r).
scenario ()
{
  reply=$1
  shift
  rm -f "$work/port" "$work/req"
  python3 -I "$work/server.py" "$work/port" "$work/req" "$reply" &
  srv=$!
  n=0
  while [ ! -s "$work/port" ] && [ $n -lt 100 ]; do
    sleep 0.1
    n=$((n + 1))
  done
  [ -s "$work/port" ] || skip "the server did not start"
  port=$(cat "$work/port")
  "$TWIST" -s --max-time 5 "$@" "rtsp://127.0.0.1:$port/stream" \
    > "$work/out" 2> "$work/err"
  status=$?
  kill $srv 2>/dev/null
  wait $srv 2>/dev/null
  out=$(sed 's/\r$/<CR>/' "$work/out")
  req=$(sed 's/\r$/<CR>/' "$work/req" 2>/dev/null)
}
nl='
'
ok='RTSP/1.0 200 OK\r\nCSeq: 1\r\nContent-Length: 0\r\n\r\n'

scenario "$ok"
check "$(is "$status" 0)" "plain: status $status"
check "$(is "$req" "OPTIONS * RTSP/1.0<CR>${nl}CSeq: 1<CR>${nl}User-Agent: twist/0.1<CR>${nl}<CR>")" \
  "plain: request"
check "$(is "$out" "")" "plain: nothing is written"

scenario 'RTSP/1.0 200 OK\r\nCSeq: 1\r\nContent-Length: 5\r\n\r\nhello'
check "$(is "$status:$out" "0:hello")" "body: $status $out"

scenario "$ok" -A foo/1 -H 'X-A: b' -u u:p -X DESCRIBE -d body -r 0-3
check "$(is "$req" "OPTIONS * RTSP/1.0<CR>${nl}CSeq: 1<CR>${nl}User-Agent: foo/1<CR>${nl}Authorization: Basic dTpw<CR>${nl}X-A: b<CR>${nl}<CR>")" \
  "options: request"

scenario 'RTSP/1.0 200 OK\r\nCSeq: 2\r\nContent-Length: 0\r\n\r\n'
check "$(is "$status" 85)" "cseq mismatch: status $status"
scenario 'RTSP/1.0 200 OK\r\nContent-Length: 0\r\n\r\n'
check "$(is "$status" 85)" "cseq missing: status $status"
scenario "$ok" -H 'CSeq: 9'
check "$(is "$status" 85)" "cseq header: status $status"
scenario "$ok" -H 'Session: abc'
check "$(is "$status" 43)" "session header: status $status"

scenario 'RTSP/1.0 404 Not Found\r\nCSeq: 1\r\nContent-Length: 0\r\n\r\n' -w '%{http_code}'
check "$(is "$status:$out" "0:404")" "404: $status $out"
scenario 'RTSP/1.0 404 Not Found\r\nCSeq: 1\r\nContent-Length: 0\r\n\r\n' -f
check "$(is "$status" 22)" "404 -f: status $status"

scenario 'HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n'
check "$(is "$status" 52)" "not rtsp: status $status"
scenario 'RTSP/1.1 200 OK\r\nCSeq: 1\r\n\r\n'
check "$(is "$status" 8)" "rtsp 1.1: status $status"
scenario ''
check "$(is "$status" 52)" "no reply: status $status"
scenario 'RTSP/1.0 200 OK\r\nCSeq: 1\r\nContent-Length: 10\r\n\r\nabc'
check "$(is "$status" 18)" "short body: status $status"

# -i writes the status line and the headers as the server sent them, a blank
# line, and then the body; -I writes the headers and the blank line only.
scenario 'RTSP/1.0 200 Fine  Thing\r\ncseq:   1\r\nContent-Length: 4\r\nx-odd:v\r\n\r\nabcd' -i
check "$(is "$out" "RTSP/1.0 200 Fine  Thing<CR>${nl}cseq:   1<CR>${nl}Content-Length: 4<CR>${nl}x-odd:v<CR>${nl}<CR>${nl}abcd")" \
  "-i: $out"
scenario 'RTSP/1.0 200 OK\r\nCSeq: 1\r\nContent-Length: 4\r\n\r\nabcd' -I
check "$(is "$status:$out" "0:RTSP/1.0 200 OK<CR>${nl}CSeq: 1<CR>${nl}Content-Length: 4<CR>${nl}<CR>")" \
  "-I: $status $out"
scenario 'RTSP/1.0 302 Found\r\nCSeq: 1\r\nLocation: rtsp://127.0.0.1:1/x\r\nContent-Length: 0\r\n\r\n' -i -L
check "$(is "$status" 0)" "-L does not follow: status $status"

exit $fail
