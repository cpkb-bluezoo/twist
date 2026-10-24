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

# A large request body is sent as the connection writes it, and not copied
# into its queue whole, and arrives whole: 8 MiB (and 100 KiB, just over the
# size at which a body is streamed, and 1 KiB, under it) posted to a server
# of python's that waits before it reads any of it, then counts the bytes and
# says how many there were.  Skips, with status 77, without python3 or twist.

TWIST=${TWIST:-../src/twist}
skip ()
{
  echo "large-post: $1; skipping" >&2
  exit 77
}
command -v python3 >/dev/null 2>&1 || skip "no python3"
[ -x "$TWIST" ] || skip "twist is not built ($TWIST)"

work=$(mktemp -d "${TMPDIR:-/tmp}/twist-large-post.XXXXXX") || skip "no temp dir"
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
import socket, sys, time
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('127.0.0.1', 0))
s.listen(8)
open(sys.argv[1], 'w').write(str(s.getsockname()[1]))
while True:
    c, _ = s.accept()
    data = b''
    while b'\r\n\r\n' not in data:
        d = c.recv(65536)
        if not d:
            break
        data += d
    head, _, rest = data.partition(b'\r\n\r\n')
    n = 0
    for line in head.split(b'\r\n'):
        if line.lower().startswith(b'content-length:'):
            n = int(line.split(b':')[1])
    time.sleep(0.5)
    got = len(rest)
    while got < n:
        d = c.recv(65536)
        if not d:
            break
        got += len(d)
    body = str(got).encode()
    c.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\n' % len(body) + body)
    c.close()
PY
python3 "$work/server.py" "$work/port" &
server_pid=$!
n=0
while [ ! -s "$work/port" ] && [ $n -lt 50 ]; do sleep 0.1; n=$((n + 1)); done
[ -s "$work/port" ] || skip "the server did not start"
url=http://127.0.0.1:$(cat "$work/port")/

for size in 1024 102400 8388608; do
  head -c "$size" /dev/zero > "$work/body"
  out=$("$TWIST" -s --data-binary @"$work/body" "$url" 2>/dev/null)
  check "$([ "$out" = "$size" ] && echo ok)" "$size bytes arrive whole (got '$out')"
done

exit $fail
