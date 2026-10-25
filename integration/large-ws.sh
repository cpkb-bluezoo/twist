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

# A WebSocket message that is large is sent a frame at a time, as the
# connection can take them, and arrives whole: 3 MiB of data (--data) to a
# server of python's that waits before it reads any of it, then joins the
# frames, says how many bytes and what hash, and closes.  Skips, with status
# 77, without python3 or twist.

TWIST=${TWIST:-../src/twist}
skip ()
{
  echo "large-ws: $1; skipping" >&2
  exit 77
}
command -v python3 >/dev/null 2>&1 || skip "no python3"
[ -x "$TWIST" ] || skip "twist is not built ($TWIST)"

work=$(mktemp -d "${TMPDIR:-/tmp}/twist-large-ws.XXXXXX") || skip "no temp dir"
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
import base64, hashlib, socket, struct, sys, time

def recv_exact(c, n):
    buf = b''
    while len(buf) < n:
        d = c.recv(min(1 << 20, n - len(buf)))
        if not d:
            raise EOFError
        buf += d
    return buf

s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('127.0.0.1', 0))
s.listen(1)
open(sys.argv[1], 'w').write(str(s.getsockname()[1]))
c, _ = s.accept()
head = b''
while b'\r\n\r\n' not in head:
    head += c.recv(4096)
key = [l.split(b':')[1].strip() for l in head.split(b'\r\n')
       if l.lower().startswith(b'sec-websocket-key')][0]
acc = base64.b64encode(hashlib.sha1(key + b'258EAFA5-E914-47DA-95CA-C5AB0DC85B11').digest())
c.sendall(b'HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n'
          b'Connection: Upgrade\r\nSec-WebSocket-Accept: ' + acc + b'\r\n\r\n')
time.sleep(1.5)
data = b''
frames = 0
while True:
    b0, b1 = recv_exact(c, 2)
    n = b1 & 0x7f
    if n == 126:
        n = struct.unpack('>H', recv_exact(c, 2))[0]
    elif n == 127:
        n = struct.unpack('>Q', recv_exact(c, 8))[0]
    mask = recv_exact(c, 4) if b1 & 0x80 else b'\0\0\0\0'
    pay = bytearray(recv_exact(c, n))
    for i in range(len(pay)):
        pay[i] ^= mask[i & 3]
    data += bytes(pay)
    frames += 1
    if b0 & 0x80:
        break
open(sys.argv[2], 'w').write('%d %d %s' % (len(data), frames, hashlib.sha256(data).hexdigest()))
c.sendall(b'\x88\x00')
time.sleep(0.3)
PY
python3 "$work/server.py" "$work/port" "$work/got" &
server_pid=$!
n=0
while [ ! -s "$work/port" ] && [ $n -lt 50 ]; do sleep 0.1; n=$((n + 1)); done
[ -s "$work/port" ] || skip "the server did not start"

head -c 3145728 /dev/urandom > "$work/msg"
want=$(python3 -c "import hashlib,sys; print(hashlib.sha256(open(sys.argv[1],'rb').read()).hexdigest())" "$work/msg")

"$TWIST" -s --data-binary @"$work/msg" "ws://127.0.0.1:$(cat "$work/port")/" >/dev/null 2>&1
got=$(cat "$work/got" 2>/dev/null)
check "$([ "${got%% *}" = 3145728 ] && echo ok)" "3 MiB arrive ($got)"
check "$([ "${got##* }" = "$want" ] && echo ok)" "and are the same bytes"
frames=$(echo "$got" | cut -d' ' -f2)
check "$([ "${frames:-0}" -gt 100 ] && echo ok)" "in many frames ($frames), not one"

exit $fail
