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

# An upload with -T is read as it is sent and not first held whole: a file of
# 150 MiB is put to a server of python's that waits before it reads any of
# it, and twist's memory stays small; the length is sent when the file has
# one (Content-Length) and the body is chunked when the data is a pipe;
# and a redirect that has the body sent again (307) goes again from the start
# of a file, and fails for a pipe, which cannot be read again, with status 65.
# Skips, with status 77, without python3 or twist.

TWIST=${TWIST:-../src/twist}
skip ()
{
  echo "large-put: $1; skipping" >&2
  exit 77
}
command -v python3 >/dev/null 2>&1 || skip "no python3"
[ -x "$TWIST" ] || skip "twist is not built ($TWIST)"

work=$(mktemp -d "${TMPDIR:-/tmp}/twist-large-put.XXXXXX") || skip "no temp dir"
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
import hashlib, socket, sys, threading, time

def read_head(c):
    data = b''
    while b'\r\n\r\n' not in data:
        d = c.recv(65536)
        if not d:
            return None, b''
        data += d
    head, _, rest = data.partition(b'\r\n\r\n')
    return head, rest

def serve(c):
    head, rest = read_head(c)
    if head is None:
        c.close()
        return
    lines = head.split(b'\r\n')
    path = lines[0].split()[1].decode()
    hdr = {}
    for l in lines[1:]:
        k, _, v = l.partition(b':')
        hdr[k.strip().lower()] = v.strip()
    if path == '/slow':
        time.sleep(2)
    h = hashlib.sha256()
    total = 0
    if b'content-length' in hdr:
        n = int(hdr[b'content-length'])
        h.update(rest)
        total = len(rest)
        while total < n:
            d = c.recv(1 << 20)
            if not d:
                break
            h.update(d)
            total += len(d)
        kind = 'length'
    elif hdr.get(b'transfer-encoding', b'').lower() == b'chunked':
        buf = rest
        kind = 'chunked'
        while True:
            while b'\r\n' not in buf:
                d = c.recv(65536)
                if not d:
                    break
                buf += d
            line, _, buf = buf.partition(b'\r\n')
            size = int(line.split(b';')[0], 16)
            while len(buf) < size + 2:
                d = c.recv(1 << 20)
                if not d:
                    break
                buf += d
            if size == 0:
                break
            h.update(buf[:size])
            total += size
            buf = buf[size + 2:]
    else:
        kind = 'none'
    if path == '/redirect':
        c.sendall(b'HTTP/1.1 307 Temporary Redirect\r\nLocation: /final\r\nContent-Length: 0\r\nConnection: close\r\n\r\n')
    else:
        body = ('%s %d %s' % (kind, total, h.hexdigest())).encode()
        c.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\n' % len(body) + body)
    c.close()

s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('127.0.0.1', 0))
s.listen(16)
open(sys.argv[1], 'w').write(str(s.getsockname()[1]))
while True:
    c, _ = s.accept()
    threading.Thread(target=serve, args=(c,), daemon=True).start()
PY
python3 "$work/server.py" "$work/port" &
server_pid=$!
n=0
while [ ! -s "$work/port" ] && [ $n -lt 50 ]; do sleep 0.1; n=$((n + 1)); done
[ -s "$work/port" ] || skip "the server did not start"
url=http://127.0.0.1:$(cat "$work/port")

sha ()
{
  python3 -c "import hashlib,sys; print(hashlib.sha256(open(sys.argv[1],'rb').read()).hexdigest())" "$1"
}

head -c 3000000 /dev/urandom > "$work/small"
want=$(sha "$work/small")

out=$("$TWIST" -s -T "$work/small" "$url/ok" 2>/dev/null)
check "$([ "$out" = "length 3000000 $want" ] && echo ok)" "a file is sent whole with its length ($out)"

out=$(cat "$work/small" | "$TWIST" -s -T - "$url/ok" 2>/dev/null)
check "$([ "$out" = "chunked 3000000 $want" ] && echo ok)" "a pipe is sent chunked ($out)"

out=$("$TWIST" -s -T "$work/small" "$url/redirect" -L 2>/dev/null)
check "$([ "$out" = "length 3000000 $want" ] && echo ok)" "a 307 sends a file again from the start ($out)"

cat "$work/small" | "$TWIST" -s -T - "$url/redirect" -L >/dev/null 2>&1
check "$([ $? -eq 65 ] && echo ok)" "a 307 for a pipe cannot be sent again: status 65"

# 150 MiB, the server not reading for two seconds: how much of it twist holds.
head -c 157286400 /dev/zero > "$work/big"
"$TWIST" -s -T "$work/big" "$url/slow" >"$work/big.out" 2>/dev/null &
tp=$!
max=0
while kill -0 "$tp" 2>/dev/null; do
  r=$(ps -o rss= -p "$tp" 2>/dev/null | tr -d ' ')
  [ -n "$r" ] && [ "$r" -gt "$max" ] && max=$r
  sleep 0.1
done
wait "$tp"
check "$([ "$(cut -d' ' -f1,2 "$work/big.out")" = "length 157286400" ] && echo ok)" "150 MiB arrive whole"
check "$([ "$max" -lt 60000 ] && echo ok)" "twist held ${max} KiB, not the 150 MiB"

exit $fail
