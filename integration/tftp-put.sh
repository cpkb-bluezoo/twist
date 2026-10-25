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

# A tftp upload with -T is read a block at a time as the server acknowledges
# them, and not first held whole: 4 MiB (and a file that is an exact number of
# blocks, which ends with a block of no data) to a server of python's, and
# what arrives is compared.  Skips, with status 77, without python3 or twist.

TWIST=${TWIST:-../src/twist}
skip ()
{
  echo "tftp-put: $1; skipping" >&2
  exit 77
}
command -v python3 >/dev/null 2>&1 || skip "no python3"
[ -x "$TWIST" ] || skip "twist is not built ($TWIST)"

work=$(mktemp -d "${TMPDIR:-/tmp}/twist-tftp-put.XXXXXX") || skip "no temp dir"
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
import hashlib, socket, struct, sys

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(('127.0.0.1', 0))
open(sys.argv[1], 'w').write(str(s.getsockname()[1]))
while True:
    pkt, peer = s.recvfrom(2048)
    if struct.unpack('>H', pkt[:2])[0] != 2:
        continue
    name = pkt[2:].split(b'\0')[0].decode()
    t = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    t.bind(('127.0.0.1', 0))
    t.settimeout(5)
    t.sendto(struct.pack('>HH', 4, 0), peer)
    data = b''
    block = 1
    while True:
        try:
            pkt, p = t.recvfrom(2048)
        except socket.timeout:
            break
        op, n = struct.unpack('>HH', pkt[:4])
        if op != 3:
            break
        if n == block:
            data += pkt[4:]
            block += 1
        t.sendto(struct.pack('>HH', 4, n), p)
        if len(pkt) - 4 < 512:
            break
    open(sys.argv[2] + name, 'w').write('%d %s' % (len(data), hashlib.sha256(data).hexdigest()))
    t.close()
PY
python3 "$work/server.py" "$work/port" "$work/got." &
server_pid=$!
n=0
while [ ! -s "$work/port" ] && [ $n -lt 50 ]; do sleep 0.1; n=$((n + 1)); done
[ -s "$work/port" ] || skip "the server did not start"
port=$(cat "$work/port")

sha ()
{
  python3 -c "import hashlib,sys; d=open(sys.argv[1],'rb').read(); print(len(d), hashlib.sha256(d).hexdigest())" "$1"
}

head -c 4194304 /dev/urandom > "$work/big"
"$TWIST" -s -T "$work/big" "tftp://127.0.0.1:$port/big" 2>/dev/null
check "$([ $? -eq 0 ] && [ "$(cat "$work/got.big" 2>/dev/null)" = "$(sha "$work/big")" ] && echo ok)" \
  "4 MiB arrive whole"

head -c 5120 /dev/urandom > "$work/exact"
"$TWIST" -s -T "$work/exact" "tftp://127.0.0.1:$port/exact" 2>/dev/null
check "$([ $? -eq 0 ] && [ "$(cat "$work/got.exact" 2>/dev/null)" = "$(sha "$work/exact")" ] && echo ok)" \
  "a whole number of blocks, with the block of no data at the end"

cat "$work/exact" | "$TWIST" -s -T - "tftp://127.0.0.1:$port/pipe" 2>/dev/null
check "$([ $? -eq 0 ] && [ "$(cat "$work/got.pipe" 2>/dev/null)" = "$(sha "$work/exact")" ] && echo ok)" \
  "a pipe"

exit $fail
