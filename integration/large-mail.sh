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

# A message sent by smtp:// goes out as the connection writes it, dot-stuffed a
# piece at a time and ended with the line with the dot, and arrives whole: a
# message of 3 MiB, from a file (-T) and from standard input, with lines that
# start with a dot, to an SMTP server of python's that waits before it reads
# the message, and says what it got.  Skips, with status 77, without python3
# or twist.

TWIST=${TWIST:-../src/twist}
skip ()
{
  echo "large-mail: $1; skipping" >&2
  exit 77
}
command -v python3 >/dev/null 2>&1 || skip "no python3"
[ -x "$TWIST" ] || skip "twist is not built ($TWIST)"

work=$(mktemp -d "${TMPDIR:-/tmp}/twist-large-mail.XXXXXX") || skip "no temp dir"
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
import hashlib, socket, sys, time
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('127.0.0.1', 0))
s.listen(8)
open(sys.argv[1], 'w').write(str(s.getsockname()[1]))
while True:
    c, _ = s.accept()
    f = c.makefile('rwb', buffering=0)
    f.write(b'220 hi\r\n')
    msg = None
    while True:
        line = f.readline()
        if not line:
            break
        cmd = line[:4].upper()
        if cmd in (b'EHLO', b'HELO'):
            f.write(b'250 hello\r\n')
        elif cmd == b'DATA':
            f.write(b'354 go\r\n')
            time.sleep(0.5)
            buf = b''
            while not buf.endswith(b'\r\n.\r\n'):
                d = c.recv(65536)
                if not d:
                    break
                buf += d
            body = buf[:-3]
            # Undo the dot-stuffing.
            lines = body.split(b'\r\n')
            lines = [l[1:] if l.startswith(b'..') else l for l in lines]
            msg = b'\r\n'.join(lines)
            open(sys.argv[2], 'w').write('%d %s' % (len(msg), hashlib.sha256(msg).hexdigest()))
            f.write(b'250 queued\r\n')
        elif cmd == b'QUIT':
            f.write(b'221 bye\r\n')
            break
        else:
            f.write(b'250 ok\r\n')
    c.close()
PY
python3 "$work/server.py" "$work/port" "$work/got" &
server_pid=$!
n=0
while [ ! -s "$work/port" ] && [ $n -lt 50 ]; do sleep 0.1; n=$((n + 1)); done
[ -s "$work/port" ] || skip "the server did not start"
url=smtp://127.0.0.1:$(cat "$work/port")

python3 - "$work/msg" <<'PY'
import sys
lines = []
n = 0
i = 0
while n < 3 * 1024 * 1024:
    l = ('.line %d with a leading dot' % i) if i % 7 == 0 else ('line %d of the message' % i)
    lines.append(l)
    n += len(l) + 2
    i += 1
open(sys.argv[1], 'wb').write(('\r\n'.join(lines) + '\r\n').encode())
PY
want=$(python3 -c "
import hashlib, sys
d = open('$work/msg', 'rb').read()
print(len(d), hashlib.sha256(d).hexdigest())")

"$TWIST" -s --mail-from a@example.org --mail-rcpt b@example.org -T "$work/msg" "$url" 2>/dev/null
check "$([ $? -eq 0 ] && echo ok)" "a message from a file is sent"
check "$([ "$(cat "$work/got")" = "$want" ] && echo ok)" "and arrives whole ($(cat "$work/got" 2>/dev/null))"

rm -f "$work/got"
"$TWIST" -s --mail-from a@example.org --mail-rcpt b@example.org -T - "$url" < "$work/msg" 2>/dev/null
check "$([ $? -eq 0 ] && echo ok)" "a message from standard input is sent"
check "$([ "$(cat "$work/got")" = "$want" ] && echo ok)" "and arrives whole ($(cat "$work/got" 2>/dev/null))"

exit $fail
