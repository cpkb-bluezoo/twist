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
# the message, and says what it got (the bytes as they were sent, compared with
# the message dot-stuffed here); and a message of 100 MiB, with twist's memory
# watched while it goes.  Skips, with status 77, without python3 or twist.

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
            h = hashlib.sha256()
            total = 0
            tail = b''
            while not tail.endswith(b'\r\n.\r\n'):
                d = c.recv(1 << 20)
                if not d:
                    break
                h.update(d)
                total += len(d)
                tail = (tail + d)[-5:]
            open(sys.argv[2], 'w').write('%d %s' % (total, h.hexdigest()))
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
# What goes on the wire: each line that starts with a dot has another, and the
# line with the dot ends it.
want=$(python3 -c "
import hashlib
d = open('$work/msg', 'rb').read()
out = b''.join((b'.' + l if l.startswith(b'.') else l) for l in d.split(b'\r\n')[:-1] and [x + b'\r\n' for x in d.split(b'\r\n')[:-1]])
out += b'.\r\n'
print(len(out), hashlib.sha256(out).hexdigest())")

"$TWIST" -s --mail-from a@example.org --mail-rcpt b@example.org -T "$work/msg" "$url" 2>/dev/null
check "$([ $? -eq 0 ] && echo ok)" "a message from a file is sent"
check "$([ "$(cat "$work/got")" = "$want" ] && echo ok)" "and arrives whole ($(cat "$work/got" 2>/dev/null))"

rm -f "$work/got"
"$TWIST" -s --mail-from a@example.org --mail-rcpt b@example.org -T - "$url" < "$work/msg" 2>/dev/null
check "$([ $? -eq 0 ] && echo ok)" "a message from standard input is sent"
check "$([ "$(cat "$work/got")" = "$want" ] && echo ok)" "and arrives whole ($(cat "$work/got" 2>/dev/null))"

# 100 MiB: how much of it twist holds while it goes.  Lines of 1000 bytes and
# no dots, so the wire is the file and a dot.
rm -f "$work/got"
python3 - "$work/big" <<'PY'
import sys
line = b'a' * 998 + b'\r\n'
with open(sys.argv[1], 'wb') as f:
    for _ in range(104858):
        f.write(line)
PY
bigwant=$(python3 -c "
import hashlib
h = hashlib.sha256()
n = 0
with open('$work/big', 'rb') as f:
    while True:
        d = f.read(1 << 20)
        if not d: break
        h.update(d); n += len(d)
h.update(b'.\r\n'); n += 3
print(n, h.hexdigest())")
"$TWIST" -s --mail-from a@example.org --mail-rcpt b@example.org -T "$work/big" "$url" 2>/dev/null &
tp=$!
max=0
while kill -0 "$tp" 2>/dev/null; do
  r=$(ps -o rss= -p "$tp" 2>/dev/null | tr -d ' ')
  [ -n "$r" ] && [ "$r" -gt "$max" ] && max=$r
  sleep 0.1
done
wait "$tp"
check "$([ $? -eq 0 ] && [ "$(cat "$work/got" 2>/dev/null)" = "$bigwant" ] && echo ok)" \
  "100 MiB arrive whole"
check "$([ "$max" -lt 60000 ] && echo ok)" "twist held ${max} KiB, not the 100 MiB"

exit $fail
