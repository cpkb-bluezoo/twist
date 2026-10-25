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

# imap:// with -T appends a message to the mailbox the URL names (RFC 3501,
# 6.3.11): APPEND, the size of the message as a literal, the server's
# go-ahead, and then the message, which is sent as the connection takes it.
# The size has to be said first, so a message of unknown size (a pipe) is
# refused, as curl refuses it.  Against an IMAP server of python's that logs
# what it is given and keeps the message: a file of 3 MiB, a mailbox that the
# server will not take (status 25), a pipe, and 100 MiB to a server that
# waits before it reads, with twist's memory watched.  Skips, with status 77,
# without python3 or twist.

TWIST=${TWIST:-../src/twist}
skip ()
{
  echo "imap-append: $1; skipping" >&2
  exit 77
}
command -v python3 >/dev/null 2>&1 || skip "no python3"
[ -x "$TWIST" ] || skip "twist is not built ($TWIST)"

work=$(mktemp -d "${TMPDIR:-/tmp}/twist-imap-append.XXXXXX") || skip "no temp dir"
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

mkdir "$work/store"
cat > "$work/server.py" <<'PY'
import re, socket, sys, threading, time

store, log, portfile = sys.argv[1], sys.argv[2], sys.argv[3]

def note(line):
    with open(log, 'a') as f:
        f.write(line + '\n')

def serve(c):
    f = c.makefile('rwb', buffering=0)
    def say(s):
        f.write((s + '\r\n').encode())
    say('* OK hi')
    while True:
        line = f.readline()
        if not line:
            break
        line = line.decode().rstrip('\r\n')
        note(line)
        tag, _, rest = line.partition(' ')
        cmd, _, arg = rest.partition(' ')
        cmd = cmd.upper()
        if cmd == 'CAPABILITY':
            say('* CAPABILITY IMAP4rev1')
            say('%s OK done' % tag)
        elif cmd == 'APPEND':
            m = re.match(r'("[^"]*"|\S+) (?:\([^)]*\) )?(?:"[^"]*" )?\{(\d+)\+?\}$', arg)
            box, n = m.group(1).strip('"'), int(m.group(2))
            if 'refuse' in box:
                say('%s NO [TRYCREATE] no such mailbox' % tag)
                continue
            say('+ ready for literal data')
            if 'slow' in box:
                time.sleep(2)
            got = 0
            with open(store + '/' + box.replace('/', '_'), 'wb') as out:
                while got < n:
                    b = f.read(min(1 << 20, n - got))
                    if not b:
                        break
                    out.write(b)
                    got += len(b)
            f.readline()
            say('%s OK APPEND completed' % tag)
        elif cmd == 'LOGOUT':
            say('* BYE')
            say('%s OK logout' % tag)
            break
        else:
            say('%s BAD what' % tag)
    c.close()

s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('127.0.0.1', 0))
s.listen(8)
open(portfile, 'w').write(str(s.getsockname()[1]))
while True:
    c, _ = s.accept()
    threading.Thread(target=serve, args=(c,), daemon=True).start()
PY
python3 "$work/server.py" "$work/store" "$work/cmds.log" "$work/port" &
server_pid=$!
n=0
while [ ! -s "$work/port" ] && [ $n -lt 50 ]; do sleep 0.1; n=$((n + 1)); done
[ -s "$work/port" ] || skip "the server did not start"
url=imap://127.0.0.1:$(cat "$work/port")

head -c 3000000 /dev/urandom > "$work/msg"

"$TWIST" -s -T "$work/msg" "$url/INBOX" 2>/dev/null
check "$([ $? -eq 0 ] && cmp -s "$work/msg" "$work/store/INBOX" && echo ok)" \
  "a message is appended whole"
check "$(grep -q '^A[0-9]* APPEND INBOX {3000000}$' "$work/cmds.log" && echo ok)" \
  "with its size as the literal"

"$TWIST" -s -T "$work/msg" "$url/refuse" 2>/dev/null
check "$([ $? -eq 25 ] && echo ok)" "a mailbox the server will not take is status 25"

rm -f "$work/cmds.log"
cat "$work/msg" | "$TWIST" -s -T - "$url/INBOX" 2>/dev/null
check "$([ $? -eq 25 ] && echo ok)" "a message of unknown size is status 25"
check "$(! grep -q APPEND "$work/cmds.log" 2>/dev/null && echo ok)" \
  "and nothing is appended"

# 100 MiB, the server not reading for two seconds: how much twist holds.
head -c 104857600 /dev/zero > "$work/big"
"$TWIST" -s -T "$work/big" "$url/slow" >/dev/null 2>&1 &
tp=$!
max=0
while kill -0 "$tp" 2>/dev/null; do
  r=$(ps -o rss= -p "$tp" 2>/dev/null | tr -d ' ')
  [ -n "$r" ] && [ "$r" -gt "$max" ] && max=$r
  sleep 0.1
done
wait "$tp"
check "$([ $? -eq 0 ] && [ "$(wc -c < "$work/store/slow")" -eq 104857600 ] && echo ok)" \
  "100 MiB arrive whole"
check "$([ "$max" -lt 60000 ] && echo ok)" "twist held ${max} KiB, not the 100 MiB"

exit $fail
