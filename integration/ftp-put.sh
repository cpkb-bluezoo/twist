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

# ftp:// uploads, against an FTP server of python's that keeps what it is sent
# in files and logs the commands it is given.  -T sends a file with STOR (a
# file, a pipe, and a name that ends in a slash, which takes the file's name);
# --append sends it with APPE; -C N resumes: the server is told where to go on
# (APPE, with the first N bytes of the file not sent again; and with -C - the
# size is asked of the server first), and a download resumes with REST.  A
# server that refuses is status 25.  The file is read as it is sent: 100 MiB to
# a server that waits before it reads, and twist's memory is watched.  Skips,
# with status 77, without python3 or twist.

TWIST=${TWIST:-../src/twist}
skip ()
{
  echo "ftp-put: $1; skipping" >&2
  exit 77
}
command -v python3 >/dev/null 2>&1 || skip "no python3"
[ -x "$TWIST" ] || skip "twist is not built ($TWIST)"

work=$(mktemp -d "${TMPDIR:-/tmp}/twist-ftp-put.XXXXXX") || skip "no temp dir"
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
import os, socket, sys, threading, time

store, log, portfile = sys.argv[1], sys.argv[2], sys.argv[3]

def note(line):
    with open(log, 'a') as f:
        f.write(line + '\n')

def path_of(name):
    return os.path.join(store, name.lstrip('/').replace('/', '_'))

def serve(c):
    f = c.makefile('rwb', buffering=0)
    def say(s):
        f.write((s + '\r\n').encode())
    say('220 hi')
    pasv = None
    rest = 0
    while True:
        line = f.readline()
        if not line:
            break
        line = line.decode().rstrip('\r\n')
        note(line)
        cmd, _, arg = line.partition(' ')
        cmd = cmd.upper()
        if cmd == 'USER':
            say('331 pass')
        elif cmd == 'PASS':
            say('230 in')
        elif cmd == 'TYPE':
            say('200 ok')
        elif cmd in ('EPSV', 'PASV'):
            pasv = socket.socket()
            pasv.bind(('127.0.0.1', 0))
            pasv.listen(1)
            port = pasv.getsockname()[1]
            if cmd == 'EPSV':
                say('229 Entering Extended Passive Mode (|||%d|)' % port)
            else:
                say('227 Entering Passive Mode (127,0,0,1,%d,%d)' % (port >> 8, port & 255))
        elif cmd == 'REST':
            rest = int(arg)
            say('350 ok')
        elif cmd == 'SIZE':
            p = path_of(arg)
            if os.path.exists(p):
                say('213 %d' % os.path.getsize(p))
            else:
                say('550 no such file')
        elif cmd in ('STOR', 'APPE'):
            if 'refuse' in arg:
                say('553 not allowed')
                continue
            say('150 go')
            d, _ = pasv.accept()
            if 'slow' in arg:
                time.sleep(2)
            mode = 'ab' if cmd == 'APPE' else 'wb'
            with open(path_of(arg), mode) as out:
                while True:
                    b = d.recv(1 << 20)
                    if not b:
                        break
                    out.write(b)
            d.close()
            say('226 done')
            rest = 0
        elif cmd == 'RETR':
            p = path_of(arg)
            if not os.path.exists(p):
                say('550 no such file')
                continue
            say('150 go')
            d, _ = pasv.accept()
            with open(p, 'rb') as src:
                src.seek(rest)
                while True:
                    b = src.read(1 << 16)
                    if not b:
                        break
                    d.sendall(b)
            d.close()
            say('226 done')
            rest = 0
        elif cmd == 'QUIT':
            say('221 bye')
            break
        else:
            say('502 no')
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
url=ftp://127.0.0.1:$(cat "$work/port")

same () { cmp -s "$1" "$2" && echo ok; }
sent () { grep -c "^$1" "$work/cmds.log" 2>/dev/null || true; }

head -c 3000000 /dev/urandom > "$work/in"

"$TWIST" -s -T "$work/in" "$url/up1" 2>/dev/null
check "$([ $? -eq 0 ] && same "$work/in" "$work/store/up1")" "a file is sent with STOR"
check "$([ "$(sent 'STOR ')" -eq 1 ] && echo ok)" "and with no other command"

cat "$work/in" | "$TWIST" -s -T - "$url/up2" 2>/dev/null
check "$([ $? -eq 0 ] && same "$work/in" "$work/store/up2")" "a pipe is sent"

"$TWIST" -s -T "$work/in" "$url/" 2>/dev/null
check "$([ $? -eq 0 ] && same "$work/in" "$work/store/in")" \
  "a URL that ends in a slash takes the name of the file"

# --append.
printf 'abc' > "$work/store/app"
printf 'def' > "$work/small"
"$TWIST" -s --append -T "$work/small" "$url/app" 2>/dev/null
check "$([ $? -eq 0 ] && [ "$(cat "$work/store/app")" = abcdef ] && echo ok)" \
  "--append adds to the file"
check "$([ "$(sent APPE)" -ge 1 ] && echo ok)" "with APPE"

# Resume an upload at 1000000: the first of the file is there already.
head -c 1000000 "$work/in" > "$work/store/res"
rm -f "$work/cmds.log"
"$TWIST" -s -C 1000000 -T "$work/in" "$url/res" 2>/dev/null
check "$([ $? -eq 0 ] && same "$work/in" "$work/store/res")" \
  "-C N resumes an upload where the server is"
check "$([ "$(sent APPE)" -eq 1 ] && [ "$(sent STOR)" -eq 0 ] && echo ok)" \
  "with APPE and no STOR"

# Resume at the size the server says.
head -c 700000 "$work/in" > "$work/store/auto"
rm -f "$work/cmds.log"
"$TWIST" -s -C - -T "$work/in" "$url/auto" 2>/dev/null
check "$([ $? -eq 0 ] && same "$work/in" "$work/store/auto")" \
  "-C - asks the server how much it has"
check "$([ "$(sent SIZE)" -eq 1 ] && echo ok)" "with SIZE"

# A download resumes with REST.
head -c 400000 "$work/in" > "$work/part"
rm -f "$work/cmds.log"
cp "$work/in" "$work/store/dl"
"$TWIST" -s -C 400000 -o "$work/part" "$url/dl" 2>/dev/null
check "$([ $? -eq 0 ] && same "$work/in" "$work/part")" \
  "-C N resumes a download"
check "$([ "$(sent 'REST 400000')" -eq 1 ] && echo ok)" "with REST"

# A server that says no.
"$TWIST" -s -T "$work/small" "$url/refuse" 2>/dev/null
check "$([ $? -eq 25 ] && echo ok)" "a refused upload is status 25"

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
