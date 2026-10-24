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

# telnet:// against a scripted server of python's that says what it is told to
# and keeps every byte it is sent.  The server's commands are answered as the
# telnet client that came before this one answers them: the bytes expected
# below were taken from a run of that client against this same server.  What a
# session sends is standard input or the file of -T, and the end of that does
# not end the session: the server's close does.  Then, with a terminal for
# standard input and with a SOCKS5 proxy (proxy-peer.py).  Skips, with
# status 77, without python3 or twist.

TWIST=${TWIST:-../src/twist}
skip ()
{
  echo "telnet: $1; skipping" >&2
  exit 77
}
command -v python3 >/dev/null 2>&1 || skip "no python3"
[ -x "$TWIST" ] || skip "twist is not built ($TWIST)"
here=$(cd "$(dirname "$0")" && pwd)

work=$(mktemp -d "${TMPDIR:-/tmp}/twist-telnet.XXXXXX") || skip "no temp dir"
pids=
cleanup ()
{
  for p in $pids; do kill "$p" 2>/dev/null; done
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

cat > "$work/peer.py" <<'PY'
# usage: peer.py PORTFILE RECVFILE STEP...
# One connection.  A STEP is s:HEX (send), w:MS (wait) or c (close).  What
# arrives is written to RECVFILE as it does.  After the steps the connection
# is held until the client closes it, for six seconds at most.  Nobody
# connecting in three seconds ends it too.
import socket, sys, threading, time

portfile, recvfile = sys.argv[1:3]
srv = socket.socket()
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", 0))
srv.listen(1)
open(portfile, "w").write(str(srv.getsockname()[1]))
srv.settimeout(3)
try:
    conn, _ = srv.accept()
except socket.timeout:
    open(recvfile, "wb").close()
    sys.exit(0)
conn.settimeout(None)
out = open(recvfile, "wb", buffering=0)
done = threading.Event()

def reader():
    while True:
        try:
            d = conn.recv(65536)
        except OSError:
            break
        if not d:
            break
        out.write(d)
    done.set()

threading.Thread(target=reader, daemon=True).start()
for step in sys.argv[3:]:
    if step.startswith("s:"):
        conn.sendall(bytes.fromhex(step[2:]))
    elif step.startswith("w:"):
        time.sleep(int(step[2:]) / 1000.0)
    elif step == "c":
        conn.close()
        sys.exit(0)
done.wait(6)
conn.close()
PY

# The server for one session: start_peer STEP..., then run the client at
# $port, then end_peer, which leaves what the server was sent in $got, as hex.
start_peer ()
{
  rm -f "$work/port" "$work/recv"
  python3 -I "$work/peer.py" "$work/port" "$work/recv" "$@" &
  peer=$!
  pids="$pids $peer"
  i=0
  while [ ! -s "$work/port" ] && [ $i -lt 50 ]; do sleep 0.1; i=$((i + 1)); done
  port=$(cat "$work/port")
}
end_peer ()
{
  wait $peer
  got=$(od -An -tx1 -v "$work/recv" | tr -d ' \n')
}
hexof () { od -An -tx1 -v | tr -d ' \n'; }
t () { "$TWIST" -s -S "$@"; }

# Text, and the commands in it.  A carriage return and a NUL is a carriage
# return; 255 255 is 255; an unknown command is dropped; and the first command
# the server sends, here WILL ECHO, starts the answers: DO ECHO, and then what
# we want (binary and suppress go-ahead, both ways).
start_peer s:68656c6c6f0d0a w:50 s:610d00620d0a w:50 s:41ff4142 w:50 \
  s:fffb01 w:50 s:4344 w:300 c
out=$(t "telnet://127.0.0.1:$port/" </dev/null | hexof)
end_peer
check "$(is "$out" 68656c6c6f0d0a610d620d0a41424344)" "the text, without the commands ($out)"
check "$(is "$got" fffd01fffb00fffd00fffb03fffd03)" "the first command is answered, and the options asked for ($got)"

# A server that negotiates a lot: WILL ECHO, DO and WILL SGA, DO BINARY, DO of
# the terminal type, window size, environment and display (we want none but
# the size, which is sent as nothing), and then a request for the terminal
# type, which is answered, empty.
B=fffb01fffd03fffb03fffd00fffd18fffd1ffffd27fffd23
start_peer s:$B w:300 s:fffa1801fff0 w:300 c
t "telnet://127.0.0.1:$port/" </dev/null >/dev/null; st=$?
end_peer
check "$(is "$st" 0)" "a negotiating server ends the session when it closes ($st)"
check "$(is "$got" fffd01fffb03fffd03fffb00fffc18fffb1ffffa1f00000000fff0fffc27fffc23fffd00fffa1800fff0)" "a negotiation is answered ($got)"

# With the options given: the terminal type, display, environment, window size
# and 7 bits.
ALL=fffd18fffd23fffd27fffd1ffffd00
SBS=fffa1801fff0fffa2301fff0fffa2701fff0
start_peer s:$ALL w:300 s:$SBS w:300 c
t -t TTYPE=vt100 -t XDISPLOC=host:0 -t NEW_ENV=A,B -t NEW_ENV=C -t WS=80x24 \
  -t BINARY=0 "telnet://127.0.0.1:$port/" </dev/null >/dev/null
end_peer
check "$(is "$got" fffb18fffb23fffb27fffb1ffffa1f00500018fff0fffc00fffb03fffd03fffa18007674313030fff0fffa2300686f73743a30fff0fffa2700004101420043fff0)" "the options are given ($got)"

# The user name, from -u or from the URL, is the environment variable USER.
start_peer s:$ALL w:300 s:$SBS w:300 c
t -u bob:secret "telnet://127.0.0.1:$port/" </dev/null >/dev/null
end_peer
check "$(is "$got" fffc18fffc23fffb27fffb1ffffa1f00000000fff0fffb00fffd00fffb03fffd03fffa1800fff0fffa2300fff0fffa2700005553455201626f62fff0)" "-u is the USER variable ($got)"
start_peer s:fffd27 w:300 c
t "telnet://bob:secret@127.0.0.1:$port/" </dev/null >/dev/null
end_peer
check "$(is "$got" fffb27fffb00fffd00fffb03fffd03)" "so is the user of the URL ($got)"

# What is sent: standard input, with each 255 doubled; the file of -T, the
# same; and not the data of -d.  The session goes on after its input ends, to
# the server's close.
start_peer s:6869 w:400 c
out=$(printf 'abc\377def\n' | t "telnet://127.0.0.1:$port/" | hexof)
end_peer
check "$(is "$out" 6869)" "the text of the server"
check "$(is "$got" 616263ffff6465660a)" "standard input is sent, a 255 doubled ($got)"
printf 'from a file\n' > "$work/up"
start_peer s:6869 w:400 c
t -T "$work/up" "telnet://127.0.0.1:$port/" </dev/null >/dev/null
end_peer
check "$(is "$got" 66726f6d20612066696c650a)" "-T sends the file ($got)"
start_peer s:6869 w:400 c
printf 'piped\n' | t -T - "telnet://127.0.0.1:$port/" >/dev/null
end_peer
check "$(is "$got" 70697065640a)" "-T - is standard input ($got)"
start_peer s:6869 w:400 c
t -d hello "telnet://127.0.0.1:$port/" </dev/null >/dev/null
end_peer
check "$(is "$got" "")" "-d is not sent ($got)"
start_peer s:6869 w:400 c
t -T "$work/nothing" "telnet://127.0.0.1:$port/" </dev/null >/dev/null 2>&1; st=$?
end_peer
check "$(is "$st" 26)" "-T of a file that is not there is status 26 ($st)"

# Input that comes later is sent when it comes: the session is open for a
# second and a half, and the input arrives half a second into it.
start_peer s:6869 w:1500 c
( sleep 0.5; printf late ) | t "telnet://127.0.0.1:$port/" >/dev/null
end_peer
check "$(is "$got" 6c617465)" "input that comes later is sent ($got)"

# What the server sent is counted as the text, not the commands.
start_peer s:6162fffb01630d00 w:200 c
out=$(t -w '[%{size_download}]' "telnet://127.0.0.1:$port/" </dev/null)
end_peer
check "$(is "$out" "$(printf 'abc\r[4]')")" "size_download is the text ($out)"

# Options that are bad end the transfer before it connects: if they did not,
# the status would be 7, nobody being at port 1.
t -t WS=bad "telnet://127.0.0.1:1/" </dev/null >/dev/null 2>&1; st=$?
check "$(is "$st" 49)" "a bad option is status 49 ($st)"
t -t NOPE=1 "telnet://127.0.0.1:1/" </dev/null >/dev/null 2>&1; st=$?
check "$(is "$st" 48)" "an unknown option is status 48 ($st)"

# A server that says nothing is waited for to the end of -m; nobody there is
# status 7.
start_peer w:2000
t -m 1 "telnet://127.0.0.1:$port/" </dev/null >/dev/null 2>&1; st=$?
end_peer
check "$(is "$st" 28)" "-m ends a session with a quiet server, status 28 ($st)"
t "telnet://127.0.0.1:1/" </dev/null >/dev/null 2>&1; st=$?
check "$(is "$st" 7)" "nobody there is status 7 ($st)"

# A terminal is standard input: what is typed is sent as it is typed, and the
# session ends when the server closes, with the terminal still open.
cat > "$work/on-tty.py" <<'PY'
import os, pty, subprocess, sys, time
twist, url = sys.argv[1:3]
master, slave = pty.openpty()
p = subprocess.Popen([twist, "-s", "-S", url], stdin=slave,
                     stdout=subprocess.PIPE, stderr=subprocess.PIPE)
os.close(slave)
time.sleep(0.5)
os.write(master, b"typed line\n")
out, err = p.communicate(timeout=10)
sys.exit(0 if p.returncode == 0 and out == b"z" else 1)
PY
if python3 -c 'import pty' 2>/dev/null; then
  start_peer s:7a w:1500 c
  python3 -I "$work/on-tty.py" "$TWIST" "telnet://127.0.0.1:$port/"; st=$?
  end_peer
  check "$(is "$st" 0)" "a terminal as standard input: the session ends with the server ($st)"
  check "$(is "$got" 7479706564206c696e650a)" "and what is typed is sent ($got)"
fi

# Through a SOCKS5 proxy: the tunnel is asked for, and standard input goes
# through it.
start_peer s:fffd03 w:800 s:6869 w:300 c
python3 -I "$here/proxy-peer.py" socks ok "$work/pport" "$work/plog" &
pids="$pids $!"
i=0
while [ ! -s "$work/pport" ] && [ $i -lt 50 ]; do sleep 0.1; i=$((i + 1)); done
out=$(printf 'via proxy\n' | t -x "socks5://127.0.0.1:$(cat "$work/pport")" \
  "telnet://127.0.0.1:$port/" | hexof)
end_peer
check "$(is "$out" 6869)" "through a proxy: the text ($out)"
check "$(is "$got" 7669612070726f78790afffb03fffb00fffd00fffd03)" "through a proxy: the input and the answers ($got)"
check "$(grep -q "CONNECT atyp1 127.0.0.1:$port" "$work/plog" && echo ok)" \
  "the proxy was asked for the tunnel"

[ $fail = 0 ]
