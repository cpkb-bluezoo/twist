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

# ftp:// through an HTTP proxy and a SOCKS5 proxy (proxy-peer.py), against an
# FTP server of python's.  The data connection is a second connection and has
# to go through the proxy as well: made directly, it connects from the client's
# own address, past the proxy, which with a proxy that is there to hide the
# client (Tor) gives it away, and with one that is the only way out does not
# work.  The proxy logs every tunnel it is asked for, so what is checked is
# that it was asked for the control connection and then for the data port the
# server named.  Skips, with status 77, without python3 or twist.

TWIST=${TWIST:-../src/twist}
skip ()
{
  echo "ftp-proxy: $1; skipping" >&2
  exit 77
}
command -v python3 >/dev/null 2>&1 || skip "no python3"
[ -x "$TWIST" ] || skip "twist is not built ($TWIST)"
here=$(cd "$(dirname "$0")" && pwd)

work=$(mktemp -d "${TMPDIR:-/tmp}/twist-ftp-proxy.XXXXXX") || skip "no temp dir"
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

cat > "$work/ftpd.py" <<'PY'
import socket, sys, threading

log = sys.argv[1]
BODY = b"hello over ftp\n"

def note(text):
    with open(log, "a") as f:
        f.write(text + "\n")

def readline(sock):
    buf = b""
    while not buf.endswith(b"\r\n"):
        c = sock.recv(1)
        if not c:
            return None
        buf += c
    return buf[:-2].decode("latin-1")

def session(conn):
    def say(s):
        conn.sendall(s.encode() + b"\r\n")
    say("220 ready")
    lst = None
    while True:
        line = readline(conn)
        if line is None:
            break
        verb = line.split(" ")[0].upper()
        arg = line.split(" ", 1)[1] if " " in line else ""
        if verb == "USER":
            say("331 password")
        elif verb == "PASS":
            say("230 in")
        elif verb == "TYPE":
            say("200 type")
        elif verb == "PASV":
            say("500 no")
        elif verb == "EPSV":
            lst = socket.socket()
            lst.bind(("127.0.0.1", 0))
            lst.listen(1)
            note("data port %d" % lst.getsockname()[1])
            say("229 Entering Extended Passive Mode (|||%d|)" % lst.getsockname()[1])
        elif verb == "RETR":
            lst.settimeout(5)
            try:
                d, _ = lst.accept()
            except OSError:
                say("425 no data connection")
                continue
            say("150 Opening data connection (%d bytes)." % len(BODY))
            d.sendall(BODY)
            d.close()
            say("226 done")
        elif verb == "QUIT":
            say("221 bye")
            break
        else:
            say("502 no")
    conn.close()

srv = socket.socket()
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", 0))
srv.listen(5)
print(srv.getsockname()[1], flush=True)
while True:
    c, _ = srv.accept()
    threading.Thread(target=session, args=(c,), daemon=True).start()
PY

waitfor ()
{
  i=0
  while [ ! -s "$1" ] && [ $i -lt 50 ]; do sleep 0.1; i=$((i + 1)); done
  [ -s "$1" ] || skip "a server did not start"
}
: > "$work/ftpd.log"
python3 -I "$work/ftpd.py" "$work/ftpd.log" > "$work/ftpd.port" 2>/dev/null &
pids="$pids $!"
waitfor "$work/ftpd.port"
ftp_port=$(cat "$work/ftpd.port")
for kind in http socks; do
  : > "$work/$kind.log"
  python3 -I "$here/proxy-peer.py" $kind ok "$work/$kind.port" "$work/$kind.log" \
    >/dev/null 2>&1 &
  pids="$pids $!"
  waitfor "$work/$kind.port"
done
http_port=$(cat "$work/http.port")
socks_port=$(cat "$work/socks.port")

for v in ftp_proxy FTP_PROXY all_proxy ALL_PROXY no_proxy NO_PROXY; do
  unset $v
done
url="ftp://u:p@127.0.0.1:$ftp_port/hello"
get () { timeout 20 "$TWIST" -s -S "$@" 2>/dev/null; }
# The ports the proxy was asked to reach, one to a line.
asked () { sed 's/.*:\([0-9]*\)$/\1/' "$work/$1.log"; }
data_port () { tail -1 "$work/ftpd.log" | sed 's/^data port //'; }

check "$(is "$(get "$url")" "hello over ftp")" "ftp, direct"

for kind in http socks; do
  case $kind in
    http) px="http://127.0.0.1:$http_port" ;;
    socks) px="socks5h://127.0.0.1:$socks_port" ;;
  esac
  : > "$work/$kind.log"
  check "$(is "$(get -x "$px" "$url")" "hello over ftp")" "ftp through a $kind proxy"
  dp=$(data_port)
  check "$(is "$(asked $kind | tr '\n' ' ')" "$ftp_port $dp ")" \
    "the $kind proxy was asked for the control connection, then the data port ($(asked $kind | tr '\n' ' '), data port $dp)"
done

[ $fail = 0 ]
