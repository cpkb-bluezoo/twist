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

# Names that need no DNS: localhost, and any name under it, are this machine
# (RFC 6761), and a name in the hosts file is where the file says.  Twist asks
# neither of a nameserver, which on some machines (those with a resolver
# of the network's in /etc/resolv.conf, and not a stub of their own) does not
# know them.  Tried with a server of python's on the loopback, through HTTP
# and through a protocol of the other kind of handler.  The hosts file itself
# is in tests/test-dns.c: this one cannot be written to.  Skips, with status
# 77, without python3 or twist.

TWIST=${TWIST:-../src/twist}
skip ()
{
  echo "hosts: $1; skipping" >&2
  exit 77
}
command -v python3 >/dev/null 2>&1 || skip "no python3"
[ -x "$TWIST" ] || skip "twist is not built ($TWIST)"

tmp=${TMPDIR:-/tmp}
work=$(mktemp -d "${tmp%/}/twist-hosts.XXXXXX") || skip "no temp dir"
srv_pid=
cleanup ()
{
  [ -n "$srv_pid" ] && kill "$srv_pid" 2>/dev/null
  rm -rf "$work"
}
trap 'cleanup' EXIT INT TERM
exec < /dev/null

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

# A server of HTTP on the loopback, which answers "ok" to anything, and also,
# on the same port, to Gopher: a line is read and "gopher ok" written back.
cat > "$work/server.py" <<'PY'
import socket, sys, threading
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", 0)); s.listen(8)
open(sys.argv[1], "w").write(str(s.getsockname()[1]))
def serve(c):
    c.settimeout(2)
    try:
        data = b""
        while b"\n" not in data:
            d = c.recv(4096)
            if not d: return
            data += d
        if data.startswith(b"GET "):
            c.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
        else:
            c.sendall(b"gopher ok\r\n")
    except OSError:
        pass
    finally:
        c.close()
while True:
    c, _ = s.accept(); threading.Thread(target=serve, args=(c,), daemon=True).start()
PY
python3 -I "$work/server.py" "$work/port" > /dev/null 2>&1 &
srv_pid=$!
n=0
while [ ! -s "$work/port" ] && [ $n -lt 100 ]; do
  sleep 0.1
  n=$((n + 1))
done
[ -s "$work/port" ] || skip "the server did not start"
port=$(cat "$work/port")

# get URL: the output and the status.
get ()
{
  out=$("$TWIST" -s -S --max-time 8 "$1" 2> "$work/err")
  status=$?
  err=$(cat "$work/err")
}

for name in localhost LocalHost. app.localhost a.b.c.localhost
do
  get "http://$name:$port/"
  check "$(is "$status:$out" "0:ok")" "http://$name: the loopback ($status $out $err)"
done
get "gopher://api.localhost:$port/1/"
check "$(case "$out" in ("gopher ok"*) echo ok;; esac)" \
  "gopher://api.localhost: the loopback, for another handler ($status $out $err)"

# What only looks like it is a name for DNS, and not the loopback: it is not
# found, and does not hang.
get "http://notlocalhost.invalid:$port/"
check "$([ "$status" -ne 0 ] && echo ok)" "notlocalhost.invalid is not the loopback ($status $out)"

exit $fail
