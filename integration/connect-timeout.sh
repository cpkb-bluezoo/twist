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

# --connect-timeout, as curl has it, against servers of python's that say what
# they are told to and then nothing.  For smtp, imap, pop3 and ftp it is the
# time to make the connection, and that is the lookup, the TCP connect, the
# greeting and the login: a server that is silent, or greets and goes quiet,
# ends the transfer at the connect timeout (status 28).  Once the login is
# done it no longer counts, and a server that then stalls is waited for until
# --max-time.  The other protocols have no greeting, and are waited for until
# --max-time too.  Skips, with status 77, without python3 or twist.

TWIST=${TWIST:-../src/twist}
skip ()
{
  echo "connect-timeout: $1; skipping" >&2
  exit 77
}
command -v python3 >/dev/null 2>&1 || skip "no python3"
[ -x "$TWIST" ] || skip "twist is not built ($TWIST)"

tmp=${TMPDIR:-/tmp}
work=$(mktemp -d "${tmp%/}/twist-connect-timeout.XXXXXX") || skip "no temp dir"
srv_pid=
cleanup ()
{
  [ -n "$srv_pid" ] && kill "$srv_pid" 2>/dev/null
  rm -rf "$work"
}
trap 'cleanup' EXIT INT TERM
exec < /dev/null
printf 'Subject: t\r\n\r\nbody\r\n' > "$work/msg"

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

# The server: PROTO is smtp, imap, pop3 or ftp, or anything else for a server
# that is silent; MODE is silent (accept, say nothing), greet (say the
# greeting, then nothing) or login (answer until the login is done and the
# first command of the transfer comes, and then say nothing).
cat > "$work/server.py" <<'PY'
import socket, sys, threading, time
port_file, proto, mode = sys.argv[1], sys.argv[2], sys.argv[3]
GREET = {'smtp': '220 x ESMTP\r\n', 'imap': '* OK x\r\n', 'pop3': '+OK x\r\n',
         'ftp': '220 x\r\n'}
def reply(proto, line):
    """The answer to LINE, or None to say nothing from now on."""
    word = line.split(' ')[0].upper()
    if proto == 'smtp':
        if word in ('EHLO', 'HELO'): return '250 x\r\n'
        return None
    if proto == 'imap':
        tag, _, rest = line.partition(' ')
        cmd = rest.split(' ')[0].upper()
        if cmd == 'CAPABILITY': return '* CAPABILITY IMAP4rev1\r\n%s OK done\r\n' % tag
        if cmd in ('LOGIN', 'AUTHENTICATE'): return '%s OK logged in\r\n' % tag
        return None
    if proto == 'pop3':
        if word == 'CAPA': return '+OK\r\nUSER\r\n.\r\n'
        if word in ('USER', 'PASS'): return '+OK\r\n'
        return None
    if proto == 'ftp':
        if word == 'USER': return '331 password\r\n'
        if word == 'PASS': return '230 in\r\n'
        if word == 'PWD': return '257 "/"\r\n'
        if word == 'SYST': return '215 UNIX\r\n'
        if word in ('TYPE', 'EPSV', 'PASV', 'EPRT', 'PORT', 'SIZE', 'MDTM', 'RETR',
                    'CWD', 'LIST', 'NLST', 'REST', 'STOR'):
            return None
        return '200 ok\r\n'
    return None
def serve(c):
    c.settimeout(0.2)
    if mode != 'silent' and proto in GREET:
        c.sendall(GREET[proto].encode())
    buf = b''
    stalled = mode != 'login'
    end = time.time() + 30
    while time.time() < end:
        try:
            d = c.recv(4096)
            if not d: return
            buf += d
        except socket.timeout:
            pass
        except OSError:
            return
        while b'\r\n' in buf and not stalled:
            line, _, buf = buf.partition(b'\r\n')
            r = reply(proto, line.decode('latin1'))
            if r is None: stalled = True
            else: c.sendall(r.encode())
        if stalled: buf = b''
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('127.0.0.1', 0)); s.listen(8)
open(port_file, 'w').write(str(s.getsockname()[1]))
while True:
    c, _ = s.accept()
    threading.Thread(target=serve, args=(c,), daemon=True).start()
PY

# serve PROTO MODE: starts the server for one scenario; its port is in $port.
serve ()
{
  [ -n "$srv_pid" ] && kill "$srv_pid" 2>/dev/null
  rm -f "$work/port"
  python3 -I "$work/server.py" "$work/port" "$1" "$2" > /dev/null 2>&1 &
  srv_pid=$!
  n=0
  while [ ! -s "$work/port" ] && [ $n -lt 100 ]; do
    sleep 0.1
    n=$((n + 1))
  done
  [ -s "$work/port" ] || skip "the server did not start"
  port=$(cat "$work/port")
}

# run URL ARGS...: the status, and the whole seconds it took, in $status and
# $secs.  Two seconds to connect in and eight in all.
run ()
{
  target=$1
  shift
  start=$(date +%s)
  "$TWIST" -s -o /dev/null --connect-timeout 2 --max-time 8 "$@" "$target" \
    > /dev/null 2>&1
  status=$?
  secs=$(( $(date +%s) - start ))
}

# The four that have a greeting.
for proto in smtp imap pop3 ftp
do
  case $proto in
    (smtp) url="smtp://127.0.0.1:%s/"; args="--mail-from a@b.example --mail-rcpt c@d.example -T $work/msg" ;;
    (imap) url="imap://127.0.0.1:%s/INBOX/;UID=1"; args="-u user:pass" ;;
    (pop3) url="pop3://127.0.0.1:%s/1"; args="-u user:pass" ;;
    (ftp)  url="ftp://127.0.0.1:%s/file"; args="-u user:pass" ;;
  esac
  for mode in silent greet
  do
    serve $proto $mode
    # shellcheck disable=SC2086
    run "$(printf "$url" "$port")" $args
    check "$(is "$status" 28)" "$proto, $mode: status 28 ($status)"
    check "$([ "$secs" -le 4 ] && echo ok)" \
      "$proto, $mode: at the connect timeout, and not at --max-time ($secs s)"
  done
  # Logged in, and then nothing: the connect timeout is over, and the
  # transfer is waited for until --max-time.
  serve $proto login
  # shellcheck disable=SC2086
  run "$(printf "$url" "$port")" $args
  check "$(is "$status" 28)" "$proto, logged in and then silent: status 28 ($status)"
  check "$([ "$secs" -ge 7 ] && echo ok)" \
    "$proto, logged in and then silent: waited for --max-time ($secs s)"
done

# The others have no greeting, and a silent server is waited for until
# --max-time.
serve none silent
for u in "dict://127.0.0.1:$port/d:word" "gopher://127.0.0.1:$port/1/" \
         "http://127.0.0.1:$port/" "rtsp://127.0.0.1:$port/s"
do
  run "$u"
  check "$(is "$status" 28)" "${u%%:*}, silent: status 28 ($status)"
  check "$([ "$secs" -ge 7 ] && echo ok)" \
    "${u%%:*}, silent: waited for --max-time ($secs s)"
done

exit $fail
