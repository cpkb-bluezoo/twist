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

# Where a redirect may go, and what goes with it, against servers of python's
# (an HTTP one that redirects where it is told, an HTTPS one, and a small FTP
# one that writes down who logs in).  A redirect goes by scheme: from http to
# http, https, ftp and ftps; from https to https and ftps; from nothing else to
# anything.  An ftp target is a transfer of its own: the user name and
# password given for the HTTP request are not sent to it, those of the
# Location are, and the headers of the redirect are shown before the file.
# --proto-redir changes nothing and says so.  The positive cases are curl's
# too; the refusals are stricter than curl's.  Skips, with status 77, without
# python3 or twist; the https cases also without openssl, or with a python
# that has no TLS 1.3 (which twist needs).

TWIST=${TWIST:-../src/twist}
skip ()
{
  echo "redirect: $1; skipping" >&2
  exit 77
}
command -v python3 >/dev/null 2>&1 || skip "no python3"
[ -x "$TWIST" ] || skip "twist is not built ($TWIST)"

tmp=${TMPDIR:-/tmp}
work=$(mktemp -d "${tmp%/}/twist-redirect.XXXXXX") || skip "no temp dir"
pids=
cleanup ()
{
  for p in $pids; do kill "$p" 2>/dev/null; done
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

# An FTP server that has one file, for any name, and writes down who logs in.
cat > "$work/ftpd.py" <<'PY'
import socket, sys, threading
port_file, log_file = sys.argv[1], sys.argv[2]
DATA = b"hello from ftp\n"
def log(line):
    with open(log_file, "a") as f: f.write(line + "\n")
def serve(c):
    f = c.makefile("rb"); w = c.sendall
    w(b"220 ftpd\r\n"); data_l = None
    while True:
        line = f.readline()
        if not line: break
        line = line.decode("latin1").strip(); cmd, _, arg = line.partition(" "); cmd = cmd.upper()
        if cmd in ("USER", "PASS"): log("%s %s" % (cmd, arg))
        if cmd == "USER": w(b"331 password\r\n")
        elif cmd == "PASS": w(b"230 logged in\r\n")
        elif cmd == "PWD": w(b'257 "/"\r\n')
        elif cmd == "SYST": w(b"215 UNIX\r\n")
        elif cmd in ("TYPE", "MODE", "STRU", "OPTS"): w(b"200 ok\r\n")
        elif cmd == "SIZE": w(b"213 %d\r\n" % len(DATA))
        elif cmd in ("EPSV", "PASV"):
            data_l = socket.socket(); data_l.bind(("127.0.0.1", 0)); data_l.listen(1)
            p = data_l.getsockname()[1]
            if cmd == "EPSV": w(b"229 Entering Extended Passive Mode (|||%d|)\r\n" % p)
            else: w(b"227 Entering Passive Mode (127,0,0,1,%d,%d)\r\n" % (p // 256, p % 256))
        elif cmd == "RETR":
            log("RETR %s" % arg)
            w(b"150 Opening data connection (%d bytes)\r\n" % len(DATA))
            d, _ = data_l.accept(); d.sendall(DATA); d.close(); data_l.close()
            w(b"226 done\r\n")
        elif cmd == "QUIT": w(b"221 bye\r\n"); break
        else: w(b"502 not implemented\r\n")
    c.close()
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", 0)); s.listen(8)
open(port_file, "w").write(str(s.getsockname()[1]))
while True:
    c, _ = s.accept(); threading.Thread(target=serve, args=(c,), daemon=True).start()
PY

# An HTTP or HTTPS server: /r?to=LOCATION answers 302 to LOCATION (/slow?to= does
# so after two seconds), /ok is "ok".
cat > "$work/httpd.py" <<'PY'
import http.server, socketserver, ssl, sys, time, urllib.parse
port_file, cert, key = sys.argv[1], sys.argv[2], sys.argv[3]
class H(http.server.BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'
    def log_message(self, *a): pass
    def do_GET(self):
        u = urllib.parse.urlparse(self.path)
        q = urllib.parse.parse_qs(u.query)
        if u.path in ('/r', '/slow'):
            if u.path == '/slow': time.sleep(2)
            self.send_response(302); self.send_header('Location', q['to'][0])
            self.send_header('Content-Length', '0'); self.end_headers()
        else:
            body = b'ok'
            self.send_response(200); self.send_header('Content-Length', str(len(body)))
            self.end_headers(); self.wfile.write(body)
class Server(http.server.HTTPServer):
    def server_bind(self):
        # Not HTTPServer's, which looks the name of the address up, and can
        # take a long time to be told there is none.
        socketserver.TCPServer.server_bind(self)
        self.server_name = '127.0.0.1'
        self.server_port = self.server_address[1]
srv = Server(('127.0.0.1', 0), H)
if cert != '-':
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); ctx.load_cert_chain(cert, key)
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
open(port_file, 'w').write(str(srv.server_address[1]))
srv.serve_forever()
PY

# A server that accepts connections and says nothing.
cat > "$work/silent.py" <<'PY'
import socket, sys, time
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", 0)); s.listen(8)
open(sys.argv[1], "w").write(str(s.getsockname()[1]))
conns = []; s.settimeout(0.5); end = time.time() + 60
while time.time() < end:
    try: conns.append(s.accept()[0])
    except socket.timeout: pass
PY

# start NAME ARGS...: a server in the background; its port is in $work/NAME.port.
start ()
{
  name=$1
  shift
  rm -f "$work/$name.port"
  python3 -I "$work/$name.py" "$work/$name.port" "$@" > /dev/null 2>&1 &
  pids="$pids $!"
  n=0
  while [ ! -s "$work/$name.port" ] && [ $n -lt 100 ]; do
    sleep 0.1
    n=$((n + 1))
  done
  [ -s "$work/$name.port" ] || skip "the $name server did not start"
}
start ftpd "$work/ftp.log"
start httpd - -
start silent
fport=$(cat "$work/ftpd.port")
sport=$(cat "$work/silent.port")
hport=$(cat "$work/httpd.port")
http="http://127.0.0.1:$hport"

# redirect URL ARGS...: a request that is redirected to URL.  The output is in
# $out, the status in $status, what the tool said in $err, and the FTP server's
# log in $log (the lines of USER and PASS, and the RETR).
redirect ()
{
  loc=$1
  shift
  : > "$work/ftp.log"
  out=$("$TWIST" --max-time 10 -L "$@" "$base/r?to=$loc" 2> "$work/err")
  status=$?
  err=$(cat "$work/err")
  log=$(tr '\n' ';' < "$work/ftp.log")
}
base=$http

# An ftp target: it is a transfer of its own, an anonymous one unless the
# Location names someone.
redirect "ftp://127.0.0.1:$fport/file" -s -S
check "$(is "$status:$out" "0:hello from ftp")" "http -> ftp: the file ($status $out)"
case $log in
  (USER\ anonymous\;PASS\ *\;RETR\ file\;) ;;
  (*) check bad "http -> ftp: an anonymous login and the file ($log)" ;;
esac
redirect "ftp://127.0.0.1:$fport/file" -s -S -u alice:secret
check "$(is "$status:$out" "0:hello from ftp")" "the user and password of the request: the file ($status $out)"
case $log in
  (*alice*|*secret*) check bad "the user and password of the request are not sent to ftp ($log)" ;;
esac
redirect "ftp://bob:pw@127.0.0.1:$fport/file" -s -S -u alice:secret
case $log in
  (USER\ bob\;PASS\ pw\;RETR\ file\;) ;;
  (*) check bad "the user and password of the Location are ($log)" ;;
esac
redirect "ftp://127.0.0.1:$fport/file" -s -S -i
check "$(case "$out" in ("HTTP/1.1 302"*"
hello from ftp") echo ok;; esac)" "-i: the headers of the redirect, then the file ($out)"
redirect "ftp://127.0.0.1:$fport/file" -s -S -w '[%{url_effective}]'
check "$(is "$out" "hello from ftp
[ftp://127.0.0.1:$fport/file]")" "-w url_effective is the ftp URL ($out)"
redirect "ftp://127.0.0.1:1/file" -s -S
check "$(is "$status" 7)" "an ftp server that is not there: status 7 ($status)"

# ftps is the other handler for the other scheme: against a server that does not
# speak TLS it fails at the handshake (35), where ftp would have worked.
redirect "ftps://127.0.0.1:$fport/file" -s -S
check "$(is "$status" 35)" "http -> ftps goes to the ftps handler: status 35 ($status)"

# --max-time is for all of it: two seconds are spent on the redirect, and the
# three that were given are not given again to the ftp server that says nothing.
start=$(date +%s)
out=$("$TWIST" -s --max-time 3 -L "$http/slow?to=ftp://127.0.0.1:$sport/file" 2>/dev/null)
status=$?
secs=$(( $(date +%s) - start ))
check "$(is "$status" 28)" "a silent ftp server after a redirect: status 28 ($status)"
check "$([ "$secs" -le 4 ] && echo ok)" \
  "and the time of the whole is --max-time, not that and again ($secs s)"

# http -> http, and the redirect that is not followed without -L.
redirect "$http/ok" -s -S
check "$(is "$status:$out" "0:ok")" "http -> http ($status $out)"
out=$("$TWIST" -s "$http/r?to=$http/ok")
check "$(is "$out" "")" "no -L: the redirect is not followed"

# Where it may not go: exit 1, said, and nothing there is asked.
for to in "gopher://127.0.0.1:1/" "file:///etc/hostname" "ws://127.0.0.1:1/" \
          "wss://127.0.0.1:1/" "sftp://127.0.0.1:1/x" "smtp://127.0.0.1:1/" \
          "dict://127.0.0.1:1/d:w" "scp://127.0.0.1:1/x" "ldap://127.0.0.1:1/"
do
  redirect "$to" -s -S
  check "$(is "$status" 1)" "http -> ${to%%:*} is refused: status 1 ($status)"
  check "$(case "$err" in (*"is not followed"*) echo ok;; esac)" \
    "and said so: $err"
done

# --proto-redir changes nothing, and says that it does not.
redirect "gopher://127.0.0.1:1/" --proto-redir =all
check "$(is "$status" 1)" "--proto-redir =all: gopher is still refused ($status)"
check "$(case "$err" in (*"--proto-redir"*"no effect"*) echo ok;; esac)" \
  "--proto-redir says it has no effect: $err"
redirect "gopher://127.0.0.1:1/" -s --proto-redir =all
check "$(case "$err" in (*"--proto-redir"*) echo bad;; (*) echo ok;; esac)" \
  "and not with -s"
redirect "$http/ok" -s -S --proto-redir =https
check "$(is "$status:$out" "0:ok")" "--proto-redir =https does not narrow it: http -> http ($status $out)"

# From https: to https and ftps, and to nothing that is not encrypted.
if command -v openssl >/dev/null 2>&1 \
   && python3 -I -c 'import ssl, sys; sys.exit(0 if ssl.HAS_TLSv1_3 else 1)'
then
  openssl req -x509 -newkey rsa:2048 -nodes -keyout "$work/key.pem" \
    -out "$work/cert.pem" -days 2 -subj /CN=localhost > /dev/null 2>&1 \
    || skip "openssl could not make a certificate"
  start httpd "$work/cert.pem" "$work/key.pem"
  base=https://127.0.0.1:$(cat "$work/httpd.port")
  redirect "$base/ok" -s -S -k
  check "$(is "$status:$out" "0:ok")" "https -> https ($status $out)"
  redirect "ftps://127.0.0.1:$fport/file" -s -S -k
  check "$(is "$status" 35)" "https -> ftps goes to the ftps handler: status 35 ($status)"
  redirect "$http/ok" -s -S -k
  check "$(is "$status" 1)" "https -> http is refused: status 1 ($status)"
  check "$(case "$err" in (*"is not followed"*) echo ok;; esac)" "and said so: $err"
  redirect "ftp://127.0.0.1:$fport/file" -s -S -k
  check "$(is "$status" 1)" "https -> ftp is refused: status 1 ($status)"
  case $log in
    ("") ;;
    (*) check bad "and the ftp server was not asked ($log)" ;;
  esac
  redirect "gopher://127.0.0.1:1/" -s -S -k
  check "$(is "$status" 1)" "https -> gopher is refused: status 1 ($status)"
  redirect "ws://127.0.0.1:1/" -s -S -k
  check "$(is "$status" 1)" "https -> ws is refused: status 1 ($status)"
else
  echo "redirect: no openssl, or a python without TLS 1.3; the https cases are not tried" >&2
fi

exit $fail
