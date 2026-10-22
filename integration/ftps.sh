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
# <https://www.gnu.org/licenses/>.

# ftps:// against an FTPS server of python's (implicit TLS on the control
# connection): the data connection must be protected as well (RFC 4217,
# PBSZ 0 and PROT P), verified like the control connection, and a server that
# will not protect it ends the transfer, and one that requires the data
# connection to resume the control session is satisfied.  The server takes the data
# connection when it is asked for the file, answers 150, and only then
# starts TLS on it, as vsftpd does, and records what it saw in a log.
# Skips, with status 77, without python3, openssl or twist.

TWIST=${TWIST:-../src/twist}
skip ()
{
  echo "ftps: $1; skipping" >&2
  exit 77
}
command -v python3 >/dev/null 2>&1 || skip "no python3"
command -v openssl >/dev/null 2>&1 || skip "no openssl"
[ -x "$TWIST" ] || skip "twist is not built ($TWIST)"

work=$(mktemp -d "${TMPDIR:-/tmp}/twist-ftps.XXXXXX") || skip "no temp dir"
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

mkcert ()
{
  openssl req -x509 -newkey rsa:2048 -nodes -keyout "$work/$1-key.pem" \
    -out "$work/$1-cert.pem" -days 2 -subj "/CN=127.0.0.1" \
    -addext "subjectAltName=IP:127.0.0.1" \
    -addext "basicConstraints=critical,CA:TRUE" >/dev/null 2>&1 \
    || skip "openssl cannot make a certificate"
}
mkcert good
mkcert other

cat > "$work/server.py" <<'PY'
import socket, ssl, sys, threading

cert, key, log, mode, data_cert, data_key = sys.argv[1:7]
HELLO = b"hello over ftps\n"
BIG = (b"0123456789abcdef" * 4096) * 5          # 327680 bytes

def note(text):
    with open(log, "a") as f:
        f.write(text + "\n")

def context(c, k):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(c, k)
    return ctx

ctl_ctx = context(cert, key)
# "reuse" is vsftpd's default: the data connection has to resume the session
# of the control connection, so both are served by one context (one set of
# ticket keys), and one that does not resume is refused.
data_ctx = ctl_ctx if mode == "reuse" else context(data_cert, data_key)

def readline(sock):
    buf = b""
    while not buf.endswith(b"\r\n"):
        c = sock.recv(1)
        if not c:
            return None
        buf += c
    return buf[:-2].decode("latin-1")

def session(raw):
    try:
        conn = ctl_ctx.wrap_socket(raw, server_side=True)
    except (ssl.SSLError, OSError):
        raw.close()
        return
    def say(s):
        conn.sendall(s.encode() + b"\r\n")
    say("220 ready")
    pbsz = prot = False
    lst = None
    while True:
        line = readline(conn)
        if line is None:
            break
        note("cmd " + line.split(" ")[0] + (" " + line.split(" ", 1)[1] if " " in line and not line.startswith("PASS") else ""))
        verb = line.split(" ")[0].upper()
        arg = line.split(" ", 1)[1] if " " in line else ""
        if verb == "USER":
            say("331 password")
        elif verb == "PASS":
            say("230 in")
        elif verb == "PBSZ":
            pbsz = True
            say("200 PBSZ=0")
        elif verb == "PROT":
            if mode == "refuse":
                say("534 Request denied for policy reasons.")
            elif not pbsz:
                say("503 PBSZ first")
            else:
                prot = arg == "P"
                say("200 PROT now " + ("Private" if prot else "Clear"))
        elif verb == "TYPE":
            say("200 type")
        elif verb == "PASV":
            say("500 no")
        elif verb == "EPSV":
            lst = socket.socket()
            lst.bind(("127.0.0.1", 0))
            lst.listen(1)
            say("229 Entering Extended Passive Mode (|||%d|)" % lst.getsockname()[1])
        elif verb in ("RETR", "LIST"):
            body = BIG if arg == "big" else HELLO
            if verb == "LIST":
                body = b"-rw-r--r-- 1 u g 16 Jan 1 00:00 hello\r\n"
            lst.settimeout(5)
            try:
                d, _ = lst.accept()
            except OSError:
                say("425 no data connection")
                continue
            say("150 Opening data connection (%d bytes)." % len(body))
            try:
                if prot:
                    d.settimeout(5)
                    d = data_ctx.wrap_socket(d, server_side=True)
                    note("data tls reused=%s" % d.session_reused)
                    if mode == "reuse" and not d.session_reused:
                        d.close()
                        say("522 SSL connection failed; session reuse required")
                        continue
                else:
                    note("data plain")
                d.sendall(body)
                if prot:
                    d = d.unwrap()
                d.close()
                say("226 done")
            except (ssl.SSLError, OSError) as e:
                note("data failed")
                try: d.close()
                except OSError: pass
                say("425 data failed")
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
    raw, _ = srv.accept()
    threading.Thread(target=session, args=(raw,), daemon=True).start()
PY

# start NAME MODE DATA-CERT-NAME: a server on a new port; its log is NAME.log.
port=
start ()
{
  : > "$work/$1.log"
  python3 -I "$work/server.py" "$work/good-cert.pem" "$work/good-key.pem" \
    "$work/$1.log" "$2" "$work/$3-cert.pem" "$work/$3-key.pem" \
    > "$work/$1.port" 2>/dev/null &
  pids="$pids $!"
  i=0
  while [ ! -s "$work/$1.port" ] && [ $i -lt 50 ]; do sleep 0.1; i=$((i + 1)); done
  port=$(cat "$work/$1.port")
  [ -n "$port" ] || skip "the server did not start"
}

for v in ftp_proxy FTP_PROXY all_proxy ALL_PROXY no_proxy NO_PROXY \
         SSL_CERT_FILE SSL_CERT_DIR TWIST_CA_BUNDLE SSLKEYLOGFILE; do
  unset $v
done
ca="--cacert $work/good-cert.pem"
get () { timeout 20 "$TWIST" -s -S "$@" 2>/dev/null; }
status () { timeout 20 "$TWIST" -s -o /dev/null "$@" 2>/dev/null; echo $?; }
before () # NAME A B: the log has A before B
{
  a=$(grep -n "^$2\$" "$work/$1.log" | head -1 | cut -d: -f1)
  b=$(grep -n "^$3\$" "$work/$1.log" | head -1 | cut -d: -f1)
  [ -n "$a" ] && [ -n "$b" ] && [ "$a" -lt "$b" ] && echo ok
}
has () { grep -q "$2" "$work/$1.log" && echo ok; }

# A server that protects the data connection.
start good good good
check "$(is "$(get $ca "ftps://u:p@127.0.0.1:$port/hello")" "hello over ftps")" \
  "ftps fetches a file"
check "$(before good "cmd PBSZ 0" "cmd PROT P")" "PBSZ 0 before PROT P"
check "$(before good "cmd PROT P" "cmd RETR hello")" "PROT P before RETR"
check "$(has good "^data tls")" "the data connection ran TLS"
check "$(is "$(has good "^data plain")" "")" "and was never plain"
n=$(get $ca "ftps://u:p@127.0.0.1:$port/big" | wc -c)
check "$(is "$n" 327680)" "a file of several records, whole (got $n)"
check "$(is "$(get $ca "ftps://u:p@127.0.0.1:$port/" | head -c 10)" "-rw-r--r--")" \
  "a listing over a protected data connection"

# A server that insists the data connection resumes the control session, as
# vsftpd, ProFTPD and FileZilla Server do unless told not to.
start reuse reuse good
check "$(is "$(get $ca "ftps://u:p@127.0.0.1:$port/hello")" "hello over ftps")" \
  "a server that requires session reuse"
check "$(has reuse "^data tls reused=True")" "the data session was the control session"

# A server that will not protect it: the file is not fetched in the clear.
start refuse refuse good
out=$(get $ca "ftps://u:p@127.0.0.1:$port/hello"; echo "status $?")
check "$(is "$out" "status 35")" "PROT P refused is status 35 ($out)"
check "$(is "$(has refuse "^cmd RETR")" "")" "and the file is not asked for"
check "$(is "$(has refuse "^data plain")" "")" "nor sent in the clear"

# The data connection is verified like the control one: a certificate that
# is not trusted, on the data connection only, is refused.
start other good other
out=$(get $ca "ftps://u:p@127.0.0.1:$port/hello"; echo "status $?")
check "$(is "$out" "status 35")" "an untrusted data certificate is status 35 ($out)"

# And -k turns that off, as it does for the control connection.
check "$(is "$(get -k "ftps://u:p@127.0.0.1:$port/hello")" "hello over ftps")" \
  "-k accepts it"

[ $fail = 0 ]
