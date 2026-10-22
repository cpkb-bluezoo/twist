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

# Explicit TLS (--ssl, --ssl-reqd) for smtp, imap, pop3 and ftp, against
# servers of python's that really upgrade a connection that starts in the
# clear (STARTTLS, STARTTLS, STLS and AUTH TLS).  A server in "normal" mode
# refuses a login in the clear, so a transfer that succeeds proves that the
# upgrade came first, and the log of each server says what it was sent and
# whether that arrived encrypted.  The other modes: the server does not offer
# TLS, offers it and refuses it, and says yes and then sends bytes in the
# clear behind its answer.  Skips, with status 77, without python3, openssl
# or twist.

TWIST=${TWIST:-../src/twist}
skip ()
{
  echo "starttls: $1; skipping" >&2
  exit 77
}
command -v python3 >/dev/null 2>&1 || skip "no python3"
command -v openssl >/dev/null 2>&1 || skip "no openssl"
[ -x "$TWIST" ] || skip "twist is not built ($TWIST)"

work=$(mktemp -d "${TMPDIR:-/tmp}/twist-starttls.XXXXXX") || skip "no temp dir"
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
has () { grep -q -e "$2" "$work/$1.log" && echo ok; }
lacks () { grep -q -e "$2" "$work/$1.log" || echo ok; }

openssl req -x509 -newkey rsa:2048 -nodes -keyout "$work/key.pem" \
  -out "$work/cert.pem" -days 2 -subj "/CN=127.0.0.1" \
  -addext "subjectAltName=IP:127.0.0.1" \
  -addext "basicConstraints=critical,CA:TRUE" >/dev/null 2>&1 \
  || skip "openssl cannot make a certificate"

cat > "$work/server.py" <<'PY'
import base64, socket, ssl, sys, threading

proto, mode, cert, key, log = sys.argv[1:6]
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain(cert, key)
lock = threading.Lock()

def note(c, text):
    with lock:
        with open(log, 'a') as f:
            f.write('%s %s\n' % ('tls' if c.tls else 'clear', text))

class Conn:
    def __init__(self, sock):
        self.sock = sock
        self.buf = b''
        self.tls = False
    def line(self):
        while b'\n' not in self.buf:
            d = self.sock.recv(4096)
            if not d:
                return None
            self.buf += d
        l, self.buf = self.buf.split(b'\n', 1)
        return l.rstrip(b'\r').decode('latin-1')
    def send(self, text):
        self.sock.sendall(text.encode('latin-1'))
    def upgrade(self, said):
        # SAID is the server's yes.  In inject mode it comes with bytes that
        # are not encrypted, in the same write, as an attacker could add.
        if mode == 'inject':
            said += INJECT[proto]
        self.send(said)
        self.sock = ctx.wrap_socket(self.sock, server_side=True)
        self.buf = b''
        self.tls = True

INJECT = {'smtp': '250 AUTH PLAIN\r\n', 'imap': '* CAPABILITY IMAP4rev1 AUTH=PLAIN\r\n',
          'pop3': '+OK\r\nUSER\r\n.\r\n', 'ftp': '331 injected\r\n'}

def offers():
    return mode in ('normal', 'refuse', 'inject')

def login_ok(c):
    # A server of "normal" or "inject" mode takes no login in the clear.  One
    # that has no TLS, or that offers it and then says no, has nothing else.
    return c.tls or mode in ('nooffer', 'refuse')

def smtp(c):
    c.send('220 test ESMTP\r\n')
    data = False
    body = []
    while True:
        l = c.line()
        if l is None:
            return
        if data:
            if l == '.':
                data = False
                note(c, 'BODY ' + '|'.join(body))
                c.send('250 queued\r\n')
            else:
                body.append(l)
            continue
        note(c, l.split(' ')[0] + (' ' + l.split(' ')[1] if l.upper().startswith('AUTH') else ''))
        u = l.upper()
        if u.startswith('EHLO'):
            c.send('250-test\r\n' + ('250-STARTTLS\r\n' if offers() and not c.tls else '')
                   + '250 AUTH PLAIN\r\n')
        elif u == 'STARTTLS':
            if mode == 'refuse' or mode == 'nooffer':
                c.send('454 TLS not available\r\n')
            else:
                c.upgrade('220 go ahead\r\n')
        elif u.startswith('AUTH'):
            if login_ok(c):
                note(c, 'LOGIN ' + base64.b64decode(l.split(' ')[2]).replace(b'\0', b'/').decode())
                c.send('235 ok\r\n')
            else:
                c.send('530 Must issue a STARTTLS command first\r\n')
        elif u.startswith('MAIL') or u.startswith('RCPT'):
            c.send('250 ok\r\n')
        elif u == 'DATA':
            data = True
            c.send('354 go\r\n')
        elif u == 'QUIT':
            c.send('221 bye\r\n')
            return
        else:
            c.send('500 what\r\n')

def imap(c):
    c.send('* OK ready\r\n')
    while True:
        l = c.line()
        if l is None:
            return
        tag, _, rest = l.partition(' ')
        cmd = rest.split(' ')[0].upper()
        note(c, cmd)
        if cmd == 'CAPABILITY':
            c.send('* CAPABILITY IMAP4rev1 ' + ('STARTTLS ' if offers() and not c.tls else '')
                   + 'AUTH=PLAIN\r\n%s OK done\r\n' % tag)
        elif cmd == 'STARTTLS':
            if mode in ('refuse', 'nooffer'):
                c.send('%s NO not available\r\n' % tag)
            else:
                c.upgrade('%s OK Begin TLS negotiation now\r\n' % tag)
        elif cmd == 'AUTHENTICATE':
            if login_ok(c):
                note(c, 'LOGIN ' + base64.b64decode(rest.split(' ')[2]).replace(b'\0', b'/').decode())
                c.send('%s OK logged in\r\n' % tag)
            else:
                c.send('%s NO [PRIVACYREQUIRED] TLS first\r\n' % tag)
        elif cmd == 'SELECT':
            c.send('* 1 EXISTS\r\n%s OK [READ-WRITE] selected\r\n' % tag)
        elif cmd == 'UID':
            c.send('* 1 FETCH (BODY[] {5}\r\nhello)\r\n%s OK fetched\r\n' % tag)
        elif cmd == 'LOGOUT':
            c.send('* BYE\r\n%s OK bye\r\n' % tag)
            return
        else:
            c.send('%s BAD what\r\n' % tag)

def pop3(c):
    c.send('+OK ready\r\n')
    user = None
    while True:
        l = c.line()
        if l is None:
            return
        cmd = l.split(' ')[0].upper()
        note(c, cmd)
        if cmd == 'CAPA':
            c.send('+OK\r\nUSER\r\n' + ('STLS\r\n' if offers() and not c.tls else '') + '.\r\n')
        elif cmd == 'STLS':
            if mode in ('refuse', 'nooffer'):
                c.send('-ERR not now\r\n')
            else:
                c.upgrade('+OK Begin TLS negotiation\r\n')
        elif cmd == 'USER':
            user = l[5:]
            c.send('+OK\r\n' if login_ok(c) else '-ERR TLS first\r\n')
        elif cmd == 'PASS':
            note(c, 'LOGIN %s/%s' % (user, l[5:]))
            c.send('+OK\r\n')
        elif cmd == 'RETR':
            c.send('+OK 5\r\nhello\r\n.\r\n')
        elif cmd == 'QUIT':
            c.send('+OK bye\r\n')
            return
        else:
            c.send('-ERR what\r\n')

def ftp(c):
    c.send('220 ready\r\n')
    user = None
    listener = None
    prot_p = False
    while True:
        l = c.line()
        if l is None:
            return
        cmd = l.split(' ')[0].upper()
        note(c, cmd + (' ' + l.split(' ')[1] if cmd in ('AUTH', 'PROT') else ''))
        if cmd == 'AUTH':
            if mode in ('refuse', 'nooffer'):
                c.send('534 Unavailable\r\n')
            else:
                c.upgrade('234 Proceed with negotiation.\r\n')
        elif cmd == 'USER':
            user = l[5:]
            c.send('331 password please\r\n' if login_ok(c) else '530 Must use AUTH TLS first\r\n')
        elif cmd == 'PASS':
            note(c, 'LOGIN %s/%s' % (user, l[5:]))
            c.send('230 ok\r\n')
        elif cmd == 'PBSZ':
            c.send('200 PBSZ=0\r\n')
        elif cmd == 'PROT':
            prot_p = l.upper().endswith(' P')
            c.send('200 ok\r\n')
        elif cmd == 'TYPE':
            c.send('200 ok\r\n')
        elif cmd == 'EPSV':
            listener = socket.socket()
            listener.bind(('127.0.0.1', 0))
            listener.listen(1)
            c.send('229 Entering Extended Passive Mode (|||%d|)\r\n' % listener.getsockname()[1])
        elif cmd == 'RETR':
            c.send('150 Opening data connection (5 bytes)\r\n')
            listener.settimeout(10)
            d, _ = listener.accept()
            if prot_p:
                d = ctx.wrap_socket(d, server_side=True)
                note(c, 'DATA protected')
            else:
                note(c, 'DATA clear')
            d.sendall(b'hello')
            try:
                d.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            d.close()
            c.send('226 done\r\n')
        elif cmd == 'QUIT':
            c.send('221 bye\r\n')
            return
        else:
            c.send('500 what\r\n')

handler = {'smtp': smtp, 'imap': imap, 'pop3': pop3, 'ftp': ftp}[proto]

def session(raw):
    c = Conn(raw)
    try:
        handler(c)
    except (ssl.SSLError, OSError, ValueError, IndexError):
        pass
    finally:
        try:
            c.sock.close()
        except OSError:
            pass

srv = socket.socket()
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(('127.0.0.1', 0))
srv.listen(8)
print(srv.getsockname()[1], flush=True)
while True:
    raw, _ = srv.accept()
    threading.Thread(target=session, args=(raw,), daemon=True).start()
PY

port=
n=0
# start PROTO MODE: a server on a new port, in $port; its log is $work/$log.log
start ()
{
  n=$((n + 1))
  log=$1-$2-$n
  : > "$work/$log.log"
  python3 -I "$work/server.py" "$1" "$2" "$work/cert.pem" "$work/key.pem" \
    "$work/$log.log" > "$work/$log.port" 2>/dev/null &
  pids="$pids $!"
  i=0
  while [ ! -s "$work/$log.port" ] && [ $i -lt 50 ]; do sleep 0.1; i=$((i + 1)); done
  port=$(cat "$work/$log.port")
  [ -n "$port" ] || skip "the server did not start"
}

for v in ftp_proxy FTP_PROXY all_proxy ALL_PROXY no_proxy NO_PROXY \
         SSL_CERT_FILE SSL_CERT_DIR TWIST_CA_BUNDLE SSLKEYLOGFILE \
         smtp_proxy SMTP_PROXY imap_proxy IMAP_PROXY pop3_proxy POP3_PROXY; do
  unset $v
done
ca="--cacert $work/cert.pem"

# url PROTO PORT: the URL of the one thing each does.
url ()
{
  case $1 in
    smtp) echo "smtp://alice:secret@127.0.0.1:$2/" ;;
    imap) echo "imap://alice:secret@127.0.0.1:$2/INBOX;UID=1" ;;
    pop3) echo "pop3://alice:secret@127.0.0.1:$2/1" ;;
    ftp) echo "ftp://alice:secret@127.0.0.1:$2/f.txt" ;;
  esac
}
# run PROTO OPTIONS...: the output in $out, the exit status in $rc, and what
# the transfer was for (the body, or the message sent) checked by the caller.
run ()
{
  p=$1; shift
  if [ "$p" = smtp ]; then
    out=$(timeout 30 "$TWIST" -s -S "$@" --mail-from a@b.example \
            --mail-rcpt c@d.example -d 'hello-mail' "$(url smtp "$port")" 2>&1)
  else
    out=$(timeout 30 "$TWIST" -s -S "$@" "$(url "$p" "$port")" 2>&1)
  fi
  rc=$?
}
# worked PROTO: what a transfer that went through leaves behind.
worked ()
{
  if [ "$1" = smtp ]; then
    has "$log" 'BODY .*hello-mail'
  else
    printf %s "$out" | tr -d '\r\n' | grep -q '^hello$' && echo ok
  fi
}

for p in smtp imap pop3 ftp; do
  # Required, and offered: the login is made after the upgrade, and only then.
  start $p normal
  run $p --ssl-reqd $ca
  check "$(is $rc 0)" "$p: --ssl-reqd against a server that offers TLS works ($rc: $out)"
  check "$(worked $p)" "$p: and the transfer is whole"
  check "$(has $log 'tls LOGIN .*alice/secret')" "$p: the login came encrypted"
  check "$(lacks $log 'clear LOGIN')" "$p: and none in the clear"
  [ $p = ftp ] && check "$(has $log 'DATA protected')" "ftp: and the data connection is protected"

  # Wanted, offered: the same.
  start $p normal
  run $p --ssl $ca
  check "$(is $rc 0)" "$p: --ssl against a server that offers TLS works ($rc: $out)"
  check "$(has $log 'tls LOGIN .*alice/secret')" "$p: and upgrades"

  # Not asked for: nothing is upgraded, though it is offered, and this server
  # takes no login in the clear.
  start $p normal
  run $p $ca
  check "$(is $rc 67)" "$p: without --ssl the login in the clear is refused, status 67 ($rc)"
  check "$(lacks $log 'STARTTLS\|STLS\|AUTH TLS')" "$p: and no upgrade was asked for"

  # Wanted, not offered: on in the clear.
  start $p nooffer
  run $p --ssl $ca
  check "$(is $rc 0)" "$p: --ssl against a server without TLS goes on ($rc: $out)"
  check "$(has $log 'clear LOGIN .*alice/secret')" "$p: in the clear"

  # Required, not offered: status 64, and no login was sent.
  start $p nooffer
  run $p --ssl-reqd $ca
  check "$(is $rc 64)" "$p: --ssl-reqd against a server without TLS is status 64 ($rc: $out)"
  check "$(lacks $log 'LOGIN')" "$p: and no login was sent"

  # Offered and then refused.
  start $p refuse
  run $p --ssl-reqd $ca
  check "$(is $rc 64)" "$p: --ssl-reqd and a refusal is status 64 ($rc: $out)"
  check "$(lacks $log 'LOGIN')" "$p: and no login was sent"
  start $p refuse
  run $p --ssl $ca
  check "$(is $rc 0)" "$p: --ssl and a refusal goes on ($rc: $out)"

  # The certificate is checked after the upgrade, as always.
  start $p normal
  run $p --ssl-reqd
  check "$(is $rc 35)" "$p: an untrusted certificate is status 35 ($rc: $out)"
  check "$(lacks $log 'LOGIN')" "$p: and no login was sent"
  start $p normal
  run $p --ssl-reqd -k
  check "$(is $rc 0)" "$p: -k takes it ($rc: $out)"

  # Bytes in the clear behind the server's yes are an attack.
  start $p inject
  run $p --ssl-reqd $ca
  check "$(is $rc 8)" "$p: bytes in the clear behind the yes end the transfer, status 8 ($rc: $out)"
  check "$(lacks $log 'LOGIN')" "$p: and no login was sent"
done

[ $fail -eq 0 ]
