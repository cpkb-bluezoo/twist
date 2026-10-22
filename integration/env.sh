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

# The environment variables of the ENVIRONMENT section of the manual, against
# servers of python's on loopback ports: the proxy variables and NO_PROXY with
# a server that says whether it was asked as a proxy or directly; and
# SSL_CERT_FILE, SSL_CERT_DIR, TWIST_CA_BUNDLE and SSLKEYLOGFILE with an HTTPS
# server whose certificate only they, or --cacert and --capath, make trusted.
# Skips, with status 77, without python3, openssl or twist.

TWIST=${TWIST:-../src/twist}
skip ()
{
  echo "env: $1; skipping" >&2
  exit 77
}
command -v python3 >/dev/null 2>&1 || skip "no python3"
command -v openssl >/dev/null 2>&1 || skip "no openssl"
[ -x "$TWIST" ] || skip "twist is not built ($TWIST)"

work=$(mktemp -d "${TMPDIR:-/tmp}/twist-env.XXXXXX") || skip "no temp dir"
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

# A certificate for 127.0.0.1 that signs itself.
openssl req -x509 -newkey rsa:2048 -nodes -keyout "$work/key.pem" \
  -out "$work/cert.pem" -days 2 -subj "/CN=127.0.0.1" \
  -addext "subjectAltName=IP:127.0.0.1" -addext "basicConstraints=critical,CA:TRUE" \
  >/dev/null 2>&1 || skip "openssl cannot make a certificate"

cat > "$work/server.py" <<'PY'
import http.server, socketserver, ssl, sys, threading
class H(http.server.BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'
    def log_message(self, *a): pass
    def do_GET(self):
        # A proxy is asked for the whole URL; a server for the path.
        body = b'proxy' if self.path.startswith('http://') else b'direct'
        self.send_response(200)
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)
class S(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True
plain = S(('127.0.0.1', 0), H)
tls = S(('127.0.0.1', 0), H)
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain(sys.argv[1], sys.argv[2])
tls.socket = ctx.wrap_socket(tls.socket, server_side=True)
print(plain.server_address[1], tls.server_address[1], flush=True)
threading.Thread(target=tls.serve_forever, daemon=True).start()
plain.serve_forever()
PY
python3 -I "$work/server.py" "$work/cert.pem" "$work/key.pem" > "$work/ports" 2>/dev/null &
pids="$pids $!"
i=0
while [ ! -s "$work/ports" ] && [ $i -lt 50 ]; do sleep 0.1; i=$((i + 1)); done
read -r port tport < "$work/ports"
[ -n "$port" ] && [ -n "$tport" ] || skip "the server did not start"

# Start from nothing: a person's own settings are none of this test's business.
for v in http_proxy HTTP_PROXY https_proxy HTTPS_PROXY ftp_proxy FTP_PROXY \
         all_proxy ALL_PROXY no_proxy NO_PROXY SSL_CERT_FILE SSL_CERT_DIR \
         TWIST_CA_BUNDLE SSLKEYLOGFILE QLOGDIR COLUMNS; do
  unset $v
done
u="http://127.0.0.1:$port/x"
px="http://127.0.0.1:$port"
get () { timeout 20 "$TWIST" -s -S "$@" 2>/dev/null; }

# The proxy variables.
check "$(is "$(get "$u")" direct)" "no proxy, direct"
check "$(is "$(http_proxy=$px get "$u")" proxy)" "http_proxy"
check "$(is "$(HTTP_PROXY=$px get "$u")" direct)" "HTTP_PROXY is not read"
check "$(is "$(all_proxy=$px get "$u")" proxy)" "all_proxy"
check "$(is "$(ALL_PROXY=$px get "$u")" proxy)" "ALL_PROXY"
check "$(is "$(https_proxy=$px get "$u")" direct)" "https_proxy is not for http"
check "$(is "$(ftp_proxy=$px get "$u")" direct)" "nor ftp_proxy"
check "$(is "$(http_proxy=$px all_proxy=http://127.0.0.1:1 get "$u")" proxy)" "http_proxy before all_proxy"
check "$(is "$(http_proxy= all_proxy=$px get "$u")" direct)" "an empty http_proxy is no proxy"

# -x, and the environment.
check "$(is "$(get -x "$px" "$u")" proxy)" "-x"
check "$(is "$(http_proxy=http://127.0.0.1:1 get -x "$px" "$u")" proxy)" "-x before http_proxy"
check "$(is "$(http_proxy=$px get -x "" "$u")" direct)" "-x \"\" turns the environment's off"

# NO_PROXY, in either case, and --noproxy.
check "$(is "$(http_proxy=$px no_proxy=127.0.0.1 get "$u")" direct)" "no_proxy"
check "$(is "$(http_proxy=$px NO_PROXY=127.0.0.1 get "$u")" direct)" "NO_PROXY"
check "$(is "$(http_proxy=$px NO_PROXY=127.0.0.0/8 get "$u")" direct)" "a network in NO_PROXY"
check "$(is "$(http_proxy=$px NO_PROXY='*' get "$u")" direct)" "* in NO_PROXY"
check "$(is "$(http_proxy=$px NO_PROXY=example.com,10.0.0.0/8 get "$u")" proxy)" "NO_PROXY that is not this host"
check "$(is "$(NO_PROXY=127.0.0.1 get -x "$px" "$u")" direct)" "NO_PROXY with -x"
check "$(is "$(http_proxy=$px get --noproxy 127.0.0.1 "$u")" direct)" "--noproxy"
check "$(is "$(http_proxy=$px get --noproxy '*' "$u")" direct)" "--noproxy *"
check "$(is "$(http_proxy=$px NO_PROXY=127.0.0.1 get --noproxy example.com "$u")" proxy)" "--noproxy instead of NO_PROXY"
check "$(is "$(http_proxy=$px NO_PROXY=127.0.0.1 get --noproxy "" "$u")" proxy)" "--noproxy \"\" turns NO_PROXY off"

# A certificate that is not trusted: the transfer is refused.
tu="https://127.0.0.1:$tport/x"
"$TWIST" -s -o /dev/null "$tu" 2>/dev/null
check "$([ $? -ne 0 ] && echo ok)" "a certificate nobody trusts is refused"
check "$(is "$(get --cacert "$work/cert.pem" "$tu")" direct)" "--cacert"
check "$(is "$(SSL_CERT_FILE=$work/cert.pem get "$tu")" direct)" "SSL_CERT_FILE"
check "$(is "$(TWIST_CA_BUNDLE=$work/cert.pem get "$tu")" direct)" "TWIST_CA_BUNDLE"

mkdir "$work/certs" "$work/hashed"
cp "$work/cert.pem" "$work/certs/ca.pem"
hash=$(openssl x509 -hash -noout -in "$work/cert.pem")
cp "$work/cert.pem" "$work/hashed/$hash.0"
check "$(is "$(SSL_CERT_DIR=$work/certs get "$tu")" direct)" "SSL_CERT_DIR"
check "$(is "$(SSL_CERT_DIR=$work/hashed get "$tu")" direct)" "SSL_CERT_DIR with hashed names"
check "$(is "$(get --capath "$work/certs" "$tu")" direct)" "--capath"
mkdir "$work/empty"
"$TWIST" -s -o /dev/null --capath "$work/empty" "$tu" 2>/dev/null
check "$([ $? -ne 0 ] && echo ok)" "a directory with no authority trusts nobody"

# What is given on the command line is not mixed with the environment's.
"$TWIST" -s -o /dev/null --cacert /nonexistent/ca.pem "$tu" 2>/dev/null
check "$([ $? -ne 0 ] && echo ok)" "--cacert that is not there"
SSL_CERT_FILE=$work/cert.pem "$TWIST" -s -o /dev/null --cacert /nonexistent/ca.pem "$tu" 2>/dev/null
check "$([ $? -ne 0 ] && echo ok)" "--cacert before SSL_CERT_FILE"
# A bundle that is not there is an error.
SSL_CERT_FILE=/nonexistent/ca.pem "$TWIST" -s -o /dev/null "$tu" 2>/dev/null
check "$([ $? -ne 0 ] && echo ok)" "SSL_CERT_FILE that is not there"
# TWIST_CA_BUNDLE is looked at before the others.
check "$([ "$(TWIST_CA_BUNDLE=/nonexistent/ca.pem SSL_CERT_FILE=$work/cert.pem get "$tu")" != direct ] && echo ok)" "TWIST_CA_BUNDLE first"

# SSLKEYLOGFILE gets the secrets of the connections that are made.
SSLKEYLOGFILE=$work/keys get --cacert "$work/cert.pem" "$tu" >/dev/null
check "$(grep -q '^CLIENT_TRAFFIC_SECRET_0 ' "$work/keys" 2>/dev/null && echo ok)" "SSLKEYLOGFILE has the client's traffic secret"
check "$(grep -q '^SERVER_TRAFFIC_SECRET_0 ' "$work/keys" 2>/dev/null && echo ok)" "and the server's"
check "$(grep -q '^CLIENT_HANDSHAKE_TRAFFIC_SECRET ' "$work/keys" 2>/dev/null && echo ok)" "and the handshake's"
rm -f "$work/keys"
get --cacert "$work/cert.pem" "$tu" >/dev/null
check "$([ ! -e "$work/keys" ] && echo ok)" "no file without the variable"

[ $fail -eq 0 ] || exit 1
exit 0
