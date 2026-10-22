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

# What an HTTP request carries, against a server of python's on a loopback
# port that reports what it was sent: long header values (a bearer token, a
# cookie, a referer, a user agent, a range) arrive whole, and not cut off at
# some fixed size, and a long path arrives whole.  Skips, with status 77,
# without python3 or twist.

TWIST=${TWIST:-../src/twist}
skip ()
{
  echo "http-request: $1; skipping" >&2
  exit 77
}
command -v python3 >/dev/null 2>&1 || skip "no python3"
[ -x "$TWIST" ] || skip "twist is not built ($TWIST)"

work=$(mktemp -d "${TMPDIR:-/tmp}/twist-http-request.XXXXXX") || skip "no temp dir"
srv_pid=
cleanup ()
{
  [ -n "$srv_pid" ] && kill "$srv_pid" 2>/dev/null
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

cat > "$work/server.py" <<'PY'
import gzip, http.server, socketserver, sys, urllib.parse
class H(http.server.BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'
    def log_message(self, *a): pass
    def reply(self, code, body, extra=()):
        self.send_response(code)
        self.send_header('Content-Length', str(len(body)))
        for k, v in extra:
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)
    def do_GET(self):
        p = self.path
        if p == '/echo':
            # The length of each header the request carried.
            lines = ['%s %d' % (k.lower(), len(v)) for k, v in self.headers.items()]
            self.reply(200, ('\n'.join(lines) + '\n').encode())
        elif p == '/hello-gz':
            self.reply(200, gzip.compress(b'hello gzip\n'), [('Content-Encoding', 'gzip')])
        elif p == '/gz':
            # 64 MiB of zeros, in about 64 KB.
            self.reply(200, gzip.compress(bytes(64 * 1024 * 1024), 1), [('Content-Encoding', 'gzip')])
        elif p.startswith('/redir/'):
            loc = urllib.parse.unquote(p[len('/redir/'):])
            self.reply(302, b'', [('Location', loc)])
        else:
            # The target as it arrived, and the Host it was sent to.
            self.reply(200, ('%d %s %s\n' % (len(p), p[:60], self.headers.get('Host'))).encode())
class S(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True
srv = S(('127.0.0.1', 0), H)
print(srv.server_address[1], flush=True)
srv.serve_forever()
PY
python3 -I "$work/server.py" > "$work/port" 2>/dev/null &
srv_pid=$!
i=0
while [ ! -s "$work/port" ] && [ $i -lt 50 ]; do sleep 0.1; i=$((i + 1)); done
port=$(cat "$work/port")
[ -n "$port" ] || skip "the server did not start"

for v in http_proxy HTTP_PROXY https_proxy HTTPS_PROXY all_proxy ALL_PROXY \
         no_proxy NO_PROXY; do
  unset $v
done
base="http://127.0.0.1:$port"
get () { timeout 20 "$TWIST" -s -S "$@" 2>/dev/null; }
# length_of HEADER ARGS...: the length of that header the server was sent.
length_of ()
{
  h=$1; shift
  get "$@" "$base/echo" | awk -v h="$h" '$1 == h { print $2 }'
}

# Credentials and the like are routinely longer than a few hundred bytes (a
# JWT, a session cookie), and are sent whole.
tok=$(head -c 700 /dev/zero | tr '\0' 'a')
check "$(is "$(length_of authorization --oauth2-bearer "$tok")" $((7 + 700)))" \
  "a 700-byte bearer token is sent whole"
check "$(is "$(length_of cookie -b "c=$tok")" $((2 + 700)))" \
  "a 700-byte cookie is sent whole"
check "$(is "$(length_of referer -e "http://r.example/$tok")" $((17 + 700)))" \
  "a long referer is sent whole"
check "$(is "$(length_of user-agent -A "$tok")" 700)" \
  "a long user agent is sent whole"
spec=$(awk 'BEGIN { for (i = 0; i < 150; i++) printf "%s%d-%d", (i ? "," : ""), i * 2, i * 2 }')
check "$(is "$(length_of range -r "$spec")" $((6 + ${#spec})))" \
  "a long range (${#spec} bytes) is sent whole"
check "$(is "$(length_of x-long -H "X-Long: $tok")" 700)" \
  "a long header of the caller's is sent whole"

# A long path arrives whole.
long=$(head -c 1900 /dev/zero | tr '\0' 'p')
check "$(is "$(get "$base/$long" | cut -d' ' -f1)" 1901)" \
  "a path of 1900 bytes arrives whole"

# The URL reported back (-w %{url_effective}) has no credentials in it: a
# script that logs it would log the password.  That goes for the URL given and
# for one a redirect names.
eff=$(timeout 20 "$TWIST" -s -o /dev/null -w '%{url_effective}' \
        "http://alice:s3cret@127.0.0.1:$port/p?q=1" 2>/dev/null)
check "$(is "$eff" "http://127.0.0.1:$port/p?q=1")" \
  "the effective URL has no credentials ($eff)"
eff=$(timeout 20 "$TWIST" -s -L -o /dev/null -w '%{url_effective}' \
        "$base/redir/http%3A%2F%2Fbob%3Apw%40127.0.0.1%3A$port%2Fq" 2>/dev/null)
check "$(is "$eff" "http://127.0.0.1:$port/q")" \
  "nor the one a redirect names ($eff)"

# A redirect goes only where this transfer can go.  file:// has no host and
# was waited on until the timeout, and another scheme was an HTTP request to
# a host and port the server chose.  The exit is 1, as curl's is, at once.
for loc in file%3A%2F%2F%2Fetc%2Fhostname sftp%3A%2F%2F127.0.0.1%3A1%2Fx \
           ftp%3A%2F%2F127.0.0.1%3A1%2Fx; do
  timeout 10 "$TWIST" -s -L -o /dev/null "$base/redir/$loc" 2>/dev/null
  check "$(is $? 1)" "a redirect to $(printf %s "$loc" | sed 's/%3A/:/g; s/%2F/\//g') is refused at once"
done
# A URL that names a host and has none is not a URL (status 3), at once.
timeout 10 "$TWIST" -s -L -o /dev/null "$base/redir/http%3A%2F%2F" 2>/dev/null
check "$(is $? 3)" "a redirect to http:// is a bad URL, at once"

# A redirect to an authority (//host/path) is another host, and the request
# goes to it, with its Host, not to the origin as a path.
check "$(is "$(get -L "$base/redir/%2F%2Flocalhost%3A$port%2Fwhere")" "6 /where localhost:$port")" \
  "a redirect to //host:port/path goes to that host"
# And a relative one, with a query that has a URL in it, stays on the origin.
check "$(is "$(get -L "$base/redir/%2Flanded%3Fnext%3Dhttp%3A%2F%2Fx.example%2F" | cut -d' ' -f2)" "/landed?next=http://x.example/")" \
  "a relative redirect whose query holds a URL"
# One with dots in it is cleaned.
check "$(is "$(get -L "$base/redir/..%2F..%2Fa%2F.%2Fb" | cut -d' ' -f2)" "/a/b")" \
  "dot segments in a redirect are removed"

# A coded body is decoded as it comes, and a small one that expands to a great
# deal is delivered whole, in pieces, not held.
check "$(is "$(get --compressed "$base/hello-gz")" "hello gzip")" \
  "a gzip body is decoded"
n=$(timeout 60 "$TWIST" -s -S --compressed -o /dev/null -w '%{size_download}' \
      "$base/gz" 2>/dev/null)
check "$(is "$n" 67108864)" "a gzip body of 64 MiB, sent in 64 KB, arrives whole (got $n)"

[ $fail = 0 ]
