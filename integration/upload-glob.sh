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

# Globbing of the file given to -T, and of the directory of --output-dir:
# -T "{a,b}.txt" uploads each file to the URL (to its own name when the URL
# ends in a slash); #1 in the URL, in -o and in --output-dir is the first
# glob, the URL's before the file's; -g turns it off; a file that is not there
# is the transfer of that file that fails, and the others are still done; and
# a pattern that is wrong is a malformed URL.  A server of python's logs each
# PUT.  Skips, with status 77, without python3 or twist.

TWIST=${TWIST:-../src/twist}
skip ()
{
  echo "upload-glob: $1; skipping" >&2
  exit 77
}
command -v python3 >/dev/null 2>&1 || skip "no python3"
[ -x "$TWIST" ] || skip "twist is not built ($TWIST)"
TWIST=$(cd "$(dirname "$TWIST")" && pwd)/$(basename "$TWIST")

work=$(mktemp -d "${TMPDIR:-/tmp}/twist-upload-glob.XXXXXX") || skip "no temp dir"
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

cat > "$work/server.py" <<'PY'
import http.server, sys

class H(http.server.BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'
    def do_PUT(self):
        if self.headers.get('Transfer-Encoding', '').lower() == 'chunked':
            body = b''
            while True:
                size = int(self.rfile.readline().split(b';')[0], 16)
                if size == 0:
                    self.rfile.readline()
                    break
                body += self.rfile.read(size)
                self.rfile.readline()
        else:
            n = int(self.headers.get('Content-Length', 0))
            body = self.rfile.read(n)
        with open(sys.argv[2], 'a') as f:
            f.write('PUT %s %s\n' % (self.path, body.decode().strip()))
        reply = ('stored ' + self.path).encode()
        self.send_response(200)
        self.send_header('Content-Length', str(len(reply)))
        self.end_headers()
        self.wfile.write(reply)
    def log_message(self, *a):
        pass

s = http.server.ThreadingHTTPServer(('127.0.0.1', 0), H)
open(sys.argv[1], 'w').write(str(s.server_address[1]))
s.serve_forever()
PY
python3 "$work/server.py" "$work/port" "$work/log" &
server_pid=$!
n=0
while [ ! -s "$work/port" ] && [ $n -lt 50 ]; do sleep 0.1; n=$((n + 1)); done
[ -s "$work/port" ] || skip "the server did not start"
h=http://127.0.0.1:$(cat "$work/port")

mkdir "$work/in" "$work/out"
for f in a b c; do echo "content-$f" > "$work/in/$f.txt"; done
for i in 1 2 3; do echo "img-$i" > "$work/in/img$i.png"; done

t () { "$TWIST" -s -S "$@"; }
logged () { sort "$work/log" | tr '\n' ' '; }
fresh () { rm -f "$work/log"; touch "$work/log"; }
cd "$work/in" || exit 77

# A set: each file to the URL that ends in a slash, under its own name.
fresh
t -T '{a,b}.txt' "$h/dir/"
check "$([ "$(logged)" = 'PUT /dir/a.txt content-a PUT /dir/b.txt content-b ' ] && echo ok)" \
  "a set of files, each to its own name ($(logged))"

# A range, and #1 in the URL is the file's glob.
fresh
t -T 'img[1-3].png' "$h/up-#1.png"
check "$([ "$(logged)" = 'PUT /up-1.png img-1 PUT /up-2.png img-2 PUT /up-3.png img-3 ' ] && echo ok)" \
  "#1 in the URL is the file's ($(logged))"

# The URL's globs come first, the file's after; the URL is the outer loop.
fresh
t -T '{a,b}.txt' "$h/{x,y}/f-#1-#2"
check "$([ "$(logged)" = 'PUT /x/f-x-a content-a PUT /x/f-x-b content-b PUT /y/f-y-a content-a PUT /y/f-y-b content-b ' ] && echo ok)" \
  "two sets of globs: the URL's, then the file's ($(logged))"

# -o names the answers with the same numbers.
fresh
(cd "$work/out" && t -T "$work/in/{a,b}.txt" -o 'answer-#1' "$h/put")
check "$([ "$(cat "$work/out/answer-a")" = 'stored /put' ] && [ "$(cat "$work/out/answer-b")" = 'stored /put' ] && echo ok)" \
  "#1 in -o is the file's"

# --output-dir has them too.
fresh
rm -rf "$work/out"; mkdir "$work/out"
t --create-dirs --output-dir "$work/out/d-#1" -o reply -T '{a,b}.txt' "$h/put"
check "$([ -f "$work/out/d-a/reply" ] && [ -f "$work/out/d-b/reply" ] && echo ok)" \
  "#1 in --output-dir"
rm -rf "$work/out"; mkdir "$work/out"
t --create-dirs --output-dir "$work/out/u-#1" -o reply "file://$work/in/{a,b}.txt"
check "$([ "$(cat "$work/out/u-a/reply")" = content-a ] && [ "$(cat "$work/out/u-b/reply")" = content-b ] && echo ok)" \
  "#1 in --output-dir for the URL's glob"

# A file of the set that is not there fails, and the others are done.
fresh
t -T '{a,missing,b}.txt' "$h/dir/" 2>/dev/null
rc=$?
check "$([ "$(logged)" = 'PUT /dir/a.txt content-a PUT /dir/b.txt content-b ' ] && [ $rc -eq 0 ] && echo ok)" \
  "all are tried; the last one's status (exit $rc, $(logged))"
fresh
t -T '{a,missing}.txt' "$h/dir/" 2>/dev/null
rc=$?
check "$([ $rc -eq 26 ] && [ "$(logged)" = 'PUT /dir/a.txt content-a ' ] && echo ok)" \
  "a missing file is status 26 (exit $rc)"

# -g: the braces are the name.
fresh
t -g -T '{a,b}.txt' "$h/dir/" 2>/dev/null
rc=$?
check "$([ $rc -eq 26 ] && [ -z "$(logged)" ] && echo ok)" "-g turns it off (exit $rc)"

# A pattern that is wrong.
t -T '{a,b' "$h/dir/" 2>"$work/err"
rc=$?
check "$([ $rc -eq 3 ] && grep -q 'unmatched brace' "$work/err" && echo ok)" \
  "a pattern that is wrong is exit 3 ($rc)"

# Without globs it is as it was; so is a name that is only the stream.
fresh
t -T a.txt "$h/dir/"
check "$([ "$(logged)" = 'PUT /dir/a.txt content-a ' ] && echo ok)" "a plain name"
fresh
cat a.txt | t -T - "$h/stdin"
check "$([ "$(logged)" = 'PUT /stdin content-a ' ] && echo ok)" "standard input"

exit $fail
