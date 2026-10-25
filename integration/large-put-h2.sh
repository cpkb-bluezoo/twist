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

# An upload over HTTP/2 is sent a chunk at a time, as the server's windows and
# the connection allow, and is not held whole.  nghttpd, with small windows,
# sends the upload back (--echo-upload), so what arrived is what is compared:
# a file, a pipe, and a body from -d, each of them larger than a window; and
# 100 MiB, with twist's memory watched while it goes.  Skips, with status 77,
# without nghttpd or twist.

TWIST=${TWIST:-../src/twist}
skip ()
{
  echo "large-put-h2: $1; skipping" >&2
  exit 77
}
command -v nghttpd >/dev/null 2>&1 || skip "no nghttpd"
[ -x "$TWIST" ] || skip "twist is not built ($TWIST)"

work=$(mktemp -d "${TMPDIR:-/tmp}/twist-large-put-h2.XXXXXX") || skip "no temp dir"
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

port=$((20000 + $$ % 20000))
mkdir "$work/docs"
nghttpd --no-tls --echo-upload -w 14 -W 14 -d "$work/docs" "$port" \
  >"$work/server.log" 2>&1 &
server_pid=$!
n=0
until "$TWIST" -s -o /dev/null "http://127.0.0.1:$port/" --http2-prior-knowledge \
      2>/dev/null || [ $n -ge 30 ]; do
  sleep 0.2
  n=$((n + 1))
done
kill -0 "$server_pid" 2>/dev/null || skip "nghttpd did not start"
url=http://127.0.0.1:$port/

head -c 1000000 /dev/urandom > "$work/in"

"$TWIST" -s --http2-prior-knowledge -T "$work/in" -o "$work/out1" "$url" 2>/dev/null
check "$([ $? -eq 0 ] && cmp -s "$work/in" "$work/out1" && echo ok)" \
  "a file is sent whole through small windows"

cat "$work/in" | "$TWIST" -s --http2-prior-knowledge -T - -o "$work/out2" "$url" 2>/dev/null
check "$([ $? -eq 0 ] && cmp -s "$work/in" "$work/out2" && echo ok)" \
  "a pipe is sent whole"

"$TWIST" -s --http2-prior-knowledge --data-binary @"$work/in" -o "$work/out3" "$url" 2>/dev/null
check "$([ $? -eq 0 ] && cmp -s "$work/in" "$work/out3" && echo ok)" \
  "a body from -d is sent whole"

# An encoded body is a buffer of twist's own, which has to last until the
# last of it has gone through the windows: it is larger than the first one.
"$TWIST" -s --http2-prior-knowledge --content-encoding gzip \
  --data-binary @"$work/in" -o "$work/out4" "$url" 2>/dev/null
check "$([ $? -eq 0 ] && gunzip -c "$work/out4" 2>/dev/null | cmp -s "$work/in" - && echo ok)" \
  "an encoded body is sent whole through small windows"

# 100 MiB: how much of it twist holds while it goes.
head -c 104857600 /dev/zero > "$work/big"
"$TWIST" -s --http2-prior-knowledge -T "$work/big" -o /dev/null "$url" 2>/dev/null &
tp=$!
max=0
while kill -0 "$tp" 2>/dev/null; do
  r=$(ps -o rss= -p "$tp" 2>/dev/null | tr -d ' ')
  [ -n "$r" ] && [ "$r" -gt "$max" ] && max=$r
  sleep 0.1
done
wait "$tp"
check "$([ $? -eq 0 ] && echo ok)" "100 MiB are sent"
check "$([ "$max" -lt 60000 ] && echo ok)" "twist held ${max} KiB, not the 100 MiB"

exit $fail
