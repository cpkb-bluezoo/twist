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

# Many HTTP/3 requests share one connection.  The peer is aioquic's
# (h3-peer.py).  Skips, with status 77, without python3 and its aioquic module,
# openssl or twist.

TWIST=${TWIST:-../src/twist}
here=$(cd "$(dirname "$0")" && pwd)
skip ()
{
  echo "h3-many: $1; skipping" >&2
  exit 77
}
command -v python3 >/dev/null 2>&1 || skip "no python3"
python3 -c 'import aioquic' >/dev/null 2>&1 || skip "no aioquic"
command -v openssl >/dev/null 2>&1 || skip "no openssl"
[ -x "$TWIST" ] || skip "twist is not built ($TWIST)"

work=$(mktemp -d "${TMPDIR:-/tmp}/twist-h3m.XXXXXX") || skip "no temp dir"
pids=
cleanup ()
{
  for p in $pids; do kill "$p" 2>/dev/null; done
  rm -rf "${work:?}"
}
trap cleanup EXIT INT TERM
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

openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
  -keyout "$work/key.pem" -out "$work/cert.pem" -days 2 \
  -subj "/CN=127.0.0.1" -addext "subjectAltName=IP:127.0.0.1" >/dev/null 2>&1 \
  || skip "openssl cannot make a certificate"

port=24457
: > "$work/peer.log"
python3 -I "$here/h3-peer.py" origin "$work/cert.pem" "$work/key.pem" $port \
  "$work/peer.log" "$work/ready" >"$work/peer.out" 2>&1 &
pids="$pids $!"
n=0
while [ ! -s "$work/ready" ] && [ $n -lt 100 ]; do sleep 0.1; n=$((n + 1)); done
[ -s "$work/ready" ] || skip "the peer did not start ($(head -c 200 "$work/peer.out"))"

for v in http_proxy HTTP_PROXY https_proxy HTTPS_PROXY all_proxy ALL_PROXY \
         no_proxy NO_PROXY SSL_CERT_FILE SSL_CERT_DIR TWIST_CA_BUNDLE; do
  unset $v
done


# Forty requests together, then forty more four at a time, all over the one
# connection: a connection serves as many streams as the peer allows, not a
# few, and a stream that has ended gives its place back.
urls=
outs=
n=0
while [ $n -lt 40 ]; do
  urls="$urls -o $work/o$n https://127.0.0.1:$port/"
  n=$((n + 1))
done
# shellcheck disable=SC2086
timeout 40 "$TWIST" -s -S -Z --parallel-max 100 --http3-only --max-time 30 \
  --cacert "$work/cert.pem" $urls 2> "$work/err"
st=$?
check "$(is "$st" 0)" "forty together end well ($st; $(cat "$work/err"))"
good=0
n=0
while [ $n -lt 40 ]; do
  [ "$(cat "$work/o$n" 2>/dev/null)" = "h3 ok" ] && good=$((good + 1))
  n=$((n + 1))
done
check "$(is "$good" 40)" "each with its body ($good of 40)"
check "$(is "$(grep -c '^connection$' "$work/peer.log")" 1)" \
  "over one connection ($(grep -c '^connection$' "$work/peer.log"))"

: > "$work/peer.log"
rm -f "$work"/o*
# shellcheck disable=SC2086
timeout 40 "$TWIST" -s -S -Z --parallel-max 4 --http3-only --max-time 30 \
  --cacert "$work/cert.pem" $urls 2> "$work/err"
st=$?
check "$(is "$st" 0)" "forty four at a time end well ($st; $(cat "$work/err"))"
check "$(is "$(grep -c '^connection$' "$work/peer.log")" 1)" \
  "over one connection ($(grep -c '^connection$' "$work/peer.log"))"

exit $fail
