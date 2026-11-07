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

# A slow consumer of one HTTP/3 stream does not stop the others.  Two
# transfers run together over one connection to a peer of aioquic's
# (h3-peer.py): the body of the first, 600000 bytes, goes to a FIFO that nobody
# reads yet, so its sink is full and its stream is paused; the second is answered
# meanwhile, over the same connection.  When the FIFO is read the first goes on
# and ends with all of its body.  Skips, with status 77, without python3 and
# its aioquic module, mkfifo, openssl or twist.

TWIST=${TWIST:-../src/twist}
here=$(cd "$(dirname "$0")" && pwd)
skip ()
{
  echo "h3-pause: $1; skipping" >&2
  exit 77
}
command -v python3 >/dev/null 2>&1 || skip "no python3"
python3 -c 'import aioquic' >/dev/null 2>&1 || skip "no aioquic"
command -v openssl >/dev/null 2>&1 || skip "no openssl"
command -v mkfifo >/dev/null 2>&1 || skip "no mkfifo"
[ -x "$TWIST" ] || skip "twist is not built ($TWIST)"

work=$(mktemp -d "${TMPDIR:-/tmp}/twist-h3p.XXXXXX") || skip "no temp dir"
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

port=24453
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

mkfifo "$work/fifo"
# The reader has the FIFO open, so that opening it does not wait, and reads
# nothing for a while.
( exec 3< "$work/fifo"; sleep 6; cat <&3 > "$work/big" ) &
pids="$pids $!"
timeout 40 "$TWIST" -s -S -Z --http3-only --max-time 30 \
  --cacert "$work/cert.pem" \
  -o "$work/fifo" "https://127.0.0.1:$port/big" \
  -o "$work/small" "https://127.0.0.1:$port/" 2> "$work/err" &
tw=$!
pids="$pids $tw"

# The second transfer is answered while the first is stuck on its sink.
n=0
while [ "$(cat "$work/small" 2>/dev/null)" != "h3 ok" ] && [ $n -lt 80 ]; do
  sleep 0.1
  n=$((n + 1))
done
check "$(is "$(cat "$work/small" 2>/dev/null)" "h3 ok")" \
  "the second stream is answered while the first is paused ($(cat "$work/err"))"
check "$(kill -0 "$tw" 2>/dev/null && echo ok)" "and the first is not over"

# Then the FIFO is read: the first goes on, and ends.
wait "$tw"
st=$?
check "$(is "$st" 0)" "both end ($st; $(cat "$work/err"))"
check "$(is "$(wc -c < "$work/big" | tr -d ' ')" 600000)" "with all of the body"
check "$(is "$(grep -c '^connection$' "$work/peer.log")" 1)" \
  "over one connection ($(tr '\n' ';' < "$work/peer.log"))"

exit $fail
