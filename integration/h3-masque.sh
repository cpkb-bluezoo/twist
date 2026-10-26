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


# HTTP/3 against a peer of aioquic's (h3-peer.py): a plain transfer; a server
# that opens a bidirectional stream, which twist ends the connection for with
# H3_STREAM_CREATION_ERROR (0x103), as RFC 9114 section 6.1 says it must; and
# transfers through a CONNECT-UDP proxy (RFC 9298), of the same peer, that
# carries the QUIC packets in HTTP Datagrams: one that lets the target through,
# and one that refuses it with 403, which is exit status 56.  Skips, with
# status 77, without python3 and its aioquic module, openssl or twist.

TWIST=${TWIST:-../src/twist}
here=$(cd "$(dirname "$0")" && pwd)
skip ()
{
  echo "h3-masque: $1; skipping" >&2
  exit 77
}
command -v python3 >/dev/null 2>&1 || skip "no python3"
python3 -c 'import aioquic' >/dev/null 2>&1 || skip "no aioquic"
command -v openssl >/dev/null 2>&1 || skip "no openssl"
[ -x "$TWIST" ] || skip "twist is not built ($TWIST)"

work=$(mktemp -d "${TMPDIR:-/tmp}/twist-h3.XXXXXX") || skip "no temp dir"
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

for name in origin proxy; do
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
    -keyout "$work/$name-key.pem" -out "$work/$name-cert.pem" -days 2 \
    -subj "/CN=127.0.0.1" -addext "subjectAltName=IP:127.0.0.1" >/dev/null 2>&1 \
    || skip "openssl cannot make a certificate"
done

# peer NAME MODE PORT [REFUSED]: a peer in the background, with a log of its own.
peer ()
{
  : > "$work/$1.log"
  python3 -I "$here/h3-peer.py" "$2" "$work/${2}-cert.pem" "$work/${2}-key.pem" \
    "$3" "$work/$1.log" "$work/$1.ready" $4 >"$work/$1.out" 2>&1 &
  pids="$pids $!"
  n=0
  while [ ! -s "$work/$1.ready" ] && [ $n -lt 100 ]; do sleep 0.1; n=$((n + 1)); done
  [ -s "$work/$1.ready" ] || skip "the $1 peer did not start ($(head -c 200 "$work/$1.out"))"
}
oport=24443
pport=24444
rport=24445
peer origin origin $oport
peer proxy proxy $pport
peer refuser proxy $rport $oport

for v in http_proxy HTTP_PROXY https_proxy HTTPS_PROXY all_proxy ALL_PROXY \
         no_proxy NO_PROXY SSL_CERT_FILE SSL_CERT_DIR TWIST_CA_BUNDLE; do
  unset $v
done
get () { timeout 30 "$TWIST" -s -S --http3-only --max-time 15 "$@" 2> "$work/err"; }
url="https://127.0.0.1:$oport/"
oc="--cacert $work/origin-cert.pem"
pc="--proxy-cacert $work/proxy-cert.pem"

check "$(is "$(get $oc "$url")" "h3 ok")" "HTTP/3 direct ($(cat "$work/err"))"

get $oc "${url}bidi" > "$work/out"
sleep 0.5
check "$(grep -q '^closed 0x103$' "$work/origin.log" && echo ok)" "a bidirectional stream from the server ends the connection with 0x103 ($(tr '\n' ';' < "$work/origin.log"))"

check "$(is "$(get $oc -x "https://127.0.0.1:$pport" $pc "$url")" "h3 ok")" "HTTP/3 through a CONNECT-UDP proxy ($(cat "$work/err"); the proxy saw: $(tr '\n' ';' < "$work/proxy.log"))"
check "$(grep -q "^tunnel 127.0.0.1 $oport\$" "$work/proxy.log" && echo ok)" "the proxy was asked for the target ($(tr '\n' ';' < "$work/proxy.log"))"

get $oc -x "https://127.0.0.1:$rport" $pc "$url" > "$work/out"
st=$?
check "$(is "$st" 56)" "a proxy that refuses the target is 56 ($st)"

exit $fail
