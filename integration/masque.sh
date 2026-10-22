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

# HTTP/3, direct and through a CONNECT-UDP proxy (RFC 9298), against quic-go's
# HTTP/3 server and masque-go's proxy (masque-peer.go).  The peer is built
# here with Go, which fetches the two modules the first time (the network, then
# its module cache).  Skips, with status 77, without go, openssl or twist, or if
# the peer does not build.

TWIST=${TWIST:-../src/twist}
here=$(cd "$(dirname "$0")" && pwd)
skip ()
{
  echo "masque: $1; skipping" >&2
  exit 77
}
command -v go >/dev/null 2>&1 || skip "no go"
command -v openssl >/dev/null 2>&1 || skip "no openssl"
[ -x "$TWIST" ] || skip "twist is not built ($TWIST)"

work=$(mktemp -d "${TMPDIR:-/tmp}/twist-masque.XXXXXX") || skip "no temp dir"
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

mkdir "$work/peer"
cp "$here/masque-peer.go" "$work/peer/main.go"
( cd "$work/peer" \
  && printf 'module masquepeer\ngo 1.22\n' > go.mod \
  && GOFLAGS=-mod=mod go get github.com/quic-go/masque-go@v0.6.0 \
       github.com/yosida95/uritemplate/v3 >/dev/null 2>&1 \
  && go build -o "$work/masque-peer" . >/dev/null 2>&1 ) \
  || skip "the peer does not build"

mkcert ()
{
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
    -keyout "$work/$1-key.pem" -out "$work/$1-cert.pem" -days 2 \
    -subj "/CN=127.0.0.1" -addext "subjectAltName=IP:127.0.0.1" \
    >/dev/null 2>&1 || skip "openssl cannot make a certificate"
}
mkcert origin
mkcert proxy

# Random UDP ports in 30000-60000.
rnd () { echo $((30000 + $(od -An -N2 -tu2 /dev/urandom | tr -d ' ') % 30000)); }
start ()
{
  "$work/masque-peer" "$@" > "$work/peer.log" 2>&1 &
  pids="$pids $!"
  last_pid=$!
  i=0
  while ! grep -q ready "$work/peer.log" 2>/dev/null && [ $i -lt 50 ]; do
    sleep 0.1; i=$((i + 1))
  done
  sleep 0.2
}

oport=$(rnd)
start origin -b "127.0.0.1:$oport" -c "$work/origin-cert.pem" -k "$work/origin-key.pem"
for v in http_proxy HTTP_PROXY https_proxy HTTPS_PROXY all_proxy ALL_PROXY \
         no_proxy NO_PROXY SSL_CERT_FILE SSL_CERT_DIR TWIST_CA_BUNDLE; do
  unset $v
done
get () { timeout 30 "$TWIST" -s -S "$@" 2>/dev/null; }
status () { timeout 30 "$TWIST" -s -o /dev/null "$@" 2>/dev/null; echo $?; }
ou="https://127.0.0.1:$oport/x"
oc="--cacert $work/origin-cert.pem"

# HTTP/3 with no proxy: the client, and the origin's behaviour.
check "$(is "$(get --http3-only $oc "$ou")" h3-direct)" "HTTP/3 direct"
n=$(timeout 60 "$TWIST" -s -S --http3-only $oc "https://127.0.0.1:$oport/big" 2>/dev/null | wc -c)
check "$(is "$n" 3000000)" "HTTP/3 direct, 3 MB (got $n)"

# Through the proxy: the default template, then one given.
pport=$(rnd)
start proxy -b "127.0.0.1:$pport" -c "$work/proxy-cert.pem" -k "$work/proxy-key.pem" \
  -t "https://127.0.0.1:$pport/.well-known/masque/udp/{target_host}/{target_port}/"
px="https://127.0.0.1:$pport"
pc="--proxy-cacert $work/proxy-cert.pem"
check "$(is "$(get --http3-only $oc $pc -x "$px" "$ou")" h3-direct)" \
  "HTTP/3 through CONNECT-UDP, default template"
n=$(timeout 60 "$TWIST" -s -S --http3-only $oc $pc -x "$px" \
      "https://127.0.0.1:$oport/big" 2>/dev/null | wc -c)
check "$(is "$n" 3000000)" "HTTP/3 through CONNECT-UDP, 3 MB (got $n)"
check "$(is "$(timeout 30 "$TWIST" -s -o /dev/null -w '%{http_code}' --http3-only $oc $pc \
               -x "$px" "$ou" 2>/dev/null)" 200)" \
  "status through CONNECT-UDP is 200"

# The proxy looks the target up, not twist: a name that only a lookup at the
# proxy could fail on is the proxy's failure (56), not twist's (6).
check "$(is "$(status --http3-only $oc $pc -x "$px" "https://no-such-host.invalid:$oport/x")" 56)" \
  "the target's name is not looked up here"

# A template alone names the proxy.
tmpl="https://127.0.0.1:$pport/.well-known/masque/udp/{target_host}/{target_port}/"
check "$(is "$(get --http3-only $oc $pc --proxy-template-udp "$tmpl" "$ou")" h3-direct)" \
  "--proxy-template-udp with no -x"

# A proxy that does not carry UDP, or a bad template.
check "$(is "$(status --http3-only $oc -x http://127.0.0.1:1 "$ou")" 1)" \
  "an http proxy cannot carry HTTP/3, and it is not bypassed"
bad=$(timeout 10 "$TWIST" -s -S --proxy-template-udp 'https://x/{nope}' "$ou" 2>&1 >/dev/null; echo $?)
case $bad in *"
2") ;; *) check bad "invalid template exits 2 ($bad)";; esac

# The proxy refuses: a target port it will not reach, and no credentials.
rport=$(rnd)
start proxy -b "127.0.0.1:$rport" -c "$work/proxy-cert.pem" -k "$work/proxy-key.pem" \
  -t "https://127.0.0.1:$rport/.well-known/masque/udp/{target_host}/{target_port}/" \
  -r "$oport"
check "$(is "$(status --http3-only $oc --proxy-cacert "$work/proxy-cert.pem" \
               -x "https://127.0.0.1:$rport" "$ou")" 56)" \
  "a refused target is exit 56"
aport=$(rnd)
start proxy -b "127.0.0.1:$aport" -c "$work/proxy-cert.pem" -k "$work/proxy-key.pem" \
  -t "https://127.0.0.1:$aport/.well-known/masque/udp/{target_host}/{target_port}/" \
  -u bob:secret
ax="https://127.0.0.1:$aport"
check "$(is "$(status --http3-only $oc $pc -x "$ax" "$ou")" 56)" \
  "no credentials is exit 56"
check "$(is "$(get --http3-only $oc $pc -x "https://bob:secret@127.0.0.1:$aport" "$ou")" h3-direct)" \
  "credentials from the proxy URL"
check "$(is "$(get --http3-only $oc $pc -x "$ax" -U bob:secret "$ou")" h3-direct)" \
  "credentials from -U"

[ $fail -eq 0 ] || exit 1
exit 0
