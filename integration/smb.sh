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

# smb:// against Samba, as it is run in the lab: a server of the user's own on a
# loopback port, set up as twist requires one to be (SMB 3.1.1, encryption and
# signing required, NTLMv2 only, no guests), and two more with one thing
# changed, which twist has to refuse.  Downloads (whole, a range, a resume),
# uploads (a new file, a replaced one, an append, the directories above it),
# listings, and the ways it can go wrong: a wrong password, a guest, a file that
# is not there, a file or a share that may not be written.  Then which
# algorithms the session negotiated, as Samba's smbstatus says.  A Samba that
# is not root can only log in the user who runs it, so that is the user name.
# Skips, with status 77, if there is no smbd, no pdbedit or no twist.

TWIST=${TWIST:-../src/twist}
SMBD=${SMBD:-smbd}

skip ()
{
  echo "smb: $1; skipping" >&2
  exit 77
}
command -v "$SMBD" >/dev/null 2>&1 || skip "no smbd"
SETSID=$(command -v setsid 2>/dev/null)
command -v pdbedit >/dev/null 2>&1 || skip "no pdbedit"
[ -x "$TWIST" ] || skip "twist is not built ($TWIST)"

work=$(mktemp -d "${TMPDIR:-/tmp}/twist-smb.XXXXXX") || skip "no temp dir"
pids=
cleanup ()
{
  # smbd tells its whole process group when it stops, which includes this
  # script if it is not in a group of its own (setsid, below); once is enough.
  trap '' EXIT INT TERM
  for p in $pids; do kill "$p" 2>/dev/null; done
  wait 2>/dev/null
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
    [ -s "$work/err" ] && sed 's/^/  twist: /' "$work/err" >&2
    fail=1
  fi
}
is () { [ "$1" = "$2" ] && echo ok; }
same () { cmp -s "$1" "$2" && echo ok; }

user=$(id -un)
pass=lab-pass-$$
base=$((20000 + $$ % 20000))
mkdir -p "$work/share/dir" "$work/ro" "$work/out"
printf 'hello over smb\n' > "$work/share/hello.txt"
yes 0123456789abcdef | head -c 300000 > "$work/share/big.bin"
printf 'alpha\n' > "$work/share/dir/a.txt"
printf 'beta\n' > "$work/share/dir/b.txt"
printf 'secret\n' > "$work/share/secret.txt"
chmod 000 "$work/share/secret.txt"
printf 'read only\n' > "$work/ro/note.txt"

# A configuration for a server on PORT; the rest are more lines of it.
conf ()
{
  port=$1
  shift
  mkdir -p "$work/$port/pid" "$work/$port/lock" "$work/$port/state" \
    "$work/$port/cache" "$work/$port/ncalrpc" "$work/$port/priv"
  cat > "$work/smb-$port.conf" <<CONF
[global]
  workgroup = LAB
  netbios name = LABSMB
  server role = standalone server
  security = user
  map to guest = never
  restrict anonymous = 2
  server min protocol = SMB3_11
  server smb encrypt = required
  server signing = mandatory
  ntlm auth = ntlmv2-only
  smb ports = $port
  interfaces = 127.0.0.1
  bind interfaces only = yes
  pid directory = $work/$port/pid
  lock directory = $work/$port/lock
  state directory = $work/$port/state
  cache directory = $work/$port/cache
  ncalrpc dir = $work/$port/ncalrpc
  private dir = $work/$port/priv
  passdb backend = tdbsam:$work/$port/priv/passdb.tdb
  log file = $work/log-$port
  log level = 1
  load printers = no
  printing = bsd
  printcap name = /dev/null
  disable spoolss = yes
  usershare allow guests = no
$(for line in "$@"; do printf '  %s\n' "$line"; done)

[share]
  path = $work/share
  read only = no
  guest ok = no

[ro]
  path = $work/ro
  read only = yes
  guest ok = no
CONF
  printf '%s\n%s\n' "$pass" "$pass" \
    | pdbedit -s "$work/smb-$port.conf" -a -u "$user" -t >/dev/null 2>&1 \
    || skip "cannot make a Samba user (pdbedit)"
}

# Start a server and wait for it to answer.
serve ()
{
  port=$1
  $SETSID "$SMBD" -F -s "$work/smb-$port.conf" --no-process-group >> "$work/smbd-$port.out" 2>&1 &
  pids="$pids $!"
  i=0
  while [ $i -lt 100 ]; do
    "$TWIST" -sS --connect-timeout 2 -u "$user:$pass" "smb://127.0.0.1:$port/share/hello.txt" -o /dev/null 2>/dev/null
    case $? in 0|8|67|78) return 0 ;; esac
    i=$((i + 1))
    sleep 0.2
  done
  echo "smb: smbd on $port did not come up" >&2
  cat "$work/smbd-$port.out" >&2
  tail -20 "$work/log-$port" >&2
  skip "smbd did not start"
}

conf $base
serve $base
url="smb://127.0.0.1:$base"
auth="$user:$pass"

t ()
{
  "$TWIST" -sS --connect-timeout 5 "$@" 2>"$work/err"
}

# ---- Downloads ----
t -u "$auth" "$url/share/hello.txt" -o "$work/out/hello.txt"
check "$(is $? 0)" "a download exits 0"
check "$(same "$work/out/hello.txt" "$work/share/hello.txt")" "and is the file"
t -u "$auth" "$url/share/big.bin" -o "$work/out/big.bin"
check "$(is $? 0)" "a big download exits 0"
check "$(same "$work/out/big.bin" "$work/share/big.bin")" "and is the file"
t -u "$auth" -r 1000-1999 "$url/share/big.bin" -o "$work/out/range.bin"
check "$(is $? 0)" "a range exits 0"
dd if="$work/share/big.bin" of="$work/out/range.want" bs=1 skip=1000 count=1000 2>/dev/null
check "$(same "$work/out/range.bin" "$work/out/range.want")" "and is the bytes asked for"
t -u "$auth" -r -500 "$url/share/big.bin" -o "$work/out/tail.bin"
tail -c 500 "$work/share/big.bin" > "$work/out/tail.want"
check "$(same "$work/out/tail.bin" "$work/out/tail.want")" "a range from the end is the last bytes"
head -c 100000 "$work/share/big.bin" > "$work/out/part.bin"
t -u "$auth" -C 100000 "$url/share/big.bin" -o "$work/out/part.bin"
check "$(is $? 0)" "a resume exits 0"
check "$(same "$work/out/part.bin" "$work/share/big.bin")" "and completes the file"
head -c 150000 "$work/share/big.bin" > "$work/out/part2.bin"
t -u "$auth" -C - "$url/share/big.bin" -o "$work/out/part2.bin"
check "$(same "$work/out/part2.bin" "$work/share/big.bin")" "-C - continues from the size of the file"

# ---- Uploads ----
t -u "$auth" -T "$work/share/big.bin" "$url/share/up.bin"
check "$(is $? 0)" "an upload exits 0"
check "$(same "$work/share/up.bin" "$work/share/big.bin")" "and the file is there"
printf 'short\n' > "$work/out/short.txt"
t -u "$auth" -T "$work/out/short.txt" "$url/share/up.bin"
check "$(same "$work/share/up.bin" "$work/out/short.txt")" "an upload replaces a file that is there"
t -u "$auth" -a -T "$work/out/short.txt" "$url/share/up.bin"
cat "$work/out/short.txt" "$work/out/short.txt" > "$work/out/twice.txt"
check "$(same "$work/share/up.bin" "$work/out/twice.txt")" "-a adds to it"
t -u "$auth" --ftp-create-dirs -T "$work/out/short.txt" "$url/share/new/sub/f.txt"
check "$(is $? 0)" "an upload with --ftp-create-dirs exits 0"
check "$(same "$work/share/new/sub/f.txt" "$work/out/short.txt")" "and made the directories"
t -u "$auth" -T "$work/out/short.txt" "$url/share/none/f.txt"
check "$(is $? 25)" "without it a missing directory is an upload failure (25)"
printf 'from stdin\n' | t -u "$auth" -T - "$url/share/stdin.txt"
check "$(is "$(cat "$work/share/stdin.txt" 2>/dev/null)" 'from stdin')" "-T - uploads standard input"

# ---- Listings ----
t -u "$auth" "$url/share/dir/" > "$work/out/list.txt"
check "$(is $? 0)" "a listing exits 0"
grep -q 'a\.txt' "$work/out/list.txt" && grep -q 'b\.txt' "$work/out/list.txt" \
  && grep -q -- '-rw' "$work/out/list.txt"
check "$(is $? 0)" "and has the entries, in the long form"
t -u "$auth" -l "$url/share/dir" > "$work/out/names.txt"
check "$(is "$(grep -c '^[ab]\.txt$' "$work/out/names.txt")" 2)" "-l has the names alone"

# ---- Failures ----
t -u "$user:not-the-password" "$url/share/hello.txt" -o /dev/null
check "$(is $? 67)" "a wrong password is exit 67"
t -u "nobody-here:x" "$url/share/hello.txt" -o /dev/null
check "$(is $? 67)" "a user that is not there is exit 67"
t -u "guest:" "$url/share/hello.txt" -o /dev/null
check "$(is $? 67)" "a guest is refused (67)"
t "$url/share/hello.txt" -o /dev/null
check "$(is $? 67)" "no user at all is refused (67)"
t -u "$auth" "$url/share/nope.txt" -o /dev/null
check "$(is $? 78)" "a file that is not there is exit 78"
t -u "$auth" "$url/share/dir/nope/x.txt" -o /dev/null
check "$(is $? 78)" "so is one in a directory that is not there"
t -u "$auth" "$url/nope/hello.txt" -o /dev/null
check "$(is $? 78)" "and a share that is not there"
if [ "$(id -u)" != 0 ]; then
  t -u "$auth" "$url/share/secret.txt" -o /dev/null
  check "$(is $? 9)" "a file that may not be read is exit 9"
fi
t -u "$auth" -T "$work/out/short.txt" "$url/ro/new.txt"
check "$(is $? 9)" "a share that may not be written is exit 9"
t -u "$auth" "$url/ro/note.txt" -o "$work/out/note.txt"
check "$(is "$(cat "$work/out/note.txt")" 'read only')" "though it can be read"

# ---- What was negotiated ----
# Samba logs the session it made at level 10, with the algorithms as numbers
# (smbstatus would say, but only to root): the signing algorithm is 1 for
# AES-CMAC and 2 for AES-GMAC, the cipher 1 and 2 for AES-128-CCM and -GCM and
# 3 and 4 for AES-256's.  A server of its own, so as to keep the log of the rest
# short.  Samba prefers AES-128-GCM to the AES-256-GCM that twist asks for
# first, and signs with AES-GMAC.
algos ()
{
  # The last non-zero value of NAME in the log of the server on PORT.
  grep "$2" "$work/log-$1" | grep -v '0x0000' | tail -1 | sed 's/.*: *0x[0-9a-f]* *(\([0-9]*\)).*/\1/'
}
obs=$((base + 4))
conf $obs "log level = 10"
serve $obs
t -u "$auth" "smb://127.0.0.1:$obs/share/hello.txt" -o /dev/null
check "$(is "$(algos $obs encryption_cipher)" 2)" "the session is encrypted with AES-128-GCM, which Samba prefers"
check "$(is "$(algos $obs signing_algo)" 2)" "and signed with AES-GMAC"

# ---- Servers that twist has to refuse ----
cmac=$((base + 1))
conf $cmac "server smb3 signing algorithms = AES-128-CMAC" "log level = 10"
serve $cmac
t -u "$auth" "smb://127.0.0.1:$cmac/share/hello.txt" -o "$work/out/cmac.txt"
check "$(is $? 0)" "a server that signs with AES-CMAC only is served"
check "$(same "$work/out/cmac.txt" "$work/share/hello.txt")" "and the file is right"
check "$(is "$(algos $cmac signing_algo)" 1)" "and the session was signed with AES-CMAC"
ccm=$((base + 2))
conf $ccm "server smb3 encryption algorithms = AES-128-CCM"
serve $ccm
t -u "$auth" "smb://127.0.0.1:$ccm/share/hello.txt" -o /dev/null
check "$(is $? 8)" "a server that encrypts with CCM only is refused (8)"
old=$((base + 3))
conf $old "server max protocol = SMB3_02" "server min protocol = SMB2_02"
serve $old
t -u "$auth" "smb://127.0.0.1:$old/share/hello.txt" -o /dev/null
check "$(is $? 8)" "a server of SMB 3.0.2 is refused (8)"

exit $fail
