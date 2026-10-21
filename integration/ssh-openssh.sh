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

# sftp:// and scp:// against OpenSSH's sshd.
#
# Starts an sshd of the user's own on a loopback port, with a host key and a
# user key made here, and downloads a file with twist: by key, with the host
# checked against a known_hosts file, with a pinned fingerprint, and with -k;
# and the failures (an unknown or changed host key, a missing file); and
# uploads, resuming either way, ranges, and directory listings.  Skips,
# with status 77, if there is no sshd, no ssh-keygen or no twist to run.
#
# An sshd that is not root can only log in the user who runs it, so that is
# the user name.  HOME is a directory made here, so ~/.ssh is not read.

TWIST=${TWIST:-../src/twist}
SSHD=${SSHD:-/usr/sbin/sshd}

skip ()
{
  echo "ssh-openssh: $1; skipping" >&2
  exit 77
}

[ -x "$SSHD" ] || skip "no sshd ($SSHD)"
command -v ssh-keygen >/dev/null 2>&1 || skip "no ssh-keygen"
[ -x "$TWIST" ] || skip "twist is not built ($TWIST)"

work=$(mktemp -d "${TMPDIR:-/tmp}/twist-ssh.XXXXXX") || skip "no temp dir"
sshd_pid=
agent_pid=
cleanup ()
{
  [ -n "$sshd_pid" ] && kill "$sshd_pid" 2>/dev/null
  [ -n "$agent_pid" ] && kill "$agent_pid" 2>/dev/null
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

# The person's own agent is none of this test's business.
unset SSH_AUTH_SOCK SSH_AGENT_PID

user=$(id -un)
mkdir -p "$work/home/.ssh" "$work/srv"
ssh-keygen -q -t ed25519 -N '' -f "$work/hostkey" || skip "ssh-keygen failed"
ssh-keygen -q -t ed25519 -N '' -f "$work/userkey" || skip "ssh-keygen failed"
ssh-keygen -q -t ed25519 -N '' -f "$work/otherkey" || skip "ssh-keygen failed"
cp "$work/userkey.pub" "$work/authorized_keys"
chmod 600 "$work/authorized_keys"
# A CA the server trusts, and a key the server does not know, only through a
# certificate from the CA.
ssh-keygen -q -t ed25519 -N '' -f "$work/ca" || skip "ssh-keygen failed"
ssh-keygen -q -t ed25519 -N '' -f "$work/certkey" || skip "ssh-keygen failed"
ssh-keygen -q -s "$work/ca" -I twist-test -n "$(id -un)" -V -5m:+1h \
  "$work/certkey.pub" 2>/dev/null || skip "ssh-keygen cannot sign a certificate"

# A file big enough for many reads and a rekey-free transfer.
dd if=/dev/urandom of="$work/srv/data.bin" bs=1024 count=700 2>/dev/null
printf 'small\n' > "$work/srv/small.txt"
: > "$work/srv/empty"

sftp_server=
for p in /usr/lib/openssh/sftp-server /usr/libexec/openssh/sftp-server \
         /usr/libexec/sftp-server /usr/lib/ssh/sftp-server; do
  [ -x "$p" ] && sftp_server=$p && break
done
subsystem=${sftp_server:-internal-sftp}

port=
for try in 1 2 3 4 5 6 7 8; do
  port=$((20000 + $(od -An -N2 -tu2 /dev/urandom | tr -d ' ') % 20000))
  cat > "$work/sshd_config" <<EOF
Port $port
ListenAddress 127.0.0.1
HostKey $work/hostkey
PidFile $work/sshd.pid
AuthorizedKeysFile $work/authorized_keys
StrictModes no
UsePAM no
PasswordAuthentication no
KbdInteractiveAuthentication no
PubkeyAuthentication yes
TrustedUserCAKeys $work/ca.pub
Subsystem sftp $subsystem
LogLevel INFO
EOF
  "$SSHD" -f "$work/sshd_config" -E "$work/sshd.log" && break
  port=
done
[ -n "$port" ] || skip "cannot start an sshd"
# -D is not used so that the daemon forks; wait for the pid file.
i=0
while [ ! -s "$work/sshd.pid" ] && [ $i -lt 50 ]; do sleep 0.1; i=$((i + 1)); done
sshd_pid=$(cat "$work/sshd.pid" 2>/dev/null)
[ -n "$sshd_pid" ] || skip "sshd did not start"

hostpub=$(cut -d' ' -f1,2 "$work/hostkey.pub")
otherpub=$(cut -d' ' -f1,2 "$work/otherkey.pub")
fingerprint=$(ssh-keygen -lf "$work/hostkey.pub" | cut -d' ' -f2)
printf '[127.0.0.1]:%s %s\n' "$port" "$hostpub" > "$work/home/.ssh/known_hosts"

export HOME="$work/home"
base="127.0.0.1:$port"
t ()
{
  "$TWIST" -s -S "$@"
}

# 1. A key, a host in known_hosts: the default way.
rm -f "$work/out"
t --key "$work/userkey" -o "$work/out" "sftp://$user@$base$work/srv/data.bin"
rc=$?
[ $rc -eq 0 ] && cmp -s "$work/out" "$work/srv/data.bin"
check "$([ $? -eq 0 ] && echo ok)" "sftp download by key (exit $rc)"

# 2. scp:// is the same, and /~/ is the user's directory (the user's home is
# whatever sshd says, so look the file up by an absolute path as well).
rm -f "$work/out"
t --key "$work/userkey" -o "$work/out" "scp://$user@$base$work/srv/small.txt"
rc=$?
[ $rc -eq 0 ] && [ "$(cat "$work/out")" = small ]
check "$([ $? -eq 0 ] && echo ok)" "scp download by key (exit $rc)"

# 3. An empty file.
rm -f "$work/out"
t --key "$work/userkey" -o "$work/out" "sftp://$user@$base$work/srv/empty"
rc=$?
[ $rc -eq 0 ] && [ ! -s "$work/out" ]
check "$([ $? -eq 0 ] && echo ok)" "empty file (exit $rc)"

# 4. The usual key file, found without being named.
cp "$work/userkey" "$work/home/.ssh/id_ed25519"
chmod 600 "$work/home/.ssh/id_ed25519"
rm -f "$work/out"
t -o "$work/out" "sftp://$user@$base$work/srv/small.txt"
rc=$?
[ $rc -eq 0 ] && [ "$(cat "$work/out")" = small ]
check "$([ $? -eq 0 ] && echo ok)" "usual key file (exit $rc)"
rm -f "$work/home/.ssh/id_ed25519"

# 5. A file that is not there, and one we may not read.
t --key "$work/userkey" -o /dev/null "sftp://$user@$base$work/srv/nope"
rc=$?
check "$([ $rc -eq 78 ] && echo ok)" "missing file gives 78 (got $rc)"
touch "$work/srv/locked"; chmod 000 "$work/srv/locked"
if [ ! -r "$work/srv/locked" ]; then
  t --key "$work/userkey" -o /dev/null "sftp://$user@$base$work/srv/locked"
  rc=$?
  check "$([ $rc -eq 9 ] && echo ok)" "unreadable file gives 9 (got $rc)"
fi

# 6. A key the server does not know.
t --key "$work/otherkey" -o /dev/null "sftp://$user@$base$work/srv/small.txt"
rc=$?
check "$([ $rc -eq 67 ] && echo ok)" "unknown user key gives 67 (got $rc)"

# 7. The host: not known, changed, pinned, and -k.
: > "$work/home/.ssh/known_hosts"
t --key "$work/userkey" -o /dev/null "sftp://$user@$base$work/srv/small.txt"
rc=$?
check "$([ $rc -eq 60 ] && echo ok)" "unknown host gives 60 (got $rc)"
printf '[127.0.0.1]:%s %s\n' "$port" "$otherpub" > "$work/home/.ssh/known_hosts"
t --key "$work/userkey" -o /dev/null "sftp://$user@$base$work/srv/small.txt"
rc=$?
check "$([ $rc -eq 60 ] && echo ok)" "changed host key gives 60 (got $rc)"
rm -f "$work/out"
t -k --key "$work/userkey" -o "$work/out" "sftp://$user@$base$work/srv/small.txt"
rc=$?
[ $rc -eq 0 ] && [ "$(cat "$work/out")" = small ]
check "$([ $? -eq 0 ] && echo ok)" "-k skips known_hosts (exit $rc)"
rm -f "$work/out"
t --hostpubsha256 "$fingerprint" --key "$work/userkey" -o "$work/out" \
  "sftp://$user@$base$work/srv/small.txt"
rc=$?
[ $rc -eq 0 ] && [ "$(cat "$work/out")" = small ]
check "$([ $? -eq 0 ] && echo ok)" "pinned fingerprint (exit $rc)"
t -k --hostpubsha256 "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" \
  --key "$work/userkey" -o /dev/null "sftp://$user@$base$work/srv/small.txt"
rc=$?
check "$([ $rc -eq 60 ] && echo ok)" "wrong pin gives 60 even with -k (got $rc)"

# 8. A directory listing, with names a server cannot be trusted with: a
# newline (which would make a line that is not an entry), a terminal escape,
# a space and a dot.  scp does not list, and does not expand wildcards.
mkdir -p "$work/srv/lsdir/sub"
printf 'a' > "$work/srv/lsdir/plain.txt"
printf 'b' > "$work/srv/lsdir/with space.txt"
printf 'c' > "$work/srv/lsdir/.hidden"
printf 'd' > "$work/srv/lsdir/$(printf 'new\nline')"
printf 'e' > "$work/srv/lsdir/$(printf 'esc\033[31mred')"
entries=$(find "$work/srv/lsdir" -mindepth 1 -maxdepth 1 -printf x | wc -c)
entries=$((entries + 2))
t -k --key "$work/userkey" -l -o "$work/names" "sftp://$user@$base$work/srv/lsdir/"
rc=$?
lines=$(wc -l < "$work/names")
check "$([ $rc -eq 0 ] && [ "$lines" -eq "$entries" ] && echo ok)" \
  "a listing has one line to an entry, $entries (exit $rc, got $lines)"
check "$(grep -qFx 'plain.txt' "$work/names" && grep -qFx 'with space.txt' "$work/names" && grep -qFx '.hidden' "$work/names" && grep -qFx 'sub' "$work/names" && grep -qFx '.' "$work/names" && grep -qFx '..' "$work/names" && echo ok)" \
  "the names are in the listing"
check "$(grep -qF "$(printf '\033')" "$work/names" || echo ok)" \
  "no escape character reaches the output"
check "$(grep -qFx 'new?line' "$work/names" && grep -qFx 'esc?[31mred' "$work/names" && echo ok)" \
  "control characters in names are shown as ?"
t -k --key "$work/userkey" -o "$work/long" "sftp://$user@$base$work/srv/lsdir/"
rc=$?
lines=$(wc -l < "$work/long")
check "$([ $rc -eq 0 ] && [ "$lines" -eq "$entries" ] && grep -q 'plain.txt' "$work/long" && grep -qE '^d[rwx-]{9} ' "$work/long" && echo ok)" \
  "the long form is the server's, one line to an entry (exit $rc)"
t -k --key "$work/userkey" -l -o /dev/null "sftp://$user@$base$work/srv/nodir/"
rc=$?
check "$([ $rc -eq 78 ] && echo ok)" "a directory that is not there gives 78 (got $rc)"
t -k --key "$work/userkey" -l -o /dev/null "sftp://$user@$base$work/srv/data.bin/"
rc=$?
check "$([ $rc -eq 78 ] && echo ok)" "a file with a slash after it gives 78 (got $rc)"
t -k --key "$work/userkey" -o /dev/null "scp://$user@$base$work/srv/lsdir/"
rc=$?
check "$([ $rc -eq 78 ] && echo ok)" "scp does not list a directory, 78 (got $rc)"
t -k --key "$work/userkey" -o /dev/null "scp://$user@$base$work/srv/*.txt"
rc=$?
check "$([ $rc -ne 0 ] && echo ok)" "scp wildcard is refused (got $rc)"

# 9. Upload: a new file, with the mode a new file gets, and to a directory
# URL, which takes the name of the local file.
dd if=/dev/urandom of="$work/local.bin" bs=1024 count=900 2>/dev/null
rm -f "$work/srv/up.bin"
t -k --key "$work/userkey" -T "$work/local.bin" \
  "sftp://$user@$base$work/srv/up.bin"
rc=$?
[ $rc -eq 0 ] && cmp -s "$work/local.bin" "$work/srv/up.bin"
check "$([ $? -eq 0 ] && echo ok)" "sftp upload (exit $rc)"
want=$(printf '%o' $((0644 & ~$(umask))))
got=$(stat -c %a "$work/srv/up.bin" 2>/dev/null)
check "$([ "$got" = "$want" ] && echo ok)" "new file mode $want (got $got)"
t -k --key "$work/userkey" -T "$work/local.bin" \
  "sftp://$user@$base$work/srv/"
rc=$?
[ $rc -eq 0 ] && cmp -s "$work/local.bin" "$work/srv/local.bin"
check "$([ $? -eq 0 ] && echo ok)" "upload to a directory URL (exit $rc)"
rm -f "$work/srv/up.bin"
t -k --key "$work/userkey" -T "$work/local.bin" \
  "scp://$user@$base$work/srv/up.bin"
rc=$?
[ $rc -eq 0 ] && cmp -s "$work/local.bin" "$work/srv/up.bin"
check "$([ $? -eq 0 ] && echo ok)" "scp upload (exit $rc)"

# A file that is there is replaced by a shorter one.
printf 'short\n' > "$work/short.txt"
t -k --key "$work/userkey" -T "$work/short.txt" \
  "sftp://$user@$base$work/srv/up.bin"
rc=$?
[ $rc -eq 0 ] && cmp -s "$work/short.txt" "$work/srv/up.bin"
check "$([ $? -eq 0 ] && echo ok)" "upload replaces a longer file (exit $rc)"

# 10. Resume an upload, by asking the server and by the offset.
head -c 300000 "$work/local.bin" > "$work/srv/part"
t -k --key "$work/userkey" -C - -T "$work/local.bin" \
  "sftp://$user@$base$work/srv/part"
rc=$?
[ $rc -eq 0 ] && cmp -s "$work/local.bin" "$work/srv/part"
check "$([ $? -eq 0 ] && echo ok)" "resume an upload with -C - (exit $rc)"
head -c 123456 "$work/local.bin" > "$work/srv/part"
t -k --key "$work/userkey" -C 123456 -T "$work/local.bin" \
  "sftp://$user@$base$work/srv/part"
rc=$?
[ $rc -eq 0 ] && cmp -s "$work/local.bin" "$work/srv/part"
check "$([ $? -eq 0 ] && echo ok)" "resume an upload at an offset (exit $rc)"
rm -f "$work/srv/fresh"
t -k --key "$work/userkey" -C - -T "$work/local.bin" \
  "sftp://$user@$base$work/srv/fresh"
rc=$?
[ $rc -eq 0 ] && cmp -s "$work/local.bin" "$work/srv/fresh"
check "$([ $? -eq 0 ] && echo ok)" "resume an upload that has no file yet (exit $rc)"
head -c 1000 "$work/local.bin" > "$work/srv/part"
t -k --key "$work/userkey" -C 5000 -T "$work/local.bin" \
  "sftp://$user@$base$work/srv/part"
rc=$?
check "$([ $rc -eq 36 ] && echo ok)" "resume past the end of the remote file gives 36 (got $rc)"

# 11. Resume a download: from what the output file holds, and by the offset.
head -c 250000 "$work/srv/data.bin" > "$work/out"
t -k --key "$work/userkey" -C - -o "$work/out" \
  "sftp://$user@$base$work/srv/data.bin"
rc=$?
[ $rc -eq 0 ] && cmp -s "$work/out" "$work/srv/data.bin"
check "$([ $? -eq 0 ] && echo ok)" "resume a download with -C - (exit $rc)"
head -c 100000 "$work/srv/data.bin" > "$work/out"
t -k --key "$work/userkey" -C 100000 -o "$work/out" \
  "sftp://$user@$base$work/srv/data.bin"
rc=$?
[ $rc -eq 0 ] && cmp -s "$work/out" "$work/srv/data.bin"
check "$([ $? -eq 0 ] && echo ok)" "resume a download at an offset (exit $rc)"
size=$(stat -c %s "$work/srv/data.bin")
cp "$work/srv/data.bin" "$work/out"
t -k --key "$work/userkey" -C - -o "$work/out" \
  "sftp://$user@$base$work/srv/data.bin"
rc=$?
[ $rc -eq 0 ] && [ "$(stat -c %s "$work/out")" = "$size" ]
check "$([ $? -eq 0 ] && echo ok)" "nothing left to resume (exit $rc)"
t -k --key "$work/userkey" -C $((size + 1000)) -o "$work/out" \
  "sftp://$user@$base$work/srv/data.bin"
rc=$?
check "$([ $rc -eq 36 ] && echo ok)" "resume past the end gives 36 (got $rc)"
t -k --key "$work/userkey" -C - "sftp://$user@$base$work/srv/data.bin" \
  >/dev/null 2>&1
rc=$?
check "$([ $rc -eq 2 ] && echo ok)" "-C - to the terminal is refused (got $rc)"
t -C 10 -o /dev/null "http://127.0.0.1:9/" >/dev/null 2>&1
rc=$?
check "$([ $rc -eq 2 ] && echo ok)" "-C on another scheme is refused (got $rc)"

# 12. Ranges.
t -k --key "$work/userkey" -r 1000-1999 -o "$work/out" \
  "sftp://$user@$base$work/srv/data.bin"
rc=$?
tail -c +1001 "$work/srv/data.bin" | head -c 1000 > "$work/want"
[ $rc -eq 0 ] && cmp -s "$work/out" "$work/want"
check "$([ $? -eq 0 ] && echo ok)" "range FIRST-LAST (exit $rc)"
t -k --key "$work/userkey" -r -100 -o "$work/out" \
  "sftp://$user@$base$work/srv/data.bin"
rc=$?
tail -c 100 "$work/srv/data.bin" > "$work/want"
[ $rc -eq 0 ] && cmp -s "$work/out" "$work/want"
check "$([ $? -eq 0 ] && echo ok)" "the last 100 bytes (exit $rc)"
t -k --key "$work/userkey" -r 700000- -o "$work/out" \
  "sftp://$user@$base$work/srv/data.bin"
rc=$?
tail -c +700001 "$work/srv/data.bin" > "$work/want"
[ $rc -eq 0 ] && cmp -s "$work/out" "$work/want"
check "$([ $? -eq 0 ] && echo ok)" "range FIRST- (exit $rc)"
t -k --key "$work/userkey" -r $((size + 10))- -o /dev/null \
  "sftp://$user@$base$work/srv/data.bin"
rc=$?
check "$([ $rc -eq 33 ] && echo ok)" "a range beyond the end gives 33 (got $rc)"

# 13. Failures of an upload.
t -k --key "$work/userkey" -T "$work/short.txt" \
  "sftp://$user@$base$work/srv/nodir/x"
rc=$?
check "$([ $rc -eq 25 ] && echo ok)" "upload into a missing directory gives 25 (got $rc)"
if [ ! -w "$work/srv/locked" ]; then
  t -k --key "$work/userkey" -T "$work/short.txt" \
    "sftp://$user@$base$work/srv/locked"
  rc=$?
  check "$([ $rc -eq 9 ] && echo ok)" "upload to a file we may not write gives 9 (got $rc)"
fi

# 14. ssh-agent.  A real agent holds keys, and twist asks it to sign.  Keys
# are tried in the agent's order, a key named with --key is used alone, and
# the agent is never fatal: whatever is wrong with it, the other ways are
# still tried.
if command -v ssh-agent >/dev/null 2>&1 && command -v ssh-add >/dev/null 2>&1 \
   && [ ${#work} -lt 80 ]; then
  sock="$work/agent.sock"
  agent_pid=$(ssh-agent -s -a "$sock" | sed -n 's/^SSH_AGENT_PID=\([0-9]*\);.*/\1/p')
  hostline=$(cut -d' ' -f1,2 "$work/hostkey.pub")
  # The host as twist looks it up (with the port), and as ssh-add does for a
  # key restricted to a destination (without).
  printf '[127.0.0.1]:%s %s\n' "$port" "$hostline" > "$work/home/.ssh/known_hosts"
  printf '127.0.0.1 %s\n' "$hostline" > "$work/agent_hosts"
  for k in wrong1 wrong2 wrong3 wrong4 enckey conkey; do
    rm -f "$work/$k" "$work/$k.pub"
  done
  for k in wrong1 wrong2 wrong3 wrong4 conkey; do
    ssh-keygen -q -t ed25519 -N '' -f "$work/$k"
  done
  ssh-keygen -q -t ed25519 -N 'correct horse' -f "$work/enckey"
  cat "$work/enckey.pub" "$work/conkey.pub" >> "$work/authorized_keys"
  printf '#!/bin/sh\necho "correct horse"\n' > "$work/askpass"
  chmod +x "$work/askpass"
  agent ()
  {
    ( SSH_AUTH_SOCK="$sock"; export SSH_AUTH_SOCK; "$@" )
  }
  ask ()
  {
    ( SSH_AUTH_SOCK="$sock"; export SSH_AUTH_SOCK
      SSH_ASKPASS="$work/askpass"; SSH_ASKPASS_REQUIRE=force
      export SSH_ASKPASS SSH_ASKPASS_REQUIRE
      ssh-add -q "$@" </dev/null 2>/dev/null )
  }
  rm -f "$work/home/.ssh/id_ed25519" "$work/home/.ssh/id_ecdsa" \
        "$work/home/.ssh/id_rsa"
  url="sftp://$user@$base$work/srv/small.txt"

  # The agent holds a key the server knows, and the user has no key files.
  agent ssh-add -q "$work/userkey"
  rm -f "$work/out"
  agent t -k -o "$work/out" "$url"
  rc=$?
  [ $rc -eq 0 ] && [ "$(cat "$work/out")" = small ]
  check "$([ $? -eq 0 ] && echo ok)" "login by a key in the agent (exit $rc)"

  # A key named with --key is used alone: the agent is not asked, so a wrong
  # agent is harmless and the named key decides.
  rm -f "$work/out"
  agent t -k --key "$work/otherkey" -o "$work/out" "$url"
  rc=$?
  check "$([ $rc -eq 67 ] && echo ok)" "a named key is used alone, wrong here, 67 (got $rc)"

  # Several keys the server does not know come first.  The server counts each
  # as a failed attempt and allows six, so four are fine.
  agent ssh-add -D -q
  for k in wrong1 wrong2 wrong3 wrong4; do agent ssh-add -q "$work/$k"; done
  agent ssh-add -q "$work/userkey"
  rm -f "$work/out"
  agent t -k -o "$work/out" "$url"
  rc=$?
  [ $rc -eq 0 ] && [ "$(cat "$work/out")" = small ]
  check "$([ $? -eq 0 ] && echo ok)" "the right key after four wrong ones (exit $rc)"

  # A key protected by a passphrase, which twist cannot decrypt, can be used
  # through the agent, which has it.
  agent ssh-add -D -q
  ask "$work/enckey"
  rm -f "$work/out"
  agent t -k -o "$work/out" "$url"
  rc=$?
  [ $rc -eq 0 ] && [ "$(cat "$work/out")" = small ]
  check "$([ $? -eq 0 ] && echo ok)" "a passphrase-protected key in the agent (exit $rc)"
  t -k --key "$work/enckey" -o /dev/null "$url" 2> "$work/err"
  rc=$?
  check "$([ $rc -eq 67 ] && grep -q 'protected by a passphrase' "$work/err" && echo ok)" \
    "the same key as a file is refused, and says why (exit $rc)"

  # A key that may be used only for this server.  The agent signs for it only
  # once it has been told which server this is and which key that server
  # showed (session-bind).
  agent ssh-add -D -q
  agent ssh-add -q -H "$work/agent_hosts" -h 127.0.0.1 "$work/conkey"
  rm -f "$work/out"
  agent t -k -o "$work/out" "$url"
  rc=$?
  [ $rc -eq 0 ] && [ "$(cat "$work/out")" = small ]
  check "$([ $? -eq 0 ] && echo ok)" "a key restricted to a destination (exit $rc)"

  # A certificate in the agent: ssh-add loads KEY-cert.pub with the key, and the
  # server knows this key only through the certificate.
  agent ssh-add -D -q
  agent ssh-add -q "$work/certkey" 2>/dev/null
  rm -f "$work/out"
  agent t -k -o "$work/out" "$url"
  rc=$?
  [ $rc -eq 0 ] && [ "$(cat "$work/out")" = small ]
  check "$([ $? -eq 0 ] && echo ok)" "a certificate held by the agent (exit $rc)"

  # No agent where SSH_AUTH_SOCK says.  Not fatal in itself: a key file works,
  # and with nothing else the failure names the agent.
  ( SSH_AUTH_SOCK="$work/nothing-here.sock"; export SSH_AUTH_SOCK
    t -k -o /dev/null "$url" 2> "$work/err" )
  rc=$?
  check "$([ $rc -eq 67 ] && grep -q 'ssh-agent: cannot connect' "$work/err" && echo ok)" \
    "no agent at the socket, and nothing else: 67, and it says so (exit $rc)"
  ( SSH_AUTH_SOCK="$work/nothing-here.sock"; export SSH_AUTH_SOCK
    t -k --key "$work/userkey" -o "$work/out" "$url" )
  rc=$?
  check "$([ $rc -eq 0 ] && echo ok)" "a dead agent does not stop a key file (exit $rc)"

  # No agent at all.
  t -k -o /dev/null "$url" 2> "$work/err"
  rc=$?
  check "$([ $rc -eq 67 ] && grep -q 'no private key or password' "$work/err" && echo ok)" \
    "no agent, no key, no password: 67 (exit $rc)"
else
  echo "ssh-openssh: no ssh-agent, or the work directory is too long for its socket; skipping the agent checks" >&2
fi

# 15. The URLs of one command line are fetched on one connection: sshd sees
# one login for all of them.  A transfer that fails ends its connection, so
# the next URL logs in again.  OpenSSH sends the client a few messages of its
# own after login; a connection that is kept must survive them.
printf '[127.0.0.1]:%s %s\n' "$port" "$hostpub" > "$work/home/.ssh/known_hosts"
logins ()
{
  grep -c 'Accepted publickey' "$work/sshd.log"
}
before=$(logins)
rm -f "$work/o1" "$work/o2" "$work/o3" "$work/o4"
t --key "$work/userkey" \
  -o "$work/o1" "sftp://$user@$base$work/srv/data.bin" \
  -o "$work/o2" "sftp://$user@$base$work/srv/small.txt" \
  -o "$work/o3" "scp://$user@$base$work/srv/small.txt" \
  -o "$work/o4" "sftp://$user@$base$work/srv/empty"
rc=$?
sleep 0.3
n=$(( $(logins) - before ))
ok=
if [ $rc -eq 0 ] && cmp -s "$work/o1" "$work/srv/data.bin" \
   && [ "$(cat "$work/o2")" = small ] && [ "$(cat "$work/o3")" = small ] \
   && [ ! -s "$work/o4" ] && [ $n -eq 1 ]; then
  ok=ok
fi
check "$ok" "four URLs, one login (logins $n, exit $rc)"

# A URL that fails in the middle: its connection is not kept, and the one
# after it logs in again and works.
before=$(logins)
rm -f "$work/o1" "$work/o2"
t --key "$work/userkey" \
  -o "$work/o1" "sftp://$user@$base$work/srv/small.txt" \
  -o "$work/o2" "sftp://$user@$base$work/srv/missing" \
  -o "$work/o3" "sftp://$user@$base$work/srv/small.txt"
rc=$?
sleep 0.3
n=$(( $(logins) - before ))
ok=
if [ "$(cat "$work/o3")" = small ] && [ $n -eq 2 ]; then
  ok=ok
fi
check "$ok" "a failed URL ends its connection, the next logs in again (logins $n, exit $rc)"

# 16. An upload is sent as it is read, not after all of it has been read: with
# the input held open, the first of it is on the server already.  Input that
# cannot be read is an error (26), not the end of the file.
rm -f "$work/srv/stream.bin" "$work/fifo"
mkfifo "$work/fifo"
t -k --key "$work/userkey" -T - "sftp://$user@$base$work/srv/stream.bin" \
  < "$work/fifo" &
twist_pid=$!
exec 7> "$work/fifo"
head -c 100000 /dev/zero >&7
i=0
while [ ! -s "$work/srv/stream.bin" ] && [ $i -lt 30 ]; do sleep 0.1; i=$((i + 1)); done
sofar=$(wc -c < "$work/srv/stream.bin" 2>/dev/null || echo 0)
head -c 50000 /dev/zero >&7
exec 7>&-
wait $twist_pid
rc=$?
ok=
[ $sofar -gt 0 ] && [ $rc -eq 0 ] \
  && [ "$(wc -c < "$work/srv/stream.bin")" -eq 150000 ] && ok=ok
check "$ok" "an upload is sent while it is still being read (had $sofar, exit $rc)"
rm -f "$work/fifo"

t -k --key "$work/userkey" -T "$work" "sftp://$user@$base$work/srv/dirsrc" \
  2> "$work/err"
rc=$?
check "$([ $rc -eq 26 ] && echo ok)" "input that cannot be read gives 26 (got $rc)"

# 17. User certificates.  A key with a certificate beside it (KEY-cert.pub, as
# ssh finds it) is offered with the certificate; this key is not in
# authorized_keys, so the login works only if the server accepts the
# certificate.  A certificate that is no good is said to be, since the server
# only refuses.
rm -f "$work/out"
t -k --key "$work/certkey" -o "$work/out" "sftp://$user@$base$work/srv/small.txt"
rc=$?
[ $rc -eq 0 ] && [ "$(cat "$work/out")" = small ]
check "$([ $? -eq 0 ] && echo ok)" "login with a certificate (exit $rc)"

cp "$work/certkey" "$work/home/.ssh/id_ed25519"
cp "$work/certkey-cert.pub" "$work/home/.ssh/id_ed25519-cert.pub"
chmod 600 "$work/home/.ssh/id_ed25519"
rm -f "$work/out"
t -k -o "$work/out" "sftp://$user@$base$work/srv/small.txt"
rc=$?
[ $rc -eq 0 ] && [ "$(cat "$work/out")" = small ]
check "$([ $? -eq 0 ] && echo ok)" "a certificate beside the usual key file (exit $rc)"
rm -f "$work/home/.ssh/id_ed25519" "$work/home/.ssh/id_ed25519-cert.pub"

cp "$work/certkey" "$work/oldkey"
cp "$work/certkey.pub" "$work/oldkey.pub"
ssh-keygen -q -s "$work/ca" -I twist-old -n "$user" -V -2h:-1h "$work/oldkey.pub" \
  2>/dev/null
t -k --key "$work/oldkey" -o /dev/null "sftp://$user@$base$work/srv/small.txt" \
  2> "$work/err"
rc=$?
check "$([ $rc -eq 67 ] && grep -q 'expired' "$work/err" && echo ok)" \
  "an expired certificate gives 67 and says so (exit $rc)"

ssh-keygen -q -s "$work/ca" -I twist-bob -n nobody-here -V -5m:+1h \
  "$work/oldkey.pub" 2>/dev/null
t -k --key "$work/oldkey" -o /dev/null "sftp://$user@$base$work/srv/small.txt" \
  2> "$work/err"
rc=$?
check "$([ $rc -eq 67 ] && grep -q 'not for the user' "$work/err" && echo ok)" \
  "a certificate for another user gives 67 and says so (exit $rc)"

# 18. Quote commands (-Q) and --ftp-create-dirs, for sftp.  Before the
# transfer, or after with a dash; * lets the server refuse; a failure is 21.
q="sftp://$user@$base$work/srv/small.txt"
rm -rf "$work/srv/qdir" "$work/srv/qdir2" "$work/srv/qa" "$work/srv/qb"
rm -f "$work/out"
t -k --key "$work/userkey" -Q "mkdir $work/srv/qdir" -Q "-rename $work/srv/qdir $work/srv/qdir2" \
  -o "$work/out" "$q"
rc=$?
ok=
[ $rc -eq 0 ] && [ "$(cat "$work/out")" = small ] && [ -d "$work/srv/qdir2" ] \
  && [ ! -d "$work/srv/qdir" ] && ok=ok
check "$ok" "a command before the transfer and one after (exit $rc)"

t -k --key "$work/userkey" -Q "rm $work/srv/nonexistent" -o "$work/out" "$q" 2> "$work/err"
rc=$?
check "$([ $rc -eq 21 ] && grep -q 'rm command failed' "$work/err" && echo ok)" \
  "a command the server refuses gives 21 (exit $rc)"
t -k --key "$work/userkey" -Q "*rm $work/srv/nonexistent" -o "$work/out" "$q"
rc=$?
check "$([ $rc -eq 0 ] && echo ok)" "* goes on after a refusal (exit $rc)"
t -k --key "$work/userkey" -Q "frobnicate" -o "$work/out" "$q" 2> "$work/err"
rc=$?
check "$([ $rc -eq 21 ] && grep -q 'Unknown SFTP command' "$work/err" && echo ok)" \
  "a command that is not one gives 21 (exit $rc)"
t -k --key "$work/userkey" -Q "+pwd" -o "$work/out" "$q" 2> "$work/err"
rc=$?
check "$([ $rc -eq 2 ] && echo ok)" "a + before a command is refused (exit $rc)"

printf 'x\n' > "$work/srv/target.txt"
rm -f "$work/srv/lnk" "$work/srv/with space.txt" "$work/srv/moved name.txt"
t -k --key "$work/userkey" -I \
  -Q "ln $work/srv/target.txt $work/srv/lnk" \
  -Q "chmod 600 $work/srv/target.txt" \
  -Q "chown $(id -u) $work/srv/target.txt" \
  -Q "chgrp $(id -g) $work/srv/target.txt" \
  -Q "mtime \"Thu, 02 Jan 2020 10:00:00 GMT\" $work/srv/target.txt" \
  -Q "atime \"Thu, 02 Jan 2020 11:00:00 GMT\" $work/srv/target.txt" \
  -Q "mkdir \"$work/srv/with space.txt\"" \
  -Q "rename \"$work/srv/with space.txt\" \"$work/srv/moved name.txt\"" \
  -Q "rmdir \"$work/srv/moved name.txt\"" \
  "sftp://$user@$base$work/srv/target.txt" > "$work/out" 2> "$work/err"
rc=$?
ok=
[ $rc -eq 0 ] && [ ! -s "$work/out" ] && [ "$(readlink "$work/srv/lnk")" = "$work/srv/target.txt" ] \
  && [ "$(stat -c %a "$work/srv/target.txt")" = 600 ] \
  && [ "$(stat -c %Y "$work/srv/target.txt")" = 1577959200 ] \
  && [ "$(stat -c %X "$work/srv/target.txt")" = 1577962800 ] \
  && [ ! -e "$work/srv/with space.txt" ] && [ ! -e "$work/srv/moved name.txt" ] && ok=ok
check "$ok" "ln, chmod, chown, chgrp, mtime, atime, mkdir, rename and rmdir with -I (exit $rc)"
[ -n "$ok" ] || { cat "$work/err" >&2; stat -c '%a %Y %X' "$work/srv/target.txt" >&2; }

t -k --key "$work/userkey" -I -Q "mkdir $work/srv/headq" \
  "sftp://$user@$base$work/srv/missing" 2> "$work/err"
rc=$?
check "$([ $rc -eq 78 ] && echo ok)" "-I for a file that is not there gives 78 (exit $rc)"

t -k --key "$work/userkey" -Q pwd -D "$work/hdr" -o /dev/null "$q"
rc=$?
check "$([ $rc -eq 0 ] && grep -q '^257 ".*" is current directory\.' "$work/hdr" && echo ok)" \
  "pwd goes to the header output (exit $rc)"

# scp does not take them, as with curl.
t -k --key "$work/userkey" -Q "mkdir $work/srv/qscp" -o /dev/null \
  "scp://$user@$base$work/srv/small.txt"
rc=$?
check "$([ $rc -eq 0 ] && [ ! -e "$work/srv/qscp" ] && echo ok)" "scp ignores -Q (exit $rc)"

# --ftp-create-dirs
printf 'deep\n' > "$work/deep.txt"
t -k --key "$work/userkey" -T "$work/deep.txt" "sftp://$user@$base$work/srv/qa/qb/f.txt"
rc=$?
check "$([ $rc -eq 25 ] && [ ! -e "$work/srv/qa" ] && echo ok)" \
  "an upload into missing directories fails without the option (exit $rc)"
t -k --key "$work/userkey" --ftp-create-dirs -T "$work/deep.txt" \
  "sftp://$user@$base$work/srv/qa/qb/f.txt"
rc=$?
ok=
[ $rc -eq 0 ] && [ "$(cat "$work/srv/qa/qb/f.txt")" = deep ] \
  && [ "$(stat -c %a "$work/srv/qa")" = 755 ] && [ "$(stat -c %a "$work/srv/qa/qb")" = 755 ] && ok=ok
check "$ok" "--ftp-create-dirs makes them, mode 755 (exit $rc)"
t -k --key "$work/userkey" --ftp-create-dirs -T "$work/deep.txt" \
  "sftp://$user@$base$work/srv/qa/qb/g.txt"
rc=$?
check "$([ $rc -eq 0 ] && [ -f "$work/srv/qa/qb/g.txt" ] && echo ok)" \
  "and goes on when they are there (exit $rc)"

[ $fail -eq 0 ] || exit 1
exit 0
