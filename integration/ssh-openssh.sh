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
# uploads, resuming either way, and ranges.  Skips,
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
cleanup ()
{
  [ -n "$sshd_pid" ] && kill "$sshd_pid" 2>/dev/null
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

user=$(id -un)
mkdir -p "$work/home/.ssh" "$work/srv"
ssh-keygen -q -t ed25519 -N '' -f "$work/hostkey" || skip "ssh-keygen failed"
ssh-keygen -q -t ed25519 -N '' -f "$work/userkey" || skip "ssh-keygen failed"
ssh-keygen -q -t ed25519 -N '' -f "$work/otherkey" || skip "ssh-keygen failed"
cp "$work/userkey.pub" "$work/authorized_keys"
chmod 600 "$work/authorized_keys"

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
Subsystem sftp $subsystem
LogLevel ERROR
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

# 8. A directory is not implemented yet, and scp does not expand wildcards.
t -k --key "$work/userkey" -o /dev/null "sftp://$user@$base$work/srv/"
rc=$?
check "$([ $rc -ne 0 ] && echo ok)" "directory listing is refused (got $rc)"
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

[ $fail -eq 0 ] || exit 1
exit 0
