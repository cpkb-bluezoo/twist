#!/bin/sh
# Copyright (C) 2026 Chris Burdess <dog@gnu.org>
#
#    This file is part of twist.
#
#    twist is free software: you can redistribute it and/or modify it
#    under the terms of the GNU General Public License as published
#    by the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    twist is distributed in the hope that it will be useful, but
#    WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
#    General Public License for more details.
#
#    You should have received a copy of the GNU General Public
#    License along with this program.  If not, see
#
# Where the tool's own words go, and what it will not write to a terminal, as
# curl has them, on file:// URLs so that no network is needed.  --stderr -
# sends what would be on standard error, the error message and the meter, to
# standard output.  A body that is binary (it has a NUL in it) is not written
# to a terminal, unless -o - asks for it: the tool warns, writes nothing and
# exits 23.  The terminal needs python.

TWIST=${TWIST:-../src/twist}
[ -x "$TWIST" ] || { echo "cli-output: twist is not built ($TWIST); skipping" >&2; exit 77; }
TWIST=$(cd "$(dirname "$TWIST")" && pwd)/$(basename "$TWIST")

tmp=${TMPDIR:-/tmp}
work=$(mktemp -d "${tmp%/}/twist-output.XXXXXX") || exit 77
trap 'rm -rf "$work"' EXIT INT TERM
src="$work/src"
mkdir -p "$src"
printf 'a' > "$src/a.txt"
printf 'abc\000def\n' > "$src/bin.dat"
printf 'plain text\n' > "$src/text.txt"
printf '\200\201\202\n' > "$src/high.dat"
# Standard input is nothing: the width of the meter is not the terminal's.
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

# --stderr - is standard output: the error is there and not on standard error.
"$TWIST" -S --stderr - -o /dev/null "file://$src/nope" > "$work/out" 2> "$work/err"
status=$?
check "$(is "$status" 37)" "--stderr -: the status is that of the error ($status)"
check "$(case "$(cat "$work/out")" in ("twist: (37) "*) echo ok;; esac)" \
  "--stderr -: the error is on standard output: $(cat "$work/out")"
check "$(is "$(cat "$work/err")" "")" "--stderr -: nothing on standard error"

# The meter too.
"$TWIST" --stderr - -o /dev/null "file://$src/a.txt" > "$work/out" 2> "$work/err"
check "$(case "$(cat "$work/out")" in ("  % Total"*) echo ok;; esac)" \
  "--stderr -: the meter is on standard output"
check "$(is "$(cat "$work/err")" "")" "--stderr -: and none on standard error"

# Standard output is not closed by it: the body, and what -w writes, are
# still there, in order.
out=$("$TWIST" -s -S --stderr - -w '[end]' "file://$src/a.txt" 2>/dev/null)
check "$(is "$out" "a[end]")" "--stderr -: the body and -w follow ($out)"
"$TWIST" -s -S --stderr - "file://$src/a.txt" "file://$src/nope" "file://$src/a.txt" \
  > "$work/out" 2>/dev/null
check "$(case "$(cat "$work/out")" in ("atwist: (37) "*"
a") echo ok;; esac)" "--stderr -: the error comes between the bodies, in order: $(cat "$work/out")"

# It is the last --stderr that counts, and a file is still a file.
"$TWIST" -S --stderr "$work/e1" -o /dev/null "file://$src/nope" > "$work/out" 2>/dev/null
check "$([ ! -s "$work/out" ] && case "$(cat "$work/e1")" in ("twist: (37) "*) echo ok;; esac)" \
  "--stderr FILE: the error is in the file"
"$TWIST" -S --stderr "$work/e2" --stderr - -o /dev/null "file://$src/nope" \
  > "$work/out" 2>/dev/null
check "$(case "$(cat "$work/out")" in ("twist: (37) "*) echo ok;; esac)" \
  "--stderr FILE then --stderr -: standard output"
"$TWIST" -S --stderr - --stderr "$work/e3" -o /dev/null "file://$src/nope" \
  > "$work/out" 2>/dev/null
check "$([ ! -s "$work/out" ] && case "$(cat "$work/e3")" in ("twist: (37) "*) echo ok;; esac)" \
  "--stderr - then --stderr FILE: the file"

# A binary body is not written to a terminal.
if command -v python3 >/dev/null 2>&1; then
  # tty_run ARGS...: runs twist with standard output on a terminal, and
  # prints its status, what the terminal got and what standard error got.
  tty_run ()
  {
    python3 -I -c '
import os, pty, select, subprocess, sys
m, s = pty.openpty()
p = subprocess.Popen(sys.argv[1:], stdout=s, stderr=subprocess.PIPE,
                     stdin=subprocess.DEVNULL)
os.close(s)
# Both are read while the command runs: a terminal forgets what it was given
# when the last descriptor of its other end is closed.
out = b""
err = b""
fds = [m, p.stderr.fileno()]
while fds:
    ready = select.select(fds, [], [], 10)[0]
    if not ready:
        break
    for fd in ready:
        try:
            d = os.read(fd, 4096)
        except OSError:
            d = b""
        if not d:
            fds.remove(fd)
        elif fd == m:
            out += d
        else:
            err += d
p.wait()
print("%d|%s|%s" % (p.returncode, out.decode("latin1").encode("unicode_escape").decode(),
                    err.decode("latin1").encode("unicode_escape").decode()))
' "$@"
  }
  warn1='Warning: Binary output can mess up your terminal. Use "--output -" to tell \n'
  warn2='Warning: twist to output it to your terminal anyway, or consider "--output \n'
  warn3='Warning: <FILE>" to save to a file.\n'
  e8='twist: (23) client returned ERROR on write of 8 bytes\n'

  r=$(tty_run "$TWIST" "file://$src/bin.dat")
  check "$(is "$r" "23||$warn1$warn2$warn3$e8")" "binary to a terminal: warned, nothing written, 23 ($r)"
  r=$(tty_run "$TWIST" -s "file://$src/bin.dat")
  check "$(is "$r" "23||")" "-s: the status, and nothing said ($r)"
  r=$(tty_run "$TWIST" -sS "file://$src/bin.dat")
  check "$(is "$r" "23||$e8")" "-sS: the error, and not the warning ($r)"
  r=$(tty_run "$TWIST" -s -o - "file://$src/bin.dat")
  check "$(is "$r" "0|abc\\x00def\\r\\n|")" "-o -: written to the terminal anyway ($r)"
  r=$(tty_run "$TWIST" -s --output - "file://$src/bin.dat")
  check "$(is "$r" "0|abc\\x00def\\r\\n|")" "--output -: the same ($r)"
  r=$(tty_run "$TWIST" -s "file://$src/text.txt")
  check "$(is "$r" "0|plain text\\r\\n|")" "text to a terminal is written ($r)"
  r=$(tty_run "$TWIST" -s "file://$src/high.dat")
  check "$(is "$r" "0|\\x80\\x81\\x82\\r\\n|")" "bytes above 127 are not binary ($r)"
  r=$(tty_run "$TWIST" -s -o "$work/saved" "file://$src/bin.dat")
  check "$(is "$r" "0||")" "a file is written, binary or not ($r)"
  check "$(cmp -s "$work/saved" "$src/bin.dat" && echo ok)" "and has it all"
fi

# Not a terminal: the bytes go through.
"$TWIST" -s "file://$src/bin.dat" > "$work/piped"
check "$(is "$?" 0)" "binary to a pipe: status 0"
check "$(cmp -s "$work/piped" "$src/bin.dat" && echo ok)" "and all of it"

exit $fail
