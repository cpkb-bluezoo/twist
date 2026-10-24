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
#    <https://www.gnu.org/licenses/>.
#
# Parallel transfers on the command line (-Z), with file:// URLs so that no
# network is needed: that every URL arrives, the exit status when one fails,
# what --fail-early does to those that are under way, that standard input is
# given to one transfer only, and that the limits are accepted.

TWIST=${TWIST:-../src/twist}
[ -x "$TWIST" ] || { echo "cli-parallel: twist is not built ($TWIST); skipping" >&2; exit 77; }
# The tests change directory, so the path must not be relative.
TWIST=$(cd "$(dirname "$TWIST")" && pwd)/$(basename "$TWIST")

work=$(mktemp -d "${TMPDIR:-/tmp}/twist-parallel.XXXXXX") || exit 77
trap 'rm -rf "$work"' EXIT INT TERM
src="$work/src"
mkdir -p "$src"
n=1
while [ $n -le 10 ]; do
  printf 'content-%s\n' $n > "$src/f$n.txt"
  n=$((n + 1))
done
u="file://$src"
msg='only one transfer can read standard input with --parallel'
aborted='Transfer aborted due to critical error in another transfer'

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
fresh () { rm -rf "$work/out"; mkdir "$work/out"; cd "$work/out" || exit 77; }

# Ten URLs from one pattern, all at once: every one arrives, with its own
# contents.
fresh
"$TWIST" -Z -o 'out#1' "$u/f[1-10].txt" 2>"$work/err"; st=$?
check "$(is "$st" 0)" "-Z with a pattern of ten: status 0 ($st)"
ok=ok
n=1
while [ $n -le 10 ]; do
  [ "$(cat "out$n" 2>/dev/null)" = "content-$n" ] || ok=bad
  n=$((n + 1))
done
check "$ok" "-Z with a pattern of ten: every file has its contents"

# One line for the whole run, on standard error, in curl's layout: the header
# once, the line that begins with a carriage return, and at the end a line
# whose figures are the sum of the ten files and that ends with a newline.
# The speed and the times depend on the clock.
header='DL% UL%  Dled  Uled  Xfers  Live Total     Current  Left    Speed'
check "$(is "$(grep -c '^DL% UL%  Dled  Uled  Xfers  Live Total     Current  Left    Speed$' "$work/err")" 1)" \
  "-Z draws the header once"
check "$(is "$(head -n 1 "$work/err")" "$header")" "and first"
last=$(tr '\r' '\n' < "$work/err" | grep -v '^$' | tail -n 1)
bytes=$(( $(cat "$src"/f[1-9].txt "$src"/f10.txt | wc -c) ))
check "$(printf '%s\n' "$last" | grep -q "^100 --  *$bytes  *0  *10  *0 " && echo ok)" \
  "the last line is complete: 100%, $bytes bytes, ten started, none live ($last)"
check "$([ "$(tail -c 1 "$work/err" | od -An -c | tr -d ' ')" = '\n' ] && echo ok)" \
  "and ends with a newline"
check "$(is "$(tr -cd '\n' < "$work/err" | wc -c | tr -d ' ')" 2)" \
  "and there is no other newline"

# -# is ignored: the same line, and no bar.  -s and --no-progress-meter draw
# nothing, and the files still arrive.
fresh
"$TWIST" -Z -# -o 'out#1' "$u/f[1-10].txt" 2>"$work/err"; st=$?
check "$(is "$st" 0)" "-Z -#: status 0 ($st)"
check "$(grep -q '^DL% UL%' "$work/err" && ! grep -q '#' "$work/err" && echo ok)" \
  "-Z -# draws the line and not the bar"
for opt in -s --no-progress-meter; do
  fresh
  "$TWIST" -Z $opt -o 'out#1' "$u/f[1-10].txt" 2>"$work/err"; st=$?
  check "$(is "$st" 0)" "-Z $opt: status 0 ($st)"
  check "$([ ! -s "$work/err" ] && echo ok)" "-Z $opt draws nothing"
  check "$(is "$(cat out10 2>/dev/null)" content-10)" "-Z $opt: the files arrive"
done

# A body that goes to a terminal is not mixed with the line: when any URL has
# no file of its own, nothing is drawn.  A terminal is needed to see it.
if command -v script >/dev/null 2>&1; then
  fresh
  script -qec "'$TWIST' -Z -o out1 '$u/f1.txt' '$u/f2.txt' 2>'$work/err'" /dev/null >/dev/null 2>&1
  check "$([ ! -s "$work/err" ] && echo ok)" "-Z with a body to the terminal draws nothing"
  fresh
  script -qec "'$TWIST' -Z -o out1 '$u/f1.txt' -o out2 '$u/f2.txt' 2>'$work/err'" /dev/null >/dev/null 2>&1
  check "$(grep -q '^DL% UL%' "$work/err" && echo ok)" \
    "-Z with every body in a file draws the line even on a terminal"
fi

# The long names, and a cap of one.
fresh
"$TWIST" --parallel --parallel-max 1 -o 'out#1' "$u/f[1-10].txt" 2>/dev/null; st=$?
check "$(is "$st" 0)" "--parallel --parallel-max 1: status 0 ($st)"
check "$(is "$(cat out10 2>/dev/null)" content-10)" "a cap of one still gets every file"

# The status is that of the failure, though good transfers come after it.
fresh
"$TWIST" -Z -s -S "$u/f1.txt" -o o1 "$u/none" -o o2 "$u/f3.txt" -o o3 2>/dev/null; st=$?
check "$(is "$st" 37)" "-Z: a failure among good URLs is the status ($st)"
check "$(is "$(cat o1 o3 2>&1)" "$(printf 'content-1\ncontent-3')")" \
  "-Z: the good ones arrive"
fresh
"$TWIST" -Z -s -S "$u/none" -o o2 "$u/f3.txt" -o o3 2>/dev/null; st=$?
check "$(is "$st" 37)" "-Z: a failure first is the status ($st)"
fresh
"$TWIST" -Z -s -S "$u/f1.txt" -o o1 --next "$u/none" -o o2 --next "$u/f3.txt" -o o3 \
  2>/dev/null; st=$?
check "$(is "$st" 37)" "-Z carries over --next, and the status is the failure ($st)"
check "$(is "$(cat o1 o3 2>&1)" "$(printf 'content-1\ncontent-3')")" \
  "-Z across --next: the good ones arrive"

# --fail-early: the failure is the status, and each transfer it ends is
# told so, once.
fresh
"$TWIST" -Z --fail-early -S -s "$u/none" -o o0 "$u/f[1-10].txt" -o 'out#1' \
  2>"$work/err"; st=$?
check "$(is "$st" 37)" "-Z --fail-early: the failure is the status ($st)"
count=$(grep -c "$aborted" "$work/err")
check "$([ "$count" -le 10 ] && echo ok)" \
  "-Z --fail-early: at most one abort message for each of ten ($count)"
other=$(grep -v "$aborted" "$work/err" | grep -vc "could not open file")
check "$(is "$other" 0)" "-Z --fail-early: nothing else is said"
fresh
"$TWIST" -Z -s -S "$u/f1.txt" -o o1 2>"$work/err"; st=$?
check "$(is "$st" 0)" "-Z with one URL ($st)"

# Standard input goes to one transfer.  A transfer that would read it, after
# one that does, is refused and the status is 2, whatever becomes of the
# first.  file:// takes no upload and just reads the file, so what a transfer
# does with the input is not looked at here, only that the second is refused
# before it is made.
fresh
echo input | "$TWIST" -Z -S -s -T - "$u/f1.txt" -T - "$u/f2.txt" \
  >/dev/null 2>"$work/err"; st=$?
check "$(is "$st" 2)" "-Z with two readers of standard input: status 2 ($st)"
check "$(is "$(grep -c "$msg" "$work/err")" 1)" "-Z with two readers: the message, once"
fresh
echo input | "$TWIST" -S -s -T - "$u/f1.txt" -T - "$u/f2.txt" \
  >/dev/null 2>"$work/err"; st=$?
check "$([ "$st" != 2 ] && echo ok)" "without -Z two readers are not refused ($st)"
check "$(is "$(grep -c "$msg" "$work/err")" 0)" "without -Z there is no message"
# A telnet session reads standard input too, with or without -T -.  Nothing
# listens on port 1, and the second is refused before it could connect.
fresh
"$TWIST" -Z -S -s telnet://127.0.0.1:1/ telnet://127.0.0.1:1/ </dev/null 2>"$work/err"; st=$?
check "$(is "$st" 2)" "-Z with two telnet URLs: status 2 ($st)"
check "$(is "$(grep -c "$msg" "$work/err")" 1)" "-Z with two telnet URLs: the message, once"
"$TWIST" -S -s telnet://127.0.0.1:1/ telnet://127.0.0.1:1/ </dev/null 2>"$work/err"; st=$?
check "$(is "$st" 7)" "without -Z two telnet URLs both try to connect ($st)"
check "$(is "$(grep -c "$msg" "$work/err")" 0)" "without -Z there is no message for telnet"
# One reader and some that read files is fine.
fresh
"$TWIST" -Z -S -s -o o1 "$u/f1.txt" -o o2 "$u/f2.txt" telnet://127.0.0.1:1/ \
  </dev/null 2>"$work/err"; st=$?
check "$(is "$st" 7)" "-Z with one reader of standard input is not refused ($st)"
check "$(is "$(cat o1 o2 2>&1)" "$(printf 'content-1\ncontent-2')")" \
  "and the others arrive"

# The limits: a cap below one or above 300 is brought into range, not refused;
# a value that is not a number is a bad command line.
for opt in "--parallel-max 0" "--parallel-max 1000" "--parallel-max 300" \
           "--parallel-max-host 0" "--parallel-max-host 100000" \
           "--parallel-immediate" "--no-parallel-immediate" "--no-parallel"; do
  fresh
  "$TWIST" -Z $opt -s -S -o 'out#1' "$u/f[1-3].txt" 2>/dev/null; st=$?
  check "$(is "$st" 0)" "-Z $opt is accepted ($st)"
  check "$(is "$(cat out3 2>/dev/null)" content-3)" "-Z $opt: the files arrive"
done
"$TWIST" -Z --parallel-max lots -s -S "$u/f1.txt" 2>/dev/null; st=$?
check "$(is "$st" 2)" "--parallel-max with a word is status 2 ($st)"
"$TWIST" -Z --parallel-max -3 -s -S "$u/f1.txt" 2>/dev/null; st=$?
check "$(is "$st" 2)" "--parallel-max with a negative number is status 2 ($st)"
fresh
"$TWIST" -Z --no-parallel -s -S "$u/f1.txt" -o o1 "$u/none" -o o2 "$u/f3.txt" -o o3 \
  2>/dev/null; st=$?
check "$(is "$st" 0)" "--no-parallel is serial again: the last transfer's status ($st)"

[ $fail = 0 ]
