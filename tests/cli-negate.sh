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
# --no-OPTION, which turns a yes-or-no option off again, as curl has it, on
# file:// URLs so that no network is needed.  Every option that is a switch
# has one, the last of the two on the command line counts, and one that is
# not a switch (--next, --help, the choice of HTTP version) cannot be turned
# off and is refused.  -I is the odd one: with --no-head, in either order, it
# is an error.  What the others do to a request is in
# integration/http-negate.sh, which has a server.

TWIST=${TWIST:-../src/twist}
[ -x "$TWIST" ] || { echo "cli-negate: twist is not built ($TWIST); skipping" >&2; exit 77; }
TWIST=$(cd "$(dirname "$TWIST")" && pwd)/$(basename "$TWIST")

tmp=${TMPDIR:-/tmp}
work=$(mktemp -d "${tmp%/}/twist-negate.XXXXXX") || exit 77
trap 'rm -rf "$work"' EXIT INT TERM
src="$work/src"
mkdir -p "$src" "$work/out"
printf 'content-a' > "$src/a.txt"
printf 'content-b' > "$src/b.txt"
u="file://$src/a.txt"
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

# Each switch has a --no- form, and it is taken whether or not the switch was
# given.
for o in remote-name create-dirs get head include location fail fail-early \
         parallel parallel-immediate compressed insecure proxy-insecure ssl \
         ssl-reqd list-only ftp-create-dirs silent show-error progress-bar \
         progress-meter globoff disable doh-insecure
do
  "$TWIST" -o /dev/null "--no-$o" "$u" > /dev/null 2>&1
  check "$(is "$?" 0)" "--no-$o is taken ($?)"
done

# What is not a switch cannot be turned off.
for o in next help http1.0 http1.1 http2 http2-prior-knowledge http3 http3-only
do
  "$TWIST" -o /dev/null "--no-$o" "$u" > /dev/null 2>&1
  check "$(is "$?" 2)" "--no-$o is refused ($?)"
done

# -I and --no-head do not go together.
"$TWIST" -s -o /dev/null -I --no-head "$u" > /dev/null 2>&1
check "$(is "$?" 2)" "-I --no-head is an error ($?)"
"$TWIST" -s -o /dev/null --no-head -I "$u" > /dev/null 2>&1
check "$(is "$?" 2)" "--no-head -I is an error ($?)"
"$TWIST" -s -o /dev/null --head --no-head "$u" > /dev/null 2>&1
check "$(is "$?" 2)" "--head --no-head is an error ($?)"
"$TWIST" -s -o /dev/null -I -I "$u" > /dev/null 2>&1
check "$(is "$?" 0)" "-I twice is not ($?)"
"$TWIST" -S -o /dev/null -I --no-head "$u" 2>&1 >/dev/null | grep -q 'option --no-head: is badly used here'
check "$(is "$?" 0)" "and it is said which"

# The last of a switch and its --no- counts.  --create-dirs makes the
# directories of -o, and without it they are not there.
cd "$work/out" || exit 77
"$TWIST" -s --create-dirs --no-create-dirs -o d1/f.out "$u" > /dev/null 2>&1
check "$(is "$?" 23)" "--create-dirs --no-create-dirs: no directory made ($?)"
check "$([ ! -d d1 ] && echo ok)" "and none is there"
"$TWIST" -s --no-create-dirs --create-dirs -o d2/f.out "$u" > /dev/null 2>&1
check "$([ "$(cat d2/f.out 2>/dev/null)" = content-a ] && echo ok)" \
  "--no-create-dirs --create-dirs: it is made"

# -g turns off the braces, and --no-globoff turns them on.
pair="file://$src/{a,b}.txt"
"$TWIST" -s -g --no-globoff -o 'g1_#1' "$pair" > /dev/null 2>&1
check "$([ "$(cat g1_a 2>/dev/null)" = content-a ] && [ "$(cat g1_b 2>/dev/null)" = content-b ] && echo ok)" \
  "-g --no-globoff: the braces are a glob"
"$TWIST" -s --no-globoff -g -o 'g2_#1' "$pair" > /dev/null 2>&1
check "$([ ! -e g2_a ] && [ ! -e g2_b ] && echo ok)" \
  "--no-globoff -g: they are not"

# --fail-early stops at the first URL that fails.
out=$("$TWIST" -s --fail-early "file://$src/nope" "$u" 2>/dev/null)
check "$(is "$out" "")" "--fail-early: the second URL is not tried"
out=$("$TWIST" -s --fail-early --no-fail-early "file://$src/nope" "$u" 2>/dev/null)
check "$(is "$out" content-a)" "--fail-early --no-fail-early: it is"

# --no-silent shows what -s hid, and --no-show-error what -S would.
e=$("$TWIST" -s --no-silent -o /dev/null "$u" 2>&1)
check "$(case "$e" in ("  % Total"*) echo ok;; esac)" "-s --no-silent: the meter"
e=$("$TWIST" -s --no-silent -o /dev/null "file://$src/nope" 2>&1)
check "$(case "$e" in ("twist: (37) "*) echo ok;; esac)" "and the error"

exit $fail
