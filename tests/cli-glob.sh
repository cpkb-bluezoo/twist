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
# URL globbing on the command line, with file:// URLs so that no network is
# needed.  The library (test-glob) has the rules; this is how the tool uses
# them: the pairing of URLs with -o, #1 in an output name, -O, -g, and errors.

TWIST=${TWIST:-../src/twist}
[ -x "$TWIST" ] || { echo "cli-glob: twist is not built ($TWIST); skipping" >&2; exit 77; }
# The tests change directory, so the path must not be relative.
TWIST=$(cd "$(dirname "$TWIST")" && pwd)/$(basename "$TWIST")

work=$(mktemp -d "${TMPDIR:-/tmp}/twist-glob.XXXXXX") || exit 77
trap 'rm -rf "$work"' EXIT INT TERM
src="$work/src"
mkdir -p "$src/x" "$src/y" "$work/out"
for f in a b c; do echo "content-$f" > "$src/$f.txt"; done
for d in x y; do for n in 1 2; do echo "$d$n" > "$src/$d/$n.txt"; done; done
u="file://$src"

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
t () { "$TWIST" -s -S "$@"; }
in_out () { cd "$work/out" && rm -rf ./* && "$@"; }

# A set, and #1 in the name of the file.
in_out t -o 'n_#1.out' "$u/{a,b}.txt"
check "$([ "$(cat "$work/out/n_a.out")" = content-a ] && [ "$(cat "$work/out/n_b.out")" = content-b ] && echo ok)" "a set, and #1"

# Two globs, #1 and #2, in either order and more than once.
in_out t -o 'n_#1_#2.out' "$u/{x,y}/[1-2].txt"
check "$([ "$(ls "$work/out" | tr '\n' ' ')" = 'n_x_1.out n_x_2.out n_y_1.out n_y_2.out ' ] && [ "$(cat "$work/out/n_y_2.out")" = y2 ] && echo ok)" "two globs"
in_out t -o '#2-#1-#2.out' "$u/{x,y}/[1-2].txt"
check "$([ -f "$work/out/1-x-1.out" ] && [ -f "$work/out/2-y-2.out" ] && echo ok)" "#2 before #1, and twice"

# A number that is no glob is text, and so is a # with none.
in_out t -o 'n_#2_#0_#.out' "$u/{a,b}.txt"
check "$([ -f "$work/out/n_#2_#0_#.out" ] && echo ok)" "#2 of one glob, #0 and # alone stay"

# Without a template every URL writes the same file: the last is what is left.
in_out t -o same.out "$u/{a,b}.txt"
check "$([ "$(cat "$work/out/same.out")" = content-b ] && echo ok)" "one name for all"

# -O names each from its own URL.
in_out t -O "$u/{a,b}.txt"
check "$([ -f "$work/out/a.txt" ] && [ -f "$work/out/b.txt" ] && echo ok)" "-O"

# On standard output they follow one another.
check "$([ "$(t "$u/[a-c].txt" | tr '\n' ' ')" = 'content-a content-b content-c ' ] && echo ok)" "a range on standard output"

# An -o goes with a URL, not with each thing it makes: the next URL has the
# next -o.
in_out t "$u/{a,b}.txt" "$u/c.txt" -o 'n_#1.out' -o single.out
check "$([ -f "$work/out/n_a.out" ] && [ -f "$work/out/n_b.out" ] && [ "$(cat "$work/out/single.out")" = content-c ] && echo ok)" "-o and the URL it goes with"

# -g turns it off: the braces are in the name, which is not there.
in_out t -g -o n.out "$u/{a,b}.txt" 2>/dev/null
rc=$?
check "$([ $rc -ne 0 ] && [ ! -s "$work/out/n.out" ] && echo ok)" "-g (exit $rc)"

# The URLs, as written out.
check "$([ "$(t -o /dev/null -w '%{url_effective}\n' "$u/{a,b}.txt" | sed "s|$src||" | tr '\n' ' ')" = 'file:///a.txt file:///b.txt ' ] && echo ok)" "url_effective of each"

# An IPv6 address is not a range, and each URL is tried.
out=$(t -o /dev/null --connect-timeout 1 -w '%{url_effective}\n' 'http://[::1]:1/{x,y}' 2>/dev/null)
check "$([ "$out" = "$(printf 'http://[::1]:1/x\nhttp://[::1]:1/y')" ] && echo ok)" "an IPv6 address and a set"

# Failures: the status is the last transfer's, as for several URLs, and
# --fail-early stops at the first.
in_out t -o 'n_#1.out' "$u/{a,missing,b}.txt" 2>/dev/null
rc=$?
check "$([ $rc -eq 0 ] && [ -f "$work/out/n_b.out" ] && echo ok)" "all are tried, and the last one's status (exit $rc)"
in_out t -o 'n_#1.out' "$u/{a,missing}.txt" 2>/dev/null
rc=$?
check "$([ $rc -ne 0 ] && [ -f "$work/out/n_a.out" ] && echo ok)" "the last one failed (exit $rc)"
in_out t --fail-early -o 'n_#1.out' "$u/{a,missing,b}.txt" 2>/dev/null
rc=$?
check "$([ $rc -ne 0 ] && [ -f "$work/out/n_a.out" ] && [ ! -e "$work/out/n_b.out" ] && echo ok)" "--fail-early stops (exit $rc)"

# A pattern that is wrong is a malformed URL, with the place.
t -o /dev/null "$u/[3-1]" 2> "$work/err"
rc=$?
check "$([ $rc -eq 3 ] && grep -q 'bad range in URL position' "$work/err" && grep -q '\^' "$work/err" && echo ok)" "a bad range (exit $rc)"
t -o /dev/null "$u/{a,b" 2> "$work/err"
rc=$?
check "$([ $rc -eq 3 ] && grep -q 'unmatched brace' "$work/err" && echo ok)" "an open brace (exit $rc)"
# The URLs after a bad one are still done.
out=$(cd "$work/out" && rm -rf ./* && t -o 'n_#1.out' "$u/[3-1]" "$u/a.txt" 2>/dev/null)
check "$([ "$out" = content-a ] && [ -z "$(ls "$work/out")" ] && echo ok)" "the URL after a bad pattern is done"

# A very large range is not made all at once.
in_out t --fail-early -o /dev/null "$u/[1-4000000000]/[1-4000000000]" 2>/dev/null
rc=$?
check "$([ $rc -ne 0 ] && echo ok)" "a range of billions starts at once and stops at the first failure (exit $rc)"

[ $fail -eq 0 ] || exit 1
exit 0
