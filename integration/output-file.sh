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

# The file given to -o is made when there is something to put in it, as the
# curl tool does, so a transfer that fails before any of the body has come
# leaves none: not an empty one, and not one that was there truncated.  A
# transfer that succeeds with no body does make an empty file.  Needs no
# server: a refused connection and the file scheme.  Skips, with status 77,
# without twist.

TWIST=${TWIST:-../src/twist}
[ -x "$TWIST" ] || { echo "output-file: twist is not built ($TWIST); skipping" >&2; exit 77; }

work=$(mktemp -d "${TMPDIR:-/tmp}/twist-output-file.XXXXXX") || exit 77
trap 'rm -rf "$work"' EXIT INT TERM

fail=0
check ()
{
  if [ "$1" = ok ]; then :; else echo "FAIL $2" >&2; fail=1; fi
}
is () { [ "$1" = "$2" ] && echo ok; }

: > "$work/empty"
printf 'precious' > "$work/body"

"$TWIST" -s -o "$work/out1" http://127.0.0.1:1/ 2>/dev/null
check "$(is $? 7)" "a refused connection is status 7"
check "$([ ! -e "$work/out1" ] && echo ok)" "and makes no file"

printf 'kept' > "$work/out2"
"$TWIST" -s -o "$work/out2" http://127.0.0.1:1/ 2>/dev/null
check "$([ "$(cat "$work/out2")" = kept ] && echo ok)" "and leaves a file that was there alone"

"$TWIST" -s -o "$work/out3" "file://$work/nonexistent" 2>/dev/null
check "$([ $? -ne 0 ] && [ ! -e "$work/out3" ] && echo ok)" "a missing file makes no file"

"$TWIST" -s -o "$work/out4" "file://$work/empty" 2>/dev/null
check "$(is $? 0)" "an empty body is a success"
check "$([ -f "$work/out4" ] && [ ! -s "$work/out4" ] && echo ok)" "and makes an empty file"

"$TWIST" -s -o "$work/out5" "file://$work/body" 2>/dev/null
check "$([ "$(cat "$work/out5")" = precious ] && echo ok)" "a body is written"

printf 'old' > "$work/out6"
"$TWIST" -s -o "$work/out6" "file://$work/empty" 2>/dev/null
check "$([ -f "$work/out6" ] && [ ! -s "$work/out6" ] && echo ok)" "an empty success truncates a file that was there"

exit $fail
