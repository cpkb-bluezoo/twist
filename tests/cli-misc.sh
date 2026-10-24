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
# Small things about the tool and the file scheme that are not about any one
# other part, on file:// URLs so that no network is needed: what --help says
# about -k, the mode of directories --create-dirs makes, -O with a name of "-",
# a range and percent-encoding on a file URL, and a file that is not a file.
# The telnet options are checked here too: a bad one ends the transfer before
# it connects, so nothing needs to be listening.

TWIST=${TWIST:-../src/twist}
[ -x "$TWIST" ] || { echo "cli-misc: twist is not built ($TWIST); skipping" >&2; exit 77; }
TWIST=$(cd "$(dirname "$TWIST")" && pwd)/$(basename "$TWIST")

work=$(mktemp -d "${TMPDIR:-/tmp}/twist-misc.XXXXXX") || exit 77
trap 'rm -rf "$work"' EXIT INT TERM
src="$work/src"
mkdir -p "$src" "$work/out"
printf '0123456789' > "$src/digits"
printf 'spaced' > "$src/sp ace.txt"
printf 'dash' > "$src/-"
printf 'a' > "$src/a.txt"

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
t () { "$TWIST" -s -S "$@" 2>/dev/null; }

# --help tells the truth about -k: it turns the check off.  It said that
# certificates were still checked.
line=$("$TWIST" --help | grep -A2 -e '--insecure')
case $line in
  *"still checked"*) check bad "--help says certificates are still checked with -k" ;;
esac
check "$(printf %s "$line" | grep -qi 'do not check\|not verif' && echo ok)" \
  "--help says -k turns the check off"

# Directories made for -o are 0750 as curl's are, and not 0777 less the mask:
# the tree of a download is not for everyone.
(umask 000; "$TWIST" -s --create-dirs -o "$work/d1/d2/out.txt" "file://$src/a.txt")
mode=$(stat -c %a "$work/d1" 2>/dev/null || stat -f %Lp "$work/d1" 2>/dev/null)
check "$(is "$mode" 750)" "--create-dirs makes directories 0750 (got $mode)"
mode=$(stat -c %a "$work/d1/d2" 2>/dev/null || stat -f %Lp "$work/d1/d2" 2>/dev/null)
check "$(is "$mode" 750)" "all of them (got $mode)"

# -O names the file for the last part of the URL, and for a part that is "-"
# that is a file called "-", not standard output.  -o - is standard output.
cd "$work/out" || exit 77
out=$("$TWIST" -s -O "file://$src/-" 2>/dev/null)
check "$(is "$out" "")" "-O with a name of - writes nothing to standard output"
check "$([ -f ./- ] && [ "$(cat ./-)" = dash ] && echo ok)" \
  "and makes a file called -"
rm -f ./-
check "$(is "$("$TWIST" -s -o - "file://$src/a.txt" 2>/dev/null)" a)" \
  "-o - is standard output"

# A range of a file, as for any other scheme.  It was ignored, and the whole
# file came.
check "$(is "$(t -r 2-5 "file://$src/digits")" 2345)" "-r 2-5"
check "$(is "$(t -r 7- "file://$src/digits")" 789)" "-r 7-"
check "$(is "$(t -r -3 "file://$src/digits")" 789)" "-r -3, the last three"
check "$(is "$(t -r 0-0 "file://$src/digits")" 0)" "-r 0-0, one byte"
check "$(is "$(t -r 8-99 "file://$src/digits")" 89)" "a range past the end stops at it"
t -r 20-30 "file://$src/digits" >/dev/null; st=$?
check "$(is "$st" 33)" "a range that starts past the end is status 33 ($st)"
t -r abc "file://$src/digits" >/dev/null; st=$?
check "$(is "$st" 33)" "a range that is not one is status 33 ($st)"

# A path is percent-decoded, as curl's is, and a NUL is no part of a name.
check "$(is "$(t "file://$src/sp%20ace.txt")" spaced)" "%20 in a file URL"
t "file://$src/a.txt%00.png" >/dev/null; st=$?
check "$(is "$st" 3)" "%00 in a file URL is a malformed URL ($st)"

# A file that is not a regular file is refused, and not waited on.  A FIFO
# with nobody writing blocked the open, for ever, and --max-time did not end
# it.
mkfifo "$work/fifo" 2>/dev/null && {
  timeout 10 "$TWIST" -s --max-time 2 "file://$work/fifo" >/dev/null 2>&1
  st=$?
  check "$([ "$st" != 124 ] && [ "$st" != 0 ] && echo ok)" \
    "a FIFO is refused, not waited on (status $st)"
}

# A telnet option that is not written as it must be is status 49, and one that
# is not an option is 48, both before there is a connection (nothing listens
# on port 1).  Which one is said, and a value that is not ASCII is skipped.
telnet_status ()
{
  "$TWIST" -s -S "$@" telnet://127.0.0.1:1/ </dev/null 2>"$work/err"
  st=$?
}
telnet_status -t foo
check "$(is "$st" 49)" "-t foo is status 49 ($st)"
check "$(grep -q 'foo' "$work/err" && echo ok)" "-t foo says which option"
telnet_status -t WS=bad
check "$(is "$st" 49)" "-t WS=bad is status 49 ($st)"
telnet_status -t WS=0x5
check "$(is "$st" 49)" "-t WS=0x5 is status 49 ($st)"
telnet_status -t FOO=bar
check "$(is "$st" 48)" "-t FOO=bar is status 48 ($st)"
check "$(grep -q 'FOO=bar' "$work/err" && echo ok)" "-t FOO=bar says which option"
telnet_status -t TTYPE=vt100 -t WS=80x24 -t NEW_ENV=A,B -t XDISPLOC=h:0 -t BINARY=0
check "$(is "$st" 7)" "good options go on to connect, and fail there ($st)"
telnet_status --telnet-option ws=80X24
check "$(is "$st" 7)" "--telnet-option, in either case ($st)"
telnet_status -t "TTYPE=caf$(printf '\303\251')"
check "$(is "$st" 7)" "a value with a byte above 127 is skipped ($st)"

# -d is not sent to a telnet server, and does not turn it into anything else.
telnet_status -d hello
check "$(is "$st" 7)" "-d with a telnet URL ($st)"

[ $fail = 0 ]
