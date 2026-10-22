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
# The progress meter and the bar of the tool, and the options that choose
# between them, with file:// URLs so that no network is needed.  test-progress
# and test-bar have the arithmetic and the drawing; this is when the tool shows
# them.  The expected text is curl's.

TWIST=${TWIST:-../src/twist}
[ -x "$TWIST" ] || { echo "cli-progress: twist is not built ($TWIST); skipping" >&2; exit 77; }
TWIST=$(cd "$(dirname "$TWIST")" && pwd)/$(basename "$TWIST")

work=$(mktemp -d "${TMPDIR:-/tmp}/twist-progress.XXXXXX") || exit 77
trap 'rm -rf "$work"' EXIT INT TERM
printf 'hostname' > "$work/page.txt"
u="file://$work/page.txt"
gone="file://$work/not-there"
# A line is a carriage return and the text.  Make the carriage returns visible.
vis () { tr '\r' '@'; }
unset COLUMNS

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

# The standard error of a command, with the body thrown away.
err () { "$@" 2>&1 >/dev/null; }

# The meter: two lines of heading, a line of progress rewritten, a newline.
e=$(err "$TWIST" -o /dev/null "$u"; echo x)
heading='  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed'
check "$(case "$e" in "$heading"*) echo ok;; esac)" "the meter has the heading"
last=$(printf '%s' "$e" | tr '\r' '\n' | tail -n 2 | head -n 1)
check "$(case "$last" in '100     8  100     8    0     0 '*) echo ok;; esac)" "the last line is 100%: $last"
check "$(case "$e" in *"
x") echo ok;; esac)" "and the line ends"
check "$(is "$(printf '%s' "$e" | tr '\r' '\n' | grep -c '^  0     8    0     0\|^  0     0    0     0')" 1)" "the first line is 0%"

# The body goes where it should whatever the meter does.
check "$(is "$("$TWIST" "$u" 2>/dev/null)" hostname)" "the body is on standard output"
check "$(is "$("$TWIST" -s "$u" 2>&1)" hostname)" "-s shows only the body"

# The bar: 60 columns are 53 of '#', a space and 5 for the percentage.
bar53=#####################################################
want="@$bar53 100.0%"
check "$(is "$(COLUMNS=60 err "$TWIST" -# -o /dev/null "$u" | vis)" "$want")" "the bar at 60 columns"
bar72=$bar53###################
check "$(is "$(err "$TWIST" -# -o /dev/null "$u" | vis)" "@$bar72 100.0%")" "the bar is 79 wide when nothing says"
check "$(is "$(COLUMNS=20 err "$TWIST" -# -o /dev/null "$u" | vis)" "@$bar72 100.0%")" "COLUMNS must be above 20"
check "$(is "$(COLUMNS=junk err "$TWIST" -# -o /dev/null "$u" | vis)" "@$bar72 100.0%")" "COLUMNS must be a number"
check "$(is "$(COLUMNS=30 err "$TWIST" --progress-bar -o /dev/null "$u" | vis)" "@####################### 100.0%")" "the long name, 30 columns"

# What switches them off, and on again.
check "$(is "$(err "$TWIST" -s -o /dev/null "$u")" "")" "-s"
check "$(is "$(err "$TWIST" --silent -o /dev/null "$u")" "")" "--silent"
check "$(is "$(err "$TWIST" --no-progress-meter -o /dev/null "$u")" "")" "--no-progress-meter"
check "$(is "$(err "$TWIST" --no-progress-meter -# -o /dev/null "$u")" "")" "--no-progress-meter and -#"
check "$(is "$(err "$TWIST" -# --no-progress-meter -o /dev/null "$u")" "")" "-# and --no-progress-meter"
check "$(is "$(err "$TWIST" -s -# -o /dev/null "$u")" "")" "-s and -#"
check "$(case "$(err "$TWIST" -s --no-silent -o /dev/null "$u")" in "$heading"*) echo ok;; esac)" "--no-silent"
check "$(case "$(err "$TWIST" --no-progress-meter --progress-meter -o /dev/null "$u")" in "$heading"*) echo ok;; esac)" "--progress-meter"
check "$(case "$(err "$TWIST" -# --no-progress-bar -o /dev/null "$u")" in "$heading"*) echo ok;; esac)" "--no-progress-bar"
check "$(is "$(COLUMNS=60 err "$TWIST" --no-progress-bar -# -o /dev/null "$u" | vis)" "$want")" "-# after --no-progress-bar"

# Errors are told with the meter off, or not, as -S says.  A file that is not
# there draws nothing.
msg="twist: (37) could not open file"
e=$(err "$TWIST" -o /dev/null "$gone")
check "$(case "$e" in "$msg"*) echo ok;; esac)" "an error without -s: $e"
check "$(is "$(err "$TWIST" -s -o /dev/null "$gone")" "")" "-s hides the error"
check "$(case "$(err "$TWIST" -s -S -o /dev/null "$gone")" in "$msg"*) echo ok;; esac)" "-s -S"
check "$(case "$(err "$TWIST" -S -s -o /dev/null "$gone")" in "$msg"*) echo ok;; esac)" "-S -s: independent"
check "$(is "$(err "$TWIST" -s -S --no-show-error -o /dev/null "$gone")" "")" "--no-show-error"
check "$(case "$(err "$TWIST" -s --no-silent -o /dev/null "$gone")" in "$msg"*) echo ok;; esac)" "--no-silent shows the error"
check "$(case "$(err "$TWIST" --no-progress-meter -o /dev/null "$gone")" in "$msg"*) echo ok;; esac)" "--no-progress-meter leaves the error"
check "$(case "$(err "$TWIST" -# -o /dev/null "$gone")" in "$msg"*) echo ok;; esac)" "-# and an error"
"$TWIST" -s -o /dev/null "$gone" 2>/dev/null
check "$(is $? 37)" "the exit status is the same"

# The settings are global: they carry past --next.
check "$(is "$(err "$TWIST" -s -o /dev/null "$u" --next -o /dev/null "$u")" "")" "-s after --next"
check "$(is "$(COLUMNS=60 err "$TWIST" -# -o /dev/null "$u" --next -o /dev/null "$u" | vis)" "$want
$want")" "-# after --next"

# --stderr takes the meter too.
"$TWIST" -o /dev/null --stderr "$work/err.txt" "$u" 2>"$work/real.txt"
check "$(is "$(cat "$work/real.txt")" "")" "nothing on standard error with --stderr"
check "$(case "$(cat "$work/err.txt")" in "$heading"*) echo ok;; esac)" "the meter is in the --stderr file"

# A meter in a pipe, as the body is not on a terminal: the meter is shown.
e=$("$TWIST" "$u" 2>&1 >/dev/null | head -n 1)
check "$(case "$e" in "  % Total"*) echo ok;; esac)" "a body in a pipe has the meter"

# The body going to a terminal hides the meter; with -o it
# does not.  This needs a terminal, which python can make.
if command -v python3 >/dev/null 2>&1; then
  tty_run () {
    python3 -I -c '
import os, pty, subprocess, sys
m, s = pty.openpty()
p = subprocess.Popen(sys.argv[1:], stdout=s, stderr=subprocess.PIPE,
                     stdin=subprocess.DEVNULL)
os.close(s)
err = p.stderr.read()
p.wait()
sys.stdout.write("meter" if b"% Total" in err else "none")
' "$@"
  }
  check "$(is "$(tty_run "$TWIST" "$u")" none)" "no meter for a body on a terminal"
  check "$(is "$(tty_run "$TWIST" -o /dev/null "$u")" meter)" "a meter with -o on a terminal"
  check "$(is "$(tty_run "$TWIST" -# "$u")" none)" "no bar for a body on a terminal"
fi

exit $fail
