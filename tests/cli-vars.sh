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
# Variables on the command line, with file:// URLs so that no network is
# needed.  test-vars has the rules for the expansion; this is how the tool uses
# them: --variable, --expand- on an option, the order things happen in, and
# what is said when it goes wrong.

TWIST=${TWIST:-../src/twist}
[ -x "$TWIST" ] || { echo "cli-vars: twist is not built ($TWIST); skipping" >&2; exit 77; }
TWIST=$(cd "$(dirname "$TWIST")" && pwd)/$(basename "$TWIST")

work=$(mktemp -d "${TMPDIR:-/tmp}/twist-vars.XXXXXX") || exit 77
trap 'rm -rf "$work"' EXIT INT TERM
echo hostname > "$work/page.txt"
u="file://$work/page.txt"

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
# What --expand-write-out makes of its parameter, for the given variables.
w () { "$TWIST" -s -S -o /dev/null "$@" "$u"; }

# The basics.
check "$([ "$(w --variable v=hello --expand-write-out '[{{v}}]')" = '[hello]' ] && echo ok)" "a variable"
check "$([ "$(w --variable v=hello --variable v=again --expand-write-out '[{{v}}]')" = '[again]' ] && echo ok)" "defined again"
check "$([ "$(w --expand-write-out '[{{nothere}}]')" = '[]' ] && echo ok)" "undefined is empty"
check "$([ "$(w --variable v=x --expand-write-out '[{{v}}{{v}}]')" = '[xx]' ] && echo ok)" "twice"
check "$([ "$(w --variable v=x --expand-write-out '[\{{v}}]')" = '[{{v}}]' ] && echo ok)" "a backslash makes {{ plain"
check "$([ "$(w --variable v=x --write-out '[{{v}}]')" = '[{{v}}]' ] && echo ok)" "without --expand- nothing is expanded"
check "$([ "$(w --variable v=x --expand-write-out='[{{v}}]')" = '[x]' ] && echo ok)" "--expand-option=value"
check "$([ "$(w --variable v=a=b --expand-write-out '{{v}}')" = 'a=b' ] && echo ok)" "an = in the content"

# Functions.
check "$([ "$(w --variable 'v=  pad  ' --expand-write-out '[{{v:trim}}]')" = '[pad]' ] && echo ok)" "trim"
check "$([ "$(w --variable 'v=a"b' --expand-write-out '{{v:json}}')" = 'a\"b' ] && echo ok)" "json"
check "$([ "$(w --variable 'v=a b/c' --expand-write-out '{{v:url}}')" = 'a%20b%2Fc' ] && echo ok)" "url"
check "$([ "$(w --variable 'v=hello' --expand-write-out '{{v:b64}}')" = 'aGVsbG8=' ] && echo ok)" "b64"
check "$([ "$(w --variable 'v=aGVsbG8=' --expand-write-out '{{v:64dec}}')" = 'hello' ] && echo ok)" "64dec"
check "$([ "$(w --variable 'v= hi ' --expand-write-out '{{v:trim:b64}}')" = 'aGk=' ] && echo ok)" "trim:b64"
check "$([ "$(w --variable 'v= hi ' --expand-write-out '{{v:trim,b64}}')" = 'aGk=' ] && echo ok)" "trim,b64"

# A file, and standard input.
printf '  from a file \n' > "$work/v.txt"
check "$([ "$(w --variable "f@$work/v.txt" --expand-write-out '[{{f:trim}}]')" = '[from a file]' ] && echo ok)" "name@file"
check "$([ "$(echo piped | w --variable 'f@-' --expand-write-out '[{{f:trim}}]')" = '[piped]' ] && echo ok)" "name@- is standard input"

# The environment.
check "$([ "$(TWIST_T_VAR=fromenv w --variable '%TWIST_T_VAR' --expand-write-out '{{TWIST_T_VAR}}')" = fromenv ] && echo ok)" "%name"
check "$([ "$(w --variable '%TWIST_T_NOPE=dflt' --expand-write-out '{{TWIST_T_NOPE}}')" = dflt ] && echo ok)" "%name=default"
check "$([ "$(TWIST_T_VAR=fromenv w --variable '%TWIST_T_VAR=dflt' --expand-write-out '{{TWIST_T_VAR}}')" = fromenv ] && echo ok)" "the environment before the default"
"$TWIST" -s -S -o /dev/null --variable '%TWIST_T_NOPE' "$u" 2> "$work/err"
rc=$?
check "$([ $rc -eq 2 ] && grep -q 'option --variable' "$work/err" && grep -q TWIST_T_NOPE "$work/err" && echo ok)" "%name that is not set: 2 (exit $rc)"

# Other options: the URL, the name of the output file.
check "$([ "$("$TWIST" -s -S --variable p=page --expand-url "file://$work/{{p}}.txt")" = hostname ] && echo ok)" "--expand-url"
check "$([ "$("$TWIST" -s -S --variable p=page --url "$u")" = hostname ] && echo ok)" "--url"
( cd "$work" && "$TWIST" -s -S --variable n=out --expand-output '{{n}}_file.txt' "$u" )
check "$([ "$(cat "$work/out_file.txt")" = hostname ] && echo ok)" "--expand-output"
check "$([ "$("$TWIST" -s -S -o /dev/null --variable p=page --expand-url "file://$work/{{p}}.txt" -w 'u=%{url_effective}' | sed "s|$work||")" = 'u=file:///page.txt' ] && echo ok)" "the URL that is fetched"

# Order: a variable is what it is where it is used.
check "$([ "$(w --expand-write-out '[{{v}}]' --variable v=late)" = '[]' ] && echo ok)" "used before it is defined"
check "$([ "$(w --variable v=one --expand-write-out '[{{v}}]' --variable v=two --expand-write-out '[{{v}}]')" = '[two]' ] && echo ok)" "the last --expand-write-out is the one"
check "$([ "$(w --variable v=Z --expand-variable 'w=pre{{v}}post' --expand-write-out '{{w}}')" = preZpost ] && echo ok)" "--expand-variable"
check "$([ "$(w --variable p="$work" --expand-variable 'f@{{p}}/v.txt' --expand-write-out '[{{f:trim}}]')" = '[from a file]' ] && echo ok)" "--expand-variable with a file named by a variable"
check "$([ "$(w --variable a='{{b}}' --variable b=B --expand-write-out '{{a}}')" = '{{b}}' ] && echo ok)" "content is not expanded again"

# They last across --next.
out=$("$TWIST" -s -S -o /dev/null --variable v=one --expand-write-out '[1:{{v}}]' "$u" --next -o /dev/null --expand-write-out '[2:{{v}}]' "$u")
check "$([ "$out" = '[1:one][2:one]' ] && echo ok)" "--next keeps the variables"

# What a pattern in a URL makes of an expanded one: globbing is done after.
check "$([ "$("$TWIST" -s -S --variable s='{page,page}' --expand-url "file://$work/{{s}}.txt" | tr '\n' ' ')" = 'hostname hostname ' ] && echo ok)" "an expanded URL is globbed"
check "$([ "$("$TWIST" -s -S --variable s='{page,page}' --expand-url "file://$work/{{s:url}}.txt" 2>/dev/null; echo $?)" != 0 ] && echo ok)" "url keeps braces out of a glob"

# Errors: exit 2 and which option and why.
"$TWIST" -s -S -o /dev/null --variable v=x --expand-write-out '{{v:nosuch}}' "$u" 2> "$work/err"
rc=$?
check "$([ $rc -eq 2 ] && grep -q 'option --expand-write-out' "$work/err" && grep -q nosuch "$work/err" && echo ok)" "an unknown function: 2 (exit $rc)"
"$TWIST" -s -S -o /dev/null --variable 'a-b=1' "$u" 2> "$work/err"
rc=$?
check "$([ $rc -eq 2 ] && grep -q 'option --variable' "$work/err" && grep -q 'a-b' "$work/err" && echo ok)" "a bad name: 2 (exit $rc)"
"$TWIST" -s -S -o /dev/null --variable novalue "$u" 2> "$work/err"
rc=$?
check "$([ $rc -eq 2 ] && echo ok)" "a name with no value: 2 (exit $rc)"
"$TWIST" -s -S -o /dev/null --variable "f@$work/nothere" "$u" 2> "$work/err"
rc=$?
check "$([ $rc -eq 26 ] && grep -q 'option --variable' "$work/err" && echo ok)" "a file that cannot be read: 26 (exit $rc)"
printf 'a\0b' > "$work/nul.bin"
"$TWIST" -s -S -o /dev/null --variable "n@$work/nul.bin" --expand-write-out '{{n}}' "$u" 2> "$work/err"
rc=$?
check "$([ $rc -eq 2 ] && grep -q NUL "$work/err" && echo ok)" "a NUL not encoded: 2 (exit $rc)"
check "$([ "$(w --variable "n@$work/nul.bin" --expand-write-out '{{n:b64}}')" = YQBi ] && echo ok)" "a NUL encoded"
"$TWIST" -s -S -o /dev/null --expand-silent "$u" 2> "$work/err"
rc=$?
check "$([ $rc -eq 2 ] && echo ok)" "--expand- on a flag: 2 (exit $rc)"
"$TWIST" -s -S -o /dev/null --expand-nosuchoption x "$u" 2> "$work/err"
rc=$?
check "$([ $rc -eq 2 ] && echo ok)" "--expand- on an option that is none: 2 (exit $rc)"
"$TWIST" -s -S -o /dev/null --expand-write-out "$u" 2> "$work/err"
rc=$?
check "$([ $rc -eq 2 ] && echo ok)" "--expand- with no parameter: 2 (exit $rc)"
# Nothing is transferred when an option is wrong.
"$TWIST" -s -S --variable v=x --expand-write-out '{{v:nosuch}}' "$u" > "$work/stdout" 2>/dev/null
check "$([ ! -s "$work/stdout" ] && echo ok)" "nothing is fetched after a bad option"

[ $fail -eq 0 ] || exit 1
exit 0
