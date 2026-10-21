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
# Fuzzing the parsers.  The library is compiled again with AddressSanitizer,
# UndefinedBehaviorSanitizer and edge coverage (gcc's trace-pc), and each
# harness is linked with it and with fuzz/engine.c, a small coverage-guided
# fuzzer.  Nothing here is part of 'make check'.
#
#   fuzz.sh list                       the targets
#   fuzz.sh build [TARGET...]          compile
#   fuzz.sh run [-t SECONDS] [-l] [TARGET...]
#                                      fuzz each for SECONDS (default 30);
#                                      a crash is saved in fuzz-build/artifacts.
#                                      -l also looks for leaks, which every
#                                      harness is written not to have
#   fuzz.sh replay TARGET FILE...      run a saved input again
#   fuzz.sh regress [TARGET...]        run the inputs in fuzz/regress, which
#                                      once found a bug, with leaks checked
#   fuzz.sh clean                      remove fuzz-build
#
# The tree must be configured and built (make).  FUZZ_BUILD names another
# directory for the work; CC another compiler.

here=$(cd "$(dirname "$0")" && pwd)
top=$(dirname "$here")
out=${FUZZ_BUILD:-$top/fuzz-build}
CC=${CC:-gcc}

SAN="-fsanitize=address,undefined -fno-sanitize-recover=undefined -fno-omit-frame-pointer"
COV="-fsanitize-coverage=trace-pc"

targets ()
{
  for f in "$here"/harness-*.c; do
    n=${f##*/harness-}
    echo "${n%.c}"
  done
}

die () { echo "fuzz: $*" >&2; exit 1; }

build_lib ()
{
  mkdir -p "$out/obj"
  srcs=$(make -s --no-print-directory -C "$top/src" print-sources) || die "run make first"
  cflags=$(make -s --no-print-directory -C "$top/src" print-cflags)
  for s in $srcs; do
    case $s in *.c) ;; *) continue ;; esac
    o="$out/obj/lib-$(echo "${s%.c}" | tr / _).o"
    if [ ! -f "$o" ] || [ "$top/src/$s" -nt "$o" ] || [ "$top/src/twist-int.h" -nt "$o" ]; then
      # The flags are relative to src, where make was asked for them.
      (cd "$top/src" && $CC $cflags -O1 -g $SAN $COV -c "$s" -o "$o") || die "cannot compile $s"
    fi
  done
}

# The libraries the objects need.
libs ()
{
  make -s --no-print-directory -C "$top/src" print-libs
}

build_target ()
{
  t=$1
  [ -f "$here/harness-$t.c" ] || die "no target $t"
  cflags=$(make -s --no-print-directory -C "$top/src" print-cflags)
  mkdir -p "$out/bin"
  # The engine and the harness are not instrumented: only the library is.
  (cd "$top/src" && $CC $cflags -O1 -g $SAN -c "$here/engine.c" -o "$out/obj/engine.o") || die "engine"
  (cd "$top/src" && $CC $cflags -I"$here" -O1 -g $SAN -c "$here/harness-$t.c" -o "$out/obj/harness-$t.o") || die "cannot compile harness-$t.c"
  $CC $SAN "$out/obj/harness-$t.o" "$out/obj/engine.o" "$out"/obj/lib-*.o \
    $(libs) -lpthread -o "$out/bin/fuzz-$t" || die "cannot link $t"
}

runtime ()
{
  libdirs=$(pkg-config --variable=libdir quickstep 2>/dev/null):$(pkg-config --variable=libdir foxtrot 2>/dev/null)
  LD_LIBRARY_PATH="$libdirs:$LD_LIBRARY_PATH"
  export LD_LIBRARY_PATH
}

cmd=${1:-help}
[ $# -gt 0 ] && shift
case $cmd in
list)
  targets
  ;;
build)
  build_lib
  for t in ${*:-$(targets)}; do build_target "$t"; done
  ;;
run)
  secs=30
  leaks=
  while [ $# -gt 0 ]; do
    case $1 in
      -t) secs=$2; shift 2 ;;
      -l) leaks=1; shift ;;
      *) break ;;
    esac
  done
  build_lib
  runtime
  if [ -n "$leaks" ]; then
    ASAN_OPTIONS="detect_leaks=1:$ASAN_OPTIONS"
    export ASAN_OPTIONS
  fi
  status=0
  for t in ${*:-$(targets)}; do
    build_target "$t"
    mkdir -p "$out/corpus/$t" "$out/artifacts/$t"
    echo "== $t ($secs s)"
    "$out/bin/fuzz-$t" -max_total_time="$secs" -corpus="$out/corpus/$t" \
      -artifact_dir="$out/artifacts/$t" ${leaks:+-leak_check=500} 2>&1 | tail -n 25
    if [ -n "$(ls "$out/artifacts/$t" 2>/dev/null)" ]; then
      echo "== $t: INPUTS THAT FAILED are in $out/artifacts/$t"
      status=1
    fi
  done
  exit $status
  ;;
replay)
  t=$1; shift
  [ -n "$t" ] || die "replay TARGET FILE..."
  build_lib
  build_target "$t"
  runtime
  "$out/bin/fuzz-$t" "$@"
  ;;
regress)
  build_lib
  runtime
  ASAN_OPTIONS="detect_leaks=1:$ASAN_OPTIONS"
  export ASAN_OPTIONS
  status=0
  for t in ${*:-$(ls "$here/regress" 2>/dev/null)}; do
    [ -d "$here/regress/$t" ] || continue
    build_target "$t"
    for f in "$here/regress/$t"/*; do
      if "$out/bin/fuzz-$t" "$f" >"$out/regress.log" 2>&1; then
        echo "ok   $t/${f##*/}"
      else
        echo "FAIL $t/${f##*/}"
        tail -n 20 "$out/regress.log"
        status=1
      fi
    done
  done
  exit $status
  ;;
clean)
  rm -rf "$out"
  ;;
*)
  sed -n '/^# Fuzzing/,/^# directory/p' "$0" | sed 's/^# \{0,1\}//'
  ;;
esac
