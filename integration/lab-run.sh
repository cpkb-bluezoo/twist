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

# Runs inside the lab container (the "integration" stage of ci/Dockerfile):
# the integration tests, with a skip counted as a failure.  On a developer's
# machine a missing peer skips a test, which is right; in the lab every peer is
# installed, so a skip means the lab is broken or a test has stopped running.
# Names in LAB_ALLOW_SKIP (space separated, as in "http3-zone.sh") may skip.
# Two do by default: skip-network.sh is a placeholder that always skips, and
# http3-zone.sh needs a link-local IPv6 address on loopback, which a container
# without a network does not have.

LAB_ALLOW_SKIP="skip-network.sh http3-zone.sh $LAB_ALLOW_SKIP"

cd "$(dirname "$0")/.." || exit 1
make -C integration check "$@"
status=$?
summary=integration/test-suite.log
[ -f "$summary" ] || { echo "lab: no $summary" >&2; exit 1; }

bad=
for t in integration/*.trs; do
  grep -q '^:test-result: SKIP' "$t" || continue
  name=$(basename "$t" .trs)
  case " $LAB_ALLOW_SKIP " in
    *" $name "*) ;;
    *) bad="$bad $name" ;;
  esac
done
if [ -n "$bad" ]; then
  echo "lab: skipped, and the lab has every peer:$bad" >&2
  status=1
fi
exit $status
