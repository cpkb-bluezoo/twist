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

# The benchmark in a container, built from the working tree: the same image as
# the workflow's (the "bench" stage of ci/Dockerfile), with twist installed
# and a curl that speaks HTTP/3.  Arguments go to bench.py.
#
#   bench/run.sh                              everything
#   bench/run.sh --only get-big --protocols h2
#   ENGINE=docker bench/run.sh                (default: podman, else docker)
#
# On a laptop other processes disturb the numbers; the workflow runs it on a
# runner that has nothing else to do.  Compare ratios, not times.

cd "$(dirname "$0")/.." || exit 1
engine=${ENGINE:-}
if [ -z "$engine" ]; then
  for e in podman docker; do
    command -v $e >/dev/null 2>&1 && { engine=$e; break; }
  done
fi
[ -n "$engine" ] || { echo "bench: neither podman nor docker is installed" >&2; exit 1; }
image=twist-bench
$engine build --target bench -f ci/Dockerfile \
  --build-arg "QUICKSTEP_REF=${QUICKSTEP_REF:-main}" \
  --build-arg "FOXTROT_REF=${FOXTROT_REF:-main}" \
  -t "$image" . || exit 1
# Memory for the files, and the host's network: no translation between the
# clients and nginx.
exec $engine run --rm --network host --shm-size "${SHM:-2g}" "$image" "$@"
