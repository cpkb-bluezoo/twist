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

# The integration tests in a podman container: 'make check-lab'.
#
#   integration/lab.sh                run them all
#   integration/lab.sh TESTS="ftp.sh"   run some (arguments go to make)
#   integration/lab.sh --shell        a shell in the lab, to look around
#
# The image is built from the working tree, so it holds the sources as they
# are, uncommitted changes too.  The container has no network but its own
# loopback, so a test cannot reach the real world, and each run starts clean.
# Rebuild with fresh libraries with QUICKSTEP_REF and FOXTROT_REF set.

cd "$(dirname "$0")/.." || exit 1
command -v podman >/dev/null 2>&1 || { echo "lab: podman is not installed" >&2; exit 1; }

image=twist-lab
podman build --target integration -f ci/Dockerfile \
  --build-arg "QUICKSTEP_REF=${QUICKSTEP_REF:-main}" \
  --build-arg "FOXTROT_REF=${FOXTROT_REF:-main}" \
  --build-arg "TWIST_CONFIGURE=${TWIST_CONFIGURE:-}" \
  -t "$image" . || exit 1

if [ "$1" = "--shell" ]; then
  exec podman run --rm -it --network none --user lab "$image" /bin/bash
fi
## Port 53 of the container's own loopback is for the fake nameserver of
## dns-ddr.sh; the setting is of the container's network, not the host's.
exec podman run --rm --network none \
  --sysctl net.ipv4.ip_unprivileged_port_start=0 \
  -e "LAB_ALLOW_SKIP=$LAB_ALLOW_SKIP" "$image" integration/lab-init.sh "$@"
