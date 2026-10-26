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


# The first thing the lab container does, as root: let the unprivileged user
# replace /etc/resolv.conf (podman makes it a file of the container's own, so
# this changes nothing on the host), then run the tests as that user.

chmod a+w /etc/resolv.conf 2>/dev/null
cd "$(dirname "$0")/.." || exit 1
exec runuser -u lab -- integration/lab-run.sh "$@"
