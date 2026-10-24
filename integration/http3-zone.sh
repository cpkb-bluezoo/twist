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

# An HTTP/3 URL takes an IPv6 zone (RFC 6874): https://[fe80::1%25lo0]/ is sent
# from, and to, the interface the zone names, and not left to the system to
# pick (which for a link-local address it cannot).  A UDP socket of python's
# listens on the link-local address of the loopback interface, and what is
# checked is that the QUIC Initial of twist arrives there.  Skips, with status
# 77, without python3 or twist, or when no loopback interface has a link-local
# IPv6 address.

TWIST=${TWIST:-../src/twist}
skip ()
{
  echo "http3-zone: $1; skipping" >&2
  exit 77
}
command -v python3 >/dev/null 2>&1 || skip "no python3"
[ -x "$TWIST" ] || skip "twist is not built ($TWIST)"

python3 - "$TWIST" <<'PY'
import socket, subprocess, sys

twist = sys.argv[1]
for name in ('lo0', 'lo'):
    try:
        index = socket.if_nametoindex(name)
    except OSError:
        continue
    s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    try:
        s.bind(('fe80::1', 0, 0, index))
    except OSError:
        s.close()
        continue
    break
else:
    sys.exit(77)
port = s.getsockname()[1]
s.settimeout(5)
p = subprocess.Popen([twist, '-s', '--http3-only', '-k', '-m', '3',
                      'https://[fe80::1%%25%s]:%d/' % (name, port)],
                     stderr=subprocess.DEVNULL)
try:
    data, addr = s.recvfrom(4096)
except OSError:
    print('FAIL no QUIC packet arrived on the zoned address', file=sys.stderr)
    p.kill()
    sys.exit(1)
p.wait()
if addr[3] != index:
    print('FAIL it came from scope %d, not %d' % (addr[3], index),
          file=sys.stderr)
    sys.exit(1)
PY
exit $?
