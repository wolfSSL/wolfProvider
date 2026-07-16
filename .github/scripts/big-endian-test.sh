#!/bin/bash
# big-endian-test.sh
#
# Copyright (C) 2006-2025 wolfSSL Inc.
#
# This file is part of wolfProvider.
#
# wolfProvider is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# wolfProvider is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with wolfProvider. If not, see <http://www.gnu.org/licenses/>.
#
# Runs the standard build and unit tests on a big-endian target. Meant to
# run inside an s390x container; the test-deps image is amd64-only, so the
# toolchain is installed here instead.

set -euo pipefail

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y --no-install-recommends \
    autoconf automake build-essential ca-certificates git libtool make \
    perl pkg-config

# Fail loudly rather than silently retesting x86-64 if the qemu platform
# selection ever regresses.
cat > /tmp/endian-check.c <<'EOF'
int main(void)
{
#if !defined(__BYTE_ORDER__) || (__BYTE_ORDER__ != __ORDER_BIG_ENDIAN__)
#error "not a big-endian target"
#endif
    return 0;
}
EOF
gcc -o /tmp/endian-check /tmp/endian-check.c
/tmp/endian-check
echo "confirmed big-endian target: $(uname -m)"

exec ./scripts/build-wolfprovider.sh
