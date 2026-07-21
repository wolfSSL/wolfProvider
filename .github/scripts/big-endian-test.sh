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
#
# The unit runner already continues past a failing test, so only a signal
# stops the suite. This restarts at the next case after a crash and takes a
# backtrace, so one crash does not hide the rest of the results.

set -euo pipefail

LOG_DIR=${LOG_DIR:-/wolfprov/be-logs}
RUN_LOG="${LOG_DIR}/unit-run.log"
SUMMARY="${LOG_DIR}/summary.txt"

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y --no-install-recommends \
    autoconf automake build-essential ca-certificates gdb git libtool make \
    perl pkg-config

# The workspace is bind-mounted from the runner, so its owner is not root.
git config --global --add safe.directory /wolfprov

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

mkdir -p "${LOG_DIR}"

# Build only. The suite is driven below so a crash does not end the run.
WOLFPROV_SKIP_TEST=1 ./scripts/build-wolfprovider.sh

source ./scripts/env-setup

total=$(./test/unit.test --list | grep -cE '^ *[0-9]+: ')
echo "unit test cases: ${total}"

crashed=()
failed=()
next=1

while [ "${next}" -le "${total}" ]; do
    echo "=== running cases ${next}..${total} ==="
    rc=0
    # shellcheck disable=SC2046
    ./test/unit.test $(seq "${next}" "${total}") 2>&1 | tee -a "${RUN_LOG}" \
        || rc=${PIPESTATUS[0]}

    # Under 128 means the runner reached the end on its own, reporting any
    # failures as it went. Only a signal leaves cases unrun.
    if [ "${rc}" -lt 128 ]; then
        break
    fi

    last=$(grep -oE '^#### Start: [0-9]+' "${RUN_LOG}" | tail -1 \
        | grep -oE '[0-9]+$')
    name=$(./test/unit.test --list | grep -E "^ *${last}: " \
        | sed -E 's/^ *[0-9]+: //')
    echo "=== case ${last} (${name}) died with exit ${rc}; getting backtrace ==="
    crashed+=("${last} ${name}")

    ./libtool --mode=execute gdb -batch \
        -ex run -ex 'bt full' -ex 'info registers' \
        -ex 'thread apply all bt' \
        --args ./test/unit.test "${last}" \
        > "${LOG_DIR}/backtrace-${last}.log" 2>&1 || true
    echo "--- backtrace for case ${last} (${name}) ---"
    cat "${LOG_DIR}/backtrace-${last}.log"

    next=$((last + 1))
done

mapfile -t failed < <(grep -oE '^#### FAILED: [0-9]+ - [^ ]+' "${RUN_LOG}" \
    | sed -E 's/^#### FAILED: //' | sort -u || true)

{
    echo "big-endian unit results on $(uname -m)"
    echo "cases: ${total}"
    echo
    echo "crashed (${#crashed[@]}):"
    printf '  %s\n' "${crashed[@]:-none}"
    echo
    echo "failed (${#failed[@]}):"
    printf '  %s\n' "${failed[@]:-none}"
    echo
    echo "byte-order import path (the reason this job exists):"
    grep -E '^#### (SUCCESS|FAILED): [0-9]+ - test_(rsa|dh|ec)_fromdata' \
        "${RUN_LOG}" || echo "  never reached"
} | tee "${SUMMARY}"

if [ "${#crashed[@]}" -gt 0 ] || [ "${#failed[@]}" -gt 0 ]; then
    exit 1
fi
