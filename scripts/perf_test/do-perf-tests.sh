#!/bin/bash
# do-perf-tests.sh
# Run the wolfProvider overhead regression test.
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

PERF_TEST_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
REPO_ROOT="$( cd "${PERF_TEST_DIR}/../.." &> /dev/null && pwd )"

export DO_CMD_TESTS=1

show_help() {
    cat << EOF
Usage: $0 [OPTIONS]

Measure per-invocation cost of representative openssl commands under
wolfProvider and compare against the committed baseline for the active
build variant (FIPS vs non-FIPS, selected by WOLFSSL_ISFIPS).

OPTIONS:
    --help              Show this help message
    --update-baseline   Regenerate the baseline JSON from this run instead of
                        gating against it

ENVIRONMENT VARIABLES:
    OPENSSL_BIN         Path to OpenSSL binary (auto-detected if not set)
    WOLFSSL_ISFIPS      Set to 1 to select the FIPS baseline
    PERF_ITER           Measured iterations per command (default 15)
    PERF_WARMUP         Warmup iterations per command (default 3)
    PERF_CONFIRM        Total measurement attempts for a failing command before
                        it is reported as a regression (default 3)
EOF
    exit 0
}

PASS_ARGS=()
while [[ $# -gt 0 ]]; do
    case $1 in
        --help|-h)
            show_help
            ;;
        --update-baseline)
            PASS_ARGS+=("$1")
            shift
            ;;
        *)
            echo "Unknown option: $1"
            echo "Use --help for usage information"
            exit 1
            ;;
    esac
done

source "${REPO_ROOT}/scripts/cmd_test/cmd-test-common.sh"
cmd_test_env_setup

"${PERF_TEST_DIR}/perf-cmd-test.sh" "${PASS_ARGS[@]}"
exit $?
