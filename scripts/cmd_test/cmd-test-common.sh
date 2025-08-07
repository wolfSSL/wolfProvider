#!/bin/bash
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

cmd_test_env_setup() {
    local log_file_name=$1
    SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
    # Set up environment
    export LOG_FILE="${SCRIPT_DIR}/${log_file_name}"
    touch "$LOG_FILE"

    # OPENSSL_BIN must be set by the caller
    if [ -z "${OPENSSL_BIN:-}" ]; then
        echo "Error: OPENSSL_BIN environment variable is not set" | tee -a "$LOG_FILE"
        exit 1
    fi

    # Fail flags
    FAIL=0
    FORCE_FAIL_PASSED=0

    # Get the force fail parameter
    if [ "${WOLFPROV_FORCE_FAIL}" = "1" ]; then
        echo "Force fail mode enabled"
    fi
    if [ "${WOLFSSL_ISFIPS}" = "1" ]; then
        echo "FIPS mode enabled"
    fi

    # Print environment for verification
    echo "Environment variables:"
    echo "OPENSSL_MODULES: ${OPENSSL_MODULES}"
    echo "OPENSSL_BIN: ${OPENSSL_BIN}"
}

# Function to use default provider only
use_default_provider() {
    unset OPENSSL_MODULES
    unset OPENSSL_CONF

    # Verify that we are using the default provider
    if ${OPENSSL_BIN} list -providers | grep -q "wolfprov"; then
        echo "FAIL: unable to switch to default provider, wolfProvider is still active"
        exit 1
    fi
    echo "Switched to default provider"
}

# Function to use wolf provider only
use_wolf_provider() {
    export OPENSSL_MODULES=$WOLFPROV_PATH
    export OPENSSL_CONF=${WOLFPROV_CONFIG}

    # Verify that we are using wolfProvider
    if ! ${OPENSSL_BIN} list -providers | grep -q "wolfprov"; then
        echo "FAIL: unable to switch to wolfProvider, default provider is still active"
        exit 1
    fi
    echo "Switched to wolfProvider"
}

# Helper function to handle force fail checks
check_force_fail() {
    if [ "${WOLFPROV_FORCE_FAIL}" = "1" ]; then
        echo "[PASS] Test passed when force fail was enabled"
        FORCE_FAIL_PASSED=1
    fi
}
