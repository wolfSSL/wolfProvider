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

COMMON_SETUP_DONE=0

cmd_test_env_setup() {
    # Fail flags
    FAIL=0
    FORCE_FAIL_PASSED=0

    if [ $COMMON_SETUP_DONE -ne 0 ]; then
        echo "Setup already completed, skipping."
        return
    fi

    local log_file_name=$1
    SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
    # Set up environment
    export LOG_FILE="${SCRIPT_DIR}/${log_file_name}"
    touch "$LOG_FILE"

    # If OPENSSL_BIN is not set, assume we are using a local build
    if [ -z "${OPENSSL_BIN:-}" ]; then
        echo "OPENSSL_BIN not set, assuming local build"
        # Check if the install directories exist
        if [ ! -d "${REPO_ROOT}/openssl-install" ] || 
        [ ! -d "${REPO_ROOT}/wolfssl-install" ]; then
            echo "[FAIL] OpenSSL or wolfSSL install directories not found"
            echo "Please set OPENSSL_BIN or run build-wolfprovider.sh first"
            exit 1
        fi

        # Setup the environment for a local build
        source "${REPO_ROOT}/scripts/env-setup"
    else
        echo "Using user-provided OPENSSL_BIN: ${OPENSSL_BIN}"
        # We are using a user-provided OpenSSL binary, manually set the test
        # environment variables rather than using env-setup.
        # Find the location of the wolfProvider modules
        if [ -z "${WOLFPROV_PATH:-}" ]; then
            export WOLFPROV_PATH=$(find /usr/lib /usr/local/lib -type d -name ossl-modules 2>/dev/null | head -n 1)
        fi
        # Set the path to the wolfProvider config file
        if [ -z "${WOLFPROV_CONFIG:-}" ]; then
            if [ "${WOLFSSL_ISFIPS:-0}" = "1" ]; then
                export WOLFPROV_CONFIG="${REPO_ROOT}/provider-fips.conf"
            else
                export WOLFPROV_CONFIG="${REPO_ROOT}/provider.conf"
            fi  
        fi
    fi

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
    echo "WOLFPROV_PATH: ${WOLFPROV_PATH}"
    echo "WOLFPROV_CONFIG: ${WOLFPROV_CONFIG}"
    echo "LOG_FILE: ${LOG_FILE}"

    COMMON_SETUP_DONE=1
}

# Check if default provider is in use
# Note that this may be wolfProvider if built as replace-default
is_default_provider() {
    return $($OPENSSL_BIN list -providers | grep -qi "default")
}

# Function to use default provider only
use_default_provider() {
    unset OPENSSL_MODULES
    unset OPENSSL_CONF

    # Verify that we are using the default provider
    if ! is_default_provider; then
        echo "FAIL: unable to switch to default provider"
        $OPENSSL_BIN list -providers
        exit 1
    fi
    echo "Switched to default provider"
}

is_wolf_provider() {
    return $($OPENSSL_BIN list -providers | grep -qi "wolfSSL Provider")
}

# Function to use wolf provider only
use_wolf_provider() {
    export OPENSSL_MODULES=$WOLFPROV_PATH
    export OPENSSL_CONF=${WOLFPROV_CONFIG}

    # Verify that we are using wolfProvider
    if ! is_wolf_provider; then
        echo "FAIL: unable to switch to wolfProvider"
        $OPENSSL_BIN list -providers
        exit 1
    fi
    echo "Switched to wolfProvider"
}

is_replace_default() {
    return $($OPENSSL_BIN list -providers | grep -qi "wolfSSL Provider")
}

# Helper function to handle force fail checks
check_force_fail() {
    if is_default_provider && ! is_replace_default; then
        echo "OPENSSL Default provider active, no forced failures expected."
    elif [ "${WOLFPROV_FORCE_FAIL}" = "1" ]; then
        echo "[PASS] Test passed when force fail was enabled"
        FORCE_FAIL_PASSED=1
    fi
}

# Helper function to get provider name from provider arguments
get_provider_name() {
    local provider_args=$1
    if [ "$provider_args" = "-provider default" ]; then
        echo "default"
    else
        echo "libwolfprov"
    fi
}
