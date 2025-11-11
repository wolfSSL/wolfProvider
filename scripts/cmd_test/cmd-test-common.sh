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

# Global variables to store wolfProvider installation mode
# Only initialize if not already set (allows parent script to export values)
WOLFPROV_REPLACE_DEFAULT=${WOLFPROV_REPLACE_DEFAULT:-0}
WOLFPROV_FIPS=${WOLFPROV_FIPS:-0}
WOLFPROV_INSTALLED=${WOLFPROV_INSTALLED:-0}

# Function to detect wolfProvider installation mode
detect_wolfprovider_mode() {
    if [ -z "${REPO_ROOT:-}" ]; then
        REPO_ROOT="$( cd "$( dirname "${BASH_SOURCE[0]}" )"/../.. &> /dev/null && pwd )"
    fi

    # Get OpenSSL version and initial provider info
    local openssl_version=$(${OPENSSL_BIN} version 2>/dev/null)
    local openssl_providers=$(${OPENSSL_BIN} list -providers 2>/dev/null)

    # Detect if wolfProvider is currently active
    if echo "$openssl_providers" | grep -qi "wolfSSL Provider"; then
        WOLFPROV_INSTALLED=1
        echo "Detected: wolfProvider is currently active"
    else
        WOLFPROV_INSTALLED=0
        echo "Detected: wolfProvider is not currently active"
    fi

    # Detect if FIPS mode is active
    if echo "$openssl_providers" | grep -qi "wolfSSL Provider FIPS"; then
        WOLFPROV_FIPS=1
        echo "Detected: wolfProvider FIPS mode"
    else
        WOLFPROV_FIPS=0
        echo "Detected: wolfProvider non-FIPS mode"
    fi

    # Detect replace-default mode
    if echo "$openssl_providers" | grep -q "default" && echo "$openssl_providers" | grep -qi "wolfSSL Provider"; then
        WOLFPROV_REPLACE_DEFAULT=1
        echo "Detected: wolfProvider installed in replace-default mode (provider: default)"
    elif echo "$openssl_providers" | grep -qi "libwolfprov"; then
        WOLFPROV_REPLACE_DEFAULT=0
        echo "Detected: wolfProvider installed in non-replace-default mode (provider: libwolfprov)"
    else
        WOLFPROV_REPLACE_DEFAULT=0
        echo "Detected: wolfProvider not in replace-default mode"
    fi

    # Print detection summary
    echo "wolfProvider mode detection:"
    echo "  REPLACE_DEFAULT: $WOLFPROV_REPLACE_DEFAULT"
    echo "  FIPS: $WOLFPROV_FIPS"
    echo "  INSTALLED: $WOLFPROV_INSTALLED"
}


# Function to setup the environment for the command-line tests
cmd_test_env_setup() {
    # OPENSSL_BIN must be set by the caller
    if [ -z "${OPENSSL_BIN:-}" ]; then
        echo "Error: OPENSSL_BIN environment variable is not set"
        exit 1
    fi

    # Detect wolfProvider installation mode (only if not already detected)
    if [ -z "${WOLFPROV_MODE_DETECTED:-}" ]; then
        detect_wolfprovider_mode
        export WOLFPROV_MODE_DETECTED=1
    fi
}


# Individual test setup (called by each test script)
cmd_test_init() {
    local log_file_name=$1
    SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"

    # Set up log file
    export LOG_FILE="${SCRIPT_DIR}/${log_file_name}"
    touch "$LOG_FILE"

    # Redirect all output to log file
    exec > >(tee -a "$LOG_FILE") 2>&1

    # Fail flags
    FAIL=0
    FORCE_FAIL_PASSED=0
}

# Function to use default provider only
use_default_provider() {
    unset OPENSSL_MODULES
    unset OPENSSL_CONF

    # Check if wolfProvider is in replace-default mode
    if [ "$WOLFPROV_REPLACE_DEFAULT" = "1" ]; then
        echo "INFO: wolfProvider is installed in replace-default mode"
        echo "INFO: wolfProvider IS the default provider and cannot be switched off"

        # Verify that wolfProvider (as default) is active
        local providers=$(${OPENSSL_BIN} list -providers 2>/dev/null)
        if echo "$providers" | grep -q "default" && echo "$providers" | grep -qi "wolfSSL Provider"; then
            echo "Using default provider (wolfProvider in replace-default mode)"
        else
            echo "FAIL: Expected wolfProvider as default, but provider list doesn't match"
            echo "Provider list:"
            echo "$providers"
            exit 1
        fi
    else
        # In non-replace-default mode, unsetting OPENSSL_MODULES should disable wolfProvider
        echo "INFO: wolfProvider is installed in non-replace-default mode"

        # Verify that we are using the OpenSSL default provider (not wolfProvider)
        local providers=$(${OPENSSL_BIN} list -providers 2>/dev/null)
        if echo "$providers" | grep -qi "libwolfprov"; then
            echo "FAIL: unable to switch to default provider, wolfProvider is still active"
            echo "Provider list:"
            echo "$providers"
            exit 1
        fi

        # Check if OpenSSL default provider is active
        if echo "$providers" | grep -q "default" && echo "$providers" | grep -qi "OpenSSL Default Provider"; then
            echo "Switched to default provider (OpenSSL)"
        else
            echo "FAIL: Expected OpenSSL Default Provider, but provider list doesn't match"
            echo "Provider list:"
            echo "$providers"
            exit 1
        fi
    fi
}


# Function to use wolf provider only
use_wolf_provider() {
    # Check if wolfProvider is in replace-default mode
    if [ "$WOLFPROV_REPLACE_DEFAULT" = "1" ]; then
        # In replace-default mode, wolfProvider is already the default
        # No need to set OPENSSL_MODULES or OPENSSL_CONF
        echo "INFO: wolfProvider is installed in replace-default mode"
        echo "INFO: wolfProvider is already active as the default provider"

        # Verify that wolfProvider is active
        local providers=$(${OPENSSL_BIN} list -providers 2>/dev/null)
        if echo "$providers" | grep -qi "wolfSSL Provider"; then
            echo "Using wolfProvider (replace-default mode)"
        else
            echo "FAIL: wolfProvider is not active"
            echo "Provider list:"
            echo "$providers"
            exit 1
        fi
    else
        # In non-replace-default mode, we need to set OPENSSL_MODULES and OPENSSL_CONF
        echo "INFO: wolfProvider is installed in non-replace-default mode"
        export OPENSSL_MODULES=$WOLFPROV_PATH
        export OPENSSL_CONF=${WOLFPROV_CONFIG}

        # Verify that we are using wolfProvider
        local providers=$(${OPENSSL_BIN} list -providers 2>/dev/null)
        if ! echo "$providers" | grep -qi "wolfprov"; then
            echo "FAIL: unable to switch to wolfProvider, default provider is still active"
            echo "Provider list:"
            echo "$providers"
            echo "OPENSSL_MODULES: $OPENSSL_MODULES"
            echo "OPENSSL_CONF: $OPENSSL_CONF"
            exit 1
        fi
        echo "Switched to wolfProvider"
    fi
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
