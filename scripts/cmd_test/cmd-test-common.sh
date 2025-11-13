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

if [ -z "${DO_CMD_TESTS:-}" ]; then
    echo "This script is designed to be called from do-cmd-tests.sh"
    echo "Do not run this script directly - use do-cmd-tests.sh instead"
    exit 1
fi

CMD_TEST_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
source "${CMD_TEST_DIR}/../utils-general.sh"

# Function to setup the environment for the command-line tests
cmd_test_env_setup() {
    export OPENSSL_BIN=${OPENSSL_BIN:-$(which openssl)}
    printf "Using OPENSSL_BIN: %s\n" "$OPENSSL_BIN"

    OPENSSL_CONF_ORIG="${OPENSSL_CONF:-}"
    OPENSSL_MODULES_ORIG="${OPENSSL_MODULES:-}"
}


# Individual test setup (called by each test script)
cmd_test_init() {
    local log_file_name=$1
    CMD_TEST_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"

    # Set up log file
    export LOG_FILE="${CMD_TEST_DIR}/${log_file_name}"
    touch "$LOG_FILE"

    # Redirect all output to log file
    exec > >(tee -a "$LOG_FILE") 2>&1

    # Fail flags
    FAIL=0
    FORCE_FAIL_PASSED=0
}


# Function to use default provider only
use_default_provider() {
    return 0

    if [ -z "${OPENSSL_CONF_ORIG:-}" ]; then
        export OPENSSL_CONF="/dev/null"
        export OPENSSL_MODULES="/dev/null"
    else
        unset OPENSSL_CONF
        unset OPENSSL_MODULES
    fi
    detect_wolfprovider_mode

    # Check if wolfProvider is in replace-default mode
    if [ "$is_openssl_replace_default" = "1" ]; then
        echo "INFO: wolfProvider is installed in replace-default mode"
        echo "INFO: wolfProvider IS the default provider and cannot be switched off"

        # Verify that wolfProvider (as default) is active
		if [ "$is_wp_active" = "1" ] && [ "$is_wp_default" = "1" ]; then
            echo "Using default provider (wolfProvider in replace-default mode)"
        else
            echo "FAIL: Expected wolfProvider as default, but is_wp_active: $is_wp_active and is_wp_default: $is_wp_default"
            exit 1
        fi
    else
        # In non-replace-default mode, unsetting OPENSSL_MODULES should disable wolfProvider
        echo "INFO: wolfProvider is installed in non-replace-default mode"

        # Verify that we are using the OpenSSL default provider (not wolfProvider)
        if [ "$is_openssl_default_provider" != "1" ]; then
            echo "FAIL: unable to switch to default provider, wolfProvider is still active"
            echo "is_openssl_default_provider: $is_openssl_default_provider"
            exit 1
        fi
        echo "INFO: Switched to default provider (OpenSSL)"
    fi
}


# Function to use wolf provider only
use_wolf_provider() {
    return 0

    if [ -z "${OPENSSL_CONF_ORIG:-}" ]; then
        unset OPENSSL_CONF
        unset OPENSSL_MODULES
    else 
        export OPENSSL_CONF="${OPENSSL_CONF_ORIG:-}"
        export OPENSSL_MODULES="${OPENSSL_MODULES_ORIG:-}"
    fi
    detect_wolfprovider_mode

    # Check if wolfProvider is in replace-default mode
    if [ "$is_openssl_replace_default" = "1" ]; then
        # In replace-default mode, wolfProvider is already the default
        # No need to set OPENSSL_MODULES or OPENSSL_CONF
        echo "INFO: wolfProvider is installed in replace-default mode"
        echo "INFO: wolfProvider is already active as the default provider"

        # Verify that wolfProvider is active
		if [ "$is_wp_active" = "1" ] && [ "$is_wp_default" = "1" ]; then
            echo "Using wolfProvider (replace-default mode)"
        else
            echo "FAIL: wolfProvider is not active"
            echo "is_wp_active: $is_wp_active"
            echo "is_wp_default: $is_wp_default"
            exit 1
        fi
    else
        # In non-replace-default mode, we need to set OPENSSL_MODULES and OPENSSL_CONF
        echo "INFO: wolfProvider is installed in non-replace-default mode"

        # Verify that we are using wolfProvider
        if [ "$is_wp_active" != "1" ]; then
            echo "FAIL: unable to switch to wolfProvider, default provider is still active"
            $OPENSSL_BIN list -providers
            echo "is_wp_active: $is_wp_active"
            echo "is_wp_default: $is_wp_default"
            exit 1
        fi
        echo "INFO: Switched to wolfProvider"
        $OPENSSL_BIN list -providers
    fi
}


# Helper function to handle force fail checks
check_force_fail() {
    detect_wolfprovider_mode
    if [ "$is_openssl_default_provider" = "1" ]; then
        # With the OpenSSL provider, don't expect failures
        echo "OPENSSL Default provider active, no forced failures expected."
    elif [ "$WOLFPROV_FORCE_FAIL" = "1" ]; then
        echo "[PASS] Test passed when force fail was enabled"
        FORCE_FAIL_PASSED=1
        exit 1
    fi
}

use_provider_by_name() {
    local provider_name=$1
    if [ "$provider_name" = "libwolfprov" ]; then
        use_wolf_provider
    else
        use_default_provider
    fi
}
