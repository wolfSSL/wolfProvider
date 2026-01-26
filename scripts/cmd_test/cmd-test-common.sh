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
    # Use OPENSSL_BIN if explicitly set, otherwise auto-detect
    if [ -z "${OPENSSL_BIN:-}" ]; then
        OPENSSL_BIN=$(which openssl 2>/dev/null || echo "")
        if [ -z "$OPENSSL_BIN" ]; then
            echo "ERROR: Cannot find openssl binary. Please set OPENSSL_BIN environment variable."
            exit 1
        fi
    fi
    export OPENSSL_BIN
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
    # Detect mode BEFORE modifying environment variables
    detect_wolfprovider_mode
    
    # Check if wolfProvider is in replace-default mode
    if [ "$is_openssl_replace_default" = "1" ] || [ "${WOLFPROV_REPLACE_DEFAULT:-0}" = "1" ]; then
        # In replace-default mode, wolfProvider IS the default provider
        # No provider switching possible - just verify it's active
        echo "replace-default is set, using default provider"
        
        # In replace-default mode, don't modify environment variables
        # Just verify that wolfProvider is active as the default
        if [ "$is_wp_active" = "1" ] && [ "$is_wp_default" = "1" ]; then
            echo "Using default provider (wolfProvider in replace-default mode)"
            return 0
        else
            echo "FAIL: Expected wolfProvider as default, but is_wp_active: $is_wp_active and is_wp_default: $is_wp_default"
            exit 1
        fi
    else
        # In non-replace-default mode, unsetting OPENSSL_MODULES should disable wolfProvider
        # Disable wolfProvider by setting OPENSSL_CONF and OPENSSL_MODULES to /dev/null
        if [ -z "${OPENSSL_CONF_ORIG:-}" ]; then
            export OPENSSL_CONF="/dev/null"
            export OPENSSL_MODULES="/dev/null"
        else
            unset OPENSSL_CONF
            unset OPENSSL_MODULES
        fi

        # Re-detect after disabling
        detect_wolfprovider_mode

        # Verify that we are using the OpenSSL default provider (not wolfProvider)
        if [ "$is_openssl_default_provider" != "1" ]; then
            # If we can't switch, this indicates replace-default mode
            # Check if wolfProvider is still active - if so, we're in replace-default mode
            if [ "$is_wp_active" = "1" ]; then
                echo "INFO: Cannot switch to OpenSSL default provider - detected replace-default mode"
                echo "INFO: Setting is_openssl_replace_default=1 for remaining tests"
                is_openssl_replace_default=1
                is_wp_default=1
                export is_openssl_replace_default
                export is_wp_default
                # Also set the environment variable for child processes
                export WOLFPROV_REPLACE_DEFAULT=1
                return 0  # Return success - this is expected in replace-default mode
            else
                echo "FAIL: unable to switch to default provider, and wolfProvider is not active"
                echo "is_openssl_default_provider: $is_openssl_default_provider"
                echo "is_wp_active: $is_wp_active"
                exit 1
            fi
        fi
        echo "INFO: Switched to OpenSSL default provider"
        return 0
    fi
}


# Function to use wolf provider only
use_wolf_provider() {
    # Detect mode BEFORE modifying environment variables
    detect_wolfprovider_mode
    
    # Check if wolfProvider is in replace-default mode
    if [ "$is_openssl_replace_default" = "1" ] || [ "${WOLFPROV_REPLACE_DEFAULT:-0}" = "1" ]; then
        # In replace-default mode, wolfProvider IS the default provider
        # No provider switching possible - just verify it's active
        echo "replace-default is set, using default provider"
        
        # In replace-default mode, don't modify environment variables
        # Just verify that wolfProvider is active as the default
        if [ "$is_wp_active" = "1" ] && [ "$is_wp_default" = "1" ]; then
            echo "Using wolfProvider (replace-default mode)"
            return 0
        else
            echo "FAIL: wolfProvider is not active"
            echo "is_wp_active: $is_wp_active"
            echo "is_wp_default: $is_wp_default"
            exit 1
        fi
    else
        # In non-replace-default mode, we need to set OPENSSL_MODULES and OPENSSL_CONF to enable wolfProvider
        echo "INFO: Switched to libwolfprov"
        
        # Get paths to enable wolfProvider
        # Use WOLFPROV_PATH/WOLFPROV_CONFIG if set (from env-setup), otherwise derive from OPENSSL_BIN path
        local wolfprov_lib_path="${WOLFPROV_PATH:-}"
        local provider_conf="${WOLFPROV_CONFIG:-}"
        
        # If not set, try to find library path
        if [ -z "$wolfprov_lib_path" ]; then
            # Try MODULESDIR from openssl version -a (simplest approach)
            local openssl_modules_dir=""
            openssl_modules_dir=$($OPENSSL_BIN version -a 2>/dev/null | grep -i "^MODULESDIR" | sed -E 's/.*["'\'']([^"'\'']+)["'\''].*/\1/' | head -1)
            if [ -n "$openssl_modules_dir" ] && [ -d "$openssl_modules_dir" ]; then
                # Check if provider library exists
                if [ -f "$openssl_modules_dir/libwolfprov.so" ] || \
                   [ -f "$openssl_modules_dir/libwolfprov.so.0" ] || \
                   [ -f "$openssl_modules_dir/libwolfprov.so.0.0.0" ]; then
                    wolfprov_lib_path="$openssl_modules_dir"
                fi
            fi
            
            # If still not found, try local build location
            if [ -z "$wolfprov_lib_path" ]; then
                local openssl_install_dir=$(dirname "$(dirname "$OPENSSL_BIN")" 2>/dev/null || echo "")
                local repo_root=$(dirname "$openssl_install_dir" 2>/dev/null || echo "")
                if [ -n "$repo_root" ] && [ -d "$repo_root/wolfprov-install/lib" ]; then
                    wolfprov_lib_path="$repo_root/wolfprov-install/lib"
                fi
            fi
        fi
        
        # If not set, try to find config file (optional - system installs may not need it)
        if [ -z "$provider_conf" ]; then
            # Try system location first
            if [ -f "/etc/ssl/openssl.cnf.d/wolfprovider.conf" ]; then
                provider_conf="/etc/ssl/openssl.cnf.d/wolfprovider.conf"
            else
                # Try local build location
                local openssl_install_dir=$(dirname "$(dirname "$OPENSSL_BIN")" 2>/dev/null || echo "")
                local repo_root=$(dirname "$openssl_install_dir" 2>/dev/null || echo "")
                if [ -n "$repo_root" ]; then
                    if [ "${WOLFSSL_ISFIPS:-0}" = "1" ] && [ -f "$repo_root/provider-fips.conf" ]; then
                        provider_conf="$repo_root/provider-fips.conf"
                    elif [ -f "$repo_root/provider.conf" ]; then
                        provider_conf="$repo_root/provider.conf"
                    fi
                fi
            fi
        fi
        
        # Set environment variables to enable wolfProvider
        # In system installations, the provider may be auto-loaded via openssl.cnf,
        # so library path is optional - only set it if we found it
        if [ -n "$wolfprov_lib_path" ] && [ -d "$wolfprov_lib_path" ]; then
            export OPENSSL_MODULES="$wolfprov_lib_path"
        else
            # Library path not found - this is OK for system installs with openssl.cnf configuration
            # Just warn about it, don't fail
            echo "WARNING: Cannot find wolfProvider library path - will rely on system openssl.cnf configuration"
            echo "  WOLFPROV_PATH: ${WOLFPROV_PATH:-not set}"
            echo "  OPENSSL_BIN: ${OPENSSL_BIN:-not set}"
            $OPENSSL_BIN version -a 2>&1 | grep -i "^MODULESDIR" || echo "  MODULESDIR not found in openssl version output"
        fi
        
        # Config file is optional - system installs may use openssl.cnf instead
        if [ -n "$provider_conf" ] && [ -f "$provider_conf" ]; then
            export OPENSSL_CONF="$provider_conf"
        fi
        
        # Re-detect after setting environment
        detect_wolfprovider_mode

        # Verify that we are using wolfProvider
        if [ "$is_wp_active" != "1" ]; then
            echo "FAIL: unable to switch to wolfProvider, default provider is still active"
            echo "is_wp_active: $is_wp_active"
            echo "is_wp_default: $is_wp_default"
            exit 1
        fi
        return 0
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

# Check if we can perform provider comparison tests
# Returns 0 if comparison possible (normal mode), 1 if replace-default mode (no comparison)
can_compare_providers() {
    if [ "$is_openssl_replace_default" = "1" ] || [ "${WOLFPROV_REPLACE_DEFAULT:-0}" = "1" ]; then
        return 1  # Cannot compare - replace-default mode
    fi
    return 0  # Can compare - normal mode
}
