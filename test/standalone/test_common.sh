#!/bin/bash
# test_common.sh - Common utilities for standalone tests
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

# Function to detect if wolfProvider was built with --replace-default
# Returns 0 if replace-default is detected, 1 otherwise
detect_replace_default_build() {
    local libcrypto_path=""
    
    # Try common locations relative to the test root
    local test_root="${ROOT_DIR:-}"
    
    if [ -z "$test_root" ]; then
        # Fallback: try to determine root from current location
        test_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." &>/dev/null && pwd)"
    fi
    
    # Try common locations
    if [ -n "${OPENSSL_LIB_PATH:-}" ] && [ -f "${OPENSSL_LIB_PATH}/libcrypto.so" ]; then
        libcrypto_path="${OPENSSL_LIB_PATH}/libcrypto.so"
    elif [ -f "${test_root}/openssl-install/lib64/libcrypto.so" ]; then
        libcrypto_path="${test_root}/openssl-install/lib64/libcrypto.so"
    elif [ -f "${test_root}/openssl-install/lib/libcrypto.so" ]; then
        libcrypto_path="${test_root}/openssl-install/lib/libcrypto.so"
    else
        return 1  # Can't find libcrypto, assume standard build
    fi
    
    # Check for replace-default patch symbols in libcrypto
    if strings "$libcrypto_path" 2>/dev/null | grep -q "load_wolfprov_and_init"; then
        return 0  # Replace-default build detected
    else
        return 1  # Standard build
    fi
}
