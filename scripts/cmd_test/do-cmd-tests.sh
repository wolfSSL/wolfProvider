#!/bin/bash
# do-cmd-tests.sh
# Run all command-line tests for wolfProvider
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

# Get the directory where this script is located
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
REPO_ROOT="$( cd "${SCRIPT_DIR}/../.." &> /dev/null && pwd )"
UTILS_DIR="${REPO_ROOT}/scripts"

source "${SCRIPT_DIR}/cmd-test-common.sh"

# If OPENSSL_BIN is not set, assume we are using a local build
if [ -z "${OPENSSL_BIN:-}" ]; then
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

echo "=== Running wolfProvider Command-Line Tests ==="
echo "Using OPENSSL_BIN: ${OPENSSL_BIN}" 
echo "Using WOLFPROV_PATH: ${WOLFPROV_PATH}"
echo "Using WOLFPROV_CONFIG: ${WOLFPROV_CONFIG}"

# Ensure we can switch providers before proceeding
use_default_provider
use_wolf_provider

# Run the hash comparison test
echo -e "\n=== Running Hash Comparison Test ==="
"${REPO_ROOT}/scripts/cmd_test/hash-cmd-test.sh"
HASH_RESULT=$?

# Run the AES comparison test
echo -e "\n=== Running AES Comparison Test ==="
"${REPO_ROOT}/scripts/cmd_test/aes-cmd-test.sh"
AES_RESULT=$?

# Run the RSA key generation test
echo -e "\n=== Running RSA Key Generation Test ==="
"${REPO_ROOT}/scripts/cmd_test/rsa-cmd-test.sh"
RSA_RESULT=$?

# Run the ECC key generation test
echo -e "\n=== Running ECC Key Generation Test ==="
"${REPO_ROOT}/scripts/cmd_test/ecc-cmd-test.sh"
ECC_RESULT=$?

# Check results
if [ $HASH_RESULT -eq 0 ] && [ $AES_RESULT -eq 0 ] && [ $RSA_RESULT -eq 0 ] && [ $ECC_RESULT -eq 0 ]; then
    echo -e "\n=== All Command-Line Tests Passed ==="
    if [ "${WOLFPROV_FORCE_FAIL}" = "1" ]; then
        echo "Force fail mode was enabled"
    fi
    if [ "${WOLFSSL_ISFIPS}" = "1" ]; then
        echo "FIPS mode was enabled"
    fi
    echo "Hash Test Result: $HASH_RESULT (0=success)"
    echo "AES Test Result: $AES_RESULT (0=success)"
    echo "RSA Test Result: $RSA_RESULT (0=success)"
    echo "ECC Test Result: $ECC_RESULT (0=success)"
    exit 0
else
    echo -e "\n=== Command-Line Tests Failed ==="
    if [ "${WOLFPROV_FORCE_FAIL}" = "1" ]; then
        echo "Force fail mode was enabled"
    fi
    if [ "${WOLFSSL_ISFIPS}" = "1" ]; then
        echo "FIPS mode was enabled"
    fi
    echo "Hash Test Result: $HASH_RESULT (0=success)"
    echo "AES Test Result: $AES_RESULT (0=success)"
    echo "RSA Test Result: $RSA_RESULT (0=success)"
    echo "ECC Test Result: $ECC_RESULT (0=success)"
    exit 1
fi
