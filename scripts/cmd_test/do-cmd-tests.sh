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

# Get the force fail parameter
if [ "${WOLFPROV_FORCE_FAIL}" = "1" ]; then
    echo "Force fail mode enabled for all tests"
fi
if [ "${WOLFSSL_ISFIPS}" = "1" ]; then
    echo "FIPS mode enabled for all tests"
fi

# Get the directory where this script is located
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
REPO_ROOT="$( cd "${SCRIPT_DIR}/../.." &> /dev/null && pwd )"
UTILS_DIR="${REPO_ROOT}/scripts"

# Get the built versions
if [ -d "${REPO_ROOT}/openssl-source" ] && [ -d "${REPO_ROOT}/wolfssl-source" ]; then
    # Get the actual versions that were built
    export OPENSSL_TAG=$(cd ${REPO_ROOT}/openssl-source &&
        (git describe --tags 2>/dev/null || git branch --show-current))
    export WOLFSSL_TAG=$(cd ${REPO_ROOT}/wolfssl-source &&
        (git describe --tags 2>/dev/null || git branch --show-current))
else
    echo "[FAIL] OpenSSL or wolfSSL source directories not found"
    echo "Please run build-wolfprovider.sh first"
    exit 1
fi

# Use the current version tags for testing
export USE_CUR_TAG=1

# Source OpenSSL utilities and initialize OpenSSL
source "${UTILS_DIR}/utils-openssl.sh"
init_openssl

echo "=== Running wolfProvider Command-Line Tests ==="
echo "Using OpenSSL version: ${OPENSSL_TAG}"
echo "Using wolfSSL version: ${WOLFSSL_TAG}"

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
