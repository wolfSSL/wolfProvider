#!/bin/bash
# aes-cmd-test.sh
# AES encryption test for wolfProvider
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

# Set up environment
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
REPO_ROOT="$( cd "${SCRIPT_DIR}/../.." &> /dev/null && pwd )"
UTILS_DIR="${REPO_ROOT}/scripts"
export LOG_FILE="${SCRIPT_DIR}/aes-test.log"
touch "$LOG_FILE"

# Source wolfProvider utilities
source "${UTILS_DIR}/utils-general.sh"
source "${UTILS_DIR}/utils-openssl.sh"
source "${UTILS_DIR}/utils-wolfssl.sh"
source "${UTILS_DIR}/utils-wolfprovider.sh"

# Initialize wolfProvider
init_wolfprov

# Fail flags
FAIL=0
FORCE_FAIL_PASSED=0

# Check environment variables directly
if [ "${WOLFPROV_FORCE_FAIL}" = "1" ]; then
    echo "Force fail mode enabled for AES tests"
fi
if [ "${WOLFSSL_ISFIPS}" = "1" ]; then
    echo "FIPS mode enabled for AES tests"
fi

# Verify wolfProvider is properly loaded
echo -e "\nVerifying wolfProvider configuration:"
if ! $OPENSSL_BIN list -providers | grep -q "wolf"; then
    echo "[FAIL] wolfProvider not found in OpenSSL providers!"
    echo "Current provider list:"
    $OPENSSL_BIN list -providers
    FAIL=1
else
    echo "wolfProvider is properly configured"
fi

# Print environment for verification
echo "Environment variables:"
echo "OPENSSL_MODULES: ${OPENSSL_MODULES}"
echo "LD_LIBRARY_PATH: ${LD_LIBRARY_PATH}"
echo "OPENSSL_BIN: ${OPENSSL_BIN}"

# Create test data and output directories
mkdir -p aes_outputs
echo "This is test data for AES encryption testing." > test.txt

# Helper function to handle force fail checks
check_force_fail() {
    if [ "${WOLFPROV_FORCE_FAIL}" = "1" ]; then
        echo "[PASS] Test passed when force fail was enabled"
        FORCE_FAIL_PASSED=1
    fi
}

# Arrays for test configurations
KEY_SIZES=("128" "192" "256")
# Only include modes supported by wolfProvider
if [ "${WOLFSSL_ISFIPS}" = "1" ]; then
    MODES=("ecb" "cbc" "ctr")
    echo "FIPS mode detected - excluding CFB mode"
else
    MODES=("ecb" "cbc" "ctr" "cfb")
fi

echo "=== Running AES Algorithm Comparisons ==="

# Run tests for each key size and mode
for key_size in "${KEY_SIZES[@]}"; do
    for mode in "${MODES[@]}"; do
        echo -e "\n=== Testing AES-${key_size}-${mode} ==="
        
        # Generate random key and IV
        key=$($OPENSSL_BIN rand -hex $((key_size/8)) 2>/dev/null | tail -n 1 | tr -d '\n')
        iv=""
        if [ "$mode" != "ecb" ]; then
            iv_value=$($OPENSSL_BIN rand -hex 16 2>/dev/null | tail -n 1 | tr -d '\n')
            iv="-iv $iv_value"
        fi
        echo "DEBUG: Key='$key' (length: ${#key})"
        echo "DEBUG: IV='$iv'"
        
        # Output files
        enc_file="aes_outputs/aes${key_size}_${mode}.enc"
        dec_file="aes_outputs/aes${key_size}_${mode}.dec"
        
        # Interop testing: Encrypt with default provider, decrypt with wolfProvider
        echo "Interop testing (encrypt with default, decrypt with wolfProvider):"
        
        # Encryption with OpenSSL default provider
        if ! $OPENSSL_BIN enc -aes-${key_size}-${mode} -K "$key" $iv -provider default \
            -in test.txt -out "$enc_file" -p; then
            echo "[FAIL] Interop AES-${key_size}-${mode}: OpenSSL encrypt failed"
            FAIL=1
        fi
        
        # Decryption with wolfProvider
        if ! $OPENSSL_BIN enc -aes-${key_size}-${mode} -K "$key" $iv -provider-path "$WOLFPROV_PATH" -provider libwolfprov \
            -in "$enc_file" -out "$dec_file" -d -p; then
            echo "[FAIL] Interop AES-${key_size}-${mode}: wolfProvider decrypt failed"
            FAIL=1
        fi
        
        if [ $FAIL -eq 0 ]; then
            if cmp -s "test.txt" "$dec_file"; then
                echo "[PASS] Interop AES-${key_size}-${mode}: OpenSSL encrypt, wolfProvider decrypt"
                check_force_fail
            else
                echo "[FAIL] Interop AES-${key_size}-${mode}: OpenSSL encrypt, wolfProvider decrypt"
                FAIL=1
            fi
        else
            echo "[INFO] Cannot verify encryption/decryption - no key available"
        fi
        
        # Interop testing: Encrypt with wolfProvider, decrypt with default provider
        echo "Interop testing (encrypt with wolfProvider, decrypt with default):"
        
        # Encryption with wolfProvider
        if ! $OPENSSL_BIN enc -aes-${key_size}-${mode} -K "$key" $iv -provider-path "$WOLFPROV_PATH" -provider libwolfprov \
            -in test.txt -out "$enc_file" -p; then
            echo "[FAIL] Interop AES-${key_size}-${mode}: wolfProvider encrypt failed"
            FAIL=1
        fi
        
        # Decryption with OpenSSL default provider
        if ! $OPENSSL_BIN enc -aes-${key_size}-${mode} -K "$key" $iv -provider default \
            -in "$enc_file" -out "$dec_file" -d -p; then
            echo "[FAIL] Interop AES-${key_size}-${mode}: OpenSSL decrypt failed"
            FAIL=1
        fi
        
        if [ $FAIL -eq 0 ]; then
            if cmp -s "test.txt" "$dec_file"; then
                echo "[PASS] Interop AES-${key_size}-${mode}: wolfProvider encrypt, OpenSSL decrypt"
                check_force_fail
            else
                echo "[FAIL] Interop AES-${key_size}-${mode}: wolfProvider encrypt, OpenSSL decrypt"
                FAIL=1
            fi
        else
            echo "[INFO] Cannot verify encryption/decryption - no key available"
        fi
    done
done

if [ "${WOLFPROV_FORCE_FAIL}" = "1" ]; then
    if [ $FORCE_FAIL_PASSED -eq 1 ]; then
        echo -e "\n=== AES Tests Failed With Force Fail Enabled ==="
        echo "ERROR: Some tests passed when they should have failed"
        exit 1
    else
        echo -e "\n=== AES Tests Passed With Force Fail Enabled ==="
        echo "SUCCESS: All tests failed as expected"
        exit 0
    fi
else
    if [ $FAIL -eq 0 ]; then
        echo -e "\n=== All AES tests completed successfully ==="
        exit 0
    else
        echo -e "\n=== AES tests completed with failures ==="
        exit 1
    fi
fi
