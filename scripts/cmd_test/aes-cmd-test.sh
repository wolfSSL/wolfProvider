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

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
source "${SCRIPT_DIR}/cmd-test-common.sh"
source "${SCRIPT_DIR}/clean-cmd-test.sh"
cmd_test_env_setup "aes-test.log"
clean_cmd_test "aes"

# Redirect all output to log file
exec > >(tee -a "$LOG_FILE") 2>&1

# Create test data and output directories
mkdir -p aes_outputs
echo "This is test data for AES encryption testing." > aes_outputs/test_data.txt

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
            -in aes_outputs/test_data.txt -out "$enc_file" -p; then
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
            if cmp -s "aes_outputs/test_data.txt" "$dec_file"; then
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
            -in aes_outputs/test_data.txt -out "$enc_file" -p; then
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
            if cmp -s "aes_outputs/test_data.txt" "$dec_file"; then
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
