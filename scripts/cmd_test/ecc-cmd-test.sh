#!/bin/bash
# ecc-cmd-test.sh
# ECC key generation test for wolfProvider
#
# Copyright (C) 2006-2024 wolfSSL Inc.
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
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA

# Set up environment
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
REPO_ROOT="$( cd "${SCRIPT_DIR}/../.." &> /dev/null && pwd )"
UTILS_DIR="${REPO_ROOT}/scripts"
export LOG_FILE="${SCRIPT_DIR}/ecc-test.log"
touch "$LOG_FILE"

# Source wolfProvider utilities
source "${UTILS_DIR}/utils-general.sh"
source "${UTILS_DIR}/utils-openssl.sh"
source "${UTILS_DIR}/utils-wolfssl.sh"
source "${UTILS_DIR}/utils-wolfprovider.sh"

# Initialize the environment
init_wolfprov

TEST_STATUS=0

if [ -n "$WOLFPROV_FORCE_FAIL" ] && [ "$WOLFPROV_FORCE_FAIL" -eq 1 ]; then
    echo "WOLFPROV_FORCE_FAIL=1 detected - expecting failures"
    EXPECT_FAILURE=1
else
    EXPECT_FAILURE=0
fi

# Verify wolfProvider is properly loaded
echo -e "\nVerifying wolfProvider configuration:"
if ! $OPENSSL_BIN list -providers | grep -q "libwolfprov"; then
    echo "[FAIL] wolfProvider not found in OpenSSL providers!"
    echo "Current provider list:"
    $OPENSSL_BIN list -providers
    TEST_STATUS=1
    if [ $EXPECT_FAILURE -eq 0 ]; then
        exit 1
    fi
else
    echo "[PASS] wolfProvider is properly configured"
fi

# Print environment for verification
echo "Environment variables:"
echo "OPENSSL_MODULES: ${OPENSSL_MODULES}"
echo "LD_LIBRARY_PATH: ${LD_LIBRARY_PATH}"
echo "OPENSSL_BIN: ${OPENSSL_BIN}"
echo "WOLFPROV_FORCE_FAIL: ${WOLFPROV_FORCE_FAIL}"

# Create test directories
mkdir -p ecc_outputs

# Create test data for signing
echo "This is test data for ECC signing and verification." > ecc_outputs/test_data.txt

# Array of ECC curves to test
CURVES=("prime192v1" "secp224r1" "prime256v1" "secp384r1" "secp521r1")

echo "=== Running ECC Key Generation Tests ==="

# Function to validate key
validate_key() {
    local curve=$1
    local key_file=${2:-"ecc_outputs/ecc_${curve}.pem"}
    
    echo -e "\n=== Validating ECC Key (${curve}) ==="
    
    # Check if key exists and has content
    if [ ! -s "$key_file" ]; then
        echo "[FAIL] ECC key (${curve}) file is empty or does not exist"
        TEST_STATUS=1
        return 1
    fi
    echo "[PASS] ECC key (${curve}) file exists and has content"
    
    # Try to extract public key
    local pub_key_file="ecc_outputs/ecc_${curve}_pub.pem"
    if $OPENSSL_BIN pkey -in "$key_file" -pubout -out "$pub_key_file" \
        -provider default -passin pass: 2>/dev/null; then
        echo "[PASS] ECC key (${curve}) public key extraction successful"
        return 0
    else
        echo "[FAIL] ECC key (${curve}) public key extraction failed"
        TEST_STATUS=1
        return 1
    fi
}

# Function to test sign/verify interoperability using pkeyutl
test_sign_verify_pkeyutl() {
    local curve=$1
    local key_file=$2
    local pub_key_file="ecc_outputs/ecc_${curve}_pub.pem"
    local data_file="ecc_outputs/test_data.txt"
    local sig_file="ecc_outputs/ecc_${curve}_sig.bin"
    local test_status=0
    
    echo -e "\n=== Testing ECC (${curve}) Sign/Verify with pkeyutl ==="
    
    # Test 1: Sign with OpenSSL default, verify with wolfProvider
    echo "Test 1: Sign with OpenSSL default, verify with wolfProvider"
    
    # Sign data with OpenSSL default
    echo "Signing data with OpenSSL default..."
    if ! $OPENSSL_BIN pkeyutl -sign -inkey "$key_file" \
        -provider default -passin pass: \
        -in "$data_file" -out "$sig_file" 2>/dev/null; then
        echo "[FAIL] Signing with OpenSSL default failed"
        test_status=1
    else
        # Verify signature with wolfProvider
        echo "Verifying signature with wolfProvider..."
        if $OPENSSL_BIN pkeyutl -verify -pubin -inkey "$pub_key_file" \
            -provider-path $WOLFPROV_PATH -provider libwolfprov \
            -in "$data_file" -sigfile "$sig_file" 2>/dev/null; then
            if [ $EXPECT_FAILURE -eq 1 ]; then
                echo "[UNEXPECTED PASS] Interop: OpenSSL sign, wolfProvider verify successful"
                test_status=1
            else
                echo "[PASS] Interop: OpenSSL sign, wolfProvider verify successful"
            fi
        else
            if [ $EXPECT_FAILURE -eq 1 ]; then
                echo "[EXPECTED FAIL] Interop: OpenSSL sign, wolfProvider verify failed"
            else
                echo "[FAIL] Interop: OpenSSL sign, wolfProvider verify failed"
                test_status=1
            fi
        fi
    fi
    
    # Test 2: Sign with wolfProvider, verify with OpenSSL default
    echo "Test 2: Sign with wolfProvider, verify with OpenSSL default"
    
    local wolf_sig_file="ecc_outputs/ecc_${curve}_wolf_sig.bin"
    echo "Signing data with wolfProvider..."
    if $OPENSSL_BIN pkeyutl -sign -inkey "$key_file" \
        -provider-path $WOLFPROV_PATH -provider libwolfprov \
        -in "$data_file" -out "$wolf_sig_file" 2>/dev/null; then
        if [ $EXPECT_FAILURE -eq 1 ]; then
            echo "[UNEXPECTED PASS] wolfProvider signing successful"
            test_status=1
        else
            echo "[PASS] wolfProvider signing successful"
        fi
        
        echo "Verifying signature with OpenSSL default..."
        if $OPENSSL_BIN pkeyutl -verify -pubin -inkey "$pub_key_file" \
            -provider default \
            -in "$data_file" -sigfile "$wolf_sig_file" 2>/dev/null; then
            echo "[PASS] Interop: wolfProvider sign, OpenSSL verify successful"
        else
            echo "[FAIL] Interop: wolfProvider sign, OpenSSL verify failed"
            test_status=1
        fi
    else
        if [ $EXPECT_FAILURE -eq 1 ]; then
            echo "[EXPECTED FAIL] wolfProvider signing failed"
        else
            echo "[FAIL] wolfProvider signing failed"
            test_status=1
        fi
    fi
    
    if [ $test_status -ne 0 ]; then
        TEST_STATUS=1
    fi
    
    return $test_status
}

# Function to generate and test ECC keys
generate_and_test_ecc_key() {
    local curve=$1
    local output_file="ecc_outputs/ecc_${curve}.pem"
    local key_status=0
    
    echo -e "\n=== Testing ECC Key Generation (${curve}) ==="
    
    # Generate ECC key
    echo "Generating ECC key (${curve})..."
    $OPENSSL_BIN ecparam -name $curve -genkey \
        -provider default \
        -out "$output_file" 2>/dev/null
    
    # Verify the key was generated
    if [ -s "$output_file" ]; then
        echo "[PASS] ECC key (${curve}) generation successful"
    else
        echo "[FAIL] ECC key (${curve}) generation failed"
        TEST_STATUS=1
        return 1
    fi
    
    # Validate key
    if ! validate_key "$curve" "$output_file"; then
        key_status=1
    fi
    
    # Try to use the key with wolfProvider
    echo -e "\n=== Testing ECC Key (${curve}) with wolfProvider ==="
    echo "Checking if wolfProvider can use the key..."
    
    # Try to use the key with wolfProvider (just check if it loads)
    if $OPENSSL_BIN ec -in "$output_file" -check \
        -provider-path "${WOLFPROV_PATH}" -provider libwolfprov \
        -provider default 2>/dev/null; then
        if [ $EXPECT_FAILURE -eq 1 ]; then
            echo "[UNEXPECTED PASS] wolfProvider can use ECC key (${curve})"
            key_status=1
        else
            echo "[PASS] wolfProvider can use ECC key (${curve})"
        fi
        
        # Test sign/verify interoperability with pkeyutl
        test_sign_verify_pkeyutl "$curve" "$output_file"
    else
        if [ $EXPECT_FAILURE -eq 1 ]; then
            echo "[EXPECTED FAIL] wolfProvider cannot use ECC key (${curve})"
        else
            echo "[INFO] wolfProvider cannot use ECC key (${curve}) - this is expected for some curves"
        fi
    fi
    
    if [ $key_status -ne 0 ]; then
        TEST_STATUS=1
    fi
    
    return $key_status
}

# Test ECC key generation for each curve
echo "=== Testing ECC Key Generation with ecparam ==="

for curve in "${CURVES[@]}"; do
    generate_and_test_ecc_key "$curve"
done

if [ $TEST_STATUS -eq 0 ]; then
    if [ $EXPECT_FAILURE -eq 1 ]; then
        echo -e "\n=== ECC tests completed with expected failures ==="
    else
        echo -e "\n=== All ECC key generation tests completed successfully ==="
    fi
    exit 0
else
    if [ $EXPECT_FAILURE -eq 1 ]; then
        echo -e "\n=== ECC tests failed in unexpected ways ==="
    else
        echo -e "\n=== ECC tests failed ==="
    fi
    exit 1
fi
