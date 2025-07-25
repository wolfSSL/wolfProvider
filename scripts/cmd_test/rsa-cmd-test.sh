#!/bin/bash
# rsa-cmd-test.sh
# RSA and RSA-PSS key generation test for wolfProvider
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
export LOG_FILE="${SCRIPT_DIR}/rsa-test.log"
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

# Get the force fail parameter
if [ "${WOLFPROV_FORCE_FAIL}" = "1" ]; then
    echo "Force fail mode enabled for RSA tests"
fi
if [ "${WOLFSSL_ISFIPS}" = "1" ]; then
    echo "FIPS mode enabled for RSA tests"
fi

# Verify wolfProvider is properly loaded
echo -e "\nVerifying wolfProvider configuration:"
if ! $OPENSSL_BIN list -providers | grep -q "libwolfprov"; then
    echo "[FAIL] wolfProvider not found in OpenSSL providers!"
    echo "Current provider list:"
    $OPENSSL_BIN list -providers
    FAIL=1
fi
echo "wolfProvider is properly configured"

# Print environment for verification
echo "Environment variables:"
echo "OPENSSL_MODULES: ${OPENSSL_MODULES}"
echo "LD_LIBRARY_PATH: ${LD_LIBRARY_PATH}"
echo "OPENSSL_BIN: ${OPENSSL_BIN}"

# Create test directories
mkdir -p rsa_outputs

# Create test data for signing
echo "This is test data for RSA signing and verification." > rsa_outputs/test_data.txt

# Function to use default provider only
use_default_provider() {
    unset OPENSSL_MODULES
    unset OPENSSL_CONF
    echo "Switched to default provider"
}

# Function to use wolf provider only
use_wolf_provider() {
    export OPENSSL_MODULES=$WOLFPROV_PATH
    export OPENSSL_CONF=${WOLFPROV_CONFIG}
    echo "Switched to wolfProvider"
}

# Helper function to handle force fail checks
check_force_fail() {
    if [ "${WOLFPROV_FORCE_FAIL}" = "1" ]; then
        echo "[PASS] Test passed when force fail was enabled"
        FORCE_FAIL_PASSED=1
    fi
}

# Array of RSA key types, sizes, and providers to test
KEY_TYPES=("RSA" "RSA-PSS")
KEY_SIZES=("2048" "3072" "4096")
PROVIDER_ARGS=("-provider-path $WOLFPROV_PATH -provider libwolfprov" "-provider default")

echo "=== Running RSA Key Generation Tests ==="

# Function to validate key
validate_key() {
    local key_type=$1
    local key_size=$2
    local key_file=${3:-"rsa_outputs/${key_type}_${key_size}.pem"}
    local provider_args=$4
    echo -e "\n=== Validating ${key_type} Key (${key_size}) ==="
    
    # First check if file exists
    if [ ! -f "$key_file" ]; then
        echo "[FAIL] ${key_type} key (${key_size}) file does not exist"
        FAIL=1
        return
    fi

    # Then check if file is empty (has size 0)
    if [ ! -s "$key_file" ]; then
        echo "[FAIL] ${key_type} key (${key_size}) file is empty"
        FAIL=1
        return
    else
        echo "[PASS] ${key_type} key file exists and has content"
        check_force_fail
    fi
    
    # Only try to extract public key if file exists and has content
    local pub_key_file="rsa_outputs/${key_type}_${key_size}_pub.pem"
    if $OPENSSL_BIN pkey -in "$key_file" -pubout -out "$pub_key_file" \
        ${provider_args} -passin pass: >/dev/null; then
        echo "[PASS] ${key_type} Public key extraction successful"
        check_force_fail
    else
        echo "[FAIL] ${key_type} Public key extraction failed"
        FAIL=1
    fi
}

# Function to sign data with RSA-PSS
sign_rsa_pss() {
    local key_file=$1
    local data_file=$2
    local sig_file=$3
    local provider_args=$4
    
    echo "Signing data with RSA-PSS..."
    $OPENSSL_BIN pkeyutl -sign -inkey "$key_file" \
        ${provider_args} -provider default -passin pass: \
        -rawin -digest sha256 \
        -pkeyopt rsa_padding_mode:pss \
        -pkeyopt rsa_pss_saltlen:-1 \
        -pkeyopt rsa_mgf1_md:sha256 \
        -in "$data_file" \
        -out "$sig_file"
    return $?
}

# Function to verify RSA-PSS signature
verify_rsa_pss() {
    local pub_key_file=$1
    local data_file=$2
    local sig_file=$3
    local provider_args=$4
    
    echo "Verifying RSA-PSS signature..."
    $OPENSSL_BIN pkeyutl -verify -pubin -inkey "$pub_key_file" \
        ${provider_args} -provider default -passin pass: \
        -rawin -digest sha256 \
        -pkeyopt rsa_padding_mode:pss \
        -pkeyopt rsa_pss_saltlen:-1 \
        -pkeyopt rsa_mgf1_md:sha256 \
        -in "$data_file" \
        -sigfile "$sig_file"
    return $?
}

# Function to sign data with standard RSA
sign_rsa() {
    local key_file=$1
    local data_file=$2
    local sig_file=$3
    local provider_args=$4
    
    echo "Signing data with standard RSA..."
    $OPENSSL_BIN pkeyutl -sign -inkey "$key_file" \
        ${provider_args} -passin pass: \
        -in "$data_file" \
        -out "$sig_file"
    return $?
}

# Function to verify standard RSA signature
verify_rsa() {
    local pub_key_file=$1
    local data_file=$2
    local sig_file=$3
    local provider_args=$4
    
    echo "Verifying standard RSA signature..."
    $OPENSSL_BIN pkeyutl -verify -pubin -inkey "$pub_key_file" \
        ${provider_args} -passin pass: \
        -in "$data_file" \
        -sigfile "$sig_file"
    return $?
}

# Generic function to test sign/verify interoperability using pkeyutl
test_sign_verify_pkeyutl() {
    local key_type=$1
    local key_size=$2
    local provider_args=$3
    local sign_func=$4
    local verify_func=$5

    # Print the provider args
    if [ "$provider_args" = "-provider default" ]; then
        provider_name="default"
    else
        provider_name="wolfProvider"
    fi
    
    # Handle different key naming conventions
    local key_prefix="${key_type}"
    if [ "$key_type" = "RSA" ]; then
        key_prefix="RSA"
    fi
    
    local key_file="rsa_outputs/${key_prefix}_${key_size}.pem"
    local pub_key_file="rsa_outputs/${key_prefix}_${key_size}_pub.pem"
    local data_file="rsa_outputs/test_data.txt"
    
    echo -e "\n=== Testing ${key_type} (${key_size}) Sign/Verify with pkeyutl Using ${provider_name} ==="
    
    # Test 1: Sign and verify with OpenSSL default
    use_default_provider
    echo "Test 1: Sign and verify with OpenSSL default (${key_type})"
    local default_sig_file="rsa_outputs/${key_prefix}_${key_size}_default_sig.bin"
    if $sign_func "$key_file" "$data_file" "$default_sig_file" "$provider_args"; then
        echo "[PASS] Signing with OpenSSL default successful"
        check_force_fail
        if $verify_func "$pub_key_file" "$data_file" "$default_sig_file" "$provider_args"; then
            echo "[PASS] Default provider verify successful"
            check_force_fail
        else
            echo "[FAIL] Default provider verify failed"
            FAIL=1
        fi
    else
        echo "[FAIL] Default provider signing failed"
        FAIL=1
    fi

    # Test 2: Sign and verify with wolfProvider
    use_wolf_provider
    echo "Test 2: Sign and verify with wolfProvider (${key_type})"
    local wolf_sig_file="rsa_outputs/${key_prefix}_${key_size}_wolf_sig.bin"
    if $sign_func "$key_file" "$data_file" "$wolf_sig_file" "$provider_args"; then
        echo "[PASS] Signing with wolfProvider successful"
        check_force_fail
        if $verify_func "$pub_key_file" "$data_file" "$wolf_sig_file" "$provider_args"; then
            echo "[PASS] wolfProvider sign/verify successful"
            check_force_fail
        else
            echo "[FAIL] wolfProvider verify failed"
            FAIL=1
        fi
    else
        echo "[FAIL] wolfProvider signing failed"
        FAIL=1
    fi
    
    # Test 3: Cross-provider verification (default sign, wolf verify)
    if [ $FAIL -eq 0 ]; then # only verify if previous tests passed
        use_wolf_provider
        echo "Test 3: Cross-provider verification (default sign, wolf verify)"
        if $verify_func "$pub_key_file" "$data_file" "$default_sig_file" "$provider_args"; then
            echo "[PASS] wolfProvider can verify OpenSSL default signature"
            check_force_fail
        else
            echo "[FAIL] wolfProvider cannot verify OpenSSL default signature"
            FAIL=1
        fi
        
        # Test 4: Cross-provider verification (wolf sign, default verify)
        use_default_provider
        echo "Test 4: Cross-provider verification (wolf sign, default verify)"
        if $verify_func "$pub_key_file" "$data_file" "$wolf_sig_file" "$provider_args"; then
            echo "[PASS] OpenSSL default can verify wolfProvider signature"
            check_force_fail
        else
            echo "[FAIL] OpenSSL default cannot verify wolfProvider signature"
            FAIL=1
        fi
    else 
        echo "[INFO] Cannot verify cross-provider signatures no key available"
    fi
}

# Function to generate and test RSA keys
generate_and_test_key() {
    local key_type=$1
    local key_size=$2
    local provider_args=$3
    local output_file="rsa_outputs/${key_type}_${key_size}.pem"
    
    echo -e "\n=== Testing ${key_type} Key Generation (${key_size}) with provider default ==="
    echo "Generating ${key_type} key (${key_size})..."
    if [ "$key_type" = "RSA-PSS" ]; then
        # For RSA-PSS, specify all parameters
        if $OPENSSL_BIN genpkey -algorithm RSA-PSS \
            ${provider_args} \
            -pkeyopt rsa_keygen_bits:${key_size} \
            -pkeyopt rsa_pss_keygen_md:sha256 \
            -pkeyopt rsa_pss_keygen_mgf1_md:sha256 \
            -pkeyopt rsa_pss_keygen_saltlen:-1 \
            -out "$output_file" 2>/dev/null; then
            echo "[PASS] RSA-PSS key generation successful"
            check_force_fail
        else
            echo "[FAIL] RSA-PSS key generation failed"
            FAIL=1
        fi
    else
        # Regular RSA key generation
        if $OPENSSL_BIN genpkey -algorithm RSA \
            ${provider_args} \
            -pkeyopt rsa_keygen_bits:${key_size} \
            -out "$output_file" 2>/dev/null; then
            echo "[PASS] RSA key generation successful"
            check_force_fail
        else
            echo "[FAIL] RSA key generation failed"
            FAIL=1
        fi
    fi

    # Verify the key was generated
    if [ -s "$output_file" ]; then
        echo "[PASS] ${key_type} key (${key_size}) generation successful"
        check_force_fail
    else
        echo "[FAIL] ${key_type} key (${key_size}) generation failed"
        FAIL=1
    fi
    
    # Validate key
    validate_key "$key_type" "$key_size" "$output_file" "$provider_args"

    # Try to use the key with provider default
    echo -e "\n=== Testing ${key_type} Key (${key_size}) with provider default ==="
    echo "Checking if provider default can use the key..."
    
    # Try to use the key with wolfProvider (just check if it loads)
    if $OPENSSL_BIN pkey -in "$output_file" -check \
        ${provider_args} -passin pass: >/dev/null; then
        echo "[PASS] provider default can use ${key_type} key (${key_size})"
        check_force_fail
    else
        echo "[FAIL] provider default cannot use ${key_type} key (${key_size})"
        FAIL=1
    fi
}

# Test key generation for each type, size, and provider
for key_type in "${KEY_TYPES[@]}"; do
    for key_size in "${KEY_SIZES[@]}"; do
        # Generate with default provider
        test_provider="-provider default"
        generate_and_test_key "$key_type" "$key_size" "$test_provider"
    
        # Test sign/verify interoperability with appropriate function
        for test_provider in "${PROVIDER_ARGS[@]}"; do
            if [ "$key_type" = "RSA-PSS" ]; then
                test_sign_verify_pkeyutl "$key_type" "$key_size" "$test_provider" sign_rsa_pss verify_rsa_pss
            else
                test_sign_verify_pkeyutl "$key_type" "$key_size" "$test_provider" sign_rsa verify_rsa
            fi
        done
    done
done

if [ "${WOLFPROV_FORCE_FAIL}" = "1" ]; then
    if [ $FORCE_FAIL_PASSED -eq 1 ]; then
        echo -e "\n=== RSA Tests Failed With Force Fail Enabled ==="
        echo "ERROR: Some tests passed when they should have failed"
        exit 1
    else
        echo -e "\n=== RSA Tests Passed With Force Fail Enabled ==="
        echo "SUCCESS: All tests failed as expected"
        exit 0
    fi
else
    if [ $FAIL -eq 0 ]; then
        echo -e "\n=== All RSA tests completed successfully ==="
        exit 0
    else
        echo -e "\n=== RSA tests completed with failures ==="
        exit 1
    fi
fi
