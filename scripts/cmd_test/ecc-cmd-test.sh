#!/bin/bash
# ecc-cmd-test.sh
# ECC key generation test for wolfProvider
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
cmd_test_env_setup "ecc-test.log"
clean_cmd_test "ecc"

# Redirect all output to log file
exec > >(tee -a "$LOG_FILE") 2>&1

# Create test data and output directories
mkdir -p ecc_outputs
echo "This is test data for ECC signing and verification." > ecc_outputs/test_data.txt

# Array of ECC curves and providers to test
CURVES=("prime256v1" "secp384r1" "secp521r1")
PROVIDER_ARGS=("-provider-path $WOLFPROV_PATH -provider libwolfprov" "-provider default")

echo "=== Running ECC Key Generation Tests ==="

# Function to validate key
validate_key() {
    local curve=$1
    local key_file=${2:-"ecc_outputs/ecc_${curve}.pem"}
    local provider_args=$3
    echo -e "\n=== Validating ECC Key (${curve}) ==="
    
    # First check if file exists
    if [ ! -f "$key_file" ]; then
        echo "[FAIL] ECC key (${curve}) file does not exist"
        FAIL=1
        return
    fi
    
    # Then check if file is empty (has size 0)
    if [ ! -s "$key_file" ]; then
        echo "[FAIL] ECC key (${curve}) file is empty"
        FAIL=1
        return
    else
        echo "[PASS] ECC key file exists and has content"
        check_force_fail
    fi
    
    # Only try to extract public key if file exists and has content
    local pub_key_file="ecc_outputs/ecc_${curve}_pub.pem"
    if $OPENSSL_BIN pkey -in "$key_file" -pubout -out "$pub_key_file" \
        ${provider_args} -passin pass: >/dev/null; then
        echo "[PASS] ECC Public key extraction successful"
        check_force_fail
    else
        echo "[FAIL] ECC Public key extraction failed"
        FAIL=1
    fi
}

# Function to sign data with ECC
sign_ecc() {
    local key_file=$1
    local data_file=$2
    local sig_file=$3
    local provider_args=$4
    
    echo "Signing data with ECC..."
    $OPENSSL_BIN pkeyutl -sign -inkey "$key_file" \
        ${provider_args} -passin pass: \
        -in "$data_file" \
        -out "$sig_file"
    return $?
}

# Function to verify ECC signature
verify_ecc() {
    local pub_key_file=$1
    local data_file=$2
    local sig_file=$3
    local provider_args=$4
    
    echo "Verifying ECC signature..."
    $OPENSSL_BIN pkeyutl -verify -pubin -inkey "$pub_key_file" \
        ${provider_args} -passin pass: \
        -in "$data_file" \
        -sigfile "$sig_file"
    return $?
}

# Generic function to test sign/verify interoperability using pkeyutl
test_sign_verify_pkeyutl() {
    local curve=$1
    local provider_args=$2
    
    # Get the provider name
    provider_name=$(get_provider_name "$provider_args")
    
    local key_file="ecc_outputs/ecc_${curve}.pem"
    local pub_key_file="ecc_outputs/ecc_${curve}_pub.pem"
    local data_file="ecc_outputs/test_data.txt"
    
    echo -e "\n=== Testing ECC (${curve}) Sign/Verify with pkeyutl Using ${provider_name} ==="

    if [ ! -f "$key_file" ] || [ ! -f "$pub_key_file" ]; then
        echo "[FAIL] Key files for ECC (${curve}) not found, cannot run sign/verify tests"
        FAIL=1
        exit 1
    fi

    if [ ! -f "$data_file" ]; then
        echo "[FAIL] Test data file not found, cannot run sign/verify tests"
        FAIL=1
        exit 1
    fi
    
    # Test 1: Sign and verify with OpenSSL default
    use_default_provider
    echo "Test 1: Sign and verify with OpenSSL default"
    local default_sig_file="ecc_outputs/ecc_${curve}_default_sig.bin"
    if sign_ecc "$key_file" "$data_file" "$default_sig_file" "$provider_args"; then
        echo "[PASS] Signing with OpenSSL default successful"
        check_force_fail
        if verify_ecc "$pub_key_file" "$data_file" "$default_sig_file" "$provider_args"; then
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
    echo "Test 2: Sign and verify with wolfProvider"
    local wolf_sig_file="ecc_outputs/ecc_${curve}_wolf_sig.bin"
    if sign_ecc "$key_file" "$data_file" "$wolf_sig_file" "$provider_args"; then
        echo "[PASS] Signing with wolfProvider successful"
        check_force_fail
        if verify_ecc "$pub_key_file" "$data_file" "$wolf_sig_file" "$provider_args"; then
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
        if verify_ecc "$pub_key_file" "$data_file" "$default_sig_file" "$provider_args"; then
            echo "[PASS] wolfProvider can verify OpenSSL default signature"
            check_force_fail
        else
            echo "[FAIL] wolfProvider cannot verify OpenSSL default signature"
            FAIL=1
        fi
        
        # Test 4: Cross-provider verification (wolf sign, default verify)
        use_default_provider
        echo "Test 4: Cross-provider verification (wolf sign, default verify)"
        if verify_ecc "$pub_key_file" "$data_file" "$wolf_sig_file" "$provider_args"; then
            echo "[PASS] OpenSSL default can verify wolfProvider signature"
            check_force_fail
        else
            echo "[FAIL] OpenSSL default cannot verify wolfProvider signature"
            FAIL=1
        fi
    else 
        echo "[INFO] Cannot verify cross-provider signatures - no key available"
    fi
}

# Function to generate and test ECC keys
generate_and_test_key() {
    local curve=$1
    local provider_args=$2
    local output_file="ecc_outputs/ecc_${curve}.pem"

    # Get the provider name
    provider_name=$(get_provider_name "$provider_args")
    
    echo -e "\n=== Testing ECC Key Generation (${curve}) with ${provider_name} ==="

    if [ -f "$output_file" ]; then
        echo "ECC key file $output_file already exists, removing it."
        rm -f "$output_file"
    fi

    echo "Generating ECC key (${curve})..."
    
    if $OPENSSL_BIN genpkey -algorithm EC \
        ${provider_args} \
        -pkeyopt ec_paramgen_curve:${curve} \
        -out "$output_file" 2>/dev/null; then
        echo "[PASS] ECC key generation successful"
        check_force_fail
    else
        echo "[FAIL] ECC key generation failed"
        FAIL=1
    fi

    # Verify the key was generated
    if [ -s "$output_file" ]; then
        echo "[PASS] ECC key generation successful"
        check_force_fail
    else
        echo "[FAIL] ECC key generation failed"
        FAIL=1
    fi
    
    # Validate key
    validate_key "$curve" "$output_file" "$provider_args"

    # Try to use the key with different providers
    echo -e "\n=== Testing ECC Key (${curve}) with ${provider_name} ==="
    echo "Checking if ${provider_name} can use the key..."
    
    # Try to use the key with wolfProvider (just check if it loads)
    if $OPENSSL_BIN pkey -in "$output_file" -check \
        ${provider_args} -passin pass: >/dev/null; then
        echo "[PASS] ${provider_name} can use ECC key (${curve})"
        check_force_fail
    else
        echo "[FAIL] ${provider_name} cannot use ECC key (${curve})"
        FAIL=1
    fi
}

# Test key generation for each curve and provider
for curve in "${CURVES[@]}"; do
    for test_provider in "${PROVIDER_ARGS[@]}"; do
        # Generate key with current provider
        generate_and_test_key "$curve" "$test_provider"

        # If WPFF is set, we need to run again to actually create the 
        # key files
        if [ $WOLFPROV_FORCE_FAIL -ne 0 ]; then
            WOLFPROV_FORCE_FAIL=0
            generate_and_test_key "$curve" "$test_provider"
            WOLFPROV_FORCE_FAIL=1
        fi

        # Test sign/verify interoperability
        test_sign_verify_pkeyutl "$curve" "$test_provider"
    done
done

if [ "${WOLFPROV_FORCE_FAIL}" = "1" ]; then
    if [ $FORCE_FAIL_PASSED -eq 1 ]; then
        echo -e "\n=== ECC Tests Failed With Force Fail Enabled ==="
        echo "ERROR: Some tests passed when they should have failed"
        exit 1
    else
        echo -e "\n=== ECC Tests Passed With Force Fail Enabled ==="
        echo "SUCCESS: All tests failed as expected"
        exit 0
    fi
else
    if [ $FAIL -eq 0 ]; then
        echo -e "\n=== All ECC tests completed successfully ==="
        exit 0
    else
        echo -e "\n=== ECC tests completed with failures ==="
        exit 1
    fi
fi
