#!/bin/bash
# req-cmd-test.sh
# Certificate request (X.509) generation test for wolfProvider
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
REPO_ROOT="$( cd "${SCRIPT_DIR}/../.." &> /dev/null && pwd )"
source "${SCRIPT_DIR}/cmd-test-common.sh"
source "${SCRIPT_DIR}/clean-cmd-test.sh"
cmd_test_env_setup "req-test.log"
clean_cmd_test "req"

# Redirect all output to log file
exec > >(tee -a "$LOG_FILE") 2>&1

# Create test data and output directories
mkdir -p req_outputs

# Array of ECC curves and hash algorithms to test
CURVES=("prime256v1" "secp384r1" "secp521r1")
HASH_ALGORITHMS=("sha256" "sha384" "sha512")
PROVIDER_ARGS=("-provider-path $WOLFPROV_PATH -provider libwolfprov" "-provider default")

echo "=== Running Certificate Request (X.509) Tests ==="

# Function to detect replace-default builds
detect_replace_default_build() {
    local libcrypto_path=""
    
    # Try common locations
    if [ -n "${OPENSSL_LIB_PATH:-}" ] && [ -f "${OPENSSL_LIB_PATH}/libcrypto.so" ]; then
        libcrypto_path="${OPENSSL_LIB_PATH}/libcrypto.so"
    elif [ -f "${REPO_ROOT}/openssl-install/lib64/libcrypto.so" ]; then
        libcrypto_path="${REPO_ROOT}/openssl-install/lib64/libcrypto.so"
    elif [ -f "${REPO_ROOT}/openssl-install/lib/libcrypto.so" ]; then
        libcrypto_path="${REPO_ROOT}/openssl-install/lib/libcrypto.so"
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

# Check if this is a replace-default build and skip testing if so
if detect_replace_default_build; then
    echo "INFO: --replace-default build detected"
    echo "INFO: Skipping req command tests (provider switching not supported in replace-default mode)"
    echo "SUCCESS: Certificate Request tests skipped for replace-default build"
    exit 0
fi

# Function to test certificate creation with specific curve and hash
test_cert_creation() {
    local curve=$1
    local hash_alg=$2
    local req_provider_args=$3
    
    # Get the provider name for req command
    req_provider_name=$(get_provider_name "$req_provider_args")
    
    local key_file="req_outputs/key_${curve}_${hash_alg}.pem"
    local cert_file="req_outputs/cert_${curve}_${hash_alg}_${req_provider_name//lib/}.pem"
    
    echo -e "\n=== Testing Certificate Creation (${curve}/${hash_alg}) - req with ${req_provider_name} ==="
    
    # Always generate EC key with default provider
    echo "Generating EC key with curve ${curve} using default provider..."
    use_default_provider
    if $OPENSSL_BIN ecparam -genkey -name ${curve} -out "$key_file" \
        -provider default 2>/dev/null; then
        echo "[PASS] EC key generation successful"
        check_force_fail
    else
        echo "[FAIL] EC key generation failed"
        FAIL=1
        return
    fi
    
    # Set provider for req command
    if [[ "$req_provider_args" == *"libwolfprov"* ]]; then
        use_wolf_provider
    else
        use_default_provider
    fi
    
    # Create certificate with specified provider
    echo "Creating self-signed certificate with ${hash_alg} using ${req_provider_name}..."
    if $OPENSSL_BIN req -x509 -new -key "$key_file" -${hash_alg} -days 365 \
        -out "$cert_file" -subj "/CN=test-${curve}-${hash_alg}" ${req_provider_args} 2>/dev/null; then
        echo "[PASS] Certificate creation successful"
        check_force_fail
    else
        echo "[FAIL] Certificate creation failed"
        FAIL=1
        return
    fi
    
    # Check if certificate file exists and is non-empty
    if [ -s "$cert_file" ]; then
        echo "[PASS] Certificate file exists and is non-empty"
        check_force_fail
    else
        echo "[FAIL] Certificate file does not exist or is empty"
        FAIL=1
    fi
}

# Main test execution
echo "Starting certificate request tests..."

# Test certificate creation with each combination
for curve in "${CURVES[@]}"; do
    for hash_alg in "${HASH_ALGORITHMS[@]}"; do
        for provider_arg in "${PROVIDER_ARGS[@]}"; do
            test_cert_creation "$curve" "$hash_alg" "$provider_arg"
        done
    done
done

if [ "${WOLFPROV_FORCE_FAIL}" = "1" ]; then
    if [ $FORCE_FAIL_PASSED -eq 1 ]; then
        echo -e "\n=== Certificate Request Tests Failed With Force Fail Enabled ==="
        echo "ERROR: Some tests passed when they should have failed"
        exit 1
    else
        echo -e "\n=== Certificate Request Tests Passed With Force Fail Enabled ==="
        echo "SUCCESS: All tests failed as expected"
        exit 0
    fi
else
    if [ $FAIL -eq 0 ]; then
        echo -e "\n=== All Certificate Request tests completed successfully ==="
        exit 0
    else
        echo -e "\n=== Certificate Request tests completed with failures ==="
        exit 1
    fi
fi
