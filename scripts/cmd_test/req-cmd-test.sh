#!/bin/bash
# req-cmd-test.sh
# Certificate request test for wolfProvider
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

CMD_TEST_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
source "${CMD_TEST_DIR}/cmd-test-common.sh"
source "${CMD_TEST_DIR}/clean-cmd-test.sh"

if [ -z "${DO_CMD_TESTS:-}" ]; then
    echo "This script is designed to be called from do-cmd-tests.sh"
    echo "Do not run this script directly - use do-cmd-tests.sh instead"
    exit 1
fi

cmd_test_init "req-test.log"
clean_cmd_test "req"

mkdir -p req_outputs

CURVES=("prime256v1" "secp384r1" "secp521r1") 
HASH_ALGORITHMS=("sha256" "sha384" "sha512")
PROVIDER_NAMES=("libwolfprov" "default")

# Skip tests for FIPS mode (unless force-failing)
if [ "${WOLFSSL_ISFIPS}" = "1" ] && [ "${WOLFPROV_FORCE_FAIL}" != "1" ]; then
    echo "INFO: FIPS mode detected"
    echo "INFO: Skipping req tests for FIPS mode"
    echo "SUCCESS: Certificate Request tests skipped for FIPS build"
    exit 0
fi

# Function to test certificate creation
test_cert_creation() {
    local curve=$1
    local hash_alg=$2
    local req_provider_name=$3
    
    local key_file="req_outputs/key_${curve}_${hash_alg}.pem"
    local cert_file="req_outputs/cert_${curve}_${hash_alg}_${req_provider_name//lib/}.pem"
    
    echo -e "\n=== Testing Certificate Creation (${curve}/${hash_alg}) - req with ${req_provider_name} ==="

    if [ -f "$key_file" ]; then
        echo "Key file $key_file already exists, removing it."
        rm -f "$key_file"
    fi

    if [ -f "$cert_file" ]; then
        echo "Certificate file $cert_file already exists, removing it."
        rm -f "$cert_file"
    fi
    
    # Generate EC key with default provider
    echo "Generating EC key with curve ${curve} using default provider..."
    use_default_provider
    if $OPENSSL_BIN ecparam -genkey -name ${curve} -out "$key_file" 2>/dev/null; then
        echo "[PASS] EC key generation successful"
        check_force_fail
    else
        echo "[FAIL] EC key generation failed"
        FAIL=1
        return
    fi
    
    # Set provider for req command
    use_provider_by_name "$req_provider_name"
    
    # Create certificate with specified provider
    echo "Creating self-signed certificate with ${hash_alg} using ${req_provider_name}..."
    if $OPENSSL_BIN req -x509 -new -key "$key_file" -${hash_alg} -days 365 \
        -out "$cert_file" -subj "/CN=test-${curve}-${hash_alg}"2>/dev/null; then
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

for curve in "${CURVES[@]}"; do
    for hash_alg in "${HASH_ALGORITHMS[@]}"; do
        for provider_name in "${PROVIDER_NAMES[@]}"; do
            test_cert_creation "$curve" "$hash_alg" "$provider_name"
        done
    done
done

# Force-fail handling (same pattern as other cmd tests)
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
