#!/bin/bash
# hash-cmd-test.sh
# Run hash command-line tests for wolfProvider
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
export LOG_FILE="${SCRIPT_DIR}/hash-test.log"
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
    echo "Force fail mode enabled for Hash tests"
fi
if [ "${WOLFSSL_ISFIPS}" = "1" ]; then
    echo "FIPS mode enabled for Hash tests"
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
mkdir -p hash_outputs
echo "This is test data for hash algorithm testing." > test.txt

# Helper function to handle force fail checks
check_force_fail() {
    if [ "${WOLFPROV_FORCE_FAIL}" = "1" ]; then
        echo "[PASS] Test passed when force fail was enabled"
        FORCE_FAIL_PASSED=1
    fi
}

# Array of hash algorithms to test
HASH_ALGOS=("sha1" "sha224" "sha256" "sha384" "sha512")

echo "=== Running Hash Algorithm Comparisons ==="

# Function to run hash test with specified provider options
run_hash_test() {
    local algo="$1"
    local provider_opts="$2"
    local output_file="$3"
    
    # Run the hash algorithm with specified provider options
    if ! $OPENSSL_BIN dgst -$algo $provider_opts -out "$output_file" test.txt; then
        echo "[FAIL] Hash generation failed for ${algo}"
        FAIL=1
    fi
    
    # Check if output file has content
    if [ ! -s "$output_file" ]; then
        echo "[FAIL] No hash output generated for ${algo}"
        FAIL=1
    fi
    
    # Print the hash for verification if file exists and has content
    if [ -s "$output_file" ]; then
        cat "$output_file"
    fi
}

# Function to compare hash outputs
compare_hashes() {
    local algo="$1"
    local openssl_file="hash_outputs/openssl_${algo}.txt"
    local wolf_file="hash_outputs/wolf_${algo}.txt"
    
    # Check if both files exist and have content
    if [ ! -s "$openssl_file" ] || [ ! -s "$wolf_file" ]; then
        echo "[INFO] Cannot compare hashes - one or both hash files are empty"
        FAIL=1
    else
        echo -e "\nComparing ${algo} hashes:"
        echo "OpenSSL: $(cat $openssl_file)"
        echo "Wolf:    $(cat $wolf_file)"
        
        if cmp -s "$openssl_file" "$wolf_file"; then
            echo "[PASS] ${algo} hashes match"
            check_force_fail
        else
            echo "[FAIL] ${algo} hashes don't match"
            FAIL=1
        fi
    fi
}

# Run tests for each hash algorithm
for algo in "${HASH_ALGOS[@]}"; do
    echo -e "\n=== Testing ${algo^^} ==="
    
    # Test with OpenSSL default provider
    run_hash_test $algo "-provider default" "hash_outputs/openssl_${algo}.txt"
    
    # Test with wolfProvider
    run_hash_test $algo "-provider-path $WOLFPROV_PATH -provider libwolfprov" "hash_outputs/wolf_${algo}.txt"
    
    # Compare results
    compare_hashes $algo
done

# Modify end of script
if [ "${WOLFPROV_FORCE_FAIL}" = "1" ]; then
    if [ $FORCE_FAIL_PASSED -eq 1 ]; then
        echo -e "\n=== Hash Tests Failed With Force Fail Enabled ==="
        echo "ERROR: Some tests passed when they should have failed"
        exit 1
    else
        echo -e "\n=== Hash Tests Passed With Force Fail Enabled ==="
        echo "SUCCESS: All tests failed as expected"
        exit 0
    fi
else
    if [ $FAIL -eq 0 ]; then
        echo -e "\n=== All hash tests completed successfully ==="
        exit 0
    else
        echo -e "\n=== Hash tests completed with failures ==="
        exit 1
    fi
fi
