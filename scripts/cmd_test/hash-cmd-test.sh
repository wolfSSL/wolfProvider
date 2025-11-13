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

CMD_TEST_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
source "${CMD_TEST_DIR}/cmd-test-common.sh"
source "${CMD_TEST_DIR}/clean-cmd-test.sh"

if [ -z "${DO_CMD_TESTS:-}" ]; then
    echo "This script is designed to be called from do-cmd-tests.sh"
    echo "Do not run this script directly - use do-cmd-tests.sh instead"
    exit 1
fi

cmd_test_init "hash-test.log"
clean_cmd_test "hash"

# Create test data and output directories
mkdir -p hash_outputs
echo "This is test data for hash cmd test." > hash_outputs/test_data.txt

# Array of hash algorithms to test
HASH_ALGOS=("sha1" "sha224" "sha256" "sha384" "sha512")

# Function to run hash test with specified provider options
run_hash_test() {
    local algo="$1"
    local output_file="$2"
    
    # Run the hash algorithm with specified provider options
    if ! $OPENSSL_BIN dgst -$algo $provider_opts -out "$output_file" hash_outputs/test_data.txt; then
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
    use_default_provider
    run_hash_test $algo "hash_outputs/openssl_${algo}.txt"
    
    # Test with wolfProvider
    use_wolf_provider
    run_hash_test $algo "hash_outputs/wolf_${algo}.txt"
    
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
