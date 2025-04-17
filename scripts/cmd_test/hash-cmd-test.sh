#!/bin/bash

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
if ! $OPENSSL_BIN list -providers | grep -q "wolf"; then
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

# Create test data and output directories
mkdir -p hash_outputs
echo "This is test data for hash algorithm testing." > test.txt

# Function to run hash test with specified provider options
run_hash_test() {
    local algo="$1"
    local provider_opts="$2"
    local output_file="$3"
    
    # Run the hash algorithm with specified provider options
    $OPENSSL_BIN dgst -$algo $provider_opts -out "$output_file" test.txt
    local result=$?
    
    if [ -f "$output_file" ]; then
        cat "$output_file"
    else
        echo "Output file not created"
        return 1
    fi
    
    return $result
}

# Function to compare hash outputs
compare_hashes() {
    local algo="$1"
    local openssl_file="hash_outputs/openssl_${algo}.txt"
    local wolf_file="hash_outputs/wolf_${algo}.txt"
    
    echo -e "\nComparing ${algo} hashes:"
    
    if [ ! -f "$openssl_file" ]; then
        echo "[FAIL] OpenSSL hash file does not exist"
        TEST_STATUS=1
        return 1
    fi
    
    if [ ! -f "$wolf_file" ]; then
        echo "[FAIL] Wolf hash file does not exist"
        TEST_STATUS=1
        return 1
    fi
    
    echo "OpenSSL: $(cat $openssl_file)"
    echo "Wolf:    $(cat $wolf_file)"
    
    if cmp -s "$openssl_file" "$wolf_file"; then
        if [ $EXPECT_FAILURE -eq 1 ]; then
            echo "[UNEXPECTED PASS] ${algo} hashes match when failure was expected"
            TEST_STATUS=1
            return 1
        else
            echo "[PASS] ${algo} hashes match"
            return 0
        fi
    else
        if [ $EXPECT_FAILURE -eq 1 ]; then
            echo "[EXPECTED FAIL] ${algo} hashes don't match (expected with WOLFPROV_FORCE_FAIL=1)"
            return 0
        else
            echo "[FAIL] ${algo} hashes don't match"
            TEST_STATUS=1
            return 1
        fi
    fi
}

# Array of hash algorithms to test
HASH_ALGOS=("sha1" "sha224" "sha256" "sha384" "sha512")

echo "=== Running Hash Algorithm Comparisons ==="

# Run tests for each hash algorithm
for algo in "${HASH_ALGOS[@]}"; do
    echo -e "\n=== Testing ${algo^^} ==="
    
    # Test with OpenSSL default provider
    echo "Running with OpenSSL default provider:"
    if ! run_hash_test $algo "-provider default" "hash_outputs/openssl_${algo}.txt"; then
        echo "[FAIL] OpenSSL default provider hash generation failed"
        TEST_STATUS=1
    fi
    
    # Test with wolfProvider
    echo "Running with wolfProvider:"
    if ! run_hash_test $algo "-provider-path $WOLFPROV_PATH -provider libwolfprov" "hash_outputs/wolf_${algo}.txt"; then
        echo "[FAIL] wolfProvider hash generation failed"
        if [ $EXPECT_FAILURE -eq 1 ]; then
            echo "[EXPECTED] Failure with WOLFPROV_FORCE_FAIL=1"
        else
            TEST_STATUS=1
        fi
    fi
    
    # Compare results
    compare_hashes $algo
done

if [ $TEST_STATUS -eq 0 ]; then
    if [ $EXPECT_FAILURE -eq 1 ]; then
        echo -e "\n=== Hash tests completed with expected failures ==="
    else
        echo -e "\n=== All hash tests completed successfully ==="
    fi
    exit 0
else
    if [ $EXPECT_FAILURE -eq 1 ]; then
        echo -e "\n=== Hash tests failed in unexpected ways ==="
    else
        echo -e "\n=== Hash tests failed ==="
    fi
    exit 1
fi
