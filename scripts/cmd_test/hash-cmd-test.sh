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

# Verify wolfProvider is properly loaded
echo -e "\nVerifying wolfProvider configuration:"
if ! $OPENSSL_BIN list -providers | grep -q "wolf"; then
    echo "[FAIL] wolfProvider not found in OpenSSL providers!"
    echo "Current provider list:"
    $OPENSSL_BIN list -providers
    exit 1
fi
echo "[PASS] wolfProvider is properly configured"

# Print environment for verification
echo "Environment variables:"
echo "OPENSSL_MODULES: ${OPENSSL_MODULES}"
echo "LD_LIBRARY_PATH: ${LD_LIBRARY_PATH}"
echo "OPENSSL_BIN: ${OPENSSL_BIN}"

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
    
    # Print the hash for verification
    cat "$output_file"
}

# Function to compare hash outputs
compare_hashes() {
    local algo="$1"
    local openssl_file="hash_outputs/openssl_${algo}.txt"
    local wolf_file="hash_outputs/wolf_${algo}.txt"
    
    echo -e "\nComparing ${algo} hashes:"
    echo "OpenSSL: $(cat $openssl_file)"
    echo "Wolf:    $(cat $wolf_file)"
    
    if cmp -s "$openssl_file" "$wolf_file"; then
        echo "[PASS] ${algo} hashes match"
        return 0
    else
        echo "[FAIL] ${algo} hashes don't match"
        return 1
    fi
}

# Array of hash algorithms to test
HASH_ALGOS=("sha1" "sha224" "sha256" "sha384" "sha512")

echo "=== Running Hash Algorithm Comparisons ==="

# Run tests for each hash algorithm
for algo in "${HASH_ALGOS[@]}"; do
    echo -e "\n=== Testing ${algo^^} ==="
    
    # Test with OpenSSL default provider
    run_hash_test $algo "-provider default" "hash_outputs/openssl_${algo}.txt"
    
    # Test with wolfProvider
    run_hash_test $algo "-provider-path $WOLFPROV_PATH -provider libwolfprov" "hash_outputs/wolf_${algo}.txt"
    
    # Compare results
    compare_hashes $algo || exit 1
done

echo -e "\n=== All hash tests completed successfully ==="
exit 0
