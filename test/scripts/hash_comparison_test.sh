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
if ! openssl list -providers | grep -q "wolf"; then
    echo "[FAIL] wolfProvider not found in OpenSSL providers!"
    echo "Current provider list:"
    openssl list -providers
    exit 1
fi
echo "[PASS] wolfProvider is properly configured"

# Print environment for verification
echo "Environment variables:"
echo "OPENSSL_MODULES: ${OPENSSL_MODULES}"
echo "OPENSSL_CONF: ${OPENSSL_CONF}"
echo "LD_LIBRARY_PATH: ${LD_LIBRARY_PATH}"

# Create directory for hash outputs
mkdir -p hash_outputs

# Create test data
echo "Hello, World!" > test.txt

# Function to run hash test and save output
run_hash_test() {
    local algo=$1
    local provider_args=$2
    local output_file=$3
    
    openssl dgst -$algo $provider_args test.txt | tee "$output_file"
}

# Function to compare hash files
compare_hashes() {
    local algo=$1
    local openssl_file="hash_outputs/openssl_${algo}.txt"
    local wolf_file="hash_outputs/wolf_${algo}.txt"
    
    echo -e "\nComparing ${algo^^} hashes:"
    echo "OpenSSL: $(cat $openssl_file)"
    echo "Wolf:    $(cat $wolf_file)"
    
    if diff -q "$openssl_file" "$wolf_file" >/dev/null; then
        echo "[PASS] ${algo^^} hashes match"
        return 0
    else
        echo "[FAIL] ${algo^^} hash mismatch"
        return 1
    fi
}

# Array of hash algorithms to test
HASH_ALGORITHMS=("sha1" "sha224" "sha256" "sha384" "sha512")

echo "=== Running Hash Algorithm Comparisons ==="

# Save current OPENSSL_CONF
OPENSSL_CONF_BACKUP=$OPENSSL_CONF

for algo in "${HASH_ALGORITHMS[@]}"; do
    echo -e "\n=== Testing ${algo^^} ==="
    
    # Test with default OpenSSL provider
    unset OPENSSL_CONF
    run_hash_test $algo "" "hash_outputs/openssl_${algo}.txt"
    
    # Test with wolfProvider
    export OPENSSL_CONF=$OPENSSL_CONF_BACKUP
    run_hash_test $algo "-provider wolf -provider default" "hash_outputs/wolf_${algo}.txt"
    
    # Compare results
    compare_hashes $algo || exit 1
done

# Cleanup
rm -f test.txt
rm -rf hash_outputs
