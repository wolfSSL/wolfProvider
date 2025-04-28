#!/bin/bash

# Set up environment
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
REPO_ROOT="$( cd "${SCRIPT_DIR}/../.." &> /dev/null && pwd )"
UTILS_DIR="${REPO_ROOT}/scripts"
export LOG_FILE="${SCRIPT_DIR}/aes-test.log"
touch "$LOG_FILE"

# Source wolfProvider utilities
source "${UTILS_DIR}/utils-general.sh"
source "${UTILS_DIR}/utils-openssl.sh"
source "${UTILS_DIR}/utils-wolfssl.sh"
source "${UTILS_DIR}/utils-wolfprovider.sh"

# Initialize the environment
init_wolfprov

# Fail flag
FAIL=0

# Verify wolfProvider is properly loaded
echo -e "\nVerifying wolfProvider configuration:"
if ! $OPENSSL_BIN list -providers | grep -q "wolf"; then
    echo "[FAIL] wolfProvider not found in OpenSSL providers!"
    echo "Current provider list:"
    $OPENSSL_BIN list -providers
    FAIL=1
else
    echo "[PASS] wolfProvider is properly configured"
fi

# Print environment for verification
echo "Environment variables:"
echo "OPENSSL_MODULES: ${OPENSSL_MODULES}"
echo "LD_LIBRARY_PATH: ${LD_LIBRARY_PATH}"
echo "OPENSSL_BIN: ${OPENSSL_BIN}"

# Create test data and output directories
mkdir -p aes_outputs
echo "This is test data for AES encryption testing." > test.txt

# Arrays for test configurations
KEY_SIZES=("128" "192" "256")
# Only include modes supported by wolfProvider
MODES=("ecb" "cbc" "ctr" "cfb")

echo "=== Running AES Algorithm Comparisons ==="

# Run tests for each key size and mode
for key_size in "${KEY_SIZES[@]}"; do
    for mode in "${MODES[@]}"; do
        echo -e "\n=== Testing AES-${key_size}-${mode} ==="
        
        # Generate random key and IV
        key=$($OPENSSL_BIN rand -hex $((key_size/8)))
        iv=""
        if [ "$mode" != "ecb" ]; then
            iv="-iv $($OPENSSL_BIN rand -hex 16)"
        fi
        
        # Output files
        enc_file="aes_outputs/aes${key_size}_${mode}.enc"
        dec_file="aes_outputs/aes${key_size}_${mode}.dec"
        
        # Interop testing: Encrypt with default provider, decrypt with wolfProvider
        echo "Interop testing (encrypt with default, decrypt with wolfProvider):"
        
        # Encryption with OpenSSL default provider
        if ! $OPENSSL_BIN enc -aes-${key_size}-${mode} -K $key $iv -provider default \
            -in test.txt -out "$enc_file" -p; then
            echo "[FAIL] Interop AES-${key_size}-${mode}: OpenSSL encrypt failed"
            FAIL=1
        fi
        
        # Decryption with wolfProvider
        if ! $OPENSSL_BIN enc -aes-${key_size}-${mode} -K $key $iv -provider-path $WOLFPROV_PATH -provider libwolfprov \
            -in "$enc_file" -out "$dec_file" -d -p; then
            echo "[FAIL] Interop AES-${key_size}-${mode}: wolfProvider decrypt failed"
            FAIL=1
        fi
        
        if [ $FAIL -eq 0 ]; then
            if cmp -s "test.txt" "$dec_file"; then
                echo "[PASS] Interop AES-${key_size}-${mode}: OpenSSL encrypt, wolfProvider decrypt"
            else
                echo "[FAIL] Interop AES-${key_size}-${mode}: OpenSSL encrypt, wolfProvider decrypt"
                FAIL=1
            fi
        else
            echo "[INFO] Cannot verify encryption/decryption - no key available"
        fi
        
        # Interop testing: Encrypt with wolfProvider, decrypt with default provider
        echo "Interop testing (encrypt with wolfProvider, decrypt with default):"
        
        # Encryption with wolfProvider
        if ! $OPENSSL_BIN enc -aes-${key_size}-${mode} -K $key $iv -provider-path $WOLFPROV_PATH -provider libwolfprov \
            -in test.txt -out "$enc_file" -p; then
            echo "[FAIL] Interop AES-${key_size}-${mode}: wolfProvider encrypt failed"
            FAIL=1
        fi
        
        # Decryption with OpenSSL default provider
        if ! $OPENSSL_BIN enc -aes-${key_size}-${mode} -K $key $iv -provider default \
            -in "$enc_file" -out "$dec_file" -d -p; then
            echo "[FAIL] Interop AES-${key_size}-${mode}: OpenSSL decrypt failed"
            FAIL=1
        fi
        
        if [ $FAIL -eq 0 ]; then
            if cmp -s "test.txt" "$dec_file"; then
                echo "[PASS] Interop AES-${key_size}-${mode}: wolfProvider encrypt, OpenSSL decrypt"
            else
                echo "[FAIL] Interop AES-${key_size}-${mode}: wolfProvider encrypt, OpenSSL decrypt"
                FAIL=1
            fi
        else
            echo "[INFO] Cannot verify encryption/decryption - no key available"
        fi
    done
done

# Change end of script to check FAIL flag
if [ $FAIL -eq 0 ]; then
    echo -e "\n=== All AES tests completed successfully ==="
    exit 0
else
    echo -e "\n=== AES tests completed with failures ==="
    exit 1
fi
