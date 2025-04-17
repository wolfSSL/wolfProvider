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
        $OPENSSL_BIN enc -aes-${key_size}-${mode} -K $key $iv -provider default \
            -in test.txt -out "$enc_file" -p
        if [ $? -ne 0 ]; then
            echo "[FAIL] OpenSSL default provider encryption failed"
            TEST_STATUS=1
            continue
        fi
        
        # Decryption with wolfProvider
        $OPENSSL_BIN enc -aes-${key_size}-${mode} -K $key $iv -provider-path $WOLFPROV_PATH -provider libwolfprov \
            -in "$enc_file" -out "$dec_file" -d -p
        wolf_decrypt_status=$?
        
        if [ $wolf_decrypt_status -ne 0 ]; then
            if [ $EXPECT_FAILURE -eq 1 ]; then
                echo "[EXPECTED FAIL] wolfProvider decryption failed (expected with WOLFPROV_FORCE_FAIL=1)"
            else
                echo "[FAIL] wolfProvider decryption failed"
                TEST_STATUS=1
            fi
            continue
        fi
        
        if cmp -s "test.txt" "$dec_file"; then
            if [ $EXPECT_FAILURE -eq 1 ]; then
                echo "[UNEXPECTED PASS] Interop AES-${key_size}-${mode}: OpenSSL encrypt, wolfProvider decrypt"
                TEST_STATUS=1
            else
                echo "[PASS] Interop AES-${key_size}-${mode}: OpenSSL encrypt, wolfProvider decrypt"
            fi
        else
            if [ $EXPECT_FAILURE -eq 1 ]; then
                echo "[EXPECTED FAIL] Interop AES-${key_size}-${mode}: OpenSSL encrypt, wolfProvider decrypt"
            else
                echo "[FAIL] Interop AES-${key_size}-${mode}: OpenSSL encrypt, wolfProvider decrypt"
                TEST_STATUS=1
            fi
        fi
        
        # Interop testing: Encrypt with wolfProvider, decrypt with default provider
        echo "Interop testing (encrypt with wolfProvider, decrypt with default):"
        
        # Encryption with wolfProvider
        $OPENSSL_BIN enc -aes-${key_size}-${mode} -K $key $iv -provider-path $WOLFPROV_PATH -provider libwolfprov \
            -in test.txt -out "$enc_file" -p
        wolf_encrypt_status=$?
        
        if [ $wolf_encrypt_status -ne 0 ]; then
            if [ $EXPECT_FAILURE -eq 1 ]; then
                echo "[EXPECTED FAIL] wolfProvider encryption failed (expected with WOLFPROV_FORCE_FAIL=1)"
            else
                echo "[FAIL] wolfProvider encryption failed"
                TEST_STATUS=1
            fi
            continue
        fi
        
        # Decryption with OpenSSL default provider
        $OPENSSL_BIN enc -aes-${key_size}-${mode} -K $key $iv -provider default \
            -in "$enc_file" -out "$dec_file" -d -p
        if [ $? -ne 0 ]; then
            echo "[FAIL] OpenSSL default provider decryption failed"
            TEST_STATUS=1
            continue
        fi
        
        if cmp -s "test.txt" "$dec_file"; then
            if [ $EXPECT_FAILURE -eq 1 ]; then
                echo "[UNEXPECTED PASS] Interop AES-${key_size}-${mode}: wolfProvider encrypt, OpenSSL decrypt"
                TEST_STATUS=1
            else
                echo "[PASS] Interop AES-${key_size}-${mode}: wolfProvider encrypt, OpenSSL decrypt"
            fi
        else
            if [ $EXPECT_FAILURE -eq 1 ]; then
                echo "[EXPECTED FAIL] Interop AES-${key_size}-${mode}: wolfProvider encrypt, OpenSSL decrypt"
            else
                echo "[FAIL] Interop AES-${key_size}-${mode}: wolfProvider encrypt, OpenSSL decrypt"
                TEST_STATUS=1
            fi
        fi
    done
done

# End of AES testing

if [ $TEST_STATUS -eq 0 ]; then
    if [ $EXPECT_FAILURE -eq 1 ]; then
        echo -e "\n=== AES tests completed with expected failures ==="
    else
        echo -e "\n=== All AES tests completed successfully ==="
    fi
    exit 0
else
    if [ $EXPECT_FAILURE -eq 1 ]; then
        echo -e "\n=== AES tests failed in unexpected ways ==="
    else
        echo -e "\n=== AES tests failed ==="
    fi
    exit 1
fi
