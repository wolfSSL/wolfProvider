#!/bin/bash
# rsa-cmd-test.sh
# RSA key generation and sign/verify test for wolfProvider
#
# Copyright (C) 2006-2024 wolfSSL Inc.
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
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA

# Set up environment
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
REPO_ROOT="$( cd "${SCRIPT_DIR}/../.." &> /dev/null && pwd )"
UTILS_DIR="${REPO_ROOT}/scripts"
export LOG_FILE="${SCRIPT_DIR}/rsa-test.log"
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
if ! openssl list -providers | grep -q "libwolfprov"; then
    echo "[FAIL] wolfProvider not found in OpenSSL providers!"
    echo "Current provider list:"
    openssl list -providers
    exit 1
fi
echo "[PASS] wolfProvider is properly configured"

# Print environment for verification
echo "Environment variables:"
echo "OPENSSL_MODULES: ${OPENSSL_MODULES}"
echo "LD_LIBRARY_PATH: ${LD_LIBRARY_PATH}"

# Create test directories
mkdir -p rsa_outputs

# Create test data for signing
echo "This is test data for RSA signing and verification." > rsa_outputs/test_data.txt

# Array of RSA key sizes to test
KEY_SIZES=("2048" "3072" "4096")

echo "=== Running RSA Key Generation Tests ==="

for key_size in "${KEY_SIZES[@]}"; do
    echo -e "\n=== Testing RSA-${key_size} Key Generation ==="
    
    # Generate RSA key with wolfProvider
    echo "Generating RSA-${key_size} key with wolfProvider..."
    openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:${key_size} \
        -provider-path $WOLFPROV_PATH -provider libwolfprov \
        -out "rsa_outputs/rsa_wolf_${key_size}.pem" -pass pass:

    # Verify the key was generated
    if [ -s "rsa_outputs/rsa_wolf_${key_size}.pem" ]; then
        echo "[PASS] RSA-${key_size} key generation successful"
    else
        echo "[FAIL] RSA-${key_size} key generation failed"
        exit 1
    fi
    
    # Display key information
    echo "Key information:"
    openssl rsa -in "rsa_outputs/rsa_wolf_${key_size}.pem" -text -noout \
        -provider-path $WOLFPROV_PATH -provider libwolfprov
    
    # Test sign and verify with the generated key
    echo -e "\n=== Testing RSA-${key_size} Sign/Verify ==="
    
    # Extract public key for verification
    openssl rsa -in "rsa_outputs/rsa_wolf_${key_size}.pem" -pubout \
        -provider-path $WOLFPROV_PATH -provider libwolfprov \
        -out "rsa_outputs/rsa_wolf_${key_size}_pub.pem"
    
    # Sign data with wolfProvider
    echo "Signing data with RSA-${key_size} key..."
    openssl dgst -sha256 -sign "rsa_outputs/rsa_wolf_${key_size}.pem" \
        -provider-path $WOLFPROV_PATH -provider libwolfprov \
        -out "rsa_outputs/signature_${key_size}.bin" "rsa_outputs/test_data.txt"
    
    if [ ! -s "rsa_outputs/signature_${key_size}.bin" ]; then
        echo "[FAIL] RSA-${key_size} signing failed"
        exit 1
    fi
    
    # Verify signature with wolfProvider
    echo "Verifying signature with RSA-${key_size} key..."
    openssl dgst -sha256 -verify "rsa_outputs/rsa_wolf_${key_size}_pub.pem" \
        -provider-path $WOLFPROV_PATH -provider libwolfprov \
        -signature "rsa_outputs/signature_${key_size}.bin" "rsa_outputs/test_data.txt"
    
    if [ $? -eq 0 ]; then
        echo "[PASS] RSA-${key_size} sign/verify successful"
    else
        echo "[FAIL] RSA-${key_size} sign/verify failed"
        exit 1
    fi
done

echo -e "\n=== All RSA key generation and sign/verify tests completed successfully ==="
exit 0
