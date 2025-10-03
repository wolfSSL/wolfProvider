#!/bin/bash
# req-cmd-test.sh - Certificate request test for wolfProvider

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
source "${SCRIPT_DIR}/cmd-test-common.sh"
source "${SCRIPT_DIR}/clean-cmd-test.sh"
cmd_test_env_setup "req-test.log"
clean_cmd_test "req"

exec > >(tee -a "$LOG_FILE") 2>&1
mkdir -p req_outputs

CURVES=("prime256v1" "secp384r1" "secp521r1") 
HASH_ALGORITHMS=("sha256" "sha384" "sha512")
PROVIDER_ARGS=("-provider-path $WOLFPROV_PATH -provider libwolfprov" "-provider default")

echo "=== Running Certificate Request (X.509) Tests ==="

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
    local req_provider_args=$3
    
    req_provider_name=$(get_provider_name "$req_provider_args")
    local key_file="req_outputs/key_${curve}_${hash_alg}.pem"
    local cert_file="req_outputs/cert_${curve}_${hash_alg}_${req_provider_name//lib/}.pem"
    
    echo -e "\n=== Testing Certificate Creation (${curve}/${hash_alg}) - req with ${req_provider_name} ==="
    
    # Generate EC key with default provider
    echo "Generating EC key with curve ${curve} using default provider..."
    use_default_provider
    if $OPENSSL_BIN ecparam -genkey -name ${curve} -out "$key_file" \
        -provider default 2>/dev/null; then
        echo "[PASS] EC key generation successful"
        # Don't call check_force_fail for default provider operations in force fail mode
        # as default provider operations are expected to succeed
        if [ "${WOLFPROV_FORCE_FAIL}" != "1" ]; then
            check_force_fail
        fi
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
        # Only call check_force_fail for wolfProvider operations, or when not in force fail mode
        if [[ "$req_provider_args" == *"libwolfprov"* ]] || [ "${WOLFPROV_FORCE_FAIL}" != "1" ]; then
            check_force_fail
        fi
    else
        echo "[FAIL] Certificate creation failed"
        FAIL=1
        return
    fi
    
    # Check if certificate file exists and is non-empty
    if [ -s "$cert_file" ]; then
        echo "[PASS] Certificate file exists and is non-empty"
        # Only call check_force_fail for wolfProvider operations, or when not in force fail mode
        if [[ "$req_provider_args" == *"libwolfprov"* ]] || [ "${WOLFPROV_FORCE_FAIL}" != "1" ]; then
            check_force_fail
        fi
    else
        echo "[FAIL] Certificate file does not exist or is empty"
        FAIL=1
    fi
}

# Main test execution
echo "Starting certificate request tests..."

for curve in "${CURVES[@]}"; do
    for hash_alg in "${HASH_ALGORITHMS[@]}"; do
        for provider_arg in "${PROVIDER_ARGS[@]}"; do
            test_cert_creation "$curve" "$hash_alg" "$provider_arg"
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
