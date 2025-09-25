#!/bin/bash
# Hardload test runner

set -e

# Get the directory of this script and find the root
TEST_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$TEST_DIR/../../../.." && pwd)"

# Binary should be in the test/.libs/ directory
BINARY="hardload.test"
BINARY_PATH="$ROOT_DIR/test/.libs/$BINARY"

# Make sure we can find the binary
if [ ! -f "$BINARY_PATH" ]; then
    echo "Error: Cannot find binary $BINARY_PATH"
    echo "Make sure you've built the test with: make test/hardload.test"
    exit 1
fi

# Source env-setup
if ! source "$ROOT_DIR/scripts/env-setup" >/dev/null; then
    echo "Error: env-setup failed"
    exit 1
fi

WP_USING_REPLACE_DEFAULT="0"
if [ -f "$OPENSSL_LIB_PATH/libcrypto.so" ]; then
    # Check for wolfProvider symbols in libcrypto
    if nm -D "$OPENSSL_LIB_PATH/libcrypto.so" 2>/dev/null | grep -q "wolfprov_provider_init"; then
        WP_USING_REPLACE_DEFAULT="1"
    fi
fi

# Configure environment based on build type
if [ "$WP_USING_REPLACE_DEFAULT" = "1" ]; then
    echo "Detected: --replace-default build"
    unset OPENSSL_CONF
    EXPECTED_PROVIDER_NAME="wolfSSL Provider"
else
    EXPECTED_PROVIDER_NAME="OpenSSL Default Provider"
fi

echo "Expected provider name: $EXPECTED_PROVIDER_NAME"

echo "Using environment:"
echo "LD_LIBRARY_PATH: $LD_LIBRARY_PATH"
echo "OPENSSL_CONF: $OPENSSL_CONF"
echo "OPENSSL_BIN: $OPENSSL_BIN"

# Check that wolfProvider is loaded in place of default
if [ "$WP_USING_REPLACE_DEFAULT" = "1" ]; then
    if ! ${OPENSSL_BIN} list -providers | grep -q "wolf"; then
        echo "Error: wolfProvider is not loaded in place of default"
        exit 1
    fi
fi

# Function to run a test scenario
run_test() {
    local test_name="$1"
    local should_fail="$2"
    local set_force_fail="$3"
    local output_file
    
    echo "=== $test_name ==="
    
    if [ "$set_force_fail" = "true" ]; then
        export WOLFPROV_FORCE_FAIL=1
        echo "Setting WOLFPROV_FORCE_FAIL=1"
    else
        unset WOLFPROV_FORCE_FAIL
        echo "WOLFPROV_FORCE_FAIL not set"
    fi
    
    if [ "$should_fail" = "true" ]; then
        expected="FAIL"
    else
        expected="PASS"
    fi
    
    # Create temporary file for test output
    output_file=$(mktemp)
    
    if "$BINARY_PATH" "$EXPECTED_PROVIDER_NAME" >"$output_file" 2>&1; then
        result="PASS"
    else
        result="FAIL"
    fi
    
    echo "Expected: $expected, Got: $result"
    
    if [ "$result" = "$expected" ]; then
        echo "PASS"
        rm -f "$output_file"
        return 0
    else
        echo "FAILED"
        echo "Test output:"
        cat "$output_file"
        rm -f "$output_file"
        return 1
    fi
}

echo "Running hardload test: $BINARY_PATH"
echo ""

FAILURES=0

# Run normal scenario - should always pass
if ! run_test "Normal operation" false false; then
    FAILURES=$((FAILURES + 1))
fi
echo ""

# Run force-fail scenario - success criteria depends on build type
if [ "$WP_USING_REPLACE_DEFAULT" = "1" ]; then
    # Replace-default: force-fail should actually fail (can't escape wolfProvider)
    if ! run_test "Force fail test (should fail)" true true; then
        FAILURES=$((FAILURES + 1))
    fi
else
    # Normal build: force-fail should pass (hardload bypasses wolfProvider)
    if ! run_test "Force fail test (should pass)" false true; then
        FAILURES=$((FAILURES + 1))
    fi
fi

echo ""
if [ $FAILURES -gt 0 ]; then
    echo "$FAILURES scenarios failed"
    exit 1
else
    echo "All scenarios passed"
    exit 0
fi
