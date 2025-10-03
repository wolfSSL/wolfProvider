#!/bin/bash
# SHA256 simple test runner

set -e

# Get the directory of this script and find the root
TEST_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$TEST_DIR/../../../.." && pwd)"

# Binary should be in the test/.libs/ directory
BINARY="sha256_simple.test"
BINARY_PATH="$ROOT_DIR/test/.libs/$BINARY"

# Make sure we can find the binary
if [ ! -f "$BINARY_PATH" ]; then
    echo "Error: Cannot find binary $BINARY_PATH"
    echo "Make sure you've built the test with: make test/sha256_simple.test"
    exit 1
fi

# Source env-setup
if ! source "$ROOT_DIR/scripts/env-setup" >/dev/null; then
    echo "Error: env-setup failed"
    exit 1
fi

# Source common test utilities
source "$ROOT_DIR/test/standalone/test_common.sh"

# Check if this is a replace-default build
WP_USING_REPLACE_DEFAULT="0"
if detect_replace_default_build; then
    WP_USING_REPLACE_DEFAULT="1"
fi

# Configure environment based on build type
if [ "$WP_USING_REPLACE_DEFAULT" = "1" ]; then
    echo "Detected: --replace-default build"
    unset OPENSSL_CONF
fi

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
    local custom_conf="$3"
    local output_file

    echo "=== $test_name ==="

    if [ "$should_fail" = "true" ]; then
        export WOLFPROV_FORCE_FAIL=1
        expected="FAIL"
    else
        unset WOLFPROV_FORCE_FAIL
        expected="PASS"
    fi

    # Set custom config if provided
    local original_openssl_conf="$OPENSSL_CONF"
    if [ -n "$custom_conf" ]; then
        export OPENSSL_CONF="$custom_conf"
        echo "Using custom config: $OPENSSL_CONF"
    fi

    # Create temporary file for test output
    output_file=$(mktemp)

    if "$BINARY_PATH" >"$output_file" 2>&1; then
        result="PASS"
    else
        result="FAIL"
    fi

    # Restore original config
    if [ -n "$custom_conf" ]; then
        if [ -n "$original_openssl_conf" ]; then
            export OPENSSL_CONF="$original_openssl_conf"
        else
            unset OPENSSL_CONF
        fi
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

echo "Running SHA256 test: $BINARY_PATH"
echo ""

FAILURES=0

if [ "$WP_USING_REPLACE_DEFAULT" = "1" ]; then
    echo "Replace-default build detected - running 4 test scenarios"

    if ! run_test "No config, normal operation" false; then
        FAILURES=$((FAILURES + 1))
    fi
    echo ""

    if ! run_test "No config, force fail" true; then
        FAILURES=$((FAILURES + 1))
    fi
    echo ""

    if ! run_test "Explicit default config, normal operation" false "$ROOT_DIR/test/standalone/provider-default.conf"; then
        FAILURES=$((FAILURES + 1))
    fi
    echo ""

    if ! run_test "Explicit default config, force fail" true "$ROOT_DIR/test/standalone/provider-default.conf"; then
        FAILURES=$((FAILURES + 1))
    fi
    echo ""
else
    echo "Standard build - running 2 test scenarios"

    if ! run_test "Normal operation" false; then
        FAILURES=$((FAILURES + 1))
    fi
    echo ""

    if ! run_test "Force fail test" true; then
        FAILURES=$((FAILURES + 1))
    fi
    echo ""
fi

echo ""
if [ $FAILURES -gt 0 ]; then
    echo "$FAILURES scenarios failed"
    exit 1
else
    echo "All scenarios passed"
    exit 0
fi
