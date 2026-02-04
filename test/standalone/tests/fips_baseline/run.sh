#!/bin/bash
# FIPS baseline test runner

set -e

# Get the directory of this script and find the root
TEST_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$TEST_DIR/../../../.." && pwd)"

# Binary should be in the test/.libs/ directory
BINARY="fips_baseline.test"
BINARY_PATH="$ROOT_DIR/test/.libs/$BINARY"

# Make sure we can find the binary
if [ ! -f "$BINARY_PATH" ]; then
    echo "Error: Cannot find binary $BINARY_PATH"
    echo "Make sure you've built the test with: make test/fips_baseline.test"
    exit 1
fi

# Source env-setup
if ! source "$ROOT_DIR/scripts/env-setup" >/dev/null; then
    echo "Error: env-setup failed"
    exit 1
fi

# Source common test utilities
source "$ROOT_DIR/test/standalone/test_common.sh"

echo "========================================="
echo "FIPS Baseline Test Runner"
echo "========================================="
echo ""

# Detect FIPS version
FIPS_VERSION="unknown"

# Check if provider output indicates FIPS mode
if ${OPENSSL_BIN} list -providers 2>/dev/null | grep -qi "fips"; then
    FIPS_VERSION="fips"
    echo "FIPS provider detected"
else
    FIPS_VERSION="none"
    echo "No FIPS provider detected (running in non-FIPS mode)"
fi

# Try to get more specific version info from openssl
if ${OPENSSL_BIN} list -providers -verbose 2>/dev/null | grep -i "version" | head -1; then
    echo ""
fi

echo "Using environment:"
echo "  LD_LIBRARY_PATH: $LD_LIBRARY_PATH"
echo "  OPENSSL_CONF: ${OPENSSL_CONF:-<not set>}"
echo "  OPENSSL_BIN: $OPENSSL_BIN"
echo ""

echo "Running test: $BINARY_PATH"
echo ""

# Run the test
if "$BINARY_PATH" "$FIPS_VERSION"; then
    echo ""
    echo "========================================="
    echo "Test runner: PASSED"
    echo "========================================="
    exit 0
else
    echo ""
    echo "========================================="
    echo "Test runner: FAILED"
    echo "========================================="
    exit 1
fi

