#!/bin/bash
# FIPS provider status test runner

set -e

# Get the directory of this script and find the root
TEST_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$TEST_DIR/../../../.." && pwd)"

# Binary should be in the test/.libs/ directory
BINARY="fips_status.test"
BINARY_PATH="$ROOT_DIR/test/.libs/$BINARY"

# Make sure we can find the binary
if [ ! -f "$BINARY_PATH" ]; then
    echo "Error: Cannot find binary $BINARY_PATH"
    echo "Make sure you've built the test with: make test/fips_status.test"
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
    unset OPENSSL_CONF
fi

echo "Using environment:"
echo "LD_LIBRARY_PATH: $LD_LIBRARY_PATH"
echo "OPENSSL_CONF: $OPENSSL_CONF"
echo "OPENSSL_BIN: $OPENSSL_BIN"

echo "Running FIPS status test: $BINARY_PATH"
echo ""

# The binary self-reports which injection path it took. Exit status is the
# result; the caller reports PASSED/FAILED.
exec "$BINARY_PATH"
