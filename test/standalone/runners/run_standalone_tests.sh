#!/bin/bash
# run_standalone_tests.sh - Master runner for all standalone tests

set -e

# Get the directory of this script and find the root
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/../../.." && pwd)"

echo "Running all standalone tests..."
echo "================================"

TOTAL_FAILURES=0

# Run SHA256 simple test
echo ""
echo "Running SHA256 simple test..."
set +e
"$ROOT_DIR/test/standalone/tests/sha256_simple/run.sh"
if [ $? -eq 0 ]; then
    echo "SHA256 simple test: PASSED"
else
    echo "SHA256 simple test: FAILED"
    TOTAL_FAILURES=$((TOTAL_FAILURES + 1))
fi
set -e

# Run hardload test
echo ""
echo "Running hardload test..."
set +e
"$ROOT_DIR/test/standalone/tests/hardload/run.sh"
if [ $? -eq 0 ]; then
    echo "Hardload test: PASSED"
else
    echo "Hardload test: FAILED"
    TOTAL_FAILURES=$((TOTAL_FAILURES + 1))
fi
set -e

echo ""
echo "================================"
if [ $TOTAL_FAILURES -eq 0 ]; then
    echo "All standalone tests passed!"
    exit 0
else
    echo "$TOTAL_FAILURES standalone test(s) failed"
    exit 1
fi