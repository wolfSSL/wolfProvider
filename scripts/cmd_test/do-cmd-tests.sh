#!/bin/bash
# do-cmd-tests.sh
# Run all command-line tests for wolfProvider
#
# Copyright (C) 2006-2025 wolfSSL Inc.
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
# along with wolfProvider. If not, see <http://www.gnu.org/licenses/>.

# Get the directory where this script is located
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
REPO_ROOT="$( cd "${SCRIPT_DIR}/../.." &> /dev/null && pwd )"
UTILS_DIR="${REPO_ROOT}/scripts"

# Flag to indicate that this script is being called from do-cmd-tests.sh
export DO_CMD_TESTS=1

# Parse command-line arguments
RUN_HASH=0
RUN_AES=0
RUN_RSA=0
RUN_ECC=0
RUN_REQ=0
RUN_ALL=1

show_help() {
    cat << EOF
Usage: $0 [OPTIONS] [TESTS]

Run wolfProvider command-line tests with optional configuration flags.

OPTIONS:
    --help              Show this help message

TESTS (if none specified, all tests run):
    hash                Run hash comparison test
    aes                 Run AES comparison test
    rsa                 Run RSA key generation test
    ecc                 Run ECC key generation test
    req                 Run certificate request test

ENVIRONMENT VARIABLES (env vars get detected from verify-install.sh):
    OPENSSL_BIN         Path to OpenSSL binary (auto-detected if not set)
    WOLFPROV_PATH       Path to wolfProvider modules directory
    WOLFPROV_CONFIG     Path to wolfProvider config file
    WOLFSSL_ISFIPS      Set to 1 for FIPS mode (or use --fips flag)
    WOLFPROV_FORCE_FAIL Set to 1 for force-fail mode (or use --force-fail flag)

EOF
    exit 0
}

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --help|-h)
            show_help
            ;;
        hash)
            RUN_HASH=1
            RUN_ALL=0
            shift
            ;;
        aes)
            RUN_AES=1
            RUN_ALL=0
            shift
            ;;
        rsa)
            RUN_RSA=1
            RUN_ALL=0
            shift
            ;;
        ecc)
            RUN_ECC=1
            RUN_ALL=0
            shift
            ;;
        req)
            RUN_REQ=1
            RUN_ALL=0
            shift
            ;;
        *)
            echo "Unknown option: $1"
            echo "Use --help for usage information"
            exit 1
            ;;
    esac
done

# If no specific tests were requested, run all tests
if [ $RUN_ALL -eq 1 ]; then
    RUN_HASH=1
    RUN_AES=1
    RUN_RSA=1
    RUN_ECC=1
    RUN_REQ=1
fi

source "${SCRIPT_DIR}/cmd-test-common.sh"
cmd_test_env_setup

echo "==========================================
wolfProvider Command-Line Tests
=========================================="
echo ""
echo "Running command-line test suite..."
echo ""

# Detect installation mode and setup environment
cmd_test_env_setup

echo ""
echo "=== Running wolfProvider Command-Line Tests ==="
echo "Using OPENSSL_BIN: ${OPENSSL_BIN}" 
echo "Using WOLFPROV_PATH: ${WOLFPROV_PATH}"
echo "Using WOLFPROV_CONFIG: ${WOLFPROV_CONFIG}"
if [ "${WOLFSSL_ISFIPS}" = "1" ]; then
    echo "FIPS mode: ENABLED"
fi
if [ "${WOLFPROV_FORCE_FAIL}" = "1" ]; then
    echo "Force-fail mode: ENABLED"
fi

# Export detection variables for child scripts
export WOLFPROV_REPLACE_DEFAULT
export WOLFPROV_FIPS
export WOLFPROV_INSTALLED
export WOLFPROV_MODE_DETECTED

# Ensure we can switch providers before proceeding
use_default_provider
use_wolf_provider

# Initialize result variables
HASH_RESULT=0
AES_RESULT=0
RSA_RESULT=0
ECC_RESULT=0
REQ_RESULT=0

# Run the hash comparison test
if [ $RUN_HASH -eq 1 ]; then
    echo -e "\n=== Running Hash Comparison Test ==="
    "${REPO_ROOT}/scripts/cmd_test/hash-cmd-test.sh"
    HASH_RESULT=$?
fi

# Run the AES comparison test
if [ $RUN_AES -eq 1 ]; then
    echo -e "\n=== Running AES Comparison Test ==="
    "${REPO_ROOT}/scripts/cmd_test/aes-cmd-test.sh"
    AES_RESULT=$?
fi

# Run the RSA key generation test
if [ $RUN_RSA -eq 1 ]; then
    echo -e "\n=== Running RSA Key Generation Test ==="
    "${REPO_ROOT}/scripts/cmd_test/rsa-cmd-test.sh"
    RSA_RESULT=$?
fi

# Run the ECC key generation test
if [ $RUN_ECC -eq 1 ]; then
    echo -e "\n=== Running ECC Key Generation Test ==="
    "${REPO_ROOT}/scripts/cmd_test/ecc-cmd-test.sh"
    ECC_RESULT=$?
fi

# Run the Certificate Request test
if [ $RUN_REQ -eq 1 ]; then
    echo -e "\n=== Running Certificate Request Test ==="
    "${REPO_ROOT}/scripts/cmd_test/req-cmd-test.sh"
    REQ_RESULT=$?
fi

# Check results
ALL_PASSED=1
if [ $RUN_HASH -eq 1 ] && [ $HASH_RESULT -ne 0 ]; then
    ALL_PASSED=0
fi
if [ $RUN_AES -eq 1 ] && [ $AES_RESULT -ne 0 ]; then
    ALL_PASSED=0
fi
if [ $RUN_RSA -eq 1 ] && [ $RSA_RESULT -ne 0 ]; then
    ALL_PASSED=0
fi
if [ $RUN_ECC -eq 1 ] && [ $ECC_RESULT -ne 0 ]; then
    ALL_PASSED=0
fi
if [ $RUN_REQ -eq 1 ] && [ $REQ_RESULT -ne 0 ]; then
    ALL_PASSED=0
fi

if [ $ALL_PASSED -eq 1 ]; then
    echo -e "\n=== All Command-Line Tests Passed ==="
else
    echo -e "\n=== Command-Line Tests Failed ==="
fi

# Print configuration
if [ "${WOLFPROV_FORCE_FAIL}" = "1" ]; then
    echo "Force fail mode was enabled"
fi
if [ "${WOLFSSL_ISFIPS}" = "1" ]; then
    echo "FIPS mode was enabled"
fi
if [ "${WOLFPROV_REPLACE_DEFAULT}" = "1" ]; then
    echo "Replace-default mode was enabled"
fi

# Print test results (only for tests that were run)
echo ""
if [ $RUN_HASH -eq 1 ]; then
    echo "Hash Test Result: $HASH_RESULT (0=success)"
fi
if [ $RUN_AES -eq 1 ]; then
    echo "AES Test Result: $AES_RESULT (0=success)"
fi
if [ $RUN_RSA -eq 1 ]; then
    echo "RSA Test Result: $RSA_RESULT (0=success)"
fi
if [ $RUN_ECC -eq 1 ]; then
    echo "ECC Test Result: $ECC_RESULT (0=success)"
fi
if [ $RUN_REQ -eq 1 ]; then
    echo "REQ Test Result: $REQ_RESULT (0=success)"
fi

exit $((1 - ALL_PASSED))
