#!/bin/bash
# do-cmd-tests.sh
# Run all command-line tests for wolfProvider
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

# Get the directory where this script is located
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"

echo "=== Running wolfProvider Command-Line Tests ==="

# Run the hash comparison test
echo -e "\n=== Running Hash Comparison Test ==="
"$SCRIPT_DIR/hash-cmd-test.sh"
HASH_RESULT=$?

# Run the AES comparison test
echo -e "\n=== Running AES Comparison Test ==="
"$SCRIPT_DIR/aes-cmd-test.sh"
AES_RESULT=$?

# Run the RSA key generation test
echo -e "\n=== Running RSA Key Generation Test ==="
"$SCRIPT_DIR/rsa-cmd-test.sh"
RSA_RESULT=$?

# Run the ECC key generation test
echo -e "\n=== Running ECC Key Generation Test ==="
"$SCRIPT_DIR/ecc-cmd-test.sh"
ECC_RESULT=$?

# Check results
if [ $HASH_RESULT -eq 0 ] && [ $AES_RESULT -eq 0 ] && [ $RSA_RESULT -eq 0 ] && [ $ECC_RESULT -eq 0 ]; then
    echo -e "\n=== All Command-Line Tests Passed ==="
    exit 0
else
    echo -e "\n=== Command-Line Tests Failed ==="
    echo "Hash Test Result: $HASH_RESULT (0=success)"
    echo "AES Test Result: $AES_RESULT (0=success)"
    echo "RSA Test Result: $RSA_RESULT (0=success)"
    echo "ECC Test Result: $ECC_RESULT (0=success)"
    exit 1
fi
