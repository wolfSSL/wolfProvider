#!/bin/bash
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
# along with wolfProvider. If not, see <http://www.gnu.org/licenses/>.
#

#
# Patch libcrypto.num to export internal provider functions
#
# This script appends 6 internal provider symbols to OpenSSL's libcrypto.num
# file, making them available for direct provider loading in wolfprovider unit tests.
#

set -e

# OPENSSL_SOURCE_DIR should be set by the caller (utils-openssl.sh)
if [ -z "$OPENSSL_SOURCE_DIR" ]; then
    echo "ERROR: OPENSSL_SOURCE_DIR not set"
    exit 1
fi

# Source utils-openssl.sh to use is_libcrypto_num_patched function
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/utils-openssl.sh"

LIBCRYPTO_NUM="${OPENSSL_SOURCE_DIR}/util/libcrypto.num"

# Check if file exists
if [ ! -f "$LIBCRYPTO_NUM" ]; then
    echo "ERROR: libcrypto.num not found at: $LIBCRYPTO_NUM"
    exit 1
fi

# Check if already patched using shared function
if is_libcrypto_num_patched; then
    echo "libcrypto.num already patched (provider symbols present)"
    exit 0
fi

# Get the last symbol number
LAST_NUM=$(awk '{print $2}' "$LIBCRYPTO_NUM" | grep -E '^[0-9]+$' | sort -n | tail -1)

if [ -z "$LAST_NUM" ]; then
    echo "ERROR: Could not determine last symbol number from libcrypto.num"
    exit 1
fi

# Get the version tag from the last line (column 3)
LAST_VERSION=$(tail -1 "$LIBCRYPTO_NUM" | awk '{print $3}')

if [ -z "$LAST_VERSION" ]; then
    echo "ERROR: Could not determine version tag from libcrypto.num"
    exit 1
fi

# Calculate new symbol numbers
NUM1=$((LAST_NUM + 1))
NUM2=$((LAST_NUM + 2))
NUM3=$((LAST_NUM + 3))
NUM4=$((LAST_NUM + 4))
NUM5=$((LAST_NUM + 5))
NUM6=$((LAST_NUM + 6))

# Append the 6 provider symbols
# Format matches existing entries: name (40 chars) TAB number TAB version TAB specification
# Use printf to ensure proper tab characters
{
    printf "ossl_provider_new                       %s\t%s\tEXIST::FUNCTION:\n" "${NUM1}" "${LAST_VERSION}"
    printf "ossl_provider_activate                  %s\t%s\tEXIST::FUNCTION:\n" "${NUM2}" "${LAST_VERSION}"
    printf "ossl_provider_deactivate                %s\t%s\tEXIST::FUNCTION:\n" "${NUM3}" "${LAST_VERSION}"
    printf "ossl_provider_add_to_store              %s\t%s\tEXIST::FUNCTION:\n" "${NUM4}" "${LAST_VERSION}"
    printf "ossl_provider_free                      %s\t%s\tEXIST::FUNCTION:\n" "${NUM5}" "${LAST_VERSION}"
    printf "ossl_default_provider_init              %s\t%s\tEXIST::FUNCTION:\n" "${NUM6}" "${LAST_VERSION}"
} >> "$LIBCRYPTO_NUM"

echo "Successfully patched libcrypto.num: Added symbols ${NUM1}-${NUM6} with version ${LAST_VERSION}"
exit 0

