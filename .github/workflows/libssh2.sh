#!/bin/bash

#----libssh2.sh----
#
# This script runs the libssh2 tests against the FIPS wolfProvider.
# Environment variables LIBSSH2_REF, WOLFSSL_REF, and OPENSSL_REF
# are set by Jenkins.
# TODO: Add FORCE_FAIL neg testing
set -e
set -x

# Save original directory
TOP_DIR=$(pwd)

LIBSSH2_REF="${1:-libssh2-1.10.0}"

WOLFSSL_INSTALL="$WOLFPROV_DIR/wolfssl-install"
OPENSSL_INSTALL="$WOLFPROV_DIR/openssl-install"
WOLFPROV_INSTALL="$WOLFPROV_DIR/wolfprov-install"

# Go to wolfProvider directory
cd "$WOLFPROV_DIR"

# Clone libssh2 repo
rm -rf libssh2
git clone --depth=1 --branch="${LIBSSH2_REF}" https://github.com/libssh2/libssh2.git

# Build libssh2
cd libssh2

# Apply patches
git apply ../libssh2.patch

# Build libssh2
autoreconf -fi
./configure --with-crypto=openssl --with-libssl-prefix="${OPENSSL_INSTALL}"
make -j$(nproc)

# Set environment variables
source ../scripts/env-setup

# Run the tests
DEBUG=1 make check

if [ $? -eq 0 ]; then
  echo "Workflow completed successfully"
else
  echo "Workflow failed"
  exit 1
fi
