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
# This script builds and installs wolfSSL/OpenSSL/wolfProvider packages to 
# replace the default provider to always use wolfProvider.

set -e
set -x

echo "=== Building wolfProvider Debian packages ==="

# Install build dependencies
sudo apt-get update
sudo apt-get install -y \
    build-essential \
    devscripts \
    debhelper \
    dh-autoreconf \
    libtool \
    pkg-config \
    git \
    wget \
    curl \
    ca-certificates \
    openssl \
    dpkg-dev \
    lintian \
    fakeroot \
    dh-exec \
    equivs \
    expect \
    xxd

# Ensure the working directory is safe
git config --global --add safe.directory "$PWD"

# Fetch tags (for Debian versioning)
git fetch --tags --force --prune

# Install wolfSSL Debian packages from repo tarball
mkdir -p "/tmp/wolfssl-pkg"
chmod +x debian/install-wolfssl.sh
./debian/install-wolfssl.sh \
    --tag v5.8.2-stable \
    "/tmp/wolfssl-pkg"

# Stage wolfSSL debs into artifacts directory
mkdir -p "/tmp/wolfprov-packages"
find /tmp/wolfssl-pkg -name "*wolfssl*" -type f -name "*.deb" -exec cp {} /tmp/wolfprov-packages/ \;

# Build Debian packages (wolfProvider + OpenSSL)
yes Y | ./scripts/build-wolfprovider.sh --debian

# Collect package artifacts
mv ../*.deb /tmp/wolfprov-packages/ 2>/dev/null || true

echo "=== Installing packages ==="

# Install wolfSSL first
wolfssl_debs=$(ls -1 /tmp/wolfprov-packages/*wolfssl*.deb 2>/dev/null || true)
if [ -n "$wolfssl_debs" ]; then
  sudo apt install -y $wolfssl_debs
fi

# Install OpenSSL packages in dependency order with conflict resolution
libssl3_debs=$(ls -1 /tmp/wolfprov-packages/libssl3_[0-9]*.deb 2>/dev/null || true)
openssl_debs=$(ls -1 /tmp/wolfprov-packages/openssl_[0-9]*.deb 2>/dev/null || true)
libssl_dev_debs=$(ls -1 /tmp/wolfprov-packages/libssl-dev_[0-9]*.deb 2>/dev/null || true)

# Install custom OpenSSL packages
echo "Installing custom OpenSSL packages..."
if [ -n "$libssl3_debs" ]; then
  echo "Installing custom libssl3 package..."
  sudo dpkg -i $libssl3_debs || sudo apt install -f -y
fi
if [ -n "$openssl_debs" ]; then
  echo "Installing custom openssl package..."
  sudo dpkg -i $openssl_debs || sudo apt install -f -y
fi
if [ -n "$libssl_dev_debs" ]; then
  echo "Installing custom libssl-dev package..."
  sudo dpkg -i $libssl_dev_debs || sudo apt install -f -y
fi

# Install wolfProvider main package
wolfprov_main=$(ls -1 /tmp/wolfprov-packages/libwolfprov_[0-9]*.deb 2>/dev/null | head -n1 || true)
if [ -z "$wolfprov_main" ]; then
  echo "ERROR: libwolfprov main package not found"
  exit 1
fi
sudo dpkg -i "$wolfprov_main" || sudo apt install -f -y

./scripts/verify-debian.sh

echo "=== Replace Default installed! ==="
