#!/bin/bash
# install-packages.sh
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

set -e

echo "WolfSSL artifacts:"
ls -la /tmp/wolfssl-artifacts || true
echo "OpenSSL/wolfProvider artifacts:"
ls -la /tmp/openssl-wolfprov-artifacts || true

# Install wolfSSL first
wolfssl_debs=$(ls -1 /tmp/wolfssl-artifacts/*.deb 2>/dev/null || true)
if [ -n "$wolfssl_debs" ]; then
  echo "Installing wolfSSL packages: $wolfssl_debs"
  apt install -y $wolfssl_debs
fi

# Install OpenSSL packages (runtime + development headers)
openssl_debs=$(ls -1 /tmp/openssl-wolfprov-artifacts/openssl_[0-9]*.deb 2>/dev/null || true)
libssl3_debs=$(ls -1 /tmp/openssl-wolfprov-artifacts/libssl3_[0-9]*.deb 2>/dev/null || true)
libssl_dev_debs=$(ls -1 /tmp/openssl-wolfprov-artifacts/libssl-dev_[0-9]*.deb 2>/dev/null || true)

# Install in dependency order: libssl3 first, then openssl, then dev headers
if [ -n "$libssl3_debs" ]; then
  echo "Installing libssl3: $libssl3_debs"
  apt install -y $libssl3_debs
fi
if [ -n "$openssl_debs" ]; then
  echo "Installing openssl: $openssl_debs"
  apt install -y $openssl_debs
fi
if [ -n "$libssl_dev_debs" ]; then
  echo "Installing libssl-dev: $libssl_dev_debs"
  apt install -y $libssl_dev_debs
fi

# Install wolfProvider main package only (no dev/debug needed for testing)
wolfprov_main=$(ls -1 /tmp/openssl-wolfprov-artifacts/libwolfprov_[0-9]*.deb 2>/dev/null | head -n1 || true)

if [ -z "$wolfprov_main" ]; then
  echo "ERROR: libwolfprov main package not found in artifacts"
  ls -la /tmp/openssl-wolfprov-artifacts
  exit 1
fi

echo "Installing wolfProvider main package: $wolfprov_main"
apt install -y "$wolfprov_main"
