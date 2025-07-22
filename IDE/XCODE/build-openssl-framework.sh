#!/bin/bash

# build-openssl-framework.sh
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

set -euo pipefail

WOLFSSL_DIR=$(pwd)
OUTDIR=$(pwd)/artifacts
LIPODIR=${OUTDIR}/lib
SDK_OUTPUT_DIR=${OUTDIR}/xcframework

CFLAGS_COMMON=""
# Base configure flags
CONF_OPTS=""
NUMCPU=$(sysctl -n hw.ncpu)

helpFunction()
{
   echo ""
   echo "Usage: $0 [-c <config flags>]"
   echo -e "\t-c Extra flags to be passed to ./configure"
   exit 1 # Exit script after printing help
}

# Parse command line arguments
while getopts ":c:" opt; do
  case $opt in
    c)
      CONF_OPTS+=" $OPTARG"
      ;;
    \?)
      echo "Invalid option: -$OPTARG" >&2; helpFunction
      ;;
  esac
done

mkdir -p $LIPODIR
mkdir -p $SDK_OUTPUT_DIR

build() { # <ARCH=arm64|x86_64> <TYPE=iphonesimulator|iphoneos|macosx|watchos|watchsimulator|appletvos|appletvsimulator>
    set -x
    pushd .

    ARCH=$1
    HOST="${ARCH}-apple-darwin"
    TYPE=$2
    SDK_ROOT=$(xcrun --sdk ${TYPE} --show-sdk-path)
    TARGET="darwin64-${ARCH}-cc"

    mkdir -p ${OUTDIR}/${TYPE}-${ARCH} && cd ${OUTDIR}/${TYPE}-${ARCH}

    CC="clang" CXX="clang" CFLAGS="${CFLAGS_COMMON} -Os -arch ${ARCH} -isysroot ${SDK_ROOT}" LDFLAGS="-arch ${ARCH} -isysroot ${SDK_ROOT}" ${WOLFSSL_DIR}/Configure no-asm ${TARGET} --prefix=${OUTDIR}/openssl-install-${TYPE}-${ARCH} ${CONF_OPTS}
    make -j$((${NUMCPU} / 2))
    make install

    popd
    set +x
}

XCFRAMEWORKS=
for type in iphonesimulator macosx ; do
    build arm64 ${type}
    build x86_64 ${type}

    # Create universal binaries from architecture-specific static libraries
    if [ -f "$OUTDIR/openssl-install-${type}-x86_64/lib/libssl.a" ] && [ -f "$OUTDIR/openssl-install-${type}-arm64/lib/libssl.a" ]; then
        lipo \
            "$OUTDIR/openssl-install-${type}-x86_64/lib/libssl.a" \
            "$OUTDIR/openssl-install-${type}-arm64/lib/libssl.a" \
            -create -output $LIPODIR/libopenssl-${type}.a
        else
        echo "ERROR: Required input libraries not found for ${type}"
        exit 1
    fi

    echo "Checking libraries"
    xcrun -sdk ${type} lipo -info $LIPODIR/libopenssl-${type}.a
    XCFRAMEWORKS+=" -library ${LIPODIR}/libopenssl-${type}.a -headers ${OUTDIR}/openssl-install-${type}-arm64/include"
done

for type in iphoneos ; do
    build arm64 ${type}

    # Create universal binaries from architecture-specific static libraries
    if [ -f "$OUTDIR/openssl-install-${type}-arm64/lib/libssl.a" ]; then
        cp "$OUTDIR/openssl-install-${type}-arm64/lib/libssl.a" "$LIPODIR/libopenssl-${type}.a"
        else
        echo "ERROR: Required input library not found for ${type}"
        exit 1
    fi

    echo "Checking libraries"
    xcrun -sdk ${type} lipo -info $LIPODIR/libopenssl-${type}.a
    XCFRAMEWORKS+=" -library ${LIPODIR}/libopenssl-${type}.a -headers ${OUTDIR}/openssl-install-${type}-arm64/include"
done

############################################################################################################################################
#  ********** BUILD FRAMEWORK
############################################################################################################################################

xcodebuild -create-xcframework ${XCFRAMEWORKS} -output ${SDK_OUTPUT_DIR}/libopenssl.xcframework
