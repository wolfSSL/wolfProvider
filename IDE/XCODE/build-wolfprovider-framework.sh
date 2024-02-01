#!/bin/bash

# build-wolfprov-framework.sh
#
# Copyright (C) 2006-2023 wolfSSL Inc.
#
# This file is part of wolfSSL.
#
# wolfSSL is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# wolfSSL is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA

set -euo pipefail

WOLFPROV_DIR=$(pwd)
OUTDIR=$(pwd)/artifacts
LIPODIR=${OUTDIR}/lib
SDK_OUTPUT_DIR=${OUTDIR}/xcframework

CFLAGS_COMMON=""
# Base configure flags
CONF_OPTS="--disable-shared --enable-static"

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
cd $WOLFPROV_DIR && ./autogen.sh

build() { # <ARCH=arm64|x86_64> <TYPE=iphonesimulator|iphoneos|macosx|watchos|watchsimulator|appletvos|appletvsimulator>
    set -x
    pushd .
    cd $WOLFPROV_DIR

    ARCH=$1
    HOST="${ARCH}-apple-darwin"
    TYPE=$2
    SDK_ROOT=$(xcrun --sdk ${TYPE} --show-sdk-path)

    ./configure -prefix=${OUTDIR}/wolfprov-${TYPE}-${ARCH} ${CONF_OPTS} --host=${HOST} \
	--with-openssl=${WOLFPROV_DIR}/openssl-source/artifacts/openssl-install-${TYPE}-${ARCH} \
	--with-wolfssl=${WOLFPROV_DIR}/wolfssl-source/artifacts/wolfssl-install-${TYPE}-${ARCH} \
        CFLAGS="${CFLAGS_COMMON} -arch ${ARCH} -isysroot ${SDK_ROOT}" \
    	LDFLAGS="-framework CoreFoundation -framework Security"
    make -j
    make install

    popd
    set +x
}

XCFRAMEWORKS=
for type in iphonesimulator macosx ; do
    build arm64 ${type}
    build x86_64 ${type}

    # Create universal binaries from architecture-specific static libraries
    lipo \
        "$OUTDIR/wolfprov-${type}-x86_64/lib/libwolfprov.a" \
        "$OUTDIR/wolfprov-${type}-arm64/lib/libwolfprov.a" \
        -create -output $LIPODIR/libwolfprov-${type}.a

    echo "Checking libraries"
    xcrun -sdk ${type} lipo -info $LIPODIR/libwolfprov-${type}.a
    XCFRAMEWORKS+=" -library ${LIPODIR}/libwolfprov-${type}.a"
done

for type in iphoneos ; do
    build arm64 ${type}

    # Create universal binaries from architecture-specific static libraries
    lipo \
        "$OUTDIR/wolfprov-${type}-arm64/lib/libwolfprov.a" \
        -create -output $LIPODIR/libwolfprov-${type}.a

    echo "Checking libraries"
    xcrun -sdk ${type} lipo -info $LIPODIR/libwolfprov-${type}.a
    XCFRAMEWORKS+=" -library ${LIPODIR}/libwolfprov-${type}.a"
done

############################################################################################################################################
#  ********** BUILD FRAMEWORK
############################################################################################################################################

xcodebuild -create-xcframework ${XCFRAMEWORKS} -headers ${WOLFPROV_DIR}/include -output ${SDK_OUTPUT_DIR}/libwolfprov.xcframework
