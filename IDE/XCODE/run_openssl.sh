#!/bin/bash

set -e

RUNDIR=$(pwd)
OPENSSL_DIR=${RUNDIR}/openssl-source/artifacts/macosx-x86_64
WOLFPROV_LIB=${RUNDIR}/artifacts/xcframework/libwolfprov.xcframework/macos-arm64_x86_64
export LD_LIBRARY_PATH=${WOLFPROV_LIB}:${OPENSSL_DIR}
export OPENSSL_MODULES=${WOLFPROV_LIB}
export OPENSSL_CONF=${RUNDIR}/provider.conf

# Most places expect the file to be called 'libwolfprov.so/dll/dylib'
ln -s ${WOLFPROV_LIB}/libwolfprov-macosx.dylib ${WOLFPROV_LIB}/libwolfprov.dylib || true

# Run the tests
${OPENSSL_DIR}/apps/openssl list -verbose -provider-path ${WOLFPROV_LIB} -providers

${RUNDIR}/artifacts/openssl_example