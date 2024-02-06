#!/bin/bash

set -e

RUNDIR=$(pwd)
OPENSSL_DIR=${RUNDIR}/openssl-source/artifacts/openssl-install-macosx-x86_64/
WOLFPROV_LIB=${RUNDIR}/artifacts/wolfprov-install-macos-x86_64/lib
export LD_LIBRARY_PATH=${WOLFPROV_LIB}:${OPENSSL_DIR}/lib
export OPENSSL_MODULES=${WOLFPROV_LIB}
export OPENSSL_CONF=${RUNDIR}/provider.conf

# Run the tests
${OPENSSL_DIR}/bin/openssl list -verbose -provider-path ${WOLFPROV_LIB} -providers

${RUNDIR}/artifacts/openssl_example
