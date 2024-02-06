#!/bin/bash

set -e

RUNDIR=$(pwd)
ARCH=$(uname -m)
OPENSSL_DIR=${RUNDIR}/openssl-source/artifacts/openssl-install-macosx-${ARCH}/
WOLFPROV_LIB=${RUNDIR}/artifacts/wolfprov-install-macosx-${ARCH}/lib
export LD_LIBRARY_PATH=${WOLFPROV_LIB}:${OPENSSL_DIR}/lib
export OPENSSL_MODULES=${WOLFPROV_LIB}
export OPENSSL_CONF=${RUNDIR}/provider.conf

# Run the tests
${OPENSSL_DIR}/bin/openssl list -verbose -provider-path ${WOLFPROV_LIB} -providers

${RUNDIR}/artifacts/openssl_example
