#!/bin/bash

set -e

RUNDIR=$(pwd)
OPENSSL_DIR=${RUNDIR}/openssl-source/artifacts/macosx-x86_64
WOLFPROV_LIB=${RUNDIR}/artifacts/macos-x86_64/lib
export LD_LIBRARY_PATH=${WOLFPROV_LIB}:${OPENSSL_DIR}
export OPENSSL_MODULES=${WOLFPROV_LIB}
export OPENSSL_CONF=${RUNDIR}/provider.conf

# Run the tests
${OPENSSL_DIR}/apps/openssl list -verbose -provider-path ${WOLFPROV_LIB} -providers

${RUNDIR}/artifacts/openssl_example
