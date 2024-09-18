#!/bin/bash

set -e # Fail on any error

XCODE_SCRIPTS_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
WOLFPROV_DIR=${XCODE_SCRIPTS_DIR}/../..
SCRIPT_DIR=${WOLFPROV_DIR}/scripts
OUTDIR=${WOLFPROV_DIR}/artifacts
LOG_FILE=${OUTDIR}/wolfProvider.log

source ${SCRIPT_DIR}/utils-openssl.sh
source ${SCRIPT_DIR}/utils-wolfssl.sh

mkdir -p ${OUTDIR}

clone_openssl
cd ${WOLFPROV_DIR}/openssl-source && ${XCODE_SCRIPTS_DIR}/build-openssl-framework.sh

clone_wolfssl
cd ${WOLFPROV_DIR}/wolfssl-source && ${XCODE_SCRIPTS_DIR}/build-wolfssl-framework.sh -c "${WOLFSSL_CONFIG_OPTS}" -p "${WOLFSSL_CONFIG_CFLAGS}"

cd ${WOLFPROV_DIR} && ${XCODE_SCRIPTS_DIR}/build-wolfprovider-framework.sh

ARCH=$(uname -m)
clang ${WOLFPROV_DIR}/examples/openssl_example.c -I ${OPENSSL_SOURCE_DIR}/artifacts/openssl-install-macosx-${ARCH}/include -L ${OPENSSL_SOURCE_DIR}/artifacts/openssl-install-macosx-${ARCH}/lib -lcrypto -o ${OUTDIR}/openssl_example

echo "Script ran for $SECONDS seconds"
