#!/bin/bash

set -e # Fail on any error

XCODE_SCRIPTS_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
WOLFPROV_DIR=${XCODE_SCRIPTS_DIR}/../..
SCRIPT_DIR=${WOLFPROV_DIR}/scripts
OUTDIR=${WOLFPROV_DIR}/artifacts
LOG_FILE=${OUTDIR}/wolfProvider.log

source ${SCRIPT_DIR}/utils-openssl.sh
source ${SCRIPT_DIR}/utils-wolfssl.sh

clone_openssl
cd ${WOLFPROV_DIR}/openssl-source && ${XCODE_SCRIPTS_DIR}/build-openssl-framework.sh

#init_wolfssl
#cd ${WOLFPROV_DIR}/wolfssl-source && ${XCODE_SCRIPTS_DIR}/build-wolfssl-framework.sh

cd ${WOLFPROV_DIR} && ${XCODE_SCRIPTS_DIR}/build-wolfprovider-framework.sh
