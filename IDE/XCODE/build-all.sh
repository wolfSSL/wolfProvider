#!/bin/bash

set -e # Fail on any error

XCODE_SCRIPTS_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
WOLFPROV_DIR=${XCODE_SCRIPTS_DIR}/../..
SCRIPT_DIR=${WOLFPROV_DIR}/scripts
OUTDIR=${WOLFPROV_DIR}/artifacts
LOG_FILE=${OUTDIR}/wolfProvider.log

source ${SCRIPT_DIR}/utils-openssl.sh
source ${SCRIPT_DIR}/utils-wolfssl.sh

#clone_openssl
#cd ${WOLFPROV_DIR}/openssl-source && ${XCODE_SCRIPTS_DIR}/build-openssl-framework.sh

clone_wolfssl
cd ${WOLFPROV_DIR}/wolfssl-source && ${XCODE_SCRIPTS_DIR}/build-wolfssl-framework.sh -c "--enable-opensslcoexist --enable-cmac --enable-keygen --enable-sha --enable-aesctr --enable-aesccm --enable-x963kdf --enable-compkey --enable-certgen --enable-aeskeywrap --enable-enckeys --enable-base16 --enable-aesgcm-stream --enable-pwdbased" -p "-I${WOLFPROV_DIR}/openssl-source -DHAVE_AES_ECB -DWOLFSSL_AES_DIRECT -DWC_RSA_NO_PADDING -DWOLFSSL_PUBLIC_MP -DECC_MIN_KEY_SZ=192 -DHAVE_PUBLIC_FFDHE -DHAVE_FFDHE_6144 -DHAVE_FFDHE_8192 -DFP_MAX_BITS=16384 -DWOLFSSL_DH_EXTRA -DWOLFSSL_PSS_LONG_SALT -DWOLFSSL_PSS_SALT_LEN_DISCOVER"

cd ${WOLFPROV_DIR} && ${XCODE_SCRIPTS_DIR}/build-wolfprovider-framework.sh
