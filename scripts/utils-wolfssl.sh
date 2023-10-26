#!/bin/bash
#
# Copyright (C) 2021 wolfSSL Inc.
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
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
#

#
# wolfSSL 5.0.0
#

WOLFSSL_GIT="https://github.com/wolfSSL/wolfssl.git"
WOLFSSL_TAG=${WOLFSSL_TAG:-"v5.6.3-stable"}
WOLFSSL_SOURCE_DIR=$PWD/wolfssl-source
WOLFSSL_INSTALL_DIR=$PWD/wolfssl-install

# Depends on OPENSSL_INSTALL_DIR
install_wolfssl() {
    if [ -d ${WOLFSSL_SOURCE_DIR} ]; then
        WOLFSSL_TAG_CUR=$(cd ${WOLFSSL_SOURCE_DIR} && git describe --tags)
        if [ "${WOLFSSL_TAG_CUR}" != "${WOLFSSL_TAG}" ]; then # force a rebuild
            printf "Version inconsistency. Please fix ${WOLFSSL_SOURCE_DIR} (expected: ${WOLFSSL_TAG}, got: ${WOLFSSL_TAG_CUR})\n"
            do_cleanup
            exit 1
        fi
    fi

    if [ ! -d ${WOLFSSL_SOURCE_DIR} ]; then
        printf "\tClone wolfSSL ${WOLFSSL_TAG} ... "
        git clone --depth=1 -b ${WOLFSSL_TAG} ${WOLFSSL_GIT} \
             ${WOLFSSL_SOURCE_DIR} 2>&1 >> $LOG_FILE
        if [ $? != 0 ]; then
            printf "ERROR.\n"
            do_cleanup
            exit 1
        fi
        printf "Done.\n"
    fi

    cd ${WOLFSSL_SOURCE_DIR}

    if [ ! -d ${WOLFSSL_INSTALL_DIR} ]; then
        printf "\tConfigure wolfSSL ${WOLFSSL_TAG} ... "
        if [ -z "$WOLFSSL_CONFIG_OPTS" ]; then
            WOLFSSL_CONFIG_OPTS='--enable-opensslcoexist --enable-cmac --enable-keygen --enable-sha --enable-aesctr --enable-aesccm --enable-x963kdf --enable-compkey --enable-certgen --enable-aeskeywrap --enable-enckeys --enable-base16 --enable-aesgcm-stream --enable-curve25519 --enable-curve448 --enable-ed25519 --enable-ed448 --enable-pwdbased'
            WOLFSSL_CONFIG_CPPFLAGS=CPPFLAGS="-I${OPENSSL_INSTALL_DIR} -DHAVE_AES_ECB -DWOLFSSL_AES_DIRECT -DWC_RSA_NO_PADDING -DWOLFSSL_PUBLIC_MP -DECC_MIN_KEY_SZ=192 -DHAVE_PUBLIC_FFDHE -DHAVE_FFDHE_6144 -DHAVE_FFDHE_8192 -DFP_MAX_BITS=16384 -DWOLFSSL_DH_EXTRA -DWOLFSSL_PSS_LONG_SALT -DWOLFSSL_PSS_SALT_LEN_DISCOVER"
        fi

        ./autogen.sh 2>&1 >> $LOG_FILE
        ./configure ${WOLFSSL_CONFIG_OPTS} "${WOLFSSL_CONFIG_CPPFLAGS}" -prefix=${WOLFSSL_INSTALL_DIR} 2>&1 >> $LOG_FILE
        if [ $? != 0 ]; then
            printf "ERROR.\n"
            rm -rf ${WOLFSSL_INSTALL_DIR}
            do_cleanup
            exit 1
        fi
        printf "Done.\n"

        printf "\tBuild wolfSSL ${WOLFSSL_TAG} ... "
        make -j$NUMCPU 2>&1 >> $LOG_FILE
        if [ $? != 0 ]; then
            printf "ERROR.\n"
            rm -rf ${WOLFSSL_INSTALL_DIR}
            do_cleanup
            exit 1
        fi
        printf "Done.\n"

        printf "\tInstalling wolfSSL ${WOLFSSL_TAG} ... "
        make -j$NUMCPU install 2>&1 >> $LOG_FILE
        if [ $? != 0 ]; then
            printf "ERROR.\n"
            rm -rf ${WOLFSSL_INSTALL_DIR}
            do_cleanup
            exit 1
        fi
        printf "Done.\n"
    fi

    cd ..
}

init_wolfssl() {
    install_wolfssl
    printf "\twolfSSL ${WOLFSSL_TAG} install from: ${WOLFSSL_INSTALL_DIR}\n"
}

