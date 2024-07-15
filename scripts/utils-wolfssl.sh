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

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
WOLFSSL_GIT=${WOLFSSL_GIT:-"https://github.com/wolfSSL/wolfssl.git"}
WOLFSSL_TAG=${WOLFSSL_TAG:-"v5.7.2-stable"}
WOLFSSL_SOURCE_DIR=${SCRIPT_DIR}/../wolfssl-source
WOLFSSL_INSTALL_DIR=${SCRIPT_DIR}/../wolfssl-install
WOLFSSL_ISFIPS=${WOLFSSL_ISFIPS:-0}
WOLFSSL_CONFIG_OPTS=${WOLFSSL_CONFIG_OPTS:-'--enable-all-crypto --with-eccminsz=192 --with-max-ecc-bits=1024 --enable-opensslcoexist --enable-sha'}
WOLFSSL_CONFIG_CFLAGS=${WOLFSSL_CONFIG_CFLAGS:-"-I${OPENSSL_INSTALL_DIR}/include -DWC_RSA_NO_PADDING -DWOLFSSL_PUBLIC_MP -DHAVE_PUBLIC_FFDHE -DHAVE_FFDHE_6144 -DHAVE_FFDHE_8192 -DWOLFSSL_PSS_LONG_SALT -DWOLFSSL_PSS_SALT_LEN_DISCOVER"}

WOLFPROV_DEBUG=${WOLFPROV_DEBUG:-0}

# Depends on OPENSSL_INSTALL_DIR
clone_wolfssl() {
    if [ -d ${WOLFSSL_SOURCE_DIR} ]; then
        WOLFSSL_TAG_CUR=$(cd ${WOLFSSL_SOURCE_DIR} && (git describe --tags 2>/dev/null || git branch --show-current))
        if [ "${WOLFSSL_TAG_CUR}" != "${WOLFSSL_TAG}" ]; then # force a rebuild
            printf "Version inconsistency. Please fix ${WOLFSSL_SOURCE_DIR} (expected: ${WOLFSSL_TAG}, got: ${WOLFSSL_TAG_CUR})\n"
            do_cleanup
            exit 1
        fi
    fi

    if [ ! -d ${WOLFSSL_SOURCE_DIR} ]; then
        printf "\tClone wolfSSL ${WOLFSSL_TAG} ... "
        if [ "$WOLFPROV_DEBUG" = "1" ]; then
            git clone -b ${WOLFSSL_TAG} ${WOLFSSL_GIT} \
                 ${WOLFSSL_SOURCE_DIR} >>$LOG_FILE 2>&1
            RET=$?
        else
            git clone --depth=1 -b ${WOLFSSL_TAG} ${WOLFSSL_GIT} \
                 ${WOLFSSL_SOURCE_DIR} >>$LOG_FILE 2>&1
            RET=$?
        fi
        if [ $RET != 0 ]; then
            printf "ERROR.\n"
            do_cleanup
            exit 1
        fi
        printf "Done.\n"
    fi
}

install_wolfssl() {
    clone_wolfssl
    cd ${WOLFSSL_SOURCE_DIR}

    if [ ! -d ${WOLFSSL_INSTALL_DIR} ]; then
        printf "\tConfigure wolfSSL ${WOLFSSL_TAG} ... "

        ./autogen.sh >>$LOG_FILE 2>&1
        CONF_ARGS="-prefix=${WOLFSSL_INSTALL_DIR}"

        if [ "$WOLFPROV_DEBUG" = "1" ]; then
            CONF_ARGS+=" --enable-debug"
        fi
        if [ "$WOLFSSL_ISFIPS" = "1" ]; then
            CONF_ARGS+=" --enable-fips=ready"
            if [ ! -e "XXX-fips-test" ]; then
                ./fips-check.sh keep nomakecheck fips-ready >>$LOG_FILE 2>&1
                RET=$?
                if [ $RET != 0 ]; then
                    printf "ERROR checking out FIPS\n"
                    rm -rf ${WOLFSSL_INSTALL_DIR}
                    do_cleanup
                    exit 1
                fi
                (cd XXX-fips-test && ./autogen.sh && ./configure ${CONF_ARGS} ${WOLFSSL_CONFIG_OPTS} CFLAGS="${WOLFSSL_CONFIG_CFLAGS}" && make && ./fips-hash.sh) >>$LOG_FILE 2>&1
            fi
            cd XXX-fips-test
        fi

        ./configure ${CONF_ARGS} ${WOLFSSL_CONFIG_OPTS} CFLAGS="${WOLFSSL_CONFIG_CFLAGS}" >>$LOG_FILE 2>&1
        RET=$?
        if [ $RET != 0 ]; then
            printf "ERROR.\n"
            rm -rf ${WOLFSSL_INSTALL_DIR}
            do_cleanup
            exit 1
        fi
        printf "Done.\n"

        printf "\tBuild wolfSSL ${WOLFSSL_TAG} ... "
        make >>$LOG_FILE 2>&1
        if [ $? != 0 ]; then
            printf "ERROR.\n"
            rm -rf ${WOLFSSL_INSTALL_DIR}
            do_cleanup
            exit 1
        fi
        printf "Done.\n"

        printf "\tInstalling wolfSSL ${WOLFSSL_TAG} ... "
        make install >>$LOG_FILE 2>&1
        if [ $? != 0 ]; then
            printf "ERROR.\n"
            rm -rf ${WOLFSSL_INSTALL_DIR}
            do_cleanup
            exit 1
        fi
        if [ "$WOLFSSL_ISFIPS" = "1" ]; then
            cd ..
        fi
        printf "Done.\n"
    fi

    cd ..
}

init_wolfssl() {
    install_wolfssl
    printf "\twolfSSL ${WOLFSSL_TAG} installed in: ${WOLFSSL_INSTALL_DIR}\n"
}

