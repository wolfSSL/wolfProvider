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

download_wolfssl_500() {
    WOLFSSL_5_0_0_GIT="https://github.com/wolfSSL/wolfssl.git"
    printf "\tClone wolfSSL 5.0.0 ... "
    git clone --depth=1 -b ${WOLFSSL_5_0_0_TAG} ${WOLFSSL_5_0_0_GIT} \
         ${WOLFSSL_5_0_0_SOURCE} &>> $LOGFILE
    if [ $? != 0 ]; then
        printf "ERROR.\n"
        do_cleanup
        exit 1
    fi
    printf "Done.\n"
}

configure_wolfssl() {
    ./configure $1 "$2" -prefix=${WOLFSSL_5_0_0_INSTALL} &>> $LOGFILE
    if [ $? != 0 ]; then
        printf "ERROR.\n"
        do_cleanup
        exit 1
    fi
}

build_wolfssl_500() {
    printf "\tConfigure wolfSSL 5.0.0 ... "
    cd ${WOLFSSL_5_0_0_SOURCE}

    if [ -z "$WOLFSSL_CONFIG_OPTS" ]; then
        WOLFSSL_CONFIG_OPTS='--enable-opensslcoexist --enable-cmac --enable-keygen --enable-sha --enable-aesctr --enable-aesccm --enable-x963kdf --enable-compkey --enable-certgen --enable-aeskeywrap --enable-enckeys --enable-base16 --enable-aesgcm-stream --enable-curve25519 --enable-curve448 --enable-ed25519 --enable-ed448 --enable-pwdbased'
        WOLFSSL_CONFIG_CPPFLAGS='CPPFLAGS=-DHAVE_AES_ECB -DWOLFSSL_AES_DIRECT -DWC_RSA_NO_PADDING -DWOLFSSL_PUBLIC_MP -DECC_MIN_KEY_SZ=192 -DHAVE_PUBLIC_FFDHE -DHAVE_FFDHE_6144 -DHAVE_FFDHE_8192 -DFP_MAX_BITS=16384 -DWOLFSSL_DH_EXTRA -DWOLFSSL_PSS_LONG_SALT -DWOLFSSL_PSS_SALT_LEN_DISCOVER'
    fi

    ./autogen.sh &> $LOGFILE
    configure_wolfssl "${WOLFSSL_CONFIG_OPTS}" "${WOLFSSL_CONFIG_CPPFLAGS}"
    if [ $? != 0 ]; then
        printf "ERROR.\n"
        do_cleanup
        exit 1
    fi
    printf "Done.\n"

    printf "\tBuild wolfSSL 5.0.0 ... "
    make -j$MAKE_JOBS &> $LOGFILE
    if [ $? != 0 ]; then
        printf "ERROR.\n"
        do_cleanup
        exit 1
    fi

    cd ..
    printf "Done.\n"
}

install_wolfssl_500() {
    printf "\tInstalling wolfSSL 5.0.0 ... "
    cd ${WOLFSSL_5_0_0_SOURCE}

    make -j$MAKE_JOBS install &> $LOGFILE
    if [ $? != 0 ]; then
        printf "ERROR.\n"
        do_cleanup
        exit 1
    fi

    cd ..
    printf "Done.\n"
}

install_wolfssl() {
    if [ -z "${WOLFSSL_5_0_0_INSTALL}" ]; then
        WOLFSSL_5_0_0_TAG="v5.0.0-stable"
        WOLFSSL_5_0_0_SOURCE=$PWD/wolfssl-5_0_0
        WOLFSSL_5_0_0_INSTALL=$PWD/wolfssl-5_0_0-install
        export LD_LIBRARY_PATH="$LD_LIBRARY_PATH:$WOLFSSL_5_0_0_INSTALL/lib"

        if [ ! -d ${WOLFSSL_5_0_0_SOURCE} ]; then
            download_wolfssl_500
            build_wolfssl_500
            rm -rf ${WOLFSSL_5_0_0_INSTALL}
        fi
        if [ ! -d ${WOLFSSL_5_0_0_INSTALL} ]; then
            install_wolfssl_500
        else
            printf "\twolfSSL 5.0.0 install exists.\n"
        fi
    else
        printf "\twolfSSL 5.0.0 install from: ${WOLFSSL_5_0_0_INSTALL}\n"
    fi
}

