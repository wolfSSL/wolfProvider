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
# OpenSSL 3.0.0
#

download_openssl_300() {
    OPENSSL_3_0_0_GIT="git@github.com:openssl/openssl.git"
    printf "\tClone OpenSSL 3.0.0 ... "
    git clone --depth=1 -b ${OPENSSL_3_0_0_TAG} ${OPENSSL_3_0_0_GIT} \
         ${OPENSSL_3_0_0_SOURCE} &> $LOGFILE
    printf "Done.\n"
}

build_openssl_300() {
    printf "\tConfigure OpenSSL 3.0.0 ... "
    ./config shared --prefix=${OPENSSL_3_0_0_INSTALL} &> $LOGFILE
    if [ $? != 0 ]; then
        printf "ERROR.\n"
        do_cleanup
        exit 1
    fi
    printf "Done.\n"

    printf "\tBuild OpenSSL 3.0.0 ... "
    make -j$MAKE_JOBS &> $LOGFILE
    if [ $? != 0 ]; then
        printf "ERROR.\n"
        do_cleanup
        exit 1
    fi
    printf "Done.\n"
}

install_openssl_300() {
    printf "\tInstalling OpenSSL 3.0.0 ... "
    make -j$MAKE_JOBS install &> $LOGFILE
    if [ $? != 0 ]; then
        printf "ERROR.\n"
        do_cleanup
        exit 1
    fi
    printf "Done.\n"
}

install_openssl() {
    if [ -z "${OPENSSL_3_0_0_INSTALL}" ]; then
        OPENSSL_3_0_0_TAG="openssl-3.0.0"
        OPENSSL_3_0_0_SOURCE=$PWD/openssl-3_0_0
        OPENSSL_3_0_0_INSTALL=$PWD/openssl-3_0_0-install
        export LD_LIBRARY_PATH="$LD_LIBRARY_PATH:$OPENSSL_3_0_0_INSTALL/lib64"

        if [ ! -d ${OPENSSL_3_0_0_SOURCE} ]; then
            download_openssl_300
            cd ${OPENSSL_3_0_0_SOURCE}
            build_openssl_300
            cd ..
            rm -rf ${OPENSSL_3_0_0_INSTALL}
        fi
        if [ ! -d ${OPENSSL_3_0_0_INSTALL} ]; then
            cd ${OPENSSL_3_0_0_SOURCE}
            install_openssl_300
            cd ..
        else
            printf "\tOpenSSL 3.0.0 install exists.\n"
        fi
    else
        printf "\tOpenSSL 3.0.0 install from: ${OPENSSL_3_0_0_INSTALL}\n"
    fi
}

