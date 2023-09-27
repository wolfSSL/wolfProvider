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

OPENSSL_GIT="https://github.com/openssl/openssl.git"
OPENSSL_TAG=${OPENSSL_TAG:-"openssl-3.0.0"}
OPENSSL_SOURCE_DIR=$PWD/openssl-source
OPENSSL_INSTALL_DIR=$PWD/openssl-install

install_openssl() {
    if [ -d ${OPENSSL_SOURCE_DIR} ]; then
        if [ "$(cd ${OPENSSL_SOURCE_DIR} && git describe --tags)" != "${OPENSSL_TAG}" ]; then # force a rebuild
            printf "Version inconsistency. Please fix ${OPENSSL_SOURCE_DIR}\n"
            do_cleanup
            exit 1
        fi
    fi

    if [ ! -d ${OPENSSL_SOURCE_DIR} ]; then
        printf "\tClone OpenSSL ${OPENSSL_TAG} ... "
        git clone --depth=1 -b ${OPENSSL_TAG} ${OPENSSL_GIT} \
             ${OPENSSL_SOURCE_DIR} &>> $LOG_FILE
        if [ $? != 0 ]; then
            printf "ERROR.\n"
            do_cleanup
            exit 1
        fi
        printf "Done.\n"
    fi

    cd ${OPENSSL_SOURCE_DIR}

    if [ ! -d ${OPENSSL_INSTALL_DIR} ]; then
        printf "\tConfigure OpenSSL ${OPENSSL_TAG} ... "
        ./config shared --prefix=${OPENSSL_INSTALL_DIR} &>> $LOG_FILE
        if [ $? != 0 ]; then
            printf "ERROR.\n"
            rm -rf ${OPENSSL_INSTALL_DIR}
            do_cleanup
            exit 1
        fi
        printf "Done.\n"

        printf "\tBuild OpenSSL ${OPENSSL_TAG} ... "
        make -j$NUMCPU &>> $LOG_FILE
        if [ $? != 0 ]; then
            printf "ERROR.\n"
            rm -rf ${OPENSSL_INSTALL_DIR}
            do_cleanup
            exit 1
        fi
        printf "Done.\n"

        printf "\tInstalling OpenSSL ${OPENSSL_TAG} ... "
        make -j$NUMCPU install &>> $LOG_FILE
        if [ $? != 0 ]; then
            printf "ERROR.\n"
            rm -rf ${OPENSSL_INSTALL_DIR}
            do_cleanup
            exit 1
        fi
        printf "Done.\n"
    fi

    cd ..
}

init_openssl() {
    install_openssl
    printf "\tOpenSSL ${OPENSSL_TAG} install at: ${OPENSSL_INSTALL_DIR}\n"

    OPENSSL_BIN=${OPENSSL_INSTALL_DIR}/bin/openssl
    OPENSSL_TEST=${OPENSSL_SOURCE_DIR}/test

    OSSL_VER=`LD_LIBRARY_PATH=${OPENSSL_INSTALL_DIR}/lib64 $OPENSSL_BIN version`
    case $OSSL_VER in
        OpenSSL\ 3.*) ;;
        *)
            echo "OpenSSL ($OPENSSL_BIN) has wrong version: $OSSL_VER"
            echo "Set: OPENSSL_DIR"
            exit 1
            ;;
    esac
}

