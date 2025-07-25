#!/bin/bash
#
# Copyright (C) 2006-2024 wolfSSL Inc.
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
# along with wolfProvider. If not, see <http://www.gnu.org/licenses/>.
#

#
# OpenSSL 3.5.0
#

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
source ${SCRIPT_DIR}/utils-general.sh

OPENSSL_GIT_URL="https://github.com/openssl/openssl.git"
OPENSSL_TAG=${OPENSSL_TAG:-"openssl-3.5.0"}
OPENSSL_SOURCE_DIR=${SCRIPT_DIR}/../openssl-source
OPENSSL_INSTALL_DIR=${SCRIPT_DIR}/../openssl-install
OPENSSL_BIN=${OPENSSL_INSTALL_DIR}/bin/openssl
OPENSSL_TEST=${OPENSSL_SOURCE_DIR}/test
OPENSSL_LIB_DIRS="${OPENSSL_INSTALL_DIR}/lib:${OPENSSL_INSTALL_DIR}/lib64"

NUMCPU=${NUMCPU:-8}
WOLFPROV_DEBUG=${WOLFPROV_DEBUG:-0}
USE_CUR_TAG=${USE_CUR_TAG:-0}

clean_openssl() {
    printf "\n"

    if [ "$WOLFPROV_CLEAN" -eq "1" ]; then
        printf "Cleaning OpenSSL ...\n"
        if [ -f "${OPENSSL_SOURCE_DIR}/Makefile" ]; then
            make -C "${OPENSSL_SOURCE_DIR}" clean >>$LOG_FILE 2>&1
        fi
        rm -rf "${OPENSSL_INSTALL_DIR}"
    fi
    if [ "$WOLFPROV_DISTCLEAN" -eq "1" ]; then
        printf "Removing OpenSSL source ...\n"
        rm -rf "${OPENSSL_SOURCE_DIR}"
    fi
}

clone_openssl() {
    if [ -d ${OPENSSL_SOURCE_DIR} ] && [ "$USE_CUR_TAG" != "1" ]; then
        check_git_match "${OPENSSL_TAG}" "${OPENSSL_SOURCE_DIR}"
    fi

    if [ ! -d ${OPENSSL_SOURCE_DIR} ]; then
        printf "\tOpenSSL source directory not found: ${OPENSSL_SOURCE_DIR}\n"
        printf "\tParent directory:\n"
        tree -L 2 $(dirname ${OPENSSL_SOURCE_DIR}/..) || true
        CLONE_TAG=${USE_CUR_TAG:+${OPENSSL_TAG_CUR}}
        CLONE_TAG=${CLONE_TAG:-${OPENSSL_TAG}}

        DEPTH_ARG=${WOLFPROV_DEBUG:+""}
        DEPTH_ARG=${DEPTH_ARG:---depth=1}

        printf "\tClone OpenSSL ${CLONE_TAG} from ${OPENSSL_GIT_URL} ... "
        git clone ${DEPTH_ARG} -b ${CLONE_TAG} ${OPENSSL_GIT_URL} ${OPENSSL_SOURCE_DIR}
        RET=$?

        if [ $RET != 0 ]; then
            printf "ERROR.\n"
            do_cleanup
            exit 1
        fi
        printf "Done.\n"

        printf "\tOpenSSL source cloned to: ${OPENSSL_SOURCE_DIR}\n"
        if [ ! -d ${OPENSSL_SOURCE_DIR} ]; then
            printf "ERROR: OpenSSL source directory not found after clone: ${OPENSSL_SOURCE_DIR}\n"
        fi
    else
        printf "\tOpenSSL source directory exists: ${OPENSSL_SOURCE_DIR}\n"
        if [ ! -d ${OPENSSL_SOURCE_DIR}/.git ]; then
            printf "ERROR: OpenSSL source directory is not a git repository: ${OPENSSL_SOURCE_DIR}\n"
            do_cleanup
            exit 1
        fi
    fi
}

install_openssl() {
    printf "\nInstalling OpenSSL ${OPENSSL_TAG} ...\n"
    clone_openssl
    cd ${OPENSSL_SOURCE_DIR}

    if [ ! -d ${OPENSSL_INSTALL_DIR} ]; then
        printf "\tConfigure OpenSSL ${OPENSSL_TAG} ... "
        if [ "$WOLFPROV_DEBUG" = "1" ]; then
            ./config shared enable-trace --prefix=${OPENSSL_INSTALL_DIR} --debug >>$LOG_FILE 2>&1
            RET=$?
        else
            ./config shared --prefix=${OPENSSL_INSTALL_DIR} >>$LOG_FILE 2>&1
            RET=$?
        fi
        if [ $RET != 0 ]; then
            printf "ERROR.\n"
            rm -rf ${OPENSSL_INSTALL_DIR}
            do_cleanup
            exit 1
        fi
        printf "Done.\n"

        printf "\tBuild OpenSSL ${OPENSSL_TAG} ... "
        make -j$NUMCPU >>$LOG_FILE 2>&1
        if [ $? != 0 ]; then
            printf "ERROR.\n"
            rm -rf ${OPENSSL_INSTALL_DIR}
            do_cleanup
            exit 1
        fi
        printf "Done.\n"

        printf "\tInstalling OpenSSL ${OPENSSL_TAG} ... "
        make -j$NUMCPU install >>$LOG_FILE 2>&1
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
    printf "\tOpenSSL ${OPENSSL_TAG} installed in: ${OPENSSL_INSTALL_DIR}\n"

    OSSL_VER=`LD_LIBRARY_PATH=${OPENSSL_LIB_DIRS} $OPENSSL_BIN version | tail -n1`
    case $OSSL_VER in
        OpenSSL\ 3.*) ;;
        *)
            echo "OpenSSL ($OPENSSL_BIN) has wrong version: $OSSL_VER"
            echo "Set: OPENSSL_DIR"
            exit 1
            ;;
    esac

    if [ -z $LD_LIBRARY_PATH ]; then
      export LD_LIBRARY_PATH=${OPENSSL_LIB_DIRS}
    else
      export LD_LIBRARY_PATH=${OPENSSL_LIB_DIRS}:$LD_LIBRARY_PATH
    fi
}

