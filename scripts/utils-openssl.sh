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
OPENSSL_STUB_INSTALL_DIR=${SCRIPT_DIR}/../libdefault-stub-install

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
        printf "Removing OpenSSL install ...\n"
        rm -rf "${OPENSSL_INSTALL_DIR}"
    fi
}

clone_openssl() {
    if [ -d ${OPENSSL_SOURCE_DIR} ] && [ "$USE_CUR_TAG" != "1" ]; then
        check_git_match "${OPENSSL_TAG}" "${OPENSSL_SOURCE_DIR}"
    fi

    if [ ! -d ${OPENSSL_SOURCE_DIR} ]; then
        printf "\tOpenSSL source directory not found: ${OPENSSL_SOURCE_DIR}\n"
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

check_openssl_replace_default_mismatch() {
    local openssl_is_patched=0

    # Check if the source was patched for --replace-default
    if [ -f "${OPENSSL_SOURCE_DIR}/crypto/provider_predefined.c" ]; then
        if grep -q "wolfprov_provider_init" "${OPENSSL_SOURCE_DIR}/crypto/provider_predefined.c" 2>/dev/null; then
            openssl_is_patched=1
            printf "INFO: OpenSSL source modified - wolfProvider integrated as default provider (non-stock build).\n"
        fi
    fi

    # Check for mismatch
    if [ "$WOLFPROV_REPLACE_DEFAULT" = "1" ] && [ "$openssl_is_patched" = "0" ]; then
        printf "ERROR: --replace-default build mode mismatch!\n"
        printf "Existing OpenSSL was built WITHOUT --replace-default patch\n"
        printf "Current request: --replace-default build\n\n"
        printf "Fix: ./scripts/build-wolfprovider.sh --distclean\n"
        printf "Then rebuild with desired configuration.\n"
        exit 1
    elif [ "$WOLFPROV_REPLACE_DEFAULT" != "1" ] && [ "$openssl_is_patched" = "1" ]; then
        printf "ERROR: Standard build mode mismatch!\n"
        printf "Existing OpenSSL was built WITH --replace-default patch\n"
        printf "Current request: standard build\n\n"
        printf "Fix: ./scripts/build-wolfprovider.sh --distclean\n"
        printf "Then rebuild with desired configuration.\n"
        exit 1
    fi
}

patch_openssl() {
    if [ "$WOLFPROV_REPLACE_DEFAULT" = "1" ]; then

        if [ -d "${OPENSSL_INSTALL_DIR}" ]; then
            # If openssl is already installed, patching makes no sense as
            # it will not be rebuilt. It may already be built as patched,
            # just return and let check_openssl_replace_default_mismatch
            # check for the mismatch.
            return 0
        fi

        printf "\tApplying OpenSSL default provider patch ... "
        cd ${OPENSSL_SOURCE_DIR}

        # Check if patch is already applied
        if grep -q "wolfprov_provider_init" crypto/provider_predefined.c 2>/dev/null; then
            printf "Already applied.\n"
            return 0
        fi

        # Apply the patch
        patch -p1 < ${SCRIPT_DIR}/../patches/openssl3-replace-default.patch >>$LOG_FILE 2>&1
        if [ $? != 0 ]; then
            printf "ERROR.\n"
            printf "\n\nPatch application failed. Last 40 lines of log:\n"
            tail -n 40 $LOG_FILE
            do_cleanup
            exit 1
        fi
        printf "Done.\n"

        cd ${SCRIPT_DIR}/..
    fi
}

install_openssl() {
    printf "\nInstalling OpenSSL ${OPENSSL_TAG} ...\n"
    clone_openssl
    patch_openssl
    check_openssl_replace_default_mismatch
    pushd ${OPENSSL_SOURCE_DIR} &> /dev/null

    if [ ! -d ${OPENSSL_INSTALL_DIR} ]; then
        printf "\tConfigure OpenSSL ${OPENSSL_TAG} ... "

        # Build configure command
        CONFIG_CMD="./config shared --prefix=${OPENSSL_INSTALL_DIR}"
        if [ "$WOLFPROV_DEBUG" = "1" ]; then
            CONFIG_CMD+=" enable-trace --debug"
        fi
        if [ "$WOLFPROV_REPLACE_DEFAULT" = "1" ]; then
            CONFIG_CMD+=" no-external-tests no-tests"

            # Set up library paths to find the stub libdefault
            if [ -d "${OPENSSL_STUB_INSTALL_DIR}" ]; then
                # Link the stub library directly into libcrypto using LDFLAGS and LDLIBS
                CONFIGURE_LDFLAGS="-L${OPENSSL_STUB_INSTALL_DIR}/lib"
                CONFIGURE_LDLIBS="-ldefault"
            else
                printf "ERROR - stub libdefault not found in: ${OPENSSL_STUB_INSTALL_DIR}\n"
                do_cleanup
                exit 1
            fi

            CONFIG_CMD+=" LDFLAGS=${CONFIGURE_LDFLAGS} LDLIBS=${CONFIGURE_LDLIBS}"
        fi

        $CONFIG_CMD >>$LOG_FILE 2>&1
        RET=$?
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

    popd &> /dev/null
}

init_openssl() {
    install_openssl
    printf "\tOpenSSL ${OPENSSL_TAG} installed in: ${OPENSSL_INSTALL_DIR}\n"

    # Skip version check for replace-default mode since we only build libraries
    if [ "$WOLFPROV_REPLACE_DEFAULT" != "1" ]; then
        OSSL_VER=`LD_LIBRARY_PATH=${OPENSSL_LIB_DIRS} $OPENSSL_BIN version | tail -n1`
        case $OSSL_VER in
            OpenSSL\ 3.*) ;;
            *)
                echo "OpenSSL ($OPENSSL_BIN) has wrong version: $OSSL_VER"
                echo "Set: OPENSSL_DIR"
                exit 1
                ;;
        esac
    fi

    if [ -z $LD_LIBRARY_PATH ]; then
      export LD_LIBRARY_PATH=${OPENSSL_LIB_DIRS}
    else
      export LD_LIBRARY_PATH=${OPENSSL_LIB_DIRS}:$LD_LIBRARY_PATH
    fi
}

