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
OPENSSL_TAG=${OPENSSL_TAG:-"openssl-3.5.2"}
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
        git clone ${DEPTH_ARG} -b ${CLONE_TAG} ${OPENSSL_GIT_URL} ${OPENSSL_SOURCE_DIR} >>$LOG_FILE 2>&1
        RET=$?

        if [ $RET != 0 ]; then
            printf "ERROR.\n"
            tail -n 100 $LOG_FILE
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

is_openssl_patched() {
    if [ ! -f "${OPENSSL_SOURCE_DIR}/crypto/provider_predefined.c" ]; then
        return 0
    fi

    pushd ${OPENSSL_SOURCE_DIR} &> /dev/null
    patch_applied=$(git diff --quiet "crypto/provider_predefined.c" 2>/dev/null && echo 1 || echo 0)
    popd &> /dev/null
    return $patch_applied
}

check_openssl_replace_default_mismatch() {
    local openssl_is_patched=0

    # Check if the source was patched for --replace-default
    if is_openssl_patched; then
        openssl_is_patched=1
        printf "INFO: OpenSSL source modified - wolfProvider integrated as default provider (non-stock build).\n"
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

patch_openssl_version() {
    # Patch the OpenSSL version (wolfProvider/openssl-source/VERSION.dat) 
    # with our BUILD_METADATA, depending on the FIPS flag. Either "wolfProvider" or "wolfProvider-fips".
    if [ "$WOLFSSL_ISFIPS" = "1" ]; then
        sed -i 's/BUILD_METADATA=.*/BUILD_METADATA=wolfProvider-fips/g' ${OPENSSL_SOURCE_DIR}/VERSION.dat
    else
        sed -i 's/BUILD_METADATA=.*/BUILD_METADATA=wolfProvider-nonfips/g' ${OPENSSL_SOURCE_DIR}/VERSION.dat
    fi

    # Patch the OpenSSL RELEASE_DATE field with the current date in the format DD MMM YYYY
    sed -i "s/RELEASE_DATE=.*/RELEASE_DATE=$(date '+%d %b %Y')/g" ${OPENSSL_SOURCE_DIR}/VERSION.dat
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
        pushd ${OPENSSL_SOURCE_DIR} &> /dev/null

        # Check if patch is already applied
        if is_openssl_patched; then
            printf "Already applied.\n"
            popd &> /dev/null
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
        patch_openssl_version
        printf "Done.\n"

        popd &> /dev/null
    fi
}

install_openssl_deb() {
    printf "\nInstalling OpenSSL ${OPENSSL_TAG} for Debian packaging ...\n"
    clone_openssl
    patch_openssl
    check_openssl_replace_default_mismatch

    pushd ${OPENSSL_SOURCE_DIR} &> /dev/null

    if [ -d ${OPENSSL_INSTALL_DIR} ]; then
        printf "\tOpenSSL install directory already exists: ${OPENSSL_INSTALL_DIR}\n"
        printf "\tRemoving existing install directory...\n"
        rm -rf ${OPENSSL_INSTALL_DIR}
    fi

    # Build configure command
    CONFIG_CMD="./config shared"

    # Determine the install paths for Debian Bookworm
    DEB_HOST_MULTIARCH=$(dpkg-architecture -qDEB_HOST_MULTIARCH)
    CONFIG_CMD+=" --prefix=/usr --openssldir=/usr/lib/ssl --libdir=lib/${DEB_HOST_MULTIARCH} "

    if [ "$WOLFPROV_DEBUG" = "1" ]; then
        CONFIG_CMD+=" enable-trace --debug"
    fi

    if [ "$WOLFPROV_REPLACE_DEFAULT" = "1" ]; then
        CONFIG_CMD+=" no-external-tests no-tests"
    fi

    printf "\tConfigure OpenSSL ${OPENSSL_TAG} ... "
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
    make -j$NUMCPU install DESTDIR=${OPENSSL_INSTALL_DIR} >>$LOG_FILE 2>&1
    if [ $? != 0 ]; then
        printf "ERROR.\n"
        rm -rf ${OPENSSL_INSTALL_DIR}
        do_cleanup
        exit 1
    fi
    printf "Done.\n"

    # We use a different install path for Debian, which places the outputs in $OPENSSL_INSTALL_DIR/usr/lib/${DEB_HOST_MULTIARCH}
    # rather than $OPENSSL_INSTALL_DIR. So manually copy the outputs to the correct path.
    printf "\tCopying outputs to ${OPENSSL_INSTALL_DIR} for OpenSSL ${OPENSSL_TAG} ... "
    mkdir -p $OPENSSL_INSTALL_DIR/lib
    cp -r $OPENSSL_INSTALL_DIR/usr/lib/${DEB_HOST_MULTIARCH}/* $OPENSSL_INSTALL_DIR/lib
    cp -r $OPENSSL_INSTALL_DIR/usr/bin $OPENSSL_INSTALL_DIR/bin
    cp -r $OPENSSL_INSTALL_DIR/usr/include $OPENSSL_INSTALL_DIR/include
    cp -r $OPENSSL_INSTALL_DIR/usr/lib/pkgconfig $OPENSSL_INSTALL_DIR/lib/pkgconfig
    printf "Done.\n"

    popd &> /dev/null
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
    if [ $WOLFPROV_BUILD_DEBIAN -eq 1 ]; then
        install_openssl_deb
    else
        install_openssl
    fi
    printf "\tOpenSSL ${OPENSSL_TAG} installed in: ${OPENSSL_INSTALL_DIR}\n"

    if [ -z $LD_LIBRARY_PATH ]; then
      export LD_LIBRARY_PATH=${OPENSSL_LIB_DIRS}
    else
      export LD_LIBRARY_PATH=${OPENSSL_LIB_DIRS}:$LD_LIBRARY_PATH
    fi
}

