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

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
source ${SCRIPT_DIR}/utils-openssl.sh
source ${SCRIPT_DIR}/utils-wolfssl.sh
source ${SCRIPT_DIR}/utils-general.sh

WOLFPROV_SOURCE_DIR=${SCRIPT_DIR}/..
WOLFPROV_INSTALL_DIR=${SCRIPT_DIR}/../wolfprov-install
WOLFPROV_CONFIG_OPTS=${WOLFPROV_CONFIG_OPTS:-"--with-openssl=${OPENSSL_INSTALL_DIR} --with-wolfssl=${WOLFSSL_INSTALL_DIR} --prefix=${WOLFPROV_INSTALL_DIR}"}
WOLFPROV_CONFIG_CFLAGS=${WOLFPROV_CONFIG_CFLAGS:-''}

if [ "${WOLFPROV_QUICKTEST}" = "1" ]; then
    WOLFPROV_CONFIG_CFLAGS="${WOLFPROV_CONFIG_CFLAGS} -DWOLFPROV_QUICKTEST"
fi

if [ "$WOLFSSL_ISFIPS" -eq "1" ] || [ -n "$WOLFSSL_FIPS_BUNDLE" ]; then
    WOLFPROV_CONFIG=${WOLFPROV_CONFIG:-"$WOLFPROV_SOURCE_DIR/provider-fips.conf"}
else
    WOLFPROV_CONFIG=${WOLFPROV_CONFIG:-"$WOLFPROV_SOURCE_DIR/provider.conf"}
fi

WOLFPROV_NAME="libwolfprov"
WOLFPROV_PATH=$WOLFPROV_INSTALL_DIR/lib

WOLFPROV_DEBUG=${WOLFPROV_DEBUG:-0}

WOLFPROV_CLEAN=${WOLFPROV_CLEAN:-0}
WOLFPROV_DISTCLEAN=${WOLFPROV_DISTCLEAN:-0}

clean_wolfprov() {
    printf "\n"

    if [ "$WOLFPROV_CLEAN" -eq "1" ]; then
        printf "Cleaning wolfProvider ...\n"
        if [ -f "Makefile" ]; then
            make clean >>$LOG_FILE 2>&1
        fi
        rm -rf ${WOLFPROV_INSTALL_DIR}
    fi
}

install_wolfprov() {
    cd ${WOLFPROV_SOURCE_DIR}

    init_openssl
    init_wolfssl

    printf "\nConsolidating wolfProvider ...\n"
    unset OPENSSL_MODULES
    unset OPENSSL_CONF
    printf "LD_LIBRARY_PATH: $LD_LIBRARY_PATH\n"

    printf "\tConfigure wolfProvider ... "
    if [ ! -e "${WOLFPROV_SOURCE_DIR}/configure" ]; then
        ./autogen.sh >>$LOG_FILE 2>&1
    fi

    if [ "$WOLFPROV_DEBUG" = "1" ]; then
        WOLFPROV_CONFIG_OPTS+=" --enable-debug"
    fi

    ./configure ${WOLFPROV_CONFIG_OPTS} CFLAGS="${WOLFPROV_CONFIG_CFLAGS}" >>$LOG_FILE 2>&1
    RET=$?

    if [ $RET != 0 ]; then
        printf "\n\n...\n"
        tail -n 40 $LOG_FILE
        do_cleanup
        exit 1
    fi
    printf "Done.\n"

    printf "\tBuild wolfProvider ... "
    make -j$NUMCPU >>$LOG_FILE 2>&1
    if [ $? != 0 ]; then
        printf "\n\n...\n"
        tail -n 40 $LOG_FILE
        do_cleanup
        exit 1
    fi
    printf "Done.\n"

    printf "\tTest wolfProvider ... "
    make test >>$LOG_FILE 2>&1
    if [ $? != 0 ]; then
        printf "\n\n...\n"
        tail -n 40 $LOG_FILE
        do_cleanup
        exit 1
    fi
    printf "Done.\n"

    printf "\tInstall wolfProvider ... "
    make install >>$LOG_FILE 2>&1
    if [ $? != 0 ]; then
        printf "\n\n...\n"
        tail -n 40 $LOG_FILE
        do_cleanup
        exit 1
    fi
    printf "Done.\n"
}

init_wolfprov() {
    if [ "$WOLFPROV_CLEAN" -eq "1" ] || [ "$WOLFPROV_DISTCLEAN" -eq "1" ]; then
        clean_openssl
        clean_wolfssl
        clean_wolfprov
    else
        # Unset WPFF so we dont fail unit test when building
        if [ "${WOLFPROV_FORCE_FAIL}" = "1" ]; then
            unset WOLFPROV_FORCE_FAIL
            install_wolfprov
            export WOLFPROV_FORCE_FAIL=1
        else
            install_wolfprov
        fi
        printf "\twolfProvider installed in: ${WOLFPROV_INSTALL_DIR}\n"

        export OPENSSL_MODULES=$WOLFPROV_PATH
        export OPENSSL_CONF=${WOLFPROV_CONFIG}
    fi
}

