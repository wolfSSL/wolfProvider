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
source ${SCRIPT_DIR}/utils-general.sh

WOLFSSL_GIT=${WOLFSSL_GIT:-"https://github.com/wolfSSL/wolfssl.git"}
WOLFSSL_TAG=${WOLFSSL_TAG:-"v5.8.2-stable"}
WOLFSSL_SOURCE_DIR=${SCRIPT_DIR}/../wolfssl-source
WOLFSSL_INSTALL_DIR=${SCRIPT_DIR}/../wolfssl-install
WOLFSSL_ISFIPS=${WOLFSSL_ISFIPS:-0}
WOLFSSL_FIPS_CONFIG_OPTS=${WOLFSSL_CONFIG_OPTS:-'--enable-opensslcoexist '}
WOLFSSL_FIPS_CONFIG_CFLAGS=${WOLFSSL_CONFIG_CFLAGS:-"-I${OPENSSL_INSTALL_DIR}/include -DWOLFSSL_OLD_OID_SUM -DWOLFSSL_DH_EXTRA"}
WOLFSSL_CONFIG_OPTS=${WOLFSSL_CONFIG_OPTS:-'--enable-all-crypto --with-eccminsz=192 --with-max-ecc-bits=1024 --enable-opensslcoexist --enable-sha'}
WOLFSSL_CONFIG_CFLAGS=${WOLFSSL_CONFIG_CFLAGS:-"-I${OPENSSL_INSTALL_DIR}/include -DWC_RSA_NO_PADDING -DWOLFSSL_PUBLIC_MP -DHAVE_PUBLIC_FFDHE -DHAVE_FFDHE_6144 -DHAVE_FFDHE_8192 -DWOLFSSL_PSS_LONG_SALT -DWOLFSSL_PSS_SALT_LEN_DISCOVER -DRSA_MIN_SIZE=1024 -DWOLFSSL_OLD_OID_SUM "}

WOLFSSL_DEBUG_ASN_TEMPLATE=${DWOLFSSL_DEBUG_ASN_TEMPLATE:-0}
WOLFPROV_DISABLE_ERR_TRACE=${WOLFPROV_DISABLE_ERR_TRACE:-0}
WOLFPROV_DEBUG=${WOLFPROV_DEBUG:-0}
USE_CUR_TAG=${USE_CUR_TAG:-0}

clean_wolfssl() {
    printf "\n"

    if [ "$WOLFPROV_CLEAN" -eq "1" ]; then
        printf "Cleaning wolfSSL ...\n"
        if [ -f "${WOLFSSL_SOURCE_DIR}/Makefile" ]; then
            make -C "${WOLFSSL_SOURCE_DIR}" clean >>$LOG_FILE 2>&1
        fi
        rm -rf "${WOLFSSL_INSTALL_DIR}"
    fi
    if [ "$WOLFPROV_DISTCLEAN" -eq "1" ]; then
        printf "Removing wolfSSL source ...\n"
        rm -rf "${WOLFSSL_SOURCE_DIR}"
        printf "Removing wolfSSL install ...\n"
        rm -rf "${WOLFSSL_INSTALL_DIR}"
    fi
}

# Depends on OPENSSL_INSTALL_DIR
clone_wolfssl() {
    if [ -n "$WOLFSSL_FIPS_BUNDLE" ]; then
        rm -rf ${WOLFSSL_SOURCE_DIR}
        mkdir ${WOLFSSL_SOURCE_DIR}
        cp -pr ${WOLFSSL_FIPS_BUNDLE}/* ${WOLFSSL_SOURCE_DIR}/
    else
        if [ -d ${WOLFSSL_SOURCE_DIR} ] && [ "$USE_CUR_TAG" != "1" ]; then
            check_git_match "${WOLFSSL_TAG}" "${WOLFSSL_SOURCE_DIR}"
        fi

        if [ ! -d ${WOLFSSL_SOURCE_DIR} ]; then
            CLONE_TAG=${USE_CUR_TAG:+${WOLFSSL_TAG_CUR}}
            CLONE_TAG=${CLONE_TAG:-${WOLFSSL_TAG}}

            printf "\tClone wolfSSL ${CLONE_TAG} ... "

            DEPTH_ARG=${WOLFPROV_DEBUG:+""}
            DEPTH_ARG=${DEPTH_ARG:---depth=1}

            # If we are replacing default provider, our current built openssl still
            # links to the default stub and is non-functional. Run the clone with
            # no explicitly LD_LIBRARY_PATH to ensure use of global openssl for clone
            LD_LIBRARY_PATH="" git clone ${DEPTH_ARG} -b ${CLONE_TAG} ${WOLFSSL_GIT} ${WOLFSSL_SOURCE_DIR} >>$LOG_FILE 2>&1
            RET=$?

            if [ $RET != 0 ]; then
                printf "ERROR cloning\n"
                do_cleanup
                exit 1
            fi
            printf "Done.\n"
        else
            printf "\twolfSSL source directory exists: ${WOLFSSL_SOURCE_DIR}\n"
        fi
    fi
}

install_wolfssl() {
    # Check if libwolfssl and libwolfssl-dev packages are already installed
    # This is allowed only for wolfSSL, but not for OpenSSL because we want to
    # use the custom OpenSSL built with wolfProvider.
    if command -v dpkg >/dev/null 2>&1; then
        if dpkg -l | grep -q "^ii.*libwolfssl[[:space:]]" && dpkg -l | grep -q "^ii.*libwolfssl-dev[[:space:]]"; then
            # Check if there is a FIPS mismatch
            # If the system wolfSSL is FIPS, we need to be doing a FIPS build
            dpkg -l | grep "^ii.*libwolfssl[[:space:]]" | grep -q "fips"
            if [ $? -eq 0 ] && [ "$WOLFSSL_ISFIPS" != "1" ]; then
                printf "ERROR: System wolfSSL is FIPS, but WOLFSSL_ISFIPS is not set to 1\n"
                do_cleanup
                exit 1
            elif [ $? -eq 0 ] && [ "$WOLFSSL_ISFIPS" != "0" ]; then
                printf "ERROR: System wolfSSL is non-FIPS, but WOLFSSL_ISFIPS is set to 1\n"
                do_cleanup
                exit 1
            fi
            
            printf "\nSkipping wolfSSL installation - libwolfssl and libwolfssl-dev packages are already installed.\n"
            # Set WOLFSSL_INSTALL_DIR to system installation directory
            WOLFSSL_INSTALL_DIR="/usr"
            return 0
        fi
    fi

    printf "\nInstalling wolfSSL ${WOLFSSL_TAG} ...\n"
    clone_wolfssl
    cd ${WOLFSSL_SOURCE_DIR}

    if [ ! -d ${WOLFSSL_INSTALL_DIR} ]; then
        printf "\tConfigure wolfSSL ${WOLFSSL_TAG} ... "

        ./autogen.sh >>$LOG_FILE 2>&1
        CONF_ARGS="-prefix=${WOLFSSL_INSTALL_DIR}"

        if [ "$WOLFPROV_DEBUG" = "1" ]; then
            CONF_ARGS+=" --enable-debug --enable-keylog-export"
            if [[ "$OSTYPE" != "darwin"* ]] && [ "$WOLFPROV_DISABLE_ERR_TRACE" != "1" ]; then
                # macOS doesn't support backtrace
                CONF_ARGS+=" --enable-debug-trace-errcodes=backtrace"
            fi
            WOLFSSL_CONFIG_CFLAGS+=" -DWOLFSSL_LOGGINGENABLED_DEFAULT=1"
        fi
        if [ "$WOLFSSL_DEBUG_ASN_TEMPLATE" = "1" ] && ( [ "$WOLFSSL_ISFIPS" != "1" ] || [ -z "$WOLFSSL_FIPS_BUNDLE" ] ); then
            WOLFSSL_CONFIG_CFLAGS+=" -DWOLFSSL_DEBUG_ASN_TEMPLATE"
        elif [ "$WOLFSSL_DEBUG_ASN_TEMPLATE" = "1" ] && ( [ "$WOLFSSL_ISFIPS" = "1" ] || [ -n "$WOLFSSL_FIPS_BUNDLE" ] ); then
            WOLFSSL_FIPS_CONFIG_CFLAGS+=" -DWOLFSSL_DEBUG_ASN_TEMPLATE"
        fi
        if [ -n "$WOLFSSL_FIPS_BUNDLE" ]; then
            if [ ! -n "$WOLFSSL_FIPS_VERSION" ]; then
                printf "ERROR, must specify version if using FIPS bundle (v5, v6, ready)"
                do_cleanup
                exit 1
            fi
            printf "using FIPS bundle ... "
            CONF_ARGS+=" --enable-fips=$WOLFSSL_FIPS_VERSION"
            WOLFSSL_CONFIG_OPTS=$WOLFSSL_FIPS_CONFIG_OPTS
            WOLFSSL_CONFIG_CFLAGS=$WOLFSSL_FIPS_CONFIG_CFLAGS
        elif [ "$WOLFSSL_ISFIPS" = "1" ]; then
            printf "with FIPS ... "
            if [ -n "$WOLFSSL_FIPS_VERSION" ]; then
                CONF_ARGS+=" --enable-fips=$WOLFSSL_FIPS_VERSION"
            else
                CONF_ARGS+=" --enable-fips=v5"
            fi
            WOLFSSL_CONFIG_OPTS=$WOLFSSL_FIPS_CONFIG_OPTS
            WOLFSSL_CONFIG_CFLAGS=$WOLFSSL_FIPS_CONFIG_CFLAGS
            if [ ! -e "XXX-fips-test" ]; then
                # Sometimes the system OpenSSL is different than the one we're using. So for the 'git' commands, we'll just use whatever the system comes with
                if [ -n "$WOLFSSL_FIPS_CHECK_TAG" ]; then
                    LD_LIBRARY_PATH="" ./fips-check.sh "$WOLFSSL_FIPS_CHECK_TAG" keep nomakecheck >>$LOG_FILE 2>&1
                else
                    LD_LIBRARY_PATH="" ./fips-check.sh linuxv5.2.1 keep nomakecheck >>$LOG_FILE 2>&1
                fi
                if [ $? != 0 ]; then
                    printf "ERROR checking out FIPS\n"
                    rm -rf ${WOLFSSL_INSTALL_DIR}
                    do_cleanup
                    exit 1
                fi
                (cd XXX-fips-test && ./autogen.sh && ./configure ${CONF_ARGS} ${WOLFSSL_CONFIG_OPTS} CFLAGS="${WOLFSSL_CONFIG_CFLAGS}" && make && ./fips-hash.sh) >>$LOG_FILE 2>&1
                if [ $? != 0 ]; then
                    printf "ERROR compiling FIPS version of wolfSSL\n"
                    rm -rf ${WOLFSSL_INSTALL_DIR}
                    do_cleanup
                    exit 1
                fi
            fi
            cd XXX-fips-test
        fi

        ./configure ${CONF_ARGS} ${WOLFSSL_CONFIG_OPTS} CFLAGS="${WOLFSSL_CONFIG_CFLAGS}" >>$LOG_FILE 2>&1
        if [ $? != 0 ]; then
            printf "ERROR running ./configure\n"
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

        if [ -n "$WOLFSSL_FIPS_BUNDLE" ]; then
            ./fips-hash.sh
        fi

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

    if [ -z $LD_LIBRARY_PATH ]; then
      export LD_LIBRARY_PATH="$WOLFSSL_INSTALL_DIR/lib"
    else
      export LD_LIBRARY_PATH="$WOLFSSL_INSTALL_DIR/lib:$LD_LIBRARY_PATH"
    fi
}

