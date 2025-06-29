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
# This script provides simple sanity checks to make sure the provider is working
# You can set WOLFPROV_FIPS=1 to run the tests in FIPS mode. You can also set 
# env variables before running to build with like WOLFSSL_TAG and OPENSSL_TAG etc. 

SET_PRE=$( set )
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
LOG_FILE=${SCRIPT_DIR}/test-sanity.log
rm -f ${LOG_FILE}
WOLFPROV_FIPS=${WOLFPROV_FIPS:-0}
source ${SCRIPT_DIR}/utils-wolfprovider.sh

echo "Using openssl: $OPENSSL_TAG, wolfssl: $WOLFSSL_TAG"

# Set WOLFSSL_ISFIPS if FIPS mode is requested
if [ "$WOLFPROV_FIPS" = "1" ]; then
    export WOLFSSL_ISFIPS=1
    echo "FIPS mode requested - setting WOLFSSL_ISFIPS=1 for FIPS build"
fi

function doTestCmd() {
    CMD=$*
    echo ">>>>>> Running $CMD"
    eval $CMD
    RET=$?
    if [ $RET -ne 0 ]; then
        echo "Failed $CMD: $RET"
        exit 1
    fi
    echo "<<<<<<"
}

function runSpotCheck() {
    doTestCmd init_wolfprov

    SET_POST=$( set )
    echo "New variables set:"
    diff <(echo "$SET_PRE") <(echo "$SET_POST") | grep "="

    doTestCmd "${OPENSSL_INSTALL_DIR}/bin/openssl list -providers --verbose | grep 'Providers:' -A 10"

    if [ $(${OPENSSL_INSTALL_DIR}/bin/openssl list -providers --verbose | grep libwolfprov | wc -l) = 0 ]; then
        echo "Not using wolfProvider for some reason"
        exit 2
    fi

    if [ $(${OPENSSL_INSTALL_DIR}/bin/openssl list -providers --verbose | grep OpenSSL | wc -l) -ne 0 ]; then
        echo "OpenSSL provider is also enabled"
        exit 2
    fi

    case `uname` in
        Darwin)
            doTestCmd "security find-certificate -a -p /System/Library/Keychains/SystemRootCertificates.keychain > ${SCRIPT_DIR}/allCA.pem"
            CA_ARGS="-CAfile ${SCRIPT_DIR}/allCA.pem"
            ;;
        *) CA_ARGS="-CApath /etc/ssl/certs" ;;
    esac

    doTestCmd "${OPENSSL_INSTALL_DIR}/bin/openssl s_client ${CA_ARGS} -connect github.com:443 </dev/null"
    doTestCmd "${OPENSSL_INSTALL_DIR}/bin/openssl s_client ${CA_ARGS} -connect tls.support:443 </dev/null"
}

runSpotCheck

exit $?
