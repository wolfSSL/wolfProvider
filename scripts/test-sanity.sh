#!/bin/bash
# This script provides simple sanity checks to make sure the provider is working

SET_PRE=$( set )
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
LOG_FILE=${SCRIPT_DIR}/test-sanity.log
rm -f ${LOG_FILE}
source ${SCRIPT_DIR}/utils-wolfprovider.sh

echo "Using openssl: $OPENSSL_TAG, wolfssl: $WOLFSSL_TAG"

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
