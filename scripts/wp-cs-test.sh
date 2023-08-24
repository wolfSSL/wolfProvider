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

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
CERT_DIR=$SCRIPT_DIR/../certs
LOG_FILE=$SCRIPT_DIR/wp-cs-test.log

OPENSSL_SERVER_PID=-1

set -o pipefail # pass failures up the pipe
prepend() { # Usage: cmd 2>&1 | prepend "sometext "
    while read line; do echo "${1}${line}"; done
}

kill_servers() {
    if [ $(check_process_running $OPENSSL_SERVER_PID) = "0" ]; then
        (kill -9 $OPENSSL_SERVER_PID) >/dev/null 2>&1
    fi
}

do_cleanup() {
    sleep 0.5 # flush buffers
    kill_servers
}

do_trap() {
    printf "got trap\n"
    do_cleanup
    date
    exit 1
}

trap do_trap INT TERM

TLS13_ALL_CIPHERS="TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256:TLS_AES_128_CCM_SHA256:TLS_AES_128_CCM_8_SHA256"

TLS13_CIPHERS=(
    TLS_AES_256_GCM_SHA384
    TLS_AES_128_GCM_SHA256
    TLS_AES_128_CCM_SHA256
    TLS_AES_128_CCM_8_SHA256
)
TLS12_CIPHERS=(
    ECDHE-ECDSA-AES256-GCM-SHA384
    ECDHE-RSA-AES256-GCM-SHA384
    DHE-RSA-AES256-GCM-SHA384
    ECDHE-ECDSA-AES128-GCM-SHA256
    ECDHE-RSA-AES128-GCM-SHA256
    DHE-RSA-AES128-GCM-SHA256
    ECDHE-ECDSA-AES256-CCM8
    ECDHE-ECDSA-AES256-CCM
    DHE-RSA-AES256-CCM8
    DHE-RSA-AES256-CCM
    ECDHE-ECDSA-AES128-CCM8
    ECDHE-ECDSA-AES128-CCM
    DHE-RSA-AES128-CCM8
    DHE-RSA-AES128-CCM
    ECDHE-ECDSA-AES256-SHA384
    ECDHE-RSA-AES256-SHA384
    DHE-RSA-AES256-SHA256
    ECDHE-ECDSA-AES128-SHA256
    ECDHE-RSA-AES128-SHA256
    DHE-RSA-AES128-SHA256
    ECDHE-ECDSA-AES256-SHA
    ECDHE-RSA-AES256-SHA
    DHE-RSA-AES256-SHA
    ECDHE-ECDSA-AES128-SHA
    ECDHE-RSA-AES128-SHA
    DHE-RSA-AES128-SHA
    AES256-GCM-SHA384
    AES128-GCM-SHA256
    AES256-CCM8
    AES256-CCM
    AES128-CCM8
    AES128-CCM
    AES256-SHA256
    AES128-SHA256
    AES256-SHA
    AES128-SHA
)
TLS1_CIPHERS=(
    ECDHE-RSA-AES256-SHA
    ECDHE-ECDSA-AES256-SHA
    DHE-RSA-AES256-SHA
    AES256-SHA
    ECDHE-RSA-AES128-SHA
    ECDHE-ECDSA-AES128-SHA
    DHE-RSA-AES128-SHA
    AES128-SHA
)
TLS1_STATIC_CIPHERS=(
    DH-RSA-AES256-SHA
    ECDH-RSA-AES256-SHA
    ECDH-ECDSA-AES256-SHA
    DH-RSA-AES128-SHA
    ECDH-RSA-AES128-SHA
    ECDH-ECDSA-AES128-SHA
    EDH-RSA-DES-CBC3-SHA
    DH-RSA-DES-CBC3-SHA
    ECDH-RSA-DES-CBC3-SHA
    ECDH-ECDSA-DES-CBC3-SHA
)
TLS1_DSS_CIPHERS=(
    DHE-DSS-AES256-SHA
    DH-DSS-AES256-SHA
    DHE-DSS-AES128-SHA
    DH-DSS-AES128-SHA
    EDH-DSS-DES-CBC3-SHA
    DH-DSS-DES-CBC3-SHA
)
TLS1_PSK_CIPHERS=(
    PSK-AES256-CBC-SHA
    PSK-AES128-CBC-SHA
    PSK-3DES-EDE-CBC-SHA
)

check_process_running() {
    ps -p $1 > /dev/null
    echo $?
}

# need a unique port since may run the same time as testsuite
generate_port() {
    echo $(($(od -An -N2 /dev/random) % (65535-49512) + 49512))
}

start_openssl_server() { # usage: start_openssl_server [extraArgs]
    stdbuf -oL -eL $OPENSSL_BIN s_server -www $1 \
         -cert $CERT_DIR/server-cert.pem -key $CERT_DIR/server-key.pem \
         -dcert $CERT_DIR/server-ecc.pem -dkey $CERT_DIR/ecc-key.pem \
         -accept $OPENSSL_PORT $OPENSSL_ALL_CIPHERS \
         2>&1 | prepend "[server] " >>$LOG_FILE &
    OPENSSL_SERVER_PID=$(($! - 1))

    sleep 0.1

    if [ $(check_process_running $OPENSSL_SERVER_PID) != "0" ]; then
        printf "OpenSSL server failed to start\n"
        do_cleanup
        exit 1
    fi
}

do_client() { # usage: do_client [extraArgs]
    printf "\t\t$CIPHER ... "
    printf "\n$CIPHER ...\n" >>$LOG_FILE
    if [ "$TLS_VERSION" != "-tls1_3" ]; then
        (echo -n | \
         stdbuf -oL -eL $OPENSSL_BIN s_client $1 \
             -cipher $CIPHER $TLS_VERSION \
             -connect localhost:$OPENSSL_PORT \
             -curves $CURVES \
             2>&1 | prepend "[client] " >>$LOG_FILE
        )
    else
        (echo -n | \
         stdbuf -oL -eL $OPENSSL_BIN s_client $1 \
             -ciphersuites $CIPHER $TLS_VERSION \
             -connect localhost:$OPENSSL_PORT \
             -curves $CURVES \
             2>&1 | prepend "[client] " >>$LOG_FILE
        )
    fi
    if [ "$?" = "0" ]; then
        printf "pass\n" | tee -a $LOG_FILE
    else
        printf "fail\n" | tee -a $LOG_FILE
        FAIL=$((FAIL+1))
    fi
}

do_client_test() { # usage: do_client_test [extraArgs]
#    TLS_VERSION=-tls1
#    printf "\t$TLS_VERSION\n" | tee -a $LOG_FILE
#    for CIPHER in ${TLS1_CIPHERS[@]}; do
#        do_client "$1"
#    done
#
#    TLS_VERSION=-tls1_1
#    printf "\t$TLS_VERSION\n" | tee -a $LOG_FILE
#    for CIPHER in ${TLS1_CIPHERS[@]}; do
#        do_client "$1"
#    done

    TLS_VERSION=-tls1_2
    printf "\t$TLS_VERSION\n" | tee -a $LOG_FILE
    for CIPHER in ${TLS12_CIPHERS[@]}; do
        do_client "$1"
    done

    TLS_VERSION=-tls1_3
    printf "\t$TLS_VERSION\n" | tee -a $LOG_FILE
    for CIPHER in ${TLS13_CIPHERS[@]}; do
        do_client "$1"
    done
}

if [ "$OPENSSL_DIR" = "" ]; then
    if [ -x "/usr/bin/openssl" ]; then
        OPENSSL_DIR="/usr"
    elif [ -x "/ur/local/bin/openssl" ]; then
        OPENSSL_DIR="/usr/local"
    else
        echo "Can't find OpenSSL 3.0.0"
        exit 1
    fi
else
    export LD_LIBRARY_PATH="$LD_LIBRARY_PATH:$OPENSSL_DIR/lib"
fi
OPENSSL_BIN="$OPENSSL_DIR/bin/openssl"

OSSL_VER=`$OPENSSL_BIN version`
case $OSSL_VER in
    OpenSSL\ 3.*) ;;
    *)
      echo "OpenSSL ($OPENSSL_BIN) has wrong version: $OSSL_VER"
      echo "Set: OPENSSL_DIR"
      exit 1
      ;;
esac

FAIL=0
WOLFPROV_NAME="libwolfprov"
WOLFPROV_PATH=$PWD/.libs

CURVES=prime256v1
#CURVES=X25519
OPENSSL_ALL_CIPHERS="-cipher ALL -ciphersuites $TLS13_ALL_CIPHERS"
OPENSSL_PORT=$(generate_port)

printf "\tClient testing\n" | tee $LOG_FILE
start_openssl_server
do_client_test "-provider-path $WOLFPROV_PATH -provider $WOLFPROV_NAME"
kill_servers

printf "\tServer testing\n" | tee -a $LOG_FILE
start_openssl_server "-provider-path $WOLFPROV_PATH -provider $WOLFPROV_NAME"
do_client_test
kill_servers

do_cleanup

if [ "$FAIL" = "0" ]; then
    printf "All tests passed.\n"
else
    printf "$FAIL tests failed.\n"
    exit 1
fi

