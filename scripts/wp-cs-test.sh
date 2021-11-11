#!/bin/bash

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
CERT_DIR=$SCRIPT_DIR/../certs
LOG_FILE=$SCRIPT_DIR/wp-cs-test.log
LOG_SERVER=$SCRIPT_DIR/wp-cs-test-server.log
LOG_WP_SERVER=$SCRIPT_DIR/wp-cs-test-wp-server.log
LOG_CLIENT=$SCRIPT_DIR/wp-cs-test-client.log
TMP_LOG=$SCRIPT_DIR/wp-cs-test-tmp.log

OPENSSL_SERVER_PID=-1
WP_OPENSSL_SERVER_PID=-1

kill_servers() {
    SERVER_PID=$OPENSSL_SERVER_PID
    check_process_running
    if [ "$PS_EXIT" = "0" ]; then
        (kill -INT $SERVER_PID) >/dev/null 2>&1
    fi

    SERVER_PID=$WP_OPENSSL_SERVER_PID
    check_process_running
    if [ "$PS_EXIT" = "0" ]; then
        (kill -INT $SERVER_PID) >/dev/null 2>&1
    fi
}

do_cleanup() {
    kill_servers

    rm -f $TMP_LOG
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
    ps -p $SERVER_PID > /dev/null
    PS_EXIT=$?
}

# need a unique port since may run the same time as testsuite
generate_port() {
    port=$(($(od -An -N2 /dev/random) % (65535-49512) + 49512))
}

start_openssl_server() {
    generate_port
    export OPENSSL_PORT=$port

    ($OPENSSL_BIN s_server -www \
         -cert $CERT_DIR/server-cert.pem -key $CERT_DIR/server-key.pem \
         -dcert $CERT_DIR/server-ecc.pem -dkey $CERT_DIR/ecc-key.pem \
         -accept $OPENSSL_PORT $OPENSSL_ALL_CIPHERS \
         >$LOG_SERVER 2>&1
    ) &
    OPENSSL_SERVER_PID=$!

    sleep 0.1

    SERVER_PID=$OPENSSL_SERVER_PID
    check_process_running
    if [ "$PS_EXIT" != "0" ]; then
        printf "OpenSSL server failed to start\n"
        do_cleanup
        exit 1
    fi
}

start_wp_openssl_server() {
    generate_port
    export WP_OPENSSL_PORT=$port

    ($OPENSSL_BIN s_server -www \
         -provider-path $WOLFPROV_PATH -provider $WOLFPROV_NAME \
         -cert $CERT_DIR/server-cert.pem -key $CERT_DIR/server-key.pem \
         -dcert $CERT_DIR/server-ecc.pem -dkey $CERT_DIR/ecc-key.pem \
         -accept $WP_OPENSSL_PORT $OPENSSL_ALL_CIPHERS \
         >$LOG_WP_SERVER 2>&1
    ) &
    WP_OPENSSL_SERVER_PID=$!

    sleep 0.1

    SERVER_PID=$WP_OPENSSL_SERVER_PID
    check_process_running
    if [ "$PS_EXIT" != "0" ]; then
        printf "server failed to start\n"
        printf "OpenSSL server using wolfProvider failed to start\n"
        do_cleanup
        exit 1
    fi
}
start_openssl_server() {
    generate_port
    export OPENSSL_PORT=$port

    ($OPENSSL_BIN s_server -www \
         -cert $CERT_DIR/server-cert.pem -key $CERT_DIR/server-key.pem \
         -dcert $CERT_DIR/server-ecc.pem -dkey $CERT_DIR/ecc-key.pem \
         -accept $OPENSSL_PORT $OPENSSL_ALL_CIPHERS \
         >$LOG_SERVER 2>&1
    ) &
    OPENSSL_SERVER_PID=$!

    sleep 0.1

    SERVER_PID=$OPENSSL_SERVER_PID
    check_process_running
    if [ "$PS_EXIT" != "0" ]; then
        printf "OpenSSL server failed to start\n"
        do_cleanup
        exit 1
    fi
}

start_wp_openssl_server() {
    generate_port
    export WP_OPENSSL_PORT=$port

    ($OPENSSL_BIN s_server -www \
         -provider-path $WOLFPROV_PATH -provider $WOLFPROV_NAME \
         -cert $CERT_DIR/server-cert.pem -key $CERT_DIR/server-key.pem \
         -dcert $CERT_DIR/server-ecc.pem -dkey $CERT_DIR/ecc-key.pem \
         -accept $WP_OPENSSL_PORT $OPENSSL_ALL_CIPHERS \
         >$LOG_WP_SERVER 2>&1
    ) &
    WP_OPENSSL_SERVER_PID=$!

    sleep 0.1

    SERVER_PID=$WP_OPENSSL_SERVER_PID
    check_process_running
    if [ "$PS_EXIT" != "0" ]; then
        printf "server failed to start\n"
        printf "OpenSSL server using wolfProvider failed to start\n"
        do_cleanup
        exit 1
    fi
}

do_wp_client() {
    printf "\t\t$CIPHER ... "
    if [ "$TLS_VERSION" != "-tls1_3" ]; then
        (echo -n | \
         $OPENSSL_BIN s_client \
             -provider-path $WOLFPROV_PATH \
             -provider $WOLFPROV_NAME \
             -cipher $CIPHER $TLS_VERSION \
             -curves $CURVES \
             -connect localhost:$OPENSSL_PORT \
             >$TMP_LOG 2>&1
        )
    else
        (echo -n | \
         $OPENSSL_BIN s_client \
             -provider-path $WOLFPROV_PATH \
             -provider $WOLFPROV_NAME \
             -ciphersuites $CIPHER $TLS_VERSION \
             -curves $CURVES \
             -connect localhost:$OPENSSL_PORT \
             >$TMP_LOG 2>&1
        )
    fi
    if [ "$?" = "0" ]; then
        printf "pass\n"
    else
        printf "fail\n"
        FAIL=$((FAIL+1))
    fi

    #check_log

    cat $TMP_LOG >>$LOG_CLIENT
}

do_client() {
    printf "\t\t$CIPHER ... "
    if [ "$TLS_VERSION" != "-tls1_3" ]; then
        (echo -n | \
         $OPENSSL_BIN s_client \
             -cipher $CIPHER $TLS_VERSION \
             -connect localhost:$WP_OPENSSL_PORT \
             -curves $CURVES \
             >>$LOG_CLIENT 2>&1
        )
    else
        (echo -n | \
         $OPENSSL_BIN s_client \
             -ciphersuites $CIPHER $TLS_VERSION \
             -connect localhost:$WP_OPENSSL_PORT \
             -curves $CURVES \
             >>$LOG_CLIENT 2>&1
        )
    fi
    if [ "$?" = "0" ]; then
        printf "pass\n"
    else
        printf "fail\n"
        FAIL=$((FAIL+1))
    fi

    NEW_LINES=`wc -l $LOG_WP_SERVER | awk '{print $1}'`
    tail --lines=$((NEW_LINES-LOG_LINES)) $LOG_WP_SERVER >$TMP_LOG

    #check_log

    LOG_LINES=$NEW_LINES
}

do_wp_client_test() {
    printf "\tClient testing\n"
    CHECK_CLIENT=1
    CHECK_SERVER=

    TLS_VERSION=-tls1
    printf "\t$TLS_VERSION\n"
    for CIPHER in ${TLS1_CIPHERS[@]}
    do
        do_wp_client
    done

    TLS_VERSION=-tls1_1
    printf "\t$TLS_VERSION\n"
    for CIPHER in ${TLS1_CIPHERS[@]}
    do
        do_wp_client
    done

    TLS_VERSION=-tls1_2
    printf "\t$TLS_VERSION\n"
    for CIPHER in ${TLS12_CIPHERS[@]}
    do
        do_wp_client
    done

    TLS_VERSION=-tls1_3
    printf "\t$TLS_VERSION\n"
    for CIPHER in ${TLS13_CIPHERS[@]}
    do
        do_wp_client
    done
}
do_wp_client_test() {
    printf "\tClient testing\n"
    CHECK_CLIENT=1
    CHECK_SERVER=

    #TLS_VERSION=-tls1
    #printf "\t$TLS_VERSION\n"
    #for CIPHER in ${TLS1_CIPHERS[@]}
    #do
    #    do_wp_client
    #done

    #TLS_VERSION=-tls1_1
    #printf "\t$TLS_VERSION\n"
    #for CIPHER in ${TLS1_CIPHERS[@]}
    #do
    #    do_wp_client
    #done

    TLS_VERSION=-tls1_2
    printf "\t$TLS_VERSION\n"
    for CIPHER in ${TLS12_CIPHERS[@]}
    do
        do_wp_client
    done

    TLS_VERSION=-tls1_3
    printf "\t$TLS_VERSION\n"
    for CIPHER in ${TLS13_CIPHERS[@]}
    do
        do_wp_client
    done
}

do_client_test() {
    printf "\tServer testing\n"
    CHECK_CLIENT=
    CHECK_SERVER=1
    LOG_LINES=0

    #TLS_VERSION=-tls1
    #printf "\t$TLS_VERSION\n"
    #for CIPHER in ${TLS1_CIPHERS[@]}
    #do
    #    do_client
    #done

    #TLS_VERSION=-tls1_1
    #printf "\t$TLS_VERSION\n"
    #for CIPHER in ${TLS1_CIPHERS[@]}
    #do
    #    do_client
    #done

    TLS_VERSION=-tls1_2
    printf "\t$TLS_VERSION\n"
    for CIPHER in ${TLS12_CIPHERS[@]}
    do
        do_client
    done

    TLS_VERSION=-tls1_3
    printf "\t$TLS_VERSION\n"
    for CIPHER in ${TLS13_CIPHERS[@]}
    do
        do_client
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

rm -f $LOG_CLIENT

CURVES=prime256v1
#CURVES=X25519
OPENSSL_ALL_CIPHERS="-cipher ALL -ciphersuites $TLS13_ALL_CIPHERS"
start_openssl_server
do_wp_client_test
start_wp_openssl_server
do_client_test
kill_servers
do_cleanup

if [ "$FAIL" = "0" ]; then
    printf "All tests passed.\n"
else
    printf "$FAIL tests failed.\n"
    exit 1
fi

