#!/bin/bash

do_cleanup() {
    echo "Cleanup"
}

do_trap() {
    printf "got trap\n"
    do_cleanup
    exit 1
}

#
# OpenSSL 3.0.0
#

download_openssl_300() {
    OPENSSL_3_0_0_GIT="git@github.com:openssl/openssl.git"
    printf "\tClone OpenSSSL 3.0.0 ... "
    git clone --depth=1 -b ${OPENSSL_3_0_0_TAG} ${OPENSSL_3_0_0_GIT} \
         ${OPENSSL_3_0_0_SOURCE} &> $LOGFILE
    printf "done.\n"
}

build_openssl_300() {
    printf "\tConfigure OpenSSSL 3.0.0 ... "
    ./config shared --prefix=${OPENSSL_3_0_0_INSTALL} &> $LOGFILE
    if [ $? != 0 ]; then
        printf "ERROR.\n"
        do_cleanup
        exit 1
    fi
    printf "Done.\n"

    printf "\tBuild OpenSSSL 3.0.0 ... "
    make -j$MAKE_JOBS &> $LOGFILE
    if [ $? != 0 ]; then
        printf "ERROR.\n"
        do_cleanup
        exit 1
    fi
    printf "Done.\n"
}

install_openssl_300() {
    printf "\tInstalling OpenSSSL 3.0.0 ... "
    make -j$MAKE_JOBS install &> $LOGFILE
    if [ $? != 0 ]; then
        printf "ERROR.\n"
        do_cleanup
        exit 1
    fi
    printf "Done.\n"
}

install_openssl() {
    if [ -z "${OPENSSL_3_0_0_INSTALL}" ]; then
        OPENSSL_3_0_0_TAG="openssl-3.0.0"
        OPENSSL_3_0_0_SOURCE=$PWD/openssl-3_0_0
        OPENSSL_3_0_0_INSTALL=$PWD/openssl-3_0_0-install
        export LD_LIBRARY_PATH="$LD_LIBRARY_PATH:$OPENSSL_3_0_0_INSTALL/lib64"

        if [ ! -d ${OPENSSL_3_0_0_SOURCE} ]; then
            download_openssl_300
            cd ${OPENSSL_3_0_0_SOURCE}
            build_openssl_300
            cd ..
            rm -rf ${OPENSSL_3_0_0_INSTALL}
        fi
        if [ ! -d ${OPENSSL_3_0_0_INSTALL} ]; then
            cd ${OPENSSL_3_0_0_SOURCE}
            install_openssl_300
            cd ..
        else
            printf "\tOpenSSL 3.0.0 install exists.\n"
        fi
    else
        printf "\tOpenSSL 3.0.0 install from: ${OPENSSL_3_0_0_INSTALL}\n"
    fi
}

#
# evp_test
#

# Test files copies into scripts/evp_test as they had to be modified to comment
# out unsupported algorithms.

# Other files not copied:
#   evpciph_aes_cts.txt - CTS not supported
#   evpciph_aes_ocb.txt - OCB not supported
#   evpciph_aes_siv.txt - SIV not supported
#   evpciph_aes_stitched.txt - AES-HMAC not supported
#   evpciph_aria.txt - ARIA not supported
#   evpciph_bf.txt - BlowFish not supported
#   evpciph_camellia_cts.txt - Camellia not supported
#   evpciph_camellia.txt - Camellia not supported
#   evpciph_cast5.txt - CAST5 not supported
#   evpciph_chacha.txt - CHACHA20 not supported
#   evpciph_des3_common.txt - DES3 not supported
#   evpciph_des.txt - DES not supported
#   evpciph_idea.txt - IDEA not supported
#   evpciph_rc2.txt - RC2 not supported
#   evpciph_rc4_stitched.txt - RC4 not supported
#   evpciph_rc4.txt - RC4 not supported
#   evpciph_rc5.txt - RC5 not supported
#   evpciph_seed.txt - SEED not supported
#   evpciph_sm4.txt - SM4 not supported
#   evpkdf_krb5.txt - Kerberos not supported
#   evpkdf_krb5.txt - Kerberos KDFs not supported
#   evpkdf_pbkdf1.txt - uses legacy provider
#   evpkdf_scrypt.txt - SCRYPT not supported
#   evpkdf_ssh.txt - SSH KDF not supported
#   evpkdf_ss.txt - SSKDF not supported
#   evpkdf_x942_des.txt - DES not supported
#   evpkdf_x963.txt - X963 key generation not supported
#   evpmac_blake.txt - BLAKE not supported
#   evpmac_cmac_des.txt - DES not supported
#   evpmac_poly1305.txt - Poly1305 not supported
#   evpmac_siphash.txt - SipHash not supported
#   evpmd_blake.txt - BLAKE not supported
#   evpmd_mdc2.txt - MDC2 not supported
#   evpmd_ripemd.txt - RIPEMD not supported
#   evpmd_sm3.txt - SM3 not supported
#   evpmd_whirlpool.txt - Whirlpool not supported
#   evppbe_scrypt.txt - SCRYPT not supported
#   evppkey_brainpool.txt - Brainpool curves not supported
#   evppkey_dsa.txt - DSA not supported
#   evppkey_kdf_scrypt.txt - SCRYPT not supported
#   evppkey_sm2.txt - SM2 not supported
#   evprand.txt - random is HashDRBG and internals not accessible.

evp_test_run() {
    printf "\tTesting with evp_test:\n"
    EVP_TESTS=(
        evpciph_aes_ccm_cavs.txt
        evpciph_aes_common.txt
        evpciph_aes_wrap.txt
        evpencod.txt
        evpkdf_hkdf.txt
        evpkdf_pbkdf2.txt
        evpkdf_tls11_prf.txt
        evpkdf_tls12_prf.txt
        evpkdf_tls13_kdf.txt
        evpmac_common.txt
        evpmd_md.txt
        evpmd_sha.txt
        evppbe_pbkdf2.txt
        evppbe_pkcs12.txt
        evppkey_dh.txt
        evppkey_ecc.txt
        evppkey_ecdh.txt
        evppkey_ecdsa.txt
        evppkey_ecx.txt
        evppkey_ffdhe.txt
        evppkey_kas.txt
        evppkey_kdf_hkdf.txt
        evppkey_kdf_tls1_prf.txt
        evppkey_mismatch.txt
        evppkey_rsa_common.txt
        evppkey_rsa.txt
    )

    FAIL_CNT=0
    for T in ${EVP_TESTS[@]}
    do
        printf "\t\t$T ... "
        ./evp_test -config $WOLFPROV_CONFIG \
            $WOLFPROV_DIR/scripts/evp_test/$T \
            >$LOGDIR/$T.log 2>&1 
        if [ "$?" = "0" ]; then
            echo "PASS"
        else
            echo "ERROR"
            FAIL_CNT=$((FAIL_CNT+1))
        fi
    done
    if [ $FAIL_CNT != 0 ]; then
        printf "\tFAILED=${FAIL_CNT}\n"
        # Exit code must now indicate failure.
        EC=1
    fi
}

#
# endecode_test
#

endecode_test_parse_result() {
    OLD_IFS=$IFS
    IFS=$'\n'
    for R in $RES
    do
        case $R in
        *skipped*)
            ;;
        "not ok "*)
            RES_FAIL=`printf "$RES_FAIL\n$R"`
            ;;
        "ok "*)
            RES_SUCCESS=`printf "$RES_SUCCESS\n$R"`
            ;;
        esac
    done

    FAIL_CNT=0
    for R in $RES_FAIL
    do
        case $R in
        *DSA*|*DHX*|*ECExplicit*|*RSA_PSS*|*MSBLOB*|*PVK*)
            ;;
        *)
            echo "ERROR: Unexpected failure"
            echo $R
            FAIL_CNT=$((FAIL_CNT+1))
            ;;
        esac
    done
    for R in $RES_SUCCESS
    do
        case $R in
        *DSA*|*DHX*|*ECExplicit*|*RSA_PSS*|*MSBLOB*|*PVK*)
            echo "ERROR: Unexpected success"
            echo $R
            FAIL_CNT=$((FAIL_CNT+1))
            ;;
        *)
            ;;
        esac
    done
    IFS=$OLD_IFS

    if [ $FAIL_CNT != 0 ]; then
        printf "\t\tFAILED=${FAIL_CNT}\n"
        # Exit code must now indicate failure.
        EC=1
    else
        printf "\t\tPASS\n"
    fi
}

endecode_test_run() {
    printf "\tTesting with evp_test:\n"

    RES=`./endecode_test \
        -rsa certs/ee-key.pem -pss certs/ca-pss-key.pem -context \
        -provider libwolfprov 2>&1 | grep 'ok [1-9]'`
    endecode_test_parse_result
}

#
# evp_libctx_test
#

evp_libctx_test_run() {
    printf "\tTesting with evp_libctx_test:\n"

    RES=`./evp_libctx_test -provider libwolfprov 2>&1`

    FAIL_CNT=0
    IGNORE_NEXT_ERROR="no"
    IGNORE_GROUP_ERROR="no"

    OLD_IFS=$IFS
    IFS=$'\n'
    for L in $RES
    do
        case $L in
        *DSA*|*DES*)
            IGNORE_NEXT_ERROR="yes"
            ;;
        "    not ok "*)
            if [ "$IGNORE_NEXT_ERROR" == "yes" ]; then
                IGNORE_GROUP_ERROR="yes"
                IGNORE_NEXT_ERROR="no"
            else
                echo "ERROR: Unexpected failure (case)"
                echo $L
                FAIL_CNT=$((FAIL_CNT+1))
            fi
            ;;
        "not ok "*)
            if [ "$IGNORE_NEXT_ERROR" == "yes" ]; then
                IGNORE_NEXT_ERROR="no"
            elif [ "$IGNORE_GROUP_ERROR" == "yes" ]; then
                IGNORE_GROUP_ERROR="no"
            else
                echo "ERROR: Unexpected failure (group)"
                echo $L
                FAIL_CNT=$((FAIL_CNT+1))
            fi
            ;;
        "    ok "*)
            IGNORE_NEXT_ERROR="no"
            ;;
        "ok "*)
            IGNORE_GROUP_ERROR="no"
            ;;
        esac
    done
    IFS=$OLD_IFS

    if [ $FAIL_CNT != 0 ]; then
        printf "\t\tFAILED=${FAIL_CNT}\n"
        # Exit code must now indicate failure.
        EC=1
    else
        printf "\t\tPASS\n"
    fi
}

#
# Start
#

WOLFPROV_DIR=$PWD
WOLFPROV_CONFIG=$WOLFPROV_DIR/provider.conf
WOLFPROV_PATH=$WOLFPROV_DIR/.libs
LOGDIR=$WOLFPROV_DIR/scripts/log
LOGFILE=$LOGDIR/openssl_test.log
export OPENSSL_MODULES=$WOLFPROV_PATH

if [ ! -d "$LOGDIR" ]; then
    mkdir $LOGDIR
fi

if [ "$MAKE_JOBS" = "" ]; then
    MAKE_JOBS=4
fi

echo "START OpenSSL 3.0.0 install"
if [ "$OPENSSL_SRC" = "" ]; then
    install_openssl
    OPENSSL_TEST=./openssl-3_0_0/test
else
    OPENSSL_TEST=$OPENSSL_SRC/test
fi
if [ ! -d $OPENSSL_TEST ]; then
    echo "OpenSSL source not available: $OPENSSL_TEST"
    exit 1
fi

if [ "$OPENSSL_DIR" = "" ]; then
    OPENSSL_DIR=${OPENSSL_3_0_0_INSTALL}
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
echo "FINISH OpenSSL 3.0.0 install"
echo

# Start with returning success
EC=0
cd $OPENSSL_TEST

echo "START Testing with OpenSSL tests"
evp_test_run
endecode_test_run
evp_libctx_test_run
echo "FINISHED Testing with OpenSSL tests"

exit $EC

