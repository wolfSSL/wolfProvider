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

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
NUMCPU=${NUMCPU:-8}
WOLFPROV_DEBUG=${WOLFPROV_DEBUG:-0}
source ${SCRIPT_DIR}/utils-wolfprovider.sh

if [ "${WOLFSSL_ISFIPS}" = "1" ]; then
    echo "FIPS mode enabled for openssl tests"
fi

do_cleanup() {
    echo "Cleanup"
}

do_trap() {
    printf "got trap\n"
    do_cleanup
    exit 1
}

trap do_trap INT TERM

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
#   evppkey_rsa_common.txt
#   evppkey_rsa.txt

evp_test_run() {
    printf "\tTesting with evp_test:\n"
    
    # FIPS-approved evp tests - exclude non-FIPS algorithms in FIPS mode
    if [ "${WOLFSSL_ISFIPS}" = "1" ]; then
        echo "FIPS mode enabled - using FIPS-approved evp tests only"
        EVP_TESTS=(
            evpciph_aes_ccm_cavs.txt
            evpciph_aes_common.txt
            evpkdf_hkdf.txt
            evpkdf_pbkdf2.txt
            evpkdf_tls12_prf.txt
            evpkdf_tls13_kdf.txt
            evpmac_common.txt
            evpmd_sha.txt
            evppbe_pbkdf2.txt
            evppkey_ecc.txt
            evppkey_ecdh.txt
            evppkey_ecdsa.txt
            evppkey_ffdhe.txt
            evppkey_kas.txt
            evppkey_kdf_hkdf.txt
            evppkey_kdf_tls1_prf.txt
        )
    else
        echo "Normal mode - using all evp tests"
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
        )
    fi

    for T in ${EVP_TESTS[@]}
    do
        printf "\t\t$T ... "
        ./evp_test -config $WOLFPROV_CONFIG \
            $WOLFPROV_SOURCE_DIR/scripts/evp_test/$T \
            >$LOGDIR/$T.log 2>&1 
        if [ "$?" = "0" ]; then
            echo "PASS"
        else
            echo "ERROR"
            FAIL_CNT=$((FAIL_CNT+1))
        fi
    done
}

#
# endecode_test
#

endecode_test_run() {
    printf "\tTesting with endecode_test:\n"

    RES=`./endecode_test \
        -rsa certs/ee-key.pem -pss certs/ca-pss-key.pem -context \
        -provider libwolfprov 2>&1 | tee -a $LOGDIR/endecode_test.log | grep 'ok [1-9]'`
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
}

#
# evp_libctx_test
#

evp_libctx_test_run() {
    printf "\tTesting with evp_libctx_test:\n"

    RES=`./evp_libctx_test -provider libwolfprov 2>&1`

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
}

#
# Start
#

LOGDIR=$WOLFPROV_SOURCE_DIR/scripts/log
LOG_FILE=$LOGDIR/test-openssl.log

if [ ! -d "$LOGDIR" ]; then
    mkdir $LOGDIR
fi

# Fresh start
rm -f $LOG_FILE

if [ -z $NUMCPU ]; then
    if [[ "$OSTYPE" == "linux-gnu" ]]; then
      export NUMCPU=`grep -c ^processor /proc/cpuinfo`
    elif [[ "$OSTYPE" == "darwin"* ]]; then
      export NUMCPU=`sysctl -n hw.ncpu`
    else
      export NUMCPU=4
    fi
fi

init_wolfprov

# Start with returning success
FAIL_CNT=0
cd $OPENSSL_TEST

printf "START Testing with OpenSSL tests\n"
evp_test_run
endecode_test_run
evp_libctx_test_run
printf "FINISHED Testing with OpenSSL tests\n"

if [ $FAIL_CNT != 0 ]; then
    printf "Number of tests failed: $FAIL_CNT\n"
else
    printf "All tests passed!\n"
fi

printf "Script ran for $SECONDS seconds\n"
exit $FAIL_CNT

