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

# Execute this script from: wolfProvider
#set -e

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
source "${SCRIPT_DIR}"/utils-openssl.sh
source "${SCRIPT_DIR}"/utils-wolfssl.sh

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

    for T in ${EVP_TESTS[@]}
    do
        printf "\t\t$T ... "
        ./evp_test -config "$WOLFPROV_CONFIG" \
            "$WOLFPROV_DIR"/scripts/evp_test/"$T" \
            >"$LOGDIR"/"$T".log 2>&1 
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
    printf "\tTesting with evp_test:\n"

    RES=$(./endecode_test \
        -rsa certs/ee-key.pem -pss certs/ca-pss-key.pem -context \
        -provider libwolfprov 2>&1 | grep 'ok [1-9]')
    OLD_IFS=$IFS
    IFS=$'\n'
    for R in $RES
    do
        case $R in
        *skipped*)
            ;;
        "not ok "*)
            RES_FAIL=$(printf "$RES_FAIL\n$R")
            ;;
        "ok "*)
            RES_SUCCESS=$(printf "$RES_SUCCESS\n$R")
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
            echo "$R"
            FAIL_CNT=$((FAIL_CNT+1))
            ;;
        esac
    done
    for R in $RES_SUCCESS
    do
        case $R in
        *DSA*|*DHX*|*ECExplicit*|*RSA_PSS*|*MSBLOB*|*PVK*)
            echo "ERROR: Unexpected success"
            echo "$R"
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

    RES=$(./evp_libctx_test -provider libwolfprov 2>&1)

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
                echo "$L"
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
                echo "$L"
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

WOLFPROV_DIR=$PWD
WOLFPROV_CONFIG=$WOLFPROV_DIR/provider.conf
WOLFPROV_PATH=$WOLFPROV_DIR/.libs
LOGDIR=$WOLFPROV_DIR/scripts/log
LOG_FILE=$LOGDIR/test-openssl.log
export OPENSSL_MODULES=$WOLFPROV_PATH

if [ ! -d "$LOGDIR" ]; then
    mkdir "$LOGDIR"
fi

# Fresh start
rm -f "$LOG_FILE"

if [ -z "$NUMCPU" ]; then
    if [[ "$OSTYPE" == "linux-gnu" ]]; then
      export NUMCPU=$(grep -c ^processor /proc/cpuinfo)
    elif [[ "$OSTYPE" == "darwin"* ]]; then
      export NUMCPU=$(sysctl -n hw.ncpu)
    else
      export NUMCPU=4
    fi
fi

init_openssl
init_wolfssl

if [ -z "$LD_LIBRARY_PATH" ]; then
    export LD_LIBRARY_PATH="$OPENSSL_INSTALL_DIR/lib64:$WOLFSSL_INSTALL_DIR/lib"
else
    export LD_LIBRARY_PATH="$LD_LIBRARY_PATH:$OPENSSL_INSTALL_DIR/lib64:$WOLFSSL_INSTALL_DIR/lib"
fi
printf "LD_LIBRARY_PATH: $LD_LIBRARY_PATH\n"

# Set up wolfProvider
cd "${WOLFPROV_DIR}" || exit
if [ ! -e "${WOLFPROV_DIR}/configure" ]; then
    ./autogen.sh >>"$LOG_FILE" 2>&1
    ./configure --with-openssl="${OPENSSL_INSTALL_DIR}" --with-wolfssl="${WOLFSSL_INSTALL_DIR}" >>"$LOG_FILE" 2>&1
fi
make -j$NUMCPU >>"$LOG_FILE" 2>&1
if [ $? != 0 ]; then
  printf "\n\n...\n"
  tail -n 40 "$LOG_FILE"
  do_cleanup
  exit 1
fi

make test >>"$LOG_FILE" 2>&1
if [ $? != 0 ]; then
  printf "\n\n...\n"
  tail -n 40 "$LOG_FILE"
  do_cleanup
  exit 1
fi

# Start with returning success
FAIL_CNT=0
cd "$OPENSSL_TEST" || exit

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

