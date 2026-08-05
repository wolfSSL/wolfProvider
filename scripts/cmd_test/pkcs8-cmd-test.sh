#!/bin/bash
# Verify that the pkey command honors -aes256 for provider private-key encoders.

CMD_TEST_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
source "${CMD_TEST_DIR}/cmd-test-common.sh"
source "${CMD_TEST_DIR}/clean-cmd-test.sh"

if [ -z "${DO_CMD_TESTS:-}" ]; then
    echo "This script is designed to be called from do-cmd-tests.sh"
    exit 1
fi

cmd_test_init "pkcs8-cmd-test.log"
clean_cmd_test "pkcs8"
mkdir -p pkcs8_outputs
FAIL=0

test_pkey_cipher() {
    local name=$1
    local keygen=$2
    local input="pkcs8_outputs/${name}.pem"
    local output="pkcs8_outputs/${name}-encrypted.pem"

    use_wolf_provider
    if ! eval "$keygen" >"$input" 2>/dev/null; then
        echo "[FAIL] ${name} key generation failed"
        FAIL=1
        return 1
    fi
    if ! $OPENSSL_BIN pkey -aes256 -passout pass:wolfprov-test-pass \
            -in "$input" -out "$output" 2>/dev/null; then
        echo "[FAIL] ${name} pkey encryption failed"
        FAIL=1
        return 1
    fi
    if ! grep -q "BEGIN ENCRYPTED PRIVATE KEY" "$output"; then
        echo "[FAIL] ${name} pkey -aes256 produced an unencrypted key"
        FAIL=1
        return 1
    else
        echo "[PASS] ${name} pkey -aes256 produced EncryptedPrivateKeyInfo"
        check_force_fail
    fi
    return 0
}

test_pkey_cipher "ec" "$OPENSSL_BIN genpkey -algorithm EC -pkeyopt ec_paramgen_curve:prime256v1"
if [ "${WOLFSSL_ISFIPS:-0}" != "1" ] &&
    $OPENSSL_BIN list -public-key-algorithms -provider libwolfprov 2>/dev/null |
        grep -q "ED25519"; then
    test_pkey_cipher "ed25519" "$OPENSSL_BIN genpkey -algorithm ED25519"
else
    echo "[SKIP] Ed25519 is unavailable in this OpenSSL/provider build"
fi
if [ "${WOLFSSL_ISFIPS:-0}" != "1" ] &&
    $OPENSSL_BIN list -public-key-algorithms -provider libwolfprov 2>/dev/null |
        grep -q "X25519"; then
    test_pkey_cipher "x25519" "$OPENSSL_BIN genpkey -algorithm X25519"
else
    echo "[SKIP] X25519 is unavailable in this OpenSSL/provider build"
fi
test_pkey_cipher "rsa" "$OPENSSL_BIN genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048"

# DH requires a generated parameter file before the private key can be made.
use_wolf_provider
if $OPENSSL_BIN genpkey -genparam -algorithm DH \
        -pkeyopt dh_paramgen_prime_len:2048 \
        -out pkcs8_outputs/dh-params.pem 2>/dev/null &&
    test_pkey_cipher "dh" "$OPENSSL_BIN genpkey -paramfile pkcs8_outputs/dh-params.pem"; then
    :
else
    echo "[FAIL] DH PKCS#8 command test failed"
    FAIL=1
fi

# OpenSSL versions before 3.6 do not provide the standardized PQC names.
for algorithm in ML-DSA-44 ML-DSA-65 ML-DSA-87; do
    if $OPENSSL_BIN list -signature-algorithms -provider libwolfprov 2>/dev/null |
            grep -q "${algorithm}"; then
        test_pkey_cipher "${algorithm}" \
            "$OPENSSL_BIN genpkey -algorithm ${algorithm}"
    else
        echo "[SKIP] ${algorithm} is unavailable in this OpenSSL/provider build"
    fi
done

for algorithm in ML-KEM-512 ML-KEM-768 ML-KEM-1024; do
    if $OPENSSL_BIN list -kem-algorithms -provider libwolfprov 2>/dev/null |
            grep -q "${algorithm}"; then
        test_pkey_cipher "${algorithm}" \
            "$OPENSSL_BIN genpkey -algorithm ${algorithm}"
    else
        echo "[SKIP] ${algorithm} is unavailable in this OpenSSL/provider build"
    fi
done

if [ "${WOLFPROV_FORCE_FAIL:-0}" = "1" ]; then
    if [ "$FORCE_FAIL_PASSED" -eq 1 ]; then
        echo "[FAIL] PKCS#8 command tests unexpectedly passed with force-fail"
        exit 1
    fi
elif [ "$FAIL" -ne 0 ]; then
    exit 1
fi
exit 0
