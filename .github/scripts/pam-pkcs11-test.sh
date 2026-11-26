#!/bin/bash
# Build pam_pkcs11 and authenticate testuser with a key and certificate held
# on a SoftHSM token, through a PAM service where pam_pkcs11 is the only
# module that can succeed.
#
# The valid token must first authenticate after the CA and signature checks.
# Then a wrong PIN, a certificate from an unknown CA and a key that does not
# match its certificate must each be rejected. With WOLFPROV_FORCE_FAIL=1,
# the valid token instead authenticates again under force fail and the script
# exits with pamtester's status. Setup and the first authentication always
# run without force fail. pamtester output is appended to PAM_PKCS11_TEST_LOG.
set -euo pipefail
set -x

FORCE_FAIL="${WOLFPROV_FORCE_FAIL:-0}"
unset WOLFPROV_FORCE_FAIL

PIN=1234
WRONG_PIN=0000
PAM_SERVICE=pam_pkcs11_test
PAM_SERVICE_FILE="/etc/pam.d/$PAM_SERVICE"
SOFTHSM_MODULE=/usr/lib/softhsm/libsofthsm2.so
WRONG_PIN_MSG="Error 2320: Wrong smartcard PIN"
UNKNOWN_CA_MSG="Error 2328: Certificate signature invalid"
BAD_SIG_MSG="Error 2342: Verifying signature failed"
TEST_LOG=$(realpath -m "${PAM_PKCS11_TEST_LOG:-pam-pkcs11-test.log}")
: > "$TEST_LOG"

# Confirm wolfProvider is configured by running openssl list -providers
if openssl list -providers | grep -qi wolf; then
    echo "wolfProvider is configured"
else
    echo "wolfProvider is not configured"
    exit 1
fi

echo "[*] Installing build dependencies..."
apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y \
    git \
    build-essential \
    autotools-dev \
    autoconf \
    libtool \
    pkg-config \
    libpam0g-dev \
    libpcsclite-dev \
    opensc \
    softhsm2 \
    pamtester

WORK=$(mktemp -d /tmp/pam-pkcs11-test.XXXXXX)
trap 'rm -f "$PAM_SERVICE_FILE"' EXIT

echo "[*] Cloning pam_pkcs11..."
git clone --depth 1 --branch="${PAM_PKCS11_REF}" \
    https://github.com/OpenSC/pam_pkcs11.git "$WORK/src"
cd "$WORK/src"

echo "[*] Building pam_pkcs11 from source..."
./bootstrap
./configure --prefix=/usr --sysconfdir=/etc --with-pam-dir=/lib/security --disable-nls
make -j"$(nproc)"
make install

echo "[*] Creating test user..."
if ! id -u testuser &>/dev/null; then
    useradd -m testuser
fi

echo "[*] Creating the certificates and keys..."
mkdir -p "$WORK/cacerts" "$WORK/crls"
openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
    -keyout "$WORK/ca.key" -out "$WORK/cacerts/ca.crt" \
    -subj "/CN=Test CA/O=Example" \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign,cRLSign"
openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
    -keyout "$WORK/unknown-ca.key" -out "$WORK/unknown-ca.crt" \
    -subj "/CN=Unknown CA/O=Example" \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign,cRLSign"
openssl req -newkey rsa:2048 -nodes \
    -keyout "$WORK/user.key" -out "$WORK/user.csr" \
    -subj "/CN=testuser/O=Example"
openssl x509 -req -days 365 -in "$WORK/user.csr" \
    -CA "$WORK/cacerts/ca.crt" -CAkey "$WORK/ca.key" \
    -outform DER -out "$WORK/user.der"
openssl x509 -req -days 365 -in "$WORK/user.csr" \
    -CA "$WORK/unknown-ca.crt" -CAkey "$WORK/unknown-ca.key" \
    -outform DER -out "$WORK/unknown-ca-user.der"
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 \
    -out "$WORK/other.key"
pkcs11_make_hash_link "$WORK/cacerts"

# Create a SoftHSM token in $WORK/<name> that holds <key> and <cert> under
# one ID, so pam_pkcs11 signs with that key
make_token() (
    local dir="$WORK/$1"

    mkdir -p "$dir/tokens"
    export SOFTHSM2_CONF="$dir/softhsm2.conf"
    cat > "$SOFTHSM2_CONF" <<EOF
directories.tokendir = $dir/tokens
objectstore.backend = file
log.level = INFO
EOF
    softhsm2-util --init-token --free --label testtoken \
        --pin "$PIN" --so-pin 123456
    softhsm2-util --import "$2" --token testtoken \
        --id 01 --label testkey --pin "$PIN"
    pkcs11-tool --module "$SOFTHSM_MODULE" --login --pin "$PIN" \
        --write-object "$3" --type cert --id 01 --label testcert
    pkcs11-tool --module "$SOFTHSM_MODULE" --login --pin "$PIN" -O
)

echo "[*] Creating SoftHSM tokens (simulated smartcards)..."
make_token valid "$WORK/user.key" "$WORK/user.der"
make_token unknown-ca "$WORK/user.key" "$WORK/unknown-ca-user.der"
make_token bad-key "$WORK/other.key" "$WORK/user.der"

echo "[*] Configuring pam_pkcs11..."
cat > "$WORK/pam_pkcs11.conf" <<EOF
pam_pkcs11 {
  nullok = false;
  debug = true;
  card_only = true;
  use_pkcs11_module = softhsm;
  pkcs11_module softhsm {
    module = $SOFTHSM_MODULE;
    slot_num = 0;
    ca_dir = $WORK/cacerts;
    crl_dir = $WORK/crls;
    cert_policy = ca,signature;
    token_type = "SoftHSM token";
  }
  use_mappers = cn;
  mapper cn {
    debug = true;
    module = internal;
    ignorecase = false;
    mapfile = "none";
  }
}
EOF
cat > "$PAM_SERVICE_FILE" <<EOF
auth sufficient pam_pkcs11.so debug config_file=$WORK/pam_pkcs11.conf
auth requisite  pam_deny.so
EOF

# Authenticate testuser through PAM_SERVICE with <token> and <pin>, logging
# to $WORK/<log> and TEST_LOG. Any further arguments are environment settings
# for pamtester.
run_pam() {
    local token="$1"
    local pin="$2"
    local log="$WORK/$3"
    local rc=0
    shift 3

    env SOFTHSM2_CONF="$WORK/$token/softhsm2.conf" "$@" \
        pamtester -v "$PAM_SERVICE" testuser authenticate \
        <<< "$pin" > "$log" 2>&1 || rc=$?
    tee -a "$TEST_LOG" < "$log"
    return $rc
}

# Authentication with <token> and <pin> must fail with <msg>. Any further
# arguments are environment settings for pamtester.
expect_fail() {
    local token="$1"
    local pin="$2"
    local log="$3"
    local msg="$4"
    shift 4

    if run_pam "$token" "$pin" "$log" "$@"; then
        echo "FAIL: $log: authentication succeeded"
        exit 1
    fi
    if ! grep -qF "$msg" "$WORK/$log"; then
        echo "FAIL: $log: authentication failed without '$msg'"
        exit 1
    fi
}

echo "[*] Authenticating with the valid token and the correct PIN..."
if ! run_pam valid "$PIN" auth.log; then
    echo "FAIL: authentication with the valid token failed"
    exit 1
fi
if ! grep -q "Checking signature" "$WORK/auth.log" \
    || ! grep -q "successfully authenticated" "$WORK/auth.log"; then
    echo "FAIL: authentication succeeded without the signature check"
    exit 1
fi

if [ "$FORCE_FAIL" = "1" ]; then
    echo "[*] Authenticating with the valid token and WOLFPROV_FORCE_FAIL=1..."
    rc=0
    run_pam valid "$PIN" force-fail.log WOLFPROV_FORCE_FAIL=1 || rc=$?
    exit $rc
fi

echo "[*] Authenticating with a wrong PIN..."
expect_fail valid "$WRONG_PIN" wrong-pin.log "$WRONG_PIN_MSG"

echo "[*] Authenticating with a certificate from an unknown CA..."
expect_fail unknown-ca "$PIN" unknown-ca.log "$UNKNOWN_CA_MSG"

echo "[*] Authenticating with a key that does not match the certificate..."
expect_fail bad-key "$PIN" bad-key.log "$BAD_SIG_MSG"

echo "PASS: the valid token authenticated after the CA and signature checks," \
     "and the wrong PIN, unknown CA and mismatched key were rejected"
