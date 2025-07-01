#!/bin/bash
set -euo pipefail

echo "[*] Setting up environment..."
SCRIPT_PATH="$(cd "$(dirname "$0")" && pwd)/$(basename "$0")"
REPO_ROOT=$(git -C "$(dirname "$SCRIPT_PATH")" rev-parse --show-toplevel)
source $REPO_ROOT/scripts/env-setup || true

if [[ -z "${OPENSSL_MODULES:-}" ]]; then
    echo "Environment not set up: OPENSSL_MODULES is not defined or empty"
    exit 1
elif [[ ! -d "$OPENSSL_MODULES" ]]; then
    echo "Could not find wolfProvider at $OPENSSL_MODULES"
    echo "Please build it first..."
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
    libnss3-dev \
    libpcsclite-dev \
    opensc \
    softhsm2 \
    pcscd \
    pcsc-tools \
    sudo \
    systemd \
    ssh \
    vim \
    gnupg \
    wget \
    curl

echo "[*] Cloning pam_pkcs11..."
cd /opt
if [[ ! -d "pam_pkcs11" ]]; then
  git clone https://github.com/OpenSC/pam_pkcs11.git
fi
cd pam_pkcs11

echo "[*] Building pam_pkcs11 from source..."
./bootstrap
./configure --prefix=/usr --sysconfdir=/etc --with-pam-dir=/lib/security --disable-nls
make -j"$(nproc)"
make install

echo "[*] Creating test user..."
if ! id -u testuser &>/dev/null; then
    useradd -m testuser
    echo 'testuser:testpass' | chpasswd
    echo "[*] Created user 'testuser'"
else
    echo "[*] User 'testuser' already exists, skipping creation"
fi

echo "[*] Configuring pam_pkcs11..."

# Generate dummy CA cert if missing
if [ ! -f /test/certs/test-ca.crt ]; then
    echo "[*] Generating dummy test-ca.crt..."
    mkdir -p /test/certs
    openssl req -x509 -newkey rsa:2048 -nodes \
        -keyout /test/certs/test-ca.key \
        -out /test/certs/test-ca.crt \
        -days 365 -subj "/CN=Test CA/O=Example"
fi

mkdir -p /etc/pam_pkcs11/cacerts
cp /test/certs/test-ca.crt /etc/pam_pkcs11/cacerts/
pkcs11_make_hash_link /etc/pam_pkcs11/cacerts/

# Generate test certificate and key if missing
if [ ! -f /test/certs/test-cert.pem ]; then
    echo "[*] Generating test-cert.pem and key..."
    mkdir -p /test/certs
    openssl req -newkey rsa:2048 -nodes \
        -keyout /test/certs/test-key.pem \
        -x509 -days 365 -out /test/certs/test-cert.pem \
        -subj "/CN=Test User/OU=Testing/O=Example Corp/C=US"
fi

# Extract cert subject in one-line format suitable for pam_pkcs11
CERT_SUBJECT=$(openssl x509 -in /test/certs/test-cert.pem -noout -subject -nameopt oneline | sed 's/subject=//')

echo "[*] Writing pkcs11_mapper.map with subject: $CERT_SUBJECT"

echo "subject=$CERT_SUBJECT; uid=testuser" | tee /etc/pam_pkcs11/pkcs11_mapper.map > /dev/null

# Backup and modify PAM config
cp /etc/pam.d/common-auth /etc/pam.d/common-auth.bak
echo "auth sufficient pam_pkcs11.so debug" | tee /etc/pam.d/common-auth > /dev/null
cat /etc/pam.d/common-auth.bak | tee -a /etc/pam.d/common-auth > /dev/null

echo "[*] Initializing SoftHSM (simulated smartcard)..."
mkdir -p /var/lib/softhsm/tokens
softhsm2-util --init-token --free --label "testtoken" --pin 1234 --so-pin 123456

echo "[*] Importing test certificate into SoftHSM..."
pkcs11-tool --module /usr/lib/softhsm/libsofthsm2.so \
    --login --pin 1234 --write-object /test/certs/test-cert.pem --type cert --label "testcert"

echo "[*] Starting pcscd..."
if ps aux | grep '[p]cscd' > /dev/null; then
    echo "pcscd is already running"
else
    echo "pcscd is not running, starting it now..."
    pcscd &
fi

echo "[*] Creating pam_pkcs11.conf..."
if [ -f "./etc/pam_pkcs11.conf.example" ]; then
  cp ./etc/pam_pkcs11.conf.example /etc/pam_pkcs11/pam_pkcs11.conf
else
  echo "ERROR: pam_pkcs11.conf.example not found in current directory"
  exit 1
fi

echo "[*] Configuring pam_pkcs11.conf for SoftHSM module..."

# Set correct module usage line
sed -i 's|^use_pkcs11_module.*|use_pkcs11_module = softhsm;|' /etc/pam_pkcs11/pam_pkcs11.conf

# Set the SoftHSM module path
sed -i '/^pkcs11_module softhsm {/,/^}/ s|^\s*module\s*=.*|    module = /usr/lib/softhsm/libsofthsm2.so;|' /etc/pam_pkcs11/pam_pkcs11.conf

echo "[*] Checking SoftHSM PKCS#11 module dependencies..."
ldd /usr/lib/softhsm/libsofthsm2.so | tee /tmp/libsofthsm2.ldd
if grep -q "not found" /tmp/libsofthsm2.ldd; then
  echo "ERROR: Missing dependencies for SoftHSM PKCS#11 module!"
  exit 1
fi

echo "[*] Testing SoftHSM PKCS#11 module loadability with pkcs11-tool..."
if ! pkcs11-tool --module /usr/lib/softhsm/libsofthsm2.so -L; then
  echo "ERROR: Failed to load SoftHSM PKCS#11 module"
  exit 1
fi

echo "[*] Testing login via su..."
su testuser -c 'echo "✅ Logged in as testuser"'

echo "[*] All done."
