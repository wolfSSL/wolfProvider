#!/usr/bin/env bash
set -Eeuo pipefail

# OAEP (RSA-2048, SHA-256/MGF1-SHA-256) smoke test using your default OpenSSL provider.
# Usage:
#   ./oaep.sh            # uses a mktemp dir, cleans it up on exit
#   KEEP=1 ./oaep.sh     # keep the temp dir for debugging
#   ./oaep.sh /path/dir  # use a specific directory (no auto-clean)

DIR="${1:-}"
CLEANUP=0

if [[ -n "$DIR" ]]; then
  DIR="${DIR%/}"
  mkdir -p "$DIR"
else
  DIR="$(mktemp -d)"
  CLEANUP=1
fi

if [[ "${KEEP:-0}" == "1" ]]; then
  CLEANUP=0
fi

cleanup() {
  if (( CLEANUP )); then rm -rf "$DIR"; fi
}
trap cleanup EXIT

PRIV="$DIR/priv.pem"
PUB="$DIR/pub.pem"
PT="$DIR/pt.bin"
CT="$DIR/ct.bin"
PT2="$DIR/pt2.bin"

echo "work dir: $DIR"

# 1) Ensure a known-good keypair exists (RSA-2048, e=65537)
if [[ ! -s "$PRIV" || ! -s "$PUB" ]]; then
  echo "Generating RSA-2048 keypair..."
  openssl genpkey -algorithm RSA \
    -pkeyopt rsa_keygen_bits:2048 \
    -pkeyopt rsa_keygen_pubexp:65537 \
    -out "$PRIV"
  chmod 600 "$PRIV"
  openssl pkey -in "$PRIV" -pubout > "$PUB"
fi

# 2) Quick sanity on the keys (will throw if invalid)
openssl pkey -in "$PRIV" -check -noout >/dev/null
openssl pkey -pubin -in "$PUB" -text -noout >/dev/null

# 3) Tiny plaintext
printf 'test123' > "$PT"

# 4) Encrypt with RSA-OAEP using SHA-256 (MGF1=SHA-256)
openssl pkeyutl -encrypt -pubin -inkey "$PUB" -in "$PT" -out "$CT" \
  -pkeyopt rsa_padding_mode:oaep \
  -pkeyopt rsa_oaep_md:sha256 \
  -pkeyopt rsa_mgf1_md:sha256

# 5) Decrypt and compare
openssl pkeyutl -decrypt -inkey "$PRIV" -in "$CT" -out "$PT2" \
  -pkeyopt rsa_padding_mode:oaep \
  -pkeyopt rsa_oaep_md:sha256 \
  -pkeyopt rsa_mgf1_md:sha256

if diff -u "$PT" "$PT2" >/dev/null; then
  echo "OK: OAEP-SHA256 works"
else
  echo "FAIL: decrypted plaintext mismatch"
  exit 1
fi
