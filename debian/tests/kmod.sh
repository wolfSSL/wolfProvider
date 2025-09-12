#!/usr/bin/env bash
set -Eeuo pipefail

# kmod/OpenSSL signature smoke test
# Builds a tiny .ko, signs it with your OpenSSL, and has modinfo parse the signature.
# Assumes your provider/config is already selected outside this script (OPENSSL_CONF, LD_LIBRARY_PATH, etc).

# --- Options you can override ---
: "${OPENSSL_DIR:=}"             # e.g. /usr/local/openssl/bin  (prepends to PATH so sign-file uses your openssl)
: "${KEY_BITS:=2048}"            # RSA key size
: "${HASH_ALGO:=sha256}"         # sign-file hash (sha256/sha384/sha512)
: "${CN:=kmod-smoke}"            # x509 CN for the self-signed cert
: "${KEEP:=0}"                   # set KEEP=1 to keep the temp workdir

# --- Setup workspace ---
work="$(mktemp -d)"
cleanup(){ [[ "${KEEP}" = "1" ]] && { echo "Keeping workdir: $work"; return; }; rm -rf "$work"; }
trap cleanup EXIT

[[ -n "$OPENSSL_DIR" ]] && export PATH="$OPENSSL_DIR:$PATH"

echo "=== kmod signature smoke ==="
echo "workdir:        $work"
echo "OPENSSL in use: $(command -v openssl || true)"
openssl version || true
echo

# --- Preconditions ---
need() { command -v "$1" >/dev/null 2>&1 || { echo "Missing: $1"; exit 1; }; }
need make
need modinfo

build_dir="/lib/modules/$(uname -r)/build"
if [[ ! -e "$build_dir" ]]; then
  echo "ERROR: kernel headers not found at $build_dir."
  echo "Debian/Ubuntu: sudo apt-get install build-essential linux-headers-$(uname -r)"
  exit 1
fi

sign_file="$build_dir/scripts/sign-file"
if [[ ! -x "$sign_file" ]]; then
  echo "ERROR: sign-file not found at $sign_file"
  echo "Install proper kernel headers; sign-file ships with the kernel tree."
  exit 1
fi

# --- Create module sources ---
cat > "$work/kmod_smoke.c" <<'EOF'
#include <linux/init.h>
#include <linux/module.h>
MODULE_LICENSE("GPL");
MODULE_AUTHOR("kmod-smoke");
MODULE_DESCRIPTION("kmod signature smoke test module");
MODULE_VERSION("1.0");
static int __init kmod_smoke_init(void) { return 0; }
static void __exit kmod_smoke_exit(void) {}
module_init(kmod_smoke_init);
module_exit(kmod_smoke_exit);
EOF

cat > "$work/Makefile" <<'EOF'
obj-m += kmod_smoke.o
all:
	$(MAKE) -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
clean:
	$(MAKE) -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
EOF

# --- Build the module (no insert) ---
echo "Building module..."
make -C "$work" -s

ko="$work/kmod_smoke.ko"
[[ -f "$ko" ]] || { echo "Build failed: $ko not found"; exit 1; }

# --- Generate key + self-signed cert (DER) with your OpenSSL ---
echo "Generating self-signed keypair..."
openssl req -new -x509 -newkey "rsa:${KEY_BITS}" -nodes \
  -keyout "$work/MOK.priv" -out "$work/MOK.der" -outform DER \
  -subj "/CN=${CN}/"

# --- Sign the module (CMS if available, else PKCS#7; handled by sign-file) ---
echo "Signing module with $HASH_ALGO ..."
"$sign_file" "$HASH_ALGO" "$work/MOK.priv" "$work/MOK.der" "$ko"

# --- Have kmod parse the signature block via OpenSSL ---
echo
echo "modinfo signature fields:"
modinfo -F sig_id        "$ko" || true
modinfo -F signer        "$ko" || true
modinfo -F sig_key       "$ko" || true
modinfo -F sig_hashalgo  "$ko" || true
sig_hex="$(modinfo -F signature "$ko" || true)"
echo "signature (hex): ${sig_hex:0:64}..."

# --- Basic assertions (tolerant) ---
fail=0
signer="$(modinfo -F signer "$ko" || true)"
algo="$(modinfo -F sig_hashalgo "$ko" || true)"
[[ -n "$signer" ]] || { echo "ASSERT: signer is empty"; fail=1; }
[[ "$algo" == "$HASH_ALGO" ]] || { echo "ASSERT: sig_hashalgo expected $HASH_ALGO, got $algo"; fail=1; }
if [[ -z "$sig_hex" ]]; then
  echo "ASSERT: signature blob is empty"; fail=1;
fi

echo
if [[ "$fail" -eq 0 ]]; then
  echo "=== Summary: PASS (kmod+OpenSSL can parse module signature) ==="
else
  echo "=== Summary: FAIL ==="
  exit 1
fi
