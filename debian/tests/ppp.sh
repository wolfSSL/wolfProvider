#!/usr/bin/env bash
set -Eeuo pipefail

# This wrapper assumes your provider/config is already set up externally.
# If needed, you can still point at custom libs/modules via env before running:
#   export LD_LIBRARY_PATH=/path/to/your/lib:$LD_LIBRARY_PATH
#   export OPENSSL_MODULES=/path/to/your/ossl-modules
# Optional: PROP_QUERY='provider=wolfprov' to constrain fetches.

: "${CC:=gcc}"

echo "Compiling ppp_crypto_smoke.c..."
CFLAGS="-O2 -Wall -Wextra"
if pkg-config --exists openssl 2>/dev/null; then
  $CC $CFLAGS -o ppp_crypto_smoke ppp_smoke.c $(pkg-config --cflags --libs openssl)
else
  echo "NOTE: pkg-config openssl not found; falling back to -lcrypto"
  $CC $CFLAGS -o ppp_crypto_smoke ppp_smoke.c -lcrypto
fi

echo
echo "Running..."
./ppp_crypto_smoke
rm -f ppp_crypto_smoke
