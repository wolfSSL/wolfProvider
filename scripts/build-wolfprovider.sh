#!/bin/bash
# This script provides the bare minimum function definitions for compiling
# the wolfProvider library

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
LOG_FILE=${SCRIPT_DIR}/build-release.log
source ${SCRIPT_DIR}/utils-wolfprovider.sh

show_help() {
  echo "Usage: $0"
  echo ""
  echo "Environment Variables:"
  echo "  OPENSSL_TAG          OpenSSL tag to use (e.g., openssl-3.5.0)"
  echo "  WOLFSSL_TAG          wolfSSL tag to use (e.g., v5.8.0-stable)"
  echo "  WOLFPROV_DEBUG       If set to 1, builds OpenSSL, wolfSSL, and wolfProvider with debug options enabled"
  echo "  WOLFSSL_FIPS_BUNDLE  Directory containing the wolfSSL FIPS bundle to use instead of cloning from GitHub"
  echo "  WOLFSSL_FIPS_VERSION Version of wolfSSL FIPS bundle (v5, v6, ready), used as an argument for --enable-fips when configuring wolfSSL"
  echo ""
}

if [[ "$1" == "--help" || "$1" == "-h" || "$1" == "-help" ]]; then
  show_help
  exit 0
fi

echo "Using openssl: $OPENSSL_TAG, wolfssl: $WOLFSSL_TAG"

init_wolfprov

exit $?
