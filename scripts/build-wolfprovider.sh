#!/bin/bash
# This script provides the bare minimum function definitions for compiling
# the wolfProvider library

show_help() {
  echo "Usage: $0"
  echo ""
  echo "Script Arguments:"
  echo "  --help, -help, -h          Display this help menu and exit"
  echo "  --clean                    Run make clean in OpenSSL, wolfSSL, and wolfProvider"
  echo "  --distclean                Remove source directories of OpenSSL and wolfSSL"
  echo "  --debug                    Builds OpenSSL, wolfSSL, and WolfProvider with debugging enabled. This is the same as setting WOLFPROV_DEBUG=1"
  echo "  --debug-asn-template       Enable debug information for asn within wolfSSL"
  echo "  --disable-err-trace        No debug trace messages from library errors in wolfSSL"
  echo "  --openssl-ver=VER          Which version of OpenSSL to clone"
  echo "  --wolfssl-ver=VER          Which version of wolfSSL to clone"
  echo "  --enable-fips              Build wolfProvider with a cloned FIPS bundle. Cloned FIPS bundle can be changed with --fips-check"
  echo "  --fips-bundle=DIR          Build wolfProvider with a directory containing a wolfSSL FIPS bundle instead of cloning from GitHub. Requires a FIPS version to be given by --fips-version"
  echo "  --fips-check=TAG           Choose a FIPS tag to clone. May require a version to be given by --fips-version"
  echo "  --fips-version=VER         Choose the wolfSSL FIPS version"
  echo "  --quicktest                Disable some tests for a faster testing suite"
  echo ""
  echo "Environment Variables:"
  echo "  OPENSSL_TAG                OpenSSL tag to use (e.g., openssl-3.5.0)"
  echo "  WOLFSSL_TAG                wolfSSL tag to use (e.g., v5.8.0-stable)"
  echo "  WOLFSSL_ISFIPS             If set to 1, clones a wolfSSL FIPS bundle from GitHub"
  echo "  WOLFSSL_FIPS_BUNDLE        Directory containing the wolfSSL FIPS bundle to use instead of cloning from GitHub"
  echo "  WOLFSSL_FIPS_VERSION       Version of wolfSSL FIPS bundle (v5, v6, ready), used as an argument for --enable-fips when configuring wolfSSL"
  echo "  WOLFSSL_FIPS_CHECK_TAG     Tag for wolfSSL FIPS bundle (linuxv5.2.1, v6.0.0, etc), used as an argument for fips-check.sh when cloning a wolfSSL FIPS version"
  echo "  WOLFPROV_CLEAN             If set to 1, run make clean in OpenSSL, wolfSSL, and wolfProvider"
  echo "  WOLFPROV_DISTCLEAN         If set to 1, remove the source directories of OpenSSL and wolfSSL"
  echo "  WOLFPROV_DEBUG             If set to 1, builds OpenSSL, wolfSSL, and wolfProvider with debug options enabled"
  echo "  WOLFPROV_QUICKTEST         If set to 1, disables some tests in the test suite to increase test speed"
  echo "  WOLFPROV_DISABLE_ERR_TRACE If set to 1, wolfSSL will not be configured with --enable-debug-trace-errcodes=backtrace"
  echo ""
}

args_wrong=""
args=""
for arg in "$@"; do
    args+="$arg, "
    case "$arg" in
        --help | -help | -h)
            show_help
            exit 0
            ;;
        --clean)
            WOLFPROV_CLEAN=1
            ;;
        --distclean)
            WOLFPROV_DISTCLEAN=1
            ;;
        --debug)
            WOLFPROV_DEBUG=1
            ;;
        --debug-asn-template)
            WOLFSSL_DEBUG_ASN_TEMPLATE=1
            ;;
        --disable-err-trace)
            WOLFPROV_DISABLE_ERR_TRACE=1
            ;;
        --openssl-ver=*)
            IFS='=' read -r trash ossl_ver <<< "$arg"
            if [ -z "$ossl_ver" ]; then
                echo "No version given for --openssl-ver"
                args_wrong+="$arg, "
            fi
            OPENSSL_TAG="$ossl_ver"
            ;;
        --wolfssl-ver=*)
            IFS='=' read -r trash wolf_ver <<< "$arg"
            if [ -z "$wolf_ver" ]; then
                echo "No version given for --wolfssl-ver"
                args_wrong+="$arg, "
            fi
            WOLFSSL_TAG="$wolf_ver"
            ;;
        --enable-fips)
            unset WOLFSSL_FIPS_BUNDLE
            WOLFSSL_ISFIPS=1
            ;;
        --fips-bundle=*)
            unset WOLFSSL_ISFIPS
            unset WOLFSSL_FIPS_CHECK_TAG
            IFS='=' read -r trash fips_bun <<< "$arg"
            if [ -z "$fips_bun" ]; then
                echo "No directory given for --fips-bundle"
                args_wrong+="$arg, "
            fi
            WOLFSSL_FIPS_BUNDLE="$fips_bun"
            ;;
        --fips-check=*)
            unset WOLFSSL_FIPS_BUNDLE
            IFS='=' read -r trash fips_tag <<< "$arg"
            if [ -z "$fips_tag" ]; then
                echo "No tag given for --fips-check"
                args_wrong+="$arg, "
            fi
            WOLFSSL_FIPS_CHECK_TAG="$fips_tag"
            ;;
        --fips-version=*)
            IFS='=' read -r trash fips_ver <<< "$arg"
            if [ -z "$fips_ver" ]; then
                echo "No version given for --fips-version"
                args_wrong+="$arg, "
            fi
            WOLFSSL_FIPS_VERSION="$fips_ver"
            ;;
        --quicktest)
            WOLFPROV_QUICKTEST=1
            ;;
        *)
            args_wrong+="$arg, "
            ;;
    esac
done

if [ -n "$args_wrong" ]; then
    args_wrong="`echo $args_wrong | head -c -2 -`"
    echo "Unrecognized argument(s) provided: $args_wrong"
    echo "Use --help to see a list of arguments"
    exit 1
fi

if [ -n "$args" ]; then
    args="`echo $args | head -c -2 -`"
    echo "Building wolfProvider with: $args"
    echo ""
fi

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
LOG_FILE=${SCRIPT_DIR}/build-release.log
source ${SCRIPT_DIR}/utils-wolfprovider.sh

echo "Using openssl: $OPENSSL_TAG, wolfssl: $WOLFSSL_TAG"

init_wolfprov

exit $?
