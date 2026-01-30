#!/bin/bash
# This script provides the bare minimum function definitions for compiling
# the wolfProvider library

show_help() {
  echo "Usage: $0"
  echo ""
  echo "Script Arguments:"
  echo "  --help, -help, -h          Display this help menu and exit"
  echo "  --clean                    Run make clean in OpenSSL, wolfSSL, and wolfProvider"
  echo "  --distclean                Remove source and install directories of OpenSSL, wolfSSL, and wolfProvider"
  echo "  --debug                    Builds OpenSSL, wolfSSL, and WolfProvider in debug mode with logging enabled. This is the same as setting WOLFPROV_DEBUG=1"
  echo "  --debug-log=FILE           Force all wolfProvider runtime output to specified log file instead of stderr/stdout (FILE = path to log file you want to use). Logs are appended to existing file."
  echo "  --debug-asn-template       Enable debug information for asn within wolfSSL"
  echo "  --disable-err-trace        No debug trace messages from library errors in wolfSSL"
  echo "  --openssl-ver=VER          Which version of OpenSSL to clone"
  echo "  --wolfssl-ver=VER          Which version of wolfSSL to clone"
  echo "  --enable-fips              Build wolfProvider with a cloned FIPS bundle. Use with --fips-check to specify tag (default: v5.2.4)"
  echo "  --fips-bundle=DIR          Build wolfProvider with a directory containing a wolfSSL FIPS bundle. Use with --fips-check to specify tag"
  echo "  --fips-check=TAG           Choose a FIPS tag (v5.2.1, v5.2.4, linuxv5.2.1, v6.0.0, ready, etc). Automatically determines configure option"
  echo "  --debian                   Build a Debian package"
  echo "  --debian --enable-fips     Build a Debian package with FIPS support"
  echo "  --quicktest                Disable some tests for a faster testing suite"
  echo "  --replace-default          Patch OpenSSL and build it so that wolfProvider is the default provider"
  echo "  --enable-replace-default-testing"
  echo "                             Enable direct provider loading in unit tests. This option patches openssl to export additional symbols."
  echo "                             Note: Requires --replace-default. Only for test builds, not for production."
  echo "  --leave-silent             Enable leave silent mode to suppress logging of return 0 in probing functions where expected failures may occur."
  echo "                             Note: This only affects logging; the calling function is still responsible for handling all return values appropriately."
  echo "  --debug-silent             Debug logging compiled in but silent by default. Use WOLFPROV_LOG_LEVEL and WOLFPROV_LOG_COMPONENTS env vars to enable at runtime. Requires --debug."
  echo "  --enable-seed-src          Enable SEED-SRC entropy source with /dev/urandom caching for fork-safe entropy."
  echo "                             Note: This also enables WC_RNG_SEED_CB in wolfSSL."
  echo ""
  echo "Environment Variables:"
  echo "  OPENSSL_TAG                OpenSSL tag to use (e.g., openssl-3.5.0)"
  echo "  WOLFSSL_TAG                wolfSSL tag to use (e.g., v5.8.0-stable)"
  echo "  WOLFSSL_ISFIPS             If set to 1, clones a wolfSSL FIPS bundle from GitHub"
  echo "  WOLFSSL_FIPS_BUNDLE        Directory containing the wolfSSL FIPS bundle to use instead of cloning from GitHub"
  echo "  WOLFSSL_FIPS_CHECK_TAG     Tag for wolfSSL FIPS bundle (v5.2.1, v5.2.4, linuxv5.2.1, v6.0.0, ready, etc). Automatically determines configure option (default: v5.2.4)"
  echo "  WOLFPROV_CLEAN             If set to 1, run make clean in OpenSSL, wolfSSL, and wolfProvider"
  echo "  WOLFPROV_DISTCLEAN         If set to 1, remove the source and install directories of OpenSSL, wolfSSL, and wolfProvider"
  echo "  WOLFPROV_DEBUG             If set to 1, builds OpenSSL, wolfSSL, and wolfProvider with debug options enabled"
  echo "  WOLFPROV_DEBUG_SILENT      If set to 1, debug logging is silent by default (requires WOLFPROV_DEBUG=1)"
  echo "  WOLFPROV_LOG_FILE          Path to log file for wolfProvider debug output (alternative to stderr)"
  echo "  WOLFPROV_QUICKTEST         If set to 1, disables some tests in the test suite to increase test speed"
  echo "  WOLFPROV_DISABLE_ERR_TRACE If set to 1, wolfSSL will not be configured with --enable-debug-trace-errcodes=backtrace"
  echo "  WOLFPROV_REPLACE_DEFAULT   If set to 1, patches OpenSSL so wolfProvider is the default provider"
  echo "  WOLFPROV_REPLACE_DEFAULT_TESTING If set to 1, enables direct provider loading in unit tests (requires WOLFPROV_REPLACE_DEFAULT=1)"
  echo "  WOLFPROV_LEAVE_SILENT      If set to 1, suppress logging of return 0 in functions where return 0 is expected behavior sometimes."
  echo "  WOLFPROV_SEED_SRC          If set to 1, enables SEED-SRC with /dev/urandom caching (also enables WC_RNG_SEED_CB in wolfSSL)"
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
        --debug-log=*)
            IFS='=' read -r trash log_file <<< "$arg"
            if [ -z "$log_file" ]; then
                echo "No file path given for --debug-log"
                args_wrong+="$arg, "
            fi
            WOLFPROV_LOG_FILE="$log_file"
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
            IFS='=' read -r trash fips_bun <<< "$arg"
            if [ -z "$fips_bun" ]; then
                echo "No directory given for --fips-bundle"
                args_wrong+="$arg, "
            fi
            WOLFSSL_FIPS_BUNDLE="$fips_bun"
            ;;
        --fips-check=*)
            IFS='=' read -r trash fips_tag <<< "$arg"
            if [ -z "$fips_tag" ]; then
                echo "No tag given for --fips-check"
                args_wrong+="$arg, "
            fi
            WOLFSSL_FIPS_CHECK_TAG="$fips_tag"
            ;;
        --debian)
            build_debian=1
            ;;
        --quicktest)
            WOLFPROV_QUICKTEST=1
            ;;
        --replace-default)
            WOLFPROV_REPLACE_DEFAULT=1
            ;;
        --enable-replace-default-testing)
            WOLFPROV_REPLACE_DEFAULT_TESTING=1
            ;;
        --leave-silent)
            WOLFPROV_LEAVE_SILENT=1
            ;;
        --debug-silent)
            WOLFPROV_DEBUG_SILENT=1
            ;;
        --enable-seed-src)
            WOLFPROV_SEED_SRC=1
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

# Check if --leave-silent was used without debug mode
if [ "${WOLFPROV_LEAVE_SILENT}" = "1" ] && [ -z "$WOLFPROV_DEBUG" ] && [ -z "$debug" ]; then
    echo "Error: --leave-silent requires --debug to be set."
    exit 1
fi

# Check if --debug-silent was used without debug mode
if [ "${WOLFPROV_DEBUG_SILENT}" = "1" ] && [ -z "$WOLFPROV_DEBUG" ] && [ -z "$debug" ]; then
    echo "Error: --debug-silent requires --debug to be set."
    exit 1
fi

if [ -n "$WOLFPROV_LOG_FILE" ] && [ -z "$WOLFPROV_DEBUG" ]; then
    echo "Error: --debug-log requires --debug to be set."
    exit 1
fi

# Check for consistency between replace-default options
if [ "$WOLFPROV_REPLACE_DEFAULT_TESTING" = "1" ] && [ "$WOLFPROV_REPLACE_DEFAULT" != "1" ]; then
    echo "Error: --enable-replace-default-testing requires --replace-default to also be set."
    exit 1
fi

if [ -n "$build_debian" ]; then
    set -e

    DEB_OUTPUT_DIR=$(realpath '..')

    echo "Building Debian package..."
    WOLFSSL_OPTS=
    WOLFPROV_OPTS=
    OPENSSL_OPTS=

    if [ "$WOLFPROV_DEBUG" = "1" ]; then
        WOLFSSL_OPTS="--debug"
        WOLFPROV_OPTS="--debug"
    fi
    if [ -n "$WOLFSSL_ISFIPS" ]; then
        WOLFSSL_OPTS+=" --fips"
        WOLFPROV_OPTS+=" --fips"
    fi
    if [ "$WOLFPROV_REPLACE_DEFAULT" = "1" ]; then
        OPENSSL_OPTS+=" --replace-default"
    fi

    # wolfSSL and OpenSSL are independent and must be built first
    debian/install-wolfssl.sh $WOLFSSL_OPTS --no-install -r $DEB_OUTPUT_DIR
    debian/install-openssl.sh $OPENSSL_OPTS --no-install $DEB_OUTPUT_DIR

    # wolfProvider depends on wolfSSL and OpenSSL headers and libraries.
    # We don't want to install them locally, so we unpack them to 
    # temp dirs and reference those in the build.

    # Unpack the wolfssl packages to a temporary directory
    wolfssl_dev_dir=$(mktemp -d)
    dpkg -x $DEB_OUTPUT_DIR/libwolfssl_*.deb $wolfssl_dev_dir
    dpkg -x $DEB_OUTPUT_DIR/libwolfssl-dev_*.deb $wolfssl_dev_dir
    # Unpack the libssl-dev package to a temporary directory
    openssl_dev_dir=$(mktemp -d)
    dpkg -x $DEB_OUTPUT_DIR/openssl_*.deb $openssl_dev_dir
    dpkg -x $DEB_OUTPUT_DIR/libssl-dev_*.deb $openssl_dev_dir

    export DEB_HOST_MULTIARCH=$(dpkg-architecture -qDEB_HOST_MULTIARCH)

    printf "wolfssl_dev_dir: %s\n" $wolfssl_dev_dir
    printf "wolfssl_dev_dir libs: %s\n" $(ls $wolfssl_dev_dir/usr/lib/$DEB_HOST_MULTIARCH)
    printf "openssl_dev_dir: %s\n" $openssl_dev_dir
    printf "openssl_dev_dir libs: %s\n" $(ls $openssl_dev_dir/usr/lib/$DEB_HOST_MULTIARCH)

    export DEB_CFLAGS_APPEND="-I$wolfssl_dev_dir/usr/include -I$openssl_dev_dir/usr/include"
    export DEB_CPPFLAGS_APPEND="-I$wolfssl_dev_dir/usr/include -I$openssl_dev_dir/usr/include"
    export DEB_CXXFLAGS_APPEND="-I$wolfssl_dev_dir/usr/include -I$openssl_dev_dir/usr/include"
    export DEB_LDFLAGS_APPEND="-L$wolfssl_dev_dir/usr/lib/$DEB_HOST_MULTIARCH -L$openssl_dev_dir/usr/lib/$DEB_HOST_MULTIARCH"
    export PKG_CONFIG_LIBDIR=$wolfssl_dev_dir/usr/lib/$DEB_HOST_MULTIARCH/pkgconfig:$openssl_dev_dir/usr/lib/$DEB_HOST_MULTIARCH/pkgconfig
    debian/install-wolfprov.sh $WOLFPROV_OPTS --no-install $DEB_OUTPUT_DIR

    printf "Debian packages built in: %s\n" $DEB_OUTPUT_DIR

    exit 0
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
