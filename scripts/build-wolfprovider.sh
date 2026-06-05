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
  echo "  --enable-fips-baseline     Apply FIPS baseline patch to OpenSSL (removes many algorithms, bypasses FIPS POST)"
  echo "                             Note: Mutually exclusive with --replace-default. For testing only."
  echo "  --leave-silent             Enable leave silent mode to suppress logging of return 0 in probing functions where expected failures may occur."
  echo "                             Note: This only affects logging; the calling function is still responsible for handling all return values appropriately."
  echo "  --debug-silent             Debug logging compiled in but silent by default. Use WOLFPROV_LOG_LEVEL and WOLFPROV_LOG_COMPONENTS env vars to enable at runtime. Requires --debug."
  echo "  --enable-seed-src          Enable SEED-SRC entropy source with /dev/urandom caching for fork-safe entropy."
  echo "                             Note: This also enables WC_RNG_SEED_CB in wolfSSL."
  echo "  --enable-pqc               Enable both ML-KEM and ML-DSA (requires wolfSSL master/v5.9.2+ and OpenSSL 3.6+)."
  echo "  --enable-mlkem             Enable ML-KEM only."
  echo "  --enable-mldsa             Enable ML-DSA only."
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
  echo "  WOLFPROV_FIPS_BASELINE     If set to 1, applies FIPS baseline patch to OpenSSL (mutually exclusive with WOLFPROV_REPLACE_DEFAULT)"
  echo "  WOLFPROV_LEAVE_SILENT      If set to 1, suppress logging of return 0 in functions where return 0 is expected behavior sometimes."
  echo "  WOLFPROV_SEED_SRC          If set to 1, enables SEED-SRC with /dev/urandom caching (also enables WC_RNG_SEED_CB in wolfSSL)"
  echo "  WOLFPROV_PQC               If set to 1, enables both ML-KEM and ML-DSA (requires wolfSSL master/v5.9.2+ and OpenSSL 3.6+)"
  echo "  WOLFPROV_MLKEM             If set to 1, enables ML-KEM only"
  echo "  WOLFPROV_MLDSA             If set to 1, enables ML-DSA only"
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
        --enable-fips-baseline)
            WOLFPROV_FIPS_BASELINE=1
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
        --enable-pqc)
            WOLFPROV_MLKEM=1
            WOLFPROV_MLDSA=1
            ;;
        --enable-mlkem)
            WOLFPROV_MLKEM=1
            ;;
        --enable-mldsa)
            WOLFPROV_MLDSA=1
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

# Check for mutual exclusivity between replace-default and fips-baseline
if [ "$WOLFPROV_REPLACE_DEFAULT" = "1" ] && [ "$WOLFPROV_FIPS_BASELINE" = "1" ]; then
    echo "Error: --replace-default and --enable-fips-baseline are mutually exclusive."
    echo "       Choose one or the other, not both."
    exit 1
fi

# Normalize the PQC flags before any build path reads them. WOLFPROV_PQC is the
# legacy "both algorithms" switch (also a documented env var); WOLFPROV_MLKEM /
# WOLFPROV_MLDSA are the per-algorithm switches. Keep them consistent in both
# directions so either form works.
if [ "$WOLFPROV_PQC" = "1" ]; then
    WOLFPROV_MLKEM=1
    WOLFPROV_MLDSA=1
fi
if [ "$WOLFPROV_MLKEM" = "1" ] || [ "$WOLFPROV_MLDSA" = "1" ]; then
    WOLFPROV_PQC=1
fi

# The Debian package path builds against the distribution OpenSSL (bookworm
# ships 3.0.x), which has no ML-KEM/ML-DSA and is far below the 3.6 PQC floor,
# so a PQC package cannot compile. Reject it up front rather than producing a
# broken build. Once Debian ships OpenSSL 3.6+, PQC support here is a small
# addition: forward the per-algorithm flags through install-wolfprov.sh and
# debian/rules (mirroring the --debug/--fips flags).
if [ -n "$build_debian" ] && [ "$WOLFPROV_PQC" = "1" ]; then
    echo "ERROR: PQC (--enable-pqc/--enable-mlkem/--enable-mldsa) is not supported with --debian; the distro OpenSSL is older than the required 3.6+."
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
    # PQC is rejected above for the Debian path (distro OpenSSL is < 3.6).

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

# PQC needs newer wolfSSL/OpenSSL than the repo defaults, so when PQC is
# requested and the user has not pinned a version, default to PQC-capable ones
# (the version gate below still enforces the floors for explicit pins).
if [ "$WOLFPROV_PQC" = "1" ]; then
    if [ -z "$WOLFSSL_TAG" ]; then
        WOLFSSL_TAG=master
        echo "PQC: defaulting WOLFSSL_TAG=master"
    fi
    if [ -z "$OPENSSL_TAG" ]; then
        OPENSSL_TAG=openssl-3.6.0
        echo "PQC: defaulting OPENSSL_TAG=openssl-3.6.0"
    fi
fi

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
LOG_FILE=${SCRIPT_DIR}/build-release.log
source ${SCRIPT_DIR}/utils-wolfprovider.sh

echo "Using openssl: $OPENSSL_TAG, wolfssl: $WOLFSSL_TAG"

# ML-KEM / ML-DSA need the wolfSSL FIPS 203/204 seed and message APIs that land
# after v5.9.1-stable, and the matching OpenSSL provider params that arrive in
# 3.6. Refuse PQC on older releases so the failure is an explicit message, not
# an opaque missing-symbol build error. master and non -stable wolfSSL refs
# (branches/commits) are assumed new enough.
# 'sort -V' is GNU-only; on a host without it skip the gate (a compile-time
# guard in settings.h still rejects too-old versions) rather than misfiring.
if [ "$WOLFPROV_PQC" = "1" ] && ! printf '1\n2\n' | sort -V >/dev/null 2>&1; then
    echo "WARNING: 'sort -V' unavailable; skipping PQC version check (compile-time guard still applies)."
elif [ "$WOLFPROV_PQC" = "1" ]; then
    PQC_MIN_WOLFSSL="v5.9.2-stable"
    case "$WOLFSSL_TAG" in
        v*-stable)
            if [ "$(printf '%s\n%s\n' "$PQC_MIN_WOLFSSL" "$WOLFSSL_TAG" \
                    | sort -V | head -n1)" != "$PQC_MIN_WOLFSSL" ]; then
                echo "ERROR: ML-KEM/ML-DSA require wolfSSL master or ${PQC_MIN_WOLFSSL} or higher (got ${WOLFSSL_TAG})."
                exit 1
            fi
            ;;
    esac
    PQC_MIN_OPENSSL="openssl-3.6.0"
    case "$OPENSSL_TAG" in
        openssl-3.*)
            if [ "$(printf '%s\n%s\n' "$PQC_MIN_OPENSSL" "$OPENSSL_TAG" \
                    | sort -V | head -n1)" != "$PQC_MIN_OPENSSL" ]; then
                echo "ERROR: ML-KEM/ML-DSA require ${PQC_MIN_OPENSSL} or higher (got ${OPENSSL_TAG})."
                exit 1
            fi
            ;;
    esac
fi

init_wolfprov

exit $?
