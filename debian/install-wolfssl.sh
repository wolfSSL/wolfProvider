#!/bin/bash

# Script to install wolfSSL packages for Debian
# Clones from git repository and builds from source

set -e

# Function to check if packages are already installed
check_packages_installed() {
    if dpkg -l | grep -q "^ii.*libwolfssl " && dpkg -l | grep -q "^ii.*libwolfssl-dev "; then
        echo "libwolfssl and libwolfssl-dev packages are already installed"
        dpkg -l | grep wolfssl
        return 0
    else
        return 1
    fi
}

# Function to install wolfSSL packages from git
install_wolfssl_from_git() {
    local work_dir="$1"
    local git_tag="$2"
    local debug_mode="$3"
    local reinstall_mode="$4"

    # If no working directory specified, create one using mktemp
    if [ -z "$work_dir" ]; then
        work_dir=$(mktemp -d)
        echo "No working directory specified, created temporary directory: $work_dir"
    else
        echo "Using specified working directory: $work_dir"
        # Create the directory if it doesn't exist
        mkdir -p "$work_dir"
    fi

    echo "Working directory: $work_dir"
    cd "$work_dir"

    # Check if wolfSSL directory already exists
    if [ -d "wolfssl" ]; then
        echo "Found existing wolfSSL directory, using it..."
        cd wolfssl

        # If a specific tag is requested, checkout that tag
        if [ -n "$git_tag" ]; then
            echo "Checking out tag/branch: $git_tag"
            git fetch --tags
            git checkout "$git_tag"
        else
            echo "Using existing wolfSSL version"
        fi
    else
        # Clone wolfSSL repository
        echo "Cloning wolfSSL repository..."
        if [ -n "$git_tag" ]; then
            echo "Cloning specific tag/branch: $git_tag"
            git clone https://github.com/LinuxJedi/wolfssl
            cd wolfssl
            #git checkout "$git_tag"
            git checkout fix-deb-builds
        else
            echo "Cloning master branch with depth 1"
            git clone https://github.com/LinuxJedi/wolfssl --depth 1
            cd wolfssl
            git checkout fix-deb-builds
        fi
    fi

    # Check if debian/rules.in exists, if not, we need to backport debian packaging
    if [ ! -f "debian/rules.in" ]; then
        echo "debian/rules.in not found, backporting debian packaging from master..."

        # Save current branch/tag
        current_ref=$(git rev-parse HEAD)

        # Create a temporary directory for master checkout
        temp_master_dir=$(mktemp -d)
        cd "$temp_master_dir"

        echo "Cloning master branch to get debian directory..."
        git clone https://github.com/wolfSSL/wolfssl master-checkout
        cd master-checkout

        # Copy debian directory to our working wolfssl
        echo "Copying debian directory from master..."
        cp -r debian "$work_dir/wolfssl/"

        # Go back to our working wolfssl directory
        cd "$work_dir/wolfssl"

        # Clean up temporary directory
        rm -rf "$temp_master_dir"

        # Patch configure.ac to add required substitutions for debian packaging
        echo "Patching configure.ac for debian packaging compatibility..."

        # Check if the patch is already applied
        if ! grep -q "CONFIGURE_OPTIONS=" configure.ac; then
            # Find the location to insert the new lines (before AC_OUTPUT or at the end)
            if grep -q "AC_OUTPUT" configure.ac; then
                # Insert before AC_OUTPUT
                sed -i '/^AC_OUTPUT/i \
CONFIGURE_OPTIONS="$ac_configure_args"\
CONFIGURE_CFLAGS="$CFLAGS"\
AC_SUBST([CONFIGURE_OPTIONS])\
AC_SUBST([CONFIGURE_CFLAGS])\
AC_CONFIG_FILES([debian/rules],[chmod +x debian/rules])' configure.ac
            else
                # Append at the end
                echo 'CONFIGURE_OPTIONS="$ac_configure_args"' >> configure.ac
                echo 'CONFIGURE_CFLAGS="$CFLAGS"' >> configure.ac
                echo 'AC_SUBST([CONFIGURE_OPTIONS])' >> configure.ac
                echo 'AC_SUBST([CONFIGURE_CFLAGS])' >> configure.ac
                echo 'AC_CONFIG_FILES([debian/rules],[chmod +x debian/rules])' >> configure.ac
            fi
            echo "configure.ac patched successfully"
        else
            echo "configure.ac already contains required patches"
        fi

        # Patch debian/rules.in to disable dh_strip
        echo "Patching debian/rules.in to disable dh_strip..."
        sed -i 's/^[[:space:]]*dh_strip.*/:/' debian/rules.in
        echo "debian/rules.in patched successfully"
        
    else
        echo "debian/rules.in found, using existing debian packaging"
    fi

    # Run autogen.sh
    echo "Running autogen.sh..."
    ./autogen.sh

    # Comment out part of test that fails with option -DACVP_VECTOR_TESTING
    # This is because ACVP_VECTOR_TESTING disables the erasing of output if
    # authTag check fails. But the test is checking for the erasure.
    echo "Fixing test.c for DACVP_VECTOR_TESTING compatibility..."
    sed -i "/^[[:space:]]*if (XMEMCMP(p2, c2, sizeof(p2)))/{ s/^[[:space:]]*/&\/\/ /; n; s/^[[:space:]]*/&\/\/ /; }" wolfcrypt/test/test.c

    # Configure with the specified options
    echo "Configuring wolfSSL with specified options..."
    configure_opts="--enable-opensslcoexist \
        --enable-cmac \
        --with-eccminsz=192 \
        --enable-ed25519 \
        --enable-ed448 \
        --enable-md5 \
        --enable-curve25519 \
        --enable-curve448 \
        --enable-aesccm \
        --enable-aesxts \
        --enable-aescfb \
        --enable-keygen \
        --enable-shake128 \
        --enable-shake256 \
        --enable-wolfprovider \
        --enable-rsapss \
        --enable-scrypt"

    if [ "$debug_mode" = "true" ]; then
        configure_opts="$configure_opts --enable-debug"
        echo "Debug mode enabled"
    fi

    ./configure $configure_opts \
        CFLAGS="-DWOLFSSL_OLD_OID_SUM \
            -DWOLFSSL_PUBLIC_ASN \
            -DHAVE_FFDHE_3072 \
            -DHAVE_FFDHE_4096 \
            -DWOLFSSL_DH_EXTRA \
            -DWOLFSSL_PSS_SALT_LEN_DISCOVER \
            -DWOLFSSL_PUBLIC_MP \
            -DWOLFSSL_RSA_KEY_CHECK \
            -DHAVE_FFDHE_Q \
            -DHAVE_FFDHE_6144 \
            -DHAVE_FFDHE_8192 \
            -DWOLFSSL_ECDSA_DETERMINISTIC_K \
            -DWOLFSSL_VALIDATE_ECC_IMPORT \
            -DRSA_MIN_SIZE=1024 \
            -DHAVE_AES_ECB \
            -DWC_RSA_DIRECT \
            -DWC_RSA_NO_PADDING \
            -DACVP_VECTOR_TESTING \
            -DWOLFSSL_ECDSA_SET_K" \
            LIBS="-lm"

    # Build Debian packages
    echo "Building Debian packages..."
    make deb

    # Install the generated packages
    echo "Installing generated .deb packages..."
    if [ "$reinstall_mode" = "true" ]; then
        echo "Reinstall mode: forcing package reinstallation..."
        dpkg -i --force-overwrite --force-confnew ../*.deb
    else
        dpkg -i ../*.deb
    fi

    echo "WolfSSL installation from git completed successfully"
}

# Main execution
main() {
    local work_dir=""
    local git_tag=""
    local debug_mode="false"
    local reinstall_mode="false"

    # Parse command line arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                echo "Usage: $0 [options] [working-directory]"
                echo "  Installs wolfSSL from git repository by cloning, configuring, and building .deb packages"
                echo ""
                echo "Options:"
                echo "  -t, --tag TAG        Clone and build specific tag or branch (default: master)"
                echo "  -d, --debug          Enable debug build mode (adds --enable-debug)"
                echo "  -r, --reinstall      Force reinstall even if packages are already installed"
                echo "  -h, --help          Show this help message"
                echo ""
                echo "Arguments:"
                echo "  working-directory   Directory to use for build (default: temporary directory)"
                echo ""
                echo "Examples:"
                echo "  $0                           # Build master in temp directory"
                echo "  $0 /tmp/build               # Build master in /tmp/build"
                echo "  $0 --tag v5.6.4            # Build tag v5.6.4 in temp directory"
                echo "  $0 --tag v5.6.4 /tmp/build # Build tag v5.6.4 in /tmp/build"
                echo "  $0 --debug                 # Build master with debug enabled"
                echo "  $0 --debug --tag v5.6.4    # Build tag v5.6.4 with debug enabled"
                echo "  $0 --reinstall             # Force reinstall even if packages exist"
                exit 0
                ;;
            -t|--tag)
                git_tag="$2"
                shift 2
                ;;
            -d|--debug)
                debug_mode="true"
                shift
                ;;
            -r|--reinstall)
                reinstall_mode="true"
                shift
                ;;
            -*)
                echo "Unknown option: $1" >&2
                echo "Use --help for usage information" >&2
                exit 1
                ;;
            *)
                if [ -z "$work_dir" ]; then
                    work_dir="$1"
                else
                    echo "Too many arguments" >&2
                    echo "Use --help for usage information" >&2
                    exit 1
                fi
                shift
                ;;
        esac
    done

    # Only check if packages are installed if not in reinstall mode
    if [ "$reinstall_mode" = "false" ]; then
        echo "Checking if wolfSSL packages are already installed..."
        if check_packages_installed; then
            echo "Packages already installed, exiting successfully"
            exit 0
        fi
    else
        echo "Reinstall mode enabled, bypassing package check..."
    fi

    echo "Installing wolfSSL packages from git repository..."
    if [ -n "$git_tag" ]; then
        echo "Building wolfSSL tag/branch: $git_tag"
    else
        echo "Building wolfSSL master branch"
    fi

    install_wolfssl_from_git "$work_dir" "$git_tag" "$debug_mode" "$reinstall_mode"

    echo "WolfSSL installation completed successfully"
}

# Run main function with all arguments
main "$@"
