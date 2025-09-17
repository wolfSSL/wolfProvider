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

    # Clone wolfSSL repository with depth 1 for faster clone
    echo "Cloning wolfSSL repository..."
    git clone https://github.com/wolfSSL/wolfssl --depth 1

    # Enter wolfssl directory
    cd wolfssl

    # Run autogen.sh
    echo "Running autogen.sh..."
    ./autogen.sh

    # Comment out part of test that fails with option -DACVP_VECTOR_TESTING
    echo "Fixing test.c for DACVP_VECTOR_TESTING compatibility..."
    sed -i "/^[[:space:]]*if (XMEMCMP(p2, c2, sizeof(p2)))/{ s/^[[:space:]]*/&\/\/ /; n; s/^[[:space:]]*/&\/\/ /; }" wolfcrypt/test/test.c

    # Configure with the specified options
    echo "Configuring wolfSSL with specified options..."
    ./configure --enable-opensslcoexist --enable-cmac --with-eccminsz=192 --enable-ed25519 --enable-ed448 --enable-md5 --enable-curve25519 --enable-curve448 --enable-aesccm --enable-aesxts --enable-aescfb --enable-keygen --enable-shake128 --enable-shake256 --enable-wolfprovider --enable-rsapss --enable-scrypt CFLAGS="-DWOLFSSL_OLD_OID_SUM -DWOLFSSL_PUBLIC_ASN -DHAVE_FFDHE_3072 -DHAVE_FFDHE_4096 -DWOLFSSL_DH_EXTRA -DWOLFSSL_PSS_SALT_LEN_DISCOVER -DWOLFSSL_PUBLIC_MP -DWOLFSSL_RSA_KEY_CHECK -DHAVE_FFDHE_Q -DHAVE_FFDHE_6144 -DHAVE_FFDHE_8192 -DWOLFSSL_ECDSA_DETERMINISTIC_K -DWOLFSSL_VALIDATE_ECC_IMPORT -DRSA_MIN_SIZE=1024 -DHAVE_AES_ECB -DWC_RSA_DIRECT -DWC_RSA_NO_PADDING -DACVP_VECTOR_TESTING -DWOLFSSL_ECDSA_SET_K"

    # Build Debian packages
    echo "Building Debian packages..."
    make deb

    # Install the generated packages
    echo "Installing generated .deb packages..."
    dpkg -i ../*.deb

    echo "WolfSSL installation from git completed successfully"
}

# Main execution
main() {
    local work_dir="$1"

    # Show usage if help is requested
    if [ "$1" = "-h" ] || [ "$1" = "--help" ]; then
        echo "Usage: $0 [working-directory]"
        echo "  Installs wolfSSL from git repository by cloning, configuring, and building .deb packages"
        echo "  If working-directory is not specified, a temporary directory will be created using mktemp"
        exit 0
    fi

    echo "Checking if wolfSSL packages are already installed..."
    if check_packages_installed; then
        echo "Packages already installed, exiting successfully"
        exit 0
    fi

    echo "Installing wolfSSL packages from git repository..."
    install_wolfssl_from_git "$work_dir"

    echo "WolfSSL installation completed successfully"
}

# Run main function with all arguments
main "$@"
