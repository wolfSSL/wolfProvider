#!/bin/bash

# Script to install wolfSSL packages for Debian
# Checks if packages are already installed and installs appropriate architecture-specific packages

set -e

# Function to check if packages are installed
check_packages_installed() {
    if dpkg -l | grep -q "^ii.*libwolfssl " && dpkg -l | grep -q "^ii.*libwolfssl-dev "; then
        echo "libwolfssl and libwolfssl-dev packages are already installed"
        dpkg -l | grep wolfssl
        return 0
    else
        return 1
    fi
}

# Function to install wolfSSL packages
install_wolfssl_packages() {
    local wolfssl_tar_path="$1"
    local dest_dir="$2"
    
    if [ ! -f "$wolfssl_tar_path" ]; then
        echo "Error: wolfSSL package archive not found at $wolfssl_tar_path"
        exit 1
    fi
    
    # If no destination directory specified, create one using mktemp
    if [ -z "$dest_dir" ]; then
        dest_dir=$(mktemp -d)
        echo "No destination directory specified, created temporary directory: $dest_dir"
    else
        echo "Using specified destination directory: $dest_dir"
        # Create the directory if it doesn't exist
        mkdir -p "$dest_dir"
    fi
    
    echo "Extracting wolfSSL package to: $dest_dir"
    tar -xvf "$wolfssl_tar_path" -C "$dest_dir"

    # Get current architecture
    CURRENT_ARCH=$(dpkg --print-architecture)
    echo "Current architecture: $CURRENT_ARCH"
    
    # Look for existing .deb files that match the current architecture
    cd "$dest_dir/debian-packages"
    MATCHING_DEB_FILES=$(find . -name "*_${CURRENT_ARCH}.deb" -o -name "*_${CURRENT_ARCH}_*.deb" 2>/dev/null || true)
    
    if [ -n "$MATCHING_DEB_FILES" ]; then
        echo "Found matching .deb files for architecture $CURRENT_ARCH:"
        echo "$MATCHING_DEB_FILES"
        echo "Installing existing .deb files..."
        
        # Install both libwolfssl and libwolfssl-dev packages for the current architecture
        LIBWOLFSSL_DEB=$(echo "$MATCHING_DEB_FILES" | grep "libwolfssl_[^-]" | head -n1)
        LIBWOLFSSL_DEV_DEB=$(echo "$MATCHING_DEB_FILES" | grep "libwolfssl-dev_" | head -n1)
        
        if [ -n "$LIBWOLFSSL_DEB" ]; then
            echo "Installing libwolfssl package: $LIBWOLFSSL_DEB"
            dpkg -i "$LIBWOLFSSL_DEB"
        else
            echo "No libwolfssl package found for architecture $CURRENT_ARCH"
            exit 1
        fi
        
        if [ -n "$LIBWOLFSSL_DEV_DEB" ]; then
            echo "Installing libwolfssl-dev package: $LIBWOLFSSL_DEV_DEB"
            dpkg -i "$LIBWOLFSSL_DEV_DEB"
        else
            echo "No libwolfssl-dev package found for architecture $CURRENT_ARCH"
            exit 1
        fi
    else
        echo "No matching .deb files found for architecture $CURRENT_ARCH, rebuilding from source..."
        dpkg-source -x wolfssl*.dsc
        cd wolfssl*/
        dpkg-buildpackage -b -us -uc
        
        # Install both libwolfssl and libwolfssl-dev packages
        LIBWOLFSSL_DEB=$(find .. -name "libwolfssl_*${CURRENT_ARCH}.deb" | grep -v "dev" | head -n1)
        LIBWOLFSSL_DEV_DEB=$(find .. -name "libwolfssl-dev*_${CURRENT_ARCH}.deb" | head -n1)
        
        if [ -n "$LIBWOLFSSL_DEB" ]; then
            echo "Installing libwolfssl package: $LIBWOLFSSL_DEB"
            dpkg -i "$LIBWOLFSSL_DEB"
        else
            echo "No libwolfssl package found after building for architecture $CURRENT_ARCH"
            exit 1
        fi
        
        if [ -n "$LIBWOLFSSL_DEV_DEB" ]; then
            echo "Installing libwolfssl-dev package: $LIBWOLFSSL_DEV_DEB"
            dpkg -i "$LIBWOLFSSL_DEV_DEB"
        else
            echo "No libwolfssl-dev package found after building for architecture $CURRENT_ARCH"
            exit 1
        fi
    fi
}

# Main execution
main() {
    local wolfssl_tar_path="$1"
    local dest_dir="$2"
    
    if [ -z "$wolfssl_tar_path" ]; then
        echo "Usage: $0 <path-to-wolfssl-tar.gz> [destination-directory]"
        echo "  If destination-directory is not specified, a temporary directory will be created using mktemp"
        exit 1
    fi
    
    echo "Checking if wolfSSL packages are already installed..."
    if check_packages_installed; then
        echo "Packages already installed, exiting successfully"
        exit 0
    fi
    
    echo "Installing wolfSSL packages..."
    install_wolfssl_packages "$wolfssl_tar_path" "$dest_dir"
    
    echo "WolfSSL installation completed successfully"
}

# Run main function with all arguments
main "$@"
