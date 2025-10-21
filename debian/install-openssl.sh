#!/bin/bash
#
# Copyright (C) 2006-2025 wolfSSL Inc.
#
# This file is part of wolfProvider.
#
# wolfProvider is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# wolfProvider is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with wolfProvider. If not, see <http://www.gnu.org/licenses/>.

# Script to install openSSL packages for Debian
# Clones from Debian repository and builds from source

set -e

REPO_ROOT=${GITHUB_WORKSPACE:-$(git rev-parse --show-toplevel)}

openssl_clone() {
    local debian_version=${1:-bookworm}

    printf "\tDownloading OpenSSL from Debian for $debian_version\n"
    # Check if "deb-src" is in the sources.list, which allows us to 
    # grab the source from Debian.
    if [ -f /etc/apt/sources.list ] && grep -q "deb-src" /etc/apt/sources.list; then
        printf "\tDebian sources.list already contains deb-src\n"
    else
        printf "\tAdding deb-src to sources.list\n"
        echo "deb-src http://deb.debian.org/debian ${debian_version} main" >> /etc/apt/sources.list
        echo "deb-src http://deb.debian.org/debian-security ${debian_version}-security main" >> /etc/apt/sources.list
        echo "deb-src http://deb.debian.org/debian ${debian_version}-updates main" >> /etc/apt/sources.list
    fi

    apt update
    apt-get source -t ${debian_version} openssl

    openssl_dir=$(ls -td openssl-* | head -n 1)
    printf "OpenSSL source directory: $openssl_dir\n"
    cd $openssl_dir
}

openssl_patch_version() {
    local replace_default=${1:-0}
    printf "\tPatching OpenSSL version"
    # Patch the OpenSSL version with our BUILD_METADATA
    if [ "$replace_default" = "1" ]; then
        sed -i 's/BUILD_METADATA=.*/BUILD_METADATA=wolfProvider-replace-default/g' VERSION.dat
    else
        sed -i 's/BUILD_METADATA=.*/BUILD_METADATA=wolfProvider/g' VERSION.dat
    fi
    # Patch the OpenSSL RELEASE_DATE field with the current date in the format DD MMM YYYY
    sed -i "s/RELEASE_DATE=.*/RELEASE_DATE=$(date '+%d %b %Y')/g" VERSION.dat
}

openssl_is_patched() {
    # Return 0 if patched, 1 if not
    local file="crypto/provider_predefined.c"

    # File must exist to be patched
    [[ -f "$file" ]] || return 1

    # Any time we see libwolfprov, we're patched
    if grep -q 'libwolfprov' -- "$file"; then
        return 0
    fi

    # Not patched
    return 1
}

openssl_patch() {
    local replace_default=${1:-0}

    if openssl_is_patched; then
        printf "\tOpenSSL already patched\n"
    elif [ "$replace_default" = "1" ]; then
        printf "\tApplying OpenSSL default provider patch ... "

        # Apply the patch
        patch -p1 < ${REPO_ROOT}/patches/openssl3-replace-default.patch
        if [ $? != 0 ]; then
            printf "ERROR.\n"
            printf "\n\nPatch application failed.\n"
            exit 1
        fi
    fi
    # Patch the OpenSSL version with our metadata
    openssl_patch_version $replace_default

    DEBFULLNAME="${DEBFULLNAME:-WolfSSL Developer}" DEBEMAIL="${DEBEMAIL:-support@wolfssl.com}" dch -l +wolfprov "Adjust VERSION.dat for custom build"
    DEBIAN_FRONTEND=noninteractive EDITOR=true dpkg-source --commit . adjust-version-dat
}

openssl_build() {
    DEB_BUILD_OPTIONS="parallel=$(nproc) nocheck" dpkg-buildpackage -us -uc
}

openssl_install() {
    # Install all packages in the parent directory
    for file in ../*.deb; do
        if [ -f "$file" ]; then
            packages+=("$file")
        fi
    done

    if [ ${#packages[@]} -eq 0 ]; then
        echo "No packages found in parent directory"
        exit 1
    fi

    printf "Installing packages:\n"
    printf "\t%s\n" "${packages[@]}"
    dpkg -i --force-overwrite ${packages[@]}
}

main() {
    local replace_default=0
    local no_install=0
    local work_dir=
    local output_dir=

    # Parse command line arguments
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --replace-default)
                replace_default=1
                shift
                ;;
            --no-install)
                no_install=1
                shift
                ;;
            -h|--help)
                echo "Usage: $0 [options]"
                echo "  --replace-default      Apply patch to replace default provider"
                echo "  --no-install           Build only, do not install packages"
                echo "  -h, --help             Show this help message"
                echo "Arguments:"
                echo "  output-directory       Directory to to store built packages (default: mktemp -d)"
                exit 0
                ;;
            --)
                shift
                break
                ;;
            *)
                if [ -z "$output_dir" ]; then
                    output_dir=$1
                else
                    echo "Too many arguments" >&2
                    echo "Use --help for usage information" >&2
                    exit 1
                fi
                shift
                ;;
        esac
    done

    if [ $replace_default -eq 0 ] && [ $no_install -eq 0 ]; then
        printf "Using standard OpenSSL build\n"
        apt install -y --reinstall --allow-downgrades --allow-change-held-packages \
            openssl libssl3 libssl-dev
        exit 0
    fi

    if [ -n "output_dir" ]; then
        output_dir=$(realpath $output_dir)
    fi

    work_dir=$(mktemp -d)
    printf "Working directory: $work_dir\n"
    pushd $work_dir 2>&1 > /dev/null

    openssl_clone
    openssl_patch $replace_default
    openssl_build

    if [ $no_install -eq 0 ]; then
        openssl_install
    fi

    if [ -n "$output_dir" ]; then
        if [ ! -d "$output_dir" ]; then
            printf "Creating output directory: $output_dir\n"
            mkdir -p "$output_dir"
        fi
        cp ../openssl*.deb $output_dir || true
        cp ../libssl*.deb $output_dir || true
    else
        printf "No output directory specified, packages stored in $work_dir\n"
    fi

    printf "Done.\n"
}

# Run main function with all arguments
main "$@"
