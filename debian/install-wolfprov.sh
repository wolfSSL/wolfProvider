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
set -euo pipefail

PKG_NAME="libwolfprov"
REPO_ROOT=${GITHUB_WORKSPACE:-$(git rev-parse --show-toplevel)}

wolfprov_build() {
    local WOLFSSL_ISFIPS=${1:-0}
    local WOLFPROV_DEBUG=${2:-0}

    printf "Running wolfprov_build with WOLFSSL_ISFIPS=$WOLFSSL_ISFIPS and WOLFPROV_DEBUG=$WOLFPROV_DEBUG\n"

    export WOLFSSL_ISFIPS
    export WOLFPROV_DEBUG

    # Step 1: Determine the repo root
    REPO_ROOT=${GITHUB_WORKSPACE:-$(git rev-parse --show-toplevel)}
    cd "$REPO_ROOT"

    # Step 2: Determine version from debian/changelog (no tag checks)
    if [[ ! -f debian/changelog ]]; then
    echo "❌ Error: debian/changelog not found."
    echo "👉 Run scripts/debian-changelog-update.sh to create/update the changelog first."
    exit 1
    fi

    VERSION=$(dpkg-parsechangelog --show-field Version)
    UPSTREAM_VERSION="${VERSION%%-*}"
    current_commit=$(git rev-parse HEAD)
    echo "📌 Using version from changelog: $VERSION (upstream: $UPSTREAM_VERSION)"

    TARBALL="${PKG_NAME}_${UPSTREAM_VERSION}.orig.tar.gz"
    TARBALL_PREFIX="${PKG_NAME}-${UPSTREAM_VERSION}"

    # Step 5: Warn if not on master
    current_branch=$(git rev-parse --abbrev-ref HEAD)
    if [[ "$current_branch" != "master" ]]; then
    echo "⚠️  Warning: On branch '$current_branch', not 'master'"
    fi

    # Step 6: Check for uncommitted changes
    if ! git diff --quiet || ! git diff --cached --quiet; then
    echo "⚠️  Error: Uncommitted changes in working tree:"
    git status --short
    exit 1
    fi

    # Step 7: Clean untracked files
    echo "🧹 Cleaning untracked files..."
    $REPO_ROOT/scripts/build-wolfprovider.sh --distclean
    git clean -fdx

    # Step 8: Changelog updates handled by scripts/debian-changelog-update.sh

    # Step 9: Create tarball
    if [[ -f "../$TARBALL" ]]; then
    echo "🗑️ Removing existing tarball: $TARBALL"
    rm -f "../$TARBALL"
    fi
    echo "📦 Creating tarball $TARBALL from commit $current_commit..."
    git archive --format=tar.gz --prefix="${TARBALL_PREFIX}/" \
        -o "../$TARBALL" "$current_commit"

    # Step 9.1: Set up ccache if installed
    # Optional ccache
    if command -v ccache >/dev/null 2>&1; then
    export CC="ccache gcc"
    export CXX="ccache g++"
    else
    export CC="gcc"
    export CXX="g++"
    fi

    # Optional tuning (safe if unset)
    : "${CCACHE_DIR:=}"
    : "${CCACHE_BASEDIR:=}"
    : "${CCACHE_NOHASHDIR:=}"
    : "${CCACHE_SLOPPINESS:=}"
    CCACHE_COMPILERCHECK=${CCACHE_COMPILERCHECK:-content}

    # Step 10: Build package with optional ccache (if installed)
    echo "⚙️  Building package..."
    WOLFSSL_ISFIPS=${WOLFSSL_ISFIPS:-0}
    dpkg-buildpackage -us -uc \
    -eWOLFSSL_ISFIPS \
    -eCC -eCXX \
    -eCCACHE_DIR -eCCACHE_BASEDIR -eCCACHE_NOHASHDIR -eCCACHE_COMPILERCHECK

    echo "✅ Build completed for version $VERSION"
}

wolfprov_install() {
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

# Main execution
main() {
    local debug_mode=0
    local fips_mode=0
    local no_install=0
    local output_dir=

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
                echo "  -f, --fips           Enable FIPS build mode (adds --enable-fips)"
                echo "  -n, --no-install     Build only, do not install packages"
                echo "  -h, --help           Show this help message"
                echo ""
                echo "Arguments:"
                echo "  output-directory   Directory to use for build (default: temporary directory)"
                exit 0
                ;;
            -d|--debug)
                debug_mode=1
                shift
                ;;
            -f|--fips)
                fips_mode=1
                shift
                ;;
            -n|--no-install)
                no_install=1
                shift
                ;;
            *)
                if [ -z "$output_dir" ]; then
                    output_dir="$1"
                else
                    echo "Too many arguments" >&2
                    echo "Use --help for usage information" >&2
                    exit 1
                fi
                shift
                ;;
        esac
    done

    # Check for any existing packages in the parent directory.
    # These would conflict with the install.
    existing_packages=()
    for file in $output_dir/libwolfprov*.deb; do
        if [ -f "$file" ]; then
            existing_packages+=("$file")
        fi
    done
    if [ ${#existing_packages[@]} -gt 0 ]; then
        echo "Error: libwolfprov*.deb already exists in output directory, please remove them first"
        echo "Existing packages: ${existing_packages[@]}"
        exit 1
    fi

    work_dir=$(mktemp -d)
    printf "Working directory: $work_dir\n"
    pushd $work_dir 2>&1 > /dev/null
    cp -r $REPO_ROOT .
    cd $(basename $REPO_ROOT)

    wolfprov_build $fips_mode $debug_mode
    if [ $no_install -eq 0 ]; then
        wolfprov_install
    fi

    if [ -n "$output_dir" ] && [ "$output_dir" != ".." ]; then
        if [ ! -d "$output_dir" ]; then
            printf "Creating output directory: $output_dir\n"
            mkdir -p "$output_dir"
        fi
        cp ../*.* $output_dir
    else
        printf "No output directory specified, packages stored in $work_dir\n"
    fi

    printf "Done.\n"
}

# Run main function with all arguments
main "$@"

