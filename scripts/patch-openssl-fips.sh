#!/bin/bash
#
# Copyright (C) 2006-2024 wolfSSL Inc.
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
#

#
# Apply FIPS Baseline Patch to OpenSSL Source
#
# This script replaces OpenSSL provider files with versions that:
#   1. Remove many algorithm implementations from default/FIPS/legacy providers
#   2. Bypass FIPS POST (Power-On Self Test) for testing purposes
#
# This creates a minimal OpenSSL build suitable for wolfProvider FIPS baseline testing.
#

# Return codes
readonly RC_SUCCESS=0
readonly RC_INVALID_ARGS=1
readonly RC_PATCH_FAILED=6

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PATCHES_DIR="${SCRIPT_DIR}/../patches/openssl-fips-baseline"

# Default values
DEFAULT_FIPS_VERSION="v5.2.4"
OPENSSL_SRC=""
OPENSSL_VERSION=""
FIPS_VERSION=""
QUIET=0
DRY_RUN=0

# Output functions
log_info() {
    if [ "$QUIET" -eq 0 ]; then
        echo "$@"
    fi
}

log_error() {
    echo "ERROR: $@" >&2
}

log_warning() {
    if [ "$QUIET" -eq 0 ]; then
        echo "WARNING: $@"
    fi
}

# Usage information
usage() {
    cat << EOF
Usage: $(basename "$0") -s PATH [OPTIONS]

Apply FIPS baseline patch to OpenSSL source for wolfProvider testing.

Options:
  -s, --openssl-src=PATH    Path to OpenSSL source directory (required)
  -f, --fips-version=VER    FIPS version tag (default: $DEFAULT_FIPS_VERSION)
  -q, --quiet               Suppress non-error output
  -n, --dry-run             Show what would be done without making changes
  -h, --help                Show this help message

Environment variables:
  OPENSSL_SOURCE_DIR        Fallback for --openssl-src
  WOLFSSL_FIPS_CHECK_TAG    Fallback for --fips-version

Examples:
  $(basename "$0") -s /path/to/openssl
  $(basename "$0") -s /path/to/openssl --dry-run
EOF
    exit $RC_INVALID_ARGS
}

# Map FIPS version to family (v5, v6, ready)
map_fips_version_to_family() {
    local version="$1"
    case "$version" in
        v5.2.*|v5.3.*|v5.4.*|v5.5.*|linuxv5.*)
            echo "v5"
            return 0
            ;;
        v6.*|linuxv6.*)
            echo "v6"
            return 0
            ;;
        ready)
            echo "ready"
            return 0
            ;;
        *)
            echo "unknown"
            return 1
            ;;
    esac
}

# Validate FIPS version
validate_fips_version() {
    local version="$1"
    local family

    family=$(map_fips_version_to_family "$version")
    if [ $? -ne 0 ]; then
        log_error "Unsupported FIPS version: $version"
        log_error "Supported versions: v5.2.x, v5.3.x, v5.4.x, v5.5.x, linuxv5.x, v6.x, linuxv6.x, ready"
        return 1
    fi

    # Warn about v6 being a placeholder
    if [ "$family" = "v6" ]; then
        log_warning "FIPS v6 family is currently a placeholder - using v5 patches"
    fi

    return 0
}

# Check if OpenSSL is already patched with FIPS baseline
is_fips_baseline_patched() {
    local dir="$1"
    local file="${dir}/providers/fips/self_test.c"

    # File must exist
    [ -f "$file" ] || return 1

    # Check for distinctive FIPS baseline bypass comment
    if grep -q 'If already running, just return success' -- "$file"; then
        return 0
    fi

    return 1
}

# Parse command line arguments
parse_args() {
    # Use getopt for parsing
    local TEMP
    TEMP=$(getopt -o 's:f:qnh' \
        --long 'openssl-src:,fips-version:,quiet,dry-run,help' \
        -n "$(basename "$0")" -- "$@")

    if [ $? -ne 0 ]; then
        usage
    fi

    eval set -- "$TEMP"

    while true; do
        case "$1" in
            -s|--openssl-src)
                OPENSSL_SRC="$2"
                shift 2
                ;;
            -f|--fips-version)
                FIPS_VERSION="$2"
                shift 2
                ;;
            -q|--quiet)
                QUIET=1
                shift
                ;;
            -n|--dry-run)
                DRY_RUN=1
                shift
                ;;
            -h|--help)
                usage
                ;;
            --)
                shift
                break
                ;;
            *)
                log_error "Internal error parsing arguments"
                exit $RC_INVALID_ARGS
                ;;
        esac
    done

    # Fall back to environment variables if arguments not provided
    if [ -z "$OPENSSL_SRC" ]; then
        OPENSSL_SRC="${OPENSSL_SOURCE_DIR:-}"
    fi

    if [ -z "$FIPS_VERSION" ]; then
        FIPS_VERSION="${WOLFSSL_FIPS_CHECK_TAG:-$DEFAULT_FIPS_VERSION}"
    fi

    # Validate required arguments
    if [ -z "$OPENSSL_SRC" ]; then
        log_error "OpenSSL source directory is required"
        log_error "Use --openssl-src=PATH or set OPENSSL_SOURCE_DIR environment variable"
        echo ""
        usage
    fi
}

# Validate OpenSSL source directory
validate_openssl_dir() {
    # Check if directory exists
    if [ ! -d "$OPENSSL_SRC" ]; then
        log_error "OpenSSL source directory does not exist: $OPENSSL_SRC"
        return $RC_INVALID_ARGS
    fi

    # Check if it looks like an OpenSSL source tree
    if [ ! -f "$OPENSSL_SRC/Configure" ]; then
        log_error "Directory does not appear to be an OpenSSL source tree: $OPENSSL_SRC"
        log_error "(Configure script not found)"
        return $RC_INVALID_ARGS
    fi

    if [ ! -d "$OPENSSL_SRC/providers" ]; then
        log_error "providers/ directory not found in: $OPENSSL_SRC"
        return $RC_INVALID_ARGS
    fi

    return 0
}

# Detect OpenSSL version from source directory
# Sets global variable OPENSSL_VERSION (e.g., "3.5.4")
detect_openssl_version() {
    local version_file="$OPENSSL_SRC/VERSION.dat"

    if [ -f "$version_file" ]; then
        # OpenSSL 3.x uses VERSION.dat
        local major=$(grep "^MAJOR=" "$version_file" | cut -d= -f2)
        local minor=$(grep "^MINOR=" "$version_file" | cut -d= -f2)
        local patch=$(grep "^PATCH=" "$version_file" | cut -d= -f2)
        OPENSSL_VERSION="${major}.${minor}.${patch}"
    elif [ -f "$OPENSSL_SRC/include/openssl/opensslv.h" ]; then
        # Fallback: parse from opensslv.h (POSIX-compatible)
        local version_str=$(grep "OPENSSL_VERSION_TEXT" "$OPENSSL_SRC/include/openssl/opensslv.h" | head -1)
        OPENSSL_VERSION=$(echo "$version_str" | sed -n 's/.*\([0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*\).*/\1/p' | head -1)
    else
        OPENSSL_VERSION="unknown"
    fi
}

# Compare two version strings (returns 0 if v1 >= v2, 1 otherwise)
version_ge() {
    local v1="$1"
    local v2="$2"

    # Use sort -V for version comparison
    local higher=$(printf '%s\n%s\n' "$v1" "$v2" | sort -V | tail -n1)
    [ "$higher" = "$v1" ]
}

# Compare two version strings (returns 0 if v1 < v2, 1 otherwise)
version_lt() {
    local v1="$1"
    local v2="$2"

    # Use sort -V for version comparison
    local lower=$(printf '%s\n%s\n' "$v1" "$v2" | sort -V | head -n1)
    [ "$lower" = "$v1" ] && [ "$v1" != "$v2" ]
}

# Get the version range suffix for a restriction patch
# Usage: get_restriction_range <version> <restriction>
# Returns: "all-versions", "3.0.0-3.3.x", "3.4.0-3.5.2", "3.5.3+", etc.
get_restriction_range() {
    local version="$1"
    local restriction="$2"

    if [ "$version" = "unknown" ]; then
        # Default to latest for unknown versions
        case "$restriction" in
            rsa-min-modulus|provider-naming)
                echo "all-versions"
                ;;
            dh-ffdhe)
                echo "3.0.0+"
                ;;
            sha1-signing|ecdsa-sha1-signing)
                echo "3.5.3+"
                ;;
            ecdsa-key-size)
                echo "3.5.0+"
                ;;
            pbkdf2-password)
                echo "3.4.0+"
                ;;
        esac
        return
    fi

    case "$restriction" in
        rsa-min-modulus|provider-naming)
            echo "all-versions"
            ;;
        dh-ffdhe)
            # All supported versions (3.0.0+) use the same patch
            echo "3.0.0+"
            ;;
        sha1-signing|ecdsa-sha1-signing)
            if version_lt "$version" "3.4.0"; then
                echo "3.0.0-3.3.x"
            elif version_lt "$version" "3.5.3"; then
                echo "3.4.0-3.5.2"
            else
                echo "3.5.3+"
            fi
            ;;
        ecdsa-key-size)
            if version_lt "$version" "3.2.0"; then
                echo "3.0.0-3.1.x"
            elif version_lt "$version" "3.4.0"; then
                echo "3.2.0-3.3.x"
            elif version_lt "$version" "3.5.0"; then
                echo "3.4.0-3.4.x"
            else
                echo "3.5.0+"
            fi
            ;;
        pbkdf2-password)
            if version_lt "$version" "3.4.0"; then
                echo "3.0.0-3.3.x"
            else
                echo "3.4.0+"
            fi
            ;;
    esac
}

# Get the version range suffix for a provider file
# Usage: get_provider_range <version> <provider>
# Returns: "3.0.0-3.1.x", "3.2.0-3.3.x", "3.4.0-3.4.x", "3.5.0+", etc.
get_provider_range() {
    local version="$1"
    local provider="$2"

    if [ "$version" = "unknown" ]; then
        # Default to latest for unknown versions
        case "$provider" in
            defltprov|self_test)
                echo "3.5.0+"
                ;;
            legacyprov|fipsprov)
                echo "3.5.2+"
                ;;
        esac
        return
    fi

    case "$provider" in
        defltprov)
            if version_lt "$version" "3.2.0"; then
                echo "3.0.0-3.1.x"
            elif version_lt "$version" "3.4.0"; then
                echo "3.2.0-3.3.x"
            elif version_lt "$version" "3.5.0"; then
                echo "3.4.0-3.4.x"
            else
                echo "3.5.0+"
            fi
            ;;
        legacyprov|fipsprov)
            if version_lt "$version" "3.2.0"; then
                echo "3.0.0-3.1.x"
            elif version_lt "$version" "3.4.0"; then
                echo "3.2.0-3.3.x"
            elif version_lt "$version" "3.5.0"; then
                echo "3.4.0-3.4.x"
            elif version_lt "$version" "3.5.2"; then
                echo "3.5.0-3.5.1"
            else
                echo "3.5.2+"
            fi
            ;;
        self_test)
            if version_lt "$version" "3.5.0"; then
                echo "3.0.0-3.4.x"
            else
                echo "3.5.0+"
            fi
            ;;
    esac
}

# Apply file replacements (provider .c files)
apply_file_replacements() {
    log_info "Applying file replacements..."

    # Get version ranges for each provider
    local defltprov_range=$(get_provider_range "$OPENSSL_VERSION" "defltprov")
    local legacyprov_range=$(get_provider_range "$OPENSSL_VERSION" "legacyprov")
    local fipsprov_range=$(get_provider_range "$OPENSSL_VERSION" "fipsprov")
    local self_test_range=$(get_provider_range "$OPENSSL_VERSION" "self_test")

    # Source and destination mappings
    local src_files=(
        "$PATCHES_DIR/providers/defltprov/${defltprov_range}.c"
        "$PATCHES_DIR/providers/legacyprov/${legacyprov_range}.c"
        "$PATCHES_DIR/providers/fips/fipsprov/${fipsprov_range}.c"
        "$PATCHES_DIR/providers/fips/self_test/${self_test_range}.c"
    )

    local dest_files=(
        "$OPENSSL_SRC/providers/defltprov.c"
        "$OPENSSL_SRC/providers/legacyprov.c"
        "$OPENSSL_SRC/providers/fips/fipsprov.c"
        "$OPENSSL_SRC/providers/fips/self_test.c"
    )

    local range_info=(
        "defltprov/${defltprov_range}"
        "legacyprov/${legacyprov_range}"
        "fipsprov/${fipsprov_range}"
        "self_test/${self_test_range}"
    )

    for i in "${!src_files[@]}"; do
        local src="${src_files[$i]}"
        local dest="${dest_files[$i]}"
        local info="${range_info[$i]}"

        if [ "$DRY_RUN" -eq 1 ]; then
            log_info "  [DRY-RUN] Would replace: $(basename "$dest") (from $info)"
        else
            if [ -f "$src" ]; then
                cp "$src" "$dest"
                log_info "  Replaced: $(basename "$dest") (from $info)"
            else
                log_error "Source file not found: $src"
                return 1
            fi
        fi
    done

    return 0
}

# Apply a single diff patch with retry logic
apply_diff_patch() {
    local patch_name="$1"
    local patch_file="$2"
    local description="$3"

    if [ ! -f "$patch_file" ]; then
        log_warning "$patch_name patch not found at $patch_file"
        log_warning "Continuing anyway - $description"
        return 0
    fi

    log_info "Applying $patch_name..."

    if [ "$DRY_RUN" -eq 1 ]; then
        log_info "  [DRY-RUN] Would apply: $patch_file"
        return 0
    fi

    local orig_dir="$(pwd)"
    cd "$OPENSSL_SRC"

    # Try to apply patch normally
    if patch -p1 < "$patch_file" > /dev/null 2>&1; then
        log_info "  Applied: $description"
        cd "$orig_dir"
        return 0
    fi

    # Patch failed, try with fuzz
    patch -R -p1 < "$patch_file" > /dev/null 2>&1 || true

    if patch -p1 -F3 --fuzz=3 < "$patch_file" > /dev/null 2>&1; then
        log_info "  Applied: $description (with fuzz)"
        cd "$orig_dir"
        return 0
    fi

    log_error "$patch_name patch failed even with fuzz"
    cd "$orig_dir"
    return 1
}

# Apply all diff patches
apply_diff_patches() {
    local result=0

    log_info "Using restriction-based patches for OpenSSL $OPENSSL_VERSION"

    # Helper function to get patch path from restrictions directory
    get_restriction_patch() {
        local restriction="$1"
        local range=$(get_restriction_range "$OPENSSL_VERSION" "$restriction")
        echo "$PATCHES_DIR/restrictions/$restriction/${range}.patch"
    }

    # RSA minimum modulus patch (common across all versions)
    apply_diff_patch "RSA minimum modulus restriction" \
        "$(get_restriction_patch "rsa-min-modulus")" \
        "RSA_MIN_MODULUS_BITS = 2048"
    [ $? -ne 0 ] && result=1

    # RSA SHA1 signing restriction (version-specific)
    apply_diff_patch "RSA SHA1 signing restriction" \
        "$(get_restriction_patch "sha1-signing")" \
        "RSA SHA1 signing blocked (verification allowed)"
    [ $? -ne 0 ] && result=1

    # ECDSA SHA1 signing restriction (version-specific)
    apply_diff_patch "ECDSA SHA1 signing restriction" \
        "$(get_restriction_patch "ecdsa-sha1-signing")" \
        "ECDSA SHA1 signing blocked (verification allowed)"
    [ $? -ne 0 ] && result=1

    # ECDSA key size restriction (version-specific)
    apply_diff_patch "ECDSA key size restriction" \
        "$(get_restriction_patch "ecdsa-key-size")" \
        "ECDSA operations blocked for curves < 112-bit strength (e.g., P-192)"
    [ $? -ne 0 ] && result=1

    # PBKDF2 password length restriction (version-specific)
    apply_diff_patch "PBKDF2 password length restriction" \
        "$(get_restriction_patch "pbkdf2-password")" \
        "PBKDF2 password minimum length = 14 bytes (112 bits)"
    [ $? -ne 0 ] && result=1

    # DH FFDHE restriction (version-specific)
    apply_diff_patch "DH FFDHE-only restriction" \
        "$(get_restriction_patch "dh-ffdhe")" \
        "DH restricted to FFDHE groups only, 2048-bit minimum"
    [ $? -ne 0 ] && result=1

    # Provider FIPS restrictions (non-critical)
    log_info "Applying FIPS restrictions to providers..."
    if [ "$DRY_RUN" -eq 1 ]; then
        log_info "  [DRY-RUN] Would apply: provider-naming/all-versions.patch"
    else
        local fips_restrictions_patch="$(get_restriction_patch "provider-naming")"
        if [ -f "$fips_restrictions_patch" ]; then
            local orig_dir="$(pwd)"
            cd "$OPENSSL_SRC"
            if patch -p1 < "$fips_restrictions_patch" > /dev/null 2>&1; then
                log_info "  Applied: Provider names updated with FIPS restriction markers"
            else
                log_warning "FIPS restrictions patch failed (may already be applied or version mismatch)"
                log_warning "Continuing anyway - providers will work but may not show restriction markers"
            fi
            cd "$orig_dir"
        else
            log_warning "FIPS restrictions patch not found at $fips_restrictions_patch"
        fi
    fi

    return $result
}

# Print success message
print_success() {
    log_info ""
    log_info "SUCCESS: FIPS Baseline Patch Applied"
    log_info ""
    log_info "OpenSSL $OPENSSL_VERSION patched for FIPS $FIPS_VERSION baseline testing."
    log_info "You can now build OpenSSL with the modified providers."
    log_info ""
}

# Main function
main() {
    parse_args "$@"

    # Validate FIPS version
    if ! validate_fips_version "$FIPS_VERSION"; then
        exit $RC_INVALID_ARGS
    fi

    # Validate OpenSSL directory
    validate_openssl_dir
    local ret=$?
    if [ $ret -ne 0 ]; then
        exit $ret
    fi

    # Detect OpenSSL version
    detect_openssl_version

    # Check if already patched (idempotent)
    if is_fips_baseline_patched "$OPENSSL_SRC"; then
        log_info "OpenSSL is already patched with FIPS baseline modifications."
        log_info "No changes needed."
        exit $RC_SUCCESS
    fi

    log_info "Applying FIPS Baseline Patch"
    log_info "  OpenSSL: $OPENSSL_SRC ($OPENSSL_VERSION)"
    log_info "  FIPS:    $FIPS_VERSION"
    if [ "$DRY_RUN" -eq 1 ]; then
        log_info "  Mode:    DRY-RUN"
    fi
    log_info ""

    # Apply file replacements
    if ! apply_file_replacements; then
        log_error "File replacements failed"
        exit $RC_PATCH_FAILED
    fi
    log_info ""

    # Apply diff patches
    if ! apply_diff_patches; then
        log_error "One or more patches failed to apply"
        exit $RC_PATCH_FAILED
    fi
    log_info ""

    # Verify patches applied (unless dry-run)
    if [ "$DRY_RUN" -eq 0 ]; then
        if ! is_fips_baseline_patched "$OPENSSL_SRC"; then
            log_error "Patch verification failed - patches may not have been applied correctly"
            exit $RC_PATCH_FAILED
        fi
    fi

    print_success
    exit $RC_SUCCESS
}

# Run main function
main "$@"
