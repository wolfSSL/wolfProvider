#!/bin/bash
# This script provides the bare minimum function definitions for compiling
# the wolfProvider library

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"

if [ "$UTILS_GENERAL_LOADED" != "yes" ]; then # only set once
    kill_servers() {
        if [ "$(jobs -p)" != "" ]; then
            kill $(jobs -p)
        fi
    }

    do_cleanup() {
        sleep 0.5 # flush buffers
        kill_servers
    }

    do_trap() {
        printf "got trap\n"
        do_cleanup
        date
        exit 1
    }
    trap do_trap INT TERM

    export UTILS_GENERAL_LOADED=yes
fi

# Check if the current git repository matches the target commit/tag/branch
# Usage: check_git_match <target_ref> [<repo_dir>]
check_git_match() {
    local target_ref="$1"
    local repo_dir="${2:-.}"

    pushd "$repo_dir" > /dev/null || return 2

    local current_tag current_branch current_commit_long current_commit_short
    current_tag=$(git describe --tags --exact-match 2>/dev/null || true)
    current_branch=$(git symbolic-ref --short HEAD 2>/dev/null || true)
    current_commit_long=$(git rev-parse HEAD 2>/dev/null || true)
    current_commit_short=$(git rev-parse --short HEAD 2>/dev/null || true)

    if [[ -n "$current_tag" && "$target_ref" == "$current_tag" ]]; then
        echo "match: tag ($current_tag)"
        popd > /dev/null
        return 0
    elif [[ -n "$current_branch" && "$target_ref" == "$current_branch" ]]; then
        echo "match: branch ($current_branch)"
        popd > /dev/null
        return 0
    elif [[ -n "$current_commit_long" && "$target_ref" == "$current_commit_long" ]]; then
        echo "match: commit (long $current_commit_long)"
        popd > /dev/null
        return 0
    elif [[ -n "$current_commit_short" && "$target_ref" == "$current_commit_short" ]]; then
        echo "match: commit (short $current_commit_short)"
        popd > /dev/null
        return 0
    else
        echo "no match found for $target_ref"
        printf "Version inconsistency. Please fix ${repo_dir}\n"
        printf "(expected: ${target_ref}, got: ${current_tag} ${current_branch} ${current_commit_long} ${current_commit_short})\n"
        popd > /dev/null
        exit 1
    fi
}

# Apply patch for OpenSSL version info
openssl_patch_metadata() {
    local replace_default=${1:-0}
    local openssl_source_dir=${2:-.}
    printf "\tPatching OpenSSL version metadata ... "
    # Patch the OpenSSL version with our BUILD_METADATA
    if [ "$replace_default" = "1" ]; then
        sed -i 's/BUILD_METADATA=.*/BUILD_METADATA=wolfProvider-replace-default/g' $openssl_source_dir/VERSION.dat
    else
        sed -i 's/BUILD_METADATA=.*/BUILD_METADATA=wolfProvider/g' $openssl_source_dir/VERSION.dat
    fi
    # Patch the OpenSSL RELEASE_DATE field with the current date in the format DD MMM YYYY
    sed -i "s/RELEASE_DATE=.*/RELEASE_DATE=\"$(date '+%d %b %Y')\"/g" $openssl_source_dir/VERSION.dat

    printf "Done.\n"
}

# Check if replace-default patch is applied
# Return 0 if patched, 1 if not
openssl_is_patched() {
    local openssl_source_dir=${1:-.}
    local file="$openssl_source_dir/crypto/provider_predefined.c"
    local ret=1

    # File must exist to be patched
    if [[ ! -f "$file" ]]; then
        printf "\tOpenSSL source file not found: %s\n" "$file"
    elif grep -q 'libwolfprov' -- "$file"; then
        # Any time we see libwolfprov, we're patched
        ret=0
    else
        : # Not patched
    fi

    return $ret
}

# Apply replace-default and version patches
openssl_patch() {
    local replace_default=${1:-0}
    local openssl_source_dir=${2:-.}
    local patch_file="${SCRIPT_DIR}/../patches/openssl3-replace-default.patch"

    if openssl_is_patched $openssl_source_dir; then
        printf "\tOpenSSL already patched\n"
    elif [ "$replace_default" = "1" ]; then
        if [ ! -f "${patch_file}" ]; then
            printf "ERROR: OpenSSL replace-default patch file not found: ${patch_file}\n"
            printf "  Looked in directory: $(dirname ${patch_file})\n"
            exit 1
        fi

        printf "\tApplying OpenSSL default provider patch ... "

        # Apply the patch
        patch -d $openssl_source_dir -p1 < ${patch_file}
        if [ $? != 0 ]; then
            printf "ERROR.\n"
            printf "\n\nPatch application failed.\n"
            exit 1
        fi
    fi
    # Patch the OpenSSL version with our metadata
    openssl_patch_metadata $replace_default $openssl_source_dir
}
