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

    UTILS_GENERAL_LOADED=yes

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

    export is_openssl_replace_default=${is_openssl_replace_default:-0}
    export is_openssl_default_provider=${is_openssl_default_provider:-0}
    export is_wp_active=${is_wp_active:-0}
    export is_wp_default=${is_wp_default:-0}
    export is_wp_fips=${is_wp_fips:-0}

    # Function to detect wolfProvider installation mode
    detect_wolfprovider_mode() {
        local openssl_version=$(${OPENSSL_BIN} version 2>/dev/null)
        local openssl_providers=$(${OPENSSL_BIN} list -providers 2>/dev/null)

        # Method 1: Check for "replace-default" in version string
        is_openssl_replace_default=$(echo "$openssl_version" | grep -qi "replace-default" && echo 1 || echo 0)

        # Method 2: Check environment variable
        if [ "$is_openssl_replace_default" = "0" ] && [ "${WOLFPROV_REPLACE_DEFAULT:-0}" = "1" ]; then
            is_openssl_replace_default=1
        fi

        # Method 3: Check if provider list shows "default" with "wolfSSL Provider" name
        if [ "$is_openssl_replace_default" = "0" ]; then
            # Check if provider list shows "default" with "wolfSSL Provider" name but NOT "OpenSSL Default Provider"
            # This indicates replace-default mode
            if echo "$openssl_providers" | grep -q "^  default$" && \
               echo "$openssl_providers" | grep -q "wolfSSL Provider" && \
               ! echo "$openssl_providers" | grep -q "OpenSSL Default Provider"; then
                is_openssl_replace_default=1
            fi
        fi

        # Method 4: Check for "+wolfProvider" in version string (Debian package indicator)
        # AND no "OpenSSL Default Provider" available
        if [ "$is_openssl_replace_default" = "0" ]; then
            if echo "$openssl_version" | grep -qi "+wolfProvider" && \
               ! echo "$openssl_providers" | grep -q "OpenSSL Default Provider"; then
                is_openssl_replace_default=1
            fi
        fi

        # Method 5: Check if libwolfprov is the ONLY provider loaded (shown as "libwolfprov")
        # and wolfSSL Provider is active with NO OpenSSL Default Provider
        if [ "$is_openssl_replace_default" = "0" ]; then
            if echo "$openssl_providers" | grep -q "^  libwolfprov$" && \
               echo "$openssl_providers" | grep -q "wolfSSL Provider" && \
               ! echo "$openssl_providers" | grep -q "OpenSSL Default Provider"; then
                is_openssl_replace_default=1
            fi
        fi

        # Method 6: If wolfSSL Provider is active but NO OpenSSL Default Provider exists at all,
        # this strongly indicates replace-default mode
        if [ "$is_openssl_replace_default" = "0" ]; then
            if echo "$openssl_providers" | grep -q "wolfSSL Provider" && \
               ! echo "$openssl_providers" | grep -q "OpenSSL Default Provider"; then
                is_openssl_replace_default=1
            fi
        fi
        
        # In replace-default mode, there's no "OpenSSL Default Provider" - wolfProvider IS the default
        is_openssl_default_provider=$(echo "$openssl_providers" | grep -qi "OpenSSL Default Provider" && echo 1 || echo 0)
        is_wp_active=$(echo "$openssl_providers" | grep -qi "wolfSSL Provider" && echo 1 || echo 0)
        
        # Check if wolfProvider is the default provider
        if [ "$is_openssl_replace_default" = "1" ]; then
            # In replace-default mode, wolfProvider IS the default provider
            is_wp_default=1
            # Also mark as active if we're in replace-default mode
            if [ "$is_wp_active" = "0" ]; then
                # In replace-default mode, the "default" provider IS wolfProvider
                is_wp_active=1
            fi
        else
            # In normal mode, check if default provider is wolfProvider
            is_wp_default=$(echo "$openssl_providers" | grep -q -Pzo 'Providers:\s*\n\s*default\s*\n\s*name:\s*wolfSSL Provider' && echo 1 || echo 0)
        fi
        is_wp_fips=$(echo "$openssl_providers" | grep -qi "wolfSSL Provider FIPS" && echo 1 || echo 0)
    }
fi