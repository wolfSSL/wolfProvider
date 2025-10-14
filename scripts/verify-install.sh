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
# This script verifies that wolfProvider is correctly installed and configured.

# Default values
REPLACE_DEFAULT=0
FIPS=0

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --replace-default)
            REPLACE_DEFAULT=1
            shift
            ;;
        --fips)
            FIPS=1
            shift
            ;;
        --help|-h)
            echo "Usage: $0 [--replace-default] [--fips]"
            echo "  --replace-default       Set replace default to 1 (default: 0)"
            echo "  --fips                  Set FIPS to 1 (default: 0)"
            echo "  --help, -h              Show this help message"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            echo "Use --help for usage information"
            exit 1
            ;;
    esac
done

handle_error() {
    local message="$1"
    local exit_code="${2:-1}"

    echo "ERROR: $message" >&2
    exit $exit_code
}

log_success() {
    echo "SUCCESS: $1"
}
log_info() {
    echo "INFO: $1"
}

verify_provider_loaded() {
    local replace_default="$1"
    local fips="$2"

    # When replace-default is 0, expect something like this:
    # $ openssl list -providers
    # Providers:
    #   libwolfprov
    #     name: wolfSSL Provider
    #     version: 1.0.2
    #     status: active

    # When replace-default is 1, expect something like this:
    # $ openssl list -providers
    # Providers: 
    #   default 
    #     name: wolfSSL Provider 
    #     version: 1.0.2 
    #     status: active

    log_info "Verifying wolfProvider is active..."

    local provider_output
    provider_output=$(openssl list -providers 2>&1)

    echo "Provider list:"
    echo "$provider_output"

    # Check for the presence of "wolfSSL Provider" and "status: active"
    if echo "$provider_output" | grep -qi "wolfSSL Provider" && echo "$provider_output" | grep -qi "status: active"; then
        log_success "wolfProvider is loaded"
    else
        handle_error "wolfProvider not found in provider list"
    fi

    if [ $replace_default -eq 0 ]; then
        if echo "$provider_output" | grep -qi "libwolfprov"; then
            log_success "wolfProvider is non-default"
        else
            handle_error "wolfProvider is default"
        fi
    else
        if echo "$provider_output" | grep -qi "default"; then
            log_success "wolfProvider is default"
        else
            handle_error "wolfProvider is non-default"
        fi
    fi

    # Expect "wolfSSL Provider" for non-FIPS, "wolfSSL Provider FIPS" for FIPS
    if [ $fips -eq 0 ]; then
        if echo "$provider_output" | grep -q "wolfSSL Provider FIPS"; then
            handle_error "wolfSSL Provider is FIPS"
        else
            log_success "wolfSSL Provider is non-FIPS"
        fi
    else
        if echo "$provider_output" | grep -q "wolfSSL Provider FIPS"; then
            log_success "wolfSSL Provider is FIPS"
        else
            handle_error "wolfSSL Provider is non-FIPS"
        fi
    fi
}

verify_openssl_version() {
    local replace_default="$1"

    # When replace-default is 0, expect something like this:
    # $openssl version
    # OpenSSL 3.0.17 1 Jul 2025 (Library: OpenSSL 3.0.17 1 Jul 2025

    log_info "Verifying OpenSSL version..."

    local version_output
    version_output=$(openssl version 2>&1)

    echo "OpenSSL version information:"
    echo "$version_output"

    if [ $replace_default -eq 0 ]; then
        # Verify that "wolf" is not in the version output
        # We should be using a stock OpenSSL build, not ours
        if echo "$version_output" | grep "OpenSSL 3" | grep -qi "wolf"; then
            handle_error "OpenSSL version appears to be patched"
        else
            log_success "OpenSSL version is not patched"
        fi
    else
        # Verify that wolfProv (case-insensitive) is in the version output
        if echo "$version_output" | grep "OpenSSL 3" | grep -qi "wolf"; then
            log_success "wolfProv is not in the version output"
        else
            handle_error "wolfProv is in the version output"
        fi
    fi
}

# Main verification function
verify_wolfprovider() {
    local replace_default="$1"
    local fips="$2"

    # echo "Replace default value: $replace_default"
    # echo "FIPS value: $fips"

    echo "--------------------------------"
    verify_provider_loaded $replace_default $fips
    echo "--------------------------------"
    verify_openssl_version $replace_default $fips
    echo "--------------------------------"
    echo "wolfProvider installed correctly"

    return 0
}

verify_wolfprovider "$REPLACE_DEFAULT" "$FIPS"
