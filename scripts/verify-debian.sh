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
# This script verifies that wolfProvider is correctly installed and configured
# on Debian with default replace. It can be sourced to set verification status
# or executed for standalone verification.
#
# Usage: source scripts/verify-debian.sh
#    Or: ./scripts/verify-debian.sh

# Check if script is being sourced or executed
if [[ -n "${ZSH_VERSION:-}" ]]; then
    [[ $ZSH_EVAL_CONTEXT =~ :file$ ]] && is_sourced=1 || is_sourced=0
else # bash
    [ "$0" = "$BASH_SOURCE" ] && is_sourced=0 || is_sourced=1
fi

handle_error() {
    local message="$1"
    local exit_code="${2:-1}"

    echo "ERROR: $message" >&2
    if [ $is_sourced -eq 1 ]; then
        # If sourced, return instead of exit
        return $exit_code
    else
        # If executed, exit
        exit $exit_code
    fi
}

log_success() {
    echo "SUCCESS: $1"
}
log_info() {
    echo "INFO: $1"
}

# Verify wolfProvider configuration file
verify_provider_config() {
    local provider_conf="/usr/lib/ssl/openssl.cnf.d/wolfprovider.conf"

    log_info "Checking wolfProvider configuration file..."

    if [ -f "$provider_conf" ]; then
        log_success "wolfProvider configuration found at $provider_conf"
        echo "Configuration contents:"
        cat "$provider_conf"
        return 0
    else
        handle_error "wolfProvider configuration not found at $provider_conf"
        return 1
    fi
}

# Verify wolfProvider is loaded
verify_provider_loaded() {
    log_info "Verifying wolfProvider is active..."

    local provider_output
    provider_output=$(openssl list -providers 2>&1)

    if echo "$provider_output" | grep -qi "wolfSSL Provider"; then
        log_success "wolfProvider is loaded"
        echo "Provider list:"
        echo "$provider_output"
        return 0
    else
        handle_error "wolfProvider not found in provider list"
        echo "Provider list:"
        echo "$provider_output"
        return 1
    fi
}

# Verify wolfProvider version (for default replace)
verify_provider_version() {
    log_info "Verifying wolfProvider replace default version..."

    local version_output
    version_output=$(openssl version -a 2>&1)

    echo "OpenSSL version information:"
    echo "$version_output"

    if echo "$version_output" | grep -q "Library: OpenSSL 3.5.2+wolfProvider-nonfips"; then
        log_success "wolfProvider replace default version is correct"
        return 0
    else
        handle_error "wolfProvider replace default version is incorrect"
        return 1
    fi
}

# Main verification function
verify_wolfprovider() {
    local overall_success=0

    echo "=== wolfProvider Verification for Debian ==="
    # Run all verification checks
    verify_provider_config || overall_success=1
    echo ""
    verify_provider_loaded || overall_success=1
    echo ""
    verify_provider_version || overall_success=1
    echo ""

    echo "=== Verification Summary ==="
    if [ $overall_success -eq 0 ]; then
        log_success "All wolfProvider verifications passed!"
        echo "wolfProvider is correctly installed and configured on this Debian system."
    else
        handle_error "Some wolfProvider verifications failed!"
        echo "wolfProvider is not properly installed on this Debian system."
    fi

    # Set environment variable for sourced usage
    if [ $is_sourced -eq 1 ]; then
        export WOLFPROVIDER_VERIFIED=$([ $overall_success -eq 0 ] && echo "1" || echo "0")
        echo "Environment variable WOLFPROVIDER_VERIFIED set to: $WOLFPROVIDER_VERIFIED"
    fi

    return $overall_success
}

if [ $is_sourced -eq 0 ]; then
    verify_wolfprovider
fi
if [ $is_sourced -eq 1 ]; then
    verify_wolfprovider
fi
