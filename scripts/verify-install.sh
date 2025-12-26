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
SELF_TEST=0
NO_WP=0
VERBOSE=0

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
        --no-wp)
            NO_WP=1
            shift
            ;;
        --self-test)
            SELF_TEST=1
            shift
            ;;
        --verbose)
            VERBOSE=1
            shift
            ;;
        --help|-h)
            echo "Usage: $0 [--replace-default] [--fips] [--no-wp] [--self-test]"
            echo "  --replace-default       Set replace default to 1 (default: 0)"
            echo "  --fips                  Set FIPS to 1 (default: 0)"
            echo "  --no-wp                 Check that wolfprovider is not installed (default: 0)"
            echo "  --self-test             Run self test of this script (default: 0). Other options are ignored."
            echo "  --verbose               Show verbose output (default: 0)"
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

OPENSSL_BIN=${OPENSSL_BIN:-openssl}

if ! command -v $OPENSSL_BIN >/dev/null 2>&1; then
    handle_error "$OPENSSL_BIN not found"
fi

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
source "${SCRIPT_DIR}/utils-general.sh"

handle_error() {
    local message="$1"
    local exit_code="${2:-1}"

    echo "ERROR: $message" >&2

    echo "DEBUG: openssl_version: $openssl_version"
    echo "DEBUG: openssl_providers: $openssl_providers"
    echo "DEBUG: dpkg_output: $dpkg_output"
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
    local fips="$1"
    local replace_default="$2"
    local no_wp="$3"

    detect_wolfprovider_mode
    dpkg_output=$(dpkg -l 2> /dev/null | grep wolf)
    is_wolfssl_installed=$(echo "$dpkg_output" | grep -Eq '^ii\s+libwolfssl\s' && echo 1 || echo 0)
    is_wolfssl_fips=$(echo "$dpkg_output" | grep -E '^ii\s+libwolfssl\s' | grep -qi "fips" && echo 1 || echo 0)

    if [ $VERBOSE -eq 1 ]; then
        echo "fips: $fips"
        echo "replace_default: $replace_default"
        echo "no_wp: $no_wp"
        echo "DEBUG: is_openssl_replace_default: $is_openssl_replace_default"
        echo "DEBUG: is_openssl_default_provider: $is_openssl_default_provider"
        echo "DEBUG: is_wp_active: $is_wp_active"
        echo "DEBUG: is_wp_default: $is_wp_default"
        echo "DEBUG: is_wp_fips: $is_wp_fips"
        echo "DEBUG: is_wolfssl_installed: $is_wolfssl_installed"
        echo "DEBUG: is_wolfssl_fips: $is_wolfssl_fips"
    fi

    if [ $no_wp -eq 1 ]; then
        if [ $is_openssl_default_provider -ne 1 ]; then
            handle_error "OpenSSL is not the default provider"
        elif [ $is_wp_active -eq 1 ]; then
            handle_error "wolfProvider is active"
        elif [ $is_wp_default -eq 1 ]; then
            handle_error "wolfProvider is the default provider"
        fi

        return 0
    else
        if [ $is_openssl_default_provider -eq 1 ]; then
            handle_error "OpenSSL is the default provider"
        fi
    fi

    if [ $replace_default -eq 1 ]; then
        if [ $is_openssl_replace_default -ne 1 ]; then
            handle_error "OpenSSL is not replace default"
        elif [ $is_wolfssl_installed -ne 1 ]; then
            handle_error "wolfSSL is not installed"
        elif [ $is_wp_active -ne 1 ]; then
            handle_error "wolfProvider is not active"
        elif [ $is_wp_default -ne 1 ]; then
            handle_error "wolfProvider is not the default provider"
        fi
    else
        if [ $is_openssl_replace_default -eq 1 ]; then
            handle_error "OpenSSL is replace default"
        elif [ $is_wolfssl_installed -ne 1 ]; then
            handle_error "wolfSSL is not installed"
        elif [ $is_wp_active -ne 1 ]; then
            handle_error "wolfProvider is not in the provider list"
        elif [ $is_wp_default -eq 1 ]; then
            handle_error "wolfProvider is the default provider"
        fi
    fi

    if [ $fips -eq 1 ]; then
        if [ $is_wp_fips -ne 1 ]; then
            handle_error "wolfProvider is not FIPS"
        elif [ $is_wolfssl_fips -ne 1 ]; then
            handle_error "wolfSSL is not FIPS"
        fi
    else
        if [ $is_wp_fips -eq 1 ]; then
            handle_error "wolfProvider is FIPS"
        elif [ $is_wolfssl_fips -eq 1 ]; then
            handle_error "wolfSSL is FIPS"
        fi
    fi

    return 0
}

# With standard openssl and no wolfProvider, expect something like this:
# $openssl list -providers    
# Providers:
#   default
#     name: OpenSSL Default Provider
#     version: 3.0.17
#     status: active

# When replace-default is 0, expect:
# $ openssl list -providers
# Providers:
#   libwolfprov
#     name: wolfSSL Provider
#     version: 1.0.2
#     status: active

# When replace-default is 1, expect:
# $ openssl list -providers
# Providers:
#   default
#     name: wolfSSL Provider
#     version: 1.0.2
#     status: active

# When fips is 1, expect:
# $ openssl list -providers
# Providers:
#   default
#     name: wolfSSL Provider FIPS
#     version: 1.0.2
#     status: active

# When replace-default is 0, expect:
# $ openssl version        
# OpenSSL 3.0.17 1 Jul 2025 (Library: OpenSSL 3.0.17 1 Jul 2025

# When replace-default is 1 and fips is 0, expect:
# $ openssl version        
# OpenSSL 3.0.17+wolfProvider-nonfips 30 Sep 2025 (Library: OpenSSL 3.0.17+wolfProvider-nonfips 30 Sep 2025)

# When fips is 1, expect:
# $ openssl version        
# OpenSSL 3.0.17+wolfProvider-fips 11 Oct 2025 (Library: OpenSSL 3.0.17+wolfProvider-fips 11 Oct 2025)

# When fips is 1, expect:
# $ dpkg -l | grep libwolfssl
# ii  libwolfssl                              5.8.2+commercial.fips.linuxv5.2.4   amd64        wolfSSL encryption library

self_test() {
    # Build mock outputs for openssl and dpkg, then verify expected outcomes
    local pass_count=0
    local fail_count=0

    # Suppress normal output during self-test
    handle_error() {
        local message="$1"
        local exit_code="${2:-1}"
        exit $exit_code
    }
    log_success() { :; }

    # Mock strings for openssl version
    local ver_base="OpenSSL 3.0.17 1 Jul 2025 (Library: OpenSSL 3.0.17 1 Jul 2025)"
    local ver_replace_default_nonfips="OpenSSL 3.0.17+wolfProvider-nonfips 30 Sep 2025 (Library: OpenSSL 3.0.17+wolfProvider-nonfips 30 Sep 2025)"
    local ver_replace_default_fips="OpenSSL 3.0.17+wolfProvider-fips 11 Oct 2025 (Library: OpenSSL 3.0.17+wolfProvider-fips 11 Oct 2025)"

    # Mock strings for provider listings
    read -r -d '' providers_libwolfprov_nonfips <<'EOF'
Providers:
  libwolfprov
    name: wolfSSL Provider
    version: 1.0.2
    status: active
EOF

    read -r -d '' providers_libwolfprov_fips <<'EOF'
Providers:
  libwolfprov
    name: wolfSSL Provider FIPS
    version: 1.0.2
    status: active
EOF

    read -r -d '' providers_default_wolf_nonfips <<'EOF'
Providers:
  default
    name: wolfSSL Provider
    version: 1.0.2
    status: active
EOF

    read -r -d '' providers_default_wolf_fips <<'EOF'
Providers:
  default
    name: wolfSSL Provider FIPS
    version: 1.0.2
    status: active
EOF

    read -r -d '' providers_default_openssl_only <<'EOF'
Providers:
  default
    name: OpenSSL Default Provider
    version: 3.0.17
    status: active
EOF

    read -r -d '' providers_both_default_and_libwolfprov <<'EOF'
Providers:
  default
    name: wolfSSL Provider
    version: 1.0.2
    status: active
  libwolfprov
    name: wolfSSL Provider
    version: 1.0.2
    status: active
EOF

read -r -d '' providers_none <<'EOF'
Providers:
EOF

    # Mock strings for dpkg
    read -r -d '' dpkg_installed_nonfips <<'EOF'
ii  libwolfssl                              5.8.2+commercial.linuxv5.2.4   amd64        wolfSSL encryption library
ii  libwolfssl-dbgsym                       5.8.2+commercial.linuxv5.2.4   amd64        debug symbols for libwolfssl
ii  libwolfssl-dev                          5.8.2+commercial.linuxv5.2.4   amd64        wolfSSL encryption library
EOF

    read -r -d '' dpkg_installed_fips <<'EOF'
ii  libwolfssl                              5.8.2+commercial.fips.linuxv5.2.4   amd64        wolfSSL encryption library
ii  libwolfssl-dbgsym                       5.8.2+commercial.fips.linuxv5.2.4   amd64        debug symbols for libwolfssl
ii  libwolfssl-dev                          5.8.2+commercial.fips.linuxv5.2.4   amd64        wolfSSL encryption library
EOF

    run_case() {
        local name="$1"
        local expected_rc="$2"
        local fips="$3"
        local replace_default="$4"
        local no_wp="$5"
        local ver_var="$6"
        local prov_var="$7"
        local dpkg_var="$8"

        local ver_val="${!ver_var}"
        local prov_val="${!prov_var}"
        local dpkg_val="${!dpkg_var}"

        (
            openssl_version="$ver_val"
            openssl_providers="$prov_val"
            dpkg_output="$dpkg_val"
            verify_wolfprovider "$fips" "$replace_default" "$no_wp"
        )
        local rc=$?
        if [ "$rc" -eq "$expected_rc" ]; then
            log_success "[$name] passed"
            pass_count=$((pass_count+1))
        else
            echo "FAIL: [$name] expected rc=$expected_rc got rc=$rc" >&2
            fail_count=$((fail_count+1))
        fi
    }

    # Positive cases per comment expectations
    run_case "pos: replace_default=0,fips=0" 0 0 0 0 ver_base providers_libwolfprov_nonfips dpkg_installed_nonfips
    run_case "pos: replace_default=1,fips=0" 0 0 1 0 ver_replace_default_nonfips providers_default_wolf_nonfips dpkg_installed_nonfips
    run_case "pos: replace_default=1,fips=1" 0 1 1 0 ver_replace_default_fips providers_default_wolf_fips dpkg_installed_fips
    run_case "pos: replace_default=0,fips=1" 0 1 0 0 ver_base providers_libwolfprov_fips dpkg_installed_fips
    # run positive test cases with providers_default_openssl_only
    run_case "pos: no_wp true with OpenSSL default, default provider" 0 0 0 1 ver_base providers_default_openssl_only dpkg_installed_nonfips
    run_case "pos: no_wp true but wolfProvider active" 1 0 0 1 ver_base providers_libwolfprov_nonfips  dpkg_installed_nonfips

    # Negative cases
    run_case "neg: rd=0 but OpenSSL replace-default" 1 0 0 0 ver_replace_default_nonfips providers_libwolfprov_nonfips dpkg_installed_nonfips
    run_case "neg: rd=0 but provider default" 1 0 0 0 ver_base providers_both_default_and_libwolfprov dpkg_installed_nonfips
    run_case "neg: rd=0 but no providers listed" 1 0 0 0 ver_base providers_none dpkg_installed_nonfips
    run_case "neg: rd=0 missing provider" 1 0 0 0 ver_base providers_default_openssl_only dpkg_installed_nonfips
    run_case "neg: rd=1,fips=0 but OpenSSL FIPS" 1 0 1 0 ver_replace_default_fips providers_default_wolf_nonfips dpkg_installed_nonfips
    run_case "neg: rd=1,fips=0 but provider FIPS" 1 0 1 0 ver_replace_default_nonfips providers_default_wolf_fips dpkg_installed_nonfips
    run_case "neg: rd=1,fips=0 but no providers listed" 1 0 1 0 ver_replace_default_nonfips providers_none dpkg_installed_nonfips
    run_case "neg: rd=1,fips=1 but OpenSSL non-FIPS" 1 1 1 0 ver_replace_default_nonfips providers_default_wolf_fips dpkg_installed_fips
    run_case "neg: fips=1 but wolfSSL non-FIPS" 1 1 0 0 ver_base providers_libwolfprov_fips dpkg_installed_nonfips

    # no_wp positive and negative cases
    run_case "neg: no_wp true with OpenSSL default, default provider" 1 0 0 1 ver_base providers_none dpkg_installed_nonfips
    run_case "neg: no_wp true but wolfProvider active" 1 0 0 1 ver_base providers_libwolfprov_nonfips dpkg_installed_nonfips

    log_info "self_test results: ${pass_count} passed, ${fail_count} failed"
    if [ "$fail_count" -gt 0 ]; then
        handle_error "self_test had ${fail_count} failing case(s)"
    fi

    return 0
}

if [ $SELF_TEST -eq 1 ]; then
    self_test
    exit 0
fi

verify_wolfprovider "$FIPS" "$REPLACE_DEFAULT" "$NO_WP"
log_success "openssl and wolfProvider installed correctly"
