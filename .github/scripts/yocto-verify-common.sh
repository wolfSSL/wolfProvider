#!/bin/bash
#
# yocto-verify-common.sh
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
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
#
# Common verification functions for wolfProvider yocto test images
# Source this file to use the verification functions and call the high-level
# wrapper functions in yocto-*.yml workflow files.


########################################################
# Common verification functions
########################################################


# Verify OpenSSL version
verify_openssl_version() {
    local output_file="$1"
    local expected_version="$2"
    local errors_var="$3"  # Name of errors variable to increment

    local openssl_line=$(grep -E "^OpenSSL [0-9]" "$output_file" | head -1)
    if [ -z "$openssl_line" ]; then
        echo "✗ ERROR: OpenSSL version line not found in output"
        eval "$errors_var=\$((\$$errors_var + 1))"
        return 1
    fi

    local actual_version=$(echo "$openssl_line" | grep -oE "[0-9]+\.[0-9]+\.[0-9]+" | head -1)
    local expected_num=$(echo "$expected_version" | grep -oE "[0-9]+\.[0-9]+\.[0-9]+" | head -1)
    if [ -z "$expected_num" ]; then
        expected_num="$expected_version"
    fi

    if echo "$openssl_line" | grep -q "$expected_num"; then
        echo "✓ OpenSSL version matches: $actual_version"
        return 0
    else
        echo "✗ ERROR: OpenSSL version mismatch"
        echo "  Expected: $expected_num"
        echo "  Found: $actual_version"
        echo "  Full line: $openssl_line"
        eval "$errors_var=\$((\$$errors_var + 1))"
        return 1
    fi
}

# Verify wolfSSL version
verify_wolfssl_version() {
    local output_file="$1"
    local expected_version="$2"
    local errors_var="$3"

    local wolfssl_line=$(grep -E "build info: wolfSSL" "$output_file" | head -1)
    if [ -z "$wolfssl_line" ]; then
        echo "✗ ERROR: wolfSSL version line not found in output"
        eval "$errors_var=\$((\$$errors_var + 1))"
        return 1
    fi

    local actual_version=$(echo "$wolfssl_line" | grep -oE "[0-9]+\.[0-9]+\.[0-9]+" | head -1)
    local expected_num=$(echo "$expected_version" | grep -oE "[0-9]+\.[0-9]+\.[0-9]+" | head -1)
    if [ -z "$expected_num" ]; then
        expected_num="$expected_version"
    fi

    if echo "$wolfssl_line" | grep -q "$expected_num"; then
        echo "✓ wolfSSL version matches: $actual_version"
        return 0
    else
        echo "✗ ERROR: wolfSSL version mismatch"
        echo "  Expected: $expected_num"
        echo "  Found: $actual_version"
        echo "  Full line: $wolfssl_line"
        eval "$errors_var=\$((\$$errors_var + 1))"
        return 1
    fi
}

# Verify FIPS mode loaded correctly
verify_fips_mode() {
    local output_file="$1"
    local expected_fips="$2"
    local errors_var="$3"

    if [ "$expected_fips" = "FIPS" ]; then
        if grep -q "Detected wolfSSL FIPS build\|FIPS Mode: Enabled" "$output_file"; then
            echo "✓ FIPS mode detected correctly"
            return 0
        else
            echo "✗ ERROR: FIPS mode not detected (expected: FIPS)"
            eval "$errors_var=\$((\$$errors_var + 1))"
            return 1
        fi
    else
        if grep -q "Detected wolfSSL non-FIPS build\|FIPS Mode: Disabled" "$output_file"; then
            echo "✓ Non-FIPS mode detected correctly"
            return 0
        else
            echo "✗ ERROR: Non-FIPS mode not detected (expected: non-FIPS)"
            eval "$errors_var=\$((\$$errors_var + 1))"
            return 1
        fi
    fi
}

# Verify provider mode loaded correctly (replace-default vs standalone)
verify_provider_mode() {
    local output_file="$1"
    local expected_replace_default="$2"
    local errors_var="$3"

    local provider_output=$(sed -n '/Test 2: OpenSSL Provider List/,/Test [0-9]:/p' "$output_file" | head -n -1 2>/dev/null || sed -n '/Test 2: OpenSSL Provider List/,$p' "$output_file" | head -50)
    local replace_default_file=$(grep -A 2 "cat /etc/openssl/replace-default-enabled" "$output_file" | grep -E "^[01]$" | head -1 || echo "")

    if [ "$expected_replace_default" = "true" ]; then
        if echo "$provider_output" | grep -qi "libwolfprov"; then
            echo "✗ ERROR: libwolfprov found (indicates standalone mode, not replace-default)"
            eval "$errors_var=\$((\$$errors_var + 1))"
            return 1
        elif echo "$provider_output" | grep -q "default" && echo "$provider_output" | grep -A 5 "default" | grep -qi "wolfSSL Provider"; then
            echo "✓ Default provider is wolfProvider (replace-default mode confirmed)"
            if [ "$replace_default_file" = "0" ]; then
                echo "  ⚠ WARNING: Config file says standalone (0) but runtime shows replace-default mode"
            elif [ -z "$replace_default_file" ]; then
                echo "  ⚠ WARNING: Config file not found (runtime detection takes precedence)"
            fi
            return 0
        else
            echo "✗ ERROR: Default provider is not wolfSSL Provider (expected in replace-default mode)"
            echo "  Provider output snippet:"
            echo "$provider_output" | head -30
            eval "$errors_var=\$((\$$errors_var + 1))"
            return 1
        fi
    else
        if echo "$provider_output" | grep -qi "libwolfprov"; then
            echo "✓ libwolfprov found (standalone mode confirmed)"
            return 0
        elif echo "$provider_output" | grep -qi "wolfSSL Provider"; then
            echo "✓ wolfProvider found in provider output (standalone mode)"
            return 0
        else
            echo "✗ ERROR: wolfProvider not found in provider output (expected in standalone mode)"
            echo "  Provider output:"
            echo "$provider_output" | head -40
            eval "$errors_var=\$((\$$errors_var + 1))"
            return 1
        fi
    fi
}

# Verify provider loaded successfully (replace-default vs standalone)
verify_provider_loaded() {
    local output_file="$1"
    local expected_replace_default="$2"
    local errors_var="$3"

    if [ "$expected_replace_default" = "true" ]; then
        echo "✓ Provider is the default provider (replace-default mode)"
        return 0
    else
        if grep -q "Custom provider 'libwolfprov' loaded successfully" "$output_file"; then
            echo "✓ Provider loaded successfully"
            return 0
        else
            echo "✗ ERROR: Provider load success message not found (expected in standalone mode)"
            eval "$errors_var=\$((\$$errors_var + 1))"
            return 1
        fi
    fi
}

# Verify wolfProvider test results (wolfproviderenv, wolfprovidercmd, wolfprovidertest)
# Usage: verify_test_results <output-file> <errors-var-name> <test-name>
verify_test_results() {
    local output_file="$1"
    local errors_var="$2"
    local test_name="$3"

    local env_status="999"
    local cmd_status="999"
    local test_status="999"
    local tests_passed=0
    local test_failed=0

    # Extract exit codes from output
    # Look for patterns like "wolfproviderenv" followed by exit code or success indicators
    if grep -q "=== Running wolfproviderenv ===" "$output_file"; then
        # Check if wolfproviderenv completed successfully
        if grep -A 50 "=== Running wolfproviderenv ===" "$output_file" | grep -q "Environment setup completed\|Passed!"; then
            env_status="0"
        elif grep -A 50 "=== Running wolfproviderenv ===" "$output_file" | grep -qi "error\|failed"; then
            env_status="1"
        fi
    fi

    if grep -q "=== Running wolfprovidercmd ===" "$output_file"; then
        # Check if wolfprovidercmd completed successfully
        if grep -A 50 "=== Running wolfprovidercmd ===" "$output_file" | grep -q "PASSED\|passed\|success"; then
            cmd_status="0"
        elif grep -A 50 "=== Running wolfprovidercmd ===" "$output_file" | grep -qi "error\|failed\|FAILED"; then
            cmd_status="1"
        fi
    fi

    if grep -q "=== Running wolfprovidertest ===" "$output_file"; then
        # Check if wolfprovidertest completed successfully
        if grep -A 50 "=== Running wolfprovidertest ===" "$output_file" | grep -q "PASSED\|passed\|success\|All tests passed"; then
            test_status="0"
        elif grep -A 50 "=== Running wolfprovidertest ===" "$output_file" | grep -qi "error\|failed\|FAILED"; then
            test_status="1"
        fi
    fi

    echo ""
    echo "=========================================="
    echo "Reviewing Test Results"
    echo "=========================================="
    echo ""

    # Check wolfproviderenv
    if [ "$env_status" -eq "0" ]; then
        echo "  ✓ wolfproviderenv: PASSED"
        tests_passed=$((tests_passed + 1))
    elif [ "$env_status" -eq "999" ]; then
        echo "  ✗ wolfproviderenv: NOT FOUND (script may not have run)"
        test_failed=1
    else
        echo "  ✗ wolfproviderenv: FAILED"
        test_failed=1
    fi

    # Check wolfprovidercmd
    if [ "$cmd_status" -eq "0" ]; then
        echo "  ✓ wolfprovidercmd: PASSED"
        tests_passed=$((tests_passed + 1))
    elif [ "$cmd_status" -eq "999" ]; then
        echo "  ✗ wolfprovidercmd: NOT FOUND (script may not have run)"
        test_failed=1
    else
        echo "  ✗ wolfprovidercmd: FAILED"
        test_failed=1
    fi

    # Check wolfprovidertest
    if [ "$test_status" -eq "0" ]; then
        echo "  ✓ wolfprovidertest: PASSED"
        tests_passed=$((tests_passed + 1))
    elif [ "$test_status" -eq "999" ]; then
        echo "  ✗ wolfprovidertest: NOT FOUND (script may not have run)"
        test_failed=1
    else
        echo "  ✗ wolfprovidertest: FAILED"
        test_failed=1
    fi

    echo ""
    echo "=========================================="
    echo "Final Results: ${tests_passed}/3 tests passed"
    echo "=========================================="
    echo ""

    if [ $test_failed -eq 1 ]; then
        echo "✗ Some tests FAILED"
        echo ""
        echo "Log file (last 50 lines):"
        tail -50 "$output_file"
        eval "$errors_var=\$((\$$errors_var + 1))"
        return 1
    else
        echo "✓ All tests PASSED!"
        return 0
    fi
}

# Verify curl ptest results (uses TESTDONE format)
# Usage: verify_ptest_curl <output-file> <errors-var-name> <test-name>
verify_ptest_curl() {
    local output_file="$1"
    local errors_var="$2"
    local test_name="$3"

    echo ""
    echo "=========================================="
    echo "Verifying ${test_name} Ptest Results"
    echo "=========================================="
    echo ""

    # Check for success indicators
    local test_done_found=0
    local all_passed=0

    # Look for "TESTDONE: X tests out of X reported OK: 100%"
    if grep -q "TESTDONE:" "$output_file"; then
        test_done_found=1
        # Check if all tests passed (100%)
        if grep -q "TESTDONE:.*reported OK: 100%" "$output_file"; then
            all_passed=1
        fi
    fi

    if [ $test_done_found -eq 1 ]; then
        if [ $all_passed -eq 1 ]; then
            local test_count=$(grep "TESTDONE:" "$output_file" | grep -oE "[0-9]+ tests" | head -1 | grep -oE "[0-9]+")
            echo "✓ ${test_name} ptest completed successfully"
            echo "  Tests passed: 100% ($test_count tests)"
            return 0
        else
            echo "✗ ERROR: ${test_name} ptest did not achieve 100% pass rate"
            grep "TESTDONE:" "$output_file" | head -5
            eval "$errors_var=\$((\$$errors_var + 1))"
            return 1
        fi
    else
        echo "✗ ERROR: ${test_name} ptest TESTDONE message not found"
        echo "  This may indicate the ptest did not complete"
        eval "$errors_var=\$((\$$errors_var + 1))"
        return 1
    fi
}

# Generic ptest verification function (checks for FAIL: lines)
# Usage: verify_ptest_generic <output-file> <errors-var-name> <test-name>
verify_ptest_generic() {
    local output_file="$1"
    local errors_var="$2"
    local test_name="$3"

    echo ""
    echo "=========================================="
    echo "Verifying ${test_name} Ptest Results"
    echo "=========================================="
    echo ""

    # Extract the FAIL count from summary line (e.g., "# FAIL: 0")
    local fail_count=$(grep -E "^[[:space:]]*# FAIL:[[:space:]]*[0-9]+" "$output_file" 2>/dev/null | grep -oE "[0-9]+" | head -1 || echo "")
    
    # Also check for non-summary FAIL lines (actual test failures, not starting with #)
    local test_failures=$(grep "FAIL:" "$output_file" 2>/dev/null | grep -vE "^[[:space:]]*#" || true)
    
    # Fail only if there are actual test failures OR if fail_count is a number > 0
    if [ -n "$test_failures" ] || { [ -n "$fail_count" ] && [ "$fail_count" -gt 0 ]; }; then
        echo "✗ ERROR: ${test_name} ptest had failures"
        if [ -n "$test_failures" ]; then
            echo "$test_failures" | head -5
        fi
        if [ -n "$fail_count" ] && [ "$fail_count" -gt 0 ]; then
            echo "  Summary: # FAIL: $fail_count"
        fi
        eval "$errors_var=\$((\$$errors_var + 1))"
        return 1
    fi

    echo "✓ ${test_name} ptest completed successfully"
    return 0
}


########################################################
# Wrapper verification functions
########################################################


# Verify wolfProvider environment configuration
# Usage: yocto_env_verify <output-file> <openssl-version> <wolfssl-version> <replace-default> <fips>
yocto_env_verify() {
    local output_file="$1"
    local expected_openssl_version="$2"
    local expected_wolfssl_version="$3"
    local expected_replace_default="$4"
    local expected_fips="$5"

    if [ $# -ne 5 ]; then
        echo "ERROR: Invalid arguments"
        echo "Usage: yocto_env_verify <output-file> <openssl-version> <wolfssl-version> <replace-default> <fips>"
        return 1
    fi

    if [ ! -f "$output_file" ]; then
        echo "ERROR: Output file not found: $output_file"
        return 1
    fi

    echo "=========================================="
    echo "Verifying wolfproviderenv Configuration"
    echo "=========================================="
    echo "Expected OpenSSL: $expected_openssl_version"
    echo "Expected wolfSSL: $expected_wolfssl_version"
    echo "Expected Replace-Default: $expected_replace_default"
    echo "Expected FIPS: $expected_fips"
    echo ""

    local ERRORS=0

    # Use common verification functions
    verify_openssl_version "$output_file" "$expected_openssl_version" "ERRORS"
    verify_wolfssl_version "$output_file" "$expected_wolfssl_version" "ERRORS"
    verify_fips_mode "$output_file" "$expected_fips" "ERRORS"
    verify_provider_loaded "$output_file" "$expected_replace_default" "ERRORS"
    verify_provider_mode "$output_file" "$expected_replace_default" "ERRORS"

    # Verify test passed
    if grep -q "Passed!" "$output_file"; then
        echo "✓ Test 1 passed"
    else
        echo "✗ ERROR: Test 1 'Passed!' message not found"
        ERRORS=$((ERRORS + 1))
    fi

    # Verify environment setup completed
    if grep -q "Environment setup completed" "$output_file"; then
        echo "✓ Environment setup completed"
    else
        echo "✗ ERROR: Environment setup completion message not found"
        ERRORS=$((ERRORS + 1))
    fi

    echo ""
    echo "=========================================="
    if [ $ERRORS -eq 0 ]; then
        echo "✓ All verifications PASSED"
        echo "=========================================="
        return 0
    else
        echo "✗ $ERRORS verification(s) FAILED"
        echo "=========================================="
        return 1
    fi
}

# Verify wolfProvider test and Ptests results
# Usage: yocto_test_verify <test-name> <output-file>
yocto_test_verify() {
    local test_name="$1"
    local output_file="$2"

    if [ $# -ne 2 ]; then
        echo "ERROR: Invalid arguments"
        echo "Usage: yocto_test_verify <test-name> <output-file>"
        return 1
    fi

    if [ ! -f "$output_file" ]; then
        echo "ERROR: Output file not found: $output_file"
        return 1
    fi

    local ERRORS=0

    # Verify test results
    if [ "$test_name" = "wolfProvider" ]; then
        verify_test_results "$output_file" "ERRORS" "$test_name"
    elif ["$test_name" = "curl"]; then
        verify_ptest_curl "$output_file" "ERRORS" "$test_name"
    else
        verify_ptest_generic "$output_file" "ERRORS" "$test_name"
    fi

    echo ""
    echo "=========================================="
    if [ $ERRORS -eq 0 ]; then
        echo "✓ ${test_name} test verifications PASSED"
        echo "=========================================="
        return 0
    else
        echo "✗ ${test_name} test verifications FAILED"
        echo "  ${ERRORS} verification(s) failed"
        echo "=========================================="
        return 1
    fi
}
