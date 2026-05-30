#!/bin/bash
# check-workflow-result.sh
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

set -e

if [ $# -lt 1 ]; then
    echo "Usage: $0 <test_result> [WOLFPROV_FORCE_FAIL] [TEST_SUITE]"
    exit 1
fi

TEST_RESULT="$1"
WOLFPROV_FORCE_FAIL="${2:-}"
TEST_SUITE="${3:-}"

# Ensure TEST_RESULT is treated as a number
TEST_RESULT=$((TEST_RESULT + 0))

# If test suite is empty treat second arg as test suite
if [ -z "$TEST_SUITE" ]; then
    TEST_SUITE=$WOLFPROV_FORCE_FAIL
    WOLFPROV_FORCE_FAIL=""
fi

if [ "$WOLFPROV_FORCE_FAIL" = "WOLFPROV_FORCE_FAIL=1" ]; then
    # ----- CURL -----
    if [ "$TEST_SUITE" = "curl" ]; then
        # Under WOLFPROV_FORCE_FAIL=1, wolfProvider deliberately errors on
        # every call, so the curl test-suite is expected to fail somewhere.
        # We don't pin the exact test numbers (they drift across curl
        # versions), but we DO require curl-test.log to exist with at
        # least one TESTFAIL line - otherwise a build/network/infra
        # failure that never actually ran curl would silently pass.
        if [ "$TEST_RESULT" -ne 0 ] \
            && [ -f "curl-test.log" ] \
            && grep -q '^TESTFAIL:' curl-test.log; then
            echo "PASS: curl tests failed (exit $TEST_RESULT) as expected under WOLFPROV_FORCE_FAIL=1"
            exit 0
        elif [ "$TEST_RESULT" -eq 0 ]; then
            echo "FAIL: curl tests unexpectedly succeeded under WOLFPROV_FORCE_FAIL=1"
            exit 1
        else
            echo "FAIL: curl exited $TEST_RESULT but curl-test.log missing/has no TESTFAIL - looks like infra failure, not a real force-fail run"
            exit 1
        fi
    # ----- OPENVPN -----
    elif [ "$TEST_SUITE" = "openvpn" ]; then
        if [ -f "openvpn-test.log" ]; then
            # Extract failed tests from the log
            ACTUAL_FAILS=$(grep -a '^FAIL: ' openvpn-test.log | sed 's/^FAIL: //' | sort)

            # Define expected failures
            EXPECTED_FAILS="auth_token_testdriver crypto_testdriver pkt_testdriver tls_crypt_testdriver"

            # This test may fail when replace-default is enabled
            OPTIONAL_FAILS="provider_testdriver"
            
            # Create temporary files for sorted lists
            TEMP_DIR=$(mktemp -d)
            ACTUAL_SORTED="${TEMP_DIR}/actual_sorted.txt"
            EXPECTED_SORTED="${TEMP_DIR}/expected_sorted.txt"
            OPTIONAL_SORTED="${TEMP_DIR}/optional_sorted.txt"
            
            # Clean and sort both lists
            echo "$ACTUAL_FAILS" | tr ' ' '\n' | grep -v '^$' | sort > "$ACTUAL_SORTED"
            echo "$EXPECTED_FAILS" | tr ' ' '\n' | grep -v '^$' | sort > "$EXPECTED_SORTED"
            echo "$OPTIONAL_FAILS" | tr ' ' '\n' | grep -v '^$' | sort > "$OPTIONAL_SORTED"

            echo "DEBUG: Actual failed tests: $(tr '\n' ' ' < "$ACTUAL_SORTED")"
            echo "DEBUG: Expected failed tests: $(tr '\n' ' ' < "$EXPECTED_SORTED")"
            echo "DEBUG: Optional failed tests: $(tr '\n' ' ' < "$OPTIONAL_SORTED")"

            # Find missing in actual (in expected but not in actual)
            MISSING=$(comm -23 "$EXPECTED_SORTED" "$ACTUAL_SORTED" | tr '\n' ' ')
            # Find extra in actual (in actual but not in expected)
            EXTRA=$(comm -13 "$EXPECTED_SORTED" "$ACTUAL_SORTED" | tr '\n' ' ')
            # Strip out optional failures
            EXTRA=$(comm -23 "$EXTRA" "$OPTIONAL_SORTED" | tr '\n' ' ')
            # List the optional failures
            OPTIONAL_FAILS=$(comm -13 "$EXPECTED_SORTED" "$OPTIONAL_SORTED" | tr '\n' ' ')

            # Clean up temporary files
            rm -rf "$TEMP_DIR"
            
            echo "Test(s) that should have failed: $MISSING"
            echo "Test(s) that shouldn't have failed: $EXTRA"
            echo "Test(s) that failed (optional): $OPTIONAL_FAILS"

            if [ -z "$MISSING" ] && [ -z "$EXTRA" ]; then
                echo "PASS: Actual failed tests match expected."
                exit 0
            else
                echo "FAIL: Actual failed tests do not match expected."
                exit 1
            fi
        else
            echo "Error: openvpn-test.log not found"
            exit 1
        fi
    # ----- SSSD -----
    elif [ "$TEST_SUITE" = "sssd" ]; then
        if [ -f "sssd-test.log" ]; then
            # Extract failed tests from the log
            ACTUAL_FAILS=$(grep -a '^FAIL: ' sssd-test.log | sed 's/^FAIL: //' | sort)
            
            # Define expected failures
            EXPECTED_FAILS="src/tests/pysss-test.py3.sh pam-srv-tests ssh-srv-tests test_cert_utils sss_certmap_test sysdb-tests crypto-tests"
            
            # Create temporary files for sorted lists
            TEMP_DIR=$(mktemp -d)
            ACTUAL_SORTED="${TEMP_DIR}/actual_sorted.txt"
            EXPECTED_SORTED="${TEMP_DIR}/expected_sorted.txt"
            
            # Clean and sort both lists
            echo "$ACTUAL_FAILS" | tr ' ' '\n' | grep -v '^$' | sort > "$ACTUAL_SORTED"
            echo "$EXPECTED_FAILS" | tr ' ' '\n' | grep -v '^$' | sort > "$EXPECTED_SORTED"
            
            echo "DEBUG: Actual failed tests: $(tr '\n' ' ' < "$ACTUAL_SORTED")"
            echo "DEBUG: Expected failed tests: $(tr '\n' ' ' < "$EXPECTED_SORTED")"
            
            # Find missing in actual (in expected but not in actual)
            MISSING=$(comm -23 "$EXPECTED_SORTED" "$ACTUAL_SORTED" | tr '\n' ' ')
            # Find extra in actual (in actual but not in expected)
            EXTRA=$(comm -13 "$EXPECTED_SORTED" "$ACTUAL_SORTED" | tr '\n' ' ')
            
            # Clean up temporary files
            rm -rf "$TEMP_DIR"
            
            echo "Test(s) that should have failed: $MISSING"
            echo "Test(s) that shouldn't have failed: $EXTRA"
            
            if [ -z "$MISSING" ] && [ -z "$EXTRA" ]; then
                echo "PASS: Actual failed tests match expected."
                exit 0
            else
                echo "FAIL: Actual failed tests do not match expected."
                exit 1
            fi
        else
            echo "Error: sssd-test.log not found"
            exit 1
        fi
    # ----- NET-SNMP -----
    elif [ "$TEST_SUITE" = "net-snmp" ]; then
        if [ -f "net-snmp-test.log" ]; then
            # Check if we have exactly 29 failed tests and a FAIL result
            if grep -q "We failed these 29 tests:" net-snmp-test.log && grep -q "Result: FAIL" net-snmp-test.log; then
                echo "PASS: net-snmp tests failed as expected with force fail enabled"
                exit 0
            else
                echo "FAIL: net-snmp tests unexpectedly succeeded with force fail enabled"
                exit 1
            fi
        else
            echo "Error: tests/net-snmp-test.log not found"
            exit 1
        fi
    # ----- NGINX -----
    elif [ "$TEST_SUITE" = "nginx" ]; then
        if [ -f "nginx-test.log" ]; then
            # Check if the test result shows FAIL
            if grep -q "Result: FAIL" nginx-test.log; then
                echo "PASS: nginx tests failed as expected with force fail enabled"
                exit 0
            else
                echo "FAIL: nginx tests unexpectedly succeeded with force fail enabled"
                exit 1
            fi
        else
            echo "Error: nginx-test.log not found"
            exit 1
        fi
    # ----- STUNNEL -----
    elif [ "$TEST_SUITE" = "stunnel" ]; then
        if [ -f "stunnel-test.log" ]; then
            # Check for expected error patterns
            if grep -q "failed: 41" "stunnel-test.log"; then
                echo "PASS: stunnel tests failed as expected with force fail enabled"
                exit 0
            else
                echo "FAIL: stunnel tests unexpectedly succeeded with force fail enabled"
                exit 1
            fi
        else
            echo "Error: stunnel-test.log not found"
            exit 1
        fi
    # ----- OPENSSH -----
    elif [ "$TEST_SUITE" = "openssh" ]; then
        if [ -f "openssh-test.log" ]; then
            # Check for expected PRNGD socket error and exit code 255
            if grep -q "Couldn't connect to PRNGD socket" openssh-test.log && grep -q "Error 255" openssh-test.log; then
                echo "PASS: OpenSSH tests failed as expected with PRNGD socket error"
                exit 0
            else
                echo "FAIL: OpenSSH tests did not fail as expected"
                exit 1
            fi
        else
            echo "Error: openssh-test.log not found"
            exit 1
        fi
    # ----- LIBOAUTH2 -----
    elif [ "$TEST_SUITE" = "liboauth2" ]; then
        if [ -f "liboauth2-test.log" ]; then
            # Check for expected error patterns
            if grep -q "FAIL: check_liboauth2" "liboauth2-test.log"; then
                echo "PASS: liboauth2 tests failed as expected with force fail enabled"
                exit 0
            else
                echo "FAIL: liboauth2 tests unexpectedly succeeded with force fail enabled"
                exit 1
            fi
        else
            echo "Error: liboauth2-test.log not found"
            exit 1
        fi
    # ----- TCPDUMP -----
    elif [ "$TEST_SUITE" = "tcpdump" ]; then
        if [ -f "tcpdump-test.log" ]; then
            # Expect 7 failed tests (ESP/crypto segfaults) in non-FIPS
            # and 2 failed tests in FIPS mode
            if grep -q "Tests passed successfully" tcpdump-test.log; then
                echo "FAIL: tcpdump tests did not fail as expected"
                exit 1
            else
                echo "PASS: tcpdump tests failed as expected with force fail enabled"
                exit 0
            fi
        else
            echo "Error: tcpdump-test.log not found"
            exit 1
        fi
    # ----- IPERF -----
    elif [ "$TEST_SUITE" = "iperf" ]; then
        IPERF_TEST_LOG="iperf-test.log"
        if [ -f $IPERF_TEST_LOG ]; then
              read sender_gb receiver_gb < <(awk '/sender/ {s=$4} /receiver/ {r=$4} END{print s, r}' )

            if [[ -z "$sender_gb" && -z "$receiver_gb" ]]; then
                echo "PASS: No data sent or received, as expected with force fail enabled"
                exit 0
            else
                echo "FAIL: Iperf tests unexpectedly succeeded with data sent or received"
                echo "  Sent: $sender_gb GB, Received: $receiver_gb GB"
                exit 1
            fi
        else
            echo "Error: $IPERF_TEST_LOG not found"
            exit 1
        fi
    else
        if [ $TEST_RESULT -eq 0 ]; then
            echo "$TEST_SUITE tests unexpectedly succeeded with force fail enabled"
            exit 1 # failure was not seen when expected
        else
            echo "$TEST_SUITE tests failed as expected with force fail enabled"
            exit 0 # expected failure occurred
        fi
    fi
elif [ $TEST_RESULT -ne 0 ]; then
    echo "Tests failed unexpectedly"
    exit 1
else
    echo "Tests passed successfully"
    exit 0
fi
