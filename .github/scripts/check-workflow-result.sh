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
        if [ -f "curl-test.log" ]; then
            # Extract and clean the failed test list from the log
            ACTUAL_FAILS=$(grep -a '^TESTFAIL: These test cases failed:' curl-test.log | sed 's/.*failed: //')
        else
            echo "Error: curl-test.log not found"
            exit 1
        fi

        # Get curl version from the workflow ref
        CURL_VERSION="${CURL_REF:-}"

        # Define expected failures based on curl version
        case "$CURL_VERSION" in
            "curl-7_88_1")
                EXPECTED_FAILS="9 39 41 44 64 65 70 71 72 88 153 154 158 163 166 167 168 169 170 173 186 206 245 246 258 259 273 277 327 335 388 540 551 552 554 565 579 584 643 645 646 647 648 649 650 651 652 653 654 666 667 668 669 670 671 672 673 1001 1002 1030 1053 1060 1061 1071 1072 1079 1095 1133 1136 1158 1186 1187 1189 1190 1191 1192 1193 1194 1195 1196 1198 1199 1229 1284 1285 1286 1293 1315 1404 1412 1418 1437 1568 1905 1916 1917 2024 2026 2027 2028 2030 2058 2059 2060 2061 2062 2063 2064 2065 2066 2067 2068 2069 2073 2076 2200 2201 2202 2203 2204 3017 3018"
                ;;
            "curl-8_4_0")
                EXPECTED_FAILS="9 31 39 41 44 46 61 64 65 70 71 72 73 88 153 154 158 163 166 167 168 169 170 171 173 186 206 245 246 258 259 273 277 327 335 388 420 444 540 551 552 554 565 579 584 643 645 646 647 648 649 650 651 652 653 654 666 667 668 669 670 671 672 673 977 1001 1002 1030 1053 1060 1061 1071 1072 1079 1095 1105 1133 1136 1151 1155 1158 1160 1161 1186 1187 1189 1190 1191 1192 1193 1194 1195 1196 1198 1199 1229 1284 1285 1286 1293 1315 1404 1412 1415 1418 1437 1568 1903 1905 1916 1917 1964 2024 2026 2027 2028 2030 2058 2059 2060 2061 2062 2063 2064 2065 2066 2067 2068 2069 2073 2076 2200 2201 2202 2203 2204 3017 3018"
                ;;
            "master")
                EXPECTED_FAILS="9 31 39 41 44 46 61 64 65 70 71 72 73 88 153 154 158 163 166 167 168 169 170 171 173 186 206 245 246 258 259 273 277 327 335 388 420 444 483 540 551 552 554 565 579 584 643 645 646 647 648 649 650 651 652 653 654 666 667 668 669 670 671 672 673 695 977 1001 1002 1030 1053 1060 1061 1071 1072 1079 1095 1105 1133 1136 1151 1155 1158 1160 1161 1186 1187 1189 1190 1191 1192 1193 1194 1195 1196 1198 1199 1229 1284 1285 1286 1293 1315 1404 1412 1415 1418 1437 1476 1568 1608 1610 1615 1654 1660 1903 1905 1916 1917 1964 2024 2026 2027 2028 2030 2058 2059 2060 2061 2062 2063 2064 2065 2066 2067 2068 2069 2073 2076 2200 2201 2202 2203 2204 3017 3018"
                ;;
            *)
                echo "Error: Unknown curl version: $CURL_VERSION"
                exit 1
                ;;
        esac

        # Create temporary files for sorted lists
        TEMP_DIR=$(mktemp -d)
        ACTUAL_SORTED="${TEMP_DIR}/actual_sorted.txt"
        EXPECTED_SORTED="${TEMP_DIR}/expected_sorted.txt"

        # Clean and sort both lists and remove empty lines
        echo "$ACTUAL_FAILS" | tr ' ' '\n' | grep -v '^$' | sort -n > "$ACTUAL_SORTED"
        echo "$EXPECTED_FAILS" | tr ' ' '\n' | grep -v '^$' | sort -n > "$EXPECTED_SORTED"

        echo "DEBUG: Sorted actual fails: $(tr '\n' ' ' < "$ACTUAL_SORTED")"
        echo "DEBUG: Sorted expected fails: $(tr '\n' ' ' < "$EXPECTED_SORTED")"

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
    # ----- OPENVPN -----
    elif [ "$TEST_SUITE" = "openvpn" ]; then
        if [ -f "openvpn-test.log" ]; then
            # Extract failed tests from the log
            ACTUAL_FAILS=$(grep -a '^FAIL: ' openvpn-test.log | sed 's/^FAIL: //' | sort)

            # Define expected failures
            EXPECTED_FAILS="auth_token_testdriver crypto_testdriver pkt_testdriver tls_crypt_testdriver"
            
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
            # Check for expected 7 failed tests (ESP/crypto segfaults)
            if grep -q "7 tests failed" tcpdump-test.log; then
                echo "PASS: tcpdump tests failed as expected with force fail enabled (7 tests failed)"
                exit 0
            else
                echo "FAIL: tcpdump tests did not fail as expected (should have 7 failed tests)"
                exit 1
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
