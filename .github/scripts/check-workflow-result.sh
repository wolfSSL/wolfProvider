#!/bin/bash

set -e

if [ $# -lt 2 ]; then
    echo "Usage: $0 <test_result> [WOLFPROV_FORCE_FAIL] [TEST_SUITE]"
    exit 1
fi

TEST_RESULT="$1"
WOLFPROV_FORCE_FAIL="${2:-}"
TEST_SUITE="${3:-}"

if [ "$WOLFPROV_FORCE_FAIL" = "1" ]; then
    if [ "$TEST_SUITE" = "curl" ]; then
        # --- curl-specific logic ---
        if [ -f "tests/test.log" ]; then
            # Extract and clean the failed test list from the log
            ACTUAL_FAILS=$(grep -a '^TESTFAIL: These test cases failed:' tests/test.log | sed 's/.*failed: //')
        else
            echo "Error: tests/test.log not found"
            exit 1
        fi

        # Get curl version from the workflow ref
        CURL_VERSION="${CURL_REF:-}"

        # Define expected failures based on curl version
        case "$CURL_VERSION" in
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
    elif [ "$TEST_SUITE" = "simple" ]; then
        # --- simple test suite specific logic ---
        if [ -f "test-suite.log" ]; then
            # For simple tests, we expect all tests to fail when force fail is enabled
            if [ $TEST_RESULT -eq 0 ]; then
                echo "Simple tests unexpectedly succeeded with force fail enabled"
                exit 1
            else
                echo "Simple tests failed as expected with force fail enabled"
                exit 0
            fi
        else
            echo "Error: test-suite.log not found"
            exit 1
        fi
    else
        # --- generic force-fail logic for other suites ---
        if [ $TEST_RESULT -eq 0 ]; then
            echo "Test unexpectedly succeeded with force fail enabled"
            exit 1 # failure was not seen when expected
        else
            echo "Test failed as expected with force fail enabled"
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
