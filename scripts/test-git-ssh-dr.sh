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
# Local test script for wolfProvider git operations
# This script tests git operations with wolfProvider
# as the default replace provider

echo "=== wolfProvider Git Operations Local Test ==="
echo "Testing git operations with wolfProvider default replace functionality"
echo ""

# Configuration
KEY_TYPES=("rsa" "ecdsa" "ed25519")
ITERATIONS=10
TEST_BASE_DIR="/tmp/git-wolfprovider-test"
SSH_TEST_ENABLED=${SSH_TEST_ENABLED:-true}  # Enable SSH key testing

# Non-interactive settings
VERBOSE_OUTPUT=${VERBOSE_OUTPUT:-false}     # Set to true for verbose output
QUIET_MODE=${QUIET_MODE:-false}             # Set to true for minimal output
MAX_LOG_LINES=${MAX_LOG_LINES:-5}           # Maximum lines to show from git log

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    local status=$1
    local message=$2
    case $status in
        "SUCCESS")
            echo -e "${GREEN}✓ SUCCESS:${NC} $message"
            ;;
        "FAILURE")
            echo -e "${RED}✗ FAILURE:${NC} $message"
            ;;
        "WARNING")
            echo -e "${YELLOW}⚠ WARNING:${NC} $message"
            ;;
        "INFO")
            echo -e "${BLUE}ℹ INFO:${NC} $message"
            ;;
        *)
            echo "$message"
            ;;
    esac
}

# Function to setup git test environment
setup_git_environment() {
    echo "=== Setting up Git Test Environment ==="

    # Clean up any existing test directory
    rm -rf "$TEST_BASE_DIR"
    mkdir -p "$TEST_BASE_DIR"
    cd "$TEST_BASE_DIR"

    # Configure git
    git config --global user.name "Test User"
    git config --global user.email "test@example.com"
    git config --global init.defaultBranch main

    # Create bare repository
    git init --bare test-repo.git
    print_status "SUCCESS" "Created bare repository at $TEST_BASE_DIR/test-repo.git"

    # Create workspace and initial commit
    mkdir test-workspace
    cd test-workspace
    git init
    echo "# Test Repository" > README.md
    git add README.md
    git commit -m "Initial commit"
    git remote add origin "$TEST_BASE_DIR/test-repo.git"
    git push origin main
    print_status "SUCCESS" "Created initial commit and pushed to bare repository"

    cd "$TEST_BASE_DIR"
    echo ""
}

# Function to verify repository setup
verify_repository() {
    echo "=== Repository Setup Verification ==="
    echo "Checking test repository:"
    ls -la "$TEST_BASE_DIR/"
    echo ""
    echo "Repository contents:"
    ls -la "$TEST_BASE_DIR/test-repo.git/"
    echo ""
    echo "Git log in bare repository:"
    cd "$TEST_BASE_DIR/test-repo.git" && git log --oneline
    echo ""
    echo "Git branches in bare repository:"
    cd "$TEST_BASE_DIR/test-repo.git" && git branch -a
    echo ""
    echo "Git refs in bare repository:"
    cd "$TEST_BASE_DIR/test-repo.git" && git show-ref
    echo ""

    echo "Git information:"
    which git
    git --version
    echo "Git help (first 10 lines):"
    git help -a | head -10
    echo ""
}

# Function to test git operations
test_git_operations() {
    local key_type=$1
    local iterations=$2

    echo "=== Testing Git Operations for $key_type ==="

    # Verify wolfProvider is still active
    echo "Pre-Git wolfProvider Verification:"
    if openssl list -providers | grep -q "wolfSSL Provider"; then
        print_status "SUCCESS" "wolfProvider is active before git operations"
    else
        print_status "FAILURE" "wolfProvider is not active before git operations"
        return 1
    fi
    echo ""

    local success_count=0
    local failure_count=0
    local timing_log="/tmp/git-timing-$key_type.log"
    local error_log="/tmp/git-errors-$key_type.log"

    echo "Iteration,Operation,Status,Duration,Error" > "$timing_log"

    for attempt in $(seq 1 "$iterations"); do
        echo "--- Attempt $attempt for $key_type ---"
        local test_dir="$TEST_BASE_DIR/git-test-$attempt"
        mkdir -p "$test_dir"
        cd "$test_dir"

        for operation in "clone" "push" "pull" "fetch"; do
            echo "Testing $operation operation..."
            local start_time=$(date +%s.%N)
            local status="UNKNOWN"

            case "$operation" in
                "clone")
                    echo "Attempting to clone from $TEST_BASE_DIR/test-repo.git"
                    echo "Current directory: $(pwd)"
                    echo "Repository exists: $(test -d "$TEST_BASE_DIR/test-repo.git" && echo 'YES' || echo 'NO')"

                    if git clone --verbose "$TEST_BASE_DIR/test-repo.git" cloned-repo 2>&1 | tee -a "$error_log"; then
                        status="SUCCESS"
                        ((success_count++))
                        print_status "SUCCESS" "Clone successful"

                        # Verify the clone worked
                        if [ -d "cloned-repo" ]; then
                            echo "Cloned repository exists and contains:"
                            ls -la cloned-repo/
                            echo "Git status in cloned repo:"
                            cd cloned-repo
                            if ! git status 2>/dev/null; then
                                echo "WARNING: Git status failed - potential wolfProvider interference"
                                print_status "WARNING" "Git status failed in cloned repo"
                            fi
                            echo "Git log in cloned repo:"
                            if ! git log --oneline | head -${MAX_LOG_LINES} 2>/dev/null; then
                                echo "WARNING: Git log failed - potential wolfProvider interference"
                                print_status "WARNING" "Git log failed in cloned repo"
                            fi
                            cd ..
                        else
                            print_status "FAILURE" "cloned-repo directory not found after successful clone"
                            status="FAILURE"
                            ((failure_count++))
                        fi
                    else
                        status="FAILURE"
                        ((failure_count++))
                        print_status "FAILURE" "Clone failed on attempt $attempt"
                    fi
                    ;;

                "push")
                    if [ -d "cloned-repo" ]; then
                        echo "Entering cloned-repo directory..."
                        cd cloned-repo
                        echo "Test change $attempt" >> test-file.txt
                        git add test-file.txt
                        git commit -m "Test commit $attempt" || true
                        echo "Attempting git push..."
                        if timeout 30 git push origin main 2>>"$error_log"; then
                            status="SUCCESS"
                            ((success_count++))
                            print_status "SUCCESS" "Push successful"
                        else
                            status="FAILURE"
                            ((failure_count++))
                            print_status "FAILURE" "Push failed on attempt $attempt"
                        fi
                        cd ..
                    else
                        status="SKIPPED"
                        echo "Skipping push - clone failed"
                    fi
                    ;;

                "pull")
                    if [ -d "cloned-repo" ]; then
                        echo "Entering cloned-repo directory for pull..."
                        cd cloned-repo
                        echo "Attempting git pull..."
                        if timeout 30 git pull origin main 2>>"$error_log"; then
                            status="SUCCESS"
                            ((success_count++))
                            print_status "SUCCESS" "Pull successful"
                        else
                            status="FAILURE"
                            ((failure_count++))
                            print_status "FAILURE" "Pull failed on attempt $attempt"
                        fi
                        cd ..
                    else
                        status="SKIPPED"
                        echo "Skipping pull - clone failed"
                    fi
                    ;;

                "fetch")
                    if [ -d "cloned-repo" ]; then
                        echo "Entering cloned-repo directory for fetch..."
                        cd cloned-repo
                        echo "Attempting git fetch..."
                        if timeout 30 git fetch origin 2>>"$error_log"; then
                            status="SUCCESS"
                            ((success_count++))
                            print_status "SUCCESS" "Fetch successful"
                        else
                            status="FAILURE"
                            ((failure_count++))
                            print_status "FAILURE" "Fetch failed on attempt $attempt"
                        fi
                        cd ..
                    else
                        status="SKIPPED"
                        echo "Skipping fetch - clone failed"
                    fi
                    ;;
            esac

            local end_time=$(date +%s.%N)
            local duration=$(echo "$end_time - $start_time" | bc -l 2>/dev/null || echo "0")
            echo "$attempt,$operation,$status,$duration," >> "$timing_log"
            echo "  $operation: $status (${duration}s)"
        done

        rm -rf "$test_dir"
    done

    # Print summary
    echo ""
    echo "=== SUMMARY FOR $key_type ==="
    echo "Total operations: $((success_count + failure_count))"
    echo "Successful operations: $success_count"
    echo "Failed operations: $failure_count"

    if [ $failure_count -gt 0 ]; then
        local failure_rate=$(echo "scale=2; $failure_count * 100 / ($success_count + failure_count)" | bc -l)
        echo "Failure rate: ${failure_rate}%"
    else
        echo "Failure rate: 0%"
    fi

    echo ""
    echo "Timing data saved to: $timing_log"
    echo "Error log saved to: $error_log"

    if [ -f "$error_log" ] && [ -s "$error_log" ]; then
        echo ""
        echo "=== ERROR LOG SUMMARY ==="
        tail -20 "$error_log"
    fi
    echo ""
}

# Function to test git operations with different SSH key types
test_ssh_key_operations() {
    local key_type=$1
    local iterations=$2

    echo "=== Testing Git Operations with $key_type SSH Keys ==="
    echo "Investigating intermittent failures with wolfProvider + git + SSH keys"
    echo ""

    # Verify wolfProvider is still active (if available)
    echo "Pre-SSH wolfProvider Verification:"
    if openssl list -providers | grep -q "wolfSSL Provider"; then
        print_status "SUCCESS" "wolfProvider is active before SSH key operations"
    else
        print_status "INFO" "wolfProvider not detected - testing SSH keys without wolfProvider"
    fi
    echo ""

    local success_count=0
    local failure_count=0
    local timing_log="/tmp/ssh-key-timing-$key_type.log"
    local error_log="/tmp/ssh-key-errors-$key_type.log"

    echo "Iteration,Operation,Status,Duration,Error" > "$timing_log"

    # Test SSH key generation and git operations
    for attempt in $(seq 1 "$iterations"); do
        echo "--- SSH Key Test $attempt for $key_type ---"
        local test_dir="$TEST_BASE_DIR/ssh-key-test-$attempt"
        mkdir -p "$test_dir"
        cd "$test_dir"

        # Generate SSH key for this attempt
        local ssh_key="/tmp/test_${key_type}_key_$attempt"
        local ssh_pub_key="${ssh_key}.pub"

        echo "Generating $key_type SSH key (attempt $attempt)..."
        local key_gen_start=$(date +%s.%N)
        local key_gen_status="UNKNOWN"

        case "$key_type" in
            "rsa")
                if ssh-keygen -t rsa -b 4096 -f "$ssh_key" -N "" -C "test-rsa-key-$attempt" 2>/dev/null; then
                    key_gen_status="SUCCESS"
                    ((success_count++))
                    print_status "SUCCESS" "RSA key generation successful"
                else
                    key_gen_status="FAILURE"
                    ((failure_count++))
                    print_status "FAILURE" "RSA key generation failed"
                fi
                ;;
            "ecdsa")
                if ssh-keygen -t ecdsa -b 521 -f "$ssh_key" -N "" -C "test-ecdsa-key-$attempt" 2>/dev/null; then
                    key_gen_status="SUCCESS"
                    ((success_count++))
                    print_status "SUCCESS" "ECDSA key generation successful"
                else
                    key_gen_status="FAILURE"
                    ((failure_count++))
                    print_status "FAILURE" "ECDSA key generation failed"
                fi
                ;;
            "ed25519")
                if ssh-keygen -t ed25519 -f "$ssh_key" -N "" -C "test-ed25519-key-$attempt" 2>/dev/null; then
                    key_gen_status="SUCCESS"
                    ((success_count++))
                    print_status "SUCCESS" "ED25519 key generation successful"
                else
                    key_gen_status="FAILURE"
                    ((failure_count++))
                    print_status "FAILURE" "ED25519 key generation failed"
                fi
                ;;
        esac

        local key_gen_end=$(date +%s.%N)
        local key_gen_duration=$(echo "$key_gen_end - $key_gen_start" | bc -l 2>/dev/null || echo "0")
        echo "$attempt,key_generation,$key_gen_status,$key_gen_duration," >> "$timing_log"
        echo "  Key generation: $key_gen_status (${key_gen_duration}s)"

        if [ "$key_gen_status" = "SUCCESS" ] && [ -f "$ssh_key" ]; then
            echo "Key fingerprint: $(ssh-keygen -lf "$ssh_pub_key" 2>/dev/null | awk '{print $2}')"
            echo "Key size: $(stat -c%s "$ssh_key") bytes"

            # Test git operations with this SSH key
            for operation in "clone" "push" "pull" "fetch"; do
                echo "Testing git $operation with $key_type SSH key..."
                local start_time=$(date +%s.%N)
                local status="UNKNOWN"

                case "$operation" in
                    "clone")
                        echo "Setting up SSH key for git operations..."
                        mkdir -p ~/.ssh
                        cp "$ssh_key" ~/.ssh/id_${key_type}_test
                        cp "$ssh_pub_key" ~/.ssh/id_${key_type}_test.pub
                        chmod 600 ~/.ssh/id_${key_type}_test
                        chmod 644 ~/.ssh/id_${key_type}_test.pub

                        # Test git clone with SSH key (using local path but with SSH key setup)
                        if git clone --verbose "$TEST_BASE_DIR/test-repo.git" cloned-repo 2>&1 | tee -a "$error_log"; then
                            status="SUCCESS"
                            ((success_count++))
                            print_status "SUCCESS" "Git clone with $key_type key successful"

                            if [ -d "cloned-repo" ]; then
                                echo "Cloned repository exists and contains:"
                                ls -la cloned-repo/
                                echo "Git status in cloned repo:"
                                cd cloned-repo
                                git status || echo "Git status failed (this may be normal)"
                                echo "Git log in cloned repo:"
                                git log --oneline | head -${MAX_LOG_LINES} || echo "Git log failed"
                                cd ..
                            fi
                        else
                            status="FAILURE"
                            ((failure_count++))
                            print_status "FAILURE" "Git clone with $key_type key failed"
                        fi
                        ;;

                    "push")
                        if [ -d "cloned-repo" ]; then
                            echo "Entering cloned-repo directory for git push..."
                            cd cloned-repo
                            echo "Test change $attempt with $key_type key" >> test-file.txt
                            git add test-file.txt
                            git commit -m "$key_type Test commit $attempt" || true
                            echo "Attempting git push..."
                            if timeout 30 git push origin main 2>>"$error_log"; then
                                status="SUCCESS"
                                ((success_count++))
                                print_status "SUCCESS" "Git push with $key_type key successful"
                            else
                                status="FAILURE"
                                ((failure_count++))
                                print_status "FAILURE" "Git push with $key_type key failed"
                            fi
                            cd ..
                        else
                            status="SKIPPED"
                            echo "Skipping push - clone failed"
                        fi
                        ;;

                    "pull")
                        if [ -d "cloned-repo" ]; then
                            echo "Entering cloned-repo directory for git pull..."
                            cd cloned-repo
                            echo "Attempting git pull..."
                            if timeout 30 git pull origin main 2>>"$error_log"; then
                                status="SUCCESS"
                                ((success_count++))
                                print_status "SUCCESS" "Git pull with $key_type key successful"
                            else
                                status="FAILURE"
                                ((failure_count++))
                                print_status "FAILURE" "Git pull with $key_type key failed"
                            fi
                            cd ..
                        else
                            status="SKIPPED"
                            echo "Skipping pull - clone failed"
                        fi
                        ;;

                    "fetch")
                        if [ -d "cloned-repo" ]; then
                            echo "Entering cloned-repo directory for git fetch..."
                            cd cloned-repo
                            echo "Attempting git fetch..."
                            if timeout 30 git fetch origin 2>>"$error_log"; then
                                status="SUCCESS"
                                ((success_count++))
                                print_status "SUCCESS" "Git fetch with $key_type key successful"
                            else
                                status="FAILURE"
                                ((failure_count++))
                                print_status "FAILURE" "Git fetch with $key_type key failed"
                            fi
                            cd ..
                        else
                            status="SKIPPED"
                            echo "Skipping fetch - clone failed"
                        fi
                        ;;
                esac

                local end_time=$(date +%s.%N)
                local duration=$(echo "$end_time - $start_time" | bc -l 2>/dev/null || echo "0")
                echo "$attempt,git_${operation},$status,$duration," >> "$timing_log"
                echo "  Git $operation with $key_type: $status (${duration}s)"
            done

            # Clean up SSH key for this attempt
            rm -f ~/.ssh/id_${key_type}_test ~/.ssh/id_${key_type}_test.pub
        fi

        # Clean up test files
        rm -f "$ssh_key" "$ssh_pub_key"
        rm -rf "$test_dir"
    done

    # Print summary
    echo ""
    echo "=== SSH KEY TEST SUMMARY FOR $key_type ==="
    echo "Total operations: $((success_count + failure_count))"
    echo "Successful operations: $success_count"
    echo "Failed operations: $failure_count"

    if [ $failure_count -gt 0 ]; then
        local failure_rate=$(echo "scale=2; $failure_count * 100 / ($success_count + failure_count)" | bc -l)
        echo "Failure rate: ${failure_rate}%"
        if [ "$key_type" = "ed25519" ] && [ $failure_count -gt 2 ]; then
            print_status "WARNING" "High failure rate detected for ED25519 keys - potential intermittent issue!"
            echo "This confirms the suspected ED25519 intermittent failures!"
        fi
    else
        echo "Failure rate: 0%"
    fi

    echo ""
    echo "SSH Key timing data saved to: $timing_log"
    echo "SSH Key error log saved to: $error_log"

    if [ -f "$error_log" ] && [ -s "$error_log" ]; then
        echo ""
        echo "=== SSH KEY ERROR LOG SUMMARY ==="
        tail -20 "$error_log"
    fi
    echo ""
}

# Function to cleanup
cleanup() {
    echo "=== Cleanup ==="

    # Stop SSH server if running
    if pgrep -f "sshd.*2222" > /dev/null; then
        echo "Stopping SSH test server..."
        pkill -f "sshd.*2222" || true
    fi

    # Clean up test directory
    rm -rf "$TEST_BASE_DIR"
    print_status "SUCCESS" "Cleaned up test directory: $TEST_BASE_DIR"
    echo ""
}

# Function to show usage
show_usage() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  -h, --help              Show this help message"
    echo "  -v, --verbose           Enable verbose debug output"
    echo "  -q, --quiet             Enable quiet mode (minimal output)"
    echo "  -s, --ssh               Enable SSH key testing (default: enabled)"
    echo "  -n, --no-ssh            Disable SSH key testing"
    echo "  -i, --iterations N      Number of iterations per test (default: 10)"
    echo "  -k, --key-types TYPES   Comma-separated key types (default: rsa,ecdsa,ed25519)"
    echo "  -l, --log-lines N       Maximum git log lines to show (default: 5)"
    echo ""
    echo "Environment Variables:"
    echo "  VERBOSE_OUTPUT=true     Enable verbose output"
    echo "  QUIET_MODE=true         Enable quiet mode"
    echo "  SSH_TEST_ENABLED=false  Disable SSH testing"
    echo "  MAX_LOG_LINES=10        Set maximum log lines"
    echo ""
    echo "Examples:"
    echo "  $0                      # Run all tests with default settings"
    echo "  $0 --verbose            # Run with verbose debug output"
    echo "  $0 --no-ssh             # Skip SSH key testing"
    echo "  $0 --iterations 20      # Run 20 iterations per test"
    echo "  $0 --key-types rsa,ed25519  # Test only RSA and ED25519 keys"
    echo ""
}

# Function to parse command line arguments
parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                show_usage
                exit 0
                ;;
            -v|--verbose)
                VERBOSE_OUTPUT=true
                shift
                ;;
            -q|--quiet)
                QUIET_MODE=true
                shift
                ;;
            -s|--ssh)
                SSH_TEST_ENABLED=true
                shift
                ;;
            -n|--no-ssh)
                SSH_TEST_ENABLED=false
                shift
                ;;
            -i|--iterations)
                ITERATIONS="$2"
                shift 2
                ;;
            -k|--key-types)
                IFS=',' read -ra KEY_TYPES <<< "$2"
                shift 2
                ;;
            -l|--log-lines)
                MAX_LOG_LINES="$2"
                shift 2
                ;;
            *)
                echo "Unknown option: $1"
                show_usage
                exit 1
                ;;
        esac
    done
}

# Main execution
main() {
    # Parse command line arguments
    parse_args "$@"

    echo "Starting wolfProvider Git Operations Test"
    echo "=========================================="
    echo ""

    # Check if running as root (recommended for full permissions)
    if [ "$EUID" -ne 0 ]; then
        print_status "WARNING" "Not running as root. Some operations may fail due to permissions."
        echo "Consider running with: sudo $0"
        echo ""
    fi

    # Verify wolfProvider is properly installed
    source scripts/verify-debian.sh

    # Setup git environment
    setup_git_environment

    # Verify repository setup
    verify_repository

    # Test git operations for each key type
    for key_type in "${KEY_TYPES[@]}"; do
        test_git_operations "$key_type" "$ITERATIONS"
    done

    # Test SSH key operations if enabled
    if [ "$SSH_TEST_ENABLED" = "true" ]; then
        echo "=== SSH Key Testing Enabled ==="
        echo "Testing SSH key generation and validation with different key types"
        echo ""

        for key_type in "${KEY_TYPES[@]}"; do
            test_ssh_key_operations "$key_type" "$ITERATIONS"
        done
    else
        echo "=== SSH Key Testing Disabled ==="
        echo "Set SSH_TEST_ENABLED=true to enable SSH key testing"
        echo ""
    fi

    # Final verification
    echo "=== Final wolfProvider Verification ==="
    if openssl list -providers | grep -q "wolfSSL Provider"; then
        print_status "SUCCESS" "wolfProvider is still active after git operations"
    else
        print_status "WARNING" "wolfProvider may have been affected by git operations"
    fi
    echo ""

    # Cleanup
    cleanup

    print_status "SUCCESS" "wolfProvider Git Operations Test completed successfully!"
}

# Run main function
main "$@"
