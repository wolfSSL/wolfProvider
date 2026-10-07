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
# Git over SSH with wolfProvider as the replace-default provider.
#
# Starts a local sshd and runs ssh-keygen and git clone, push, pull and fetch
# against it over ssh://. Client and server allow only the algorithms of one
# suite, and every git operation checks the negotiated algorithms:
#
#   aes-ctr  RSA 4096 keys (rsa-sha2-512), diffie-hellman-group14-sha256,
#            aes128-ctr, hmac-sha2-256
#   aes-gcm  ECDSA P-521 keys (ecdsa-sha2-nistp521), ecdh-sha2-nistp256,
#            aes256-gcm@openssh.com
#
# OpenSSH gets its RNG, SHA-2 digests and AES ciphers from libcrypto, so
# from wolfProvider. With WOLFPROV_FORCE_FAIL=1 only the client operations
# run with force fail. The script exits 0 only when every operation succeeds,
# and its Result line counts the operations that failed with FORCE_FAIL_REASON.
#
# Force fail stops ssh and ssh-keygen in seed_rng(), before any key exchange
# or cipher, so only the normal runs show the AES and SHA-2 paths working.
# Ed25519, curve25519 and chacha20-poly1305, OpenSSH's defaults, are left
# out: OpenSSH computes them itself and asks wolfProvider only for RNG and
# SHA-2, which both suites already use.
#
# Runs as root with /usr/sbin/sshd, binds sshd to 127.0.0.1:2222, and works
# in a new mktemp directory under /tmp.

SUITE="aes-ctr"
ITERATIONS=10
VERBOSE_OUTPUT=false
WOLFPROV_FORCE_FAIL=${WOLFPROV_FORCE_FAIL:-0}

# OpenSSH exits in seed_rng() when wolfProvider's RNG fails.
FORCE_FAIL_REASON="PRNG is not seeded"

SSH_PORT=2222
# Seconds before a single setup step or client command is killed
OP_TIMEOUT=120
# Set by init_workspace(), together with every path inside it
TEST_BASE_DIR=""
# Commit that the next pull or fetch must bring in, set by advance_remote()
REMOTE_HEAD=""

OPS=("keygen" "clone" "push" "pull" "fetch")
declare -A OK_COUNT RNG_COUNT FAIL_COUNT SKIP_COUNT

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

is_force_fail() {
    [ "${WOLFPROV_FORCE_FAIL}" = "1" ]
}

# Print the last lines of a log file, if it has any
show_log() {
    local title=$1
    local file=$2

    if [ -s "$file" ]; then
        echo "--- $title (last 20 lines of $file) ---"
        tail -20 "$file"
    fi
}

die() {
    print_status "FAILURE" "$1"
    show_log "setup log" "$SETUP_LOG"
    show_log "sshd log" "$SSHD_LOG"
    exit 1
}

# Run a setup step without force fail and stop the test if it fails
setup_run() {
    if ! env -u WOLFPROV_FORCE_FAIL timeout "$OP_TIMEOUT" "$@" \
            >>"$SETUP_LOG" 2>&1; then
        die "Setup step failed: $*"
    fi
}

select_suite() {
    case "$SUITE" in
        "aes-ctr")
            KEY_TYPE="rsa"
            KEY_BITS=4096
            KEY_ALGO="rsa-sha2-512"
            HOST_KEY_NAME="ssh-rsa"
            KEX_ALGO="diffie-hellman-group14-sha256"
            CIPHER="aes128-ctr"
            MAC="hmac-sha2-256"
            NEGOTIATED_MAC="hmac-sha2-256"
            ;;
        "aes-gcm")
            KEY_TYPE="ecdsa"
            KEY_BITS=521
            KEY_ALGO="ecdsa-sha2-nistp521"
            HOST_KEY_NAME="ecdsa-sha2-nistp521"
            KEX_ALGO="ecdh-sha2-nistp256"
            CIPHER="aes256-gcm@openssh.com"
            MAC="hmac-sha2-256"
            NEGOTIATED_MAC="<implicit>"
            ;;
        *)
            echo "Unknown suite: $SUITE"
            show_usage
            exit 1
            ;;
    esac
}

ssh_command() {
    local key=$1

    echo "ssh -F /dev/null -i $key -o IdentitiesOnly=yes -o BatchMode=yes" \
         "-o StrictHostKeyChecking=yes -o UserKnownHostsFile=$KNOWN_HOSTS" \
         "-o GlobalKnownHostsFile=/dev/null -o ConnectTimeout=10" \
         "-o ServerAliveInterval=10 -o ServerAliveCountMax=3" \
         "-o HostKeyAlgorithms=$KEY_ALGO -o PubkeyAcceptedAlgorithms=$KEY_ALGO" \
         "-o KexAlgorithms=$KEX_ALGO -o Ciphers=$CIPHER -o MACs=$MAC" \
         "-v -E $SSH_LOG"
}

sshd_listening() {
    (exec 3<>"/dev/tcp/127.0.0.1/$SSH_PORT") 2>/dev/null
}

# Create a new workspace (mode 0700) and derive every test path from it
init_workspace() {
    TEST_BASE_DIR=$(mktemp -d /tmp/git-wolfprovider-test.XXXXXX) || {
        echo "Cannot create a workspace under /tmp"
        exit 1
    }
    KEY_DIR="$TEST_BASE_DIR/keys"
    HOST_KEY="$KEY_DIR/host_key"
    SETUP_KEY="$KEY_DIR/setup_key"
    AUTH_KEYS="$KEY_DIR/authorized_keys"
    KNOWN_HOSTS="$KEY_DIR/known_hosts"
    SSHD_CONFIG="$TEST_BASE_DIR/sshd_config"
    SSHD_PID="$TEST_BASE_DIR/sshd.pid"
    SSHD_LOG="$TEST_BASE_DIR/sshd.log"
    SETUP_LOG="$TEST_BASE_DIR/setup.log"
    OP_LOG="$TEST_BASE_DIR/op.log"
    SSH_LOG="$TEST_BASE_DIR/ssh.log"
    BARE_REPO="$TEST_BASE_DIR/test-repo.git"
    SETUP_CLONE="$TEST_BASE_DIR/setup-clone"
    UPSTREAM_CLONE="$TEST_BASE_DIR/upstream-clone"
}

# Stop the sshd this run started and remove its workspace
cleanup() {
    if [ -z "$TEST_BASE_DIR" ]; then
        return
    fi
    if [ -s "$SSHD_PID" ]; then
        kill "$(cat "$SSHD_PID")" 2>/dev/null
    fi
    rm -rf "$TEST_BASE_DIR"
}

# Check that ssh and openssl load the replace-default libcrypto
check_install() {
    local version
    local providers

    echo "=== Installation Check ==="
    version=$(env -u WOLFPROV_FORCE_FAIL ssh -V 2>&1)
    echo "ssh -V: $version"
    case "$version" in
        *"+wolfProvider-replace-default"*)
            ;;
        *)
            die "ssh is not linked with the wolfProvider replace-default libcrypto"
            ;;
    esac

    providers=$(env -u WOLFPROV_FORCE_FAIL openssl list -providers 2>&1)
    echo "$providers"
    case "$providers" in
        *"wolfSSL Provider"*)
            ;;
        *)
            die "wolfProvider is not the active provider"
            ;;
    esac

    if [ ! -x /usr/sbin/sshd ]; then
        die "/usr/sbin/sshd not found"
    fi
    echo ""
}

setup_sshd() {
    echo "=== Starting sshd on 127.0.0.1:$SSH_PORT ($SUITE) ==="

    setup_run ssh-keygen -q -t "$KEY_TYPE" -b "$KEY_BITS" -N "" \
        -C "git-ssh-dr-host" -f "$HOST_KEY"
    setup_run ssh-keygen -q -t "$KEY_TYPE" -b "$KEY_BITS" -N "" \
        -C "git-ssh-dr-setup" -f "$SETUP_KEY"
    cp "$SETUP_KEY.pub" "$AUTH_KEYS"
    echo "[127.0.0.1]:$SSH_PORT $(cut -d' ' -f1,2 "$HOST_KEY.pub")" \
        > "$KNOWN_HOSTS"

    cat > "$SSHD_CONFIG" <<EOF
Port $SSH_PORT
ListenAddress 127.0.0.1
HostKey $HOST_KEY
PidFile $SSHD_PID
AuthorizedKeysFile $AUTH_KEYS
StrictModes no
UsePAM no
PubkeyAuthentication yes
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitRootLogin prohibit-password
HostKeyAlgorithms $KEY_ALGO
PubkeyAcceptedAlgorithms $KEY_ALGO
KexAlgorithms $KEX_ALGO
Ciphers $CIPHER
MACs $MAC
LogLevel VERBOSE
EOF

    mkdir -p /run/sshd
    setup_run /usr/sbin/sshd -t -f "$SSHD_CONFIG"
    if sshd_listening; then
        die "Port $SSH_PORT is already in use"
    fi
    setup_run /usr/sbin/sshd -f "$SSHD_CONFIG" -E "$SSHD_LOG"

    for _ in $(seq 1 50); do
        if sshd_listening; then
            print_status "SUCCESS" "sshd is listening"
            echo ""
            return
        fi
        sleep 0.1
    done
    die "sshd did not start listening on port $SSH_PORT"
}

setup_repository() {
    local seed="$TEST_BASE_DIR/seed"

    echo "=== Setting up Git Repository ==="
    cat > "$GIT_CONFIG_GLOBAL" <<EOF
[user]
	name = Test User
	email = test@example.com
[init]
	defaultBranch = main
[pull]
	ff = only
EOF

    setup_run git init -q --bare "$BARE_REPO"
    setup_run git init -q "$seed"
    echo "# Test Repository" > "$seed/README.md"
    setup_run git -C "$seed" add README.md
    setup_run git -C "$seed" commit -q -m "Initial commit"
    setup_run git -C "$seed" push -q "$BARE_REPO" main

    # Clone over SSH: the server works, and force fail has a clone to use
    setup_run env GIT_SSH_COMMAND="$(ssh_command "$SETUP_KEY")" \
        git clone -q "$REPO_URL" "$SETUP_CLONE"
    print_status "SUCCESS" "Created $BARE_REPO and cloned it over SSH"

    # Local clone that adds commits for pull and fetch to download
    setup_run git clone -q "$BARE_REPO" "$UPSTREAM_CLONE"
    echo ""
}

# Require the suite's algorithms in the ssh client log of the last operation
check_negotiation() {
    local want

    for want in "kex: algorithm: $KEX_ALGO" \
                "kex: host key algorithm: $KEY_ALGO" \
                "kex: server->client cipher: $CIPHER MAC: $NEGOTIATED_MAC" \
                "kex: client->server cipher: $CIPHER MAC: $NEGOTIATED_MAC" \
                "Server host key: $HOST_KEY_NAME" \
                "Authenticated to 127.0.0.1"; do
        if ! grep -qF "$want" "$SSH_LOG"; then
            echo "Not found in ssh log: $want"
            return 1
        fi
    done
}

# Require that ref in dir is the commit advance_remote() pushed last
check_ref() {
    local dir=$1
    local ref=$2
    local id

    if [ -z "$REMOTE_HEAD" ]; then
        return 0
    fi
    id=$(git -C "$dir" rev-parse "$ref") || return 1
    if [ "$id" != "$REMOTE_HEAD" ]; then
        echo "$ref is $id, expected $REMOTE_HEAD"
        return 1
    fi
}

op_keygen() {
    local key=$1

    timeout "$OP_TIMEOUT" ssh-keygen -q -t "$KEY_TYPE" -b "$KEY_BITS" -N "" \
        -C "git-ssh-dr-test" -f "$key"
}

op_clone() {
    local key=$1
    local dir=$2

    GIT_SSH_COMMAND="$(ssh_command "$key")" \
        timeout "$OP_TIMEOUT" git clone "$REPO_URL" "$dir" &&
        check_negotiation
}

op_push() {
    local key=$1
    local dir=$2
    local head
    local remote

    GIT_SSH_COMMAND="$(ssh_command "$key")" \
        timeout "$OP_TIMEOUT" git -C "$dir" push origin main || return
    check_negotiation || return 1

    head=$(git -C "$dir" rev-parse HEAD) || return 1
    remote=$(GIT_SSH_COMMAND="$(ssh_command "$key")" \
        timeout "$OP_TIMEOUT" git -C "$dir" ls-remote origin refs/heads/main) ||
        return
    if [ "${remote%%[[:space:]]*}" != "$head" ]; then
        echo "Remote main is '$remote', expected $head"
        return 1
    fi
}

op_pull() {
    local key=$1
    local dir=$2

    GIT_SSH_COMMAND="$(ssh_command "$key")" \
        timeout "$OP_TIMEOUT" git -C "$dir" pull origin main &&
        check_negotiation && check_ref "$dir" HEAD
}

op_fetch() {
    local key=$1
    local dir=$2

    GIT_SSH_COMMAND="$(ssh_command "$key")" \
        timeout "$OP_TIMEOUT" git -C "$dir" fetch origin &&
        check_negotiation && check_ref "$dir" origin/main
}

# Run one client operation, count its result and return its exit status
run_op() {
    local op=$1
    local rc
    local outcome
    local expected
    shift

    : > "$OP_LOG"
    : > "$SSH_LOG"
    "$@" >"$OP_LOG" 2>&1
    rc=$?
    if [ $rc -eq 124 ]; then
        echo "Timed out after ${OP_TIMEOUT}s" >> "$OP_LOG"
    fi

    if [ "$VERBOSE_OUTPUT" = "true" ]; then
        sed 's/^/    /' "$OP_LOG"
    fi

    if [ $rc -eq 0 ]; then
        ((OK_COUNT[$op]++))
        outcome="succeeded"
    elif grep -qF "$FORCE_FAIL_REASON" "$OP_LOG" "$SSH_LOG"; then
        ((RNG_COUNT[$op]++))
        outcome="failed on the RNG"
    else
        ((FAIL_COUNT[$op]++))
        outcome="failed"
    fi

    if is_force_fail; then
        expected="failed on the RNG"
    else
        expected="succeeded"
    fi
    if [ "$outcome" = "$expected" ]; then
        print_status "SUCCESS" "$op $outcome"
    else
        print_status "FAILURE" "$op $outcome"
        show_log "$op output" "$OP_LOG"
        show_log "ssh log" "$SSH_LOG"
        show_log "sshd log" "$SSHD_LOG"
    fi

    return $rc
}

skip_op() {
    local op=$1

    ((SKIP_COUNT[$op]++))
    print_status "WARNING" "$op skipped"
}

# Commit a change to push, without force fail
make_commit() {
    local dir=$1
    local attempt=$2

    echo "Test change $attempt" >> "$dir/test-file.txt"
    setup_run git -C "$dir" add test-file.txt
    setup_run git -C "$dir" commit -q -m "Test commit $attempt"
}

# Push a new commit from UPSTREAM_CLONE, without force fail
advance_remote() {
    local label=$1

    setup_run git -C "$UPSTREAM_CLONE" pull -q origin main
    echo "Upstream change $label" >> "$UPSTREAM_CLONE/upstream-file.txt"
    setup_run git -C "$UPSTREAM_CLONE" add upstream-file.txt
    setup_run git -C "$UPSTREAM_CLONE" commit -q -m "Upstream commit $label"
    setup_run git -C "$UPSTREAM_CLONE" push -q origin main
    REMOTE_HEAD=$(git -C "$UPSTREAM_CLONE" rev-parse HEAD) ||
        die "Cannot read the upstream clone's HEAD"
}

# Run keygen, clone, push, pull and fetch once. Under force fail, a step
# that fails uses the setup key or setup clone so the next step still runs.
run_iteration() {
    local attempt=$1
    local iter_dir="$TEST_BASE_DIR/iter-$attempt"
    local key="$iter_dir/id_$KEY_TYPE"
    local clone_key=""
    local work_dir=""
    local op

    echo "--- Iteration $attempt of $ITERATIONS ($SUITE) ---"
    mkdir -p "$iter_dir"

    if run_op "keygen" op_keygen "$key"; then
        cat "$key.pub" >> "$AUTH_KEYS"
        clone_key=$key
    elif is_force_fail; then
        clone_key=$SETUP_KEY
    fi

    if [ -z "$clone_key" ]; then
        skip_op "clone"
    elif run_op "clone" op_clone "$clone_key" "$iter_dir/clone"; then
        work_dir="$iter_dir/clone"
    elif is_force_fail; then
        work_dir=$SETUP_CLONE
    fi

    for op in "push" "pull" "fetch"; do
        if [ -z "$work_dir" ]; then
            skip_op "$op"
            continue
        fi
        if [ "$op" = "push" ]; then
            make_commit "$work_dir" "$attempt"
        elif ! is_force_fail; then
            advance_remote "$attempt-$op"
        fi
        if ! run_op "$op" "op_$op" "$clone_key" "$work_dir" &&
                [ "$op" = "push" ] && ! is_force_fail; then
            # Drop the unpushed commit so pull can still fast-forward
            setup_run git -C "$work_dir" reset -q --hard origin/main
        fi
    done

    rm -rf "$iter_dir"
    echo ""
}

show_usage() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  -h, --help              Show this help message"
    echo "  -v, --verbose           Print the output of every operation"
    echo "  -i, --iterations N      Number of iterations (default: 10)"
    echo "  -s, --suite SUITE       aes-ctr or aes-gcm (default: aes-ctr)"
    echo ""
}

# Exit unless the option in $1 is followed by a value
need_value() {
    if [ $# -lt 2 ]; then
        echo "Missing value for $1"
        show_usage
        exit 1
    fi
}

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
            -i|--iterations)
                need_value "$@"
                ITERATIONS="$2"
                shift 2
                ;;
            -s|--suite)
                need_value "$@"
                SUITE="$2"
                shift 2
                ;;
            *)
                echo "Unknown option: $1"
                show_usage
                exit 1
                ;;
        esac
    done

    if ! [[ "$ITERATIONS" =~ ^[1-9][0-9]*$ ]]; then
        echo "Invalid iteration count: $ITERATIONS"
        exit 1
    fi
}

main() {
    local op
    local ok=0
    local rng=0
    local failed=0
    local skipped=0

    parse_args "$@"
    select_suite

    echo "=== wolfProvider Git over SSH Test ==="
    echo "Suite: $SUITE ($KEY_ALGO, $KEX_ALGO, $CIPHER, $MAC)"
    echo "Iterations: $ITERATIONS"
    if is_force_fail; then
        echo "WOLFPROV_FORCE_FAIL=1: client operations are expected to fail" \
             "with '$FORCE_FAIL_REASON'"
    fi
    echo ""

    if [ "$(id -u)" -ne 0 ]; then
        echo "This test starts sshd and must run as root"
        exit 1
    fi

    trap cleanup EXIT
    init_workspace
    mkdir -m 700 "$KEY_DIR"

    export GIT_CONFIG_GLOBAL="$TEST_BASE_DIR/gitconfig"
    REPO_URL="ssh://$(id -un)@127.0.0.1:$SSH_PORT$BARE_REPO"

    check_install
    setup_sshd
    setup_repository

    for op in "${OPS[@]}"; do
        OK_COUNT[$op]=0
        RNG_COUNT[$op]=0
        FAIL_COUNT[$op]=0
        SKIP_COUNT[$op]=0
    done

    for attempt in $(seq 1 "$ITERATIONS"); do
        run_iteration "$attempt"
    done

    echo "=== Summary ($SUITE, $ITERATIONS iterations) ==="
    printf "  %-7s %9s %12s %14s %8s\n" "" "succeeded" "RNG failure" \
        "other failure" "skipped"
    for op in "${OPS[@]}"; do
        printf "  %-7s %9d %12d %14d %8d\n" "$op" "${OK_COUNT[$op]}" \
            "${RNG_COUNT[$op]}" "${FAIL_COUNT[$op]}" "${SKIP_COUNT[$op]}"
        ok=$((ok + OK_COUNT[$op]))
        rng=$((rng + RNG_COUNT[$op]))
        failed=$((failed + FAIL_COUNT[$op]))
        skipped=$((skipped + SKIP_COUNT[$op]))
    done
    echo ""
    # check-workflow-result.sh matches this line in force fail runs
    echo "Result: $ok succeeded, $rng failed on the RNG, $failed failed" \
         "otherwise, $skipped skipped"

    if [ $rng -eq 0 ] && [ $failed -eq 0 ] && [ $skipped -eq 0 ] &&
            [ $ok -gt 0 ]; then
        print_status "SUCCESS" "All $ok operations succeeded"
        exit 0
    fi
    if ! is_force_fail; then
        show_log "sshd log" "$SSHD_LOG"
        print_status "FAILURE" "Not every operation succeeded"
    fi
    exit 1
}

main "$@"
