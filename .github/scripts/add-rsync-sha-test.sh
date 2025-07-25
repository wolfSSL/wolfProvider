i#!/bin/bash
# add-rsync-sha-test.sh
# Script to add SHA test to rsync testsuite
# Should be placed in /wolfprovider/.github/scripts/

set -e

# Create the SHA test script in the testsuite directory
cat > testsuite/sha-test.test << 'EOF'
#!/bin/sh
# Use rsync binary from current directory or parent directory
if [ -f "./rsync" ]; then
    RSYNC="./rsync"
elif [ -f "../rsync" ]; then
    RSYNC="../rsync"
else
    echo "ERROR: Could not find rsync binary"
    exit 1
fi
# Verify SHA256 and SHA512 are available
if $RSYNC --version | grep -A1 "Daemon auth list:" | grep -q "sha512.*sha256"; then
    echo "PASS: SHA256 and SHA512 available"
else
    echo "FAIL: SHA256/SHA512 not found"
    exit 1
fi
# Verify OpenSSL crypto is enabled
if $RSYNC --version | grep -q "openssl-crypto"; then
    echo "PASS: OpenSSL crypto enabled"
else
    echo "FAIL: OpenSSL crypto not enabled"
    exit 1
fi
# Test daemon authentication
TEST_DIR="/tmp/rsync-sha-test"
SECRETS_FILE="$TEST_DIR/secrets"
CONFIG_FILE="$TEST_DIR/rsyncd.conf"
rm -rf "$TEST_DIR"
mkdir -p "$TEST_DIR"
echo "testuser:testpass" > "$SECRETS_FILE"
chmod 600 "$SECRETS_FILE"
cat > "$CONFIG_FILE" << EOC
port = 8730
[test]
path = /tmp
auth users = testuser
secrets file = $SECRETS_FILE
EOC
$RSYNC --daemon --config="$CONFIG_FILE" &
DAEMON_PID=$!
sleep 3
if echo "testpass" | $RSYNC --list-only --password-file=- rsync://testuser@localhost:8730/test/ >/dev/null 2>&1; then
    echo "PASS: SHA authentication works"
else
    echo "FAIL: SHA authentication failed"
    kill $DAEMON_PID 2>/dev/null
    rm -rf "$TEST_DIR"
    exit 1
fi
kill $DAEMON_PID 2>/dev/null || true
rm -rf "$TEST_DIR" || true
exit 0
EOF

# Make the test script executable
chmod +x testsuite/sha-test.test

echo "SHA test script created successfully in testsuite/sha-test.test"
