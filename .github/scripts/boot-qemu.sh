#!/bin/bash
#
# boot-qemu-wic.sh
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
#
# Boot a Yocto WIC image in QEMU and run commands
# Usage: boot-qemu-wic.sh <wic-file> "command1" "command2" "command3" ...
set -e

WIC_FILE="$1"
shift

if [ -z "$WIC_FILE" ] || [ ! -f "$WIC_FILE" ]; then
    echo "ERROR: WIC file not found: $WIC_FILE"
    echo "Usage: $0 <wic-file> <command1> [command2] ..."
    exit 1
fi

if [ $# -eq 0 ]; then
    echo "ERROR: No commands provided"
    echo "Usage: $0 <wic-file> <command1> [command2] ..."
    exit 1
fi

echo "=== Booting WIC image: $WIC_FILE ==="
echo "=== Commands to run: $# ==="

# Create expect script dynamically
EXPECT_SCRIPT=$(mktemp /tmp/qemu-boot.XXXXXX.exp)

cat > "$EXPECT_SCRIPT" <<'EXPECT_HEADER'
#!/usr/bin/expect
if {[info exists env(EXPECT_TIMEOUT)]} {
    set timeout $env(EXPECT_TIMEOUT)
} else {
    set timeout 10800
}
log_user 1

# Get WIC path from environment
set wic_path $env(WIC_FILE)

puts "=== Starting QEMU with WIC: $wic_path ==="

# Boot QEMU with SandyBridge CPU (supports AVX for compatibility)
spawn qemu-system-x86_64 \
  -cpu SandyBridge \
  -drive file=$wic_path,if=virtio,format=raw \
  -m 2048 \
  -smp 2 \
  -nographic \
  -serial mon:stdio

# Wait for login prompt
puts "=== Waiting for login prompt ==="
expect {
  "login:" {
    puts "=== Login prompt detected ==="
    sleep 2
    send "root\r"
  }
  timeout {
    puts "ERROR: Timeout waiting for login"
    exit 1
  }
}

# Wait for shell prompt
puts "=== Waiting for shell prompt ==="
expect {
  -re "#|root@" {
    puts "\n=== LOGGED IN SUCCESSFULLY ==="
  }
  "login:" {
    puts "=== Got login again, retrying ==="
    sleep 1
    send "root\r"
    exp_continue
  }
  timeout {
    puts "ERROR: Timeout waiting for shell"
    exit 1
  }
}

sleep 2

EXPECT_HEADER

# Add each command to the expect script
CMD_NUM=1
for cmd in "$@"; do
    cat >> "$EXPECT_SCRIPT" <<EXPECT_CMD

# Command $CMD_NUM: $cmd
puts "=== Running command $CMD_NUM: $cmd ==="
send "$cmd\r"
expect -re "#|root@"
sleep 1

EXPECT_CMD
    CMD_NUM=$((CMD_NUM + 1))
done

# Add shutdown logic
cat >> "$EXPECT_SCRIPT" <<'EXPECT_FOOTER'

# Shutdown
puts "=== All commands completed, shutting down ==="
send "poweroff\r"

expect {
  eof {
    puts "\n=== QEMU SHUTDOWN COMPLETE ==="
  }
  timeout {
    puts "\n=== Timeout on shutdown ==="
  }
}
EXPECT_FOOTER

# Make executable and run
chmod +x "$EXPECT_SCRIPT"

echo "=== Generated expect script ==="

# Export WIC_FILE for expect script
export WIC_FILE

# Run the expect script
if "$EXPECT_SCRIPT"; then
    EXIT_CODE=0
    echo "=== Boot and test completed successfully ==="
else
    EXIT_CODE=$?
    echo "=== Boot and test failed with exit code $EXIT_CODE ==="
fi

# Cleanup
rm -f "$EXPECT_SCRIPT"

exit $EXIT_CODE

