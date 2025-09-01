#!/usr/bin/env bash

# iperf3-auth-smoke.sh
set -Eeuo pipefail

PORT="$(shuf -i 42000-49000 -n1)"
tmp="$(mktemp -d)"; srv=
cleanup(){ [[ -n "$srv" ]] && kill "$srv" 2>/dev/null || true; rm -rf "$tmp"; }
trap cleanup EXIT

echo "tmp: $tmp  port: $PORT"

# 1) Keys and user DB
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$tmp/priv.pem" >/dev/null
openssl pkey -in "$tmp/priv.pem" -pubout > "$tmp/pub.pem" 2>/dev/null

user=alice; pass=secret
hash="$(printf "{%s}%s" "$user" "$pass" | sha256sum | awk '{print $1}')"
printf "# username,sha256\n%s,%s\n" "$user" "$hash" > "$tmp/users.csv"

# 2) Start server (debug so it logs auth) and wait for it to bind
iperf3 -s -1 -d -p "$PORT" \
  --rsa-private-key-path "$tmp/priv.pem" \
  --authorized-users-path "$tmp/users.csv" \
  >"$tmp/server.log" 2>&1 &
srv=$!

for i in {1..20}; do
  sleep 0.1
  ss -Huan | awk '{print $5}' | grep -qE "127\.0\.0\.1:$PORT" && break || true
done

# helper: run a client once and return exit code
run_client() {
  local pw="$1"
  IPERF3_PASSWORD="$pw" \
  iperf3 -c 127.0.0.1 -p "$PORT" -t 1 \
    --username "$user" --rsa-public-key-path "$tmp/pub.pem" \
    --json >"$tmp/client.json" 2>"$tmp/client.err" || return $?
}

# 3) Positive case (correct password)
if run_client "$pass"; then
  echo "PASS(positive): client completed with correct password"
else
  echo "FAIL: client failed with correct password"
  echo "--- server.log (tail) ---"; tail -n 50 "$tmp/server.log"
  echo "--- client.err ---"; cat "$tmp/client.err"
  exit 1
fi

# 4) Negative case (wrong password must fail)
if run_client "WRONG-password"; then
  echo "FAIL: client unexpectedly succeeded with wrong password"
  echo "--- server.log (tail) ---"; tail -n 50 "$tmp/server.log"
  exit 1
else
  echo "PASS(negative): client failed with wrong password (auth enforced)"
fi

# 5) Optional: show explicit auth lines from server debug
echo "--- auth lines from server.log ---"
grep -i 'auth' "$tmp/server.log" || echo "(no explicit lines; depends on build verbosity)"

echo "OK: iperf3 auth smoke test completed."
