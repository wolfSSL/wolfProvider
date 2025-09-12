#!/usr/bin/env bash
set -Eeuo pipefail

URL="https://example.com"
INCLUDE_LEGACY=0   # add CBC-only suites if requested

# --- args: [--legacy] [URL] ---
for a in "$@"; do
  case "$a" in
    --legacy) INCLUDE_LEGACY=1 ;;
    http://*|https://*) URL="$a" ;;
    *) URL="$a" ;;
  esac
done

# Require curl linked with OpenSSL
if ! curl -V | grep -q 'OpenSSL'; then
  echo "SKIP: this curl is not OpenSSL-backed"; exit 2
fi

run_case() {
  local name="$1"; shift
  local tls_line verify rc
  if tls_line="$(curl -q -fsS -o /dev/null -v "$URL" "$@" 2>&1 | awk '/SSL connection using/{sub(/.*using /,""); print; exit}')"; then
    verify="$(curl -q -fsS -o /dev/null -w '%{ssl_verify_result}' "$URL" "$@")"
    if [ "$verify" = "0" ]; then
      printf 'PASS %-30s %s\n' "[$name]" "$tls_line"
    else
      printf 'FAIL %-30s verify=%s  (%s)\n' "[$name]" "$verify" "$tls_line"
      return 1
    fi
  else
    rc=$?
    printf 'FAIL %-30s curl exit=%s (likely no overlap)\n' "[$name]" "$rc"
    return "$rc"
  fi
}

echo "Target: $URL"
echo "curl:   $(curl -V | head -n1)"
echo "(CHACHA20 suites intentionally excluded)"

# 0) Default handshake (server's choice)
run_case "default" || true

# 1) TLS 1.3 (all TLS1.3 suites use (EC)DHE KEX; choose AES-GCM only)
run_case "tls13 AES128-GCM" --tlsv1.3 --tls-max 1.3 \
  --tls13-ciphers TLS_AES_128_GCM_SHA256 || true
run_case "tls13 AES256-GCM" --tlsv1.3 --tls-max 1.3 \
  --tls13-ciphers TLS_AES_256_GCM_SHA384 || true

# 2) TLS 1.2 ECDHE (Elliptic-Curve Diffie-Hellman Ephemeral) — AES-GCM
run_case "tls12 ECDHE AES128-GCM" --tlsv1.2 --tls-max 1.2 \
  --ciphers 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256' || true
run_case "tls12 ECDHE AES256-GCM" --tlsv1.2 --tls-max 1.2 \
  --ciphers 'ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384' || true

# 3) TLS 1.2 classic DHE (finite-field Diffie-Hellman) — AES-GCM
run_case "tls12 DHE AES128-GCM" --tlsv1.2 --tls-max 1.2 \
  --ciphers 'DHE-RSA-AES128-GCM-SHA256' || true
run_case "tls12 DHE AES256-GCM" --tlsv1.2 --tls-max 1.2 \
  --ciphers 'DHE-RSA-AES256-GCM-SHA384' || true

# 4) Optional legacy CBC (often disabled server-side)
if [ "$INCLUDE_LEGACY" -eq 1 ]; then
  run_case "tls12 ECDHE AES128-CBC" --tlsv1.2 --tls-max 1.2 \
    --ciphers 'ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES128-SHA' || true
  run_case "tls12 ECDHE AES256-CBC" --tlsv1.2 --tls-max 1.2 \
    --ciphers 'ECDHE-ECDSA-AES256-SHA:ECDHE-RSA-AES256-SHA' || true
  run_case "tls12 DHE AES128-CBC" --tlsv1.2 --tls-max 1.2 \
    --ciphers 'DHE-RSA-AES128-SHA' || true
  run_case "tls12 DHE AES256-CBC" --tlsv1.2 --tls-max 1.2 \
    --ciphers 'DHE-RSA-AES256-SHA' || true
fi

