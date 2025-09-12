#!/bin/bash


# Generates a temp RSA key, signs "hello", verifies the signature.
# Success prints "OK: OpenSSL RSA SHA-256 sign+verify".
set -euo pipefail
tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
printf "hello" >"$tmp/msg"
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$tmp/priv.pem" >/dev/null
openssl pkey -in "$tmp/priv.pem" -pubout -out "$tmp/pub.pem" >/dev/null
openssl dgst -sha256 -sign "$tmp/priv.pem" -out "$tmp/sig" "$tmp/msg" >/dev/null
openssl dgst -sha256 -verify "$tmp/pub.pem" -signature "$tmp/sig" "$tmp/msg" >/dev/null
echo "OK: OpenSSL RSA SHA-256 sign+verify"
