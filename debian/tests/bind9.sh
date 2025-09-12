#!/usr/bin/env bash
set -Eeuo pipefail

ALG="${1:-ecdsa}"   # ecdsa | rsa | both
ZONENAME="smoke.test"   # no trailing dot for args
ZFILE="zone.db"

mk_zone_dir() {
  local dir="$1"
  mkdir -p "$dir"
  cat >"$dir/$ZFILE" <<'ZONE'
$ORIGIN smoke.test.
$TTL 300
@   IN SOA ns.smoke.test. hostmaster.smoke.test. ( 1 3600 600 604800 300 )
    IN NS  ns.smoke.test.
ns  IN A   127.0.0.1
www IN A   127.0.0.1
ZONE
}

sign_one() {
  local algo="$1" dir
  dir="$(mktemp -d)"; echo "work dir: $dir"
  mk_zone_dir "$dir"
  pushd "$dir" >/dev/null

  case "$algo" in
    ecdsa)
      dnssec-keygen -a ECDSAP256SHA256 -b 256  -n ZONE -f KSK "$ZONENAME" >/dev/null
      dnssec-keygen -a ECDSAP256SHA256 -b 256  -n ZONE        "$ZONENAME" >/dev/null
      ;;
    rsa)
      dnssec-keygen -a RSASHA256       -b 2048 -n ZONE -f KSK "$ZONENAME" >/dev/null
      dnssec-keygen -a RSASHA256       -b 2048 -n ZONE        "$ZONENAME" >/dev/null
      ;;
  esac

  # Import/publish keys and sign (no need to $INCLUDE)
  dnssec-signzone -v 5 -S -K "$PWD" -o "$ZONENAME" "$ZFILE" >"sign-$algo.log" 2>&1 || {
    echo "FAIL: [$algo] signing failed"; sed -n '1,200p' "sign-$algo.log"; exit 1; }

  dnssec-verify -o "$ZONENAME" "$ZFILE.signed" >"verify-$algo.log" 2>&1 && \
    echo "PASS: [$algo] sign+verify OK" || { echo "FAIL verify"; sed -n '1,200p' "verify-$algo.log"; exit 1; }

  popd >/dev/null
  echo "kept: $dir"
}

case "${ALG,,}" in
  ecdsa) sign_one ecdsa ;;
  rsa)   sign_one rsa   ;;
  both)  sign_one ecdsa; sign_one rsa ;;
  *)     echo "usage: $0 [ecdsa|rsa|both]"; exit 2 ;;
esac
