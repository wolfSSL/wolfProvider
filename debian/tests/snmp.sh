#!/usr/bin/env bash
# snmp-openssl-smoke.sh (numeric OID; no MIBs needed)
set -Eeuo pipefail

USER="${USER:-smokeuser}"
AUTHPASS="${AUTHPASS:-authpass123}"     # ≥8 chars
PRIVPASS="${PRIVPASS:-privpass123}"     # ≥8 chars
OID_NUM="${OID_NUM:-.1.3.6.1.2.1.1.3.0}"  # sysUpTime.0 numeric
PORT="$(shuf -i 16100-16999 -n1)"

need() { command -v "$1" >/dev/null || { echo "ERR: '$1' not found"; exit 2; }; }
need snmpd; need snmpget

# Ensure the client will hit OpenSSL/libcrypto
if ! ldd "$(command -v snmpget)" | grep -Eq 'libcrypto\.so|libssl\.so'; then
  echo "SKIP: snmpget not linked with OpenSSL/libcrypto on this host"; exit 2
fi

tmp="$(mktemp -d)"; srv=''
cleanup(){ [ -n "$srv" ] && kill "$srv" 2>/dev/null || true; rm -rf "$tmp"; }
trap cleanup EXIT

# Minimal agent config: localhost only, v3 user with SHA auth + AES privacy
cat >"$tmp/snmpd.conf" <<EOF
agentAddress  udp:127.0.0.1:$PORT
createUser $USER SHA "$AUTHPASS" AES "$PRIVPASS"
rouser $USER priv
sysLocation "snmp-openssl-smoke"
EOF

snmpd -f -Lo -C -c "$tmp/snmpd.conf" >"$tmp/snmpd.log" 2>&1 &
srv=$!

# Quick readiness: attempt the real v3 GET a few times
tries=20
ok=0
while (( tries-- > 0 )); do
  if snmpget -v3 -l authPriv -u "$USER" -a SHA -A "$AUTHPASS" -x AES -X "$PRIVPASS" \
       -On -Oqv -r 0 -t 0.5 udp:127.0.0.1:$PORT "$OID_NUM" >/dev/null 2>&1; then
    ok=1; break
  fi
  sleep 0.1
done

# Now run once for output + verify
if (( ok )); then
  val="$(snmpget -v3 -l authPriv -u "$USER" -a SHA -A "$AUTHPASS" -x AES -X "$PRIVPASS" \
          -On -Oqv udp:127.0.0.1:$PORT "$OID_NUM" 2>"$tmp/client.err" || true)"
  if [ -n "$val" ]; then
    # Pull auth/priv hints from debug (optional)
    hint="$(snmpget -v3 -l authPriv -u "$USER" -a SHA -A "$AUTHPASS" -x AES -X "$PRIVPASS" \
            -On -Oqv -Dtemp:usm udp:127.0.0.1:$PORT "$OID_NUM" 2>&1 \
            | awk '/usm/ && /authProtocol:|privProtocol:/ {print $0}' \
            | sed -n 's/.*authProtocol: \([^ ]*\).*/auth=\1/p; s/.*privProtocol: \([^ ]*\).*/ priv=\1/p' \
            | tr -d '\n')"
    echo "PASS: SNMPv3 authPriv succeeded — $OID_NUM = $val ${hint:+($hint)}"
    exit 0
  fi
fi

echo "FAIL: SNMPv3 authPriv GET failed"
echo "--- snmpd.log (tail) ---"; tail -n 20 "$tmp/snmpd.log" || true
echo "--- client.err ---"; cat "$tmp/client.err" 2>/dev/null || true
exit 1
