#!/bin/bash
#
# oqs-demos nginx connection test, wolfProvider edition. Starts the quantum-safe
# nginx and connects once per supported group (the s_client / HTTP GET
# equivalent of oqs-demos testrun.py's "curl --cacert CA.crt --curves <kem>"),
# asserting the negotiated PQC group, the ML-DSA peer signature, a verified
# chain, and that the page is served. Exits non-zero if any group fails; the CI
# step inverts that under WOLFPROV_FORCE_FAIL=1.

O=/opt/wolfProvider/openssl-install
CA=/opt/nginx/cacert/CA.crt
PORT=4433
GROUPS="X25519MLKEM768 SecP256r1MLKEM768 SecP384r1MLKEM1024 MLKEM512 MLKEM768 MLKEM1024"

export LD_LIBRARY_PATH="/opt/wolfProvider/wolfprov-install/lib:/opt/wolfProvider/wolfssl-install/lib:${O}/lib:${O}/lib64${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"

/opt/nginx/sbin/nginx -c /opt/nginx/conf/nginx.conf
sleep 2

fail=0
for g in ${GROUPS}; do
    out=$( (printf 'GET / HTTP/1.0\r\nHost: localhost\r\n\r\n'; sleep 1) \
        | "${O}/bin/openssl" s_client -connect "localhost:${PORT}" \
            -groups "${g}" -CAfile "${CA}" -servername localhost 2>&1)

    if echo "${out}" | grep -q "Negotiated TLS1.3 group: ${g}" \
        && echo "${out}" | grep -qi "Peer signature type: mldsa65" \
        && echo "${out}" | grep -q "Verify return code: 0 (ok)" \
        && echo "${out}" | grep -q "wolfProvider quantum-safe nginx"; then
        echo "PASS: ${g} (ML-DSA auth + quantum-safe key exchange)"
    else
        echo "FAIL: ${g}"
        echo "${out}" | grep -iE "group|signature|verify return|alert|error" | head -4
        fail=1
    fi
done

/opt/nginx/sbin/nginx -c /opt/nginx/conf/nginx.conf -s stop 2>/dev/null

if [ "${fail}" -eq 0 ]; then
    echo "All quantum-safe groups served successfully."
else
    echo "One or more quantum-safe groups failed."
fi
exit "${fail}"
