#!/bin/bash
# perf-cmd-test.sh
# Measure per-invocation init/run cost of representative openssl commands under
# wolfProvider and gate against a committed baseline.
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

# Own variable: cmd-test-common.sh reassigns CMD_TEST_DIR to its own location.
PERF_TEST_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
source "${PERF_TEST_DIR}/../cmd_test/cmd-test-common.sh"
source "${PERF_TEST_DIR}/clean-perf-test.sh"

if [ -z "${DO_CMD_TESTS:-}" ]; then
    echo "This script is designed to be called from do-perf-tests.sh"
    echo "Do not run this script directly - use do-perf-tests.sh instead"
    exit 1
fi

for tool in jq awk; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "ERROR: required tool '$tool' not found"
        exit 1
    fi
done

# Timing needs GNU date's nanoseconds; BSD/macOS date yields a literal 'N'.
if [ "$(date +%N)" = "N" ]; then
    echo "ERROR: GNU 'date' with %N support is required (BSD/macOS date lacks it)"
    exit 1
fi

UPDATE_BASELINE=0
if [ "${1:-}" = "--update-baseline" ] || [ "${PERF_UPDATE_BASELINE:-0}" = "1" ]; then
    UPDATE_BASELINE=1
fi

PERF_ITER="${PERF_ITER:-15}"
PERF_WARMUP="${PERF_WARMUP:-3}"
# Total measurement attempts for a failing command; it is only reported as a
# regression if it fails the gate on every attempt (guards against flukes).
PERF_CONFIRM="${PERF_CONFIRM:-3}"
# Headroom added above the just-measured value when writing a fresh baseline.
PERF_MARGIN="${PERF_MARGIN:-0.30}"

if [ "${WOLFSSL_ISFIPS:-0}" = "1" ]; then
    BASELINE="${PERF_TEST_DIR}/perf-baseline.fips.json"
    VARIANT="fips"
else
    BASELINE="${PERF_TEST_DIR}/perf-baseline.nonfips.json"
    VARIANT="nonfips"
fi

clean_perf_test
# cmd_test_init would put the log under scripts/cmd_test; keep it with this suite.
LOG_FILE="${PERF_TEST_DIR}/perf-test.log"
touch "$LOG_FILE"
exec > >(tee -a "$LOG_FILE") 2>&1

OUTDIR="perf_outputs"
mkdir -p "$OUTDIR"
IN="$OUTDIR/input.bin"
# pkeyutl -sign does raw (unhashed) RSA signing, capped well under the modulus
# size, so it needs a digest-sized input, not the bulk IN blob.
SIGIN="$OUTDIR/sign_input.bin"

# Commands measured, in display order, and the gate each is checked against:
# 'abs' commands are near no-ops (gated on absolute ms, no meaningful ratio);
# 'ratio' commands are gated on wolfProvider time relative to the default provider.
CMDS=(init-probe version dgst-sha256 enc-aes genpkey-rsa genpkey-ec pkeyutl-rsa dh-derive)
declare -A GATE=(
    [init-probe]=abs
    [version]=abs
    [dgst-sha256]=ratio
    [enc-aes]=ratio
    [genpkey-rsa]=ratio
    [genpkey-ec]=ratio
    [pkeyutl-rsa]=ratio
    [dh-derive]=ratio
)

exec_cmd() {
    case "$1" in
        init-probe)  "$OPENSSL_BIN" list -providers ;;
        version)     "$OPENSSL_BIN" version ;;
        dgst-sha256) "$OPENSSL_BIN" dgst -sha256 "$IN" ;;
        enc-aes)     "$OPENSSL_BIN" enc -aes-256-cbc -pbkdf2 -k testpass -in "$IN" -out "$OUTDIR/enc.bin" ;;
        genpkey-rsa) "$OPENSSL_BIN" genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$OUTDIR/rsa_tmp.pem" ;;
        genpkey-ec)  "$OPENSSL_BIN" genpkey -algorithm EC -pkeyopt ec_paramgen_curve:prime256v1 -out "$OUTDIR/ec_tmp.pem" ;;
        pkeyutl-rsa) "$OPENSSL_BIN" pkeyutl -sign -inkey "$OUTDIR/rsa.pem" -in "$SIGIN" -out "$OUTDIR/rsa_sig.bin" ;;
        dh-derive)   "$OPENSSL_BIN" pkeyutl -derive -inkey "$OUTDIR/dh1.pem" -peerkey "$OUTDIR/dh2_pub.pem" -out "$OUTDIR/dh_secret.bin" ;;
        *)           return 1 ;;
    esac
}

gen_or_die() {
    if ! "$@" >/dev/null 2>&1; then
        echo "ERROR: setup step failed: $*"
        exit 1
    fi
}

# Generate all inputs/keys under the default provider so the measured
# wolfProvider runs never include setup cost. A setup failure is fatal - a
# missing key would otherwise make the dependent command fail on every run.
generate_inputs() {
    use_default_provider
    gen_or_die dd if=/dev/urandom of="$IN" bs=4096 count=1
    gen_or_die dd if=/dev/urandom of="$SIGIN" bs=32 count=1
    gen_or_die "$OPENSSL_BIN" genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$OUTDIR/rsa.pem"
    gen_or_die "$OPENSSL_BIN" genpkey -algorithm DH -pkeyopt group:ffdhe2048 -out "$OUTDIR/dh1.pem"
    gen_or_die "$OPENSSL_BIN" genpkey -algorithm DH -pkeyopt group:ffdhe2048 -out "$OUTDIR/dh2.pem"
    gen_or_die "$OPENSSL_BIN" pkey -in "$OUTDIR/dh2.pem" -pubout -out "$OUTDIR/dh2_pub.pem"
}

write_baseline() {
    local obj name r w gate cmds="{}" all
    all=$(printf '%s\n' "${RESULTS[@]}" | jq -s '.')
    for name in "${CMDS[@]}"; do
        r=$(jq -r --arg c "$name" '.[] | select(.name==$c) | .ratio' <<< "$all")
        w=$(jq -r --arg c "$name" '.[] | select(.name==$c) | .wolf_ms' <<< "$all")
        gate="${GATE[$name]}"
        if [ "$gate" = "abs" ]; then
            obj=$(jq -nc --argjson w "$w" --argjson m "$PERF_MARGIN" '{abs_ms_max: (($w*(1+$m))*100|round/100)}')
        else
            obj=$(jq -nc --argjson r "$r" --argjson m "$PERF_MARGIN" '{ratio_max: (($r*(1+$m))*100|round/100)}')
        fi
        cmds=$(jq -nc --argjson c "$cmds" --arg n "$name" --argjson o "$obj" '$c + {($n): $o}')
    done
    jq -n --argjson tol "$TOL" --argjson cmds "$cmds" \
        '{tolerance: $tol, commands: $cmds}' > "$BASELINE"
}

# Minimum wall time in ms over PERF_ITER runs after PERF_WARMUP discarded runs.
measure() {
    local name=$1
    local i start end dur best=""
    for ((i=0; i<PERF_WARMUP; i++)); do
        exec_cmd "$name" >/dev/null 2>&1
    done
    for ((i=0; i<PERF_ITER; i++)); do
        start=$(date +%s.%N)
        exec_cmd "$name" >/dev/null 2>&1
        end=$(date +%s.%N)
        dur=$(awk -v s="$start" -v e="$end" 'BEGIN{printf "%.3f", (e-s)*1000}')
        best=$(awk -v d="$dur" -v b="$best" 'BEGIN{ if (b=="" || d+0<b+0) printf "%.3f", d; else printf "%.3f", b }')
    done
    echo "$best"
}

# One full measurement of a command: times it under the default provider and
# under wolfProvider, sets default_ms / wolf_ms / ratio. Sets cmd_error=1 if the
# command does not exit 0 - timing a failing command would otherwise look fast
# and pass the gate, hiding a broken capability.
measure_pair() {
    local name=$1
    cmd_error=0
    default_ms="0"
    if [ "$CAN_COMPARE" = "1" ]; then
        use_default_provider >/dev/null 2>&1
        if ! exec_cmd "$name" >/dev/null 2>&1; then
            echo "  [$name] ERROR: command failed under the default provider"
            cmd_error=1
        fi
        default_ms=$(measure "$name")
    fi
    use_wolf_provider >/dev/null 2>&1
    if ! exec_cmd "$name" >/dev/null 2>&1; then
        echo "  [$name] ERROR: command failed under wolfProvider"
        cmd_error=1
    fi
    wolf_ms=$(measure "$name")
    ratio=$(awk -v w="$wolf_ms" -v d="$default_ms" 'BEGIN{ if (d+0>0) printf "%.3f", w/d; else printf "0" }')
}

# Apply the baseline gate to the current wolf_ms / ratio, setting verdict / limit.
gate_check() {
    local name=$1 ratio_max abs_ms_max
    if [ "${cmd_error:-0}" = "1" ]; then
        verdict="ERROR"
        limit="-"
        return
    fi
    ratio_max=$(jq -r --arg c "$name" '.commands[$c].ratio_max // empty' "$BASELINE" 2>/dev/null)
    abs_ms_max=$(jq -r --arg c "$name" '.commands[$c].abs_ms_max // empty' "$BASELINE" 2>/dev/null)
    verdict="INFO"
    limit="-"
    if [ "${GATE[$name]}" = "abs" ] && [ -n "$abs_ms_max" ]; then
        limit="${abs_ms_max}ms"
        if awk -v v="$wolf_ms" -v m="$abs_ms_max" -v t="$TOL" 'BEGIN{exit !(v+0 > m*(1+t))}'; then
            verdict="FAIL"
        else
            verdict="PASS"
        fi
    elif [ "${GATE[$name]}" = "ratio" ] && [ -n "$ratio_max" ] && [ "$CAN_COMPARE" = "1" ]; then
        limit="${ratio_max}x"
        if awk -v v="$ratio" -v m="$ratio_max" -v t="$TOL" 'BEGIN{exit !(v+0 > m*(1+t))}'; then
            verdict="FAIL"
        else
            verdict="PASS"
        fi
    fi
}

echo "=========================================="
echo "wolfProvider per-command init-overhead check"
echo "=========================================="
echo "Regression tripwire for provider load/init overhead - NOT a crypto"
echo "throughput benchmark. The OpenSSL default provider is used only as a"
echo "per-run baseline to cancel runner-speed noise; an overhead above 1.0 is"
echo "expected because a loadable provider pays startup cost the built-in"
echo "default does not. This check only flags growth beyond the committed budget."
echo ""
echo "Variant:   $VARIANT"
echo "Baseline:  $BASELINE"
echo "Iterations: $PERF_ITER (warmup $PERF_WARMUP), confirm fails x$PERF_CONFIRM"
echo ""

if [ "$UPDATE_BASELINE" = "0" ] && [ ! -f "$BASELINE" ]; then
    echo "ERROR: baseline $BASELINE not found (run with --update-baseline to create it)"
    exit 1
fi

TOL=0.25
if [ -f "$BASELINE" ]; then
    TOL=$(jq -r '.tolerance // 0.25' "$BASELINE")
fi

generate_inputs

CAN_COMPARE=1
if ! can_compare_providers; then
    CAN_COMPARE=0
    echo "INFO: replace-default mode - ratio gates skipped, measuring wolfProvider only"
fi

# Regenerating ratio baselines needs the default provider to compare against;
# in replace-default mode every ratio would be 0 and poison the baseline.
if [ "$UPDATE_BASELINE" = "1" ] && [ "$CAN_COMPARE" = "0" ]; then
    echo "ERROR: --update-baseline requires normal mode (cannot compare against the default provider in replace-default mode)"
    exit 1
fi

FAIL=0
UPDATE_FAILED=0
RESULTS=()
printf "%-14s %12s %12s %9s %9s %s\n" "command" "base_ms" "wolfprov_ms" "overhead" "budget" "verdict"
printf -- "------------------------------------------------------------------------\n"

for name in "${CMDS[@]}"; do
    measure_pair "$name"

    verdict="INFO"
    limit="-"
    attempts=1
    if [ "$UPDATE_BASELINE" = "1" ]; then
        if [ "${cmd_error:-0}" = "1" ]; then
            echo "  [$name] command failed - refusing to baseline a failing command"
            UPDATE_FAILED=1
        fi
    else
        gate_check "$name"
        # Only a failing command is re-measured. It must fail every attempt to
        # be reported - a single passing round means the first FAIL was a fluke.
        while [ "$verdict" = "FAIL" ] && [ "$attempts" -lt "$PERF_CONFIRM" ]; do
            attempts=$((attempts + 1))
            echo "  [$name] gate failed, confirming (attempt $attempts/$PERF_CONFIRM)..."
            measure_pair "$name"
            gate_check "$name"
        done
        if [ "$verdict" = "FAIL" ]; then
            FAIL=1
            echo "  [$name] regression confirmed over $attempts attempts"
        elif [ "$verdict" = "ERROR" ]; then
            FAIL=1
            echo "  [$name] command did not run successfully - cannot measure"
        fi
    fi

    printf "%-14s %12s %12s %9s %9s %s\n" "$name" "$default_ms" "$wolf_ms" "$ratio" "$limit" "$verdict"

    RESULTS+=("$(jq -nc \
        --arg n "$name" --arg g "${GATE[$name]}" \
        --argjson d "$default_ms" --argjson w "$wolf_ms" --argjson r "$ratio" \
        --argjson a "$attempts" --arg v "$verdict" \
        '{name:$n, gate:$g, default_ms:$d, wolf_ms:$w, ratio:$r, attempts:$a, verdict:$v}')")
done

printf -- "------------------------------------------------------------------------\n"

RESULTS_JSON="$OUTDIR/results.json"
printf '%s\n' "${RESULTS[@]}" | jq -s \
    --arg variant "$VARIANT" \
    --arg when "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    --arg wolfssl "${WOLFSSL_TAG:-unknown}" \
    --arg openssl "${OPENSSL_TAG:-unknown}" \
    '{variant:$variant, generated:$when, wolfssl_ref:$wolfssl, openssl_ref:$openssl, results:.}' \
    > "$RESULTS_JSON"
echo "Results written to $RESULTS_JSON"

if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
    {
        echo "### wolfProvider per-command init-overhead check ($VARIANT)"
        echo ""
        echo "Regression tripwire for provider load/init overhead - **not** a crypto"
        echo "throughput benchmark. The OpenSSL default provider is a per-run baseline"
        echo "to cancel runner-speed noise; \`overhead\` above 1.0 is expected (a loadable"
        echo "provider pays startup cost the built-in default does not). Only growth"
        echo "beyond \`budget\` fails the check."
        echo ""
        echo "| command | base_ms | wolfprov_ms | overhead | budget | verdict |"
        echo "|---|---|---|---|---|---|"
        jq -r '.results[] | "| \(.name) | \(.default_ms) | \(.wolf_ms) | \(.ratio) | \(.gate) | \(.verdict) |"' "$RESULTS_JSON"
    } >> "$GITHUB_STEP_SUMMARY"
fi

if [ "$UPDATE_BASELINE" = "1" ]; then
    if [ "$UPDATE_FAILED" -ne 0 ]; then
        echo "ERROR: refusing to write baseline - one or more commands failed to run"
        exit 1
    fi
    write_baseline
    echo "Baseline written to $BASELINE"
    exit 0
fi

if [ "$FAIL" -ne 0 ]; then
    echo "=== Init-overhead regression detected (exceeded budget) ==="
    exit 1
fi
echo "=== All commands within overhead budget ==="
exit 0
