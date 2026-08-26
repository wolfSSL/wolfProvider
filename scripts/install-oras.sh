#!/usr/bin/env bash
set -euo pipefail

# Install the pinned ORAS CLI. Single source for the version + checksum so a
# bump is one edit. Used by the FIPS Ready publish job and the
# fetch-fips-bundle action.
#
# Usage: install-oras.sh [--dest DIR] [--skip-if-present] [--best-effort]
#   --dest DIR         where to place the oras binary (default /usr/local/bin)
#   --skip-if-present  no-op if oras is already on PATH or at DEST
#   --best-effort      warn and exit 0 on download/checksum failure instead of
#                      failing the job (for callers that can proceed without it)

ORAS_VERSION="1.2.2"
ORAS_CHECKSUM="bff970346470e5ef888e9f2c0bf7f8ee47283f5a45207d6e7a037da1fb0eae0d"
DEST="/usr/local/bin"
SKIP_IF_PRESENT=0
BEST_EFFORT=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        --dest) DEST="$2"; shift 2 ;;
        --dest=*) DEST="${1#--dest=}"; shift ;;
        --skip-if-present) SKIP_IF_PRESENT=1; shift ;;
        --best-effort) BEST_EFFORT=1; shift ;;
        *) echo "install-oras: unknown option $1" >&2; exit 2 ;;
    esac
done

warn_or_fail() {
    if [[ "$BEST_EFFORT" -eq 1 ]]; then
        echo "::warning::$1"
        exit 0
    fi
    echo "::error::$1" >&2
    exit 1
}

if [[ "$SKIP_IF_PRESENT" -eq 1 ]] \
        && { command -v oras >/dev/null 2>&1 || [[ -x "$DEST/oras" ]]; }; then
    exit 0
fi

tgz="oras_${ORAS_VERSION}_linux_amd64.tar.gz"
ok=""
for attempt in 1 2 3 4 5; do
    if curl -fsSLO "https://github.com/oras-project/oras/releases/download/v${ORAS_VERSION}/${tgz}"; then
        ok=1
        break
    fi
    echo "install-oras: download attempt $attempt failed; retrying..." >&2
    sleep $((attempt * 3))
done
[[ -n "$ok" ]] || warn_or_fail "ORAS download failed after retries"

if ! echo "${ORAS_CHECKSUM}  ${tgz}" | sha256sum -c -; then
    rm -f "$tgz"
    warn_or_fail "ORAS checksum mismatch"
fi

mkdir -p "$DEST" 2>/dev/null || true
if [[ -w "$DEST" ]]; then
    tar xzf "$tgz" -C "$DEST" oras
else
    sudo tar xzf "$tgz" -C "$DEST" oras
fi
rm -f "$tgz"
"$DEST/oras" version
