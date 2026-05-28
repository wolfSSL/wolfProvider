#!/usr/bin/env bash
set -euo pipefail

# Pick the right OSP patch file for a (project, projectversion, wolfssl_ref) tuple.
#
# Usage:
#   resolve-osp-patch.sh <osp-dir> <project> <projectversion> <wolfssl_ref> [--fips]
#
# Example:
#   resolve-osp-patch.sh ./osp libnice 0.1.21 v5.9.1-stable
#   resolve-osp-patch.sh ./osp krb5 1.20.1-final v5.8.4-stable --fips
#
# OSP patch names follow one convention:
#   <project>/<project>-<projver>[-wolfssl-X.Y.Z]-wolfprov[-fips].patch
# A bare name (no -wolfssl-X.Y.Z-) is the latest/universal content; a
# -wolfssl-X.Y.Z- infix is a snapshot pinned to that wolfSSL line.
#
# Resolution (first match wins):
#   wolfssl_ref priority:  v5.8.X -> -wolfssl-5.8.4-, then universal
#                          v5.9.X -> -wolfssl-5.9.1-, then universal
#                          master/other -> universal
#   --fips: prefer the -wolfprov-fips.patch, else fall back to -wolfprov.patch

if [ $# -lt 4 ] || [ $# -gt 5 ]; then
    echo "Usage: $0 <osp-dir> <project> <projectversion> <wolfssl_ref> [--fips]" >&2
    exit 1
fi

OSP_DIR="$1"
PROJECT="$2"
PROJVER="$3"
WOLFSSL_REF="$4"
WANT_FIPS=""
if [ "${5:-}" = "--fips" ]; then
    WANT_FIPS=1
fi

DIR="$OSP_DIR/wolfProvider/$PROJECT"

# Empty projver (e.g. libmemcached-wolfprov-fips.patch) -> no trailing dash.
if [ -n "$PROJVER" ]; then
    stem="$PROJECT-$PROJVER"
else
    stem="$PROJECT"
fi

# wolfSSL-ref-specific snapshot infix(es), universal ("") last.
case "$WOLFSSL_REF" in
    v5.8.*)  wolfssl_infixes=("-wolfssl-5.8.4" "") ;;
    v5.9.*)  wolfssl_infixes=("-wolfssl-5.9.1" "") ;;
    *)       wolfssl_infixes=("") ;;
esac

# FIPS suffix preference. A project may ship only one of the two
# variants; use whichever exists. --fips prefers -fips then non-FIPS;
# non-FIPS prefers the plain patch then -fips.
if [ -n "$WANT_FIPS" ]; then
    fips_suffixes=("-fips" "")
else
    fips_suffixes=("" "-fips")
fi

candidates=()
for fsfx in "${fips_suffixes[@]}"; do
    for winfix in "${wolfssl_infixes[@]}"; do
        candidates+=("$DIR/$stem$winfix-wolfprov$fsfx.patch")
    done
done

for f in "${candidates[@]}"; do
    if [ -f "$f" ]; then
        echo "$f"
        exit 0
    fi
done

echo "resolve-osp-patch: no patch found for project=$PROJECT version=$PROJVER wolfssl=$WOLFSSL_REF fips=${WANT_FIPS:+yes}" >&2
echo "  tried:" >&2
for f in "${candidates[@]}"; do
    echo "    $f" >&2
done
exit 1
