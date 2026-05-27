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
# Resolution rule (first match wins):
#   1. wolfssl_ref == master:       try -wolfssl-5.9.1-, then -wolfssl-5.8.4-, then universal
#   2. wolfssl_ref ~ v5.9.X-*:      require -wolfssl-5.9.1- (or fall back to universal)
#   3. wolfssl_ref ~ v5.8.X-*:      require -wolfssl-5.8.4- (or fall back to universal)
#   4. anything else:               try universal
#
# "Universal" = filename with no -wolfssl-X.Y.Z- infix (e.g. legacy
# pre-rename layout). Lets the helper work against an OSP tree that
# hasn't been renamed yet.

if [ $# -lt 4 ] || [ $# -gt 5 ]; then
    echo "Usage: $0 <osp-dir> <project> <projectversion> <wolfssl_ref> [--fips]" >&2
    exit 1
fi

OSP_DIR="$1"
PROJECT="$2"
PROJVER="$3"
WOLFSSL_REF="$4"
FIPS_SUFFIX=""
if [ "${5:-}" = "--fips" ]; then
    FIPS_SUFFIX="-fips"
fi

# opensc uses -wolfprovider, everything else uses -wolfprov.
BASE_SUFFIX="-wolfprov"
if [ "$PROJECT" = "opensc" ]; then
    BASE_SUFFIX="-wolfprovider"
fi

DIR="$OSP_DIR/wolfProvider/$PROJECT"

# OSP uses two FIPS naming conventions; try both when --fips is set.
#   suffix: <project>-<projver>-wolfssl-X.Y.Z-wolfprov-fips.patch
#   infix:  <project>-FIPS-<projver>-wolfssl-X.Y.Z-wolfprov.patch
stems=("$PROJECT-$PROJVER")
if [ -n "$FIPS_SUFFIX" ]; then
    stems=("$PROJECT-$PROJVER" "$PROJECT-FIPS-$PROJVER")
    fips_suffixes=("$FIPS_SUFFIX" "")
else
    fips_suffixes=("")
fi

# Wolfssl-ref-specific infix(es) in priority order.
case "$WOLFSSL_REF" in
    master|main)        wolfssl_infixes=("-wolfssl-5.9.1" "-wolfssl-5.8.4" "") ;;
    v5.9.*)             wolfssl_infixes=("-wolfssl-5.9.1" "") ;;
    v5.8.*)             wolfssl_infixes=("-wolfssl-5.8.4" "") ;;
    *)                  wolfssl_infixes=("") ;;
esac

candidates=()
for i in "${!stems[@]}"; do
    stem="${stems[$i]}"
    fsfx="${fips_suffixes[$i]}"
    for winfix in "${wolfssl_infixes[@]}"; do
        candidates+=("$DIR/$stem$winfix$BASE_SUFFIX$fsfx.patch")
    done
done

for f in "${candidates[@]}"; do
    if [ -f "$f" ]; then
        echo "$f"
        exit 0
    fi
done

echo "resolve-osp-patch: no patch found for project=$PROJECT version=$PROJVER wolfssl=$WOLFSSL_REF fips=${FIPS_SUFFIX:+yes}" >&2
echo "  tried:" >&2
for f in "${candidates[@]}"; do
    echo "    $f" >&2
done
exit 1
