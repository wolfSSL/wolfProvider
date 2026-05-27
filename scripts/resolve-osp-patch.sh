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
# Naming convention:
#   Universal filename (no -wolfssl-X.Y.Z- infix) = LATEST patch content,
#   tracks current wolfssl master / latest stable.
#   -wolfssl-X.Y.Z- infix = SNAPSHOT pinned to that wolfssl line, used
#   when the universal patch has diverged and no longer applies cleanly.
#
# Resolution rule (first match wins):
#   v5.8.X-stable: try -wolfssl-5.8.4-, then universal
#   v5.9.X-stable: try -wolfssl-5.9.1-, then universal
#   master / anything else: just universal

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
# Empty projver (e.g. libmemcached-FIPS-wolfprov.patch) -> drop trailing dash.
if [ -n "$PROJVER" ]; then
    base_stem="$PROJECT-$PROJVER"
    fips_infix_stem="$PROJECT-FIPS-$PROJVER"
else
    base_stem="$PROJECT"
    fips_infix_stem="$PROJECT-FIPS"
fi
stems=("$base_stem")
fips_suffixes=("")
if [ -n "$FIPS_SUFFIX" ]; then
    stems=("$base_stem" "$fips_infix_stem")
    fips_suffixes=("$FIPS_SUFFIX" "")
fi

# Wolfssl-ref-specific infix(es) in priority order. Universal ("") last.
case "$WOLFSSL_REF" in
    v5.8.*)             wolfssl_infixes=("-wolfssl-5.8.4" "") ;;
    v5.9.*)             wolfssl_infixes=("-wolfssl-5.9.1" "") ;;
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
