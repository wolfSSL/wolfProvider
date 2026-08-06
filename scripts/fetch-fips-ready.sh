#!/usr/bin/env bash
set -euo pipefail

# Resolves and downloads wolfSSL FIPS Ready bundles from wolfssl.com.
# Usage: ./fetch-fips-ready.sh --list [--floor X.Y.Z]
#        ./fetch-fips-ready.sh --latest [--floor X.Y.Z]
#        ./fetch-fips-ready.sh <version> [--dest DIR]
# Example: ./fetch-fips-ready.sh 5.9.2 --dest /tmp

# 5.8.2 is the oldest bundle wolfProvider is tested against.
FLOOR="5.8.2"
DEST="$PWD"
MODE=""
VERSION=""

DOWNLOAD_PAGE="https://www.wolfssl.com/download/"
WOLFSSL_GIT="https://github.com/wolfSSL/wolfssl.git"

usage() {
    echo "Usage: $0 --list|--latest [--floor X.Y.Z]" >&2
    echo "       $0 <version> [--dest DIR]" >&2
    exit 1
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --list|--latest)
            MODE="${1#--}"
            shift
            ;;
        --floor)
            [[ $# -ge 2 ]] || usage
            FLOOR="$2"
            shift 2
            ;;
        --floor=*)
            FLOOR="${1#--floor=}"
            shift
            ;;
        --dest)
            [[ $# -ge 2 ]] || usage
            DEST="$2"
            shift 2
            ;;
        --dest=*)
            DEST="${1#--dest=}"
            shift
            ;;
        -h|--help)
            usage
            ;;
        -*)
            echo "fetch-fips-ready: unknown option $1" >&2
            usage
            ;;
        *)
            [[ -z "$VERSION" ]] || usage
            VERSION="$1"
            MODE="${MODE:-fetch}"
            shift
            ;;
    esac
done

[[ -n "$MODE" ]] || usage
[[ "$MODE" != "fetch" || -n "$VERSION" ]] || usage

bundle_url() {
    echo "https://www.wolfssl.com/wolfssl-$1-gplv3-fips-ready.zip"
}

retry_out() {
    local out attempt
    for attempt in 1 2 3; do
        if out=$("$@" 2>/dev/null) && [[ -n "$out" ]]; then
            printf '%s' "$out"
            return 0
        fi
        echo "fetch-fips-ready: retry $attempt/3: '$*' failed; retrying..." >&2
        sleep $((attempt * 5))
    done
    return 1
}

# ver_ge A B -- true when A >= B
ver_ge() {
    [[ "$(printf '%s\n%s\n' "$2" "$1" | sort -V | head -n1)" == "$2" ]]
}

get_page() {
    curl -fsSL "$DOWNLOAD_PAGE"
}

# The download page advertises only the newest bundle.
page_latest() {
    get_page \
        | grep -o 'wolfssl-[0-9][0-9.]*-gplv3-fips-ready\.zip' \
        | sed -E 's/^wolfssl-(.*)-gplv3-fips-ready\.zip$/\1/' \
        | sort -V | tail -n 1
}

page_sha256() {
    get_page | tr -d '\n' \
        | grep -o "wolfssl-$1-gplv3-fips-ready\.zip[^(]*(SHA256: *[0-9a-f]\{64\}" \
        | head -n 1 | grep -o '[0-9a-f]\{64\}'
}

ls_wolfssl_stable() {
    git ls-remote --tags --refs "$WOLFSSL_GIT" 'v*-stable' \
        | awk -F/ '{print $NF}' \
        | sed -E 's/^v(.*)-stable$/\1/' \
        | grep -E '^[0-9]+\.[0-9]+\.[0-9]+$'
}

# Retries transient failures (timeout, 5xx, connection error) but treats a
# confirmed 4xx as a definitive "not hosted" with no retry -- conflating the
# two would silently drop a version on a network blip.
bundle_exists() {
    local ver="$1" code attempt
    for attempt in 1 2 3; do
        # A genuine connection failure (not just a non-200 status) makes
        # curl itself exit nonzero; `|| code=""` keeps that from tripping
        # `set -e` before the retry loop below gets to run.
        code=$(curl -sS -I -o /dev/null -w '%{http_code}' --max-time 30 \
            "$(bundle_url "$ver")" 2>/dev/null) || code=""
        case "$code" in
            200) return 0 ;;
            4??) return 1 ;;
            *)
                if [[ "$attempt" -lt 3 ]]; then
                    sleep $((attempt * 3))
                fi
                ;;
        esac
    done
    echo "fetch-fips-ready: could not confirm bundle $ver after retries" \
        "(last status: ${code:-none})" >&2
    return 1
}

# Candidates are the union of upstream -stable tags and the advertised latest,
# because neither set alone matches what is hosted: 5.8.6 has a tag but no
# bundle, and 5.9.1 has a bundle the page never lists.
list_versions() {
    local candidates ver found probe_dir
    candidates=$(retry_out ls_wolfssl_stable) || {
        echo "fetch-fips-ready: could not list wolfSSL tags" >&2
        return 1
    }
    candidates="$candidates
$(page_latest 2>/dev/null || true)"
    candidates=$(printf '%s\n' "$candidates" | grep -E '^[0-9.]+$' | sort -V -u \
        | while read -r ver; do ver_ge "$ver" "$FLOOR" && echo "$ver"; done)
    [[ -n "$candidates" ]] || return 1

    # This runs inside the shared _discover-versions.yml job, which every
    # caller pays for even when it never touches FIPS outputs -- probe
    # candidates in parallel so N versions costs one round trip, not N.
    probe_dir=$(mktemp -d)
    trap 'rm -rf "$probe_dir"' RETURN
    for ver in $candidates; do
        (bundle_exists "$ver" && touch "$probe_dir/$ver") &
    done
    wait

    found=""
    for ver in $(printf '%s\n' "$candidates" | sort -V); do
        [[ -e "$probe_dir/$ver" ]] && found="$found$ver"$'\n'
    done

    [[ -n "$found" ]] || return 1
    printf '%s' "$found"
}

sha256_of() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | awk '{print $1}'
    else
        shasum -a 256 "$1" | awk '{print $1}'
    fi
}

fetch_bundle() {
    local ver="$1" zip dir want got attempt scratch scratch_dir

    mkdir -p "$DEST"
    # Download and verify into a scratch dir first; the caller's existing
    # $dir is only touched after a verified download, so a failed fetch
    # never destroys a bundle that was already there.
    scratch=$(mktemp -d "$DEST/.fetch-fips-ready.XXXXXX")
    trap 'rm -rf "$scratch"' RETURN
    zip="$scratch/wolfssl-$ver-gplv3-fips-ready.zip"
    dir="$DEST/wolfssl-$ver-gplv3-fips-ready"

    for attempt in 1 2 3; do
        if curl -fsSL --max-time 900 -o "$zip" "$(bundle_url "$ver")"; then
            break
        fi
        if [[ "$attempt" -eq 3 ]]; then
            echo "fetch-fips-ready: could not download bundle $ver" >&2
            return 1
        fi
        echo "fetch-fips-ready: download attempt $attempt failed; retrying..." >&2
        sleep $((attempt * 5))
    done

    want=$(page_sha256 "$ver" 2>/dev/null || true)
    if [[ -n "$want" ]]; then
        got=$(sha256_of "$zip")
        if [[ "$got" != "$want" ]]; then
            echo "fetch-fips-ready: SHA256 mismatch for $ver (want $want, got $got)" >&2
            return 1
        fi
    else
        # Only the newest bundle has a published hash; the rest get an integrity
        # check from the archive itself.
        echo "fetch-fips-ready: no published SHA256 for $ver, verifying archive" >&2
        if ! unzip -tqq "$zip" >/dev/null; then
            echo "fetch-fips-ready: downloaded archive for $ver failed integrity check" >&2
            return 1
        fi
    fi

    unzip -q "$zip" -d "$scratch"
    rm -f "$zip"

    if [[ ! -d "$scratch/wolfssl-$ver-gplv3-fips-ready" ]]; then
        scratch_dir=$(find "$scratch" -maxdepth 1 -mindepth 1 -type d -name '*fips-ready*' | head -n 1)
    else
        scratch_dir="$scratch/wolfssl-$ver-gplv3-fips-ready"
    fi
    if [[ -z "$scratch_dir" || ! -d "$scratch_dir" ]]; then
        echo "fetch-fips-ready: no bundle directory after extracting $ver" >&2
        return 1
    fi

    # Verified: safe to replace whatever was at $dir.
    rm -rf "$dir"
    mv "$scratch_dir" "$dir"

    cd "$(dirname "$dir")" && echo "$PWD/$(basename "$dir")"
}

case "$MODE" in
    list)
        list_versions
        ;;
    latest)
        list_versions | tail -n 1
        ;;
    fetch)
        fetch_bundle "$VERSION"
        ;;
esac
