#!/usr/bin/env bash
set -euo pipefail

# Converts a git tag or branch name to a commit SHA.
# Usage: ./resolve-ref.sh <ref> <repo>
# Example: ./resolve-ref.sh master openssl/openssl

if [[ $# -ne 2 ]]; then
    echo "Usage: $0 <ref> <repo>" >&2
    exit 1
fi

REF="$1"       # e.g., "master"
REPO="$2"      # e.g., "openssl/openssl"

if [[ "$REF" =~ ^[0-9a-f]{40}$ ]]; then
    echo "$REF"
else
    api_url="https://api.github.com/repos/$REPO/commits/$REF"

    curl_args=(-fsSL)
    if [[ -n "${GITHUB_TOKEN:-}" ]]; then
        curl_args+=(-H "Authorization: Bearer $GITHUB_TOKEN" -H "Accept: application/vnd.github+json")
    fi

    body=""
    for attempt in 1 2 3 4 5; do
        if body=$(curl "${curl_args[@]}" "$api_url"); then
            break
        fi
        body=""
        # GitHub rate-limits with 429/403; back off before retrying.
        [[ "$attempt" -lt 5 ]] && sleep $((attempt * 10))
    done

    if [[ -z "$body" ]]; then
        echo "resolve-ref: failed to resolve $REF in $REPO after retries" >&2
        exit 1
    fi

    # OSP container images (e.g. sssd) ship without jq; fall back to grep.
    if command -v jq >/dev/null 2>&1; then
        sha=$(printf '%s' "$body" | jq -r .sha)
    else
        sha=$(printf '%s' "$body" | grep -o '"sha"[[:space:]]*:[[:space:]]*"[0-9a-f]\{40\}"' | head -n1 | grep -o '[0-9a-f]\{40\}')
    fi
    if [[ -z "$sha" || "$sha" == "null" ]]; then
        echo "resolve-ref: no sha for $REF in $REPO" >&2
        exit 1
    fi
    echo "$sha"
fi
