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

    if [[ -n "${GITHUB_TOKEN:-}" ]]; then
        sha=$(curl -fsSL -H "Authorization: Bearer $GITHUB_TOKEN" -H "Accept: application/vnd.github+json" "$api_url" | jq -r .sha)
    else
        sha=$(curl -fsSL "$api_url" | jq -r .sha)
    fi
    echo "$sha"
fi
