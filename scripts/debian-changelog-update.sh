#!/bin/bash
#
# Update or create debian/changelog using dch.
# Usage:
#   scripts/debian-changelog-update.sh [--version VERSION] [--message MSG] [--distribution DIST] [--help]
#
# Behavior:
# - If --version is provided, set that exact Debian version (e.g., 1.2.3-1).
# - If not provided, auto-bump the Debian revision for the upstream version
#   found in the existing changelog; if no changelog exists, requires --version.
# - If --distribution is not provided, defaults to "unstable".

set -euo pipefail

REPO_ROOT=${GITHUB_WORKSPACE:-$(git rev-parse --show-toplevel)}
cd "$REPO_ROOT"

PKG_NAME="libwolfprov"
DEBFULLNAME="${DEBFULLNAME:-WolfSSL Developer}"
DEBEMAIL="${DEBEMAIL:-support@wolfssl.com}"
export DEBFULLNAME DEBEMAIL

explicit_version=""
message="Release"
distribution="unstable"

print_help() {
  cat <<EOF
Update or create debian/changelog using dch.

Usage:
  scripts/debian-changelog-update.sh [--version VERSION] [--message MSG] [--distribution DIST]

Options:
  --version VERSION       Set exact Debian version (e.g., 1.2.3-1). If omitted, auto-bump Debian revision.
  --message MSG           Changelog message prefix. Default: "Release".
  --distribution DIST     Target distribution for dch. Default: "unstable".
  --help                  Show this help and exit.

Examples:
  # Create or update changelog with explicit version for bookworm
  scripts/debian-changelog-update.sh --version 1.2.3-1 --distribution bookworm --message "Release"

  # Auto-bump Debian revision in existing changelog for unstable
  scripts/debian-changelog-update.sh --message "Nightly build" --distribution unstable
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --version)
      explicit_version="$2"; shift 2 ;;
    --message)
      message="$2"; shift 2 ;;
    --distribution)
      distribution="$2"; shift 2 ;;
    --help)
      print_help; exit 0 ;;
    *)
      echo "Unknown argument: $1" >&2; exit 2 ;;
  esac
done

mkdir -p debian

if [[ -n "$explicit_version" ]]; then
  # Validate explicit version for non-native packages: must include Debian revision (e.g., -1)
  format=""
  if [[ -f debian/source/format ]]; then
    format="$(head -n1 debian/source/format || true)"
  fi
  if [[ "$format" != "3.0 (native)" ]]; then
    # If there is no dash, assume missing Debian revision and provide a suggestion
    if [[ "$explicit_version" == "${explicit_version%%-*}" ]]; then
      echo "❌ Non-native package version must include a Debian revision (e.g., -1)." >&2
      echo "   Provided: $explicit_version" >&2
      echo "   Suggested: ${explicit_version}-1" >&2
      exit 2
    fi
  fi

  if [[ -f debian/changelog ]]; then
    dch -v "$explicit_version" --distribution "$distribution" --urgency=medium "$message version $explicit_version"
  else
    dch --create -v "$explicit_version" --package "$PKG_NAME" \
        --distribution "$distribution" --urgency=medium "$message version $explicit_version"
  fi
  echo "Updated changelog to version $explicit_version"
  exit 0
fi

# No explicit version provided. Attempt to auto-bump Debian revision.
if [[ ! -f debian/changelog ]]; then
  echo "❌ debian/changelog does not exist. Provide --version to create it." >&2
  exit 1
fi

current_version=$(dpkg-parsechangelog --show-field Version)
upstream_version="${current_version%%-*}"
current_rev="${current_version##*-}"

if [[ "$current_version" == "$upstream_version" ]]; then
  # No Debian revision part present; start at -1
  new_version="${upstream_version}-1"
else
  if [[ "$current_rev" =~ ^[0-9]+$ ]]; then
    new_rev=$((current_rev + 1))
  else
    echo "❌ Could not parse Debian revision from version: $current_version" >&2
    exit 1
  fi
  new_version="${upstream_version}-${new_rev}"
fi

dch -v "$new_version" --distribution "$distribution" --urgency=medium "$message version $new_version"
echo "Bumped changelog version to $new_version"


