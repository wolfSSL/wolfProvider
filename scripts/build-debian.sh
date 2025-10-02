#!/bin/bash
#
# Copyright (C) 2006-2024 wolfSSL Inc.
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
set -euo pipefail

PKG_NAME="libwolfprov"

WOLFSSL_ISFIPS=${WOLFSSL_ISFIPS:-0}
WOLFPROV_DEBUG=${WOLFPROV_DEBUG:-0}

printf "Running build-debian.sh with WOLFSSL_ISFIPS=$WOLFSSL_ISFIPS and WOLFPROV_DEBUG=$WOLFPROV_DEBUG\n"

# Step 1: Determine the repo root
REPO_ROOT=${GITHUB_WORKSPACE:-$(git rev-parse --show-toplevel)}
cd "$REPO_ROOT"

# Step 2: Determine latest upstream tag
latest_tag=$(git tag --list 'v[0-9]*.[0-9]*.[0-9]*' | sort -V | tail -n1)
if [[ -z "$latest_tag" ]]; then
  echo "❌ Error: No tag found in format vX.Y.Z"
  exit 1
fi
latest_tag_commit=$(git rev-list -n 1 "$latest_tag")
current_commit=$(git rev-parse HEAD)

UPSTREAM_VERSION="${latest_tag#v}"  # e.g. 1.0.2

# Step 3: Determine Debian revision automatically
if [[ -f debian/changelog ]]; then
  last_version=$(dpkg-parsechangelog --show-field Version)
  last_upstream="${last_version%%-*}"   # strip Debian revision
  last_revision="${last_version##*-}"   # get Debian revision number

  if [[ "$last_upstream" == "$UPSTREAM_VERSION" ]]; then
    # Same upstream version → increment Debian revision
    DEB_REVISION=$((last_revision + 1))
  else
    # New upstream version → reset Debian revision to 1
    DEB_REVISION=1
  fi
else
  DEB_REVISION=1
fi

# Step 4: Compose full version string
if [[ "$current_commit" == "$latest_tag_commit" ]]; then
  VERSION="${UPSTREAM_VERSION}-${DEB_REVISION}"
  echo "📌 On tag $latest_tag — using version: $VERSION"
else
  echo "⚠️  Not on latest tagged commit ($latest_tag)"
  read -rp "❓ Continue building snapshot version? Type Y to confirm: " CONFIRM
  if [[ "$CONFIRM" != "Y" ]]; then
    echo "🚫 Aborting."
    exit 1
  fi
  VERSION="${UPSTREAM_VERSION}-${DEB_REVISION}"
  echo "📌 Snapshot build — using version: $VERSION"
fi

TARBALL="${PKG_NAME}_${UPSTREAM_VERSION}.orig.tar.gz"
TARBALL_PREFIX="${PKG_NAME}-${UPSTREAM_VERSION}"

# Step 5: Warn if not on master
current_branch=$(git rev-parse --abbrev-ref HEAD)
if [[ "$current_branch" != "master" ]]; then
  echo "⚠️  Warning: On branch '$current_branch', not 'master'"
fi

# Step 6: Check for uncommitted changes
if ! git diff --quiet || ! git diff --cached --quiet; then
  echo "⚠️  Error: Uncommitted changes in working tree:"
  git status --short
  exit 1
fi

# Step 7: Clean untracked files
echo "🧹 Cleaning untracked files..."
git clean -fdx

# Step 8: Update debian/changelog
echo "📝 Updating debian/changelog..."
mkdir -p debian
export DEBFULLNAME="${DEBFULLNAME:-WolfSSL Developer}"
export DEBEMAIL="${DEBEMAIL:-support@wolfssl.com}"

if [[ -f debian/changelog ]]; then
  dch -v "$VERSION" --distribution unstable --urgency=medium "Release version $VERSION"
else
  dch --create -v "$VERSION" --package "$PKG_NAME" --distribution unstable --urgency=medium "Initial release."
fi

# Step 9: Create tarball
if [[ -f "../$TARBALL" ]]; then
  echo "🗑️ Removing existing tarball: $TARBALL"
  rm -f "../$TARBALL"
fi
echo "📦 Creating tarball $TARBALL from commit $current_commit..."
git archive --format=tar.gz --prefix="${TARBALL_PREFIX}/" \
    -o "../$TARBALL" "$current_commit"

# Step 9.1: Set up ccache if installed
# Optional ccache
if command -v ccache >/dev/null 2>&1; then
  export CC="ccache gcc"
  export CXX="ccache g++"
else
  export CC="gcc"
  export CXX="g++"
fi

# Optional tuning (safe if unset)
: "${CCACHE_DIR:=}"
: "${CCACHE_BASEDIR:=}"
: "${CCACHE_NOHASHDIR:=}"
: "${CCACHE_SLOPPINESS:=}"
CCACHE_COMPILERCHECK=${CCACHE_COMPILERCHECK:-content}

# Step 10: Build package with optional ccache (if installed)
echo "⚙️  Building package..."
WOLFSSL_ISFIPS=${WOLFSSL_ISFIPS:-0}
dpkg-buildpackage -us -uc \
  -eWOLFSSL_ISFIPS \
  -eCC -eCXX \
  -eCCACHE_DIR -eCCACHE_BASEDIR -eCCACHE_NOHASHDIR -eCCACHE_COMPILERCHECK

echo "✅ Build completed for version $VERSION"
