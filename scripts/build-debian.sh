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

# Step 2: Determine version from debian/changelog (no tag checks)
if [[ ! -f debian/changelog ]]; then
  echo "❌ Error: debian/changelog not found."
  echo "👉 Run scripts/debian-changelog-update.sh to create/update the changelog first."
  exit 1
fi

VERSION=$(dpkg-parsechangelog --show-field Version)
UPSTREAM_VERSION="${VERSION%%-*}"
current_commit=$(git rev-parse HEAD)
echo "📌 Using version from changelog: $VERSION (upstream: $UPSTREAM_VERSION)"

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

# Step 8: Changelog updates handled by scripts/debian-changelog-update.sh

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
