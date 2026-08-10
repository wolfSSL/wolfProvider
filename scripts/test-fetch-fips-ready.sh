#!/bin/bash
#
# Copyright (C) 2006-2026 wolfSSL Inc.
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
#
# Isolated, network-free tests for scripts/fetch-fips-ready.sh: mocks curl
# and git so the resolver and extraction logic, especially its destructive
# and failure paths, run deterministically in CI without hitting
# wolfssl.com or GitHub.
set -euo pipefail

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
TARGET="${SCRIPT_DIR}/fetch-fips-ready.sh"
WORK=$(mktemp -d)
MOCKBIN="${WORK}/bin"
FNS="${WORK}/fns.sh"
PASS=0
FAIL=0

cleanup() {
    rm -rf "${WORK}"
}
trap cleanup EXIT

mkdir -p "${MOCKBIN}"

# Source only fetch-fips-ready.sh's function definitions, not its argv
# parser or the case-dispatch at the bottom (both would run immediately,
# and call exit, if sourced as-is). Boundaries are located by marker
# pattern, not hardcoded line numbers, so this stays in sync as the
# script grows.
# shellcheck disable=SC2016  # single-quoted on purpose: matching a literal
# '$' in fetch-fips-ready.sh's source, not expanding a variable here.
while_line=$(grep -n '^while \[\[ \$# -gt 0' "${TARGET}" | head -n1 | cut -d: -f1)
bundle_url_line=$(grep -n '^bundle_url()' "${TARGET}" | head -n1 | cut -d: -f1)
# shellcheck disable=SC2016
case_line=$(grep -n '^case "\$MODE"' "${TARGET}" | head -n1 | cut -d: -f1)
if [[ -z "${while_line}" || -z "${bundle_url_line}" || -z "${case_line}" ]]; then
    echo "test-fetch-fips-ready: could not locate expected markers in" \
        "${TARGET}; has its structure changed?" >&2
    exit 1
fi
{
    sed -n "1,$((while_line - 1))p" "${TARGET}"
    sed -n "${bundle_url_line},$((case_line - 1))p" "${TARGET}"
} > "${FNS}"

pass() {
    PASS=$((PASS + 1))
    echo "PASS: $1"
}

fail() {
    FAIL=$((FAIL + 1))
    echo "FAIL: $1"
}

# Runs $2.. in a subshell with the mock bin dir first on PATH and the
# resolver functions sourced, so each test gets an isolated MOCKBIN/DEST
# without polluting other tests' mock scripts or fixtures.
run_case() {
    local dest="$1"
    shift
    # DEST must be set AFTER sourcing: the sourced preamble itself sets
    # DEST="$PWD", which would otherwise clobber a prefix assignment made
    # before the source builtin runs. DEST is consumed inside fns.sh, not
    # this file, hence the two shellcheck disables below.
    # SC2030: the PATH override is deliberately scoped to this subshell,
    # so each call gets an isolated mock PATH without polluting later tests.
    # shellcheck disable=SC1090,SC2030,SC2034
    ( PATH="${MOCKBIN}:${PATH}"; source "${FNS}"; DEST="${dest}"; "$@" )
}

# bundle_exists: retries a transient failure (connection error, no HTTP
# response) and succeeds once the server recovers.
test_bundle_exists_retries_transient() {
    local d counter
    d=$(mktemp -d)
    counter="${d}/count"
    cat > "${MOCKBIN}/curl" <<EOF
#!/usr/bin/env bash
n=0
[[ -f "${counter}" ]] && n=\$(cat "${counter}")
n=\$((n + 1))
echo "\$n" > "${counter}"
if [[ "\$*" == *"-I"* && "\$*" == *"%{http_code}"* ]]; then
    if [[ "\$n" -lt 3 ]]; then exit 7; fi
    printf '200'
    exit 0
fi
exit 1
EOF
    chmod +x "${MOCKBIN}/curl"

    if run_case "${d}" bundle_exists "9.9.9"; then
        if [[ "$(cat "${counter}")" == "3" ]]; then
            pass "bundle_exists retries transient failures and succeeds"
        else
            fail "bundle_exists succeeded but call count was $(cat "${counter}"), want 3"
        fi
    else
        fail "bundle_exists did not recover from a transient failure"
    fi
    rm -rf "${d}"
}

# bundle_exists: a confirmed 4xx is definitive, no retry burned.
test_bundle_exists_confirmed_404_no_retry() {
    local d counter rc
    d=$(mktemp -d)
    counter="${d}/count"
    cat > "${MOCKBIN}/curl" <<EOF
#!/usr/bin/env bash
n=0
[[ -f "${counter}" ]] && n=\$(cat "${counter}")
n=\$((n + 1))
echo "\$n" > "${counter}"
if [[ "\$*" == *"-I"* && "\$*" == *"%{http_code}"* ]]; then
    printf '404'
    exit 0
fi
exit 1
EOF
    chmod +x "${MOCKBIN}/curl"

    rc=0
    run_case "${d}" bundle_exists "9.9.9" || rc=$?
    if [[ "${rc}" -ne 1 ]]; then
        fail "bundle_exists returned ${rc} for a confirmed 404, want 1 (absent)"
    elif [[ "$(cat "${counter}")" == "1" ]]; then
        pass "bundle_exists treats a confirmed 404 as final, no retry"
    else
        fail "bundle_exists retried after a confirmed 404 ($(cat "${counter}") calls)"
    fi
    rm -rf "${d}"
}

# bundle_exists: a 429 (rate limit) is transient, not a confirmed absence.
# A prior review round flagged classifying all 4xx as permanently absent.
test_bundle_exists_429_is_transient() {
    local d counter rc
    d=$(mktemp -d)
    counter="${d}/count"
    cat > "${MOCKBIN}/curl" <<EOF
#!/usr/bin/env bash
n=0
[[ -f "${counter}" ]] && n=\$(cat "${counter}")
n=\$((n + 1))
echo "\$n" > "${counter}"
if [[ "\$*" == *"-I"* && "\$*" == *"%{http_code}"* ]]; then
    if [[ "\$n" -lt 2 ]]; then printf '429'; exit 0; fi
    printf '200'
    exit 0
fi
exit 1
EOF
    chmod +x "${MOCKBIN}/curl"

    rc=0
    run_case "${d}" bundle_exists "9.9.9" || rc=$?
    if [[ "${rc}" -eq 0 ]]; then
        pass "bundle_exists retries a 429 instead of treating it as absent"
    else
        fail "bundle_exists returned ${rc} for a 429-then-200 sequence, want 0 (exists)"
    fi
    rm -rf "${d}"
}

# bundle_exists: exhausts retries and reports indeterminate (rc=2), not
# confirmed-absent (rc=1), when every attempt is transient.
test_bundle_exists_exhausts_on_persistent_transient() {
    local d rc
    d=$(mktemp -d)
    cat > "${MOCKBIN}/curl" <<'EOF'
#!/usr/bin/env bash
if [[ "$*" == *"-I"* && "$*" == *"%{http_code}"* ]]; then
    exit 7
fi
exit 1
EOF
    chmod +x "${MOCKBIN}/curl"

    rc=0
    run_case "${d}" bundle_exists "9.9.9" 2>/dev/null || rc=$?
    if [[ "${rc}" -eq 2 ]]; then
        pass "bundle_exists reports indeterminate (rc=2), distinct from confirmed absent"
    else
        fail "bundle_exists returned ${rc} for persistent transient failure, want 2"
    fi
    rm -rf "${d}"
}

# list_versions: unions git tags with the page's advertised latest,
# applies the floor, and only keeps versions that probe as hosted.
test_list_versions_filters_and_sorts() {
    local d html
    d=$(mktemp -d)
    html="${d}/page.html"
    cat > "${html}" <<'EOF'
<input value="wolfssl-5.9.2-gplv3-fips-ready.zip" /> (SHA256: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa)<br>
EOF
    cat > "${MOCKBIN}/git" <<'EOF'
#!/usr/bin/env bash
if [[ "$1" == "ls-remote" ]]; then
    cat <<TAGS
aaa1	refs/tags/v5.7.0-stable
aaa2	refs/tags/v5.8.2-stable
aaa3	refs/tags/v5.8.6-stable
aaa4	refs/tags/v5.9.0-stable
aaa5	refs/tags/v5.9.1-stable
TAGS
    exit 0
fi
exit 1
EOF
    chmod +x "${MOCKBIN}/git"
    cat > "${MOCKBIN}/curl" <<EOF
#!/usr/bin/env bash
if [[ "\$*" == *"-I"* && "\$*" == *"%{http_code}"* ]]; then
    # Everything except 5.8.6 is hosted: exercises the "tag exists but no
    # bundle" gap the floor/union logic has to handle.
    for a in "\$@"; do
        if [[ "\$a" == *"5.8.6"* ]]; then printf '404'; exit 0; fi
    done
    printf '200'
    exit 0
fi
cat "${html}"
exit 0
EOF
    chmod +x "${MOCKBIN}/curl"

    local out expected
    out=$(run_case "${d}" list_versions)
    expected="5.8.2
5.9.0
5.9.1
5.9.2"
    if [[ "${out}" == "${expected}" ]]; then
        pass "list_versions unions tags + page, applies floor, drops unhosted"
    else
        fail "list_versions returned [${out}], want [${expected}]"
    fi
    rm -rf "${d}"
}

# list_versions: fails cleanly (not a crash) when upstream tags can't
# be resolved at all.
test_list_versions_fails_when_tags_unavailable() {
    local d
    d=$(mktemp -d)
    cat > "${MOCKBIN}/git" <<'EOF'
#!/usr/bin/env bash
exit 1
EOF
    chmod +x "${MOCKBIN}/git"
    cat > "${MOCKBIN}/curl" <<'EOF'
#!/usr/bin/env bash
exit 1
EOF
    chmod +x "${MOCKBIN}/curl"

    if run_case "${d}" list_versions 2>/dev/null; then
        fail "list_versions succeeded despite git ls-remote failing entirely"
    else
        pass "list_versions fails cleanly when upstream tags are unavailable"
    fi
    rm -rf "${d}"
}

# list_versions: one candidate hosted, one persistently indeterminate
# (5xx/timeout throughout). The whole resolution must fail rather than
# publishing a list that quietly omits the flaky candidate.
test_list_versions_fails_on_indeterminate_candidate() {
    local d rc
    d=$(mktemp -d)
    cat > "${MOCKBIN}/git" <<'EOF'
#!/usr/bin/env bash
if [[ "$1" == "ls-remote" ]]; then
    cat <<TAGS
aaa1	refs/tags/v5.8.2-stable
aaa2	refs/tags/v5.9.2-stable
TAGS
    exit 0
fi
exit 1
EOF
    chmod +x "${MOCKBIN}/git"
    cat > "${MOCKBIN}/curl" <<'EOF'
#!/usr/bin/env bash
if [[ "$*" == *"-I"* && "$*" == *"%{http_code}"* ]]; then
    for a in "$@"; do
        # 5.8.2 is persistently flaky (503 forever); 5.9.2 is healthy.
        if [[ "$a" == *"5.8.2"* ]]; then printf '503'; exit 0; fi
    done
    printf '200'
    exit 0
fi
exit 1
EOF
    chmod +x "${MOCKBIN}/curl"

    rc=0
    run_case "${d}" list_versions 2>/dev/null || rc=$?
    if [[ "${rc}" -ne 0 ]]; then
        pass "list_versions fails when a real candidate is indeterminate"
    else
        fail "list_versions succeeded despite an indeterminate candidate (5.8.2 always 503)"
    fi
    rm -rf "${d}"
}

# Entrypoint-level regression for the indeterminate-candidate case. Bash
# disables errexit for the whole call tree beneath a command on the left
# of ||/&&/if, so every other test's `run_case ... || rc=$?` masked a real
# errexit bug that only showed up running the real binary unconditioned.
# This runs `bash "$TARGET" --list` directly to match production CI.
test_entrypoint_list_fails_on_indeterminate_candidate() {
    local d out status
    d=$(mktemp -d)
    cat > "${MOCKBIN}/git" <<'EOF'
#!/usr/bin/env bash
if [[ "$1" == "ls-remote" ]]; then
    cat <<TAGS
aaa1	refs/tags/v5.8.2-stable
aaa2	refs/tags/v5.9.2-stable
TAGS
    exit 0
fi
exit 1
EOF
    chmod +x "${MOCKBIN}/git"
    cat > "${MOCKBIN}/curl" <<'EOF'
#!/usr/bin/env bash
if [[ "$*" == *"-I"* && "$*" == *"%{http_code}"* ]]; then
    for a in "$@"; do
        # 5.8.2 is persistently flaky (503 forever); 5.9.2 is healthy.
        if [[ "$a" == *"5.8.2"* ]]; then printf '503'; exit 0; fi
    done
    printf '200'
    exit 0
fi
exit 1
EOF
    chmod +x "${MOCKBIN}/curl"

    status=0
    # SC2031: the PATH override only needs to reach the `bash "$TARGET"`
    # call on this line; it isn't meant to escape the subshell.
    # shellcheck disable=SC2031
    out=$(cd "${d}" && PATH="${MOCKBIN}:${PATH}" bash "${TARGET}" --list \
        --floor 5.8.2 2>&1) || status=$?

    if [[ "${status}" -ne 0 ]]; then
        pass "entrypoint --list fails on an indeterminate candidate (real subprocess, no errexit masking)"
    else
        fail "entrypoint --list exited 0 despite an indeterminate candidate; got: [${out}]"
    fi
    rm -rf "${d}"
}

# Builds a valid zip fixture at $2 containing wolfssl-$1-gplv3-fips-ready/.
make_fixture_zip() {
    local ver="$1" out="$2" stage
    stage=$(mktemp -d)
    mkdir -p "${stage}/wolfssl-${ver}-gplv3-fips-ready"
    echo "fixture" > "${stage}/wolfssl-${ver}-gplv3-fips-ready/README"
    ( cd "${stage}" && zip -q -r "${out}" "wolfssl-${ver}-gplv3-fips-ready" )
    rm -rf "${stage}"
}

# fetch_bundle: a download failure must not destroy a bundle already at
# the destination (the bug the HIGH finding flagged).
test_fetch_bundle_preserves_existing_on_download_failure() {
    local d
    d=$(mktemp -d)
    mkdir -p "${d}/wolfssl-9.9.9-gplv3-fips-ready"
    touch "${d}/wolfssl-9.9.9-gplv3-fips-ready/CANARY"

    cat > "${MOCKBIN}/curl" <<'EOF'
#!/usr/bin/env bash
if [[ "$*" == *"-I"* && "$*" == *"%{http_code}"* ]]; then
    printf '200'
    exit 0
fi
if [[ "$*" == *"--max-time 900"* || "$*" == *"-o"* ]]; then
    for a in "$@"; do
        if [[ "$a" == *"gplv3-fips-ready.zip"* ]]; then
            exit 1
        fi
    done
fi
exit 1
EOF
    chmod +x "${MOCKBIN}/curl"

    if run_case "${d}" fetch_bundle "9.9.9" 2>/dev/null; then
        fail "fetch_bundle reported success despite the download failing"
    elif [[ -f "${d}/wolfssl-9.9.9-gplv3-fips-ready/CANARY" ]]; then
        pass "fetch_bundle preserves an existing bundle when download fails"
    else
        fail "fetch_bundle destroyed the existing bundle on a failed download"
    fi
    rm -rf "${d}"
}

# fetch_bundle: a checksum mismatch must also preserve whatever was
# already there, not just a hard network failure.
test_fetch_bundle_checksum_mismatch_preserves_existing() {
    local d html zip
    d=$(mktemp -d)
    mkdir -p "${d}/wolfssl-9.9.9-gplv3-fips-ready"
    touch "${d}/wolfssl-9.9.9-gplv3-fips-ready/CANARY"

    zip="${d}/fixture.zip"
    make_fixture_zip "9.9.9" "${zip}"
    html="${d}/page.html"
    # Advertise a hash that will never match the fixture's real SHA256.
    cat > "${html}" <<'EOF'
<input value="wolfssl-9.9.9-gplv3-fips-ready.zip" /> (SHA256: 0000000000000000000000000000000000000000000000000000000000000000)<br>
EOF
    cat > "${MOCKBIN}/curl" <<EOF
#!/usr/bin/env bash
if [[ "\$*" == *"-I"* && "\$*" == *"%{http_code}"* ]]; then
    printf '200'
    exit 0
fi
for a in "\$@"; do
    if [[ "\$a" == *"gplv3-fips-ready.zip" ]]; then
        cp "${zip}" "\$a"
        exit 0
    fi
done
cat "${html}"
exit 0
EOF
    chmod +x "${MOCKBIN}/curl"

    if run_case "${d}" fetch_bundle "9.9.9" 2>/dev/null; then
        fail "fetch_bundle accepted a bundle with a mismatched checksum"
    elif [[ -f "${d}/wolfssl-9.9.9-gplv3-fips-ready/CANARY" ]]; then
        pass "fetch_bundle preserves an existing bundle on checksum mismatch"
    else
        fail "fetch_bundle destroyed the existing bundle on checksum mismatch"
    fi
    rm -rf "${d}"
}

# fetch_bundle: a verified, successful fetch does replace whatever was
# there; the fix must not make replacement impossible, only safe.
test_fetch_bundle_replaces_on_success() {
    local d zip out
    d=$(mktemp -d)
    mkdir -p "${d}/wolfssl-9.9.9-gplv3-fips-ready"
    touch "${d}/wolfssl-9.9.9-gplv3-fips-ready/CANARY"

    zip="${d}/fixture.zip"
    make_fixture_zip "9.9.9" "${zip}"
    if command -v sha256sum >/dev/null 2>&1; then
        real=$(sha256sum "${zip}" | awk '{print $1}')
    else
        real=$(shasum -a 256 "${zip}" | awk '{print $1}')
    fi
    html="${d}/page.html"
    # 9.9.9 is the newest bundle and its published hash matches the fixture.
    cat > "${html}" <<EOF
<input value="wolfssl-9.9.9-gplv3-fips-ready.zip" /> (SHA256: ${real})<br>
EOF
    cat > "${MOCKBIN}/curl" <<EOF
#!/usr/bin/env bash
if [[ "\$*" == *"-I"* && "\$*" == *"%{http_code}"* ]]; then
    printf '200'
    exit 0
fi
for a in "\$@"; do
    if [[ "\$a" == *"gplv3-fips-ready.zip" ]]; then
        cp "${zip}" "\$a"
        exit 0
    fi
done
cat "${html}"
exit 0
EOF
    chmod +x "${MOCKBIN}/curl"

    if out=$(run_case "${d}" fetch_bundle "9.9.9" 2>/dev/null); then
        if [[ -f "${d}/wolfssl-9.9.9-gplv3-fips-ready/CANARY" ]]; then
            fail "fetch_bundle left the stale bundle in place after a verified success"
        elif [[ -f "${d}/wolfssl-9.9.9-gplv3-fips-ready/README" ]] \
            && [[ "${out}" == "${d}/wolfssl-9.9.9-gplv3-fips-ready" ]]; then
            pass "fetch_bundle replaces an existing bundle on verified success"
        else
            fail "fetch_bundle succeeded but left an unexpected result: [${out}]"
        fi
    else
        fail "fetch_bundle failed on a fully valid download"
    fi
    rm -rf "${d}"
}

# fetch_bundle: the newest bundle must never be accepted without a published
# SHA256, even when the download page is reachable but lists no hash for it.
test_fetch_bundle_newest_no_hash_fails() {
    local d html zip
    d=$(mktemp -d)
    mkdir -p "${d}/wolfssl-9.9.9-gplv3-fips-ready"
    touch "${d}/wolfssl-9.9.9-gplv3-fips-ready/CANARY"

    zip="${d}/fixture.zip"
    make_fixture_zip "9.9.9" "${zip}"
    html="${d}/page.html"
    cat > "${html}" <<'EOF'
<input value="wolfssl-9.9.9-gplv3-fips-ready.zip" /><br>
EOF
    cat > "${MOCKBIN}/curl" <<EOF
#!/usr/bin/env bash
if [[ "\$*" == *"-I"* && "\$*" == *"%{http_code}"* ]]; then
    printf '200'
    exit 0
fi
for a in "\$@"; do
    if [[ "\$a" == *"gplv3-fips-ready.zip" ]]; then
        cp "${zip}" "\$a"
        exit 0
    fi
done
cat "${html}"
exit 0
EOF
    chmod +x "${MOCKBIN}/curl"

    if run_case "${d}" fetch_bundle "9.9.9" 2>/dev/null; then
        fail "fetch_bundle accepted the newest bundle with no published SHA256"
    else
        pass "fetch_bundle refuses the newest bundle when no SHA256 is published"
    fi
    rm -rf "${d}"
}

# fetch_bundle: an unreachable download page must fail closed, not downgrade
# the newest bundle to a CRC-only check. Regression test for the fail-open.
test_fetch_bundle_unreachable_page_fails() {
    local d zip
    d=$(mktemp -d)
    mkdir -p "${d}/wolfssl-9.9.9-gplv3-fips-ready"
    touch "${d}/wolfssl-9.9.9-gplv3-fips-ready/CANARY"

    zip="${d}/fixture.zip"
    make_fixture_zip "9.9.9" "${zip}"
    cat > "${MOCKBIN}/curl" <<EOF
#!/usr/bin/env bash
if [[ "\$*" == *"-I"* && "\$*" == *"%{http_code}"* ]]; then
    printf '200'
    exit 0
fi
for a in "\$@"; do
    if [[ "\$a" == *"gplv3-fips-ready.zip" ]]; then
        cp "${zip}" "\$a"
        exit 0
    fi
done
# Download page unreachable.
exit 1
EOF
    chmod +x "${MOCKBIN}/curl"

    if run_case "${d}" fetch_bundle "9.9.9" 2>/dev/null; then
        fail "fetch_bundle accepted a bundle while the download page was unreachable"
    elif [[ -f "${d}/wolfssl-9.9.9-gplv3-fips-ready/CANARY" ]]; then
        pass "fetch_bundle refuses when the download page is unreachable"
    else
        fail "fetch_bundle destroyed the existing bundle on an unreachable page"
    fi
    rm -rf "${d}"
}

test_bundle_exists_retries_transient
test_bundle_exists_confirmed_404_no_retry
test_bundle_exists_429_is_transient
test_bundle_exists_exhausts_on_persistent_transient
test_list_versions_filters_and_sorts
test_list_versions_fails_when_tags_unavailable
test_list_versions_fails_on_indeterminate_candidate
test_entrypoint_list_fails_on_indeterminate_candidate
test_fetch_bundle_preserves_existing_on_download_failure
test_fetch_bundle_checksum_mismatch_preserves_existing
test_fetch_bundle_replaces_on_success
test_fetch_bundle_newest_no_hash_fails
test_fetch_bundle_unreachable_page_fails

echo ""
echo "fetch-fips-ready tests: ${PASS} passed, ${FAIL} failed"
[[ "${FAIL}" -eq 0 ]]
