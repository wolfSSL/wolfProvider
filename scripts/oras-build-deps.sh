#!/usr/bin/env bash
set -euo pipefail

# Pull or push a prebuilt OpenSSL/wolfSSL install tree as an OCI artifact.
# Lets from-source CI builders reuse a dependency built once per commit
# instead of recompiling it every job.
#
# Usage:
#   oras-build-deps.sh pull <oci-ref> <dir>   # extract artifact into <dir>; exit 0 hit, 3 miss
#   oras-build-deps.sh push <oci-ref> <dir>   # tar <dir> and push (best-effort; never fails the job)

if [[ $# -lt 3 || $# -gt 4 ]]; then
    echo "Usage: $0 pull|push <oci-ref> <dir> [verify-src-dir]" >&2
    exit 1
fi

CMD="$1"
REF="$2"
DIR="$3"
VERIFY_SRC="${4:-}"
ARTIFACT="deps.tar.gz"

# No oras on PATH (best-effort install failed): fast-path instead of burning
# retry backoff on 'command not found'. pull -> miss, push -> no-op.
if ! command -v oras >/dev/null 2>&1; then
    case "$CMD" in
        pull) echo "miss (oras not installed): $REF"; exit 3 ;;
        push) echo "push skipped (oras not installed): $REF"; exit 0 ;;
    esac
fi

oras_retry() {
    local attempt
    for attempt in 1 2 3; do
        if "$@"; then
            return 0
        fi
        [[ "$attempt" -lt 3 ]] && sleep $((attempt * 15))
    done
    return 1
}

case "$CMD" in
    pull)
        # A missing tag is a normal cache miss, not an error.
        if ! err=$(oras manifest fetch "$REF" 2>&1 >/dev/null); then
            case "$err" in
                *"not found"*|*"failed to resolve"*|*"unauthorized"*|*"denied"*|*"UNAUTHORIZED"*|*"forbidden"*|*"401"*|*"403"*)
                    echo "miss: $REF"
                    exit 3
                    ;;
            esac
        fi
        # Stage in the same directory as $DIR so the final swap is an atomic
        # rename, not a cross-filesystem copy (container /tmp vs the workspace
        # bind-mount) that could leave a half-populated install dir on failure.
        parent=$(dirname "$DIR")
        tmp=$(mktemp -d "${parent}/.oras-deps.XXXXXX")
        trap 'rm -rf "$tmp"' EXIT
        if ! oras_retry oras pull "$REF" -o "$tmp"; then
            echo "miss (pull failed): $REF"
            exit 3
        fi
        if [[ ! -f "$tmp/$ARTIFACT" ]]; then
            echo "miss (no artifact in $REF)"
            exit 3
        fi
        # Extract into the temp dir first, then swap into place. A failed or
        # partial extract must never leave a half-populated install dir - the
        # build scripts treat a present dir as a cache hit and skip rebuild.
        if ! tar xzf "$tmp/$ARTIFACT" -C "$tmp"; then
            echo "miss (extract failed): $REF"
            exit 3
        fi
        base=$(basename "$DIR")
        if [[ ! -d "$tmp/$base" ]]; then
            echo "miss (artifact missing $base): $REF"
            exit 3
        fi
        rm -rf "$DIR"
        mv "$tmp/$base" "$DIR"
        echo "hit: $REF"
        ;;
    push)
        # Best-effort: a push failure must never fail the job, so guard every
        # fallible step and always exit 0.
        if [[ ! -d "$DIR" ]]; then
            echo "nothing to push: $DIR absent"
            exit 0
        fi
        # Guard against a moving ref (master) advancing between the resolve step
        # and the clone: the tag embeds the resolved SHA, so refuse to push if
        # the built source is a different commit (would poison the durable tag).
        if [[ -n "$VERIFY_SRC" && -d "$VERIFY_SRC/.git" ]]; then
            expected=$(printf '%s' "$REF" | grep -oE '[0-9a-f]{40}' | head -1 || true)
            built=$(git -C "$VERIFY_SRC" rev-parse HEAD 2>/dev/null || true)
            if [[ -n "$expected" && -n "$built" && "$expected" != "$built" ]]; then
                echo "push skipped: $VERIFY_SRC at $built != tag $expected (moving ref advanced)"
                exit 0
            fi
        fi
        if ! tmp=$(mktemp -d); then
            echo "push skipped: mktemp failed"
            exit 0
        fi
        trap 'rm -rf "$tmp"' EXIT
        if ! tar czf "$tmp/$ARTIFACT" -C "$(dirname "$DIR")" "$(basename "$DIR")"; then
            echo "push skipped: tar failed"
            exit 0
        fi
        # oras rejects absolute file paths on push, and an absolute path stored
        # in the manifest would break the pull side too; push by relative name
        # from inside the temp dir.
        if ( cd "$tmp" && oras_retry oras push "$REF" "$ARTIFACT" ); then
            echo "pushed: $REF"
        else
            echo "push failed (non-fatal): $REF"
        fi
        ;;
    *)
        echo "unknown command: $CMD" >&2
        exit 1
        ;;
esac
