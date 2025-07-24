#!/bin/bash
# This script provides the bare minimum function definitions for compiling
# the wolfProvider library

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"

if [ "$UTILS_GENERAL_LOADED" != "yes" ]; then # only set once
    kill_servers() {
        if [ "$(jobs -p)" != "" ]; then
            kill $(jobs -p)
        fi
    }

    do_cleanup() {
        sleep 0.5 # flush buffers
        kill_servers
    }

    do_trap() {
        printf "got trap\n"
        do_cleanup
        date
        exit 1
    }
    trap do_trap INT TERM

    export UTILS_GENERAL_LOADED=yes
fi

# Usage: check_git_match <target_ref> [<repo_dir>]
check_git_match() {
    local target_ref="$1"
    local repo_dir="${2:-.}"

    pushd "$repo_dir" > /dev/null || return 2

    local current_tag current_branch current_commit_long current_commit_short
    current_tag=$(git describe --tags --exact-match 2>/dev/null || true)
    current_branch=$(git symbolic-ref --short HEAD 2>/dev/null || true)
    current_commit_long=$(git rev-parse HEAD 2>/dev/null || true)
    current_commit_short=$(git rev-parse --short HEAD 2>/dev/null || true)

    if [[ -n "$current_tag" && "$target_ref" == "$current_tag" ]]; then
        echo "match: tag ($current_tag)"
        popd > /dev/null
        return 0
    elif [[ -n "$current_branch" && "$target_ref" == "$current_branch" ]]; then
        echo "match: branch ($current_branch)"
        popd > /dev/null
        return 0
    elif [[ -n "$current_commit_long" && "$target_ref" == "$current_commit_long" ]]; then
        echo "match: commit (long $current_commit_long)"
        popd > /dev/null
        return 0
    elif [[ -n "$current_commit_short" && "$target_ref" == "$current_commit_short" ]]; then
        echo "match: commit (short $current_commit_short)"
        popd > /dev/null
        return 0
    else
        echo "no match found for $target_ref"
        printf "Version inconsistency. Please fix ${repo_dir}\n"
        printf "(expected: ${target_ref}, got: ${current_tag} ${current_branch} ${current_commit_long} ${current_commit_short})\n"
        popd > /dev/null
        exit 1
    fi
}
