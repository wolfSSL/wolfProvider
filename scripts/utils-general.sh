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

check_folder_age() {
    folderA=$1
    folderB=$2
    folderA_age=$(find "$folderA" -type f -printf '%T@' | sort -n | tail -n 1)
    folderB_age=$(find "$folderB" -type f -printf '%T@' | sort -n | tail -n 1)

    if awk "BEGIN {exit !($folderA_age > $folderB_age)}"; then
        echo 1
    elif awk "BEGIN {exit !($folderA_age < $folderB_age)}"; then
        echo -1
    else
        echo 0
    fi
}

