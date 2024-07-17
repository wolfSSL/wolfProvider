#!/bin/bash
# This script provides the bare minimum function definitions for compiling
# the wolfProvider library

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
LOG_FILE=${SCRIPT_DIR}/build-release.log
source ${SCRIPT_DIR}/utils-wolfprovider.sh

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

echo "Using openssl: $OPENSSL_TAG, wolfssl: $WOLFSSL_TAG"

init_wolfprov

exit $?
