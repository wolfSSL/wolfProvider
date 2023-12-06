#!/bin/bash

set -e
WORKSPACE=$(pwd)

# Prepare to copy over and run on an Android system
rm -rf ${WORKSPACE}/openssl-install/share
rm -rf ${WORKSPACE}/openssl-install/ssl/misc/tsget

adb push --sync ${WORKSPACE}/openssl ${WORKSPACE}/openssl-install ${WORKSPACE}/wolfssl-install/lib/libwolfssl.so ${WORKSPACE}/wolfProvider/.libs/libwolfprov.so ${WORKSPACE}/wolfProvider/provider.conf ${WORKSPACE}/wolfProvider/scripts run_helper.sh ${WORKSPACE}/wolfProvider/examples/openssl_example run_openssl.sh /data/local/tmp/.

adb shell "cd /data/local/tmp/ && ./run_helper.sh"

adb shell "cd /data/local/tmp/ && ./run_openssl.sh"
