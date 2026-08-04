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

# Run OpenSSL's ML-KEM, ML-DSA, and LMS EVP KAT vectors through wolfProvider
# using OpenSSL's evp_test harness.
#
# The script reports a raw result: exit 0 only when every vector file passes
# and the exact selected sub-test count ran. The caller owns force-fail
# interpretation: under
# WOLFPROV_FORCE_FAIL=1 every operation fails, so this exits non-zero, and the
# CI job inverts that via check-workflow-result.sh. wolfProvider (replace-default
# or not) must already be built by a prior build-wolfprovider.sh step; this
# script does not build it, only runs the KAT against it. WOLFPROV_PQC and
# WOLFPROV_LMS select families; when both are unset, ML-KEM/ML-DSA is the default.

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
source ${SCRIPT_DIR}/utils-wolfprovider.sh

# OpenSSL's KAT data files are run unmodified.
VECTOR_DIR=${OPENSSL_SOURCE_DIR}/test/recipes/30-test_evp_data
EVP_TEST=${OPENSSL_TEST}/evp_test

require_evp_test() {
    if [ -x "${EVP_TEST}" ]; then
        return 0
    fi
    # evp_test must come from the OpenSSL build. A replace-default build omits
    # OpenSSL's test suite ('no-tests') unless --enable-openssl-test was passed;
    # non-replace builds include it by default.
    printf "ERROR: evp_test not found at %s\n" "${EVP_TEST}"
    printf "       Build with --enable-openssl-test and the selected PQC flags\n"
    return 1
}

# Make the runtime linker find libwolfprov, mirroring scripts/env-setup.
set_lib_env() {
    local libs="${WOLFPROV_INSTALL_DIR}/lib:${WOLFSSL_INSTALL_DIR}/lib"
    libs="${libs}:${OPENSSL_INSTALL_DIR}/lib:${OPENSSL_INSTALL_DIR}/lib64"
    export LD_LIBRARY_PATH="${libs}${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
    export DYLD_LIBRARY_PATH="${libs}${DYLD_LIBRARY_PATH:+:$DYLD_LIBRARY_PATH}"
    export OPENSSL_MODULES="${WOLFPROV_INSTALL_DIR}/lib"
}

run_pqc_kat() {
    local bad=0
    local files=0
    local total=0
    local expected=0
    local out line n
    local vectors=""

    if [ -z "${WOLFPROV_PQC+x}" ] && [ -z "${WOLFPROV_LMS+x}" ]; then
        WOLFPROV_PQC=1
    fi

    if [ "${WOLFPROV_PQC:-0}" = "1" ]; then
        vectors="${VECTOR_DIR}/evppkey_ml_kem_*.txt ${VECTOR_DIR}/evppkey_ml_dsa_*.txt"
        expected=$((expected + 2602))
    fi
    if [ "${WOLFPROV_LMS:-0}" = "1" ]; then
        if [ ! -f "${VECTOR_DIR}/evppkey_lms_sigver.txt" ]; then
            printf "ERROR: LMS vector file is missing: %s\n" \
                "${VECTOR_DIR}/evppkey_lms_sigver.txt"
            return 1
        fi
        vectors="${vectors} ${VECTOR_DIR}/evppkey_lms_sigver.txt"
        expected=$((expected + 320))
    fi
    if [ -z "${vectors}" ]; then
        printf "ERROR: no PQC KAT family selected; set WOLFPROV_PQC=1 and/or WOLFPROV_LMS=1\n"
        return 1
    fi

    printf "PQC KAT: %d sub-tests expected across all files\n" \
        "${expected}"

    for f in ${vectors}; do
        files=$((files + 1))
        printf "\t%-42s ... " "$(basename ${f})"
        out=$(${EVP_TEST} -config ${WOLFPROV_CONFIG} "${f}" 2>&1)
        local rc=$?
        line=$(echo "${out}" | grep -oE 'Completed [0-9]+ tests')
        n=$(echo "${line}" | grep -oE '[0-9]+')
        total=$((total + ${n:-0}))
        if [ ${rc} -eq 0 ]; then
            printf "PASS (%s)\n" "${n:-0}"
        else
            printf "FAIL\n"
            printf "%s\n" "${out}"
            bad=$((bad + 1))
        fi
    done

    printf "Ran %d files, %d sub-tests, %d failures\n" \
        "${files}" "${total}" "${bad}"
    if [ ${bad} -ne 0 ]; then
        return 1
    fi
    if [ ${total} -ne ${expected} ]; then
        printf "ERROR: expected %d sub-tests, ran %d\n" \
            "${expected}" "${total}"
        return 1
    fi
    return 0
}

if [ -z "${NUMCPU}" ]; then
    if [[ "${OSTYPE}" == "darwin"* ]]; then
        NUMCPU=$(sysctl -n hw.ncpu)
    else
        NUMCPU=$(grep -c ^processor /proc/cpuinfo)
    fi
fi

# wolfProvider must already be built with the selected PQC flags.
# This script only runs the KAT against that build; it does not rebuild, so it
# cannot drop the opt-in PQC flags. WOLFPROV_FORCE_FAIL is honored at runtime.
set_lib_env
require_evp_test || exit 1
run_pqc_kat
exit $?
