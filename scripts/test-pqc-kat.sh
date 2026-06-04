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

# Run OpenSSL's own ML-KEM/ML-DSA EVP KAT vectors (NIST ACVP + Wycheproof,
# 2602 sub-tests) through wolfProvider using OpenSSL's own evp_test harness.
# This proves wolfcrypt serves the FIPS 203 / FIPS 204 reference vectors
# unmodified via the OpenSSL provider interface.
#
# The script reports a raw result: exit 0 only when every vector file passes
# and all 2602 sub-tests ran. The caller owns force-fail interpretation: under
# WOLFPROV_FORCE_FAIL=1 every operation fails, so this exits non-zero, and the
# CI job inverts that via check-workflow-result.sh. Build mode (replace-default
# or not) is selected by WOLFPROV_REPLACE_DEFAULT, honored by init_wolfprov.

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
source ${SCRIPT_DIR}/utils-wolfprovider.sh

# OpenSSL's own KAT data files, run unmodified: the wolfcrypt FIPS 203/204
# decode fix makes every ML-KEM/ML-DSA vector pass as-is, so nothing is
# staged or edited here.
VECTOR_DIR=${OPENSSL_SOURCE_DIR}/test/recipes/30-test_evp_data
EVP_TEST=${OPENSSL_TEST}/evp_test
EXPECTED_TESTS=2602

build_evp_test() {
    if [ -x "${EVP_TEST}" ]; then
        return 0
    fi
    # 'no-tests' only drops test programs from the default build; the Makefile
    # still has the rule, so this one target builds with no reconfigure and
    # the replace-default patch (in the source files) stays intact.
    printf "Building evp_test ...\n"
    (cd ${OPENSSL_SOURCE_DIR} && make -j${NUMCPU:-4} test/evp_test >/dev/null 2>&1)
    if [ ! -x "${EVP_TEST}" ]; then
        printf "ERROR: failed to build evp_test\n"
        return 1
    fi
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
    local out line n

    printf "PQC KAT: %d sub-tests expected across all files\n" \
        "${EXPECTED_TESTS}"

    for f in ${VECTOR_DIR}/evppkey_ml_kem_*.txt \
             ${VECTOR_DIR}/evppkey_ml_dsa_*.txt; do
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
            bad=$((bad + 1))
        fi
    done

    printf "Ran %d files, %d sub-tests, %d failures\n" \
        "${files}" "${total}" "${bad}"
    if [ ${bad} -ne 0 ]; then
        return 1
    fi
    if [ ${total} -ne ${EXPECTED_TESTS} ]; then
        printf "ERROR: expected %d sub-tests, ran %d\n" \
            "${EXPECTED_TESTS}" "${total}"
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

init_wolfprov
set_lib_env
build_evp_test || exit 1
run_pqc_kat
exit $?
