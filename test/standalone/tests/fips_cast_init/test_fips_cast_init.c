/* test_fips_cast_init.c
 *
 * Copyright (C) 2006-2026 wolfSSL Inc.
 *
 * This file is part of wolfProvider.
 *
 * wolfProvider is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * wolfProvider is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with wolfProvider. If not, see <http://www.gnu.org/licenses/>.
 */

/*
 * Regression test for running the FIPS CASTs at provider init.
 *
 * wolfCrypt FIPS runs an algorithm's CAST on its first use. Threads making
 * that first use at once race on the CAST state and the losers fail. The
 * provider now runs every CAST not run yet when it is loaded, except the DH
 * and ECC primitive-Z ones, which stay lazy behind wp_init_cast().
 *
 * Standalone process because the CASTs must be cold, and the shared unit.test
 * process warms them. Each race round runs in a fresh child process, as a
 * CAST can only be raced once per process.
 * Non-FIPS: there are no CASTs, so this skips.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef WOLFPROV_USER_SETTINGS
#include <user_settings.h>
#endif
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/wc_port.h>

#include <openssl/provider.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/core_names.h>
#include <openssl/err.h>

#include "test_common.h"

#if defined(HAVE_FIPS) && !defined(WP_SINGLE_THREADED) && !defined(_WIN32)
#include <pthread.h>
#include <unistd.h>
#include <sys/wait.h>
#include <wolfssl/wolfcrypt/fips_test.h>

/* Threads making their first use of an algorithm at once. */
#define RACE_THREADS        8
/* Fresh processes per operation. */
#define RACE_ROUNDS         8

/* First uses raced. Each fires CASTs that wolfCrypt runs inside the call. */
enum {
    RACE_TLS1_PRF,
    RACE_TLS13_KDF,
    RACE_SSHKDF,
    RACE_HMAC,
    RACE_OP_COUNT
};

static const char* raceOpName[RACE_OP_COUNT] = {
    "TLS1-PRF", "TLS13-KDF", "SSHKDF", "HMAC"
};

static OSSL_LIB_CTX* wpLibCtx = NULL;
static OSSL_PROVIDER* wpProv = NULL;

static int load_provider(void)
{
    wpLibCtx = OSSL_LIB_CTX_new();
    if (wpLibCtx == NULL) {
        TEST_ERROR("Failed to create library context");
        return TEST_FAILURE;
    }
    /* Match unit.test: find libwolfprov in .libs. */
    OSSL_PROVIDER_set_default_search_path(wpLibCtx, ".libs");
    wpProv = OSSL_PROVIDER_load(wpLibCtx, "libwolfprov");
    if (wpProv == NULL) {
        TEST_ERROR("Failed to load wolfProvider");
        OSSL_LIB_CTX_free(wpLibCtx);
        wpLibCtx = NULL;
        return TEST_FAILURE;
    }
    return TEST_SUCCESS;
}

static void unload_provider(void)
{
    if (wpProv != NULL) {
        OSSL_PROVIDER_unload(wpProv);
        wpProv = NULL;
    }
    if (wpLibCtx != NULL) {
        OSSL_LIB_CTX_free(wpLibCtx);
        wpLibCtx = NULL;
    }
}

static const char* cast_state_str(int s)
{
    switch (s) {
        case FIPS_CAST_STATE_INIT:       return "INIT";
        case FIPS_CAST_STATE_PROCESSING: return "PROCESSING";
        case FIPS_CAST_STATE_SUCCESS:    return "SUCCESS";
        case FIPS_CAST_STATE_FAILURE:    return "FAILURE";
        default:                         return "?";
    }
}

/*
 * TEST 1: once the provider is loaded, no CAST is left to run except the DH
 * and ECC primitive-Z ones, which must still be cold. A CAST the module was
 * built without is left PROCESSING by wolfCrypt when run, so only INIT and
 * FAILURE are errors.
 */
static int test_casts_run_at_init(void)
{
    int err = TEST_SUCCESS;
    int i;
    int state;

    TEST_INFO("Test 1: CASTs have run once the provider is loaded");

    for (i = 0; i < FIPS_CAST_COUNT; i++) {
        state = wc_GetCastStatus_fips(i);
        if ((i == FIPS_CAST_DH_PRIMITIVE_Z) ||
                (i == FIPS_CAST_ECC_PRIMITIVE_Z)) {
            if (state != FIPS_CAST_STATE_INIT) {
                TEST_ERROR("  CAST %d is %s, expected INIT (lazy)", i,
                    cast_state_str(state));
                err = TEST_FAILURE;
            }
        }
        else if ((state == FIPS_CAST_STATE_INIT) ||
                 (state == FIPS_CAST_STATE_FAILURE)) {
            TEST_ERROR("  CAST %d is %s after provider load", i,
                cast_state_str(state));
            err = TEST_FAILURE;
        }
    }
    return err;
}

static int race_kdf(EVP_KDF* kdf, int op)
{
    int ok;
    EVP_KDF_CTX* kctx;
    OSSL_PARAM params[6];
    OSSL_PARAM* p = params;
    unsigned char key[32];
    unsigned char seed[32];
    unsigned char out[32];
    int mode = EVP_KDF_HKDF_MODE_EXTRACT_ONLY;

    memset(key, 0x0b, sizeof(key));
    memset(seed, 0x0c, sizeof(seed));

    *p++ = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST,
        (char*)"SHA256", 0);
    if (op == RACE_TLS1_PRF) {
        *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SECRET, key,
            sizeof(key));
        *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SEED, seed,
            sizeof(seed));
    }
    else if (op == RACE_TLS13_KDF) {
        *p++ = OSSL_PARAM_construct_int(OSSL_KDF_PARAM_MODE, &mode);
        *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, key,
            sizeof(key));
        *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, seed,
            sizeof(seed));
    }
    else {
        *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, key,
            sizeof(key));
        *p++ = OSSL_PARAM_construct_octet_string(
            OSSL_KDF_PARAM_SSHKDF_XCGHASH, seed, sizeof(seed));
        *p++ = OSSL_PARAM_construct_octet_string(
            OSSL_KDF_PARAM_SSHKDF_SESSION_ID, seed, sizeof(seed));
        *p++ = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_SSHKDF_TYPE,
            (char*)"A", 0);
    }
    *p = OSSL_PARAM_construct_end();

    kctx = EVP_KDF_CTX_new(kdf);
    ok = (kctx != NULL) &&
        (EVP_KDF_derive(kctx, out, sizeof(out), params) == 1);
    EVP_KDF_CTX_free(kctx);
    return ok;
}

static int race_hmac(EVP_MAC* mac)
{
    int ok;
    EVP_MAC_CTX* mctx;
    OSSL_PARAM params[2];
    unsigned char key[32];
    unsigned char out[32];
    size_t outLen = 0;

    memset(key, 0x0b, sizeof(key));
    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST,
        (char*)"SHA256", 0);
    params[1] = OSSL_PARAM_construct_end();

    mctx = EVP_MAC_CTX_new(mac);
    ok = (mctx != NULL) &&
        (EVP_MAC_init(mctx, key, sizeof(key), params) == 1) &&
        (EVP_MAC_update(mctx, key, sizeof(key)) == 1) &&
        (EVP_MAC_final(mctx, out, &outLen, sizeof(out)) == 1);
    EVP_MAC_CTX_free(mctx);
    return ok;
}

typedef struct race_ctx {
    pthread_barrier_t barrier;
    int op;
    EVP_KDF* kdf;
    EVP_MAC* mac;
} race_ctx;

static void* race_thread(void* arg)
{
    race_ctx* rc = (race_ctx*)arg;
    int ok;

    pthread_barrier_wait(&rc->barrier);
    if (rc->op == RACE_HMAC) {
        ok = race_hmac(rc->mac);
    }
    else {
        ok = race_kdf(rc->kdf, rc->op);
    }
    return ok ? NULL : (void*)1;
}

/* Child process: load the provider and race first use of op. Returns the
 * number of threads that failed, or RACE_THREADS + 1 on setup failure. */
static int race_child(int op)
{
    race_ctx rc;
    pthread_t threads[RACE_THREADS];
    void* res;
    int i;
    int failed = 0;

    if (load_provider() != TEST_SUCCESS) {
        return RACE_THREADS + 1;
    }
    rc.op = op;
    rc.kdf = NULL;
    rc.mac = NULL;
    /* Fetch up front: only the first use of the algorithm is raced. */
    if (op == RACE_HMAC) {
        rc.mac = EVP_MAC_fetch(wpLibCtx, "HMAC", NULL);
    }
    else {
        rc.kdf = EVP_KDF_fetch(wpLibCtx, raceOpName[op], NULL);
    }
    if ((rc.mac == NULL) && (rc.kdf == NULL)) {
        unload_provider();
        return RACE_THREADS + 1;
    }

    pthread_barrier_init(&rc.barrier, NULL, RACE_THREADS);
    for (i = 0; i < RACE_THREADS; i++) {
        if (pthread_create(&threads[i], NULL, race_thread, &rc) != 0) {
            /* The barrier can never be reached: give up on this process. */
            _exit(RACE_THREADS + 1);
        }
    }
    for (i = 0; i < RACE_THREADS; i++) {
        pthread_join(threads[i], &res);
        if (res != NULL) {
            failed++;
        }
    }
    pthread_barrier_destroy(&rc.barrier);

    EVP_MAC_free(rc.mac);
    EVP_KDF_free(rc.kdf);
    unload_provider();
    return failed;
}

/*
 * TEST 2: threads making the first use of a KDF or HMAC at once all succeed.
 * Each round is a fresh process so the CASTs start cold.
 */
static int test_first_use_race(void)
{
    int err = TEST_SUCCESS;
    int op;
    int round;
    int status;
    int failed;
    int badRounds;
    pid_t pid;

    TEST_INFO("Test 2: %d threads making first use at once, %d processes "
        "per algorithm", RACE_THREADS, RACE_ROUNDS);

    for (op = 0; op < RACE_OP_COUNT; op++) {
        badRounds = 0;
        for (round = 0; round < RACE_ROUNDS; round++) {
            fflush(NULL);
            pid = fork();
            if (pid < 0) {
                TEST_ERROR("  fork failed");
                return TEST_FAILURE;
            }
            if (pid == 0) {
                _exit(race_child(op));
            }
            if ((waitpid(pid, &status, 0) != pid) || !WIFEXITED(status)) {
                TEST_ERROR("  %s: child did not exit normally",
                    raceOpName[op]);
                return TEST_FAILURE;
            }
            failed = WEXITSTATUS(status);
            if (failed > RACE_THREADS) {
                TEST_ERROR("  %s: child setup failed", raceOpName[op]);
                return TEST_FAILURE;
            }
            if (failed != 0) {
                badRounds++;
            }
        }
        TEST_INFO("  %s: %d of %d processes had a failed thread",
            raceOpName[op], badRounds, RACE_ROUNDS);
        if (badRounds != 0) {
            err = TEST_FAILURE;
        }
    }
    return err;
}

#endif /* HAVE_FIPS && !WP_SINGLE_THREADED && !_WIN32 */

int main(void)
{
    TEST_INFO("========================================");
    TEST_INFO("FIPS CAST at provider init test");
    TEST_INFO("========================================");

#if !defined(HAVE_FIPS) || defined(WP_SINGLE_THREADED) || defined(_WIN32)
    TEST_INFO("SKIPPED - not a multi-threaded POSIX FIPS build");
    return TEST_SUCCESS;
#else
    {
    int rc = TEST_SUCCESS;

    /* Race first: the children must start from cold CASTs, so this process
     * loads no wolfCrypt state before forking. */
    if (test_first_use_race() != TEST_SUCCESS) {
        rc = TEST_FAILURE;
    }
    if (load_provider() != TEST_SUCCESS) {
        return TEST_FAILURE;
    }
    if (test_casts_run_at_init() != TEST_SUCCESS) {
        rc = TEST_FAILURE;
    }
    unload_provider();

    TEST_INFO("========================================");
    if (rc == TEST_SUCCESS) {
        TEST_INFO("All FIPS CAST at provider init tests PASSED");
    }
    else {
        TEST_ERROR("FIPS CAST at provider init tests FAILED");
    }
    TEST_INFO("========================================");

    return rc;
    }
#endif
}
