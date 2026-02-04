/*
 * Copyright 2019-2024 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * Modified for wolfProvider FIPS Baseline - POST bypass for 3.4.x
 */

#include <string.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/crypto.h>
#include "internal/cryptlib.h"
#include <openssl/fipskey.h>
#include <openssl/err.h>
#include <openssl/proverr.h>
#include <openssl/rand.h>
#include "internal/e_os.h"
#include "internal/tsan_assist.h"
#include "prov/providercommon.h"
#include "crypto/rand.h"

/*
 * We're cheating here. Normally we don't allow RUN_ONCE usage inside the FIPS
 * module because all such initialisation should be associated with an
 * individual OSSL_LIB_CTX. That doesn't work with the self test though because
 * it should be run once regardless of the number of OSSL_LIB_CTXs we have.
 */
#define ALLOW_RUN_ONCE_IN_FIPS
#include "internal/thread_once.h"
#include "self_test.h"

#define FIPS_STATE_INIT     0
#define FIPS_STATE_SELFTEST 1
#define FIPS_STATE_RUNNING  2
#define FIPS_STATE_ERROR    3

/*
 * The number of times the module will report it is in the error state
 * before going quiet.
 */
#define FIPS_ERROR_REPORTING_RATE_LIMIT     10

/* The size of a temp buffer used to read in data */
#define INTEGRITY_BUF_SIZE (4096)
#define MAX_MD_SIZE 64
#define MAC_NAME    "HMAC"
#define DIGEST_NAME "SHA256"

static int FIPS_conditional_error_check = 1;
static CRYPTO_RWLOCK *self_test_lock = NULL;

static CRYPTO_ONCE fips_self_test_init = CRYPTO_ONCE_STATIC_INIT;
#if !defined(OPENSSL_NO_FIPS_POST)
static unsigned char fixed_key[32] = { FIPS_KEY_ELEMENTS };
#endif

DEFINE_RUN_ONCE_STATIC(do_fips_self_test_init)
{
    /*
     * These locks get freed in platform specific ways that may occur after we
     * do mem leak checking. If we don't know how to free it for a particular
     * platform then we just leak it deliberately.
     */
    self_test_lock = CRYPTO_THREAD_lock_new();
    return self_test_lock != NULL;
}

/*
 * Declarations for the DEP entry/exit points.
 * Ones not required or incorrect need to be undefined or redefined respectively.
 */
#define DEP_INITIAL_STATE   FIPS_STATE_INIT
#define DEP_INIT_ATTRIBUTE  static
#define DEP_FINI_ATTRIBUTE  static

static void init(void);
static void cleanup(void);

/*
 * This is the Default Entry Point (DEP) code.
 * See FIPS 140-2 IG 9.10
 */
#if defined(_WIN32) || defined(__CYGWIN__)
# ifdef __CYGWIN__
/* pick DLL_[PROCESS|THREAD]_[ATTACH|DETACH] definitions */
#  include <windows.h>
/*
 * this has side-effect of _WIN32 getting defined, which otherwise is
 * mutually exclusive with __CYGWIN__...
 */
# endif

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved);
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
    switch (fdwReason) {
    case DLL_PROCESS_ATTACH:
        init();
        break;
    case DLL_PROCESS_DETACH:
        cleanup();
        break;
    default:
        break;
    }
    return TRUE;
}

#elif defined(__GNUC__) && !defined(_AIX)
# undef DEP_INIT_ATTRIBUTE
# undef DEP_FINI_ATTRIBUTE
# define DEP_INIT_ATTRIBUTE static __attribute__((constructor))
# define DEP_FINI_ATTRIBUTE static __attribute__((destructor))

#elif defined(__sun)
# pragma init(init)
# pragma fini(cleanup)

#elif defined(_AIX) && !defined(__GNUC__)
void _init(void);
void _cleanup(void);
# pragma init(_init)
# pragma fini(_cleanup)
void _init(void)
{
    init();
}
void _cleanup(void)
{
    cleanup();
}

#elif defined(__hpux)
# pragma init "init"
# pragma fini "cleanup"

#elif defined(__TANDEM)
/* Method automatically called by the NonStop OS when the DLL loads */
void __INIT__init(void) {
    init();
}

/* Method automatically called by the NonStop OS prior to unloading the DLL */
void __TERM__cleanup(void) {
    cleanup();
}

#else
/*
 * This build does not support any kind of DEP.
 * We force the self-tests to run as part of the FIPS provider initialisation
 * rather than being triggered by the DEP.
 */
# undef DEP_INIT_ATTRIBUTE
# undef DEP_FINI_ATTRIBUTE
# undef DEP_INITIAL_STATE
# define DEP_INITIAL_STATE  FIPS_STATE_SELFTEST
#endif

static TSAN_QUALIFIER int FIPS_state = DEP_INITIAL_STATE;

#if defined(DEP_INIT_ATTRIBUTE)
DEP_INIT_ATTRIBUTE void init(void)
{
    tsan_store(&FIPS_state, FIPS_STATE_SELFTEST);
}
#endif

#if defined(DEP_FINI_ATTRIBUTE)
DEP_FINI_ATTRIBUTE void cleanup(void)
{
    CRYPTO_THREAD_lock_free(self_test_lock);
}
#endif

static void set_fips_state(int state)
{
    tsan_store(&FIPS_state, state);
}

/*
 * FIPS Baseline: POST bypass for wolfProvider testing
 *
 * This version of SELF_TEST_post() bypasses all FIPS self-tests and
 * immediately transitions to FIPS_STATE_RUNNING. This allows wolfProvider
 * to provide cryptographic implementations without the overhead of
 * OpenSSL's FIPS module integrity checks and KATs.
 */
int SELF_TEST_post(SELF_TEST_POST_PARAMS *st, int on_demand_test)
{
    int loclstate;

    if (!RUN_ONCE(&fips_self_test_init, do_fips_self_test_init))
        return 0;

    loclstate = tsan_load(&FIPS_state);

    /* If already running, just return success */
    if (loclstate == FIPS_STATE_RUNNING) {
        return 1;
    }

    /* FIPS Baseline: Bypass all self-tests and set state to running */
    set_fips_state(FIPS_STATE_RUNNING);
    return 1;

    /*
     * Original FIPS POST code below has been bypassed for wolfProvider
     * FIPS baseline testing. The code is retained for reference.
     */
#if 0
    int ok = 0;
    long checksum_len;
    OSSL_CORE_BIO *bio_module = NULL;
    unsigned char *module_checksum = NULL;
    OSSL_SELF_TEST *ev = NULL;
    EVP_RAND *testrand = NULL;
    EVP_RAND_CTX *rng;

    if (loclstate != FIPS_STATE_SELFTEST) {
        ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_STATE);
        return 0;
    }

    if (!CRYPTO_THREAD_write_lock(self_test_lock))
        return 0;

    loclstate = tsan_load(&FIPS_state);
    if (loclstate == FIPS_STATE_RUNNING) {
        if (!on_demand_test) {
            CRYPTO_THREAD_unlock(self_test_lock);
            return 1;
        }
        set_fips_state(FIPS_STATE_SELFTEST);
    } else if (loclstate != FIPS_STATE_SELFTEST) {
        CRYPTO_THREAD_unlock(self_test_lock);
        ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_STATE);
        return 0;
    }

    if (st == NULL
            || st->module_checksum_data == NULL) {
        ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_CONFIG_DATA);
        goto end;
    }

    ev = OSSL_SELF_TEST_new(st->cb, st->cb_arg);
    if (ev == NULL)
        goto end;

    module_checksum = OPENSSL_hexstr2buf(st->module_checksum_data,
                                         &checksum_len);
    if (module_checksum == NULL) {
        ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_CONFIG_DATA);
        goto end;
    }
    bio_module = (*st->bio_new_file_cb)(st->module_filename, "rb");

    /* Always check the integrity of the fips module */
    if (bio_module == NULL
            || !verify_integrity(bio_module, st->bio_read_ex_cb,
                                 module_checksum, checksum_len, st->libctx,
                                 ev, OSSL_SELF_TEST_TYPE_MODULE_INTEGRITY)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_MODULE_INTEGRITY_FAILURE);
        goto end;
    }

    if (!SELF_TEST_kats(ev, st->libctx)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_SELF_TEST_KAT_FAILURE);
        goto end;
    }

    /* Verify that the RNG has been restored properly */
    rng = ossl_rand_get0_private_noncreating(st->libctx);
    if (rng != NULL)
        if ((testrand = EVP_RAND_fetch(st->libctx, "TEST-RAND", NULL)) == NULL
                || strcmp(EVP_RAND_get0_name(EVP_RAND_CTX_get0_rand(rng)),
                          EVP_RAND_get0_name(testrand)) == 0) {
            ERR_raise(ERR_LIB_PROV, PROV_R_SELF_TEST_KAT_FAILURE);
            goto end;
        }

    ok = 1;
end:
    EVP_RAND_free(testrand);
    OSSL_SELF_TEST_free(ev);
    OPENSSL_free(module_checksum);

    if (st != NULL)
        (*st->bio_free_cb)(bio_module);

    if (ok)
        set_fips_state(FIPS_STATE_RUNNING);
    else
        ossl_set_error_state(OSSL_SELF_TEST_TYPE_NONE);
    CRYPTO_THREAD_unlock(self_test_lock);

    return ok;
#endif /* 0 - Bypassed POST code */
}

void SELF_TEST_disable_conditional_error_state(void)
{
    FIPS_conditional_error_check = 0;
}

void ossl_set_error_state(const char *type)
{
    int cond_test = (type != NULL && strcmp(type, OSSL_SELF_TEST_TYPE_PCT) == 0);

    if (!cond_test || (FIPS_conditional_error_check == 1)) {
        set_fips_state(FIPS_STATE_ERROR);
        ERR_raise(ERR_LIB_PROV, PROV_R_FIPS_MODULE_ENTERING_ERROR_STATE);
    } else {
        ERR_raise(ERR_LIB_PROV, PROV_R_FIPS_MODULE_CONDITIONAL_ERROR);
    }
}

int ossl_prov_is_running(void)
{
    int res, loclstate;
    static TSAN_QUALIFIER unsigned int rate_limit = 0;

    loclstate = tsan_load(&FIPS_state);
    res = loclstate == FIPS_STATE_RUNNING || loclstate == FIPS_STATE_SELFTEST;
    if (loclstate == FIPS_STATE_ERROR)
        if (tsan_counter(&rate_limit) < FIPS_ERROR_REPORTING_RATE_LIMIT)
            ERR_raise(ERR_LIB_PROV, PROV_R_FIPS_MODULE_IN_ERROR_STATE);
    return res;
}
