/* test_rand.c
 *
 * Copyright (C) 2006-2025 wolfSSL Inc.
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

#include "unit.h"

#ifdef WP_HAVE_RANDOM

static int test_random_api(void)
{
    int err;
    unsigned char buf[128];

    err = RAND_status() != 1;
    if (err == 0) {
        err = RAND_priv_bytes(buf, sizeof(buf)) != 1;
        PRINT_BUFFER("True random", buf, sizeof(buf));
    }
    if (err == 0) {
        RAND_seed(buf, sizeof(buf));

        RAND_add(buf, sizeof(buf), 128);

        err = RAND_bytes(buf, sizeof(buf)) != 1;
        PRINT_BUFFER("Seeded", buf, sizeof(buf));
    }
    if (err == 0) {
        err = RAND_status() != 1;
    }

    return err;
}

int test_random(void *data)
{
    int err;
    OSSL_LIB_CTX* origLibCtx;

    (void)data;

    PRINT_MSG("Set OpenSSL as default library context");
    origLibCtx = OSSL_LIB_CTX_set0_default(osslLibCtx);
    err = test_random_api();
    if (err == 0) {
        PRINT_MSG("Set wolfProvider as default library context");
        OSSL_LIB_CTX_set0_default(wpLibCtx);
        err = test_random_api();
    }
    OSSL_LIB_CTX_set0_default(origLibCtx);

    return err;
}

/* Fake parent DRBG: counts locking violations. */
static struct {
    int locked;
    int violations;
    int seedCalls;
    int clearSeedCalls;
    int enableLockingCalls;
} fakeParent;
static unsigned char fakeSeed[32];

static int fake_enable_locking(void* ctx)
{
    (void)ctx;
    fakeParent.enableLockingCalls++;
    return 1;
}

static int fake_lock(void* ctx)
{
    (void)ctx;
    fakeParent.violations += fakeParent.locked;
    fakeParent.locked = 1;
    return 1;
}

static void fake_unlock(void* ctx)
{
    (void)ctx;
    fakeParent.violations += !fakeParent.locked;
    fakeParent.locked = 0;
}

static size_t fake_get_seed(void* ctx, unsigned char** pout,
    int entropy, size_t minLen, size_t maxLen, int predResist,
    const unsigned char* adin, size_t adinLen)
{
    (void)ctx; (void)entropy; (void)minLen; (void)maxLen;
    (void)predResist; (void)adin; (void)adinLen;
    fakeParent.seedCalls++;
    fakeParent.violations += !fakeParent.locked;
    *pout = fakeSeed;
    return sizeof(fakeSeed);
}

static void fake_clear_seed(void* ctx, unsigned char* seed, size_t seedLen)
{
    (void)ctx; (void)seed; (void)seedLen;
    fakeParent.clearSeedCalls++;
    fakeParent.violations += !fakeParent.locked;
}

static const OSSL_DISPATCH fakeParentFuncs[] = {
    { OSSL_FUNC_RAND_ENABLE_LOCKING, (void (*)(void))fake_enable_locking },
    { OSSL_FUNC_RAND_LOCK,           (void (*)(void))fake_lock },
    { OSSL_FUNC_RAND_UNLOCK,         (void (*)(void))fake_unlock },
    { OSSL_FUNC_RAND_GET_SEED,       (void (*)(void))fake_get_seed },
    { OSSL_FUNC_RAND_CLEAR_SEED,     (void (*)(void))fake_clear_seed },
    { 0, NULL }
};

int test_drbg_parent_locking(void *data)
{
    int err;
    int noCache = 0;
    const OSSL_ALGORITHM* algs;
    const OSSL_ALGORITHM* alg;
    const OSSL_DISPATCH* fns = NULL;
    OSSL_FUNC_rand_newctx_fn* newCtx = NULL;
    OSSL_FUNC_rand_freectx_fn* freeCtx = NULL;
    OSSL_FUNC_rand_instantiate_fn* instantiate = NULL;
    OSSL_FUNC_rand_enable_locking_fn* enableLocking = NULL;
    void* ctx = NULL;

    (void)data;

    /* Use the DRBG dispatch table directly so the parent can be a fake. */
    algs = OSSL_PROVIDER_query_operation(wpProv, OSSL_OP_RAND, &noCache);
    for (alg = algs; alg != NULL && alg->algorithm_names != NULL; alg++) {
        if (strstr(alg->algorithm_names, "HASH-DRBG") != NULL) {
            fns = alg->implementation;
        }
    }
    for (; fns != NULL && fns->function_id != 0; fns++) {
        switch (fns->function_id) {
            case OSSL_FUNC_RAND_NEWCTX:
                newCtx = OSSL_FUNC_rand_newctx(fns);
                break;
            case OSSL_FUNC_RAND_FREECTX:
                freeCtx = OSSL_FUNC_rand_freectx(fns);
                break;
            case OSSL_FUNC_RAND_INSTANTIATE:
                instantiate = OSSL_FUNC_rand_instantiate(fns);
                break;
            case OSSL_FUNC_RAND_ENABLE_LOCKING:
                enableLocking = OSSL_FUNC_rand_enable_locking(fns);
                break;
        }
    }
    err = (newCtx == NULL) || (freeCtx == NULL) || (instantiate == NULL) ||
          (enableLocking == NULL);
    if (err == 0) {
        memset(&fakeParent, 0, sizeof(fakeParent));
        ctx = newCtx(OSSL_PROVIDER_get0_provider_ctx(wpProv), &fakeParent,
            fakeParentFuncs);
        err = ctx == NULL;
    }
    if (err == 0) {
        PRINT_MSG("Enable locking propagates to parent");
        err = (enableLocking(ctx) != 1) ||
              (fakeParent.enableLockingCalls != 1);
    }
    if (err == 0) {
        PRINT_MSG("Seed taken from parent under parent lock");
        err = (instantiate(ctx, 256, 0, NULL, 0, NULL) != 1) ||
              (fakeParent.seedCalls == 0) ||
              (fakeParent.clearSeedCalls != fakeParent.seedCalls) ||
              (fakeParent.violations != 0) || (fakeParent.locked != 0);
    }

    if (ctx != NULL) {
        freeCtx(ctx);
    }
    OSSL_PROVIDER_unquery_operation(wpProv, OSSL_OP_RAND, algs);

    return err;
}

#endif /* WP_HAVE_RANDOM */
