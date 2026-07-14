/* test_rand_seed.c
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

/*
 * This test file verifies the SEED-SRC and parent-child DRBG hierarchy
 * that is needed for OpenSSH sandbox compatibility.
 *
 * OpenSSH Flow:
 * 1. Provider loads, SEED-SRC is initialized (can access /dev/urandom)
 * 2. OpenSSH forks and calls RAND_poll() BEFORE activating sandbox
 * 3. This instantiates the DRBG hierarchy: SEED-SRC -> Primary DRBG -> Child DRBGs
 * 4. After sandbox activation, child DRBGs get entropy from parent (no file I/O)
 *
 * NOTE: This test requires WP_HAVE_SEED_SRC to be defined (--enable-seed-src).
 */

#include "unit.h"

/* test_seed_src_refcount / test_seed_src_reload are declared in unit.h and
 * defined in both configurations below (real tests when SEED-SRC is enabled,
 * otherwise skip stubs). */

#if defined(WP_HAVE_SEED_SRC) && defined(WP_HAVE_RANDOM)

#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <errno.h>
#include <limits.h>

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/core_names.h>

#include <wolfssl/wolfcrypt/random.h>
#include <wolfprovider/wp_wolfprov.h>

/* wpUnitProviderDir/wpUnitProviderName are declared in unit.h for every
 * SEED-SRC build (see the WP_HAVE_SEED_SRC && WP_HAVE_RANDOM block there). */

/**
 * Test that we can fetch a SEED-SRC and generate random bytes from it.
 *
 * This tests the basic SEED-SRC functionality.
 */
static int test_seed_src_basic(OSSL_LIB_CTX *libCtx, const char *propq)
{
    int err = 0;
    EVP_RAND *seed_src = NULL;
    EVP_RAND_CTX *seed_ctx = NULL;
    unsigned char buf[32];
    int state;

    PRINT_MSG("Testing SEED-SRC basic functionality with propq: %s",
              propq ? propq : "(null)");

    /* Fetch SEED-SRC */
    seed_src = EVP_RAND_fetch(libCtx, "SEED-SRC", propq);
    if (seed_src == NULL) {
        PRINT_ERR_MSG("Failed to fetch SEED-SRC");
        err = 1;
        goto cleanup;
    }
    PRINT_MSG("Fetched SEED-SRC: %s", EVP_RAND_get0_name(seed_src));

    /* Create context */
    seed_ctx = EVP_RAND_CTX_new(seed_src, NULL);
    if (seed_ctx == NULL) {
        PRINT_ERR_MSG("Failed to create SEED-SRC context");
        err = 1;
        goto cleanup;
    }

    /* Instantiate */
    if (EVP_RAND_instantiate(seed_ctx, 0, 0, NULL, 0, NULL) != 1) {
        PRINT_ERR_MSG("Failed to instantiate SEED-SRC");
        err = 1;
        goto cleanup;
    }

    /* Check state using EVP_RAND_get_state */
    state = EVP_RAND_get_state(seed_ctx);
    if (state != EVP_RAND_STATE_READY) {
        PRINT_ERR_MSG("SEED-SRC not in READY state: %d", state);
        err = 1;
        goto cleanup;
    }
    PRINT_MSG("SEED-SRC is in READY state");

    /* Generate random bytes */
    if (EVP_RAND_generate(seed_ctx, buf, sizeof(buf), 0, 0, NULL, 0) != 1) {
        PRINT_ERR_MSG("Failed to generate from SEED-SRC");
        err = 1;
        goto cleanup;
    }
    PRINT_BUFFER("SEED-SRC output", buf, sizeof(buf));

    PRINT_MSG("SEED-SRC basic test passed");

cleanup:
    EVP_RAND_CTX_free(seed_ctx);
    EVP_RAND_free(seed_src);
    return err;
}

/**
 * Test the parent-child DRBG hierarchy: SEED-SRC -> CTR-DRBG
 *
 * This mimics what OpenSSL does internally and what OpenSSH relies on.
 */
static int test_seed_src_parent_child(OSSL_LIB_CTX *libCtx, const char *propq)
{
    int err = 0;
    EVP_RAND *seed_src = NULL;
    EVP_RAND *ctr_drbg = NULL;
    EVP_RAND_CTX *seed_ctx = NULL;
    EVP_RAND_CTX *drbg_ctx = NULL;
    unsigned char buf[64];

    PRINT_MSG("Testing SEED-SRC -> CTR-DRBG parent-child hierarchy with propq: %s",
              propq ? propq : "(null)");

    /* Fetch SEED-SRC */
    seed_src = EVP_RAND_fetch(libCtx, "SEED-SRC", propq);
    if (seed_src == NULL) {
        PRINT_ERR_MSG("Failed to fetch SEED-SRC");
        err = 1;
        goto cleanup;
    }

    /* Create SEED-SRC context (parent) */
    seed_ctx = EVP_RAND_CTX_new(seed_src, NULL);
    if (seed_ctx == NULL) {
        PRINT_ERR_MSG("Failed to create SEED-SRC context");
        err = 1;
        goto cleanup;
    }

    /* Instantiate SEED-SRC parent first */
    if (EVP_RAND_instantiate(seed_ctx, 0, 0, NULL, 0, NULL) != 1) {
        PRINT_ERR_MSG("Failed to instantiate SEED-SRC parent");
        err = 1;
        goto cleanup;
    }
    PRINT_MSG("Instantiated SEED-SRC parent");

    /* Fetch CTR-DRBG */
    ctr_drbg = EVP_RAND_fetch(libCtx, "CTR-DRBG", propq);
    if (ctr_drbg == NULL) {
        PRINT_ERR_MSG("Failed to fetch CTR-DRBG");
        err = 1;
        goto cleanup;
    }
    PRINT_MSG("Fetched CTR-DRBG: %s", EVP_RAND_get0_name(ctr_drbg));

    /* Create CTR-DRBG context with SEED-SRC as parent */
    drbg_ctx = EVP_RAND_CTX_new(ctr_drbg, seed_ctx);
    if (drbg_ctx == NULL) {
        PRINT_ERR_MSG("Failed to create CTR-DRBG context with parent");
        err = 1;
        goto cleanup;
    }
    PRINT_MSG("Created CTR-DRBG with SEED-SRC as parent");

    /* Set cipher parameter before instantiation */
    {
        OSSL_PARAM params[2];
        params[0] = OSSL_PARAM_construct_utf8_string(OSSL_DRBG_PARAM_CIPHER,
                                                     (char*)"AES-256-CTR", 0);
        params[1] = OSSL_PARAM_construct_end();
        if (EVP_RAND_CTX_set_params(drbg_ctx, params) != 1) {
            PRINT_ERR_MSG("Failed to set CTR-DRBG cipher param");
            err = 1;
            goto cleanup;
        }
    }

    /* Instantiate CTR-DRBG - this should get entropy from parent SEED-SRC */
    if (EVP_RAND_instantiate(drbg_ctx, 256, 0, NULL, 0, NULL) != 1) {
        PRINT_ERR_MSG("Failed to instantiate CTR-DRBG");
        err = 1;
        goto cleanup;
    }
    PRINT_MSG("Instantiated CTR-DRBG (got entropy from SEED-SRC parent)");

    /* Generate random bytes from child DRBG */
    if (EVP_RAND_generate(drbg_ctx, buf, sizeof(buf), 256, 0, NULL, 0) != 1) {
        PRINT_ERR_MSG("Failed to generate from CTR-DRBG");
        err = 1;
        goto cleanup;
    }
    PRINT_BUFFER("CTR-DRBG output (via SEED-SRC parent)", buf, sizeof(buf));

    /* Generate more bytes to ensure it continues working */
    if (EVP_RAND_generate(drbg_ctx, buf, sizeof(buf), 256, 0, NULL, 0) != 1) {
        PRINT_ERR_MSG("Failed to generate second block from CTR-DRBG");
        err = 1;
        goto cleanup;
    }
    PRINT_BUFFER("CTR-DRBG second output", buf, sizeof(buf));

    PRINT_MSG("SEED-SRC -> CTR-DRBG parent-child test passed");

cleanup:
    EVP_RAND_CTX_free(drbg_ctx);
    EVP_RAND_CTX_free(seed_ctx);
    EVP_RAND_free(ctr_drbg);
    EVP_RAND_free(seed_src);
    return err;
}

/**
 * Test the parent-child DRBG hierarchy: SEED-SRC -> HASH-DRBG
 */
static int test_seed_src_hash_drbg(OSSL_LIB_CTX *libCtx, const char *propq)
{
    int err = 0;
    EVP_RAND *seed_src = NULL;
    EVP_RAND *hash_drbg = NULL;
    EVP_RAND_CTX *seed_ctx = NULL;
    EVP_RAND_CTX *drbg_ctx = NULL;
    unsigned char buf[64];

    PRINT_MSG("Testing SEED-SRC -> HASH-DRBG parent-child hierarchy with propq: %s",
              propq ? propq : "(null)");

    /* Fetch SEED-SRC */
    seed_src = EVP_RAND_fetch(libCtx, "SEED-SRC", propq);
    if (seed_src == NULL) {
        PRINT_ERR_MSG("Failed to fetch SEED-SRC");
        err = 1;
        goto cleanup;
    }

    /* Create SEED-SRC context (parent) */
    seed_ctx = EVP_RAND_CTX_new(seed_src, NULL);
    if (seed_ctx == NULL) {
        PRINT_ERR_MSG("Failed to create SEED-SRC context");
        err = 1;
        goto cleanup;
    }

    /* Instantiate SEED-SRC parent first */
    if (EVP_RAND_instantiate(seed_ctx, 0, 0, NULL, 0, NULL) != 1) {
        PRINT_ERR_MSG("Failed to instantiate SEED-SRC parent");
        err = 1;
        goto cleanup;
    }
    PRINT_MSG("Instantiated SEED-SRC parent");

    /* Fetch HASH-DRBG */
    hash_drbg = EVP_RAND_fetch(libCtx, "HASH-DRBG", propq);
    if (hash_drbg == NULL) {
        PRINT_ERR_MSG("Failed to fetch HASH-DRBG");
        err = 1;
        goto cleanup;
    }
    PRINT_MSG("Fetched HASH-DRBG: %s", EVP_RAND_get0_name(hash_drbg));

    /* Create HASH-DRBG context with SEED-SRC as parent */
    drbg_ctx = EVP_RAND_CTX_new(hash_drbg, seed_ctx);
    if (drbg_ctx == NULL) {
        PRINT_ERR_MSG("Failed to create HASH-DRBG context with parent");
        err = 1;
        goto cleanup;
    }
    PRINT_MSG("Created HASH-DRBG with SEED-SRC as parent");

    /* Set digest parameter before instantiation */
    {
        OSSL_PARAM params[2];
        params[0] = OSSL_PARAM_construct_utf8_string(OSSL_DRBG_PARAM_DIGEST,
                                                     (char*)"SHA-256", 0);
        params[1] = OSSL_PARAM_construct_end();
        if (EVP_RAND_CTX_set_params(drbg_ctx, params) != 1) {
            PRINT_ERR_MSG("Failed to set HASH-DRBG digest param");
            err = 1;
            goto cleanup;
        }
    }

    /* Instantiate HASH-DRBG - this should get entropy from parent SEED-SRC */
    if (EVP_RAND_instantiate(drbg_ctx, 256, 0, NULL, 0, NULL) != 1) {
        PRINT_ERR_MSG("Failed to instantiate HASH-DRBG");
        err = 1;
        goto cleanup;
    }
    PRINT_MSG("Instantiated HASH-DRBG (got entropy from SEED-SRC parent)");

    /* Generate random bytes from child DRBG */
    if (EVP_RAND_generate(drbg_ctx, buf, sizeof(buf), 256, 0, NULL, 0) != 1) {
        PRINT_ERR_MSG("Failed to generate from HASH-DRBG");
        err = 1;
        goto cleanup;
    }
    PRINT_BUFFER("HASH-DRBG output (via SEED-SRC parent)", buf, sizeof(buf));

    PRINT_MSG("SEED-SRC -> HASH-DRBG parent-child test passed");

cleanup:
    EVP_RAND_CTX_free(drbg_ctx);
    EVP_RAND_CTX_free(seed_ctx);
    EVP_RAND_free(hash_drbg);
    EVP_RAND_free(seed_src);
    return err;
}

/**
 * Test a three-level hierarchy: SEED-SRC -> Primary DRBG -> Public DRBG
 *
 * This is closer to how OpenSSL actually structures its internal DRBGs.
 */
static int test_seed_src_three_level(OSSL_LIB_CTX *libCtx, const char *propq)
{
    int err = 0;
    EVP_RAND *seed_src = NULL;
    EVP_RAND *ctr_drbg = NULL;
    EVP_RAND_CTX *seed_ctx = NULL;
    EVP_RAND_CTX *primary_ctx = NULL;
    EVP_RAND_CTX *public_ctx = NULL;
    unsigned char buf[32];

    PRINT_MSG("Testing three-level hierarchy: SEED-SRC -> Primary -> Public");

    /* Fetch algorithms */
    seed_src = EVP_RAND_fetch(libCtx, "SEED-SRC", propq);
    ctr_drbg = EVP_RAND_fetch(libCtx, "CTR-DRBG", propq);
    if (seed_src == NULL || ctr_drbg == NULL) {
        PRINT_ERR_MSG("Failed to fetch RAND algorithms");
        err = 1;
        goto cleanup;
    }

    /* Level 1: SEED-SRC (root entropy source) */
    seed_ctx = EVP_RAND_CTX_new(seed_src, NULL);
    if (seed_ctx == NULL) {
        PRINT_ERR_MSG("Failed to create SEED-SRC context");
        err = 1;
        goto cleanup;
    }

    /* Instantiate SEED-SRC */
    if (EVP_RAND_instantiate(seed_ctx, 0, 0, NULL, 0, NULL) != 1) {
        PRINT_ERR_MSG("Failed to instantiate SEED-SRC");
        err = 1;
        goto cleanup;
    }
    PRINT_MSG("Created Level 1: SEED-SRC (root entropy source)");

    /* Level 2: Primary DRBG (child of SEED-SRC) */
    primary_ctx = EVP_RAND_CTX_new(ctr_drbg, seed_ctx);
    if (primary_ctx == NULL) {
        PRINT_ERR_MSG("Failed to create primary CTR-DRBG context");
        err = 1;
        goto cleanup;
    }

    {
        OSSL_PARAM params[2];
        params[0] = OSSL_PARAM_construct_utf8_string(OSSL_DRBG_PARAM_CIPHER,
                                                     (char*)"AES-256-CTR", 0);
        params[1] = OSSL_PARAM_construct_end();
        if (EVP_RAND_CTX_set_params(primary_ctx, params) != 1) {
            PRINT_ERR_MSG("Failed to set primary CTR-DRBG cipher param");
            err = 1;
            goto cleanup;
        }
    }

    if (EVP_RAND_instantiate(primary_ctx, 256, 0, NULL, 0, NULL) != 1) {
        PRINT_ERR_MSG("Failed to instantiate primary DRBG");
        err = 1;
        goto cleanup;
    }
    PRINT_MSG("Created Level 2: Primary CTR-DRBG (parent: SEED-SRC)");

    /* Level 3: Public DRBG (child of Primary DRBG) */
    public_ctx = EVP_RAND_CTX_new(ctr_drbg, primary_ctx);
    if (public_ctx == NULL) {
        PRINT_ERR_MSG("Failed to create public CTR-DRBG context");
        err = 1;
        goto cleanup;
    }

    {
        OSSL_PARAM params[2];
        params[0] = OSSL_PARAM_construct_utf8_string(OSSL_DRBG_PARAM_CIPHER,
                                                     (char*)"AES-256-CTR", 0);
        params[1] = OSSL_PARAM_construct_end();
        if (EVP_RAND_CTX_set_params(public_ctx, params) != 1) {
            PRINT_ERR_MSG("Failed to set public CTR-DRBG cipher param");
            err = 1;
            goto cleanup;
        }
    }

    if (EVP_RAND_instantiate(public_ctx, 256, 0, NULL, 0, NULL) != 1) {
        PRINT_ERR_MSG("Failed to instantiate public DRBG");
        err = 1;
        goto cleanup;
    }
    PRINT_MSG("Created Level 3: Public CTR-DRBG (parent: Primary DRBG)");

    /* Generate from the public (leaf) DRBG */
    if (EVP_RAND_generate(public_ctx, buf, sizeof(buf), 256, 0, NULL, 0) != 1) {
        PRINT_ERR_MSG("Failed to generate from public DRBG");
        err = 1;
        goto cleanup;
    }
    PRINT_BUFFER("Public DRBG output (3-level hierarchy)", buf, sizeof(buf));

    PRINT_MSG("Three-level hierarchy test passed");

cleanup:
    EVP_RAND_CTX_free(public_ctx);
    EVP_RAND_CTX_free(primary_ctx);
    EVP_RAND_CTX_free(seed_ctx);
    EVP_RAND_free(ctr_drbg);
    EVP_RAND_free(seed_src);
    return err;
}

/**
 * Test that SEED-SRC remains usable after a child DRBG instantiates from it.
 * Instantiates two child DRBGs from the same SEED-SRC parent and verifies
 * both can generate random bytes.
 */
static int test_seed_src_multi_child(OSSL_LIB_CTX *libCtx, const char *propq)
{
    int err = 0;
    EVP_RAND *seed_src = NULL;
    EVP_RAND *ctr_drbg = NULL;
    EVP_RAND_CTX *seed_ctx = NULL;
    EVP_RAND_CTX *child1_ctx = NULL;
    EVP_RAND_CTX *child2_ctx = NULL;
    unsigned char buf[32];
    OSSL_PARAM params[2];

    PRINT_MSG("Testing SEED-SRC survives multiple child DRBG instantiations");

    seed_src = EVP_RAND_fetch(libCtx, "SEED-SRC", propq);
    ctr_drbg = EVP_RAND_fetch(libCtx, "CTR-DRBG", propq);
    if (seed_src == NULL || ctr_drbg == NULL) {
        PRINT_ERR_MSG("Failed to fetch RAND algorithms");
        err = 1;
        goto cleanup;
    }

    seed_ctx = EVP_RAND_CTX_new(seed_src, NULL);
    if (seed_ctx == NULL) {
        PRINT_ERR_MSG("Failed to create SEED-SRC context");
        err = 1;
        goto cleanup;
    }
    if (EVP_RAND_instantiate(seed_ctx, 0, 0, NULL, 0, NULL) != 1) {
        PRINT_ERR_MSG("Failed to instantiate SEED-SRC");
        err = 1;
        goto cleanup;
    }

    /* First child DRBG: instantiate from SEED-SRC (calls get_seed + clear_seed) */
    child1_ctx = EVP_RAND_CTX_new(ctr_drbg, seed_ctx);
    if (child1_ctx == NULL) {
        PRINT_ERR_MSG("Failed to create first child DRBG");
        err = 1;
        goto cleanup;
    }
    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_DRBG_PARAM_CIPHER,
                                                  (char*)"AES-256-CTR", 0);
    params[1] = OSSL_PARAM_construct_end();
    if (EVP_RAND_CTX_set_params(child1_ctx, params) != 1) {
        PRINT_ERR_MSG("Failed to set first child DRBG params");
        err = 1;
        goto cleanup;
    }
    if (EVP_RAND_instantiate(child1_ctx, 256, 0, NULL, 0, NULL) != 1) {
        PRINT_ERR_MSG("Failed to instantiate first child DRBG");
        err = 1;
        goto cleanup;
    }
    PRINT_MSG("First child DRBG instantiated OK");

    /* Second child DRBG: instantiate from same SEED-SRC.
     * Before the fix, this fails because clear_seed set SEED-SRC to
     * UNINITIALISED and get_seed returns 0. */
    child2_ctx = EVP_RAND_CTX_new(ctr_drbg, seed_ctx);
    if (child2_ctx == NULL) {
        PRINT_ERR_MSG("Failed to create second child DRBG");
        err = 1;
        goto cleanup;
    }
    if (EVP_RAND_CTX_set_params(child2_ctx, params) != 1) {
        PRINT_ERR_MSG("Failed to set second child DRBG params");
        err = 1;
        goto cleanup;
    }
    if (EVP_RAND_instantiate(child2_ctx, 256, 0, NULL, 0, NULL) != 1) {
        PRINT_ERR_MSG("Failed to instantiate second child DRBG from same "
                      "SEED-SRC");
        err = 1;
        goto cleanup;
    }
    PRINT_MSG("Second child DRBG instantiated OK");

    /* Verify both children can generate */
    if (EVP_RAND_generate(child1_ctx, buf, sizeof(buf), 256, 0, NULL, 0) != 1) {
        PRINT_ERR_MSG("Failed to generate from first child DRBG");
        err = 1;
        goto cleanup;
    }
    if (EVP_RAND_generate(child2_ctx, buf, sizeof(buf), 256, 0, NULL, 0) != 1) {
        PRINT_ERR_MSG("Failed to generate from second child DRBG");
        err = 1;
        goto cleanup;
    }
    PRINT_MSG("Both child DRBGs generate OK after shared SEED-SRC parent");

cleanup:
    EVP_RAND_CTX_free(child2_ctx);
    EVP_RAND_CTX_free(child1_ctx);
    EVP_RAND_CTX_free(seed_ctx);
    EVP_RAND_free(ctr_drbg);
    EVP_RAND_free(seed_src);
    return err;
}

/**
 * Main test entry point - runs tests with OpenSSL default provider and wolfProvider.
 */
int test_rand_seed(void *data)
{
    int err = 0;

    (void)data;

    PRINT_MSG("=== Testing DRBG SEED-SRC hierarchy with OpenSSL default provider ===");

    /* Test with OpenSSL default provider */
    err = test_seed_src_basic(osslLibCtx, NULL);
    if (err == 0) {
        err = test_seed_src_parent_child(osslLibCtx, NULL);
    }
    if (err == 0) {
        err = test_seed_src_hash_drbg(osslLibCtx, NULL);
    }
    if (err == 0) {
        err = test_seed_src_three_level(osslLibCtx, NULL);
    }

    if (err == 0) {
        PRINT_MSG("=== OpenSSL default provider tests passed ===");
    }

    /* Test with wolfProvider */
    if (err == 0) {
        PRINT_MSG("=== Testing DRBG SEED-SRC hierarchy with wolfProvider ===");
        err = test_seed_src_basic(wpLibCtx, NULL);
    }
    if (err == 0) {
        err = test_seed_src_parent_child(wpLibCtx, NULL);
    }
    if (err == 0) {
        err = test_seed_src_hash_drbg(wpLibCtx, NULL);
    }
    if (err == 0) {
        err = test_seed_src_three_level(wpLibCtx, NULL);
    }
    if (err == 0) {
        err = test_seed_src_multi_child(wpLibCtx, NULL);
    }

    if (err == 0) {
        PRINT_MSG("=== All DRBG SEED-SRC hierarchy tests passed ===");
    }

    return err;
}

/**
 * Test DRBG reseed and verify_zeroization - Validates #169, #170.
 *
 * Creates SEED-SRC -> CTR-DRBG hierarchy, generates bytes, reseeds,
 * generates more bytes (verifying they differ), then uninstantiates
 * and calls verify_zeroization.
 */
static int test_drbg_reseed_helper(OSSL_LIB_CTX *libCtx, const char *propq)
{
    int err = 0;
    EVP_RAND *seed_src = NULL;
    EVP_RAND *ctr_drbg = NULL;
    EVP_RAND_CTX *seed_ctx = NULL;
    EVP_RAND_CTX *drbg_ctx = NULL;
    unsigned char buf1[32];
    unsigned char buf2[32];

    PRINT_MSG("Testing DRBG reseed and verify_zeroization");

    seed_src = EVP_RAND_fetch(libCtx, "SEED-SRC", propq);
    if (seed_src == NULL) {
        PRINT_ERR_MSG("Failed to fetch SEED-SRC");
        err = 1;
        goto cleanup;
    }

    seed_ctx = EVP_RAND_CTX_new(seed_src, NULL);
    if (seed_ctx == NULL) {
        PRINT_ERR_MSG("Failed to create SEED-SRC context");
        err = 1;
        goto cleanup;
    }

    if (EVP_RAND_instantiate(seed_ctx, 0, 0, NULL, 0, NULL) != 1) {
        PRINT_ERR_MSG("Failed to instantiate SEED-SRC");
        err = 1;
        goto cleanup;
    }

    ctr_drbg = EVP_RAND_fetch(libCtx, "CTR-DRBG", propq);
    if (ctr_drbg == NULL) {
        PRINT_ERR_MSG("Failed to fetch CTR-DRBG");
        err = 1;
        goto cleanup;
    }

    drbg_ctx = EVP_RAND_CTX_new(ctr_drbg, seed_ctx);
    if (drbg_ctx == NULL) {
        PRINT_ERR_MSG("Failed to create CTR-DRBG context");
        err = 1;
        goto cleanup;
    }

    {
        OSSL_PARAM params[2];
        params[0] = OSSL_PARAM_construct_utf8_string(OSSL_DRBG_PARAM_CIPHER,
                                                     (char*)"AES-256-CTR", 0);
        params[1] = OSSL_PARAM_construct_end();
        if (EVP_RAND_CTX_set_params(drbg_ctx, params) != 1) {
            PRINT_ERR_MSG("Failed to set CTR-DRBG cipher param");
            err = 1;
            goto cleanup;
        }
    }

    if (EVP_RAND_instantiate(drbg_ctx, 256, 0, NULL, 0, NULL) != 1) {
        PRINT_ERR_MSG("Failed to instantiate CTR-DRBG");
        err = 1;
        goto cleanup;
    }

    /* Generate first block. */
    if (EVP_RAND_generate(drbg_ctx, buf1, sizeof(buf1), 256, 0,
                          NULL, 0) != 1) {
        PRINT_ERR_MSG("Failed first generate");
        err = 1;
        goto cleanup;
    }

    /* Reseed (exercises fix #169). */
    if (EVP_RAND_reseed(drbg_ctx, 0, NULL, 0, NULL, 0) != 1) {
        PRINT_ERR_MSG("EVP_RAND_reseed failed");
        err = 1;
        goto cleanup;
    }
    PRINT_MSG("DRBG reseed succeeded");

    /* Generate second block after reseed. */
    if (EVP_RAND_generate(drbg_ctx, buf2, sizeof(buf2), 256, 0,
                          NULL, 0) != 1) {
        PRINT_ERR_MSG("Failed second generate after reseed");
        err = 1;
        goto cleanup;
    }

    /* Buffers should differ (extremely high probability). */
    if (memcmp(buf1, buf2, sizeof(buf1)) == 0) {
        PRINT_ERR_MSG("Pre/post-reseed outputs are identical");
        err = 1;
        goto cleanup;
    }
    PRINT_MSG("Pre/post-reseed outputs differ as expected");

    /* Reseed with explicit entropy + addIn. */
    {
        unsigned char ent[32], add[16];
        memset(ent, 0xA5, sizeof(ent));
        memset(add, 0x5A, sizeof(add));
        if (EVP_RAND_reseed(drbg_ctx, 0, ent, sizeof(ent),
                            add, sizeof(add)) != 1) {
            PRINT_ERR_MSG("Reseed with entropy/addIn failed");
            err = 1;
            goto cleanup;
        }
        if (EVP_RAND_generate(drbg_ctx, buf1, sizeof(buf1), 256, 0, NULL, 0)
                != 1 || memcmp(buf1, buf2, sizeof(buf1)) == 0) {
            PRINT_ERR_MSG("Generate after entropy reseed failed/unchanged");
            err = 1;
            goto cleanup;
        }
    }

    /* Uninstantiate and verify zeroization (exercises fix #170). */
    if (EVP_RAND_uninstantiate(drbg_ctx) != 1) {
        PRINT_ERR_MSG("EVP_RAND_uninstantiate failed");
        err = 1;
        goto cleanup;
    }

    if (EVP_RAND_verify_zeroization(drbg_ctx) != 1) {
        PRINT_ERR_MSG("EVP_RAND_verify_zeroization failed");
        err = 1;
        goto cleanup;
    }
    PRINT_MSG("DRBG verify_zeroization succeeded");

cleanup:
    EVP_RAND_CTX_free(drbg_ctx);
    EVP_RAND_CTX_free(seed_ctx);
    EVP_RAND_free(ctr_drbg);
    EVP_RAND_free(seed_src);
    return err;
}

/**
 * Non-seccomp coverage for reference counting of the shared /dev/urandom fd and
 * wolfSSL seed callback: load wolfProvider into two library contexts, draw
 * entropy from both, unload the first, and confirm the survivor still gets
 * entropy via both the OpenSSL RAND path and the wolfSSL seed callback. The main
 * suite holds a wolfProvider reference throughout, so the fd is not closed here;
 * the seccomp T3 test covers the decrement-to-zero close path.
 */
int test_seed_src_refcount(void *data)
{
    int err = 0;
    const char *providerDir = wpUnitProviderDir;
    const char *providerName = wpUnitProviderName;
    OSSL_LIB_CTX *ctx1 = NULL;
    OSSL_LIB_CTX *ctx2 = NULL;
    OSSL_PROVIDER *provider1 = NULL;
    OSSL_PROVIDER *provider2 = NULL;
    EVP_RAND_CTX *rctx = NULL;
    unsigned char buf[32];
    WC_RNG rng;
    int rngInit = 0;

    (void)data;

    if (providerDir == NULL) {
        providerDir = ".libs";
    }
    if (providerName == NULL) {
        providerName = wolfprovider_id;
    }

    PRINT_MSG("Testing SEED-SRC shared urandom fd/callback refcount lifecycle");

    /* First provider context: forces wp_urandom_init (refcount increments). */
    ctx1 = OSSL_LIB_CTX_new();
    if (ctx1 == NULL) {
        PRINT_ERR_MSG("Failed to create first library context");
        err = 1;
        goto cleanup;
    }
    if (OSSL_PROVIDER_set_default_search_path(ctx1, providerDir) != 1) {
        PRINT_ERR_MSG("Failed to set search path for first context: %s",
                      providerDir);
        err = 1;
        goto cleanup;
    }
    provider1 = OSSL_PROVIDER_load(ctx1, providerName);
    if (provider1 == NULL) {
        PRINT_ERR_MSG("Failed to load provider %s into first context",
                      providerName);
        err = 1;
        goto cleanup;
    }
    if (RAND_bytes_ex(ctx1, buf, sizeof(buf), 0) != 1) {
        PRINT_ERR_MSG("First-context RAND_bytes_ex failed");
        err = 1;
        goto cleanup;
    }

    /* Second provider context: shares the fd/callback (refcount increments). */
    ctx2 = OSSL_LIB_CTX_new();
    if (ctx2 == NULL) {
        PRINT_ERR_MSG("Failed to create second library context");
        err = 1;
        goto cleanup;
    }
    if (OSSL_PROVIDER_set_default_search_path(ctx2, providerDir) != 1) {
        PRINT_ERR_MSG("Failed to set search path for second context: %s",
                      providerDir);
        err = 1;
        goto cleanup;
    }
    provider2 = OSSL_PROVIDER_load(ctx2, providerName);
    if (provider2 == NULL) {
        PRINT_ERR_MSG("Failed to load provider %s into second context",
                      providerName);
        err = 1;
        goto cleanup;
    }
    if (RAND_bytes_ex(ctx2, buf, sizeof(buf), 0) != 1) {
        PRINT_ERR_MSG("Second-context RAND_bytes_ex failed");
        err = 1;
        goto cleanup;
    }

    /* Unload the first context (one cleanup, one decrement). The second context
     * and the main suite still hold references, so the fd/callback must survive. */
    OSSL_PROVIDER_unload(provider1);
    provider1 = NULL;
    OSSL_LIB_CTX_free(ctx1);
    ctx1 = NULL;

    /* Survivor must still draw entropy; force a fresh seed pull so an fd wrongly
     * closed on the first teardown would surface here. */
    rctx = RAND_get0_public(ctx2);
    if (rctx == NULL) {
        PRINT_ERR_MSG("Survivor RAND_get0_public failed after first unload");
        err = 1;
        goto cleanup;
    }
    if (EVP_RAND_reseed(rctx, 0, NULL, 0, NULL, 0) != 1) {
        PRINT_ERR_MSG("Survivor EVP_RAND_reseed failed after first unload");
        err = 1;
        goto cleanup;
    }
    if (RAND_bytes_ex(ctx2, buf, sizeof(buf), 0) != 1) {
        PRINT_ERR_MSG("Survivor RAND_bytes_ex failed after first unload");
        err = 1;
        goto cleanup;
    }

    /* The wolfSSL seed callback must also still be registered for the survivor. */
    if (wc_InitRng(&rng) != 0) {
        PRINT_ERR_MSG("wc_InitRng failed after first unload");
        err = 1;
        goto cleanup;
    }
    rngInit = 1;
    if (wc_RNG_GenerateBlock(&rng, buf, sizeof(buf)) != 0) {
        PRINT_ERR_MSG("wc_RNG_GenerateBlock failed after first unload");
        err = 1;
        goto cleanup;
    }

    PRINT_MSG("Survivor context still produces entropy after first unload");

cleanup:
    if (rngInit) {
        wc_FreeRng(&rng);
    }
    /* Unload the second context too. The main suite's reference keeps the count
     * above zero, so the fd stays open for the remaining tests. */
    OSSL_PROVIDER_unload(provider2);
    OSSL_LIB_CTX_free(ctx2);
    OSSL_PROVIDER_unload(provider1);
    OSSL_LIB_CTX_free(ctx1);

    return err;
}

/**
 * Fresh-process worker for the SEED-SRC full teardown -> reload cycle. Runs
 * after a re-exec (see test_seed_src_reload) so the refcount starts at zero and
 * can be driven to zero and back: load reopens the shared fd and registers
 * wp_wolfssl_seed_cb; a full unload closes the fd and restores the seed callback
 * to wc_GenerateSeed (not NULL, which would yield DRBG_NO_SEED_CB); reload must
 * reopen and re-register.
 *
 * Returns 0 on success, non-zero on failure.
 */
int test_seed_src_reload_helper(void)
{
    int err = 0;
    const char *providerDir = wpUnitProviderDir;
    const char *providerName = wpUnitProviderName;
    OSSL_LIB_CTX *ctx1 = NULL;
    OSSL_LIB_CTX *ctx2 = NULL;
    OSSL_PROVIDER *provider1 = NULL;
    OSSL_PROVIDER *provider2 = NULL;
    unsigned char buf[32];
    WC_RNG rng;

    if (providerDir == NULL) {
        providerDir = ".libs";
    }
    if (providerName == NULL) {
        providerName = wolfprovider_id;
    }

    PRINT_MSG("Testing SEED-SRC teardown-to-zero then reload in fresh process");

    /*
     * Load wolfProvider into the first context. This is the first reference, so
     * wp_urandom_init lazily opens the shared /dev/urandom fd (refcount 0 -> 1)
     * and registers wp_wolfssl_seed_cb.
     */
    ctx1 = OSSL_LIB_CTX_new();
    if (ctx1 == NULL) {
        PRINT_ERR_MSG("Failed to create first library context");
        err = 1;
    }
    if (err == 0 &&
            OSSL_PROVIDER_set_default_search_path(ctx1, providerDir) != 1) {
        PRINT_ERR_MSG("Failed to set search path for first context: %s",
                      providerDir);
        err = 1;
    }
    if (err == 0) {
        provider1 = OSSL_PROVIDER_load(ctx1, providerName);
        if (provider1 == NULL) {
            PRINT_ERR_MSG("Failed to load provider %s into first context",
                          providerName);
            err = 1;
        }
    }

    /* Draw entropy so the shared fd is actually opened. */
    if (err == 0 && RAND_bytes_ex(ctx1, buf, sizeof(buf), 0) != 1) {
        PRINT_ERR_MSG("First-context RAND_bytes_ex failed");
        err = 1;
    }

    /* Fully unload: releases the last reference, so cleanup decrements to zero,
     * closes the fd, and restores the seed callback to wc_GenerateSeed. */
    if (provider1 != NULL) {
        OSSL_PROVIDER_unload(provider1);
        provider1 = NULL;
    }
    OSSL_LIB_CTX_free(ctx1);
    ctx1 = NULL;

    /* With the callback restored (not NULL), a direct wolfCrypt RNG must still
     * seed and generate; a NULL callback would surface as DRBG_NO_SEED_CB. */
    if (err == 0) {
        if (wc_InitRng(&rng) != 0) {
            PRINT_ERR_MSG("wc_InitRng failed after teardown to zero");
            err = 1;
        }
        else {
            if (wc_RNG_GenerateBlock(&rng, buf, sizeof(buf)) != 0) {
                PRINT_ERR_MSG(
                    "wc_RNG_GenerateBlock failed after teardown to zero");
                err = 1;
            }
            wc_FreeRng(&rng);
        }
    }

    /* Reload into a second context (refcount 0 -> 1): the fd must lazily reopen
     * and wp_wolfssl_seed_cb must re-register. */
    if (err == 0) {
        ctx2 = OSSL_LIB_CTX_new();
        if (ctx2 == NULL) {
            PRINT_ERR_MSG("Failed to create second library context");
            err = 1;
        }
    }
    if (err == 0 &&
            OSSL_PROVIDER_set_default_search_path(ctx2, providerDir) != 1) {
        PRINT_ERR_MSG("Failed to set search path for second context: %s",
                      providerDir);
        err = 1;
    }
    if (err == 0) {
        provider2 = OSSL_PROVIDER_load(ctx2, providerName);
        if (provider2 == NULL) {
            PRINT_ERR_MSG("Failed to load provider %s into second context",
                          providerName);
            err = 1;
        }
    }

    /* Entropy through the reopened fd must succeed. */
    if (err == 0 && RAND_bytes_ex(ctx2, buf, sizeof(buf), 0) != 1) {
        PRINT_ERR_MSG("Second-context RAND_bytes_ex failed after reload");
        err = 1;
    }

    /* The wolfSSL seed callback path must work after reload too. */
    if (err == 0) {
        if (wc_InitRng(&rng) != 0) {
            PRINT_ERR_MSG("wc_InitRng failed after reload");
            err = 1;
        }
        else {
            if (wc_RNG_GenerateBlock(&rng, buf, sizeof(buf)) != 0) {
                PRINT_ERR_MSG("wc_RNG_GenerateBlock failed after reload");
                err = 1;
            }
            wc_FreeRng(&rng);
        }
    }

    if (err == 0) {
        PRINT_MSG("SEED-SRC reload after full teardown succeeded");
    }

    OSSL_PROVIDER_unload(provider2);
    OSSL_LIB_CTX_free(ctx2);
    OSSL_PROVIDER_unload(provider1);
    OSSL_LIB_CTX_free(ctx1);

    return err;
}

/**
 * Non-seccomp coverage for the SEED-SRC shared fd/seed callback being fully torn
 * down (refcount to zero) and reloaded. The main suite always holds a
 * wolfProvider reference, so this re-execs a fresh unit.test as
 * --seed-src-reload-helper (refcount starts at zero) and passes iff that child
 * completes the teardown-then-reload sequence and exits 0.
 */
int test_seed_src_reload(void *data)
{
    const char *providerDir = wpUnitProviderDir;
    const char *providerName = wpUnitProviderName;
    char exePath[PATH_MAX];
    ssize_t exeLen;
    pid_t pid;
    int status;
    int err = 0;

    (void)data;

    if (providerDir == NULL) {
        providerDir = ".libs";
    }
    if (providerName == NULL) {
        providerName = wolfprovider_id;
    }

    PRINT_MSG("Testing SEED-SRC full teardown then reload via re-exec");

    /* This test re-execs the unit binary via /proc/self/exe to get a fresh,
     * zero-based refcount. On platforms without /proc/self/exe (non-Linux)
     * there is no portable way to re-exec, so skip rather than hard-fail. */
    exeLen = readlink("/proc/self/exe", exePath, sizeof(exePath) - 1);
    if (exeLen < 0 || exeLen >= (ssize_t)sizeof(exePath) - 1) {
        PRINT_MSG("SEED-SRC reload test skipped - /proc/self/exe unavailable");
        return 0;
    }
    exePath[exeLen] = '\0';

    pid = fork();
    if (pid == -1) {
        PRINT_ERR_MSG("fork() failed: %s", strerror(errno));
        return 1;
    }

    if (pid == 0) {
        execl(exePath, exePath, "--seed-src-reload-helper", providerDir,
            providerName, (char *)NULL);
        PRINT_ERR_MSG("execl reload helper failed: %s", strerror(errno));
        _exit(127);
    }

    if (waitpid(pid, &status, 0) == -1) {
        PRINT_ERR_MSG("waitpid(reload helper) failed: %s", strerror(errno));
        return 1;
    }

    if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
        PRINT_MSG("SEED-SRC reload helper passed");
    }
    else if (WIFEXITED(status)) {
        PRINT_ERR_MSG("SEED-SRC reload helper exited with status %d",
            WEXITSTATUS(status));
        err = 1;
    }
    else if (WIFSIGNALED(status)) {
        PRINT_ERR_MSG("SEED-SRC reload helper killed by signal %d",
            WTERMSIG(status));
        err = 1;
    }
    else {
        PRINT_ERR_MSG("SEED-SRC reload helper exited abnormally");
        err = 1;
    }

    return err;
}

#else /* !(WP_HAVE_SEED_SRC && WP_HAVE_RANDOM) */

int test_rand_seed(void *data)
{
    (void)data;
    PRINT_MSG("SEED-SRC test skipped - not enabled");
    PRINT_MSG("Enable with: ./configure --enable-seed-src");
    return 0;
}

int test_seed_src_refcount(void *data)
{
    (void)data;
    PRINT_MSG("SEED-SRC refcount lifecycle test skipped - not enabled");
    return 0;
}

int test_seed_src_reload(void *data)
{
    (void)data;
    PRINT_MSG("SEED-SRC reload lifecycle test skipped - not enabled");
    return 0;
}

#endif /* WP_HAVE_SEED_SRC && WP_HAVE_RANDOM */

int test_drbg_reseed(void *data)
{
    int err = 0;

    (void)data;

#if defined(WP_HAVE_SEED_SRC) && defined(WP_HAVE_RANDOM)
    PRINT_MSG("Test OpenSSL DRBG reseed/zeroization");
    err = test_drbg_reseed_helper(osslLibCtx, NULL);
    if (err == 0) {
        PRINT_MSG("Test wolfProvider DRBG reseed/zeroization");
        err = test_drbg_reseed_helper(wpLibCtx, NULL);
    }
#else
    PRINT_MSG("DRBG reseed test skipped - SEED-SRC not enabled");
#endif

    return err;
}

