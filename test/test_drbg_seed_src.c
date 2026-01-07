/* test_drbg_seed_src.c
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

#ifdef WP_HAVE_SEED_SRC

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/core_names.h>

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
 * Main test entry point - runs tests with OpenSSL default provider and wolfProvider.
 */
int test_drbg_seed_src(void *data)
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
        PRINT_MSG("=== All DRBG SEED-SRC hierarchy tests passed ===");
    }

    return err;
}

#else /* !WP_HAVE_SEED_SRC */

int test_drbg_seed_src(void *data)
{
    (void)data;
    PRINT_MSG("SEED-SRC test skipped - not enabled");
    PRINT_MSG("Enable with: ./configure --enable-seed-src");
    return 0;
}

#endif /* WP_HAVE_SEED_SRC */

