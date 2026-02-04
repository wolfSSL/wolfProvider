/*
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

#include "test_fips_baseline.h"

#include <openssl/dh.h>
#include <openssl/core_names.h>
#include <openssl/param_build.h>

/**
 * Helper: Generate DH key using a named group (e.g. "modp_2048", "ffdhe2048")
 * Returns 1 on success, 0 on failure
 */
static int try_dh_named_group(OSSL_LIB_CTX *libctx, const char *group_name)
{
    EVP_PKEY_CTX *pctx = NULL;
    EVP_PKEY *key = NULL;
    OSSL_PARAM params[2];
    int ret = 0;

    pctx = EVP_PKEY_CTX_new_from_name(libctx, "DH", NULL);
    if (pctx == NULL)
        goto cleanup;

    if (EVP_PKEY_keygen_init(pctx) <= 0)
        goto cleanup;

    /* Set group name via params */
    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME,
                                                  (char *)group_name, 0);
    params[1] = OSSL_PARAM_construct_end();
    if (EVP_PKEY_CTX_set_params(pctx, params) <= 0)
        goto cleanup;

    if (EVP_PKEY_keygen(pctx, &key) <= 0)
        goto cleanup;

    ret = 1;

cleanup:
    EVP_PKEY_free(key);
    EVP_PKEY_CTX_free(pctx);
    ERR_clear_error();
    return ret;
}

/**
 * Helper: Try custom DH paramgen + keygen with specified prime length
 * Returns 1 on success (keygen worked), 0 on failure (blocked)
 */
static int try_dh_custom_keygen(OSSL_LIB_CTX *libctx, int prime_bits)
{
    EVP_PKEY_CTX *pctx = NULL;
    EVP_PKEY_CTX *kctx = NULL;
    EVP_PKEY *params = NULL;
    EVP_PKEY *key = NULL;
    int ret = 0;

    /* Step 1: paramgen */
    pctx = EVP_PKEY_CTX_new_from_name(libctx, "DH", NULL);
    if (pctx == NULL)
        goto cleanup;

    if (EVP_PKEY_paramgen_init(pctx) <= 0)
        goto cleanup;

    if (EVP_PKEY_CTX_set_dh_paramgen_prime_len(pctx, prime_bits) <= 0)
        goto cleanup;

    if (EVP_PKEY_paramgen(pctx, &params) <= 0)
        goto cleanup;

    /* Step 2: keygen from params */
    kctx = EVP_PKEY_CTX_new_from_pkey(libctx, params, NULL);
    if (kctx == NULL)
        goto cleanup;

    if (EVP_PKEY_keygen_init(kctx) <= 0)
        goto cleanup;

    if (EVP_PKEY_keygen(kctx, &key) <= 0)
        goto cleanup;

    ret = 1;

cleanup:
    EVP_PKEY_free(key);
    EVP_PKEY_free(params);
    EVP_PKEY_CTX_free(kctx);
    EVP_PKEY_CTX_free(pctx);
    ERR_clear_error();
    return ret;
}

/*
 * ============================================================================
 * NEGATIVE TESTS - These operations MUST be blocked by both providers
 * ============================================================================
 */

/**
 * Test 1: MODP 2048 named group must be BLOCKED
 * wolfProvider doesn't support MODP groups (only FFDHE)
 * Baseline OpenSSL (with patch) also blocks MODP groups
 */
static int test_modp_2048_blocked(void)
{
    int wolf_blocked, baseline_blocked;

    TEST_INFO("  Test 1: modp_2048 named group (must be BLOCKED)");

    /* wolfProvider should block */
    wolf_blocked = (try_dh_named_group(g_wolfprov_libctx, "modp_2048") == 0);
    TEST_INFO("    [wolfProvider] modp_2048: %s",
              wolf_blocked ? "BLOCKED" : "ALLOWED");

    if (!wolf_blocked) {
        TEST_ERROR("    wolfProvider should block modp_2048");
        return TEST_FAILURE;
    }

    /* Baseline should also block (after patch) */
    baseline_blocked = (try_dh_named_group(g_default_libctx, "modp_2048") == 0);
    TEST_INFO("    [baseline] modp_2048: %s",
              baseline_blocked ? "BLOCKED" : "ALLOWED");

    if (!baseline_blocked) {
        TEST_ERROR("    Baseline should block modp_2048 (patch may not be applied)");
        return TEST_FAILURE;
    }

    TEST_INFO("    ✓ Both providers block modp_2048");
    return TEST_SUCCESS;
}

/**
 * Test 2: Small custom DH keygen (1024-bit) must be BLOCKED
 * Both providers should enforce 2048-bit minimum
 */
static int test_small_custom_dh_blocked(void)
{
    int wolf_blocked, baseline_blocked;

    TEST_INFO("  Test 2: 1024-bit custom DH keygen (must be BLOCKED)");

    /* wolfProvider should block */
    wolf_blocked = (try_dh_custom_keygen(g_wolfprov_libctx, 1024) == 0);
    TEST_INFO("    [wolfProvider] 1024-bit custom DH: %s",
              wolf_blocked ? "BLOCKED" : "ALLOWED");

    if (!wolf_blocked) {
        TEST_ERROR("    wolfProvider should block 1024-bit DH");
        return TEST_FAILURE;
    }

    /* Baseline should also block (after patch) */
    baseline_blocked = (try_dh_custom_keygen(g_default_libctx, 1024) == 0);
    TEST_INFO("    [baseline] 1024-bit custom DH: %s",
              baseline_blocked ? "BLOCKED" : "ALLOWED");

    if (!baseline_blocked) {
        TEST_ERROR("    Baseline should block 1024-bit DH (patch may not be applied)");
        return TEST_FAILURE;
    }

    TEST_INFO("    ✓ Both providers block 1024-bit custom DH");
    return TEST_SUCCESS;
}

/*
 * ============================================================================
 * POSITIVE TESTS - These operations MUST be allowed by both providers
 * ============================================================================
 */

/**
 * Test 3: FFDHE 2048 named group must be ALLOWED
 * This is the FIPS-approved DH group that should work
 */
static int test_ffdhe2048_allowed(void)
{
    int wolf_allowed, baseline_allowed;

    TEST_INFO("  Test 3: ffdhe2048 named group (must be ALLOWED)");

    /* wolfProvider should allow */
    wolf_allowed = (try_dh_named_group(g_wolfprov_libctx, "ffdhe2048") == 1);
    TEST_INFO("    [wolfProvider] ffdhe2048: %s",
              wolf_allowed ? "ALLOWED" : "BLOCKED");

    if (!wolf_allowed) {
        TEST_ERROR("    wolfProvider should allow ffdhe2048");
        return TEST_FAILURE;
    }

    /* Baseline should also allow */
    baseline_allowed = (try_dh_named_group(g_default_libctx, "ffdhe2048") == 1);
    TEST_INFO("    [baseline] ffdhe2048: %s",
              baseline_allowed ? "ALLOWED" : "BLOCKED");

    if (!baseline_allowed) {
        TEST_ERROR("    Baseline should allow ffdhe2048");
        return TEST_FAILURE;
    }

    TEST_INFO("    ✓ Both providers allow ffdhe2048");
    return TEST_SUCCESS;
}

/**
 * Main DH restrictions test
 *
 * Focus: Ensure restricted operations are blocked and allowed operations work
 * by both wolfProvider and baseline OpenSSL (with FIPS baseline patch)
 *
 * Restrictions tested:
 * 1. MODP named groups blocked (only FFDHE allowed)
 * 2. Custom DH < 2048-bit blocked
 * 3. FFDHE named groups allowed (ffdhe2048, etc.)
 */
int test_dh_restrictions(void)
{
    TEST_INFO("Testing DH FIPS baseline restrictions:");
    TEST_INFO("  - Only FFDHE named groups allowed (MODP blocked)");
    TEST_INFO("  - Minimum 2048-bit prime for custom params");
    TEST_INFO("");

    /* Test 1: MODP 2048 must be blocked */
    if (test_modp_2048_blocked() != TEST_SUCCESS)
        return TEST_FAILURE;

    TEST_INFO("");

    /* Test 2: Small custom DH must be blocked */
    if (test_small_custom_dh_blocked() != TEST_SUCCESS)
        return TEST_FAILURE;

    TEST_INFO("");

    /* Test 3: FFDHE 2048 must be allowed */
    if (test_ffdhe2048_allowed() != TEST_SUCCESS)
        return TEST_FAILURE;

    TEST_INFO("");
    TEST_INFO("✓ DH restrictions enforced equivalently by both providers");
    return TEST_SUCCESS;
}
