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

/**
 * ECDH FIPS Baseline Tests
 *
 * Tests ECDH key exchange restrictions under FIPS:
 * - P-192 ECDH should be BLOCKED (< 112-bit security strength)
 * - P-256 ECDH should be ALLOWED (128-bit security strength)
 */

#include "test_fips_baseline.h"

/**
 * Helper: Generate EC key with specified curve
 * Returns 1 on success, 0 on failure
 */
static int generate_ec_key(OSSL_LIB_CTX *libctx, const char *curve_name,
                          EVP_PKEY **pkey_out)
{
    EVP_PKEY_CTX *kctx = NULL;
    EVP_PKEY *pkey = NULL;
    OSSL_PARAM params[2];
    char curve_buf[32];
    int ret = 0;

    kctx = EVP_PKEY_CTX_new_from_name(libctx, "EC", NULL);
    if (kctx == NULL || EVP_PKEY_keygen_init(kctx) <= 0)
        goto cleanup;

    snprintf(curve_buf, sizeof(curve_buf), "%s", curve_name);
    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME,
                                                  curve_buf, 0);
    params[1] = OSSL_PARAM_construct_end();

    if (EVP_PKEY_CTX_set_params(kctx, params) <= 0)
        goto cleanup;

    if (EVP_PKEY_keygen(kctx, &pkey) <= 0)
        goto cleanup;

    *pkey_out = pkey;
    pkey = NULL;
    ret = 1;

cleanup:
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(kctx);
    return ret;
}

/**
 * Helper: Perform ECDH key derivation between two keys
 * Returns 1 on success, 0 on failure
 */
static int perform_ecdh(OSSL_LIB_CTX *libctx, EVP_PKEY *priv_key,
                        EVP_PKEY *peer_pub_key, unsigned char *secret,
                        size_t *secret_len)
{
    EVP_PKEY_CTX *ctx = NULL;
    int ret = 0;

    /* Use libctx to ensure correct provider handles the derive operation */
    ctx = EVP_PKEY_CTX_new_from_pkey(libctx, priv_key, NULL);
    if (ctx == NULL) {
        ERR_clear_error();
        goto cleanup;
    }

    if (EVP_PKEY_derive_init(ctx) <= 0) {
        ERR_clear_error();
        goto cleanup;
    }

    if (EVP_PKEY_derive_set_peer(ctx, peer_pub_key) <= 0) {
        ERR_clear_error();
        goto cleanup;
    }

    /* First call to get the required buffer size */
    if (EVP_PKEY_derive(ctx, NULL, secret_len) <= 0) {
        ERR_clear_error();
        goto cleanup;
    }

    /* Actual derivation */
    if (EVP_PKEY_derive(ctx, secret, secret_len) <= 0) {
        ERR_clear_error();
        goto cleanup;
    }

    ret = 1;

cleanup:
    EVP_PKEY_CTX_free(ctx);
    return ret;
}

/**
 * Test ECDH with P-192 keys
 * This should be BLOCKED under FIPS (< 112-bit security strength)
 *
 * @param expected_blocked  1 if P-192 ECDH should be blocked, 0 if allowed
 * @return TEST_SUCCESS if behavior matches expectation, TEST_FAILURE otherwise
 */
static int test_ecdh_p192(OSSL_LIB_CTX *libctx, const char *provider,
                          int expected_blocked)
{
    EVP_PKEY *key1 = NULL;
    EVP_PKEY *key2 = NULL;
    unsigned char secret[256];
    size_t secret_len = sizeof(secret);
    int ret = TEST_FAILURE;
    int was_blocked = 0;

    /* First, try to generate P-192 keys
     * If keygen is blocked, ECDH is implicitly blocked */
    if (generate_ec_key(libctx, "prime192v1", &key1) != 1) {
        was_blocked = 1;
    } else if (generate_ec_key(libctx, "prime192v1", &key2) != 1) {
        was_blocked = 1;
    } else if (perform_ecdh(libctx, key1, key2, secret, &secret_len) != 1) {
        was_blocked = 1;
    }

    /* Enforce expected behavior */
    if (expected_blocked && !was_blocked) {
        TEST_ERROR("    [%s] P-192 ECDH should be BLOCKED but was ALLOWED", provider);
        goto cleanup;
    }
    if (!expected_blocked && was_blocked) {
        TEST_ERROR("    [%s] P-192 ECDH should be ALLOWED but was BLOCKED", provider);
        goto cleanup;
    }

    TEST_INFO("    [%s] P-192 ECDH correctly %s", provider,
              was_blocked ? "BLOCKED" : "ALLOWED");
    ret = TEST_SUCCESS;

cleanup:
    EVP_PKEY_free(key1);
    EVP_PKEY_free(key2);
    return ret;
}

/**
 * Test ECDH with P-256 keys
 * This should be ALLOWED under FIPS (128-bit security strength)
 */
static int test_ecdh_p256(OSSL_LIB_CTX *libctx, const char *provider)
{
    EVP_PKEY *key1 = NULL;
    EVP_PKEY *key2 = NULL;
    unsigned char secret1[256], secret2[256];
    size_t secret1_len = sizeof(secret1), secret2_len = sizeof(secret2);
    int ret = TEST_FAILURE;

    /* Generate two P-256 keys */
    if (generate_ec_key(libctx, "prime256v1", &key1) != 1) {
        TEST_ERROR("    [%s] Failed to generate P-256 key1", provider);
        goto cleanup;
    }

    if (generate_ec_key(libctx, "prime256v1", &key2) != 1) {
        TEST_ERROR("    [%s] Failed to generate P-256 key2", provider);
        goto cleanup;
    }

    /* Perform ECDH in both directions */
    if (perform_ecdh(libctx, key1, key2, secret1, &secret1_len) != 1) {
        TEST_ERROR("    [%s] P-256 ECDH derivation failed (key1 -> key2)", provider);
        goto cleanup;
    }

    if (perform_ecdh(libctx, key2, key1, secret2, &secret2_len) != 1) {
        TEST_ERROR("    [%s] P-256 ECDH derivation failed (key2 -> key1)", provider);
        goto cleanup;
    }

    /* Verify both parties derived the same secret */
    if (secret1_len != secret2_len ||
        memcmp(secret1, secret2, secret1_len) != 0) {
        TEST_ERROR("    [%s] P-256 ECDH secrets don't match!", provider);
        goto cleanup;
    }

    TEST_INFO("    [%s] ✓ P-256 ECDH works correctly (secret_len=%zu)", provider, secret1_len);
    ret = TEST_SUCCESS;

cleanup:
    EVP_PKEY_free(key1);
    EVP_PKEY_free(key2);
    return ret;
}

/**
 * Main ECDH restriction test
 */
int test_ecdh_restrictions(void)
{
    TEST_INFO("Testing ECDH FIPS baseline restrictions:");
    TEST_INFO("  - P-192 ECDH should be BLOCKED (< 112-bit security)");
    TEST_INFO("  - P-256 ECDH should be ALLOWED (128-bit security)");
    TEST_INFO("");

    /* Test 1: P-192 ECDH - should be BLOCKED */
    TEST_INFO("  Test 1: P-192 ECDH (should be blocked)");
    TEST_INFO("    Testing with wolfProvider...");
    if (test_ecdh_p192(wpLibCtx, "wolfProvider", 1) != TEST_SUCCESS)
        return TEST_FAILURE;

    TEST_INFO("    Testing with default (baseline)...");
    if (test_ecdh_p192(osslLibCtx, "default", 1) != TEST_SUCCESS)
        return TEST_FAILURE;

    TEST_INFO("    ✓ Both providers correctly block P-192 ECDH");
    TEST_INFO("");

    /* Test 2: P-256 ECDH - should be ALLOWED */
    TEST_INFO("  Test 2: P-256 ECDH (should be allowed)");
    TEST_INFO("    Testing with wolfProvider...");
    if (test_ecdh_p256(wpLibCtx, "wolfProvider") != TEST_SUCCESS)
        return TEST_FAILURE;

    TEST_INFO("    Testing with default (baseline)...");
    if (test_ecdh_p256(osslLibCtx, "default") != TEST_SUCCESS)
        return TEST_FAILURE;

    TEST_INFO("    ✓ Both providers correctly allow P-256 ECDH");
    TEST_INFO("");

    TEST_INFO("✓ All ECDH restrictions properly enforced");
    return TEST_SUCCESS;
}

