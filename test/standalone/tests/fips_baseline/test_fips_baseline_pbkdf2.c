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

#include <openssl/kdf.h>
#include <openssl/core_names.h>

/* Good password for tests (32 bytes = 256 bits) */
static const unsigned char good_password[32] = {
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
    0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
    0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20
};

/* Salt for tests (16 bytes = 128 bits) */
static const unsigned char test_salt[16] = {
    0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8,
    0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf, 0xb0
};

/**
 * Helper: Attempt PBKDF2 operation with specified parameters
 * Returns 1 on success, 0 on failure
 */
static int try_pbkdf2_full(OSSL_LIB_CTX *libctx, const char *digest_name,
                           const unsigned char *password, size_t password_len,
                           const unsigned char *salt, size_t salt_len,
                           unsigned int iterations)
{
    EVP_KDF *kdf = NULL;
    EVP_KDF_CTX *kctx = NULL;
    OSSL_PARAM params[5];
    unsigned char out[32];
    int ret = 0;

    kdf = EVP_KDF_fetch(libctx, "PBKDF2", NULL);
    if (kdf == NULL)
        goto cleanup;

    kctx = EVP_KDF_CTX_new(kdf);
    if (kctx == NULL)
        goto cleanup;

    params[0] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_PASSWORD,
                                                   (void *)password,
                                                   password_len);
    params[1] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT,
                                                   (void *)salt,
                                                   salt_len);
    params[2] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST,
                                                  (char *)digest_name, 0);
    params[3] = OSSL_PARAM_construct_uint(OSSL_KDF_PARAM_ITER, &iterations);
    params[4] = OSSL_PARAM_construct_end();

    if (EVP_KDF_derive(kctx, out, sizeof(out), params) != 1)
        goto cleanup;

    ret = 1;

cleanup:
    EVP_KDF_CTX_free(kctx);
    EVP_KDF_free(kdf);
    ERR_clear_error();
    return ret;
}

/* Convenience wrapper for password tests (uses standard salt and iterations) */
static int try_pbkdf2_password(OSSL_LIB_CTX *libctx, const char *digest_name,
                               const unsigned char *password, size_t password_len)
{
    return try_pbkdf2_full(libctx, digest_name, password, password_len,
                           test_salt, sizeof(test_salt), 10000);
}

/*
 * ============================================================================
 * PASSWORD LENGTH TESTS
 * ============================================================================
 */

/**
 * Test PBKDF2 with small password (< 112-bit / 14 bytes)
 */
static int test_pbkdf2_small_password(OSSL_LIB_CTX *libctx, const char *provider,
                                      int expected_blocked)
{
    /* 10-byte password = 80 bits (< 112-bit minimum) */
    static const unsigned char small_password[10] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a
    };
    int was_blocked = (try_pbkdf2_password(libctx, "SHA256", small_password,
                                           sizeof(small_password)) != 1);

    if (expected_blocked && !was_blocked) {
        TEST_ERROR("    [%s] 80-bit password should be BLOCKED but was ALLOWED",
                   provider);
        return TEST_FAILURE;
    }
    if (!expected_blocked && was_blocked) {
        TEST_ERROR("    [%s] 80-bit password should be ALLOWED but was BLOCKED",
                   provider);
        return TEST_FAILURE;
    }

    TEST_INFO("    [%s] 80-bit password correctly %s", provider,
              was_blocked ? "BLOCKED" : "ALLOWED");
    return TEST_SUCCESS;
}

/**
 * Test PBKDF2 with minimum acceptable password (112-bit / 14 bytes)
 */
static int test_pbkdf2_min_password(OSSL_LIB_CTX *libctx, const char *provider)
{
    /* 14-byte password = 112 bits (minimum acceptable) */
    static const unsigned char min_password[14] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e
    };

    if (try_pbkdf2_password(libctx, "SHA256", min_password,
                            sizeof(min_password)) != 1) {
        TEST_ERROR("    [%s] 112-bit password BLOCKED (should work)", provider);
        return TEST_FAILURE;
    }

    TEST_INFO("    [%s] ✓ 112-bit password works correctly", provider);
    return TEST_SUCCESS;
}

/**
 * Test PBKDF2 with adequate password (256-bit / 32 bytes)
 */
static int test_pbkdf2_good_password(OSSL_LIB_CTX *libctx, const char *provider)
{
    if (try_pbkdf2_password(libctx, "SHA256", good_password,
                            sizeof(good_password)) != 1) {
        TEST_ERROR("    [%s] 256-bit password BLOCKED (should work)", provider);
        return TEST_FAILURE;
    }

    TEST_INFO("    [%s] ✓ 256-bit password works correctly", provider);
    return TEST_SUCCESS;
}

/*
 * ============================================================================
 * MAIN TEST FUNCTION
 * ============================================================================
 */

int test_pbkdf2_restrictions(void)
{
    TEST_INFO("Testing PBKDF2 password length restrictions:");
    TEST_INFO("  (wolfCrypt FIPS enforces password >= 112 bits via HMAC_FIPS_MIN_KEY)");
    TEST_INFO("  Note: Salt length and iteration count are not enforced by wolfCrypt FIPS");

    /*
     * PASSWORD LENGTH TESTS
     * wolfCrypt FIPS enforces this via HMAC_FIPS_MIN_KEY (14 bytes = 112 bits)
     */
    TEST_INFO("");
    TEST_INFO("  Password Length Tests (>= 112 bits / 14 bytes):");

    /* Test 1: Small password (80-bit) - MUST be blocked by both providers */
    TEST_INFO("    Test 1: 80-bit password (< 112-bit minimum, should be BLOCKED)");
    TEST_INFO("      Testing with wolfProvider...");
    if (test_pbkdf2_small_password(wpLibCtx, "wolfProvider", 1) != TEST_SUCCESS)
        return TEST_FAILURE;
    TEST_INFO("      Testing with default (baseline)...");
    if (test_pbkdf2_small_password(osslLibCtx, "default", 1) != TEST_SUCCESS)
        return TEST_FAILURE;
    TEST_INFO("    Both providers correctly block 80-bit passwords");

    /* Test 2: Minimum acceptable password (112-bit) */
    TEST_INFO("    Test 2: 112-bit password (minimum acceptable)");
    TEST_INFO("      Testing with wolfProvider...");
    if (test_pbkdf2_min_password(wpLibCtx, "wolfProvider") != TEST_SUCCESS)
        return TEST_FAILURE;
    TEST_INFO("      Testing with default (baseline)...");
    if (test_pbkdf2_min_password(osslLibCtx, "default") != TEST_SUCCESS)
        return TEST_FAILURE;

    /* Test 3: Good password (256-bit) */
    TEST_INFO("    Test 3: 256-bit password (adequate)");
    TEST_INFO("      Testing with wolfProvider...");
    if (test_pbkdf2_good_password(wpLibCtx, "wolfProvider") != TEST_SUCCESS)
        return TEST_FAILURE;
    TEST_INFO("      Testing with default (baseline)...");
    if (test_pbkdf2_good_password(osslLibCtx, "default") != TEST_SUCCESS)
        return TEST_FAILURE;

    TEST_INFO("");
    TEST_INFO("PBKDF2 password length restrictions properly enforced");
    return TEST_SUCCESS;
}
