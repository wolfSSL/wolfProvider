/* test_fips_baseline_ciphers.c
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

#include <stdio.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/err.h>

#include "test_fips_baseline.h"

/**
 * Test that a specific cipher is unavailable.
 *
 * @param libctx Library context with provider loaded
 * @param cipher_name Name of the cipher to test
 * @param desc Description for logging
 * @return TEST_SUCCESS if cipher is unavailable, TEST_FAILURE otherwise.
 */
static int test_cipher_unavailable(OSSL_LIB_CTX *libctx, const char *cipher_name,
                                    const char *desc)
{
    EVP_CIPHER *cipher = NULL;
    int ret = TEST_FAILURE;

    TEST_INFO("    Testing %s with %s...", cipher_name, desc);

    cipher = EVP_CIPHER_fetch(libctx, cipher_name, NULL);

    if (cipher != NULL) {
        TEST_ERROR("      ✗ %s is available - FIPS baseline restriction NOT enforced", cipher_name);
        EVP_CIPHER_free(cipher);
        ret = TEST_FAILURE;
    }
    else {
        TEST_INFO("      ✓ %s is unavailable - FIPS baseline restriction enforced", cipher_name);
        ERR_clear_error();
        ret = TEST_SUCCESS;
    }

    return ret;
}

/**
 * Test DES cipher restriction with both providers.
 *
 * @return TEST_SUCCESS if both providers properly restrict DES, TEST_FAILURE otherwise.
 */
static int test_des_restriction(void)
{
    TEST_INFO("  Testing DES cipher restriction:");

    /* Test with wolfProvider */
    if (test_cipher_unavailable(g_wolfprov_libctx, "DES-CBC", "wolfProvider") != TEST_SUCCESS) {
        TEST_ERROR("    DES restriction test failed for wolfProvider");
        return TEST_FAILURE;
    }

    /* Test with default (baseline) provider */
    if (test_cipher_unavailable(g_default_libctx, "DES-CBC", "default (baseline)") != TEST_SUCCESS) {
        TEST_ERROR("    DES restriction test failed for default (baseline) provider");
        return TEST_FAILURE;
    }

    TEST_INFO("    ✓ Both providers properly restrict DES");
    return TEST_SUCCESS;
}

/**
 * Test 3DES cipher restriction with both providers.
 *
 * @return TEST_SUCCESS if both providers properly restrict 3DES, TEST_FAILURE otherwise.
 */
static int test_3des_restriction(void)
{
    TEST_INFO("  Testing 3DES cipher restriction:");

    /* Test with wolfProvider */
    if (test_cipher_unavailable(g_wolfprov_libctx, "DES-EDE3-CBC", "wolfProvider") != TEST_SUCCESS) {
        TEST_ERROR("    3DES restriction test failed for wolfProvider");
        return TEST_FAILURE;
    }

    /* Test with default (baseline) provider */
    if (test_cipher_unavailable(g_default_libctx, "DES-EDE3-CBC", "default (baseline)") != TEST_SUCCESS) {
        TEST_ERROR("    3DES restriction test failed for default (baseline) provider");
        return TEST_FAILURE;
    }

    TEST_INFO("    ✓ Both providers properly restrict 3DES");
    return TEST_SUCCESS;
}

/**
 * Test ChaCha20 cipher restriction with both providers.
 *
 * @return TEST_SUCCESS if both providers properly restrict ChaCha20, TEST_FAILURE otherwise.
 */
static int test_chacha20_restriction(void)
{
    TEST_INFO("  Testing ChaCha20 cipher restriction:");

    /* Test with wolfProvider */
    if (test_cipher_unavailable(g_wolfprov_libctx, "ChaCha20", "wolfProvider") != TEST_SUCCESS) {
        TEST_ERROR("    ChaCha20 restriction test failed for wolfProvider");
        return TEST_FAILURE;
    }

    /* Test with default (baseline) provider */
    if (test_cipher_unavailable(g_default_libctx, "ChaCha20", "default (baseline)") != TEST_SUCCESS) {
        TEST_ERROR("    ChaCha20 restriction test failed for default (baseline) provider");
        return TEST_FAILURE;
    }

    TEST_INFO("    ✓ Both providers properly restrict ChaCha20");
    return TEST_SUCCESS;
}

/**
 * Test ChaCha20-Poly1305 cipher restriction with both providers.
 *
 * @return TEST_SUCCESS if both providers properly restrict ChaCha20-Poly1305, TEST_FAILURE otherwise.
 */
static int test_chacha20_poly1305_restriction(void)
{
    TEST_INFO("  Testing ChaCha20-Poly1305 cipher restriction:");

    /* Test with wolfProvider */
    if (test_cipher_unavailable(g_wolfprov_libctx, "ChaCha20-Poly1305", "wolfProvider") != TEST_SUCCESS) {
        TEST_ERROR("    ChaCha20-Poly1305 restriction test failed for wolfProvider");
        return TEST_FAILURE;
    }

    /* Test with default (baseline) provider */
    if (test_cipher_unavailable(g_default_libctx, "ChaCha20-Poly1305", "default (baseline)") != TEST_SUCCESS) {
        TEST_ERROR("    ChaCha20-Poly1305 restriction test failed for default (baseline) provider");
        return TEST_FAILURE;
    }

    TEST_INFO("    ✓ Both providers properly restrict ChaCha20-Poly1305");
    return TEST_SUCCESS;
}

/**
 * Test all cipher restrictions.
 *
 * @return TEST_SUCCESS if all cipher restrictions are properly enforced, TEST_FAILURE otherwise.
 */
int test_cipher_restrictions(void)
{
    TEST_INFO("Testing cipher restrictions with both providers:");

    if (test_des_restriction() != TEST_SUCCESS) {
        return TEST_FAILURE;
    }

    if (test_3des_restriction() != TEST_SUCCESS) {
        return TEST_FAILURE;
    }

    if (test_chacha20_restriction() != TEST_SUCCESS) {
        return TEST_FAILURE;
    }

    if (test_chacha20_poly1305_restriction() != TEST_SUCCESS) {
        return TEST_FAILURE;
    }

    TEST_INFO("✓ All cipher restrictions properly enforced");
    return TEST_SUCCESS;
}

