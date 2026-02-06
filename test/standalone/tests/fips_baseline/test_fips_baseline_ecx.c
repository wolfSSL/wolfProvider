/* test_fips_baseline_ecx.c
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
 * Test that a specific signature algorithm is unavailable.
 *
 * @param libctx Library context with provider loaded
 * @param sig_name Name of the signature algorithm to test
 * @param desc Description for logging
 * @return TEST_SUCCESS if signature algorithm is unavailable, TEST_FAILURE otherwise.
 */
static int test_signature_unavailable(OSSL_LIB_CTX *libctx, const char *sig_name,
                                       const char *desc)
{
    EVP_PKEY_CTX *pctx = NULL;
    int ret = TEST_FAILURE;

    TEST_INFO("    Testing %s with %s...", sig_name, desc);

    pctx = EVP_PKEY_CTX_new_from_name(libctx, sig_name, NULL);

    if (pctx != NULL) {
        TEST_ERROR("      ✗ %s is available - FIPS baseline restriction NOT enforced", sig_name);
        EVP_PKEY_CTX_free(pctx);
        ret = TEST_FAILURE;
    }
    else {
        TEST_INFO("      ✓ %s is unavailable - FIPS baseline restriction enforced", sig_name);
        ERR_clear_error();
        ret = TEST_SUCCESS;
    }

    return ret;
}

/**
 * Test Ed25519 signature algorithm restriction with both providers.
 *
 * @return TEST_SUCCESS if both providers properly restrict Ed25519, TEST_FAILURE otherwise.
 */
static int test_ed25519_restriction(void)
{
    TEST_INFO("  Testing Ed25519 signature restriction:");

    /* Test with wolfProvider */
    if (test_signature_unavailable(wpLibCtx, "ED25519", "wolfProvider") != TEST_SUCCESS) {
        TEST_ERROR("    Ed25519 restriction test failed for wolfProvider");
        return TEST_FAILURE;
    }

    /* Test with default (baseline) provider */
    if (test_signature_unavailable(osslLibCtx, "ED25519", "default (baseline)") != TEST_SUCCESS) {
        TEST_ERROR("    Ed25519 restriction test failed for default (baseline) provider");
        return TEST_FAILURE;
    }

    TEST_INFO("    ✓ Both providers properly restrict Ed25519");
    return TEST_SUCCESS;
}

/**
 * Test Ed448 signature algorithm restriction with both providers.
 *
 * @return TEST_SUCCESS if both providers properly restrict Ed448, TEST_FAILURE otherwise.
 */
static int test_ed448_restriction(void)
{
    TEST_INFO("  Testing Ed448 signature restriction:");

    /* Test with wolfProvider */
    if (test_signature_unavailable(wpLibCtx, "ED448", "wolfProvider") != TEST_SUCCESS) {
        TEST_ERROR("    Ed448 restriction test failed for wolfProvider");
        return TEST_FAILURE;
    }

    /* Test with default (baseline) provider */
    if (test_signature_unavailable(osslLibCtx, "ED448", "default (baseline)") != TEST_SUCCESS) {
        TEST_ERROR("    Ed448 restriction test failed for default (baseline) provider");
        return TEST_FAILURE;
    }

    TEST_INFO("    ✓ Both providers properly restrict Ed448");
    return TEST_SUCCESS;
}

/**
 * Test X25519 key exchange algorithm restriction with both providers.
 *
 * @return TEST_SUCCESS if both providers properly restrict X25519, TEST_FAILURE otherwise.
 */
static int test_x25519_restriction(void)
{
    TEST_INFO("  Testing X25519 key exchange restriction:");

    /* Test with wolfProvider */
    if (test_signature_unavailable(wpLibCtx, "X25519", "wolfProvider") != TEST_SUCCESS) {
        TEST_ERROR("    X25519 restriction test failed for wolfProvider");
        return TEST_FAILURE;
    }

    /* Test with default (baseline) provider */
    if (test_signature_unavailable(osslLibCtx, "X25519", "default (baseline)") != TEST_SUCCESS) {
        TEST_ERROR("    X25519 restriction test failed for default (baseline) provider");
        return TEST_FAILURE;
    }

    TEST_INFO("    ✓ Both providers properly restrict X25519");
    return TEST_SUCCESS;
}

/**
 * Test X448 key exchange algorithm restriction with both providers.
 *
 * @return TEST_SUCCESS if both providers properly restrict X448, TEST_FAILURE otherwise.
 */
static int test_x448_restriction(void)
{
    TEST_INFO("  Testing X448 key exchange restriction:");

    /* Test with wolfProvider */
    if (test_signature_unavailable(wpLibCtx, "X448", "wolfProvider") != TEST_SUCCESS) {
        TEST_ERROR("    X448 restriction test failed for wolfProvider");
        return TEST_FAILURE;
    }

    /* Test with default (baseline) provider */
    if (test_signature_unavailable(osslLibCtx, "X448", "default (baseline)") != TEST_SUCCESS) {
        TEST_ERROR("    X448 restriction test failed for default (baseline) provider");
        return TEST_FAILURE;
    }

    TEST_INFO("    ✓ Both providers properly restrict X448");
    return TEST_SUCCESS;
}

/**
 * Test all Edwards curve and X curve restrictions.
 *
 * @return TEST_SUCCESS if all ECX restrictions are properly enforced, TEST_FAILURE otherwise.
 */
int test_ecx_restrictions(void)
{
    TEST_INFO("Testing Edwards curve and X curve restrictions with both providers:");

    if (test_ed25519_restriction() != TEST_SUCCESS) {
        return TEST_FAILURE;
    }

    if (test_ed448_restriction() != TEST_SUCCESS) {
        return TEST_FAILURE;
    }

    if (test_x25519_restriction() != TEST_SUCCESS) {
        return TEST_FAILURE;
    }

    if (test_x448_restriction() != TEST_SUCCESS) {
        return TEST_FAILURE;
    }

    TEST_INFO("✓ All Edwards curve and X curve restrictions properly enforced");
    return TEST_SUCCESS;
}

