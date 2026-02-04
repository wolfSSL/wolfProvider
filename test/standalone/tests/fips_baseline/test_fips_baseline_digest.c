/* test_fips_baseline_digest.c
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
 * Test that MD5 digest is unavailable in FIPS mode.
 *
 * @param libctx Library context with provider loaded
 * @param desc Description for logging
 * @return TEST_SUCCESS if MD5 is unavailable, TEST_FAILURE otherwise.
 */
static int test_md5_unavailable(OSSL_LIB_CTX *libctx, const char *desc)
{
    EVP_MD *md5 = NULL;
    int ret = TEST_FAILURE;

    TEST_INFO("  Testing with %s...", desc);

    md5 = EVP_MD_fetch(libctx, "MD5", NULL);

    if (md5 != NULL) {
        TEST_ERROR("    ✗ MD5 is available - FIPS restriction NOT enforced");
        EVP_MD_free(md5);
        ret = TEST_FAILURE;
    }
    else {
        TEST_INFO("    ✓ MD5 is unavailable - FIPS restriction enforced");
        ERR_clear_error();
        ret = TEST_SUCCESS;
    }

    return ret;
}

/**
 * Test MD5 restriction with both providers.
 *
 * @return TEST_SUCCESS if both providers properly restrict MD5, TEST_FAILURE otherwise.
 */
int test_md5_restriction(void)
{
    TEST_INFO("Testing MD5 restriction with both providers:");

    /* Test with wolfProvider */
    if (test_md5_unavailable(g_wolfprov_libctx, "wolfProvider") != TEST_SUCCESS) {
        TEST_ERROR("MD5 restriction test failed for wolfProvider");
        return TEST_FAILURE;
    }

    /* Test with default (baseline) provider */
    if (test_md5_unavailable(g_default_libctx, "default (baseline)") != TEST_SUCCESS) {
        TEST_ERROR("MD5 restriction test failed for default (baseline) provider");
        return TEST_FAILURE;
    }

    TEST_INFO("✓ Both providers properly restrict MD5");
    return TEST_SUCCESS;
}

