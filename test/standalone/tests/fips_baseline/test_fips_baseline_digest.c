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
 * Test that a basic FIPS-approved operation (SHA-256 digest) works.
 * This provides a positive sanity check before running restriction tests.
 *
 * @param libctx Library context with provider loaded
 * @param desc Description for logging
 * @return TEST_SUCCESS if SHA-256 works, TEST_FAILURE otherwise.
 */
static int test_sha256_available(OSSL_LIB_CTX *libctx, const char *desc)
{
    EVP_MD *sha256 = NULL;
    EVP_MD_CTX *mdctx = NULL;
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digest_len = 0;
    const char *test_data = "FIPS sanity check test data";
    int ret = TEST_FAILURE;

    TEST_INFO("  Testing with %s...", desc);

    sha256 = EVP_MD_fetch(libctx, "SHA256", NULL);
    if (sha256 == NULL) {
        TEST_ERROR("    ✗ SHA-256 is unavailable (should be available in FIPS)");
        ERR_clear_error();
        goto cleanup;
    }

    mdctx = EVP_MD_CTX_new();
    if (mdctx == NULL) {
        TEST_ERROR("    ✗ Failed to create EVP_MD_CTX");
        goto cleanup;
    }

    if (EVP_DigestInit_ex(mdctx, sha256, NULL) != 1) {
        TEST_ERROR("    ✗ SHA-256 DigestInit failed");
        ERR_clear_error();
        goto cleanup;
    }

    if (EVP_DigestUpdate(mdctx, test_data, strlen(test_data)) != 1) {
        TEST_ERROR("    ✗ SHA-256 DigestUpdate failed");
        ERR_clear_error();
        goto cleanup;
    }

    if (EVP_DigestFinal_ex(mdctx, digest, &digest_len) != 1) {
        TEST_ERROR("    ✗ SHA-256 DigestFinal failed");
        ERR_clear_error();
        goto cleanup;
    }

    if (digest_len != 32) {
        TEST_ERROR("    ✗ SHA-256 digest length is %u (expected 32)", digest_len);
        goto cleanup;
    }

    TEST_INFO("    ✓ SHA-256 digest works correctly (len=%u)", digest_len);
    ret = TEST_SUCCESS;

cleanup:
    EVP_MD_CTX_free(mdctx);
    EVP_MD_free(sha256);
    return ret;
}

/**
 * FIPS sanity check: verify that SHA-256 (a FIPS-approved algorithm) works
 * with both providers before testing restrictions.
 *
 * @return TEST_SUCCESS if both providers support SHA-256, TEST_FAILURE otherwise.
 */
int test_fips_sanity(void)
{
    TEST_INFO("Testing FIPS sanity (SHA-256 should work with both providers):");

    /* Test with wolfProvider */
    if (test_sha256_available(wpLibCtx, "wolfProvider") != TEST_SUCCESS) {
        TEST_ERROR("FIPS sanity check failed for wolfProvider");
        return TEST_FAILURE;
    }

    /* Test with default (baseline) provider */
    if (test_sha256_available(osslLibCtx, "default (baseline)") != TEST_SUCCESS) {
        TEST_ERROR("FIPS sanity check failed for default (baseline) provider");
        return TEST_FAILURE;
    }

    TEST_INFO("✓ Both providers support SHA-256 (FIPS sanity check passed)");
    return TEST_SUCCESS;
}

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
    if (test_md5_unavailable(wpLibCtx, "wolfProvider") != TEST_SUCCESS) {
        TEST_ERROR("MD5 restriction test failed for wolfProvider");
        return TEST_FAILURE;
    }

    /* Test with default (baseline) provider */
    if (test_md5_unavailable(osslLibCtx, "default (baseline)") != TEST_SUCCESS) {
        TEST_ERROR("MD5 restriction test failed for default (baseline) provider");
        return TEST_FAILURE;
    }

    TEST_INFO("✓ Both providers properly restrict MD5");
    return TEST_SUCCESS;
}

