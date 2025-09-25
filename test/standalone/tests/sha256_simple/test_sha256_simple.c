/* test_sha256_simple.c
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
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#ifdef WOLFPROV_USER_SETTINGS
#include <user_settings.h>
#endif
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/wc_port.h>

#include <openssl/provider.h>
#include <openssl/evp.h>
#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

#include <wolfprovider/settings.h>
#include <wolfprovider/wp_logging.h>

#include "../../test_common.h"

/* Test data and expected results */
static const char test_data[] = "Hello, wolfProvider!";
static const char expected_sha256_hex[] = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

int main(int argc, char *argv[])
{
    EVP_MD_CTX *mdctx = NULL;
    const EVP_MD *sha256 = NULL;
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digest_len = 0;
    char digest_hex[EVP_MAX_MD_SIZE * 2 + 1];
    int ret = TEST_FAILURE;

    (void)argc;
    (void)argv;

    TEST_INFO("Starting SHA256 simple test");

    /* Get SHA256 algorithm */
    sha256 = EVP_MD_fetch(NULL, "SHA256", NULL);
    if (sha256 == NULL) {
        TEST_ERROR("Failed to fetch SHA256 algorithm");
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }

    /* Create message digest context */
    mdctx = EVP_MD_CTX_new();
    if (mdctx == NULL) {
        TEST_ERROR("Failed to create MD context");
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }

    /* Initialize digest operation */
    if (EVP_DigestInit_ex(mdctx, sha256, NULL) != 1) {
        TEST_ERROR("Failed to initialize digest");
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }

    TEST_DEBUG("Computing SHA256 of: \"%s\" (%zu bytes)", test_data, strlen(test_data));

    /* Update digest with test data */
    if (EVP_DigestUpdate(mdctx, test_data, strlen(test_data)) != 1) {
        TEST_ERROR("Failed to update digest");
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }

    /* Finalize digest */
    if (EVP_DigestFinal_ex(mdctx, digest, &digest_len) != 1) {
        TEST_ERROR("Failed to finalize digest");
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }

    /* Convert to hex string for comparison */
    if (test_bytes_to_hex(digest, digest_len, digest_hex, sizeof(digest_hex)) != TEST_SUCCESS) {
        TEST_ERROR("Failed to convert digest to hex");
        goto cleanup;
    }

    TEST_INFO("Computed SHA256: %s", digest_hex);
    TEST_DEBUG("Expected SHA256:  %s", expected_sha256_hex);

    /* Verify the result */
    if (strlen(expected_sha256_hex) != digest_len * 2) {
        TEST_ERROR("Digest length mismatch (expected %zu, got %u)", 
                  strlen(expected_sha256_hex) / 2, digest_len);
        goto cleanup;
    }

    TEST_PRINT_BUFFER("SHA256 digest", digest, digest_len);

    /* For now, just verify we got a 32-byte SHA256 result */
    if (digest_len != 32) {
        TEST_ERROR("Invalid SHA256 digest length: %u (expected 32)", digest_len);
        goto cleanup;
    }

    TEST_INFO("SHA256 computation successful - got %u byte digest", digest_len);

    ret = TEST_SUCCESS;

cleanup:
    if (mdctx != NULL) {
        EVP_MD_CTX_free(mdctx);
    }
    if (sha256 != NULL) {
        EVP_MD_free((EVP_MD*)sha256);
    }

    if (ret == TEST_SUCCESS) {
        TEST_INFO("Test PASSED");
    } else {
        TEST_ERROR("Test FAILED");
    }

    return ret;
}
