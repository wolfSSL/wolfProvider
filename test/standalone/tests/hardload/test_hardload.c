/* test_hardload.c
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
static const char test_data[] = "Hello, hardload test!";

int main(int argc, char *argv[])
{
    OSSL_LIB_CTX *libctx = NULL;
    OSSL_PROVIDER *default_prov = NULL;
    EVP_MD_CTX *mdctx = NULL;
    const EVP_MD *sha256 = NULL;
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digest_len = 0;
    char digest_hex[EVP_MAX_MD_SIZE * 2 + 1];
    const char *expected_provider_name = "default";
    int ret = TEST_FAILURE;
    const char *wpProviderName = NULL;
    OSSL_PARAM wpParams[] = {
        { OSSL_PROV_PARAM_NAME, OSSL_PARAM_UTF8_PTR, &wpProviderName, 0, 0 },
        { NULL, 0, NULL, 0, 0 }
    };

    /* Parse command line arguments */
    if (argc > 1) {
        expected_provider_name = argv[1];
    }

    TEST_INFO("Expected provider name: %s", expected_provider_name);

    /* Initialize OpenSSL */
    OPENSSL_init_ssl(OPENSSL_INIT_LOAD_CONFIG, NULL);

    /* Create library context */
    libctx = OSSL_LIB_CTX_new();
    if (libctx == NULL) {
        TEST_ERROR("Failed to create OpenSSL library context");
        goto cleanup;
    }

    /* Hard load the default provider - ignore environment variables */
    TEST_DEBUG("Hard loading default provider (ignoring environment)");
    default_prov = OSSL_PROVIDER_load(libctx, "default");
    if (default_prov == NULL) {
        TEST_ERROR("Failed to hard load default provider");
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }

    /* Verify the default provider is loaded */
    if (!OSSL_PROVIDER_available(libctx, "default")) {
        TEST_ERROR("Default provider is not available after loading");
        goto cleanup;
    }

    TEST_INFO("Default provider hard loaded successfully");

    /* Validate the provider name matches expected using OSSL_PROVIDER_get_params */
    if (OSSL_PROVIDER_get_params(default_prov, wpParams) != 1) {
        TEST_ERROR("Failed to get provider parameters");
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }

    if (wpProviderName == NULL) {
        TEST_ERROR("Provider name parameter returned NULL");
        goto cleanup;
    }

    TEST_INFO("Actual provider name: %s", wpProviderName);

    if (strcmp(wpProviderName, expected_provider_name) != 0) {
        TEST_ERROR("Provider name mismatch - Expected: '%s', Got: '%s'",
                   expected_provider_name, wpProviderName);
        goto cleanup;
    }

    TEST_INFO("Provider name validation passed: %s", wpProviderName);

    /* Get SHA256 algorithm from the explicitly loaded default provider */
    sha256 = EVP_MD_fetch(libctx, "SHA256", NULL);
    if (sha256 == NULL) {
        TEST_ERROR("Failed to fetch SHA256 algorithm from default provider");
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

    /* Convert to hex string for logging */
    if (test_bytes_to_hex(digest, digest_len, digest_hex, sizeof(digest_hex)) != TEST_SUCCESS) {
        TEST_ERROR("Failed to convert digest to hex");
        goto cleanup;
    }

    TEST_INFO("Computed SHA256: %s", digest_hex);

    /* Verify we got a 32-byte SHA256 result */
    if (digest_len != 32) {
        TEST_ERROR("Invalid SHA256 digest length: %u (expected 32)", digest_len);
        goto cleanup;
    }

    TEST_PRINT_BUFFER("SHA256 digest", digest, digest_len);

    TEST_INFO("SHA256 computation successful using hard loaded default provider - got %u byte digest", digest_len);

    /* Test passed */
    ret = TEST_SUCCESS;

cleanup:
    if (mdctx != NULL) {
        EVP_MD_CTX_free(mdctx);
    }
    if (sha256 != NULL) {
        EVP_MD_free((EVP_MD*)sha256);
    }
    if (default_prov != NULL) {
        OSSL_PROVIDER_unload(default_prov);
    }
    if (libctx != NULL) {
        OSSL_LIB_CTX_free(libctx);
    }

    if (ret == TEST_SUCCESS) {
        TEST_INFO("Test PASSED");
    } else {
        TEST_ERROR("Test FAILED");
    }

    return ret;
}
