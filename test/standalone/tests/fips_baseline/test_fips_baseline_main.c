/* test_fips_baseline.c
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

#ifdef WOLFPROV_USER_SETTINGS
#include <user_settings.h>
#endif
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/wc_port.h>

#include <openssl/provider.h>
#include <openssl/core_names.h>
#include <openssl/param_build.h>

#include <wolfprovider/settings.h>
#include <wolfprovider/wp_logging.h>

#include "test_fips_baseline.h"

/* Global provider handles */
OSSL_PROVIDER *g_default_prov = NULL;
OSSL_PROVIDER *g_wolfprov = NULL;

/* Global library contexts - one for each provider */
OSSL_LIB_CTX *osslLibCtx = NULL;
OSSL_LIB_CTX *wpLibCtx = NULL;

/**
 * Setup and verify both providers for FIPS baseline testing.
 * This function:
 * 1. Loads the "default" provider and verifies it's FIPS baseline patched
 * 2. Loads the "libwolfprov" provider and verifies it's in FIPS mode
 * 3. Creates library contexts for each provider
 *
 * Both providers are loaded so that each test can verify that the FIPS baseline
 * patched OpenSSL enforces the same restrictions as wolfProvider in FIPS mode.
 * This comparison confirms that the baseline patches accurately reflect
 * wolfProvider's FIPS behavior, giving users confidence that passing baseline
 * tests means their application will work with wolfProvider FIPS.
 *
 * @return TEST_SUCCESS if both providers are properly configured, TEST_FAILURE otherwise.
 */
int setup_and_verify_providers(void)
{
    OSSL_PARAM params[2];
    char name_buf[256] = {0};
    char *name_ptr = name_buf;

    TEST_INFO("========================================");
    TEST_INFO("Provider Setup and Verification");
    TEST_INFO("========================================");

    /* Step 1: Load and verify default provider */
    TEST_INFO("Step 1: Loading OpenSSL default provider...");
    g_default_prov = OSSL_PROVIDER_load(NULL, "default");
    if (g_default_prov == NULL) {
        TEST_ERROR("  ✗ Failed to load default provider");
        return TEST_FAILURE;
    }
    TEST_INFO("  ✓ Default provider loaded");

    /* Query default provider name */
    name_ptr = name_buf;
    params[0] = OSSL_PARAM_construct_utf8_ptr(OSSL_PROV_PARAM_NAME,
                                               &name_ptr, sizeof(name_buf));
    params[1] = OSSL_PARAM_construct_end();

    if (!OSSL_PROVIDER_get_params(g_default_prov, params)) {
        TEST_ERROR("  ✗ Failed to get default provider name");
        goto cleanup_fail;
    }

    TEST_INFO("  Provider name: '%s'", name_ptr);

    /* Verify FIPS baseline patch is applied */
    if (strstr(name_ptr, "wolfProvider FIPS Baseline") == NULL) {
        TEST_ERROR("  ✗ Default provider is NOT the FIPS baseline version");
        TEST_ERROR("    Expected name to contain: 'wolfProvider FIPS Baseline'");
        TEST_ERROR("    Actual name: %s", name_ptr);
        goto cleanup_fail;
    }
    TEST_INFO("  ✓ FIPS baseline patch confirmed");
    TEST_INFO("");

    /* Step 2: Load and verify wolfProvider */
    TEST_INFO("Step 2: Loading wolfProvider (libwolfprov)...");
    g_wolfprov = OSSL_PROVIDER_load(NULL, "libwolfprov");
    if (g_wolfprov == NULL) {
        TEST_ERROR("  ✗ Failed to load libwolfprov provider");
        goto cleanup_fail;
    }
    TEST_INFO("  ✓ wolfProvider loaded");

    /* Query wolfProvider name */
    name_ptr = name_buf;
    params[0] = OSSL_PARAM_construct_utf8_ptr(OSSL_PROV_PARAM_NAME,
                                               &name_ptr, sizeof(name_buf));
    params[1] = OSSL_PARAM_construct_end();

    if (!OSSL_PROVIDER_get_params(g_wolfprov, params)) {
        TEST_ERROR("  ✗ Failed to get libwolfprov provider name");
        goto cleanup_fail;
    }

    TEST_INFO("  Provider name: '%s'", name_ptr);

    /* Verify wolfProvider is in FIPS mode */
    if (strstr(name_ptr, "FIPS") == NULL) {
        TEST_ERROR("  ✗ wolfProvider is NOT in FIPS mode");
        TEST_ERROR("    Expected name to contain: 'FIPS'");
        TEST_ERROR("    Actual name: %s", name_ptr);
        goto cleanup_fail;
    }
    TEST_INFO("  ✓ wolfProvider FIPS mode confirmed");

    /* Step 3: Create library contexts for each provider */
    TEST_INFO("Step 3: Creating library contexts for each provider...");

    osslLibCtx = OSSL_LIB_CTX_new();
    if (osslLibCtx == NULL) {
        TEST_ERROR("  ✗ Failed to create library context for default provider");
        goto cleanup_fail;
    }
    if (!OSSL_PROVIDER_add_builtin(osslLibCtx, "default",
                                    OSSL_PROVIDER_get_params(g_default_prov, NULL) ? NULL : NULL)) {
        /* Note: This is a simplified approach - we're just creating a new libctx */
    }
    /* Load default provider into its context */
    OSSL_PROVIDER *default_in_ctx = OSSL_PROVIDER_load(osslLibCtx, "default");
    if (default_in_ctx == NULL) {
        TEST_ERROR("  ✗ Failed to load default provider into its context");
        goto cleanup_fail;
    }
    TEST_INFO("  ✓ Default provider library context created");

    wpLibCtx = OSSL_LIB_CTX_new();
    if (wpLibCtx == NULL) {
        TEST_ERROR("  ✗ Failed to create library context for wolfProvider");
        goto cleanup_fail;
    }
    /* Load wolfProvider into its context */
    OSSL_PROVIDER *wolfprov_in_ctx = OSSL_PROVIDER_load(wpLibCtx, "libwolfprov");
    if (wolfprov_in_ctx == NULL) {
        TEST_ERROR("  ✗ Failed to load wolfProvider into its context");
        goto cleanup_fail;
    }
    TEST_INFO("  ✓ wolfProvider library context created");
    TEST_INFO("");

    TEST_INFO("========================================");
    TEST_INFO("Both providers loaded successfully");
    TEST_INFO("  • default: FIPS baseline patched OpenSSL");
    TEST_INFO("  • libwolfprov: wolfProvider (FIPS mode)");
    TEST_INFO("Library contexts ready for testing");
    TEST_INFO("========================================");
    TEST_INFO("");

    return TEST_SUCCESS;

cleanup_fail:
    cleanup_providers();
    return TEST_FAILURE;
}

/**
 * Cleanup and unload both providers.
 */
void cleanup_providers(void)
{
    if (osslLibCtx != NULL) {
        OSSL_LIB_CTX_free(osslLibCtx);
        osslLibCtx = NULL;
    }
    if (wpLibCtx != NULL) {
        OSSL_LIB_CTX_free(wpLibCtx);
        wpLibCtx = NULL;
    }
    if (g_default_prov != NULL) {
        OSSL_PROVIDER_unload(g_default_prov);
        g_default_prov = NULL;
    }
    if (g_wolfprov != NULL) {
        OSSL_PROVIDER_unload(g_wolfprov);
        g_wolfprov = NULL;
    }
}

int main(int argc, char *argv[])
{
    const char *fips_version = "unknown";

    /* Parse FIPS version from command line */
    if (argc > 1) {
        fips_version = argv[1];
    }
    else {
        TEST_INFO("Usage: %s <fips_version>", argv[0]);
        TEST_INFO("  fips_version: FIPS module version (e.g., '5.3.0', '2.0.0', or 'none')");
        TEST_INFO("Proceeding with version: unknown");
    }

    TEST_INFO("========================================");
    TEST_INFO("FIPS Baseline Test");
    TEST_INFO("========================================");
    TEST_INFO("FIPS Version: %s", fips_version);
    TEST_INFO("");

    /* Setup and verify both providers */
    if (setup_and_verify_providers() != TEST_SUCCESS) {
        TEST_ERROR("========================================");
        TEST_ERROR("Test ABORTED - Provider setup failed");
        TEST_ERROR("========================================");
        TEST_ERROR("Build OpenSSL with the baseline patch:");
        TEST_ERROR("  ./scripts/build-wolfprovider.sh --enable-fips-baseline --enable-fips");
        return TEST_FAILURE;
    }

#ifndef HAVE_FIPS
    TEST_INFO("========================================");
    TEST_INFO("Test SKIPPED - Not built with FIPS");
    TEST_INFO("========================================");
    TEST_INFO("This test requires HAVE_FIPS to be defined.");
    TEST_INFO("Build wolfSSL with FIPS enabled to run this test.");
    TEST_INFO("Example: ./scripts/build-wolfprovider.sh --enable-fips-baseline --enable-fips");
    cleanup_providers();
    return TEST_SUCCESS;
#endif

    /* Test 0: Sanity check - verify a basic FIPS operation works */
    TEST_INFO("========================================");
    TEST_INFO("Test 0: FIPS Sanity Check (SHA-256)");
    TEST_INFO("========================================");
    TEST_INFO("Expected: SHA-256 should work in FIPS mode");
    TEST_INFO("");
    if (test_fips_sanity() != TEST_SUCCESS) {
        TEST_ERROR("TEST 0 FAILED");
        TEST_ERROR("========================================");
        cleanup_providers();
        return TEST_FAILURE;
    }
    TEST_INFO("TEST 0 PASSED");
    TEST_INFO("");

    /* Test 1: MD5 should be unavailable in FIPS mode */
    TEST_INFO("========================================");
    TEST_INFO("Test 1: MD5 Digest Restriction");
    TEST_INFO("========================================");
    TEST_INFO("Expected: MD5 should be unavailable in FIPS mode");
    TEST_INFO("");
    if (test_md5_restriction() != TEST_SUCCESS) {
        TEST_ERROR("TEST 1 FAILED");
        TEST_ERROR("========================================");
        cleanup_providers();
        return TEST_FAILURE;
    }
    TEST_INFO("TEST 1 PASSED");
    TEST_INFO("");

    /* Test 2: Cipher restrictions (DES, 3DES, ChaCha20, ChaCha20-Poly1305) */
    TEST_INFO("========================================");
    TEST_INFO("Test 2: Cipher Restrictions");
    TEST_INFO("========================================");
    TEST_INFO("Expected: DES, 3DES, ChaCha20, ChaCha20-Poly1305 unavailable");
    TEST_INFO("");
    if (test_cipher_restrictions() != TEST_SUCCESS) {
        TEST_ERROR("TEST 2 FAILED");
        TEST_ERROR("========================================");
        cleanup_providers();
        return TEST_FAILURE;
    }
    TEST_INFO("TEST 2 PASSED");
    TEST_INFO("");

    /* Test 3: Edwards curve and X curve restrictions */
    TEST_INFO("========================================");
    TEST_INFO("Test 3: Edwards Curve and X Curve Restrictions");
    TEST_INFO("========================================");
    TEST_INFO("Expected: Ed25519, Ed448, X25519, X448 unavailable");
    TEST_INFO("");
    if (test_ecx_restrictions() != TEST_SUCCESS) {
        TEST_ERROR("TEST 3 FAILED");
        TEST_ERROR("========================================");
        cleanup_providers();
        return TEST_FAILURE;
    }
    TEST_INFO("TEST 3 PASSED");
    TEST_INFO("");

    /* Test 4: Comprehensive RSA tests (keygen + signatures) */
    TEST_INFO("========================================");
    TEST_INFO("Test 4: RSA FIPS Restrictions");
    TEST_INFO("========================================");
    TEST_INFO("Expected: 1024-bit keygen fails, 2048-bit succeeds");
    TEST_INFO("Expected: SHA1 signing fails, SHA256 signing/verify works");
    TEST_INFO("");
    if (test_rsa_restriction() != TEST_SUCCESS) {
        TEST_ERROR("TEST 4 FAILED");
        TEST_ERROR("========================================");
        cleanup_providers();
        return TEST_FAILURE;
    }
    TEST_INFO("TEST 4 PASSED");
    TEST_INFO("");

    /* Test 5: ECDSA key size restrictions */
    TEST_INFO("========================================");
    TEST_INFO("Test 5: ECDSA Key Size Restrictions");
    TEST_INFO("========================================");
    TEST_INFO("Expected: P-192 keygen/signing blocked (< 112-bit strength)");
    TEST_INFO("Expected: P-256 keygen/signing works (>= 112-bit strength)");
    TEST_INFO("");
    if (test_ecdsa_key_size_restrictions() != TEST_SUCCESS) {
        TEST_ERROR("TEST 5 FAILED");
        TEST_ERROR("========================================");
        cleanup_providers();
        return TEST_FAILURE;
    }
    TEST_INFO("TEST 5 PASSED");
    TEST_INFO("");

    /* Test 6: ECDH restrictions */
    TEST_INFO("========================================");
    TEST_INFO("Test 6: ECDH Restrictions");
    TEST_INFO("========================================");
    TEST_INFO("Expected: P-192 ECDH blocked (< 112-bit strength)");
    TEST_INFO("Expected: P-256 ECDH allowed (128-bit strength)");
    TEST_INFO("");
    if (test_ecdh_restrictions() != TEST_SUCCESS) {
        TEST_ERROR("TEST 6 FAILED");
        TEST_ERROR("========================================");
        cleanup_providers();
        return TEST_FAILURE;
    }
    TEST_INFO("TEST 6 PASSED");
    TEST_INFO("");

    /* Test 7: DH restrictions */
    TEST_INFO("========================================");
    TEST_INFO("Test 7: DH Restrictions");
    TEST_INFO("========================================");
    TEST_INFO("Expected: MODP groups blocked, FFDHE groups allowed");
    TEST_INFO("Expected: < 2048-bit custom params blocked");
    TEST_INFO("");
    if (test_dh_restrictions() != TEST_SUCCESS) {
        TEST_ERROR("TEST 7 FAILED");
        TEST_ERROR("========================================");
        cleanup_providers();
        return TEST_FAILURE;
    }
    TEST_INFO("TEST 7 PASSED");
    TEST_INFO("");

    /* Test 8: HMAC key strength restrictions */
    TEST_INFO("========================================");
    TEST_INFO("Test 8: HMAC Key Strength Restrictions");
    TEST_INFO("========================================");
    TEST_INFO("Expected: Both providers allow short HMAC keys (implementation detail)");
    TEST_INFO("Expected: >= 112-bit keys work correctly");
    TEST_INFO("");
    if (test_hmac_key_restrictions() != TEST_SUCCESS) {
        TEST_ERROR("TEST 8 FAILED");
        TEST_ERROR("========================================");
        cleanup_providers();
        return TEST_FAILURE;
    }
    TEST_INFO("TEST 8 PASSED");
    TEST_INFO("");

    /* Test 9: PBKDF2 password strength restrictions */
    TEST_INFO("========================================");
    TEST_INFO("Test 9: PBKDF2 Restrictions");
    TEST_INFO("========================================");
    TEST_INFO("Expected: < 112-bit passwords blocked, >= 112-bit allowed");
    TEST_INFO("Note: Salt length and iteration count not enforced by wolfCrypt FIPS");
    TEST_INFO("");
    if (test_pbkdf2_restrictions() != TEST_SUCCESS) {
        TEST_ERROR("TEST 9 FAILED");
        TEST_ERROR("========================================");
        cleanup_providers();
        return TEST_FAILURE;
    }
    TEST_INFO("TEST 9 PASSED");
    TEST_INFO("");

    /* Summary */
    TEST_INFO("========================================");
    TEST_INFO("Test Summary");
    TEST_INFO("========================================");
    TEST_INFO("Providers tested:");
    TEST_INFO("  • default (FIPS baseline patched OpenSSL)");
    TEST_INFO("  • libwolfprov (wolfProvider FIPS mode)");
    TEST_INFO("Total tests: 10");
    TEST_INFO("Passed: 10");
    TEST_INFO("Failed: 0");
    TEST_INFO("========================================");

    /* Cleanup providers */
    cleanup_providers();

    TEST_INFO("All tests PASSED");
    return TEST_SUCCESS;
}

