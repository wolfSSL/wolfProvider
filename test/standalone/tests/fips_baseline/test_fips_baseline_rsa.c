/* test_fips_baseline_rsa.c
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
#include <openssl/bio.h>
#include <openssl/pem.h>

#include "test_fips_baseline.h"

/* Test message for RSA signature tests */
static const char test_message[] = "FIPS baseline test message for RSA signatures";
static const size_t test_message_len = sizeof(test_message) - 1;

/*
 * Pre-computed RSA-SHA1 verification test artifacts.
 * Generated out-of-band using system OpenSSL (non-FIPS mode):
 *   openssl genrsa -out rsa_test_key.pem 2048
 *   openssl rsa -in rsa_test_key.pem -pubout -out rsa_test_pubkey.pem
 *   echo -n "FIPS baseline test message for RSA-SHA1 verification" > msg.txt
 *   openssl dgst -sha1 -sign rsa_test_key.pem -out sig.bin msg.txt
 *
 * SHA1 signing is BLOCKED in FIPS mode, but SHA1 verification is ALLOWED
 * for legacy compatibility.
 */

/* Message that was signed */
static const char sha1_verify_message[] =
    "FIPS baseline test message for RSA-SHA1 verification";
static const size_t sha1_verify_message_len = sizeof(sha1_verify_message) - 1;

/* RSA 2048-bit public key for verification */
static const char sha1_verify_pubkey_pem[] =
    "-----BEGIN PUBLIC KEY-----\n"
    "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAytq5LRSp3VRSWkDyDUWz\n"
    "R5oR3b8t9zfk9wHfk6OiuWtOrzs08fu71jId/xgL9n9tPNzbIXmjmwqHFrJoxkDg\n"
    "W5o5O9F7901fzaXKTFZ91pQF1NtGA0bGYA1LPM0nfuRvzLAwcwM/XoNzFlRh9FED\n"
    "sQUK7e+BEvHlLi1X/QtTrx1UcE3BGSxNYRfYjO9q94IAKPRXBnKT6Yyh9HO9mp/U\n"
    "0KBn/gz5SJUdxMAFyOi676ZdJdVx0Ms8xaft8F66talLtTl0C+fcJ9/hKCYYjbBq\n"
    "NsmjQYG9U9QDyAoBV+wBXqxAlsnxMLJYcVXRpV9GTnNVpaERpVjHebntlc5qUDnC\n"
    "UQIDAQAB\n"
    "-----END PUBLIC KEY-----\n";

/* Pre-computed RSA-SHA1 signature (256 bytes for 2048-bit key) */
static const unsigned char sha1_verify_signature[] = {
    0x0b, 0x49, 0x31, 0xc2, 0x41, 0x62, 0xcb, 0x47, 0x24, 0x4d, 0x46, 0x2d,
    0x31, 0x71, 0x37, 0xc3, 0x94, 0xc5, 0xee, 0x4a, 0x65, 0xbf, 0xac, 0x78,
    0xe7, 0x36, 0x61, 0xd8, 0xbf, 0x3d, 0x3b, 0x3c, 0x41, 0xab, 0x4a, 0x0e,
    0x46, 0xf9, 0xfc, 0x65, 0x41, 0xff, 0xa9, 0x30, 0xf1, 0x6f, 0xf6, 0xf4,
    0x64, 0x04, 0x6f, 0xdf, 0xcc, 0x7d, 0xb0, 0x01, 0xb6, 0xd2, 0xc2, 0x25,
    0x94, 0x63, 0x92, 0x7c, 0xf3, 0x20, 0x01, 0x4b, 0xbd, 0x21, 0xe9, 0x45,
    0xbf, 0xf8, 0x7c, 0x0f, 0xa0, 0x1a, 0x3b, 0x62, 0x88, 0x72, 0xbc, 0x68,
    0xf3, 0x44, 0x29, 0xa6, 0x6d, 0x50, 0x2c, 0xc7, 0xb6, 0x21, 0xdb, 0x7d,
    0xbb, 0xc2, 0x64, 0x3a, 0xc0, 0x3e, 0x1d, 0x7f, 0xb0, 0xd8, 0x9c, 0x14,
    0x8e, 0x80, 0x4b, 0x4f, 0x0f, 0x19, 0xc2, 0xe8, 0xe1, 0x83, 0xe4, 0x10,
    0xb5, 0x42, 0xbd, 0xa0, 0xe8, 0x60, 0x34, 0xdf, 0x0c, 0x2a, 0x54, 0x94,
    0xf8, 0x4f, 0xf2, 0x99, 0xc3, 0x02, 0xef, 0x13, 0x30, 0x09, 0x58, 0x61,
    0xfa, 0x12, 0xf0, 0x89, 0xc2, 0xa8, 0x75, 0x38, 0xd0, 0xe1, 0x38, 0x46,
    0xd8, 0xcf, 0xfe, 0x4e, 0xbb, 0xb1, 0x8c, 0x2f, 0x24, 0x13, 0x78, 0xc0,
    0x9d, 0x1c, 0x7a, 0x4d, 0xf9, 0xe2, 0x8a, 0xc5, 0xcf, 0x10, 0xb3, 0x6c,
    0x86, 0x1f, 0xec, 0x67, 0x63, 0x7d, 0x1f, 0x87, 0xc2, 0x64, 0x46, 0x00,
    0x3e, 0x19, 0x1e, 0x59, 0x54, 0x8b, 0x7a, 0x8f, 0xa2, 0x2d, 0x3c, 0xad,
    0x80, 0xc8, 0x9b, 0xd5, 0x49, 0x8c, 0x40, 0xa4, 0xf0, 0xb4, 0xbc, 0x7c,
    0x4f, 0x81, 0x3e, 0x06, 0x06, 0x6f, 0xf2, 0x7e, 0x25, 0xa1, 0xa1, 0xef,
    0xbc, 0xb3, 0x6c, 0x87, 0xcb, 0x63, 0xa1, 0x43, 0x81, 0x65, 0x7a, 0xf0,
    0xaf, 0xae, 0x0a, 0xfc, 0x7f, 0x3f, 0x72, 0x62, 0x5f, 0x62, 0x60, 0x8f,
    0x72, 0x04, 0x27, 0x2b
};
static const size_t sha1_verify_signature_len = sizeof(sha1_verify_signature);

/**
 * Test RSA-SHA1 verification with pre-computed signature.
 *
 * SHA1 signing is BLOCKED in FIPS mode, but SHA1 verification is ALLOWED
 * for legacy compatibility. This test verifies a signature that was created
 * out-of-band (using non-FIPS OpenSSL).
 *
 * @param libctx Library context with provider loaded
 * @param desc Description for logging
 * @param was_verified Output: 1 if verification succeeded, 0 if failed
 * @return TEST_SUCCESS if test ran correctly, TEST_FAILURE on error.
 */
static int test_rsa_sha1_verify(OSSL_LIB_CTX *libctx, const char *desc,
                                int *was_verified)
{
    EVP_MD_CTX *mdctx = NULL;
    EVP_PKEY *pubkey = NULL;
    BIO *bio = NULL;
    int ret = TEST_FAILURE;
    int rc;

    *was_verified = 0;

    TEST_INFO("    Testing RSA-SHA1 verification with %s...", desc);

    /* Load the public key from PEM */
    bio = BIO_new_mem_buf(sha1_verify_pubkey_pem, -1);
    if (bio == NULL) {
        TEST_ERROR("      Failed to create BIO for public key");
        goto cleanup;
    }

    pubkey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
    if (pubkey == NULL) {
        TEST_ERROR("      Failed to load RSA public key from PEM");
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }
    TEST_INFO("      Loaded RSA 2048-bit public key");

    /* Verify the pre-computed SHA1 signature */
    mdctx = EVP_MD_CTX_new();
    if (mdctx == NULL) {
        TEST_ERROR("      Failed to create EVP_MD_CTX");
        goto cleanup;
    }

    /* Use EVP_DigestVerifyInit_ex to explicitly specify the library context */
    rc = EVP_DigestVerifyInit_ex(mdctx, NULL, "SHA1", libctx, NULL, pubkey, NULL);
    if (rc != 1) {
        TEST_INFO("      RSA-SHA1 verify init FAILED");
        ERR_clear_error();
        ret = TEST_SUCCESS; /* Test ran correctly, verify just failed */
        goto cleanup;
    }

    rc = EVP_DigestVerify(mdctx, sha1_verify_signature, sha1_verify_signature_len,
                          (const unsigned char*)sha1_verify_message,
                          sha1_verify_message_len);
    if (rc != 1) {
        TEST_INFO("      RSA-SHA1 verification FAILED");
        ERR_clear_error();
        ret = TEST_SUCCESS; /* Test ran correctly */
        goto cleanup;
    }

    TEST_INFO("      RSA-SHA1 verification SUCCEEDED");
    *was_verified = 1;
    ret = TEST_SUCCESS;

cleanup:
    if (mdctx != NULL) {
        EVP_MD_CTX_free(mdctx);
    }
    if (pubkey != NULL) {
        EVP_PKEY_free(pubkey);
    }
    if (bio != NULL) {
        BIO_free(bio);
    }

    return ret;
}

/**
 * Test RSA key generation restrictions in FIPS mode.
 * Tests that 1024-bit fails and 2048-bit succeeds.
 *
 * @param libctx Library context with provider loaded
 * @param desc Description for logging
 * @param key_2048 Output parameter for generated 2048-bit key (caller must free)
 * @return TEST_SUCCESS if restrictions enforced correctly, TEST_FAILURE otherwise.
 */
static int test_rsa_keygen(OSSL_LIB_CTX *libctx, const char *desc, EVP_PKEY **key_2048)
{
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *key = NULL;
    int ret = TEST_FAILURE;
    int rc;

    if (key_2048 == NULL) {
        TEST_ERROR("    Invalid parameter: key_2048 is NULL");
        return TEST_FAILURE;
    }
    *key_2048 = NULL;

    TEST_INFO("    Testing RSA keygen with %s...", desc);

    /* Test 1: 1024-bit key generation should fail */
    TEST_INFO("      1024-bit key generation (should fail)...");

    ctx = EVP_PKEY_CTX_new_from_name(libctx, "RSA", NULL);
    if (ctx == NULL) {
        TEST_ERROR("        Failed to create EVP_PKEY_CTX for RSA");
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }

    rc = EVP_PKEY_keygen_init(ctx);
    if (rc != 1) {
        TEST_ERROR("        Failed to initialize RSA key generation");
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }

    rc = EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 1024);
    if (rc != 1) {
        TEST_INFO("        1024-bit key size rejected - PASS");
        ERR_clear_error();
    }
    else {
        rc = EVP_PKEY_keygen(ctx, &key);
        if (rc == 1 && key != NULL) {
            TEST_ERROR("        1024-bit key generated - FAIL (FIPS restriction not enforced)");
            EVP_PKEY_free(key);
            key = NULL;
            goto cleanup;
        }
        else {
            TEST_INFO("        1024-bit key generation failed - PASS");
            ERR_clear_error();
        }
    }

    EVP_PKEY_CTX_free(ctx);
    ctx = NULL;

    /* Test 2: 2048-bit key generation should succeed */
    TEST_INFO("      2048-bit key generation (should succeed)...");

    ctx = EVP_PKEY_CTX_new_from_name(libctx, "RSA", NULL);
    if (ctx == NULL) {
        TEST_ERROR("        Failed to create EVP_PKEY_CTX for RSA");
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }

    rc = EVP_PKEY_keygen_init(ctx);
    if (rc != 1) {
        TEST_ERROR("        Failed to initialize RSA key generation");
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }

    rc = EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048);
    if (rc != 1) {
        TEST_ERROR("        Failed to set RSA key size to 2048 bits");
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }

    rc = EVP_PKEY_keygen(ctx, &key);
    if (rc != 1 || key == NULL) {
        TEST_ERROR("        Failed to generate 2048-bit RSA key - FAIL");
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }

    TEST_INFO("        2048-bit key generated successfully - PASS");
    *key_2048 = key;
    key = NULL;
    ret = TEST_SUCCESS;

cleanup:
    if (key != NULL) {
        EVP_PKEY_free(key);
    }
    if (ctx != NULL) {
        EVP_PKEY_CTX_free(ctx);
    }

    return ret;
}

/* Note: test_rsa_sha1_verify function removed - needs valid pre-computed
 * signature to work. SHA1 verification would be allowed in FIPS for legacy
 * compatibility, but the test is non-trivial to implement correctly.
 */

/**
 * Test RSA signature restrictions with SHA1 and SHA256 in FIPS mode.
 * Tests: SHA1 signing (should fail), SHA256 signing/verification (should work).
 *
 * NOTE: Uses EVP_DigestSignInit_ex with explicit libctx to ensure
 * the correct provider handles the signature operation.
 *
 * @param libctx Library context with provider loaded
 * @param desc Description for logging
 * @param key RSA key to use for signing/verification
 * @return TEST_SUCCESS if all tests pass, TEST_FAILURE otherwise.
 */
static int test_rsa_signatures(OSSL_LIB_CTX *libctx, const char *desc, EVP_PKEY *key)
{
    EVP_MD_CTX *mdctx = NULL;
    unsigned char sig[512];
    size_t siglen = sizeof(sig);
    int ret = TEST_FAILURE;
    int rc;

    if (key == NULL) {
        TEST_ERROR("    Invalid parameter: key is NULL");
        return TEST_FAILURE;
    }

    TEST_INFO("    Testing RSA signatures with %s...", desc);

    /* Test 1: SHA1 signing should fail in FIPS mode */
    TEST_INFO("      RSA-SHA1 signing (should fail in FIPS)...");

    mdctx = EVP_MD_CTX_new();
    if (mdctx == NULL) {
        TEST_ERROR("        Failed to create EVP_MD_CTX");
        goto cleanup;
    }

    /* Use EVP_DigestSignInit_ex to explicitly specify the library context.
     * This ensures the signature operation uses the correct provider.
     */
    rc = EVP_DigestSignInit_ex(mdctx, NULL, "SHA1", libctx, NULL, key, NULL);
    if (rc == 1) {
        /* Init succeeded, try to sign */
        rc = EVP_DigestSign(mdctx, sig, &siglen,
                           (const unsigned char*)test_message,
                           test_message_len);
        if (rc == 1) {
            TEST_ERROR("        RSA-SHA1 signing succeeded - FAIL (FIPS restriction not enforced)");
            goto cleanup;
        }
        else {
            TEST_INFO("        RSA-SHA1 signing failed - PASS");
            ERR_clear_error();
        }
    }
    else {
        TEST_INFO("        RSA-SHA1 signing initialization failed - PASS");
        ERR_clear_error();
    }

    EVP_MD_CTX_free(mdctx);
    mdctx = NULL;

    /* Test 2: SHA256 signing should work */
    TEST_INFO("      RSA-SHA256 signing (should succeed)...");

    mdctx = EVP_MD_CTX_new();
    if (mdctx == NULL) {
        TEST_ERROR("        Failed to create EVP_MD_CTX");
        goto cleanup;
    }

    rc = EVP_DigestSignInit_ex(mdctx, NULL, "SHA256", libctx, NULL, key, NULL);
    if (rc != 1) {
        TEST_ERROR("        Failed to initialize RSA-SHA256 signing");
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }

    siglen = sizeof(sig);
    rc = EVP_DigestSign(mdctx, sig, &siglen,
                       (const unsigned char*)test_message,
                       test_message_len);
    if (rc != 1) {
        TEST_ERROR("        RSA-SHA256 signing failed - FAIL");
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }

    TEST_INFO("        RSA-SHA256 signing succeeded - PASS");

    EVP_MD_CTX_free(mdctx);
    mdctx = NULL;

    /* Test 3: SHA256 verification should work */
    TEST_INFO("      RSA-SHA256 verification (should succeed)...");

    mdctx = EVP_MD_CTX_new();
    if (mdctx == NULL) {
        TEST_ERROR("        Failed to create EVP_MD_CTX");
        goto cleanup;
    }

    rc = EVP_DigestVerifyInit_ex(mdctx, NULL, "SHA256", libctx, NULL, key, NULL);
    if (rc != 1) {
        TEST_ERROR("        Failed to initialize RSA-SHA256 verification");
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }

    rc = EVP_DigestVerify(mdctx, sig, siglen,
                         (const unsigned char*)test_message,
                         test_message_len);
    if (rc != 1) {
        TEST_ERROR("        RSA-SHA256 verification failed - FAIL");
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }

    TEST_INFO("        RSA-SHA256 verification succeeded - PASS");
    ret = TEST_SUCCESS;

cleanup:
    if (mdctx != NULL) {
        EVP_MD_CTX_free(mdctx);
    }

    return ret;
}

/**
 * Test RSA restrictions with both providers.
 *
 * @return TEST_SUCCESS if both providers properly enforce RSA restrictions, TEST_FAILURE otherwise.
 */
int test_rsa_restriction(void)
{
    EVP_PKEY *wolfprov_key = NULL;
    EVP_PKEY *default_key = NULL;
    int wolfprov_sha1_verified = 0;
    int default_sha1_verified = 0;
    int ret = TEST_FAILURE;

    TEST_INFO("Testing RSA restrictions with both providers:");

    /* Test with wolfProvider */
    TEST_INFO("  Testing with wolfProvider...");
    if (test_rsa_keygen(g_wolfprov_libctx, "wolfProvider", &wolfprov_key) != TEST_SUCCESS) {
        TEST_ERROR("    wolfProvider RSA keygen tests failed");
        goto cleanup;
    }
    if (test_rsa_signatures(g_wolfprov_libctx, "wolfProvider", wolfprov_key) != TEST_SUCCESS) {
        TEST_ERROR("    wolfProvider RSA signature tests failed");
        goto cleanup;
    }
    if (test_rsa_sha1_verify(g_wolfprov_libctx, "wolfProvider", &wolfprov_sha1_verified) != TEST_SUCCESS) {
        TEST_ERROR("    wolfProvider RSA-SHA1 verify test failed");
        goto cleanup;
    }
    TEST_INFO("    ✓ wolfProvider RSA tests completed");

    /* Test with default (baseline) provider */
    TEST_INFO("  Testing with default (baseline) provider...");
    if (test_rsa_keygen(g_default_libctx, "default (baseline)", &default_key) != TEST_SUCCESS) {
        TEST_ERROR("    default RSA keygen tests failed");
        goto cleanup;
    }
    if (test_rsa_signatures(g_default_libctx, "default (baseline)", default_key) != TEST_SUCCESS) {
        TEST_ERROR("    default RSA signature tests failed");
        goto cleanup;
    }
    if (test_rsa_sha1_verify(g_default_libctx, "default (baseline)", &default_sha1_verified) != TEST_SUCCESS) {
        TEST_ERROR("    default RSA-SHA1 verify test failed");
        goto cleanup;
    }
    TEST_INFO("    ✓ default (baseline) RSA tests completed");

    /* Verify both providers behave equivalently for SHA1 verification */
    TEST_INFO("");
    TEST_INFO("  RSA-SHA1 verification comparison:");
    TEST_INFO("    wolfProvider: %s", wolfprov_sha1_verified ? "VERIFIED" : "FAILED");
    TEST_INFO("    baseline:     %s", default_sha1_verified ? "VERIFIED" : "FAILED");

    if (wolfprov_sha1_verified != default_sha1_verified) {
        TEST_ERROR("    ✗ Providers behave differently for SHA1 verification!");
        goto cleanup;
    }

    /* SHA1 verification MUST work - FIPS explicitly allows it for legacy
     * compatibility. The patches only block signing, not verification. If
     * verification fails, something is wrong.
     */
    if (!wolfprov_sha1_verified) {
        TEST_ERROR("    ✗ wolfProvider blocked SHA1 verification (should be allowed)");
        goto cleanup;
    }
    if (!default_sha1_verified) {
        TEST_ERROR("    ✗ Baseline blocked SHA1 verification (should be allowed)");
        goto cleanup;
    }
    TEST_INFO("    ✓ Both providers correctly allow SHA1 verification (FIPS legacy compat)");

    TEST_INFO("");
    TEST_INFO("✓ Both providers properly enforce RSA restrictions equivalently");
    ret = TEST_SUCCESS;

cleanup:
    if (wolfprov_key != NULL) {
        EVP_PKEY_free(wolfprov_key);
    }
    if (default_key != NULL) {
        EVP_PKEY_free(default_key);
    }

    return ret;
}

