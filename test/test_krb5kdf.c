/* test_krb5kdf.c
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

#include "unit.h"

#ifdef WP_HAVE_KRB5KDF

/* Test KRB5KDF using OpenSSL implementation */
static int test_krb5kdf_calc(OSSL_LIB_CTX* libCtx, unsigned char *key,
    size_t keyLen, const char* cipher, const unsigned char* inKey,
    size_t inKeyLen, const unsigned char* constant, size_t constantLen)
{
    int err = 0;
    EVP_KDF *kdf = NULL;
    EVP_KDF_CTX *kctx = NULL;
    OSSL_PARAM params[4], *p = params;

    /* Create KDF */
    kdf = EVP_KDF_fetch(libCtx, "KRB5KDF", NULL);
    if (kdf == NULL) {
        PRINT_MSG("Failed to fetch KRB5KDF");
        err = 1;
    }

    if (err == 0) {
        /* Create KDF context */
        kctx = EVP_KDF_CTX_new(kdf);
        if (kctx == NULL) {
            PRINT_MSG("Failed to create KDF context");
            err = 1;
        }
    }

    if (err == 0) {
        /* Set parameters */
        *p++ = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_CIPHER,
            (char*)cipher, 0);
        *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY,
            (unsigned char*)inKey, inKeyLen);
        *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_CONSTANT,
            (unsigned char*)constant, constantLen);
        *p = OSSL_PARAM_construct_end();

        /* Derive key */
        if (EVP_KDF_derive(kctx, key, keyLen, params) <= 0) {
            PRINT_MSG("Failed to derive key");
            err = 1;
        }
    }

    EVP_KDF_CTX_free(kctx);
    EVP_KDF_free(kdf);
    return err;
}

/* Test error cases */
static int test_krb5kdf_error_cases(OSSL_LIB_CTX* libCtx)
{
    int err;
    unsigned char key[32];
    /* 32-byte key for AES-128 test (wrong size) */
    unsigned char inKey32[] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20
    };
    /* 16-byte key for AES-256 test (wrong size) */
    unsigned char inKey16[] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10
    };
    unsigned char constant[] = {
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88
    };

    PRINT_MSG("Testing KRB5KDF error case - AES-128-CBC with 32-byte key");
    /* This should fail since AES-128 key size is 16 bytes */
    err = test_krb5kdf_calc(libCtx, key, sizeof(key), "AES-128-CBC",
        inKey32, sizeof(inKey32), constant, sizeof(constant));
    if (err == 0) {
        /* If we get here, the test failed because it should have errored */
        PRINT_MSG("FAILED: KRB5KDF accepted wrong key size for AES-128-CBC");
        return 1;
    }
    PRINT_MSG("Negative test passed - KRB5KDF correctly rejected wrong key size for AES-128-CBC");

    PRINT_MSG("Testing KRB5KDF error case - AES-256-CBC with 16-byte key");
    /* This should fail since AES-256 key size is 32 bytes */
    err = test_krb5kdf_calc(libCtx, key, sizeof(key), "AES-256-CBC",
        inKey16, sizeof(inKey16), constant, sizeof(constant));
    if (err == 0) {
        /* If we get here, the test failed because it should have errored */
        PRINT_MSG("FAILED: KRB5KDF accepted wrong key size for AES-256-CBC");
        return 1;
    }
    PRINT_MSG("Negative test passed - KRB5KDF correctly rejected wrong key size for AES-256-CBC");

    return 0;
}

/* Test vectors */
static int test_krb5kdf_vector(void)
{
    int err = 0;
    unsigned char oKey[32];
    unsigned char wKey[32];
    /* Test vector - AES-128-CBC */
    unsigned char inKey128[] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10
    };
    /* Test vector - AES-256-CBC */
    unsigned char inKey256[] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20
    };
    unsigned char constant[] = {
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88
    };

    /* Test AES-128-CBC */
    PRINT_MSG("Testing KRB5KDF with OpenSSL - AES-128-CBC");
    err = test_krb5kdf_calc(osslLibCtx, oKey, 16, "AES-128-CBC",
        inKey128, sizeof(inKey128), constant, sizeof(constant));
    if (err == 1) {
        PRINT_MSG("FAILED OpenSSL - AES-128-CBC");
        return err;
    }
    PRINT_MSG("Testing KRB5KDF with wolfSSL - AES-128-CBC");
    err = test_krb5kdf_calc(wpLibCtx, wKey, 16, "AES-128-CBC",
        inKey128, sizeof(inKey128), constant, sizeof(constant));
    if (err == 1) {
        PRINT_MSG("FAILED wolfSSL - AES-128-CBC");
        return err;
    }
    if (memcmp(oKey, wKey, 16) != 0) {
        PRINT_MSG("FAILED, wolfSSL and OpenSSL derived different keys");
        PRINT_BUFFER("OpenSSL key", oKey, 16);
        PRINT_BUFFER("wolfSSL key", wKey, 16);
        return 1;
    }

    /* Test AES-256-CBC */
    PRINT_MSG("Testing KRB5KDF with OpenSSL - AES-256-CBC");
    err = test_krb5kdf_calc(osslLibCtx, oKey, 32, "AES-256-CBC",
        inKey256, sizeof(inKey256), constant, sizeof(constant));
    if (err == 1) {
        PRINT_MSG("FAILED OpenSSL - AES-256-CBC");
        return err;
    }
    PRINT_MSG("Testing KRB5KDF with wolfSSL - AES-256-CBC");
    err = test_krb5kdf_calc(wpLibCtx, wKey, 32, "AES-256-CBC",
        inKey256, sizeof(inKey256), constant, sizeof(constant));
    if (err == 1) {
        PRINT_MSG("FAILED wolfSSL - AES-256-CBC");
        return err;
    }
    if (memcmp(oKey, wKey, 32) != 0) {
        PRINT_MSG("FAILED, wolfSSL and OpenSSL derived different keys");
        PRINT_BUFFER("OpenSSL key", oKey, 32);
        PRINT_BUFFER("wolfSSL key", wKey, 32);
        return 1;
    }

    return err;
}

int test_krb5kdf(void *data)
{
    int err = 0;

    (void)data;

    err = test_krb5kdf_vector();
    if (err != 0) {
        return err;
    }

    /* Test error cases with OpenSSL first */
    err = test_krb5kdf_error_cases(osslLibCtx);
    if (err != 0) {
        return err;
    }

    /* Test error cases with wolfSSL */
    err = test_krb5kdf_error_cases(wpLibCtx);
    if (err != 0) {
        return err;
    }

    return err;
}

#endif /* WP_HAVE_KRB5KDF */
