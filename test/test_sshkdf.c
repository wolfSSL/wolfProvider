/* test_sshkdf.c
 *
 * Copyright (C) 2006-2026 wolfSSL Inc.
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

#ifdef WP_HAVE_SSHKDF

/* Helper to derive using SSHKDF via the EVP_KDF API. */
static int test_sshkdf_calc(OSSL_LIB_CTX* libCtx, unsigned char *key,
    size_t keyLen, const char* digest, const unsigned char* inKey,
    size_t inKeyLen, const unsigned char* xcghash, size_t xcghashLen,
    const unsigned char* sessionId, size_t sessionIdLen, const char* type)
{
    int err = 0;
    EVP_KDF *kdf = NULL;
    EVP_KDF_CTX *kctx = NULL;
    OSSL_PARAM params[7], *p = params;

    kdf = EVP_KDF_fetch(libCtx, "SSHKDF", NULL);
    if (kdf == NULL) {
        PRINT_MSG("Failed to fetch SSHKDF");
        err = 1;
    }

    if (err == 0) {
        kctx = EVP_KDF_CTX_new(kdf);
        if (kctx == NULL) {
            PRINT_MSG("Failed to create KDF context");
            err = 1;
        }
    }

    if (err == 0) {
        *p++ = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST,
            (char*)digest, 0);
        *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY,
            (unsigned char*)inKey, inKeyLen);
        *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SSHKDF_XCGHASH,
            (unsigned char*)xcghash, xcghashLen);
        *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SSHKDF_SESSION_ID,
            (unsigned char*)sessionId, sessionIdLen);
        *p++ = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_SSHKDF_TYPE,
            (char*)type, 1);
        *p = OSSL_PARAM_construct_end();

        if (EVP_KDF_derive(kctx, key, keyLen, params) <= 0) {
            PRINT_MSG("Failed to derive key");
            err = 1;
        }
    }

    EVP_KDF_CTX_free(kctx);
    EVP_KDF_free(kdf);
    return err;
}

/* Test SSHKDF vectors - compare wolfProvider output against OpenSSL default. */
static int test_sshkdf_vector(void)
{
    int err = 0;
    int i;
    unsigned char oKey[64];
    unsigned char wKey[64];

    /* Test input shared secret K. */
    unsigned char inKey[] = {
        0x00, 0x00, 0x00, 0x80,
        0x55, 0xba, 0xe9, 0x31, 0xc0, 0x7f, 0xd8, 0x24,
        0xbf, 0x10, 0xad, 0xd1, 0x90, 0x2b, 0x6f, 0xbc,
        0x7c, 0x66, 0x4b, 0xf2, 0xd7, 0x51, 0x0f, 0x88,
        0x9e, 0x2c, 0x31, 0xe7, 0xf5, 0x6a, 0x9b, 0x74,
        0x12, 0x42, 0x53, 0x07, 0x42, 0x02, 0x4f, 0x30,
        0xaa, 0x2f, 0x43, 0x12, 0x95, 0x6a, 0x71, 0x1b,
        0x1a, 0x01, 0x95, 0x6f, 0xd2, 0x18, 0x37, 0x6b,
        0x7e, 0x5f, 0x29, 0x3a, 0x3a, 0xa7, 0xf0, 0x8c,
        0xe5, 0x0f, 0x9a, 0x75, 0x79, 0xcd, 0x2e, 0x43,
        0x1b, 0x3b, 0x14, 0x5e, 0x41, 0x20, 0xd1, 0x53,
        0x1c, 0xb5, 0x35, 0x23, 0xa8, 0xba, 0x38, 0x70,
        0xa9, 0x0b, 0x3d, 0x67, 0xf1, 0xa1, 0x10, 0x97,
        0x21, 0x0b, 0xe4, 0x21, 0x02, 0x2e, 0x0d, 0xb7,
        0xd3, 0x14, 0x18, 0x09, 0xef, 0xb0, 0x45, 0x86,
        0xb4, 0x3b, 0x0b, 0x50, 0x6d, 0xe9, 0x78, 0xf8,
        0xfe, 0x09, 0x8c, 0x0c, 0xf8, 0x71, 0x67, 0x50
    };

    /* Test exchange hash H. */
    unsigned char xcghash[] = {
        0xa4, 0xeb, 0xd4, 0x59, 0x34, 0xf5, 0x67, 0x92,
        0xb5, 0x11, 0x2d, 0xcd, 0x75, 0xa1, 0x07, 0x5f,
        0xdc, 0x88, 0x92, 0x45, 0x87, 0x12, 0x67, 0xe7,
        0xf6, 0x59, 0xf6, 0x8e, 0x5b, 0x22, 0x78, 0x22
    };

    /* Test session ID. */
    unsigned char sessionId[] = {
        0xa4, 0xeb, 0xd4, 0x59, 0x34, 0xf5, 0x67, 0x92,
        0xb5, 0x11, 0x2d, 0xcd, 0x75, 0xa1, 0x07, 0x5f,
        0xdc, 0x88, 0x92, 0x45, 0x87, 0x12, 0x67, 0xe7,
        0xf6, 0x59, 0xf6, 0x8e, 0x5b, 0x22, 0x78, 0x22
    };

    /* Test all key types 'A' through 'F'. */
    const char* types[] = { "A", "B", "C", "D", "E", "F" };

    for (i = 0; i < 6; i++) {
        PRINT_MSG("Testing SSHKDF with SHA-256 type '%s'", types[i]);

        /* Derive with OpenSSL. */
        err = test_sshkdf_calc(osslLibCtx, oKey, 32, "SHA-256",
            inKey, sizeof(inKey), xcghash, sizeof(xcghash),
            sessionId, sizeof(sessionId), types[i]);
        if (err != 0) {
            PRINT_MSG("FAILED OpenSSL SSHKDF type '%s'", types[i]);
            return err;
        }

        /* Derive with wolfProvider. */
        err = test_sshkdf_calc(wpLibCtx, wKey, 32, "SHA-256",
            inKey, sizeof(inKey), xcghash, sizeof(xcghash),
            sessionId, sizeof(sessionId), types[i]);
        if (err != 0) {
            PRINT_MSG("FAILED wolfProvider SSHKDF type '%s'", types[i]);
            return err;
        }

        if (memcmp(oKey, wKey, 32) != 0) {
            PRINT_MSG("FAILED, wolfProvider and OpenSSL derived different keys for type '%s'",
                types[i]);
            PRINT_BUFFER("OpenSSL key", oKey, 32);
            PRINT_BUFFER("wolfProvider key", wKey, 32);
            return 1;
        }
        PRINT_MSG("PASSED SSHKDF type '%s'", types[i]);
    }

    /* Test with a longer key derivation (> digest size). */
    PRINT_MSG("Testing SSHKDF with SHA-256 type 'A' - 64 byte output");
    err = test_sshkdf_calc(osslLibCtx, oKey, 64, "SHA-256",
        inKey, sizeof(inKey), xcghash, sizeof(xcghash),
        sessionId, sizeof(sessionId), "A");
    if (err != 0) {
        PRINT_MSG("FAILED OpenSSL SSHKDF 64-byte");
        return err;
    }
    err = test_sshkdf_calc(wpLibCtx, wKey, 64, "SHA-256",
        inKey, sizeof(inKey), xcghash, sizeof(xcghash),
        sessionId, sizeof(sessionId), "A");
    if (err != 0) {
        PRINT_MSG("FAILED wolfProvider SSHKDF 64-byte");
        return err;
    }
    if (memcmp(oKey, wKey, 64) != 0) {
        PRINT_MSG("FAILED, wolfProvider and OpenSSL derived different 64-byte keys");
        PRINT_BUFFER("OpenSSL key", oKey, 64);
        PRINT_BUFFER("wolfProvider key", wKey, 64);
        return 1;
    }
    PRINT_MSG("PASSED SSHKDF 64-byte output");

#ifndef NO_SHA
    /* Test with SHA-1. */
    PRINT_MSG("Testing SSHKDF with SHA-1 type 'A'");
    err = test_sshkdf_calc(osslLibCtx, oKey, 20, "SHA-1",
        inKey, sizeof(inKey), xcghash, sizeof(xcghash),
        sessionId, sizeof(sessionId), "A");
    if (err != 0) {
        PRINT_MSG("FAILED OpenSSL SSHKDF SHA-1");
        return err;
    }
    err = test_sshkdf_calc(wpLibCtx, wKey, 20, "SHA-1",
        inKey, sizeof(inKey), xcghash, sizeof(xcghash),
        sessionId, sizeof(sessionId), "A");
    if (err != 0) {
        PRINT_MSG("FAILED wolfProvider SSHKDF SHA-1");
        return err;
    }
    if (memcmp(oKey, wKey, 20) != 0) {
        PRINT_MSG("FAILED, wolfProvider and OpenSSL derived different SHA-1 keys");
        PRINT_BUFFER("OpenSSL key", oKey, 20);
        PRINT_BUFFER("wolfProvider key", wKey, 20);
        return 1;
    }
    PRINT_MSG("PASSED SSHKDF SHA-1");
#endif

#ifdef WP_HAVE_SHA384
    /* Test with SHA-384. */
    PRINT_MSG("Testing SSHKDF with SHA-384 type 'A'");
    err = test_sshkdf_calc(osslLibCtx, oKey, 48, "SHA-384",
        inKey, sizeof(inKey), xcghash, sizeof(xcghash),
        sessionId, sizeof(sessionId), "A");
    if (err != 0) {
        PRINT_MSG("FAILED OpenSSL SSHKDF SHA-384");
        return err;
    }
    err = test_sshkdf_calc(wpLibCtx, wKey, 48, "SHA-384",
        inKey, sizeof(inKey), xcghash, sizeof(xcghash),
        sessionId, sizeof(sessionId), "A");
    if (err != 0) {
        PRINT_MSG("FAILED wolfProvider SSHKDF SHA-384");
        return err;
    }
    if (memcmp(oKey, wKey, 48) != 0) {
        PRINT_MSG("FAILED, wolfProvider and OpenSSL derived different SHA-384 keys");
        PRINT_BUFFER("OpenSSL key", oKey, 48);
        PRINT_BUFFER("wolfProvider key", wKey, 48);
        return 1;
    }
    PRINT_MSG("PASSED SSHKDF SHA-384");
#endif

#ifdef WP_HAVE_SHA512
    /* Test with SHA-512. */
    PRINT_MSG("Testing SSHKDF with SHA-512 type 'A'");
    err = test_sshkdf_calc(osslLibCtx, oKey, 64, "SHA-512",
        inKey, sizeof(inKey), xcghash, sizeof(xcghash),
        sessionId, sizeof(sessionId), "A");
    if (err != 0) {
        PRINT_MSG("FAILED OpenSSL SSHKDF SHA-512");
        return err;
    }
    err = test_sshkdf_calc(wpLibCtx, wKey, 64, "SHA-512",
        inKey, sizeof(inKey), xcghash, sizeof(xcghash),
        sessionId, sizeof(sessionId), "A");
    if (err != 0) {
        PRINT_MSG("FAILED wolfProvider SSHKDF SHA-512");
        return err;
    }
    if (memcmp(oKey, wKey, 64) != 0) {
        PRINT_MSG("FAILED, wolfProvider and OpenSSL derived different SHA-512 keys");
        PRINT_BUFFER("OpenSSL key", oKey, 64);
        PRINT_BUFFER("wolfProvider key", wKey, 64);
        return 1;
    }
    PRINT_MSG("PASSED SSHKDF SHA-512");
#endif

    return err;
}

/* Test error cases. */
static int test_sshkdf_error_cases(OSSL_LIB_CTX* libCtx)
{
    int err;
    unsigned char key[32];
    unsigned char inKey[] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10
    };
    unsigned char xcghash[] = {
        0xa4, 0xeb, 0xd4, 0x59, 0x34, 0xf5, 0x67, 0x92,
        0xb5, 0x11, 0x2d, 0xcd, 0x75, 0xa1, 0x07, 0x5f,
        0xdc, 0x88, 0x92, 0x45, 0x87, 0x12, 0x67, 0xe7,
        0xf6, 0x59, 0xf6, 0x8e, 0x5b, 0x22, 0x78, 0x22
    };
    unsigned char sessionId[] = {
        0xa4, 0xeb, 0xd4, 0x59, 0x34, 0xf5, 0x67, 0x92,
        0xb5, 0x11, 0x2d, 0xcd, 0x75, 0xa1, 0x07, 0x5f,
        0xdc, 0x88, 0x92, 0x45, 0x87, 0x12, 0x67, 0xe7,
        0xf6, 0x59, 0xf6, 0x8e, 0x5b, 0x22, 0x78, 0x22
    };

    /* Test missing type - pass all params except type via a custom call. */
    PRINT_MSG("Testing SSHKDF error case - missing type");
    {
        EVP_KDF *kdf = NULL;
        EVP_KDF_CTX *kctx = NULL;
        OSSL_PARAM params[5], *p = params;

        kdf = EVP_KDF_fetch(libCtx, "SSHKDF", NULL);
        if (kdf == NULL) {
            PRINT_MSG("FAILED: Could not fetch SSHKDF");
            return 1;
        }
        kctx = EVP_KDF_CTX_new(kdf);
        if (kctx == NULL) {
            EVP_KDF_free(kdf);
            PRINT_MSG("FAILED: Could not create SSHKDF context");
            return 1;
        }

        *p++ = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST,
            (char*)"SHA-256", 0);
        *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY,
            inKey, sizeof(inKey));
        *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SSHKDF_XCGHASH,
            xcghash, sizeof(xcghash));
        *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SSHKDF_SESSION_ID,
            sessionId, sizeof(sessionId));
        *p = OSSL_PARAM_construct_end();

        err = EVP_KDF_derive(kctx, key, sizeof(key), params);
        if (err > 0) {
            EVP_KDF_CTX_free(kctx);
            EVP_KDF_free(kdf);
            PRINT_MSG("FAILED: SSHKDF should have failed with missing type");
            return 1;
        }
        PRINT_MSG("Negative test passed - SSHKDF correctly rejected missing type");

        EVP_KDF_CTX_free(kctx);
        EVP_KDF_free(kdf);
    }

    /* Test missing key. */
    PRINT_MSG("Testing SSHKDF error case - missing key");
    {
        EVP_KDF *kdf = NULL;
        EVP_KDF_CTX *kctx = NULL;
        OSSL_PARAM params[5], *p = params;

        kdf = EVP_KDF_fetch(libCtx, "SSHKDF", NULL);
        if (kdf == NULL) {
            PRINT_MSG("FAILED: Could not fetch SSHKDF");
            return 1;
        }
        kctx = EVP_KDF_CTX_new(kdf);
        if (kctx == NULL) {
            EVP_KDF_free(kdf);
            PRINT_MSG("FAILED: Could not create SSHKDF context");
            return 1;
        }

        *p++ = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST,
            (char*)"SHA-256", 0);
        *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SSHKDF_XCGHASH,
            xcghash, sizeof(xcghash));
        *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SSHKDF_SESSION_ID,
            sessionId, sizeof(sessionId));
        *p++ = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_SSHKDF_TYPE,
            (char*)"A", 1);
        *p = OSSL_PARAM_construct_end();

        err = EVP_KDF_derive(kctx, key, sizeof(key), params);
        if (err > 0) {
            EVP_KDF_CTX_free(kctx);
            EVP_KDF_free(kdf);
            PRINT_MSG("FAILED: SSHKDF should have failed with missing key");
            return 1;
        }
        PRINT_MSG("Negative test passed - SSHKDF correctly rejected missing key");

        EVP_KDF_CTX_free(kctx);
        EVP_KDF_free(kdf);
    }

    /* Test missing xcghash. */
    PRINT_MSG("Testing SSHKDF error case - missing xcghash");
    {
        EVP_KDF *kdf = NULL;
        EVP_KDF_CTX *kctx = NULL;
        OSSL_PARAM params[5], *p = params;

        kdf = EVP_KDF_fetch(libCtx, "SSHKDF", NULL);
        if (kdf == NULL) {
            PRINT_MSG("FAILED: Could not fetch SSHKDF");
            return 1;
        }
        kctx = EVP_KDF_CTX_new(kdf);
        if (kctx == NULL) {
            EVP_KDF_free(kdf);
            PRINT_MSG("FAILED: Could not create SSHKDF context");
            return 1;
        }

        *p++ = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST,
            (char*)"SHA-256", 0);
        *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY,
            inKey, sizeof(inKey));
        *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SSHKDF_SESSION_ID,
            sessionId, sizeof(sessionId));
        *p++ = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_SSHKDF_TYPE,
            (char*)"A", 1);
        *p = OSSL_PARAM_construct_end();

        err = EVP_KDF_derive(kctx, key, sizeof(key), params);
        if (err > 0) {
            EVP_KDF_CTX_free(kctx);
            EVP_KDF_free(kdf);
            PRINT_MSG("FAILED: SSHKDF should have failed with missing xcghash");
            return 1;
        }
        PRINT_MSG("Negative test passed - SSHKDF correctly rejected missing xcghash");

        EVP_KDF_CTX_free(kctx);
        EVP_KDF_free(kdf);
    }

    /* Test missing session ID. */
    PRINT_MSG("Testing SSHKDF error case - missing session ID");
    {
        EVP_KDF *kdf = NULL;
        EVP_KDF_CTX *kctx = NULL;
        OSSL_PARAM params[5], *p = params;

        kdf = EVP_KDF_fetch(libCtx, "SSHKDF", NULL);
        if (kdf == NULL) {
            PRINT_MSG("FAILED: Could not fetch SSHKDF");
            return 1;
        }
        kctx = EVP_KDF_CTX_new(kdf);
        if (kctx == NULL) {
            EVP_KDF_free(kdf);
            PRINT_MSG("FAILED: Could not create SSHKDF context");
            return 1;
        }

        *p++ = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST,
            (char*)"SHA-256", 0);
        *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY,
            inKey, sizeof(inKey));
        *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SSHKDF_XCGHASH,
            xcghash, sizeof(xcghash));
        *p++ = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_SSHKDF_TYPE,
            (char*)"A", 1);
        *p = OSSL_PARAM_construct_end();

        err = EVP_KDF_derive(kctx, key, sizeof(key), params);
        if (err > 0) {
            EVP_KDF_CTX_free(kctx);
            EVP_KDF_free(kdf);
            PRINT_MSG("FAILED: SSHKDF should have failed with missing session ID");
            return 1;
        }
        PRINT_MSG("Negative test passed - SSHKDF correctly rejected missing session ID");

        EVP_KDF_CTX_free(kctx);
        EVP_KDF_free(kdf);
    }

    /* Test invalid type character. */
    PRINT_MSG("Testing SSHKDF error case - invalid type 'G'");
    {
        EVP_KDF *kdf = NULL;
        EVP_KDF_CTX *kctx = NULL;
        OSSL_PARAM params[6], *p = params;

        kdf = EVP_KDF_fetch(libCtx, "SSHKDF", NULL);
        if (kdf == NULL) {
            PRINT_MSG("FAILED: Could not fetch SSHKDF");
            return 1;
        }
        kctx = EVP_KDF_CTX_new(kdf);
        if (kctx == NULL) {
            EVP_KDF_free(kdf);
            PRINT_MSG("FAILED: Could not create SSHKDF context");
            return 1;
        }

        *p++ = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST,
            (char*)"SHA-256", 0);
        *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY,
            inKey, sizeof(inKey));
        *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SSHKDF_XCGHASH,
            xcghash, sizeof(xcghash));
        *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SSHKDF_SESSION_ID,
            sessionId, sizeof(sessionId));
        *p++ = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_SSHKDF_TYPE,
            (char*)"G", 1);
        *p = OSSL_PARAM_construct_end();

        err = EVP_KDF_derive(kctx, key, sizeof(key), params);
        if (err > 0) {
            EVP_KDF_CTX_free(kctx);
            EVP_KDF_free(kdf);
            PRINT_MSG("FAILED: SSHKDF should have failed with invalid type 'G'");
            return 1;
        }
        PRINT_MSG("Negative test passed - SSHKDF correctly rejected invalid type 'G'");

        EVP_KDF_CTX_free(kctx);
        EVP_KDF_free(kdf);
    }

    return 0;
}

int test_sshkdf(void *data)
{
    int err = 0;

    (void)data;

    err = test_sshkdf_vector();
    if (err != 0) {
        return err;
    }

    /* Test error cases with OpenSSL first. */
    err = test_sshkdf_error_cases(osslLibCtx);
    if (err != 0) {
        return err;
    }

    /* Test error cases with wolfProvider. */
    err = test_sshkdf_error_cases(wpLibCtx);
    if (err != 0) {
        return err;
    }

    return err;
}

#endif /* WP_HAVE_SSHKDF */
