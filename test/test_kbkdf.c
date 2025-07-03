/* test_kbkdf.c
 *
 * Copyright (C) 2006-2024 wolfSSL Inc.
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
 * along with wolfProvider.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/core_names.h>
#include <openssl/param_build.h>

#include <wolfprovider/alg_funcs.h>
#include <wolfprovider/internal.h>

#include "unit.h"

#ifdef WP_HAVE_KBKDF

static int test_kbkdf_feedback_ex(OSSL_LIB_CTX* libctx, const unsigned char* key,
    size_t keyLen, unsigned char* out, size_t outLen)
{
    int err = 0;
    EVP_KDF *kdf = NULL;
    EVP_KDF_CTX *kctx = NULL;
    OSSL_PARAM params[7], *p = params;
    unsigned char label[] = {
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18
    };
    unsigned char zeroes[16] = {0};
    char feedback[] = "FEEDBACK";
    char cmac[] = "CMAC";
    char cipher[13];

    /* Set cipher based on key length */
    if (keyLen == 16) {
        XSTRNCPY(cipher, "AES-128-CBC", sizeof(cipher));
    }
    else if (keyLen == 32) {
        XSTRNCPY(cipher, "AES-256-CBC", sizeof(cipher));
    }
    else {
        PRINT_MSG("Invalid key length");
        return 1;
    }

    kdf = EVP_KDF_fetch(libctx, "KBKDF", NULL);
    if (!kdf) {
        PRINT_MSG("Failed to fetch KBKDF");
        err = 1;
        goto done;
    }

    kctx = EVP_KDF_CTX_new(kdf);
    if (!kctx) {
        PRINT_MSG("Failed to create KBKDF context");
        err = 1;
        goto done;
    }

    /* Set up parameters for KBKDF */
    *p++ = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_MODE,
                                           feedback, 0);
    *p++ = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_MAC,
                                           cmac, 0);
    *p++ = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_CIPHER,
                                           cipher, 0);
    *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY,
                                            (void*)key, keyLen);
    *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT,
                                            label, sizeof(label));
    *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SEED,
                                            zeroes, sizeof(zeroes));
    *p = OSSL_PARAM_construct_end();

    if (EVP_KDF_derive(kctx, out, outLen, params) <= 0) {
        PRINT_MSG("KBKDF derive failed");
        err = 1;
        goto done;
    }

done:
    EVP_KDF_free(kdf);
    EVP_KDF_CTX_free(kctx);
    return err;
}

static int test_kbkdf_feedback_compare(OSSL_LIB_CTX* osslCtx, OSSL_LIB_CTX* wpCtx,
    const unsigned char* key, size_t keyLen)
{
    int err = 0;
    unsigned char osslOut[32];
    unsigned char wpOut[32];

    PRINT_MSG("Test KBKDF with feedback mode");

    /* Get key material from OpenSSL */
    err = test_kbkdf_feedback_ex(osslCtx, key, keyLen, osslOut, keyLen);
    if (err == 0) {
        /* Get key material from wolfProvider */
        err = test_kbkdf_feedback_ex(wpCtx, key, keyLen, wpOut, keyLen);
        if (err == 0) {
            /* Compare results */
            if (XMEMCMP(osslOut, wpOut, keyLen) != 0) {
                PRINT_MSG("KBKDF derived keys do not match!");
                err = 1;
            }
        }
    }

    return err;
}

static int test_kbkdf_hmac_ex(OSSL_LIB_CTX* libctx, const unsigned char* key,
    size_t keyLen, const char* digest, unsigned char* out, size_t outLen)
{
    int err = 0;
    EVP_KDF *kdf = NULL;
    EVP_KDF_CTX *kctx = NULL;
    OSSL_PARAM params[7], *p = params;
    unsigned char label[] = {
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18
    };
    unsigned char context[] = {
        0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28
    };
    char hmac[] = "HMAC";

    kdf = EVP_KDF_fetch(libctx, "KBKDF", NULL);
    if (!kdf) {
        PRINT_MSG("Failed to fetch KBKDF");
        err = 1;
        goto done;
    }

    kctx = EVP_KDF_CTX_new(kdf);
    if (!kctx) {
        PRINT_MSG("Failed to create KBKDF context");
        err = 1;
        goto done;
    }

    /* Set up parameters for KBKDF with HMAC */
    *p++ = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST,
                                           (char *)digest, 0);
    *p++ = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_MAC,
                                           hmac, 0);
    *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY,
                                            (void*)key, keyLen);
    *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO,
                                            context, sizeof(context));
    *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT,
                                            label, sizeof(label));
    *p = OSSL_PARAM_construct_end();

    if (EVP_KDF_derive(kctx, out, outLen, params) <= 0) {
        PRINT_MSG("KBKDF derive with HMAC failed");
        err = 1;
        goto done;
    }

done:
    EVP_KDF_free(kdf);
    EVP_KDF_CTX_free(kctx);
    return err;
}

static int test_kbkdf_hmac_compare(OSSL_LIB_CTX* osslCtx, OSSL_LIB_CTX* wpCtx,
    const unsigned char* key, size_t keyLen, const char* digest)
{
    int err = 0;
    unsigned char osslOut[32];
    unsigned char wpOut[32];

    PRINT_MSG("Test KBKDF with HMAC-%s", digest);

    /* Get key material from OpenSSL */
    err = test_kbkdf_hmac_ex(osslCtx, key, keyLen, digest, osslOut, keyLen);
    if (err == 0) {
        /* Get key material from wolfProvider */
        err = test_kbkdf_hmac_ex(wpCtx, key, keyLen, digest, wpOut, keyLen);
        if (err == 0) {
            /* Compare results */
            if (XMEMCMP(osslOut, wpOut, keyLen) != 0) {
                PRINT_MSG("KBKDF derived keys do not match!");
                err = 1;
            }
        }
    }

    return err;
}

static int test_kbkdf_feedback(void)
{
    int err;
    unsigned char key128[] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10
    };
    unsigned char key256[] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20
    };

    /* Test CMAC mode */
    PRINT_MSG("\nTesting KBKDF with CMAC:");
    /* Test with 128-bit key */
    err = test_kbkdf_feedback_compare(osslLibCtx, wpLibCtx, key128, sizeof(key128));
    if (err == 0) {
        /* Test with 256-bit key */
        err = test_kbkdf_feedback_compare(osslLibCtx, wpLibCtx, key256, sizeof(key256));
    }

    if (err == 0) {
        /* Test HMAC mode with SHA256 */
        err = test_kbkdf_hmac_compare(osslLibCtx, wpLibCtx, key128, sizeof(key128), "SHA256");
        if (err == 0) {
            /* Test with 256-bit key */
            err = test_kbkdf_hmac_compare(osslLibCtx, wpLibCtx, key256, sizeof(key256), "SHA256");
        }
    }

    if (err == 0) {
        /* Test HMAC mode with SHA384 */
        err = test_kbkdf_hmac_compare(osslLibCtx, wpLibCtx, key128, sizeof(key128), "SHA384");
        if (err == 0) {
            /* Test with 256-bit key */
            err = test_kbkdf_hmac_compare(osslLibCtx, wpLibCtx, key256, sizeof(key256), "SHA384");
        }
    }

    return err;
}

int test_kbkdf(void *data)
{
    int err = 0;
    (void)data;

    err = test_kbkdf_feedback();

    return err;
}
#endif
