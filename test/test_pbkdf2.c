/* test_pbkdf2.c
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

#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/params.h>
#include <openssl/core_names.h>

#include <wolfprovider/alg_funcs.h>
#include <wolfprovider/internal.h>

#include "unit.h"

#if defined(WP_HAVE_PBE) && defined(WP_HAVE_SHA256)

/*
 * Run an EVP_KDF derive for the named KDF with the given parameters.
 *
 * Returns 0 when the derive call ran to completion (whether it succeeded or
 * was rejected); the EVP_KDF_derive() return value is stored in *deriveRet.
 * Returns 1 only on test-infrastructure failure (fetch / ctx allocation).
 */
static int test_kdf_derive(OSSL_LIB_CTX* libCtx, const char* name,
    OSSL_PARAM* params, unsigned char* out, size_t outLen, int* deriveRet)
{
    int err = 0;
    EVP_KDF* kdf = NULL;
    EVP_KDF_CTX* kctx = NULL;

    *deriveRet = -1;

    kdf = EVP_KDF_fetch(libCtx, name, NULL);
    if (kdf == NULL) {
        PRINT_MSG("Failed to fetch KDF");
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
        *deriveRet = EVP_KDF_derive(kctx, out, outLen, params);
    }

    EVP_KDF_CTX_free(kctx);
    EVP_KDF_free(kdf);
    return err;
}

/* Derive a PKCS12KDF key with the given iteration count on one provider. */
static int pkcs12_derive(OSSL_LIB_CTX* libCtx, uint64_t iter,
    unsigned char* out, size_t outLen, int* deriveRet)
{
    static unsigned char pass[] = "password";
    static unsigned char salt[16] = {
        1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16
    };
    int id = 1;
    char digest[] = "SHA256";
    OSSL_PARAM params[6];
    OSSL_PARAM* p = params;

    *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_PASSWORD,
        pass, sizeof(pass) - 1);
    *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT,
        salt, sizeof(salt));
    *p++ = OSSL_PARAM_construct_uint64(OSSL_KDF_PARAM_ITER, &iter);
    *p++ = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, digest, 0);
    *p++ = OSSL_PARAM_construct_int(OSSL_KDF_PARAM_PKCS12_ID, &id);
    *p = OSSL_PARAM_construct_end();

    return test_kdf_derive(libCtx, "PKCS12KDF", params, out, outLen, deriveRet);
}

/*
 * PKCS12KDF: OpenSSL and wolfProvider must produce the same key, including the
 * iterations==0 edge case (both run a single iteration), and iterations==0
 * must equal iterations==1.
 */
static int test_pkcs12_kdf(void)
{
    int err = 0;
    int i;
    uint64_t iters[3] = { 0, 1, 2048 };
    unsigned char oKey[24];
    unsigned char wKey[24];
    unsigned char wKey1[24];
    size_t outLen = sizeof(oKey);

    for (i = 0; (err == 0) && (i < 3); i++) {
        int oRet = 0;
        int wRet = 0;

        memset(oKey, 0, outLen);
        memset(wKey, 0, outLen);

        err = pkcs12_derive(osslLibCtx, iters[i], oKey, outLen, &oRet);
        if (err == 0) {
            err = pkcs12_derive(wpLibCtx, iters[i], wKey, outLen, &wRet);
        }
        if ((err == 0) && ((oRet <= 0) || (wRet <= 0))) {
            PRINT_MSG("PKCS12KDF derive failed");
            err = 1;
        }
        if ((err == 0) && (memcmp(oKey, wKey, outLen) != 0)) {
            PRINT_BUFFER("OpenSSL key", oKey, outLen);
            PRINT_BUFFER("wolfProvider key", wKey, outLen);
            err = 1;
        }
    }

    /* iterations==0 must match iterations==1 for wolfProvider. */
    if (err == 0) {
        int rc0 = 0;
        int rc1 = 0;

        memset(wKey, 0, outLen);
        memset(wKey1, 0, outLen);

        err = pkcs12_derive(wpLibCtx, 0, wKey, outLen, &rc0);
        if (err == 0) {
            err = pkcs12_derive(wpLibCtx, 1, wKey1, outLen, &rc1);
        }
        if ((err == 0) && ((rc0 <= 0) || (rc1 <= 0) ||
                (memcmp(wKey, wKey1, outLen) != 0))) {
            PRINT_MSG("PKCS12KDF iterations==0 differs from iterations==1");
            err = 1;
        }
    }

    return err;
}

/* Derive a PBKDF2 key on one provider, optionally setting the PKCS5 param. */
static int pbkdf2_derive(OSSL_LIB_CTX* libCtx, uint64_t iter,
    const unsigned char* salt, size_t saltLen, int setPkcs5, int pkcs5,
    unsigned char* out, size_t outLen, int* deriveRet)
{
    static unsigned char pass[] = "password";
    char digest[] = "SHA256";
    OSSL_PARAM params[6];
    OSSL_PARAM* p = params;

    *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_PASSWORD,
        pass, sizeof(pass) - 1);
    *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT,
        (void*)salt, saltLen);
    *p++ = OSSL_PARAM_construct_uint64(OSSL_KDF_PARAM_ITER, &iter);
    *p++ = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, digest, 0);
    if (setPkcs5) {
        *p++ = OSSL_PARAM_construct_int(OSSL_KDF_PARAM_PKCS5, &pkcs5);
    }
    *p = OSSL_PARAM_construct_end();

    return test_kdf_derive(libCtx, "PBKDF2", params, out, outLen, deriveRet);
}

/*
 * Derive on both providers and check they agree: same accept/reject decision,
 * the decision matches expectOk, and the keys are identical when both succeed.
 */
static int pbkdf2_compare(uint64_t iter, const unsigned char* salt,
    size_t saltLen, int setPkcs5, int pkcs5, size_t outLen, int expectOk)
{
    int err = 0;
    int oRet = 0;
    int wRet = 0;
    unsigned char oKey[64];
    unsigned char wKey[64];

    memset(oKey, 0, sizeof(oKey));
    memset(wKey, 0, sizeof(wKey));

    err = pbkdf2_derive(osslLibCtx, iter, salt, saltLen, setPkcs5, pkcs5,
        oKey, outLen, &oRet);
    if (err == 0) {
        err = pbkdf2_derive(wpLibCtx, iter, salt, saltLen, setPkcs5, pkcs5,
            wKey, outLen, &wRet);
    }

    /* Both providers must agree on accept vs reject. */
    if ((err == 0) && ((oRet > 0) != (wRet > 0))) {
        PRINT_MSG("PBKDF2 OpenSSL/wolfProvider accept-reject mismatch");
        err = 1;
    }
    /* And that decision must be what the case expects. */
    if ((err == 0) && ((oRet > 0) != (expectOk != 0))) {
        PRINT_MSG("PBKDF2 result not as expected");
        err = 1;
    }
    /* When both succeed, the derived keys must be identical. */
    if ((err == 0) && (oRet > 0) && (memcmp(oKey, wKey, outLen) != 0)) {
        PRINT_BUFFER("OpenSSL key", oKey, outLen);
        PRINT_BUFFER("wolfProvider key", wKey, outLen);
        err = 1;
    }

    return err;
}

/*
 * PBKDF2: OpenSSL and wolfProvider must agree, including the SP 800-132
 * lower bounds that are enforced only for the PKCS5=0 opt-in.
 */
static int test_pbkdf2_bounds(void)
{
    int err = 0;
    static const unsigned char salt16[16] = {
        1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16
    };
    static const unsigned char salt8[8] = {
        1, 2, 3, 4, 5, 6, 7, 8
    };

    /* Default (no PKCS5): standard parameters, keys match. */
    PRINT_MSG("PBKDF2 default params");
    err = pbkdf2_compare(2048, salt16, sizeof(salt16), 0, 0, 32, 1);

    /* Default (no PKCS5): low iteration count still accepted (checks off). */
    if (err == 0) {
        PRINT_MSG("PBKDF2 default, low iteration count accepted");
        err = pbkdf2_compare(10, salt16, sizeof(salt16), 0, 0, 32, 1);
    }

    /* PKCS5=0 opt-in: compliant parameters, keys match. */
    if (err == 0) {
        PRINT_MSG("PBKDF2 PKCS5=0 compliant");
        err = pbkdf2_compare(2000, salt16, sizeof(salt16), 1, 0, 32, 1);
    }

    /* PKCS5=0 opt-in: iteration count < 1000 rejected by both. */
    if (err == 0) {
        PRINT_MSG("PBKDF2 PKCS5=0 iteration count too low");
        err = pbkdf2_compare(10, salt16, sizeof(salt16), 1, 0, 32, 0);
    }

    /* PKCS5=0 opt-in: salt < 128 bits rejected by both. */
    if (err == 0) {
        PRINT_MSG("PBKDF2 PKCS5=0 salt too short");
        err = pbkdf2_compare(2000, salt8, sizeof(salt8), 1, 0, 32, 0);
    }

    /* PKCS5=0 opt-in: key < 112 bits (13 bytes) rejected by both. */
    if (err == 0) {
        PRINT_MSG("PBKDF2 PKCS5=0 key too short");
        err = pbkdf2_compare(2000, salt16, sizeof(salt16), 1, 0, 13, 0);
    }

    /* PKCS5=1: legacy mode disables the checks, low iteration accepted. */
    if (err == 0) {
        PRINT_MSG("PBKDF2 PKCS5=1 disables checks");
        err = pbkdf2_compare(10, salt16, sizeof(salt16), 1, 1, 32, 1);
    }

    return err;
}

/*
 * A PBKDF2 iteration count above INT_MAX must not silently truncate to a small
 * value. iter = 2^32 + 1 collapses to 1 in a plain (int) cast, which would
 * derive the same key as a single iteration.
 */
static int test_pbkdf2_iter_truncation(void)
{
    int err = 0;
    int retHuge = 0;
    int ret1 = 0;
    unsigned char keyHuge[32];
    unsigned char key1[32];
    static const unsigned char salt16[16] = {
        1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16
    };
    uint64_t hugeIter = ((uint64_t)1 << 32) + 1;

    memset(keyHuge, 0, sizeof(keyHuge));
    memset(key1, 0, sizeof(key1));

    err = pbkdf2_derive(wpLibCtx, hugeIter, salt16, sizeof(salt16), 0, 0,
        keyHuge, sizeof(keyHuge), &retHuge);
    if (err == 0) {
        err = pbkdf2_derive(wpLibCtx, 1, salt16, sizeof(salt16), 0, 0,
            key1, sizeof(key1), &ret1);
    }
    if ((err == 0) && (ret1 <= 0)) {
        PRINT_MSG("PBKDF2 baseline iter=1 derive failed");
        err = 1;
    }
    if ((err == 0) && (retHuge > 0) &&
            (memcmp(keyHuge, key1, sizeof(key1)) == 0)) {
        PRINT_MSG("PBKDF2 iteration count above INT_MAX truncated to 1");
        err = 1;
    }

    return err;
}

int test_pbkdf2(void *data)
{
    int err = 0;

    (void)data;

    PRINT_MSG("PKCS12KDF OpenSSL vs wolfProvider");
    err = test_pkcs12_kdf();

    if (err == 0) {
        PRINT_MSG("PBKDF2 OpenSSL vs wolfProvider");
        err = test_pbkdf2_bounds();
    }

    if (err == 0) {
        PRINT_MSG("PBKDF2 iteration count truncation");
        err = test_pbkdf2_iter_truncation();
    }

    return err;
}

#endif /* WP_HAVE_PBE && WP_HAVE_SHA256 */
