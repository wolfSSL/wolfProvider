/* test_hkdf.c
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

#ifdef WP_HAVE_HKDF

static int test_hkdf_calc(OSSL_LIB_CTX* libCtx, unsigned char *key, int keyLen,
    const EVP_MD *md, int mode)
{
    int err = 0;
    EVP_PKEY_CTX *ctx = NULL;
    unsigned char inKey[32] = { 0, };
    unsigned char salt[32] = { 0, };
    unsigned char info[32] = { 0, };
    size_t len = keyLen;

    if (mode == EVP_PKEY_HKDEF_MODE_EXTRACT_ONLY) {
        len = EVP_MD_get_size(md);
    }

    ctx = EVP_PKEY_CTX_new_from_name(libCtx, "HKDF", NULL);
    if (ctx == NULL) {
        err = 1;
    }
    if (err == 0) {
        if (EVP_PKEY_derive_init(ctx) != 1) {
            err = 1;
        }
    }
    if (err == 0) {
        if (EVP_PKEY_CTX_hkdf_mode(ctx, mode) != 1) {
            err = 1;
        }
    }
    if (err == 0) {
        if (EVP_PKEY_CTX_set_hkdf_md(ctx, md) != 1) {
            err = 1;
        }
    }
    if (err == 0) {
        if (EVP_PKEY_CTX_set1_hkdf_key(ctx, inKey, sizeof(inKey)) != 1) {
            err = 1;
        }
    }
    if ((err == 0) && (mode != EVP_PKEY_HKDEF_MODE_EXPAND_ONLY)) {
        if (EVP_PKEY_CTX_set1_hkdf_salt(ctx, salt, sizeof(salt)) != 1) {
            err = 1;
        }
    }
    if ((err == 0) && (mode != EVP_PKEY_HKDEF_MODE_EXTRACT_ONLY)) {
        if (EVP_PKEY_CTX_add1_hkdf_info(ctx, info, sizeof(info)) != 1) {
            err = 1;
        }
    }
    if (err == 0) {
        if (EVP_PKEY_derive(ctx, key, &len) != 1) {
            err = 1;
        }
    }

    if ((err == 0) && (mode != EVP_PKEY_HKDEF_MODE_EXTRACT_ONLY)) {
        if (len != (size_t)keyLen) {
            err = 1;
        }
    }
    else {
        if (len != (size_t)EVP_MD_size(md)) {
            err = 1;
        }
    }

    EVP_PKEY_CTX_free(ctx);
    return err;
}

#if OPENSSL_VERSION_NUMBER <= 0x30400000L

static int test_hkdf_double_set_salt(OSSL_LIB_CTX* libCtx, unsigned char *key,
    int keyLen, const EVP_MD *md, int mode)
{
    int err = 0;
    EVP_PKEY_CTX *ctx = NULL;
    unsigned char inKey[32] = { 0, };
    unsigned char salt[32] = { 0, };
    unsigned char info[32] = { 0, };
    size_t len = keyLen;

    if (mode == EVP_PKEY_HKDEF_MODE_EXTRACT_ONLY) {
        len = EVP_MD_get_size(md);
    }

    ctx = EVP_PKEY_CTX_new_from_name(libCtx, "HKDF", NULL);
    if (ctx == NULL) {
        err = 1;
    }
    if (err == 0) {
        if (EVP_PKEY_derive_init(ctx) != 1) {
            err = 1;
        }
    }
    if (err == 0) {
        if (EVP_PKEY_CTX_hkdf_mode(ctx, mode) != 1) {
            err = 1;
        }
    }
    if (err == 0) {
        if (EVP_PKEY_CTX_set_hkdf_md(ctx, md) != 1) {
            err = 1;
        }
    }
    if (err == 0) {
        if (EVP_PKEY_CTX_set1_hkdf_key(ctx, inKey, sizeof(inKey)) != 1) {
            err = 1;
        }
    }
    if ((err == 0) && (mode != EVP_PKEY_HKDEF_MODE_EXPAND_ONLY)) {
        if (EVP_PKEY_CTX_set1_hkdf_salt(ctx, NULL, 0) != 1) {
            err = 1;
        }
    }
    if ((err == 0) && (mode != EVP_PKEY_HKDEF_MODE_EXPAND_ONLY)) {
        if (EVP_PKEY_CTX_set1_hkdf_salt(ctx, salt, sizeof(salt)) != 1) {
            err = 1;
        }
    }
    if ((err == 0) && (mode != EVP_PKEY_HKDEF_MODE_EXTRACT_ONLY)) {
        if (EVP_PKEY_CTX_add1_hkdf_info(ctx, info, sizeof(info)) != 1) {
            err = 1;
        }
    }
    if (err == 0) {
        if (EVP_PKEY_derive(ctx, key, &len) != 1) {
            err = 1;
        }
    }

    if ((err == 0) && (mode != EVP_PKEY_HKDEF_MODE_EXTRACT_ONLY)) {
        if (len != (size_t)keyLen) {
            err = 1;
        }
    }
    else {
        if (len != (size_t)EVP_MD_size(md)) {
            err = 1;
        }
    }

    EVP_PKEY_CTX_free(ctx);
    return err;
}

#endif

static int test_hkdf_md(const EVP_MD *md, int mode)
{
    int err = 0;
    unsigned char oKey[128];
    unsigned char wKey[128];

    memset(oKey, 0, sizeof(oKey));
    memset(wKey, 0, sizeof(wKey));

    PRINT_MSG("Calc with OpenSSL");
    err = test_hkdf_calc(osslLibCtx, oKey, sizeof(oKey), md, mode);
    if (err == 1) {
        PRINT_MSG("FAILED OpenSSL");
    }

    if (err == 0) {
        PRINT_MSG("Calc with wolfSSL");
        err = test_hkdf_calc(wpLibCtx, wKey, sizeof(wKey), md, mode);
        if (err == 1) {
            PRINT_MSG("FAILED wolfSSL");
        }
    }

    if ((err == 0) && (memcmp(oKey, wKey, sizeof(oKey)) != 0)) {
        PRINT_BUFFER("OpenSSL key", oKey, sizeof(oKey));
        PRINT_BUFFER("wolfSSL key", wKey, sizeof(wKey));
        err = 1;
    }

#if OPENSSL_VERSION_NUMBER <= 0x30400000L

    memset(oKey, 0, sizeof(oKey));
    memset(wKey, 0, sizeof(wKey));

    if (err == 0) {
        err = test_hkdf_double_set_salt(osslLibCtx, oKey, sizeof(oKey), md, mode);
        if (err == 1) {
            PRINT_MSG("FAILED OpenSSL");
        }
    }

    if (err == 0) {
        PRINT_MSG("Calc with wolfSSL");
        err = test_hkdf_double_set_salt(wpLibCtx, wKey, sizeof(wKey), md, mode);
        if (err == 1) {
            PRINT_MSG("FAILED wolfSSL");
        }
    }

    if ((err == 0) && (memcmp(oKey, wKey, sizeof(oKey)) != 0)) {
        PRINT_BUFFER("OpenSSL key", oKey, sizeof(oKey));
        PRINT_BUFFER("wolfSSL key", wKey, sizeof(wKey));
        err = 1;
    }

#endif

    return err;
}

static int test_hkdf_str_calc(OSSL_LIB_CTX* libCtx, unsigned char *key,
    int keyLen, const char *md, const char *mode, size_t* outLen)
{
    int err = 0;
    EVP_PKEY_CTX *ctx = NULL;
    const char* inKey = "0123456789abcf";
    const char* salt = "Salt of at least 14 bytes";
    const char* info = "Some info";
    size_t len = keyLen;

    if (strncmp("EXTRACT_ONLY", mode, 12) == 0) {
        len = 32;
    }

    ctx = EVP_PKEY_CTX_new_from_name(libCtx, "HKDF", NULL);
    if (ctx == NULL) {
        err = 1;
    }
    if (err == 0) {
        if (EVP_PKEY_derive_init(ctx) != 1) {
            err = 1;
        }
    }
    if (err == 0) {
        if (EVP_PKEY_CTX_ctrl_str(ctx, "mode", mode) != 1) {
            err = 1;
        }
    }
    if (err == 0) {
        if (EVP_PKEY_CTX_ctrl_str(ctx, "md", md) != 1) {
            err = 1;
        }
    }
    if (err == 0) {
        if (EVP_PKEY_CTX_ctrl_str(ctx, "key", inKey) != 1) {
            err = 1;
        }
    }
    if ((err == 0) && (strncmp(mode, "EXPAND_ONLY", 12) != 0)) {
        if (EVP_PKEY_CTX_ctrl_str(ctx, "salt", salt) != 1) {
            err = 1;
        }
    }
    if ((err == 0) && (strncmp(mode, "EXTRACT_ONLY", 13) != 0)) {
        if (EVP_PKEY_CTX_ctrl_str(ctx, "info", info) != 1) {
            err = 1;
        }
    }
    if (err == 0) {
        if (EVP_PKEY_derive(ctx, key, &len) != 1) {
            err = 1;
        }
    }

    if ((err == 0) && (strncmp(mode, "EXTRACT_ONLY", 13) != 0)) {
        if (len != (size_t)keyLen) {
            err = 1;
        }
    }
    else {
        if (len != (size_t)EVP_MD_size(EVP_get_digestbyname(md))) {
            err = 1;
        }
    }

    *outLen = len;
    EVP_PKEY_CTX_free(ctx);
    return err;
}

static int test_hkdf_hexstr_calc(OSSL_LIB_CTX* libCtx, unsigned char *key,
    int keyLen, const char *md, const char *mode, size_t* outLen)
{
    int err = 0;
    EVP_PKEY_CTX *ctx = NULL;
    const char* inKey = "00000000000000000000000000000000";
    const char* salt = "00000000000000000000000000000000";
    const char* info = "00000000000000000000000000000000";
    size_t len = keyLen;

    if (strncmp("EXTRACT_ONLY", mode, 12) == 0) {
        len = 32;
    }

    ctx = EVP_PKEY_CTX_new_from_name(libCtx, "HKDF", NULL);
    if (ctx == NULL) {
        err = 1;
    }
    if (err == 0) {
        if (EVP_PKEY_derive_init(ctx) != 1) {
            err = 1;
        }
    }
    if (err == 0) {
        if (EVP_PKEY_CTX_ctrl_str(ctx, "mode", mode) != 1) {
            err = 1;
        }
    }
    if (err == 0) {
        if (EVP_PKEY_CTX_ctrl_str(ctx, "md", md) != 1) {
            err = 1;
        }
    }
    if (err == 0) {
        if (EVP_PKEY_CTX_ctrl_str(ctx, "hexkey", inKey) != 1) {
            err = 1;
        }
    }
    /* Set key twice to ensure no memory leak. */
    if (err == 0) {
        if (EVP_PKEY_CTX_ctrl_str(ctx, "hexkey", inKey) != 1) {
            err = 1;
        }
    }
    if ((err == 0) && (strncmp(mode, "EXPAND_ONLY", 12) != 0)) {
        if (EVP_PKEY_CTX_ctrl_str(ctx, "hexsalt", salt) != 1) {
            err = 1;
        }
    }
    /* Set salt twice to ensure no memory leak. */
    if ((err == 0) && (strncmp(mode, "EXPAND_ONLY", 12) != 0)) {
        if (EVP_PKEY_CTX_ctrl_str(ctx, "hexsalt", salt) != 1) {
            err = 1;
        }
    }
    if ((err == 0) && (strncmp(mode, "EXTRACT_ONLY", 13) != 0)) {
        if (EVP_PKEY_CTX_ctrl_str(ctx, "hexinfo", info) != 1) {
            err = 1;
        }
    }
    if (err == 0) {
        if (EVP_PKEY_derive(ctx, key, &len) != 1) {
            err = 1;
        }
    }

    if ((err == 0) && (strncmp(mode, "EXTRACT_ONLY", 13) != 0)) {
        if (len != (size_t)keyLen) {
            err = 1;
        }
    }
    else {
        if (len != (size_t)EVP_MD_size(EVP_get_digestbyname(md))) {
            err = 1;
        }
    }

    *outLen = len;
    EVP_PKEY_CTX_free(ctx);
    return err;
}

static int test_hkdf_str_md(const char *md, const char *mode)
{
    int err = 0;
    unsigned char oKey[128];
    unsigned char wKey[128];
    size_t oKeyLen;
    size_t wKeyLen;

    PRINT_MSG("Calc with strings OpenSSL");
    err = test_hkdf_str_calc(osslLibCtx, oKey, sizeof(oKey), md, mode,
        &oKeyLen);
    if (err == 1) {
        PRINT_MSG("FAILED OpenSSL");
    }

    if (err == 0) {
        PRINT_MSG("Calc with strings wolfSSL");
        err = test_hkdf_str_calc(wpLibCtx, wKey, sizeof(wKey), md, mode,
            &wKeyLen);
        if (err == 1) {
            PRINT_MSG("FAILED wolfSSL");
        }
    }


    if ((err == 0) && ((oKeyLen != wKeyLen) || (memcmp(oKey, wKey,
            oKeyLen) != 0))) {
        PRINT_BUFFER("OpenSSL key", oKey, oKeyLen);
        PRINT_BUFFER("wolfSSL key", wKey, wKeyLen);
        err = 1;
    }

    if (err == 0) {
        PRINT_MSG("Calc with hex strings OpenSSL");
        err = test_hkdf_hexstr_calc(osslLibCtx, oKey, sizeof(oKey), md, mode,
            &oKeyLen);
        if (err == 1) {
            PRINT_MSG("FAILED OpenSSL");
        }
    }

    if (err == 0) {
        PRINT_MSG("Calc with hex strings wolfSSL");
        err = test_hkdf_hexstr_calc(wpLibCtx, wKey, sizeof(wKey), md, mode,
            &wKeyLen);
        if (err == 1) {
            PRINT_MSG("FAILED wolfSSL");
        }
    }


    if ((err == 0) && ((oKeyLen != wKeyLen) || (memcmp(oKey, wKey,
            oKeyLen) != 0))) {
        PRINT_BUFFER("OpenSSL key", oKey, sizeof(oKey));
        PRINT_BUFFER("wolfSSL key", wKey, sizeof(wKey));
        err = 1;
    }
    return err;
}

static int test_hkdf_fail_calc(OSSL_LIB_CTX* libCtx)
{
    int err = 0;
#ifdef WP_HAVE_SHA256
    EVP_PKEY_CTX *ctx = NULL;
    unsigned char key[1] = { 0 };

    if (EVP_PKEY_CTX_ctrl_str(NULL, "md", "sha256") == 1) {
        err = 1;
    }
    if (err == 0) {
        ctx = EVP_PKEY_CTX_new_from_name(libCtx, "HKDF", NULL);
        if (ctx == NULL) {
            err = 1;
        }
    }
    if (err == 0) {
        if (EVP_PKEY_derive_init(ctx) != 1) {
            err = 1;
        }
    }
    if (err == 0) {
        /* Invalid control value. */
        if (EVP_PKEY_CTX_ctrl(ctx, -1, EVP_PKEY_OP_DERIVE,
                              EVP_PKEY_CTRL_TLS_SEED, 0, NULL) == 1) {
            err = 1;
        }
    }
    if ((err == 0) && (libCtx == wpLibCtx)) {
        /* Invalid mode. */
        if (EVP_PKEY_CTX_hkdf_mode(ctx, -1) == 1) {
            err = 1;
        }
    }
    if (err == 0) {
        /* Negative key length. */
        if (EVP_PKEY_CTX_set1_hkdf_key(ctx, key, -1) == 1) {
            err = 1;
        }
    }
    if (err == 0) {
        /* Negative salt length. */
        if (EVP_PKEY_CTX_set1_hkdf_salt(ctx, key, -1) == 1) {
            err = 1;
        }
    }
    if (err == 0) {
        /* Negative info length. */
        if (EVP_PKEY_CTX_add1_hkdf_info(ctx, key, -1) == 1) {
            err = 1;
        }
    }
    if (err == 0) {
        /* Invalid control type string. */
        if (EVP_PKEY_CTX_ctrl_str(ctx, "invalid", "") == 1) {
            err = 1;
        }
    }

    EVP_PKEY_CTX_free(ctx);
#endif
    return err;
}

static int test_hkdf_fail(void)
{
    int err;

    PRINT_MSG("Failure cases with OpenSSL");
    err = test_hkdf_fail_calc(osslLibCtx);
    if (err == 0) {
        PRINT_MSG("Failure cases with wolfSSL");
        err = test_hkdf_fail_calc(wpLibCtx);
    }

    return err;
}

#define NUM_MODES     3

int test_hkdf(void *data)
{
    int err = 0;
    int i;
    int mode[] = {
        EVP_PKEY_HKDEF_MODE_EXTRACT_AND_EXPAND,
        EVP_PKEY_HKDEF_MODE_EXTRACT_ONLY,
        EVP_PKEY_HKDEF_MODE_EXPAND_ONLY
    };
    const char *modeStr[NUM_MODES] = {
        "EXTRACT_AND_EXPAND",
        "EXTRACT_ONLY",
        "EXPAND_ONLY"
    };

    (void)data;

    for (i = 0; (err == 0) && (i < NUM_MODES); i++) {
    #ifdef WP_HAVE_SHA256
        err = test_hkdf_md(EVP_sha256(), mode[i]);
    #endif
    #ifdef WP_HAVE_SHA384
        if (err == 0) {
            err = test_hkdf_md(EVP_sha384(), mode[i]);
        }
    #endif
    }
    for (i = 0; (err == 0) && (i < NUM_MODES); i++) {
    #ifdef WP_HAVE_SHA256
        err = test_hkdf_str_md("sha256", modeStr[i]);
    #elif defined(WP_HAVE_SHA384)
        err = test_hkdf_str_md("sha384", modeStr[i]);
    #endif
    }
    if (err == 0) {
        err = test_hkdf_fail();
    }

    return err;
}

#endif /* WP_HAVE_HKDF */


