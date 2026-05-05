/* test_hmac.c
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
#include <openssl/core_names.h>

#include "unit.h"

#ifdef WP_HAVE_HMAC

static int test_mac_gen_pkey(OSSL_LIB_CTX* libCtx, const char* md,
    const char* pkeyType, unsigned char *pswd, int pswdSz, unsigned char *msg,
    int len, unsigned char *mac, int *macLen)
{
    int err;
    EVP_MD_CTX*   ctx = NULL;
    EVP_PKEY_CTX* pctx = NULL;
    EVP_PKEY*     pkey = NULL;

    err = (ctx = EVP_MD_CTX_new()) == NULL;
    if (err == 0) {
        err = (pkey = EVP_PKEY_new_raw_private_key_ex(libCtx, pkeyType, NULL,
            pswd, pswdSz)) == NULL;
    }
    if (err == 0) {
        err = EVP_DigestSignInit_ex(ctx, &pctx, md, libCtx, NULL, pkey,
            NULL) != 1;
    }
    if (err == 0) {
        err = EVP_DigestSignUpdate(ctx, msg, len/2) != 1;
    }
    if (err == 0) {
        err = EVP_DigestSignUpdate(ctx, msg + len/2, len - len/2) != 1;
    }
    if (err == 0) {
        size_t mlen = (size_t)*macLen;

        err = EVP_DigestSignFinal(ctx, mac, &mlen) != 1;
        *macLen = (int)mlen;
    }
    if (err == 0) {
        PRINT_BUFFER("MAC", mac, *macLen);
    }

    EVP_PKEY_free(pkey);
    EVP_MD_CTX_free(ctx);

    return err;
}

static int test_mac_gen_mac(OSSL_LIB_CTX* libCtx, const char* md,
    const char* pkeyType, unsigned char *pswd, int pswdSz, unsigned char *msg,
    int len, unsigned char *mac, int *macLen)
{
    int err;
    EVP_MAC*      emac = NULL;
    EVP_MAC_CTX*  mctx = NULL;
    size_t outLen;
    OSSL_PARAM    params[3];

    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST,
        (char*)md, 0);
    params[1] = OSSL_PARAM_construct_octet_string(OSSL_MAC_PARAM_KEY,
        (void*)pswd, pswdSz);
    params[2] = OSSL_PARAM_construct_end();

    err = (emac = EVP_MAC_fetch(libCtx, pkeyType, NULL)) == NULL;
    if (err == 0) {
        err = (mctx = EVP_MAC_CTX_new(emac)) == NULL;
    }
    if (err == 0) {
        err = EVP_MAC_CTX_set_params(mctx, params) != 1;
    }
    if (err == 0) {
        err = (EVP_MAC_init(mctx, NULL, 0, NULL)) != 1;
    }
    if (err == 0) {
        err = (EVP_MAC_update(mctx, msg, len)) != 1;
    }
    if (err == 0) {
        err = (EVP_MAC_final(mctx, mac, &outLen, *macLen)) != 1;
    }
    if (err == 0) {
        *macLen = (int)outLen;
        PRINT_BUFFER("MAC", mac, *macLen);
    }

    EVP_MAC_CTX_free(mctx);
    EVP_MAC_free(emac);

    return err;
}

static int test_hmac_create_mac_helper(void *data, const char* md,
    unsigned char* pswd, int pswdSz)
{
    int ret;
    unsigned char exp[128];
    int expLen;
    unsigned char mac[128];
    int macLen;
    unsigned char msg[] = "Test message";
    int len;

    (void)data;
    len    = sizeof(msg);
    macLen = sizeof(mac);
    expLen = sizeof(exp);

    /* generate mac using OpenSSL */
    ret = test_mac_gen_mac(osslLibCtx, md, "HMAC", pswd, pswdSz, msg,
            len, exp, &expLen);
    if (ret != 0) {
        PRINT_MSG("Generate MAC using OpenSSL failed");
    }

    if (ret == 0) {
        memset(mac, 0, sizeof(mac));
        ret = test_mac_gen_mac(wpLibCtx, md, "HMAC", pswd, pswdSz, msg,
            len, mac, &macLen);
        if (ret != 0) {
            PRINT_MSG("Generate MAC using wolfSSL failed");
        }
    }

    if (ret == 0) {
        if (macLen != expLen) {
            PRINT_MSG("generated length and expected length differ");
            ret = -1;
        }
        else {
            if (memcmp(mac, exp, expLen) != 0) {
                PRINT_MSG("generated mac and expected mac differ");
                ret = -1;
            }
        }
    }

    return ret;
}

static int test_hmac_create_pkey_helper(void *data, const char* md,
    unsigned char* pswd, int pswdSz)
{
    int ret;
    unsigned char exp[128];
    int expLen;
    unsigned char mac[128];
    int macLen;
    unsigned char msg[] = "Test message";
    int len;

    (void)data;
    len    = sizeof(msg);
    macLen = sizeof(mac);
    expLen = sizeof(exp);

    /* generate mac using OpenSSL */
    ret = test_mac_gen_pkey(osslLibCtx, md, "HMAC", pswd, pswdSz, msg,
            len, exp, &expLen);
    if (ret != 0) {
        PRINT_MSG("Generate MAC using OpenSSL failed");
    }

    if (ret == 0) {
        memset(mac, 0, sizeof(mac));
        ret = test_mac_gen_pkey(wpLibCtx, md, "HMAC", pswd, pswdSz, msg,
            len, mac, &macLen);
        if (ret != 0) {
            PRINT_MSG("Generate MAC using wolfSSL failed");
        }
    }

    if (ret == 0) {
        if (macLen != expLen) {
            PRINT_MSG("generated length and expected length differ");
            ret = -1;
        }
        else {
            if (memcmp(mac, exp, expLen) != 0) {
                PRINT_MSG("generated mac and expected mac differ");
                ret = -1;
            }
        }
    }

    return ret;
}

static int test_hmac_create_helper(void *data, const char* md,
    unsigned char* pswd, int pswdSz)
{
    int err;

    err = test_hmac_create_mac_helper(data, md, pswd, pswdSz);
    if (err == 0) {
        err = test_hmac_create_pkey_helper(data, md, pswd, pswdSz);
    }

    return err;
}

int test_hmac_create(void *data)
{
    int ret = 0;
    unsigned char pswd[] = "My empire of dirt";
#ifdef WP_HAVE_SHA1
    unsigned char bigPswd[100];

    PRINT_MSG("Testing with SHA1");
    ret = test_hmac_create_helper(data, "SHA-1", pswd, sizeof(pswd));
    if (ret == 0) {
        PRINT_MSG("Testing with SHA1, 0 length key");
        ret = test_hmac_create_helper(data, "SHA-1", pswd, 0);
    }
    if (ret == 0) {
        PRINT_MSG("Testing with SHA1, key length larger than block size");
        RAND_bytes(bigPswd, sizeof(bigPswd));
        ret = test_hmac_create_helper(data, "SHA-1", bigPswd,
                  sizeof(bigPswd));
    }
#endif

#ifdef WP_HAVE_SHA224
    if (ret == 0) {
        PRINT_MSG("Testing with SHA224");
        ret = test_hmac_create_helper(data, "SHA-224", pswd, sizeof(pswd));
    }
#endif

#ifdef WP_HAVE_SHA256
    if (ret == 0) {
        PRINT_MSG("Testing with SHA256");
        ret = test_hmac_create_helper(data, "SHA-256", pswd, sizeof(pswd));
    }
#endif

#ifdef WP_HAVE_SHA384
    if (ret == 0) {
        PRINT_MSG("Testing with SHA384");
        ret = test_hmac_create_helper(data, "SHA-384", pswd, sizeof(pswd));
    }
#endif

#ifdef WP_HAVE_SHA512
    if (ret == 0) {
        PRINT_MSG("Testing with SHA512");
        ret = test_hmac_create_helper(data, "SHA-512", pswd, sizeof(pswd));
    }
#endif

#ifdef WP_HAVE_SHA3
#ifdef WP_HAVE_SHA3_224
    if (ret == 0) {
        PRINT_MSG("Testing with SHA3-224");
        ret = test_hmac_create_helper(data, "SHA3-224", pswd, sizeof(pswd));
    }
#endif
#ifdef WP_HAVE_SHA3_256
    if (ret == 0) {
        PRINT_MSG("Testing with SHA3-256");
        ret = test_hmac_create_helper(data, "SHA3-256", pswd, sizeof(pswd));
    }
#endif
#ifdef WP_HAVE_SHA3_384
    if (ret == 0) {
        PRINT_MSG("Testing with SHA3-384");
        ret = test_hmac_create_helper(data, "SHA3-384", pswd, sizeof(pswd));
    }
#endif
#ifdef WP_HAVE_SHA3_512
    if (ret == 0) {
        PRINT_MSG("Testing with SHA3-512");
        ret = test_hmac_create_helper(data, "SHA3-512", pswd, sizeof(pswd));
    }
#endif
#endif /* WP_HAVE_SHA3 */
    return ret;
}

/******************************************************************************/

/**
 * Test that HMAC produces consistent results when data is fed in many small
 * updates vs. a single large update. Exercises the chunked update path
 * (F-1639).
 */
static int test_hmac_multi_update_helper(OSSL_LIB_CTX *libCtx)
{
    int err;
    EVP_MAC *emac = NULL;
    EVP_MAC_CTX *ctx = NULL;
    OSSL_PARAM params[3];
    char digest[] = "SHA-256";
    unsigned char key[] = "test-hmac-multi-update-key";
    unsigned char data[4096];
    unsigned char macOne[32];
    unsigned char macMulti[32];
    size_t macOneSz = sizeof(macOne);
    size_t macMultiSz = sizeof(macMulti);
    size_t i;

    RAND_bytes(data, sizeof(data));

    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST,
        digest, 0);
    params[1] = OSSL_PARAM_construct_octet_string(OSSL_MAC_PARAM_KEY,
        (void *)key, sizeof(key));
    params[2] = OSSL_PARAM_construct_end();

    err = (emac = EVP_MAC_fetch(libCtx, "HMAC", NULL)) == NULL;

    /* Single update */
    if (err == 0) {
        err = (ctx = EVP_MAC_CTX_new(emac)) == NULL;
    }
    if (err == 0) {
        err = EVP_MAC_CTX_set_params(ctx, params) != 1;
    }
    if (err == 0) {
        err = EVP_MAC_init(ctx, NULL, 0, NULL) != 1;
    }
    if (err == 0) {
        err = EVP_MAC_update(ctx, data, sizeof(data)) != 1;
    }
    if (err == 0) {
        err = EVP_MAC_final(ctx, macOne, &macOneSz, sizeof(macOne)) != 1;
    }
    EVP_MAC_CTX_free(ctx);
    ctx = NULL;

    /* Many small updates (128 bytes each) */
    if (err == 0) {
        err = (ctx = EVP_MAC_CTX_new(emac)) == NULL;
    }
    if (err == 0) {
        err = EVP_MAC_CTX_set_params(ctx, params) != 1;
    }
    if (err == 0) {
        err = EVP_MAC_init(ctx, NULL, 0, NULL) != 1;
    }
    for (i = 0; err == 0 && i < sizeof(data); i += 128) {
        err = EVP_MAC_update(ctx, data + i, 128) != 1;
    }
    if (err == 0) {
        err = EVP_MAC_final(ctx, macMulti, &macMultiSz,
            sizeof(macMulti)) != 1;
    }
    if (err == 0) {
        if (macOneSz != macMultiSz ||
            memcmp(macOne, macMulti, macOneSz) != 0) {
            PRINT_ERR_MSG("Multi-update HMAC doesn't match single update");
            err = 1;
        }
    }

    EVP_MAC_CTX_free(ctx);
    EVP_MAC_free(emac);
    return err;
}

int test_hmac_multi_update(void *data)
{
    int err;

    (void)data;

    PRINT_MSG("HMAC multi-update with OpenSSL");
    err = test_hmac_multi_update_helper(osslLibCtx);
    if (err == 0) {
        PRINT_MSG("HMAC multi-update with wolfProvider");
        err = test_hmac_multi_update_helper(wpLibCtx);
    }
    return err;
}

#endif /* WP_HAVE_HMAC */


