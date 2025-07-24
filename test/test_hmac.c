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

#endif /* WP_HAVE_HMAC */


