/* test_cmac.c
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
#undef AES_BLOCK_SIZE
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/cmac.h>

#ifdef WP_HAVE_CMAC

static int test_cmac_gen_pkey(OSSL_LIB_CTX* libCtx, const EVP_CIPHER* c,
    unsigned char *key, int keySz, unsigned char *msg, int len,
    unsigned char *out, int *outLen)
{
    int err;
    EVP_MD_CTX   *ctx;
    EVP_PKEY_CTX *pctx = NULL;
    EVP_PKEY_CTX *psctx = NULL;
    EVP_PKEY     *pkey = NULL;

    err = (ctx = EVP_MD_CTX_new()) == NULL;
    if (err == 0) {
        pctx = EVP_PKEY_CTX_new_from_name(libCtx, "CMAC", NULL);
        if (pctx == NULL)
            err = -1;
    }
    if (err == 0) {
        EVP_PKEY_keygen_init(pctx);
        err = EVP_PKEY_CTX_ctrl(pctx, -1, EVP_PKEY_OP_KEYGEN,
                EVP_PKEY_CTRL_CIPHER, 0, (void*)c) != 1;
    }
    if (err == 0) {
        err = EVP_PKEY_CTX_ctrl(pctx, -1, EVP_PKEY_OP_KEYGEN,
                EVP_PKEY_CTRL_SET_MAC_KEY, keySz, key) != 1;
    }
    if (err == 0) {
        err = EVP_PKEY_keygen(pctx, &pkey) != 1;
    }
    if (err == 0) {
        err = EVP_DigestSignInit_ex(ctx, &psctx, NULL, libCtx, NULL, pkey,
            NULL) != 1;
    }
    if (err == 0) {
        err = EVP_DigestSignUpdate(ctx, msg, len/2) != 1;
    }
    if (err == 0) {
        err = EVP_DigestSignUpdate(ctx, msg + len/2, len - len/2) != 1;
    }
    if (err == 0) {
        size_t mlen = (size_t)*outLen;

        err = EVP_DigestSignFinal(ctx, out, &mlen) != 1;
        *outLen = (int)mlen;
    }
    if (err == 0) {
        PRINT_BUFFER("CMAC", out, *outLen);
    }

    EVP_MD_CTX_free(ctx);
    EVP_PKEY_CTX_free(pctx);
    EVP_PKEY_free(pkey);

    return err;
}

static int test_cmac_gen_mac(OSSL_LIB_CTX* libCtx, const char *c,
    unsigned char *key, int keySz, unsigned char *msg, int len,
    unsigned char *out, int *outLen)
{
    int err;
    EVP_MAC*      emac = NULL;
    EVP_MAC_CTX*  mctx = NULL;
    size_t        outSz;
    OSSL_PARAM    params[3];

    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_CIPHER,
        (char*)c, 0);
    params[1] = OSSL_PARAM_construct_octet_string(OSSL_MAC_PARAM_KEY,
        (void*)key, keySz);
    params[2] = OSSL_PARAM_construct_end();

    err = (emac = EVP_MAC_fetch(libCtx, "CMAC", NULL)) == NULL;
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
        err = (EVP_MAC_final(mctx, out, &outSz, *outLen)) != 1;
    }
    if (err == 0) {
        *outLen = (int)outSz;
        PRINT_BUFFER("CMAC", out, *outLen);
    }

    EVP_MAC_CTX_free(mctx);
    EVP_MAC_free(emac);

    return err;
}

static int test_cmac_create_mac_helper(unsigned char *in, int inSz,
    unsigned char *key, int keySz, const char *c)
{
    int ret;
    unsigned char exp[16];
    int expLen = sizeof(exp);
    unsigned char mac[16];
    int macLen = sizeof(mac);

    /* generate mac using OpenSSL */
    ret = test_cmac_gen_mac(osslLibCtx, c, key, keySz, in, inSz, exp, &expLen);
    if (ret != 0) {
        PRINT_MSG("Generate MAC using OpenSSL failed");
    }

    if (ret == 0) {
        memset(mac, 0, sizeof(mac));
        ret = test_cmac_gen_mac(wpLibCtx, c, key, keySz, in, inSz, mac,
            &macLen);
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

static int test_cmac_create_pkey_helper(unsigned char *in, int inSz,
    unsigned char *key, int keySz, const EVP_CIPHER *cm)
{
    int ret;
    unsigned char exp[16];
    int expLen = sizeof(exp);
    unsigned char mac[16];
    int macLen = sizeof(mac);

    /* generate mac using OpenSSL */
    ret = test_cmac_gen_pkey(osslLibCtx, cm, key, keySz, in, inSz, exp,
        &expLen);
    if (ret != 0) {
        PRINT_MSG("Generate MAC using OpenSSL failed");
    }

    if (ret == 0) {
        memset(mac, 0, sizeof(mac));
        ret = test_cmac_gen_pkey(wpLibCtx, cm, key, keySz, in, inSz, mac,
            &macLen);
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

static int test_cmac_create_helper(unsigned char *in, int inSz,
    unsigned char *key, int keySz, const EVP_CIPHER *cm, const char* c)
{
    int err;

    err = test_cmac_create_mac_helper(in, inSz, key, keySz, c);
    if (err == 0) {
        err = test_cmac_create_pkey_helper(in, inSz, key, keySz, cm);
    }

    return err;
}

int test_cmac_create(void *data)
{
    int ret = 0;
    unsigned char in[] = "I'm gonna break my rusty cage and run";
    int inSz;

    unsigned char key[] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07
    };
    int keySz;

    (void)data;

    inSz  = sizeof(in);

    PRINT_MSG("Testing with 256 bit KEY");
    keySz = 32;
    ret = test_cmac_create_helper(in, inSz, key, keySz, EVP_aes_256_cbc(),
        "AES-256-CBC");

    if (ret == 0) {
        PRINT_MSG("Testing with 128 bit KEY");
        keySz = 16;
        ret = test_cmac_create_helper(in, inSz, key, keySz, EVP_aes_128_cbc(),
            "AES-128-CBC");
    }

    if (ret == 0) {
        PRINT_MSG("Testing with a 192 bit KEY");
        keySz = 24;
        ret = test_cmac_create_helper(in, inSz, key, keySz, EVP_aes_192_cbc(),
            "AES-192-CBC");
    }

    return ret;
}

#endif /* WP_HAVE_CMAC */


