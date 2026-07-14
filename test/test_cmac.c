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

/******************************************************************************/

/**
 * Test that CMAC produces consistent results when data is fed in many small
 * updates vs. a single large update. Exercises the chunked update path
 * (F-1640).
 */
static int test_cmac_multi_update_helper(OSSL_LIB_CTX *libCtx)
{
    int err;
    EVP_MAC *emac = NULL;
    EVP_MAC_CTX *ctx = NULL;
    OSSL_PARAM params[3];
    char cipher[] = "AES-256-CBC";
    unsigned char key[32] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07
    };
    unsigned char data[2048];
    unsigned char macOne[16];
    unsigned char macMulti[16];
    size_t macOneSz = sizeof(macOne);
    size_t macMultiSz = sizeof(macMulti);
    size_t i;

    RAND_bytes(data, sizeof(data));

    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_CIPHER,
        cipher, 0);
    params[1] = OSSL_PARAM_construct_octet_string(OSSL_MAC_PARAM_KEY,
        (void *)key, sizeof(key));
    params[2] = OSSL_PARAM_construct_end();

    err = (emac = EVP_MAC_fetch(libCtx, "CMAC", NULL)) == NULL;

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

    /* Many small updates (16 bytes each — one AES block) */
    if (err == 0) {
        err = (ctx = EVP_MAC_CTX_new(emac)) == NULL;
    }
    if (err == 0) {
        err = EVP_MAC_CTX_set_params(ctx, params) != 1;
    }
    if (err == 0) {
        err = EVP_MAC_init(ctx, NULL, 0, NULL) != 1;
    }
    for (i = 0; err == 0 && i < sizeof(data); i += 16) {
        err = EVP_MAC_update(ctx, data + i, 16) != 1;
    }
    if (err == 0) {
        err = EVP_MAC_final(ctx, macMulti, &macMultiSz,
            sizeof(macMulti)) != 1;
    }
    if (err == 0) {
        if (macOneSz != macMultiSz ||
            memcmp(macOne, macMulti, macOneSz) != 0) {
            PRINT_ERR_MSG("Multi-update CMAC doesn't match single update");
            err = 1;
        }
    }

    EVP_MAC_CTX_free(ctx);
    EVP_MAC_free(emac);
    return err;
}

int test_cmac_multi_update(void *data)
{
    int err;

    (void)data;

    PRINT_MSG("CMAC multi-update with OpenSSL");
    err = test_cmac_multi_update_helper(osslLibCtx);
    if (err == 0) {
        PRINT_MSG("CMAC multi-update with wolfProvider");
        err = test_cmac_multi_update_helper(wpLibCtx);
    }
    return err;
}

int test_cmac_dup(void *data)
{
    int ret = 0;
    EVP_MAC* emac = NULL;
    EVP_MAC_CTX* src = NULL;
    EVP_MAC_CTX* dup = NULL;
    OSSL_PARAM params[3];
    char cipher[] = "AES-256-CBC";
    unsigned char key[] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07
    };
    unsigned char prefix[] = "dup-prefix";
    unsigned char tailA[] = "-tail-a";
    unsigned char tailB[] = "-tail-b";
    unsigned char msgA[sizeof(prefix) + sizeof(tailA)];
    unsigned char msgB[sizeof(prefix) + sizeof(tailB)];
    unsigned char macA[16];
    unsigned char macB[16];
    unsigned char expA[16];
    unsigned char expB[16];
    size_t macASz = sizeof(macA);
    size_t macBSz = sizeof(macB);
    int expASz = sizeof(expA);
    int expBSz = sizeof(expB);

    (void)data;

    PRINT_MSG("Testing CMAC context dup");

    /* Build full messages for one-shot expected MAC calculations. */
    memcpy(msgA, prefix, sizeof(prefix));
    memcpy(msgA + sizeof(prefix), tailA, sizeof(tailA));
    memcpy(msgB, prefix, sizeof(prefix));
    memcpy(msgB + sizeof(prefix), tailB, sizeof(tailB));

    /* Compute expected MACs. */
    ret = test_cmac_gen_mac(wpLibCtx, cipher, key, (int)sizeof(key),
        msgA, (int)sizeof(msgA), expA, &expASz);
    if (ret != 0) {
        PRINT_MSG("Generate expected MAC A failed");
    }
    if (ret == 0) {
        ret = test_cmac_gen_mac(wpLibCtx, cipher, key, (int)sizeof(key),
            msgB, (int)sizeof(msgB), expB, &expBSz);
        if (ret != 0) {
            PRINT_MSG("Generate expected MAC B failed");
        }
    }

    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_CIPHER,
        cipher, 0);
    params[1] = OSSL_PARAM_construct_octet_string(OSSL_MAC_PARAM_KEY,
        (void*)key, sizeof(key));
    params[2] = OSSL_PARAM_construct_end();

    if (ret == 0) {
        ret = (emac = EVP_MAC_fetch(wpLibCtx, "CMAC", NULL)) == NULL;
    }
    if (ret == 0) {
        ret = (src = EVP_MAC_CTX_new(emac)) == NULL;
    }
    if (ret == 0) {
        ret = EVP_MAC_CTX_set_params(src, params) != 1;
    }
    if (ret == 0) {
        ret = EVP_MAC_init(src, NULL, 0, NULL) != 1;
    }
    if (ret == 0) {
        ret = EVP_MAC_update(src, prefix, sizeof(prefix)) != 1;
    }
    /* Duplicate after partial update. */
    if (ret == 0) {
        ret = (dup = EVP_MAC_CTX_dup(src)) == NULL;
    }
    if (ret == 0) {
        ret = EVP_MAC_update(src, tailA, sizeof(tailA)) != 1;
    }
    if (ret == 0) {
        ret = EVP_MAC_update(dup, tailB, sizeof(tailB)) != 1;
    }
    if (ret == 0) {
        ret = EVP_MAC_final(src, macA, &macASz, sizeof(macA)) != 1;
    }
    if (ret == 0) {
        ret = EVP_MAC_final(dup, macB, &macBSz, sizeof(macB)) != 1;
    }
    if (ret == 0) {
        if ((macASz != (size_t)expASz) || (memcmp(macA, expA, macASz) != 0)) {
            PRINT_MSG("Duplicated source context MAC mismatch");
            ret = -1;
        }
    }
    if (ret == 0) {
        if ((macBSz != (size_t)expBSz) || (memcmp(macB, expB, macBSz) != 0)) {
            PRINT_MSG("Duplicated destination context MAC mismatch");
            ret = -1;
        }
    }

    EVP_MAC_CTX_free(dup);
    EVP_MAC_CTX_free(src);
    EVP_MAC_free(emac);

    return ret;
}

/* The two-pass EVP_DigestSignFinal() contract: a NULL signature buffer is a
 * size query that reports the MAC length without finalizing, so the same
 * context can then produce the MAC into the allocated buffer. */
int test_cmac_size_query(void *data)
{
    int err = 0;
    EVP_MD_CTX* ctx = NULL;
    EVP_PKEY_CTX* pctx = NULL;
    EVP_PKEY_CTX* psctx = NULL;
    EVP_PKEY* pkey = NULL;
    unsigned char key[32];
    unsigned char msg[32];
    unsigned char mac[AES_BLOCK_SIZE];
    size_t macSz = 0;

    (void)data;

    memset(key, 0x0b, sizeof(key));
    memset(msg, 0x41, sizeof(msg));

    PRINT_MSG("Testing CMAC EVP_DigestSignFinal size query (NULL buffer)");

    ctx = EVP_MD_CTX_new();
    if (ctx == NULL) {
        err = 1;
    }
    if (err == 0) {
        pctx = EVP_PKEY_CTX_new_from_name(wpLibCtx, "CMAC", NULL);
        if (pctx == NULL) {
            err = 1;
        }
    }
    if (err == 0) {
        err = EVP_PKEY_keygen_init(pctx) != 1;
    }
    if (err == 0) {
        err = EVP_PKEY_CTX_ctrl(pctx, -1, EVP_PKEY_OP_KEYGEN,
            EVP_PKEY_CTRL_CIPHER, 0, (void*)EVP_aes_256_cbc()) != 1;
    }
    if (err == 0) {
        err = EVP_PKEY_CTX_ctrl(pctx, -1, EVP_PKEY_OP_KEYGEN,
            EVP_PKEY_CTRL_SET_MAC_KEY, (int)sizeof(key), key) != 1;
    }
    if (err == 0) {
        err = EVP_PKEY_keygen(pctx, &pkey) != 1;
    }
    if (err == 0) {
        err = EVP_DigestSignInit_ex(ctx, &psctx, NULL, wpLibCtx, NULL, pkey,
            NULL) != 1;
    }
    if (err == 0) {
        err = EVP_DigestSignUpdate(ctx, msg, sizeof(msg)) != 1;
    }

    /* First pass - NULL buffer must report the MAC size. */
    if (err == 0) {
        if (EVP_DigestSignFinal(ctx, NULL, &macSz) != 1) {
            PRINT_MSG("CMAC size query failed");
            err = 1;
        }
        else if (macSz != AES_BLOCK_SIZE) {
            PRINT_ERR_MSG("CMAC size query reported %zu, expected %d", macSz,
                AES_BLOCK_SIZE);
            err = 1;
        }
    }

    /* Second pass - the same context must still produce the MAC. */
    if (err == 0) {
        if (EVP_DigestSignFinal(ctx, mac, &macSz) != 1) {
            PRINT_MSG("CMAC sign after size query failed");
            err = 1;
        }
    }
    if (err == 0) {
        PRINT_BUFFER("CMAC", mac, (int)macSz);
    }

    EVP_MD_CTX_free(ctx);
    EVP_PKEY_CTX_free(pctx);
    EVP_PKEY_free(pkey);

    return err;
}

#endif /* WP_HAVE_CMAC */

