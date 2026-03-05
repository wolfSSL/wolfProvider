/* test_gmac.c
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

#ifdef WP_HAVE_GMAC

static int test_gmac_gen_mac(OSSL_LIB_CTX* libCtx, const char *c,
    unsigned char* iv, int ivSz, unsigned char *key, int keySz,
    unsigned char *msg, int len, unsigned char *out, int *outLen)
{
    int err;
    EVP_MAC*      emac = NULL;
    EVP_MAC_CTX*  mctx = NULL;
    size_t        outSz;
    OSSL_PARAM    params[4];

    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_CIPHER,
        (char*)c, 0);
    params[1] = OSSL_PARAM_construct_octet_string(OSSL_MAC_PARAM_KEY,
        (void*)key, keySz);
    params[2] = OSSL_PARAM_construct_octet_string(OSSL_MAC_PARAM_IV,
        (void*)iv, ivSz);
    params[3] = OSSL_PARAM_construct_end();

    err = (emac = EVP_MAC_fetch(libCtx, "GMAC", NULL)) == NULL;
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
        PRINT_BUFFER("GMAC", out, *outLen);
    }

    EVP_MAC_CTX_free(mctx);
    EVP_MAC_free(emac);

    return err;
}

static int test_gmac_create_helper(unsigned char *in, int inSz,
    unsigned char* iv, int ivSz, unsigned char *key, int keySz, const char* c)
{
    int ret;
    unsigned char exp[16];
    int expLen = sizeof(exp);
    unsigned char mac[16];
    int macLen = sizeof(mac);

    /* generate mac using OpenSSL */
    ret = test_gmac_gen_mac(osslLibCtx, c, iv, ivSz, key, keySz, in, inSz,
        exp, &expLen);
    if (ret != 0) {
        PRINT_MSG("Generate MAC using OpenSSL failed");
    }

    if (ret == 0) {
        memset(mac, 0, sizeof(mac));
        ret = test_gmac_gen_mac(wpLibCtx, c, iv, ivSz, key, keySz, in, inSz,
            mac, &macLen);
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

int test_gmac_create(void *data)
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
    unsigned char iv[] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x00, 0x01, 0x02, 0x03
    };
    int ivSz;

    (void)data;

    inSz = sizeof(in);
    ivSz = sizeof(iv);

    PRINT_MSG("Testing with 256 bit KEY");
    keySz = 32;
    ret = test_gmac_create_helper(in, inSz, iv, ivSz, key, keySz,
        "AES-256-GCM");

    if (ret == 0) {
        PRINT_MSG("Testing with 128 bit KEY");
        keySz = 16;
        ret = test_gmac_create_helper(in, inSz, iv, ivSz, key, keySz,
            "AES-128-GCM");
    }

    if (ret == 0) {
        PRINT_MSG("Testing with a 192 bit KEY");
        keySz = 24;
        ret = test_gmac_create_helper(in, inSz, iv, ivSz, key, keySz,
            "AES-192-GCM");
    }

    return ret;
}

int test_gmac_dup(void *data)
{
    int ret = 0;
    EVP_MAC* emac = NULL;
    EVP_MAC_CTX* src = NULL;
    EVP_MAC_CTX* dup = NULL;
    OSSL_PARAM params[4];
    char cipher[] = "AES-256-GCM";
    unsigned char key[] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07
    };
    unsigned char iv[] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x00, 0x01, 0x02, 0x03
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

    /* Build full messages used for one-shot expected MAC calculations. */
    memcpy(msgA, prefix, sizeof(prefix));
    memcpy(msgA + sizeof(prefix), tailA, sizeof(tailA));
    memcpy(msgB, prefix, sizeof(prefix));
    memcpy(msgB + sizeof(prefix), tailB, sizeof(tailB));

    /* Compute expected MACs for each post-duplication branch. */
    ret = test_gmac_gen_mac(wpLibCtx, cipher, iv, (int)sizeof(iv), key,
        (int)sizeof(key), msgA, (int)sizeof(msgA), expA, &expASz);
    if (ret != 0) {
        PRINT_MSG("Generate expected MAC A failed");
    }
    if (ret == 0) {
        ret = test_gmac_gen_mac(wpLibCtx, cipher, iv, (int)sizeof(iv),
            key, (int)sizeof(key), msgB, (int)sizeof(msgB), expB, &expBSz);
        if (ret != 0) {
            PRINT_MSG("Generate expected MAC B failed");
        }
    }

    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_CIPHER,
        cipher, 0);
    params[1] = OSSL_PARAM_construct_octet_string(OSSL_MAC_PARAM_KEY,
        (void*)key, sizeof(key));
    params[2] = OSSL_PARAM_construct_octet_string(OSSL_MAC_PARAM_IV,
        (void*)iv, sizeof(iv));
    params[3] = OSSL_PARAM_construct_end();

    if (ret == 0) {
        ret = (emac = EVP_MAC_fetch(wpLibCtx, "GMAC", NULL)) == NULL;
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
    /* Duplicate after partial update so both contexts start from same state. */
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
    /* Verify each branch matches its independently generated expected MAC. */
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

#endif /* WP_HAVE_GMAC */
