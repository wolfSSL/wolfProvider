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

int test_hmac_dup(void *data)
{
    int ret = 0;
    EVP_MAC* emac = NULL;
    EVP_MAC_CTX* src = NULL;
    EVP_MAC_CTX* dup = NULL;
    OSSL_PARAM params[3];
    char digest[] = "SHA-256";
    unsigned char key[] = "My empire of dirt";
    unsigned char prefix[] = "dup-prefix";
    unsigned char tailA[] = "-tail-a";
    unsigned char tailB[] = "-tail-b";
    unsigned char msgA[sizeof(prefix) + sizeof(tailA)];
    unsigned char msgB[sizeof(prefix) + sizeof(tailB)];
    unsigned char macA[32];
    unsigned char macB[32];
    unsigned char expA[32];
    unsigned char expB[32];
    size_t macASz = sizeof(macA);
    size_t macBSz = sizeof(macB);
    int expASz = sizeof(expA);
    int expBSz = sizeof(expB);

    (void)data;

    PRINT_MSG("Testing HMAC context dup");

    /* Build full messages for one-shot expected MAC calculations. */
    memcpy(msgA, prefix, sizeof(prefix));
    memcpy(msgA + sizeof(prefix), tailA, sizeof(tailA));
    memcpy(msgB, prefix, sizeof(prefix));
    memcpy(msgB + sizeof(prefix), tailB, sizeof(tailB));

    /* Compute expected MACs. */
    ret = test_mac_gen_mac(wpLibCtx, "SHA-256", "HMAC", key, sizeof(key),
        msgA, (int)sizeof(msgA), expA, &expASz);
    if (ret != 0) {
        PRINT_MSG("Generate expected MAC A failed");
    }
    if (ret == 0) {
        ret = test_mac_gen_mac(wpLibCtx, "SHA-256", "HMAC", key, sizeof(key),
            msgB, (int)sizeof(msgB), expB, &expBSz);
        if (ret != 0) {
            PRINT_MSG("Generate expected MAC B failed");
        }
    }

    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST,
        digest, 0);
    params[1] = OSSL_PARAM_construct_octet_string(OSSL_MAC_PARAM_KEY,
        (void*)key, sizeof(key));
    params[2] = OSSL_PARAM_construct_end();

    if (ret == 0) {
        ret = (emac = EVP_MAC_fetch(wpLibCtx, "HMAC", NULL)) == NULL;
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

int test_mac_key_match(void *data)
{
    int ret = 0;
    EVP_PKEY *pkey1 = NULL;
    EVP_PKEY *pkey2 = NULL;
    EVP_PKEY *pkey3 = NULL;
    unsigned char key1[] = "matching-key-value-1234";
    unsigned char key2[] = "different-key-value-567";

    (void)data;

    PRINT_MSG("Testing MAC key match with CRYPTO_memcmp");

    /* Create two keys with the same key material. */
    pkey1 = EVP_PKEY_new_raw_private_key_ex(wpLibCtx, "HMAC", NULL,
        key1, sizeof(key1));
    if (pkey1 == NULL) {
        PRINT_MSG("Failed to create pkey1");
        ret = 1;
    }
    if (ret == 0) {
        pkey2 = EVP_PKEY_new_raw_private_key_ex(wpLibCtx, "HMAC", NULL,
            key1, sizeof(key1));
        if (pkey2 == NULL) {
            PRINT_MSG("Failed to create pkey2");
            ret = 1;
        }
    }

    /* Verify same keys match. */
    if (ret == 0) {
        if (EVP_PKEY_eq(pkey1, pkey2) != 1) {
            PRINT_MSG("Same keys should match but don't");
            ret = -1;
        }
    }

    /* Create a third key with different material. */
    if (ret == 0) {
        pkey3 = EVP_PKEY_new_raw_private_key_ex(wpLibCtx, "HMAC", NULL,
            key2, sizeof(key2));
        if (pkey3 == NULL) {
            PRINT_MSG("Failed to create pkey3");
            ret = 1;
        }
    }

    /* Verify different keys don't match. */
    if (ret == 0) {
        if (EVP_PKEY_eq(pkey1, pkey3) == 1) {
            PRINT_MSG("Different keys should not match but do");
            ret = -1;
        }
    }

    EVP_PKEY_free(pkey3);
    EVP_PKEY_free(pkey2);
    EVP_PKEY_free(pkey1);

    return ret;
}

int test_mac_sig_dup(void *data)
{
    int ret = 0;
    EVP_MD_CTX *ctx = NULL;
    EVP_MD_CTX *dupCtx = NULL;
    EVP_PKEY_CTX *pctx = NULL;
    EVP_PKEY *pkey = NULL;
    unsigned char key[] = "My empire of dirt";
    unsigned char prefix[] = "dup-prefix";
    unsigned char tailA[] = "-tail-a";
    unsigned char tailB[] = "-tail-b";
    unsigned char msgA[sizeof(prefix) + sizeof(tailA)];
    unsigned char msgB[sizeof(prefix) + sizeof(tailB)];
    unsigned char macA[64];
    unsigned char macB[64];
    unsigned char expA[64];
    unsigned char expB[64];
    size_t macASz = sizeof(macA);
    size_t macBSz = sizeof(macB);
    int expASz = sizeof(expA);
    int expBSz = sizeof(expB);

    (void)data;

    PRINT_MSG("Testing MAC sig context dup (ref counting)");

    /* Build full messages for expected MAC computation. */
    memcpy(msgA, prefix, sizeof(prefix));
    memcpy(msgA + sizeof(prefix), tailA, sizeof(tailA));
    memcpy(msgB, prefix, sizeof(prefix));
    memcpy(msgB + sizeof(prefix), tailB, sizeof(tailB));

    /* Compute expected MACs via one-shot HMAC. */
    ret = test_mac_gen_mac(wpLibCtx, "SHA-256", "HMAC", key, sizeof(key),
        msgA, (int)sizeof(msgA), expA, &expASz);
    if (ret == 0) {
        ret = test_mac_gen_mac(wpLibCtx, "SHA-256", "HMAC", key, sizeof(key),
            msgB, (int)sizeof(msgB), expB, &expBSz);
    }

    if (ret == 0) {
        pkey = EVP_PKEY_new_raw_private_key_ex(wpLibCtx, "HMAC", NULL,
            key, sizeof(key));
        if (pkey == NULL) {
            PRINT_MSG("Failed to create HMAC pkey");
            ret = 1;
        }
    }

    if (ret == 0) {
        ctx = EVP_MD_CTX_new();
        if (ctx == NULL) {
            ret = 1;
        }
    }
    if (ret == 0) {
        ret = EVP_DigestSignInit_ex(ctx, &pctx, "SHA-256", wpLibCtx, NULL,
            pkey, NULL) != 1;
    }
    if (ret == 0) {
        ret = EVP_DigestSignUpdate(ctx, prefix, sizeof(prefix)) != 1;
    }

    /* Duplicate the signing context mid-stream. */
    if (ret == 0) {
        dupCtx = EVP_MD_CTX_new();
        if (dupCtx == NULL) {
            ret = 1;
        }
    }
    if (ret == 0) {
        ret = EVP_MD_CTX_copy_ex(dupCtx, ctx) != 1;
    }

    /* Feed different tails and finalize. */
    if (ret == 0) {
        ret = EVP_DigestSignUpdate(ctx, tailA, sizeof(tailA)) != 1;
    }
    if (ret == 0) {
        ret = EVP_DigestSignFinal(ctx, macA, &macASz) != 1;
    }
    if (ret == 0) {
        ret = EVP_DigestSignUpdate(dupCtx, tailB, sizeof(tailB)) != 1;
    }
    if (ret == 0) {
        ret = EVP_DigestSignFinal(dupCtx, macB, &macBSz) != 1;
    }

    /* Verify each branch matches its expected MAC. */
    if (ret == 0) {
        if ((macASz != (size_t)expASz) || (memcmp(macA, expA, macASz) != 0)) {
            PRINT_MSG("Source sig context MAC mismatch after dup");
            ret = -1;
        }
    }
    if (ret == 0) {
        if ((macBSz != (size_t)expBSz) || (memcmp(macB, expB, macBSz) != 0)) {
            PRINT_MSG("Duplicated sig context MAC mismatch");
            ret = -1;
        }
    }

    EVP_MD_CTX_free(dupCtx);
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);

    return ret;
}

#endif /* WP_HAVE_HMAC */

