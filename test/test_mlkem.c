/* test_mlkem.c
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

#include <openssl/core_names.h>
#include <openssl/param_build.h>

#ifdef WP_HAVE_MLKEM

#include <wolfssl/wolfcrypt/wc_mlkem.h>

/* Per-level metadata. */
typedef struct mlkem_test_level {
    const char* name;
    size_t pubKeySize;
    size_t privKeySize;
    size_t ctSize;
} mlkem_test_level;

static const mlkem_test_level mlkem_levels[] = {
    { "ML-KEM-512",  WC_ML_KEM_512_PUBLIC_KEY_SIZE,
        WC_ML_KEM_512_PRIVATE_KEY_SIZE, WC_ML_KEM_512_CIPHER_TEXT_SIZE },
    { "ML-KEM-768",  WC_ML_KEM_768_PUBLIC_KEY_SIZE,
        WC_ML_KEM_768_PRIVATE_KEY_SIZE, WC_ML_KEM_768_CIPHER_TEXT_SIZE },
    { "ML-KEM-1024", WC_ML_KEM_1024_PUBLIC_KEY_SIZE,
        WC_ML_KEM_1024_PRIVATE_KEY_SIZE, WC_ML_KEM_1024_CIPHER_TEXT_SIZE },
};
#define MLKEM_LEVEL_COUNT (sizeof(mlkem_levels) / sizeof(mlkem_levels[0]))


/**
 * Generate an ML-KEM key pair via wolfProvider.
 *
 * @param [in]  name  Algorithm name (e.g. "ML-KEM-512").
 * @param [out] pkey  Generated EVP_PKEY (caller frees).
 * @return  0 on success, non-zero on failure.
 */
static int wp_test_mlkem_keygen(const char* name, EVP_PKEY** pkey)
{
    int err = 0;
    EVP_PKEY_CTX* ctx = NULL;

    ctx = EVP_PKEY_CTX_new_from_name(wpLibCtx, name, NULL);
    err = (ctx == NULL);
    if (err == 0) {
        err = EVP_PKEY_keygen_init(ctx) != 1;
    }
    if (err == 0) {
        err = EVP_PKEY_keygen(ctx, pkey) != 1;
    }
    EVP_PKEY_CTX_free(ctx);
    return err;
}

/**
 * Extract the raw public key bytes from an ML-KEM EVP_PKEY.
 *
 * @param [in]  pkey  ML-KEM EVP_PKEY.
 * @param [out] out   Buffer for public key bytes (caller frees with OPENSSL_free).
 * @param [out] len   Length of returned key in bytes.
 * @return  0 on success, non-zero on failure.
 */
static int mlkem_get_pub(EVP_PKEY* pkey, unsigned char** out, size_t* len)
{
    int err = 0;
    size_t need = 0;

    err = EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_PUB_KEY,
        NULL, 0, &need) != 1;
    if (err == 0) {
        *out = (unsigned char*)OPENSSL_malloc(need);
        err = (*out == NULL);
    }
    if (err == 0) {
        err = EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_PUB_KEY,
            *out, need, len) != 1;
    }
    if (err && (*out != NULL)) {
        OPENSSL_free(*out);
        *out = NULL;
    }
    return err;
}

/**
 * Test ML-KEM key generation and that public key size matches expected.
 */
int test_mlkem_keygen(void* data)
{
    int err = 0;
    size_t i;
    EVP_PKEY* pkey1 = NULL;
    EVP_PKEY* pkey2 = NULL;
    unsigned char* pub1 = NULL;
    unsigned char* pub2 = NULL;
    size_t pub1Len = 0;
    size_t pub2Len = 0;

    (void)data;

    for (i = 0; (err == 0) && (i < MLKEM_LEVEL_COUNT); i++) {
        const mlkem_test_level* lvl = &mlkem_levels[i];
        PRINT_MSG("Keygen %s", lvl->name);

        err = wp_test_mlkem_keygen(lvl->name, &pkey1);
        if (err == 0) {
            err = wp_test_mlkem_keygen(lvl->name, &pkey2);
        }
        if (err == 0) {
            err = mlkem_get_pub(pkey1, &pub1, &pub1Len);
        }
        if (err == 0) {
            err = mlkem_get_pub(pkey2, &pub2, &pub2Len);
        }
        if (err == 0) {
            err = (pub1Len != lvl->pubKeySize);
            if (err) {
                PRINT_ERR_MSG("Unexpected pub key size: %zu vs %zu",
                    pub1Len, lvl->pubKeySize);
            }
        }
        if (err == 0) {
            err = (memcmp(pub1, pub2, pub1Len) == 0);
            if (err) {
                PRINT_ERR_MSG("Two keygens produced identical public keys");
            }
        }

        OPENSSL_free(pub1); pub1 = NULL;
        OPENSSL_free(pub2); pub2 = NULL;
        EVP_PKEY_free(pkey1); pkey1 = NULL;
        EVP_PKEY_free(pkey2); pkey2 = NULL;
    }

    return err;
}

/**
 * Test ML-KEM raw key import/export round-trip.
 *
 * For each level: keygen, export both pub and priv via EVP_PKEY_todata,
 * import into a fresh EVP_PKEY via EVP_PKEY_fromdata, re-export, and verify
 * the bytes match exactly. Proves the OSSL_PARAM marshaling for raw keys is
 * lossless in both directions.
 */
int test_mlkem_import_export_roundtrip(void* data)
{
    int err = 0;
    size_t i;
    EVP_PKEY* k1 = NULL;
    EVP_PKEY* k2 = NULL;
    EVP_PKEY_CTX* ctx = NULL;
    OSSL_PARAM* params = NULL;
    unsigned char* pub1 = NULL;
    unsigned char* pub2 = NULL;
    unsigned char* priv1 = NULL;
    unsigned char* priv2 = NULL;
    size_t pub1Len = 0, pub2Len = 0, priv1Len = 0, priv2Len = 0;

    (void)data;

    for (i = 0; (err == 0) && (i < MLKEM_LEVEL_COUNT); i++) {
        const mlkem_test_level* lvl = &mlkem_levels[i];
        PRINT_MSG("Import/export roundtrip %s", lvl->name);

        err = wp_test_mlkem_keygen(lvl->name, &k1);
        if (err == 0) {
            err = mlkem_get_pub(k1, &pub1, &pub1Len);
        }
        if (err == 0) {
            err = EVP_PKEY_get_octet_string_param(k1, OSSL_PKEY_PARAM_PRIV_KEY,
                NULL, 0, &priv1Len) != 1;
        }
        if (err == 0) {
            priv1 = (unsigned char*)OPENSSL_malloc(priv1Len);
            err = (priv1 == NULL);
        }
        if (err == 0) {
            err = EVP_PKEY_get_octet_string_param(k1, OSSL_PKEY_PARAM_PRIV_KEY,
                priv1, priv1Len, &priv1Len) != 1;
        }

        if (err == 0) {
            ctx = EVP_PKEY_CTX_new_from_name(wpLibCtx, lvl->name, NULL);
            err = (ctx == NULL) || EVP_PKEY_fromdata_init(ctx) != 1;
        }
        if (err == 0) {
            OSSL_PARAM_BLD* bld = OSSL_PARAM_BLD_new();
            err = (bld == NULL)
                || OSSL_PARAM_BLD_push_octet_string(bld,
                    OSSL_PKEY_PARAM_PUB_KEY, pub1, pub1Len) != 1
                || OSSL_PARAM_BLD_push_octet_string(bld,
                    OSSL_PKEY_PARAM_PRIV_KEY, priv1, priv1Len) != 1;
            if (err == 0) {
                params = OSSL_PARAM_BLD_to_param(bld);
                err = (params == NULL);
            }
            OSSL_PARAM_BLD_free(bld);
        }
        if (err == 0) {
            err = EVP_PKEY_fromdata(ctx, &k2, EVP_PKEY_KEYPAIR, params) != 1;
        }
        if (err == 0) {
            err = mlkem_get_pub(k2, &pub2, &pub2Len);
        }
        if (err == 0) {
            err = EVP_PKEY_get_octet_string_param(k2, OSSL_PKEY_PARAM_PRIV_KEY,
                NULL, 0, &priv2Len) != 1;
        }
        if (err == 0) {
            priv2 = (unsigned char*)OPENSSL_malloc(priv2Len);
            err = (priv2 == NULL);
        }
        if (err == 0) {
            err = EVP_PKEY_get_octet_string_param(k2, OSSL_PKEY_PARAM_PRIV_KEY,
                priv2, priv2Len, &priv2Len) != 1;
        }
        if (err == 0) {
            err = (pub1Len != pub2Len) ||
                (memcmp(pub1, pub2, pub1Len) != 0);
            if (err) PRINT_ERR_MSG("Public key roundtrip mismatch");
        }
        if (err == 0) {
            err = (priv1Len != priv2Len) ||
                (memcmp(priv1, priv2, priv1Len) != 0);
            if (err) PRINT_ERR_MSG("Private key roundtrip mismatch");
        }

        OPENSSL_free(pub1); pub1 = NULL;
        OPENSSL_free(pub2); pub2 = NULL;
        OPENSSL_clear_free(priv1, priv1Len); priv1 = NULL; priv1Len = 0;
        OPENSSL_clear_free(priv2, priv2Len); priv2 = NULL; priv2Len = 0;
        OSSL_PARAM_free(params); params = NULL;
        EVP_PKEY_CTX_free(ctx); ctx = NULL;
        EVP_PKEY_free(k1); k1 = NULL;
        EVP_PKEY_free(k2); k2 = NULL;
    }
    return err;
}

/**
 * Test ML-KEM encapsulate / decapsulate round trip via EVP_PKEY API.
 */
int test_mlkem_encap_decap(void* data)
{
    int err = 0;
    size_t i;
    EVP_PKEY* pkey = NULL;
    EVP_PKEY_CTX* ectx = NULL;
    EVP_PKEY_CTX* dctx = NULL;
    unsigned char* ct = NULL;
    unsigned char* ss1 = NULL;
    unsigned char* ss2 = NULL;
    size_t ctLen = 0;
    size_t ss1Len = 0;
    size_t ss2Len = 0;

    (void)data;

    for (i = 0; (err == 0) && (i < MLKEM_LEVEL_COUNT); i++) {
        const mlkem_test_level* lvl = &mlkem_levels[i];
        PRINT_MSG("Encap/Decap %s", lvl->name);

        err = wp_test_mlkem_keygen(lvl->name, &pkey);

        if (err == 0) {
            ectx = EVP_PKEY_CTX_new_from_pkey(wpLibCtx, pkey, NULL);
            err = (ectx == NULL);
        }
        if (err == 0) {
            err = EVP_PKEY_encapsulate_init(ectx, NULL) != 1;
        }
        if (err == 0) {
            err = EVP_PKEY_encapsulate(ectx, NULL, &ctLen, NULL, &ss1Len) != 1;
        }
        if (err == 0) {
            err = (ctLen != lvl->ctSize) || (ss1Len != 32);
        }
        if (err == 0) {
            ct = (unsigned char*)OPENSSL_malloc(ctLen);
            ss1 = (unsigned char*)OPENSSL_malloc(ss1Len);
            ss2 = (unsigned char*)OPENSSL_malloc(ss1Len);
            err = (ct == NULL) || (ss1 == NULL) || (ss2 == NULL);
        }
        if (err == 0) {
            err = EVP_PKEY_encapsulate(ectx, ct, &ctLen, ss1, &ss1Len) != 1;
        }

        if (err == 0) {
            dctx = EVP_PKEY_CTX_new_from_pkey(wpLibCtx, pkey, NULL);
            err = (dctx == NULL);
        }
        if (err == 0) {
            err = EVP_PKEY_decapsulate_init(dctx, NULL) != 1;
        }
        if (err == 0) {
            ss2Len = ss1Len;
            err = EVP_PKEY_decapsulate(dctx, ss2, &ss2Len, ct, ctLen) != 1;
        }
        if (err == 0) {
            err = (ss1Len != ss2Len) || (memcmp(ss1, ss2, ss1Len) != 0);
            if (err) {
                PRINT_ERR_MSG("Shared secrets do not match");
            }
        }

        OPENSSL_free(ct); ct = NULL;
        OPENSSL_free(ss1); ss1 = NULL;
        OPENSSL_free(ss2); ss2 = NULL;
        EVP_PKEY_CTX_free(ectx); ectx = NULL;
        EVP_PKEY_CTX_free(dctx); dctx = NULL;
        EVP_PKEY_free(pkey); pkey = NULL;
    }

    return err;
}

/**
 * Test ML-KEM decapsulate of a tampered ciphertext: must still succeed and
 * yield a different shared secret (implicit rejection).
 */
int test_mlkem_decap_tampered_ct(void* data)
{
    int err = 0;
    size_t i;
    EVP_PKEY* pkey = NULL;
    EVP_PKEY_CTX* ectx = NULL;
    EVP_PKEY_CTX* dctx = NULL;
    unsigned char* ct = NULL;
    unsigned char ss1[32];
    unsigned char ss2[32];
    size_t ctLen = 0;
    size_t ss1Len = sizeof(ss1);
    size_t ss2Len = sizeof(ss2);

    (void)data;

    for (i = 0; (err == 0) && (i < MLKEM_LEVEL_COUNT); i++) {
        const mlkem_test_level* lvl = &mlkem_levels[i];
        PRINT_MSG("Decap tampered ct %s", lvl->name);

        err = wp_test_mlkem_keygen(lvl->name, &pkey);
        if (err == 0) {
            ectx = EVP_PKEY_CTX_new_from_pkey(wpLibCtx, pkey, NULL);
            err = (ectx == NULL);
        }
        if (err == 0) {
            err = EVP_PKEY_encapsulate_init(ectx, NULL) != 1;
        }
        if (err == 0) {
            ctLen = lvl->ctSize;
            ct = (unsigned char*)OPENSSL_malloc(ctLen);
            err = (ct == NULL);
        }
        if (err == 0) {
            ss1Len = sizeof(ss1);
            err = EVP_PKEY_encapsulate(ectx, ct, &ctLen, ss1, &ss1Len) != 1;
        }
        if (err == 0) {
            ct[0] ^= 0x01;
            dctx = EVP_PKEY_CTX_new_from_pkey(wpLibCtx, pkey, NULL);
            err = (dctx == NULL);
        }
        if (err == 0) {
            err = EVP_PKEY_decapsulate_init(dctx, NULL) != 1;
        }
        if (err == 0) {
            ss2Len = sizeof(ss2);
            err = EVP_PKEY_decapsulate(dctx, ss2, &ss2Len, ct, ctLen) != 1;
            if (err) {
                PRINT_ERR_MSG("Decap of tampered ct should return implicit "
                    "secret, not fail");
            }
        }
        if (err == 0) {
            err = (ss1Len == ss2Len) &&
                (memcmp(ss1, ss2, ss1Len) == 0);
            if (err) {
                PRINT_ERR_MSG("Tampered ct produced original shared secret");
            }
        }

        OPENSSL_free(ct); ct = NULL;
        EVP_PKEY_CTX_free(ectx); ectx = NULL;
        EVP_PKEY_CTX_free(dctx); dctx = NULL;
        EVP_PKEY_free(pkey); pkey = NULL;
    }

    return err;
}

/**
 * Test ML-KEM decapsulate with a different key: produces a different secret.
 */
int test_mlkem_decap_wrong_key(void* data)
{
    int err = 0;
    size_t i;
    EVP_PKEY* keyA = NULL;
    EVP_PKEY* keyB = NULL;
    EVP_PKEY_CTX* ectx = NULL;
    EVP_PKEY_CTX* dctx = NULL;
    unsigned char* ct = NULL;
    unsigned char ss1[32];
    unsigned char ss2[32];
    size_t ctLen = 0;
    size_t ss1Len = sizeof(ss1);
    size_t ss2Len = sizeof(ss2);

    (void)data;

    for (i = 0; (err == 0) && (i < MLKEM_LEVEL_COUNT); i++) {
        const mlkem_test_level* lvl = &mlkem_levels[i];
        PRINT_MSG("Decap wrong key %s", lvl->name);

        err = wp_test_mlkem_keygen(lvl->name, &keyA);
        if (err == 0) {
            err = wp_test_mlkem_keygen(lvl->name, &keyB);
        }
        if (err == 0) {
            ectx = EVP_PKEY_CTX_new_from_pkey(wpLibCtx, keyA, NULL);
            err = (ectx == NULL);
        }
        if (err == 0) {
            err = EVP_PKEY_encapsulate_init(ectx, NULL) != 1;
        }
        if (err == 0) {
            ctLen = lvl->ctSize;
            ct = (unsigned char*)OPENSSL_malloc(ctLen);
            err = (ct == NULL);
        }
        if (err == 0) {
            ss1Len = sizeof(ss1);
            err = EVP_PKEY_encapsulate(ectx, ct, &ctLen, ss1, &ss1Len) != 1;
        }
        if (err == 0) {
            dctx = EVP_PKEY_CTX_new_from_pkey(wpLibCtx, keyB, NULL);
            err = (dctx == NULL);
        }
        if (err == 0) {
            err = EVP_PKEY_decapsulate_init(dctx, NULL) != 1;
        }
        if (err == 0) {
            ss2Len = sizeof(ss2);
            err = EVP_PKEY_decapsulate(dctx, ss2, &ss2Len, ct, ctLen) != 1;
        }
        if (err == 0) {
            err = (memcmp(ss1, ss2, ss1Len) == 0);
            if (err) {
                PRINT_ERR_MSG("Wrong-key decap produced matching secret");
            }
        }

        OPENSSL_free(ct); ct = NULL;
        EVP_PKEY_CTX_free(ectx); ectx = NULL;
        EVP_PKEY_CTX_free(dctx); dctx = NULL;
        EVP_PKEY_free(keyA); keyA = NULL;
        EVP_PKEY_free(keyB); keyB = NULL;
    }

    return err;
}

/* EVP_PKEY_dup roundtrip: dup pub must equal original pub, and an encap
 * with the dup must decap correctly with the original. */
int test_mlkem_dup(void* data)
{
    int err = 0;
    size_t i;
    EVP_PKEY* k = NULL;
    EVP_PKEY* d = NULL;
    EVP_PKEY_CTX* ectx = NULL;
    EVP_PKEY_CTX* dctx = NULL;
    unsigned char* pub1 = NULL;
    unsigned char* pub2 = NULL;
    size_t pub1Len = 0;
    size_t pub2Len = 0;
    unsigned char* ct = NULL;
    size_t ctLen = 0;
    unsigned char ss1[32];
    unsigned char ss2[32];
    size_t ss1Len;
    size_t ss2Len;

    (void)data;
    for (i = 0; (err == 0) && (i < MLKEM_LEVEL_COUNT); i++) {
        const mlkem_test_level* lvl = &mlkem_levels[i];
        PRINT_MSG("Dup %s", lvl->name);

        err = wp_test_mlkem_keygen(lvl->name, &k);
        if (err == 0) {
            d = EVP_PKEY_dup(k);
            err = (d == NULL);
        }
        if (err == 0) {
            err = EVP_PKEY_get_octet_string_param(k, OSSL_PKEY_PARAM_PUB_KEY,
                NULL, 0, &pub1Len) != 1;
        }
        if (err == 0) {
            pub1 = (unsigned char*)OPENSSL_malloc(pub1Len);
            err = (pub1 == NULL) || EVP_PKEY_get_octet_string_param(k,
                OSSL_PKEY_PARAM_PUB_KEY, pub1, pub1Len, &pub1Len) != 1;
        }
        if (err == 0) {
            err = EVP_PKEY_get_octet_string_param(d, OSSL_PKEY_PARAM_PUB_KEY,
                NULL, 0, &pub2Len) != 1;
        }
        if (err == 0) {
            pub2 = (unsigned char*)OPENSSL_malloc(pub2Len);
            err = (pub2 == NULL) || EVP_PKEY_get_octet_string_param(d,
                OSSL_PKEY_PARAM_PUB_KEY, pub2, pub2Len, &pub2Len) != 1;
        }
        if (err == 0) {
            err = (pub1Len != pub2Len) || (memcmp(pub1, pub2, pub1Len) != 0);
            if (err) PRINT_ERR_MSG("Dup pub byte mismatch");
        }
        if (err == 0) {
            ectx = EVP_PKEY_CTX_new_from_pkey(wpLibCtx, d, NULL);
            err = (ectx == NULL) || (EVP_PKEY_encapsulate_init(ectx, NULL) != 1);
        }
        if (err == 0) {
            ctLen = 0;
            ss1Len = 0;
            err = EVP_PKEY_encapsulate(ectx, NULL, &ctLen, NULL, &ss1Len) != 1;
        }
        if (err == 0) {
            ct = (unsigned char*)OPENSSL_malloc(ctLen);
            err = (ct == NULL);
        }
        if (err == 0) {
            ss1Len = sizeof(ss1);
            err = EVP_PKEY_encapsulate(ectx, ct, &ctLen, ss1, &ss1Len) != 1;
        }
        if (err == 0) {
            dctx = EVP_PKEY_CTX_new_from_pkey(wpLibCtx, k, NULL);
            err = (dctx == NULL) || (EVP_PKEY_decapsulate_init(dctx, NULL) != 1);
        }
        if (err == 0) {
            ss2Len = sizeof(ss2);
            err = EVP_PKEY_decapsulate(dctx, ss2, &ss2Len, ct, ctLen) != 1;
        }
        if (err == 0) {
            err = (ss1Len != ss2Len) || (memcmp(ss1, ss2, ss1Len) != 0);
            if (err) PRINT_ERR_MSG("Dup secret mismatch");
        }

        OPENSSL_free(pub1); pub1 = NULL; pub1Len = 0;
        OPENSSL_free(pub2); pub2 = NULL; pub2Len = 0;
        OPENSSL_free(ct); ct = NULL;
        EVP_PKEY_CTX_free(ectx); ectx = NULL;
        EVP_PKEY_CTX_free(dctx); dctx = NULL;
        EVP_PKEY_free(d); d = NULL;
        EVP_PKEY_free(k); k = NULL;
    }
    return err;
}

/* EVP_PKEY_eq: self == 1; distinct keys != 1; cross-level != 1. The non-self
 * pairs can return 0 or -1 (type mismatch) so accept any "not equal". */
int test_mlkem_match(void* data)
{
    int err = 0;
    size_t i;
    EVP_PKEY* k1 = NULL;
    EVP_PKEY* k2 = NULL;
    EVP_PKEY* k3 = NULL;

    (void)data;
    for (i = 0; (err == 0) && (i < MLKEM_LEVEL_COUNT); i++) {
        PRINT_MSG("Match %s", mlkem_levels[i].name);

        err = wp_test_mlkem_keygen(mlkem_levels[i].name, &k1);
        if (err == 0) {
            err = wp_test_mlkem_keygen(mlkem_levels[i].name, &k2);
        }
        if (err == 0) {
            err = EVP_PKEY_eq(k1, k1) != 1;
            if (err) PRINT_ERR_MSG("Self-eq failed");
        }
        if (err == 0) {
            err = EVP_PKEY_eq(k1, k2) == 1;
            if (err) PRINT_ERR_MSG("Distinct keys reported equal");
        }
        if ((err == 0) && (i + 1 < MLKEM_LEVEL_COUNT)) {
            err = wp_test_mlkem_keygen(mlkem_levels[i + 1].name, &k3);
            if (err == 0) {
                err = EVP_PKEY_eq(k1, k3) == 1;
                if (err) PRINT_ERR_MSG("Cross-level keys reported equal");
            }
            EVP_PKEY_free(k3); k3 = NULL;
        }
        EVP_PKEY_free(k1); k1 = NULL;
        EVP_PKEY_free(k2); k2 = NULL;
    }
    return err;
}

/* Decapsulate with out=NULL must return 1 and *outLen == 32. OpenSSL's wrapper
 * requires a valid ciphertext even on the size-query path, so encap first. */
int test_mlkem_decap_size_query(void* data)
{
    int err = 0;
    size_t i;
    EVP_PKEY* k = NULL;
    EVP_PKEY_CTX* ectx = NULL;
    EVP_PKEY_CTX* dctx = NULL;
    unsigned char* ct = NULL;
    size_t ctLen = 0;
    unsigned char ss[32];
    size_t ssLen;

    (void)data;
    for (i = 0; (err == 0) && (i < MLKEM_LEVEL_COUNT); i++) {
        PRINT_MSG("Decap size-query %s", mlkem_levels[i].name);

        err = wp_test_mlkem_keygen(mlkem_levels[i].name, &k);
        if (err == 0) {
            ectx = EVP_PKEY_CTX_new_from_pkey(wpLibCtx, k, NULL);
            err = (ectx == NULL) || (EVP_PKEY_encapsulate_init(ectx, NULL) != 1);
        }
        if (err == 0) {
            ctLen = 0;
            ssLen = 0;
            err = EVP_PKEY_encapsulate(ectx, NULL, &ctLen, NULL, &ssLen) != 1;
        }
        if (err == 0) {
            ct = (unsigned char*)OPENSSL_malloc(ctLen);
            err = (ct == NULL);
        }
        if (err == 0) {
            ssLen = sizeof(ss);
            err = EVP_PKEY_encapsulate(ectx, ct, &ctLen, ss, &ssLen) != 1;
        }
        if (err == 0) {
            dctx = EVP_PKEY_CTX_new_from_pkey(wpLibCtx, k, NULL);
            err = (dctx == NULL) || (EVP_PKEY_decapsulate_init(dctx, NULL) != 1);
        }
        if (err == 0) {
            ssLen = 0;
            err = EVP_PKEY_decapsulate(dctx, NULL, &ssLen, ct, ctLen) != 1;
        }
        if (err == 0) {
            err = (ssLen != 32);
            if (err) PRINT_ERR_MSG("Decap size-query returned %zu", ssLen);
        }
        OPENSSL_free(ct); ct = NULL;
        EVP_PKEY_CTX_free(ectx); ectx = NULL;
        EVP_PKEY_CTX_free(dctx); dctx = NULL;
        EVP_PKEY_free(k); k = NULL;
    }
    return err;
}

/* BITS / SECURITY_BITS / MAX_SIZE getters. */
int test_mlkem_get_params(void* data)
{
    /* FIPS 203: 512 -> 128 sec bits, 768 -> 192, 1024 -> 256 */
    static const int secBits[] = { 128, 192, 256 };
    int err = 0;
    size_t i;
    EVP_PKEY* k = NULL;

    (void)data;
    for (i = 0; (err == 0) && (i < MLKEM_LEVEL_COUNT); i++) {
        const mlkem_test_level* lvl = &mlkem_levels[i];
        PRINT_MSG("Params %s", lvl->name);

        err = wp_test_mlkem_keygen(lvl->name, &k);
        if (err == 0) {
            err = EVP_PKEY_get_bits(k) != (int)(lvl->pubKeySize * 8);
            if (err) PRINT_ERR_MSG("Wrong BITS");
        }
        if (err == 0) {
            err = EVP_PKEY_get_security_bits(k) != secBits[i];
            if (err) PRINT_ERR_MSG("Wrong SECURITY_BITS");
        }
        if (err == 0) {
            err = EVP_PKEY_get_size(k) != (int)lvl->ctSize;
            if (err) PRINT_ERR_MSG("Wrong MAX_SIZE");
        }
        EVP_PKEY_free(k); k = NULL;
    }
    return err;
}

/* Negative: import priv + mutated pub. Expect fromdata to FAIL. */
int test_mlkem_import_mismatched_pubpriv(void* data)
{
    int err = 0;
    size_t i;
    EVP_PKEY* k = NULL;
    EVP_PKEY* k2 = NULL;
    EVP_PKEY_CTX* ctx = NULL;
    OSSL_PARAM* params = NULL;
    OSSL_PARAM_BLD* bld;
    unsigned char* pub = NULL;
    unsigned char* priv = NULL;
    size_t pubLen = 0;
    size_t privLen = 0;
    int rc;

    (void)data;
    for (i = 0; (err == 0) && (i < MLKEM_LEVEL_COUNT); i++) {
        const mlkem_test_level* lvl = &mlkem_levels[i];
        PRINT_MSG("Mismatched pub/priv %s", lvl->name);

        err = wp_test_mlkem_keygen(lvl->name, &k);
        if (err == 0) {
            err = EVP_PKEY_get_octet_string_param(k, OSSL_PKEY_PARAM_PUB_KEY,
                NULL, 0, &pubLen) != 1;
        }
        if (err == 0) {
            pub = (unsigned char*)OPENSSL_malloc(pubLen);
            err = (pub == NULL) || EVP_PKEY_get_octet_string_param(k,
                OSSL_PKEY_PARAM_PUB_KEY, pub, pubLen, &pubLen) != 1;
        }
        if (err == 0) {
            err = EVP_PKEY_get_octet_string_param(k, OSSL_PKEY_PARAM_PRIV_KEY,
                NULL, 0, &privLen) != 1;
        }
        if (err == 0) {
            priv = (unsigned char*)OPENSSL_malloc(privLen);
            err = (priv == NULL) || EVP_PKEY_get_octet_string_param(k,
                OSSL_PKEY_PARAM_PRIV_KEY, priv, privLen, &privLen) != 1;
        }
        if (err == 0) {
            pub[0] ^= 0x01;
        }
        if (err == 0) {
            ctx = EVP_PKEY_CTX_new_from_name(wpLibCtx, lvl->name, NULL);
            err = (ctx == NULL) || (EVP_PKEY_fromdata_init(ctx) != 1);
        }
        if (err == 0) {
            bld = OSSL_PARAM_BLD_new();
            err = (bld == NULL)
                || OSSL_PARAM_BLD_push_octet_string(bld,
                    OSSL_PKEY_PARAM_PUB_KEY, pub, pubLen) != 1
                || OSSL_PARAM_BLD_push_octet_string(bld,
                    OSSL_PKEY_PARAM_PRIV_KEY, priv, privLen) != 1;
            if (err == 0) {
                params = OSSL_PARAM_BLD_to_param(bld);
                err = (params == NULL);
            }
            OSSL_PARAM_BLD_free(bld);
        }
        if (err == 0) {
            rc = EVP_PKEY_fromdata(ctx, &k2, EVP_PKEY_KEYPAIR, params);
            err = (rc == 1);
            if (err) PRINT_ERR_MSG("Mismatched import succeeded");
        }

        OPENSSL_free(pub); pub = NULL; pubLen = 0;
        OPENSSL_clear_free(priv, privLen); priv = NULL; privLen = 0;
        OSSL_PARAM_free(params); params = NULL;
        EVP_PKEY_CTX_free(ctx); ctx = NULL;
        EVP_PKEY_free(k); k = NULL;
        EVP_PKEY_free(k2); k2 = NULL;
    }
    return err;
}

#endif /* WP_HAVE_MLKEM */
