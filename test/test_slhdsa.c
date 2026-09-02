/* test_slhdsa.c
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
#include <openssl/err.h>
#include <openssl/param_build.h>
#include <openssl/encoder.h>
#include <openssl/decoder.h>
#include <openssl/x509.h>

#if defined(WP_HAVE_SLHDSA) && defined(WP_SLHDSA_TEST_SETS)

#include <wolfssl/wolfcrypt/wc_slhdsa.h>

/* Per-parameter-set metadata. */
typedef struct slhdsa_test_set {
    const char* name;
    size_t pubKeySize;
    size_t privKeySize;
    size_t sigSize;
    int securityBits;
    int securityCategory;
} slhdsa_test_set;

#ifdef WP_HAVE_SLHDSA_PRIVATE
/* Every parameter set registered by wp_slhdsa_kmgmt.c. */
static const slhdsa_test_set slhdsa_all_sets[] = {
#ifdef WP_HAVE_SLH_DSA_SHA2_128F
    { "SLH-DSA-SHA2-128f", WC_SLHDSA_SHA2_128F_PUB_LEN,
      WC_SLHDSA_SHA2_128F_PRIV_LEN, WC_SLHDSA_SHA2_128F_SIG_LEN, 128, 1 },
#endif
#ifdef WP_HAVE_SLH_DSA_SHA2_128S
    { "SLH-DSA-SHA2-128s", WC_SLHDSA_SHA2_128S_PUB_LEN,
      WC_SLHDSA_SHA2_128S_PRIV_LEN, WC_SLHDSA_SHA2_128S_SIG_LEN, 128, 1 },
#endif
#ifdef WP_HAVE_SLH_DSA_SHA2_192F
    { "SLH-DSA-SHA2-192f", WC_SLHDSA_SHA2_192F_PUB_LEN,
      WC_SLHDSA_SHA2_192F_PRIV_LEN, WC_SLHDSA_SHA2_192F_SIG_LEN, 192, 3 },
#endif
#ifdef WP_HAVE_SLH_DSA_SHA2_192S
    { "SLH-DSA-SHA2-192s", WC_SLHDSA_SHA2_192S_PUB_LEN,
      WC_SLHDSA_SHA2_192S_PRIV_LEN, WC_SLHDSA_SHA2_192S_SIG_LEN, 192, 3 },
#endif
#ifdef WP_HAVE_SLH_DSA_SHA2_256F
    { "SLH-DSA-SHA2-256f", WC_SLHDSA_SHA2_256F_PUB_LEN,
      WC_SLHDSA_SHA2_256F_PRIV_LEN, WC_SLHDSA_SHA2_256F_SIG_LEN, 256, 5 },
#endif
#ifdef WP_HAVE_SLH_DSA_SHA2_256S
    { "SLH-DSA-SHA2-256s", WC_SLHDSA_SHA2_256S_PUB_LEN,
      WC_SLHDSA_SHA2_256S_PRIV_LEN, WC_SLHDSA_SHA2_256S_SIG_LEN, 256, 5 },
#endif
#ifdef WP_HAVE_SLH_DSA_SHAKE_128F
    { "SLH-DSA-SHAKE-128f", WC_SLHDSA_SHAKE128F_PUB_LEN,
      WC_SLHDSA_SHAKE128F_PRIV_LEN, WC_SLHDSA_SHAKE128F_SIG_LEN, 128, 1 },
#endif
#ifdef WP_HAVE_SLH_DSA_SHAKE_128S
    { "SLH-DSA-SHAKE-128s", WC_SLHDSA_SHAKE128S_PUB_LEN,
      WC_SLHDSA_SHAKE128S_PRIV_LEN, WC_SLHDSA_SHAKE128S_SIG_LEN, 128, 1 },
#endif
#ifdef WP_HAVE_SLH_DSA_SHAKE_192F
    { "SLH-DSA-SHAKE-192f", WC_SLHDSA_SHAKE192F_PUB_LEN,
      WC_SLHDSA_SHAKE192F_PRIV_LEN, WC_SLHDSA_SHAKE192F_SIG_LEN, 192, 3 },
#endif
#ifdef WP_HAVE_SLH_DSA_SHAKE_192S
    { "SLH-DSA-SHAKE-192s", WC_SLHDSA_SHAKE192S_PUB_LEN,
      WC_SLHDSA_SHAKE192S_PRIV_LEN, WC_SLHDSA_SHAKE192S_SIG_LEN, 192, 3 },
#endif
#ifdef WP_HAVE_SLH_DSA_SHAKE_256F
    { "SLH-DSA-SHAKE-256f", WC_SLHDSA_SHAKE256F_PUB_LEN,
      WC_SLHDSA_SHAKE256F_PRIV_LEN, WC_SLHDSA_SHAKE256F_SIG_LEN, 256, 5 },
#endif
#ifdef WP_HAVE_SLH_DSA_SHAKE_256S
    { "SLH-DSA-SHAKE-256s", WC_SLHDSA_SHAKE256S_PUB_LEN,
      WC_SLHDSA_SHAKE256S_PRIV_LEN, WC_SLHDSA_SHAKE256S_SIG_LEN, 256, 5 },
#endif
};
#define SLHDSA_ALL_SET_COUNT \
    (sizeof(slhdsa_all_sets) / sizeof(slhdsa_all_sets[0]))
#endif

/* A representative spread rather than all 12: both hash families, both the
 * small and fast tradeoffs, and all three security parameters. The 's' sets
 * sign roughly ten times slower, so only one is in the default matrix. */
#ifdef WOLFPROV_QUICKTEST
    #if !defined(WP_HAVE_SLH_DSA_SHA2_128F) && \
        !defined(WP_HAVE_SLH_DSA_SHAKE_128F)
        #define WP_SLHDSA_TEST_NEEDS_FALLBACK
    #endif
#elif !defined(WP_HAVE_SLH_DSA_SHA2_128F) && \
      !defined(WP_HAVE_SLH_DSA_SHAKE_128F) && \
      !defined(WP_HAVE_SLH_DSA_SHA2_128S) && \
      !defined(WP_HAVE_SLH_DSA_SHAKE_192F) && \
      !defined(WP_HAVE_SLH_DSA_SHAKE_256F)
    #define WP_SLHDSA_TEST_NEEDS_FALLBACK
#endif
static const slhdsa_test_set slhdsa_sets[] = {
#ifdef WP_HAVE_SLH_DSA_SHA2_128F
    { "SLH-DSA-SHA2-128f", WC_SLHDSA_SHA2_128F_PUB_LEN,
      WC_SLHDSA_SHA2_128F_PRIV_LEN, WC_SLHDSA_SHA2_128F_SIG_LEN, 128, 1 },
#endif
#ifdef WP_HAVE_SLH_DSA_SHAKE_128F
    { "SLH-DSA-SHAKE-128f", WC_SLHDSA_SHAKE128F_PUB_LEN,
      WC_SLHDSA_SHAKE128F_PRIV_LEN, WC_SLHDSA_SHAKE128F_SIG_LEN, 128, 1 },
#endif
#ifndef WOLFPROV_QUICKTEST
#ifdef WP_HAVE_SLH_DSA_SHA2_128S
    { "SLH-DSA-SHA2-128s", WC_SLHDSA_SHA2_128S_PUB_LEN,
      WC_SLHDSA_SHA2_128S_PRIV_LEN, WC_SLHDSA_SHA2_128S_SIG_LEN, 128, 1 },
#endif
#ifdef WP_HAVE_SLH_DSA_SHAKE_192F
    { "SLH-DSA-SHAKE-192f", WC_SLHDSA_SHAKE192F_PUB_LEN,
      WC_SLHDSA_SHAKE192F_PRIV_LEN, WC_SLHDSA_SHAKE192F_SIG_LEN, 192, 3 },
#endif
#ifdef WP_HAVE_SLH_DSA_SHAKE_256F
    { "SLH-DSA-SHAKE-256f", WC_SLHDSA_SHAKE256F_PUB_LEN,
      WC_SLHDSA_SHAKE256F_PRIV_LEN, WC_SLHDSA_SHAKE256F_SIG_LEN, 256, 5 },
#endif
#endif /* !WOLFPROV_QUICKTEST */
#ifdef WP_SLHDSA_TEST_NEEDS_FALLBACK
    #if defined(WP_HAVE_SLH_DSA_SHA2_128S)
    { "SLH-DSA-SHA2-128s", WC_SLHDSA_SHA2_128S_PUB_LEN,
      WC_SLHDSA_SHA2_128S_PRIV_LEN, WC_SLHDSA_SHA2_128S_SIG_LEN, 128, 1 },
    #elif defined(WP_HAVE_SLH_DSA_SHA2_192F)
    { "SLH-DSA-SHA2-192f", WC_SLHDSA_SHA2_192F_PUB_LEN,
      WC_SLHDSA_SHA2_192F_PRIV_LEN, WC_SLHDSA_SHA2_192F_SIG_LEN, 192, 3 },
    #elif defined(WP_HAVE_SLH_DSA_SHA2_256F)
    { "SLH-DSA-SHA2-256f", WC_SLHDSA_SHA2_256F_PUB_LEN,
      WC_SLHDSA_SHA2_256F_PRIV_LEN, WC_SLHDSA_SHA2_256F_SIG_LEN, 256, 5 },
    #elif defined(WP_HAVE_SLH_DSA_SHAKE_128S)
    { "SLH-DSA-SHAKE-128s", WC_SLHDSA_SHAKE128S_PUB_LEN,
      WC_SLHDSA_SHAKE128S_PRIV_LEN, WC_SLHDSA_SHAKE128S_SIG_LEN, 128, 1 },
    #elif defined(WP_HAVE_SLH_DSA_SHAKE_192F)
    { "SLH-DSA-SHAKE-192f", WC_SLHDSA_SHAKE192F_PUB_LEN,
      WC_SLHDSA_SHAKE192F_PRIV_LEN, WC_SLHDSA_SHAKE192F_SIG_LEN, 192, 3 },
    #elif defined(WP_HAVE_SLH_DSA_SHAKE_192S)
    { "SLH-DSA-SHAKE-192s", WC_SLHDSA_SHAKE192S_PUB_LEN,
      WC_SLHDSA_SHAKE192S_PRIV_LEN, WC_SLHDSA_SHAKE192S_SIG_LEN, 192, 3 },
    #elif defined(WP_HAVE_SLH_DSA_SHAKE_256F)
    { "SLH-DSA-SHAKE-256f", WC_SLHDSA_SHAKE256F_PUB_LEN,
      WC_SLHDSA_SHAKE256F_PRIV_LEN, WC_SLHDSA_SHAKE256F_SIG_LEN, 256, 5 },
    #elif defined(WP_HAVE_SLH_DSA_SHAKE_256S)
    { "SLH-DSA-SHAKE-256s", WC_SLHDSA_SHAKE256S_PUB_LEN,
      WC_SLHDSA_SHAKE256S_PRIV_LEN, WC_SLHDSA_SHAKE256S_SIG_LEN, 256, 5 },
    #elif defined(WP_HAVE_SLH_DSA_SHA2_192S)
    { "SLH-DSA-SHA2-192s", WC_SLHDSA_SHA2_192S_PUB_LEN,
      WC_SLHDSA_SHA2_192S_PRIV_LEN, WC_SLHDSA_SHA2_192S_SIG_LEN, 192, 3 },
    #elif defined(WP_HAVE_SLH_DSA_SHA2_256S)
    { "SLH-DSA-SHA2-256s", WC_SLHDSA_SHA2_256S_PUB_LEN,
      WC_SLHDSA_SHA2_256S_PRIV_LEN, WC_SLHDSA_SHA2_256S_SIG_LEN, 256, 5 },
    #endif
#endif
};
#undef WP_SLHDSA_TEST_NEEDS_FALLBACK
#define SLHDSA_SET_COUNT (sizeof(slhdsa_sets) / sizeof(slhdsa_sets[0]))

int test_slhdsa_public_keymgmt(void* data)
{
    int err = 0;
    const slhdsa_test_set* set = &slhdsa_sets[0];
    EVP_PKEY* key = NULL;
    EVP_PKEY* dup = NULL;
#ifdef WP_HAVE_SLHDSA_PRIVATE
    EVP_PKEY* paramsKey = NULL;
#endif
    EVP_PKEY_CTX* ctx = NULL;
#ifdef WP_HAVE_SLHDSA_PRIVATE
    BIO* bio = NULL;
#endif
    unsigned char pub[64];
    unsigned char out[64];
    size_t outLen = 0;
    size_t privLen = 0;
    OSSL_PARAM params[2];
    size_t i;

    (void)data;

    PRINT_MSG("Public key management %s", set->name);
    for (i = 0; i < set->pubKeySize; i++) {
        pub[i] = (unsigned char)(i + 1);
    }
    params[0] = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PUB_KEY,
        pub, set->pubKeySize);
    params[1] = OSSL_PARAM_construct_end();

    ctx = EVP_PKEY_CTX_new_from_name(wpLibCtx, set->name, NULL);
    err = (ctx == NULL);
    if (err == 0) {
        err = EVP_PKEY_fromdata_init(ctx) != 1;
    }
    if (err == 0) {
        err = EVP_PKEY_fromdata(ctx, &key, EVP_PKEY_PUBLIC_KEY, params) != 1;
    }
    if (err == 0) {
        err = EVP_PKEY_get_octet_string_param(key, OSSL_PKEY_PARAM_PUB_KEY,
            out, sizeof(out), &outLen) != 1;
    }
    if (err == 0) {
        err = (outLen != set->pubKeySize) ||
            (XMEMCMP(pub, out, outLen) != 0);
    }
    if (err == 0) {
        err = EVP_PKEY_get_octet_string_param(key, OSSL_PKEY_PARAM_PRIV_KEY,
            NULL, 0, &privLen) == 1;
        ERR_clear_error();
    }
    if (err == 0) {
        EVP_PKEY_CTX_free(ctx);
        ctx = EVP_PKEY_CTX_new_from_pkey(wpLibCtx, key, NULL);
        err = (ctx == NULL);
    }
    if (err == 0) {
        err = EVP_PKEY_public_check(ctx) != 1;
    }
    if (err == 0) {
        err = EVP_PKEY_private_check(ctx) == 1;
        ERR_clear_error();
    }
    if (err == 0) {
        err = EVP_PKEY_pairwise_check(ctx) == 1;
        ERR_clear_error();
    }
    if (err == 0) {
        dup = EVP_PKEY_dup(key);
        err = (dup == NULL);
    }
    if (err == 0) {
        err = EVP_PKEY_eq(key, dup) != 1;
    }
#ifdef WP_HAVE_SLHDSA_PRIVATE
    if (err == 0) {
        EVP_PKEY_CTX_free(ctx);
        ctx = EVP_PKEY_CTX_new_from_name(wpLibCtx, set->name, NULL);
        err = (ctx == NULL);
    }
    if (err == 0) {
        err = EVP_PKEY_paramgen_init(ctx) != 1;
    }
    if (err == 0) {
        err = EVP_PKEY_paramgen(ctx, &paramsKey) != 1;
    }
    if (err == 0) {
        bio = BIO_new(BIO_s_mem());
        err = (bio == NULL);
    }
    if (err == 0) {
        err = PEM_write_bio_PUBKEY(bio, paramsKey) == 1;
        if (err) {
            PRINT_ERR_MSG("Parameter-only key encoded as a public key");
        }
        ERR_clear_error();
    }

    BIO_free(bio);
    EVP_PKEY_free(paramsKey);
#endif
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(dup);
    EVP_PKEY_free(key);
    return err;
}

#ifdef WP_HAVE_SLHDSA_PRIVATE


static const unsigned char slhdsa_test_msg[] =
    "wolfProvider SLH-DSA test message bytes for FIPS 205 sign/verify";
#define SLHDSA_TEST_MSG_LEN (sizeof(slhdsa_test_msg) - 1)


/**
 * Generate an SLH-DSA key pair via wolfProvider.
 *
 * @param [in]  name  Algorithm name (e.g. "SLH-DSA-SHA2-128f").
 * @param [out] pkey  Generated EVP_PKEY (caller frees).
 * @return  0 on success, non-zero on failure.
 */
static int slhdsa_keygen_ex(OSSL_LIB_CTX* libCtx, const char* prop,
    const char* name, const unsigned char* seed, size_t seedLen,
    EVP_PKEY** pkey)
{
    int err = 0;
    EVP_PKEY_CTX* ctx = NULL;
    OSSL_PARAM params[2];

    ctx = EVP_PKEY_CTX_new_from_name(libCtx, name, prop);
    err = (ctx == NULL);
    if (err == 0) {
        err = EVP_PKEY_keygen_init(ctx) != 1;
    }
    if ((err == 0) && (seed != NULL)) {
        params[0] = OSSL_PARAM_construct_octet_string(
            OSSL_PKEY_PARAM_SLH_DSA_SEED, (void*)seed, seedLen);
        params[1] = OSSL_PARAM_construct_end();
        err = EVP_PKEY_CTX_set_params(ctx, params) != 1;
    }
    if (err == 0) {
        err = EVP_PKEY_keygen(ctx, pkey) != 1;
    }
    EVP_PKEY_CTX_free(ctx);
    return err;
}

static int slhdsa_keygen(const char* name, EVP_PKEY** pkey)
{
    return slhdsa_keygen_ex(wpLibCtx, NULL, name, NULL, 0, pkey);
}

/**
 * Extract a raw octet-string key parameter from an SLH-DSA EVP_PKEY.
 */
static int slhdsa_get_raw(EVP_PKEY* pkey, const char* param,
    unsigned char** out, size_t* len)
{
    int err = 0;
    size_t need = 0;

    *out = NULL;
    err = EVP_PKEY_get_octet_string_param(pkey, param, NULL, 0, &need) != 1;
    if (err == 0) {
        *out = (unsigned char*)OPENSSL_malloc(need);
        err = (*out == NULL);
    }
    if (err == 0) {
        err = EVP_PKEY_get_octet_string_param(pkey, param, *out, need,
            len) != 1;
    }
    if (err && (*out != NULL)) {
        OPENSSL_free(*out);
        *out = NULL;
    }
    return err;
}

static int slhdsa_get_pub(EVP_PKEY* pkey, unsigned char** out, size_t* len)
{
    return slhdsa_get_raw(pkey, OSSL_PKEY_PARAM_PUB_KEY, out, len);
}

/**
 * Sign a message with the given SLH-DSA EVP_PKEY using the digest-sign API
 * (which for SLH-DSA passes the whole message to the one-shot signer).
 */
static int slhdsa_sign_msg(EVP_PKEY* pkey, const unsigned char* msg,
    size_t msgLen, unsigned char** sigOut, size_t* sigLenOut)
{
    int err = 0;
    EVP_MD_CTX* mdctx = NULL;
    size_t sigLen = 0;
    unsigned char* sig = NULL;

    mdctx = EVP_MD_CTX_new();
    err = (mdctx == NULL);
    if (err == 0) {
        err = EVP_DigestSignInit_ex(mdctx, NULL, NULL, wpLibCtx, NULL, pkey,
            NULL) != 1;
    }
    if (err == 0) {
        err = EVP_DigestSign(mdctx, NULL, &sigLen, msg, msgLen) != 1;
    }
    if (err == 0) {
        sig = (unsigned char*)OPENSSL_malloc(sigLen);
        err = (sig == NULL);
    }
    if (err == 0) {
        err = EVP_DigestSign(mdctx, sig, &sigLen, msg, msgLen) != 1;
    }
    if (err == 0) {
        *sigOut = sig;
        *sigLenOut = sigLen;
    }
    else {
        OPENSSL_free(sig);
    }
    EVP_MD_CTX_free(mdctx);
    return err;
}

/**
 * Verify a signature on a message with the given SLH-DSA EVP_PKEY.
 *
 * @return  1 if verified, 0 if not (does not set err on bad sig).
 */
static int slhdsa_verify_msg(EVP_PKEY* pkey, const unsigned char* msg,
    size_t msgLen, const unsigned char* sig, size_t sigLen)
{
    int ok = 0;
    int rc;
    EVP_MD_CTX* mdctx = NULL;

    mdctx = EVP_MD_CTX_new();
    if (mdctx == NULL) {
        return 0;
    }
    rc = EVP_DigestVerifyInit_ex(mdctx, NULL, NULL, wpLibCtx, NULL, pkey, NULL);
    if (rc == 1) {
        rc = EVP_DigestVerify(mdctx, sig, sigLen, msg, msgLen);
        if (rc == 1) {
            ok = 1;
        }
    }
    EVP_MD_CTX_free(mdctx);
    return ok;
}

/**
 * Test SLH-DSA key generation; verify key sizes and that two keys differ.
 */
int test_slhdsa_keygen(void* data)
{
    int err = 0;
    size_t i;
    EVP_PKEY* k1 = NULL;
    EVP_PKEY* k2 = NULL;
    unsigned char* p1 = NULL;
    unsigned char* p2 = NULL;
    size_t p1Len = 0;
    size_t p2Len = 0;

    (void)data;

    for (i = 0; (err == 0) && (i < SLHDSA_SET_COUNT); i++) {
        const slhdsa_test_set* set = &slhdsa_sets[i];
        PRINT_MSG("Keygen %s", set->name);

        err = slhdsa_keygen(set->name, &k1);
        if (err == 0) {
            err = slhdsa_keygen(set->name, &k2);
        }
        if (err == 0) {
            err = slhdsa_get_pub(k1, &p1, &p1Len);
        }
        if (err == 0) {
            err = slhdsa_get_pub(k2, &p2, &p2Len);
        }
        if (err == 0) {
            err = (p1Len != set->pubKeySize);
            if (err) {
                PRINT_ERR_MSG("Unexpected pub key size %zu vs %zu",
                    p1Len, set->pubKeySize);
            }
        }
        if (err == 0) {
            err = (p1Len != p2Len) || (XMEMCMP(p1, p2, p1Len) == 0);
            if (err) {
                PRINT_ERR_MSG("Generated public keys have invalid lengths or "
                    "are identical");
            }
        }

        OPENSSL_free(p1); p1 = NULL;
        OPENSSL_free(p2); p2 = NULL;
        EVP_PKEY_free(k1); k1 = NULL;
        EVP_PKEY_free(k2); k2 = NULL;
    }
    return err;
}

int test_slhdsa_validate_keypair(void* data)
{
    int err = 0;
    EVP_PKEY* key = NULL;
    EVP_PKEY_CTX* ctx = NULL;
    unsigned char* priv = NULL;
    size_t privLen = 0;
    OSSL_PARAM params[2];

    (void)data;

    PRINT_MSG("Key pair validation %s", slhdsa_sets[0].name);
    err = slhdsa_keygen(slhdsa_sets[0].name, &key);
    if (err == 0) {
        ctx = EVP_PKEY_CTX_new_from_pkey(wpLibCtx, key, NULL);
        err = (ctx == NULL);
    }
    if (err == 0) {
        err = EVP_PKEY_private_check(ctx) != 1;
    }
    if (err == 0) {
        err = EVP_PKEY_pairwise_check(ctx) != 1;
    }
    if (err == 0) {
        err = slhdsa_get_raw(key, OSSL_PKEY_PARAM_PRIV_KEY, &priv, &privLen);
    }
    if (err == 0) {
        priv[0] ^= 1;
        params[0] = OSSL_PARAM_construct_octet_string(
            OSSL_PKEY_PARAM_PRIV_KEY, priv, privLen);
        params[1] = OSSL_PARAM_construct_end();
        EVP_PKEY_CTX_free(ctx);
        ctx = EVP_PKEY_CTX_new_from_name(wpLibCtx, slhdsa_sets[0].name, NULL);
        err = (ctx == NULL);
    }
    if (err == 0) {
        err = EVP_PKEY_fromdata_init(ctx) != 1;
    }
    if (err == 0) {
        EVP_PKEY* bad = NULL;

        err = EVP_PKEY_fromdata(ctx, &bad, EVP_PKEY_PRIVATE_KEY, params) == 1;
        if (err) {
            PRINT_ERR_MSG("Corrupted private-only key was imported");
        }
        EVP_PKEY_free(bad);
        ERR_clear_error();
    }

    OPENSSL_clear_free(priv, privLen);
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(key);
    return err;
}

/**
 * Test SLH-DSA raw key import/export round-trip.
 */
int test_slhdsa_import_export_roundtrip(void* data)
{
    int err = 0;
    size_t i;
    EVP_PKEY* k1 = NULL;
    EVP_PKEY* k2 = NULL;
    EVP_PKEY_CTX* ctx = NULL;
    OSSL_PARAM* params = NULL;
    OSSL_PARAM_BLD* bld = NULL;
    unsigned char* pub = NULL;
    unsigned char* priv = NULL;
    unsigned char* pub2 = NULL;
    unsigned char* priv2 = NULL;
    size_t pubLen = 0, privLen = 0, pub2Len = 0, priv2Len = 0;

    (void)data;

    for (i = 0; (err == 0) && (i < SLHDSA_SET_COUNT); i++) {
        const slhdsa_test_set* set = &slhdsa_sets[i];
        PRINT_MSG("Import/export round-trip %s", set->name);

        err = slhdsa_keygen(set->name, &k1);
        if (err == 0) {
            err = slhdsa_get_pub(k1, &pub, &pubLen);
        }
        if (err == 0) {
            err = slhdsa_get_raw(k1, OSSL_PKEY_PARAM_PRIV_KEY, &priv,
                &privLen);
        }
        if (err == 0) {
            err = (privLen != set->privKeySize);
        }
        if (err == 0) {
            bld = OSSL_PARAM_BLD_new();
            err = (bld == NULL);
        }
        if (err == 0) {
            err = OSSL_PARAM_BLD_push_octet_string(bld,
                OSSL_PKEY_PARAM_PUB_KEY, pub, pubLen) != 1;
        }
        if (err == 0) {
            err = OSSL_PARAM_BLD_push_octet_string(bld,
                OSSL_PKEY_PARAM_PRIV_KEY, priv, privLen) != 1;
        }
        if (err == 0) {
            params = OSSL_PARAM_BLD_to_param(bld);
            err = (params == NULL);
        }
        if (err == 0) {
            ctx = EVP_PKEY_CTX_new_from_name(wpLibCtx, set->name, NULL);
            err = (ctx == NULL);
        }
        if (err == 0) {
            err = EVP_PKEY_fromdata_init(ctx) != 1;
        }
        if (err == 0) {
            err = EVP_PKEY_fromdata(ctx, &k2, EVP_PKEY_KEYPAIR, params) != 1;
        }
        if (err == 0) {
            err = slhdsa_get_pub(k2, &pub2, &pub2Len);
        }
        if (err == 0) {
            err = slhdsa_get_raw(k2, OSSL_PKEY_PARAM_PRIV_KEY, &priv2,
                &priv2Len);
        }
        if (err == 0) {
            err = (pubLen != pub2Len) || (XMEMCMP(pub, pub2, pubLen) != 0);
        }
        if (err == 0) {
            err = (privLen != priv2Len) ||
                (XMEMCMP(priv, priv2, privLen) != 0);
        }

        OPENSSL_free(pub); pub = NULL;
        OPENSSL_free(priv); priv = NULL;
        OPENSSL_free(pub2); pub2 = NULL;
        OPENSSL_free(priv2); priv2 = NULL;
        OSSL_PARAM_free(params); params = NULL;
        OSSL_PARAM_BLD_free(bld); bld = NULL;
        EVP_PKEY_CTX_free(ctx); ctx = NULL;
        EVP_PKEY_free(k1); k1 = NULL;
        EVP_PKEY_free(k2); k2 = NULL;
    }
    return err;
}

/**
 * Test SLH-DSA sign then verify succeeds, and the signature is the expected
 * FIPS 205 size.
 */
int test_slhdsa_sign_verify(void* data)
{
    int err = 0;
    size_t i;
    EVP_PKEY* key = NULL;
    unsigned char* sig = NULL;
    size_t sigLen = 0;

    (void)data;

    for (i = 0; (err == 0) && (i < SLHDSA_SET_COUNT); i++) {
        const slhdsa_test_set* set = &slhdsa_sets[i];
        PRINT_MSG("Sign/verify %s", set->name);

        err = slhdsa_keygen(set->name, &key);
        if (err == 0) {
            err = slhdsa_sign_msg(key, slhdsa_test_msg, SLHDSA_TEST_MSG_LEN,
                &sig, &sigLen);
        }
        if (err == 0) {
            err = (sigLen != set->sigSize);
            if (err) {
                PRINT_ERR_MSG("Unexpected sig size %zu vs %zu", sigLen,
                    set->sigSize);
            }
        }
        if (err == 0) {
            err = !slhdsa_verify_msg(key, slhdsa_test_msg,
                SLHDSA_TEST_MSG_LEN, sig, sigLen);
        }

        OPENSSL_free(sig); sig = NULL;
        EVP_PKEY_free(key); key = NULL;
    }
    return err;
}

/**
 * Test that a tampered signature fails verification.
 */
int test_slhdsa_verify_tampered_sig(void* data)
{
    int err = 0;
    size_t i;
    EVP_PKEY* key = NULL;
    unsigned char* sig = NULL;
    size_t sigLen = 0;

    (void)data;

    for (i = 0; (err == 0) && (i < SLHDSA_SET_COUNT); i++) {
        const slhdsa_test_set* set = &slhdsa_sets[i];
        PRINT_MSG("Tampered sig %s", set->name);

        err = slhdsa_keygen(set->name, &key);
        if (err == 0) {
            err = slhdsa_sign_msg(key, slhdsa_test_msg, SLHDSA_TEST_MSG_LEN,
                &sig, &sigLen);
        }
        /* Flip a bit in the randomizer at the front of the signature. */
        if (err == 0) {
            sig[0] ^= 0x01;
            err = slhdsa_verify_msg(key, slhdsa_test_msg,
                SLHDSA_TEST_MSG_LEN, sig, sigLen);
        }
        /* And one deep in the hypertree authentication path. */
        if (err == 0) {
            sig[0] ^= 0x01;
            sig[sigLen - 1] ^= 0x80;
            err = slhdsa_verify_msg(key, slhdsa_test_msg,
                SLHDSA_TEST_MSG_LEN, sig, sigLen);
        }
        /* A truncated signature must be rejected, not read out of bounds. */
        if (err == 0) {
            sig[sigLen - 1] ^= 0x80;
            err = slhdsa_verify_msg(key, slhdsa_test_msg,
                SLHDSA_TEST_MSG_LEN, sig, sigLen - 1);
        }

        OPENSSL_free(sig); sig = NULL;
        EVP_PKEY_free(key); key = NULL;
    }
    return err;
}

/**
 * Test that a modified message fails verification.
 */
int test_slhdsa_verify_tampered_msg(void* data)
{
    int err = 0;
    size_t i;
    EVP_PKEY* key = NULL;
    unsigned char* sig = NULL;
    size_t sigLen = 0;
    unsigned char msg[SLHDSA_TEST_MSG_LEN];

    (void)data;

    for (i = 0; (err == 0) && (i < SLHDSA_SET_COUNT); i++) {
        const slhdsa_test_set* set = &slhdsa_sets[i];
        PRINT_MSG("Tampered msg %s", set->name);

        XMEMCPY(msg, slhdsa_test_msg, SLHDSA_TEST_MSG_LEN);
        err = slhdsa_keygen(set->name, &key);
        if (err == 0) {
            err = slhdsa_sign_msg(key, msg, SLHDSA_TEST_MSG_LEN, &sig,
                &sigLen);
        }
        if (err == 0) {
            msg[0] ^= 0x01;
            err = slhdsa_verify_msg(key, msg, SLHDSA_TEST_MSG_LEN, sig,
                sigLen);
        }

        OPENSSL_free(sig); sig = NULL;
        EVP_PKEY_free(key); key = NULL;
    }
    return err;
}

/**
 * Test that a signature does not verify under a different key.
 */
int test_slhdsa_verify_wrong_key(void* data)
{
    int err = 0;
    size_t i;
    EVP_PKEY* k1 = NULL;
    EVP_PKEY* k2 = NULL;
    unsigned char* sig = NULL;
    size_t sigLen = 0;

    (void)data;

    for (i = 0; (err == 0) && (i < SLHDSA_SET_COUNT); i++) {
        const slhdsa_test_set* set = &slhdsa_sets[i];
        PRINT_MSG("Wrong key %s", set->name);

        err = slhdsa_keygen(set->name, &k1);
        if (err == 0) {
            err = slhdsa_keygen(set->name, &k2);
        }
        if (err == 0) {
            err = slhdsa_sign_msg(k1, slhdsa_test_msg, SLHDSA_TEST_MSG_LEN,
                &sig, &sigLen);
        }
        if (err == 0) {
            err = slhdsa_verify_msg(k2, slhdsa_test_msg, SLHDSA_TEST_MSG_LEN,
                sig, sigLen);
        }

        OPENSSL_free(sig); sig = NULL;
        EVP_PKEY_free(k1); k1 = NULL;
        EVP_PKEY_free(k2); k2 = NULL;
    }
    return err;
}

/**
 * Test EVP_PKEY_dup of an SLH-DSA key: the copy must sign and verify.
 */
int test_slhdsa_dup(void* data)
{
    int err = 0;
    size_t i;
    EVP_PKEY* key = NULL;
    EVP_PKEY* dup = NULL;
    EVP_PKEY* pub = NULL;
    EVP_PKEY* pubDup = NULL;
    BIO* bio = NULL;
    unsigned char* sig = NULL;
    size_t sigLen = 0;

    (void)data;

    for (i = 0; (err == 0) && (i < SLHDSA_SET_COUNT); i++) {
        const slhdsa_test_set* set = &slhdsa_sets[i];
        PRINT_MSG("Dup %s", set->name);

        err = slhdsa_keygen(set->name, &key);
        if (err == 0) {
            dup = EVP_PKEY_dup(key);
            err = (dup == NULL);
        }
        /* Sign with the duplicate, verify with the original. */
        if (err == 0) {
            err = slhdsa_sign_msg(dup, slhdsa_test_msg, SLHDSA_TEST_MSG_LEN,
                &sig, &sigLen);
        }
        if (err == 0) {
            err = !slhdsa_verify_msg(key, slhdsa_test_msg,
                SLHDSA_TEST_MSG_LEN, sig, sigLen);
        }
        /* EVP_PKEY_dup requests all components even for a public-only key. */
        if (err == 0) {
            bio = BIO_new(BIO_s_mem());
            err = (bio == NULL);
        }
        if (err == 0) {
            err = PEM_write_bio_PUBKEY(bio, key) != 1;
        }
        if (err == 0) {
            pub = PEM_read_bio_PUBKEY_ex(bio, NULL, NULL, NULL, wpLibCtx,
                NULL);
            err = (pub == NULL);
        }
        if (err == 0) {
            pubDup = EVP_PKEY_dup(pub);
            err = (pubDup == NULL);
        }
        if (err == 0) {
            err = !slhdsa_verify_msg(pubDup, slhdsa_test_msg,
                SLHDSA_TEST_MSG_LEN, sig, sigLen);
        }

        BIO_free(bio); bio = NULL;
        OPENSSL_free(sig); sig = NULL;
        EVP_PKEY_free(pubDup); pubDup = NULL;
        EVP_PKEY_free(pub); pub = NULL;
        EVP_PKEY_free(dup); dup = NULL;
        EVP_PKEY_free(key); key = NULL;
    }
    return err;
}

/**
 * Test EVP_PKEY_eq: a key matches itself and its dup, not an unrelated key.
 */
int test_slhdsa_match(void* data)
{
    int err = 0;
    size_t i;
    EVP_PKEY* k1 = NULL;
    EVP_PKEY* k2 = NULL;
    EVP_PKEY* dup = NULL;

    (void)data;

    for (i = 0; (err == 0) && (i < SLHDSA_SET_COUNT); i++) {
        const slhdsa_test_set* set = &slhdsa_sets[i];
        PRINT_MSG("Match %s", set->name);

        err = slhdsa_keygen(set->name, &k1);
        if (err == 0) {
            err = slhdsa_keygen(set->name, &k2);
        }
        if (err == 0) {
            dup = EVP_PKEY_dup(k1);
            err = (dup == NULL);
        }
        if (err == 0) {
            err = EVP_PKEY_eq(k1, dup) != 1;
        }
        if (err == 0) {
            err = EVP_PKEY_eq(k1, k2) == 1;
        }

        EVP_PKEY_free(dup); dup = NULL;
        EVP_PKEY_free(k1); k1 = NULL;
        EVP_PKEY_free(k2); k2 = NULL;
    }
    return err;
}

/**
 * Test EVP_MD_CTX_copy_ex of an in-progress SLH-DSA signing context.
 */
int test_slhdsa_dupctx(void* data)
{
    int err = 0;
    EVP_PKEY* key = NULL;
    EVP_MD_CTX* mdctx = NULL;
    EVP_MD_CTX* copy = NULL;
    unsigned char* sig = NULL;
    size_t sigLen = 0;

    (void)data;

    PRINT_MSG("Dup signing context %s", slhdsa_sets[0].name);

    err = slhdsa_keygen(slhdsa_sets[0].name, &key);
    if (err == 0) {
        mdctx = EVP_MD_CTX_new();
        err = (mdctx == NULL);
    }
    if (err == 0) {
        err = EVP_DigestSignInit_ex(mdctx, NULL, NULL, wpLibCtx, NULL, key,
            NULL) != 1;
    }
    /* Feed part of the message, copy, then finish on the copy. */
    if (err == 0) {
        err = EVP_DigestSignUpdate(mdctx, slhdsa_test_msg, 8) != 1;
    }
    if (err == 0) {
        copy = EVP_MD_CTX_new();
        err = (copy == NULL);
    }
    if (err == 0) {
        err = EVP_MD_CTX_copy_ex(copy, mdctx) != 1;
    }
    if (err == 0) {
        err = EVP_DigestSignUpdate(copy, slhdsa_test_msg + 8,
            SLHDSA_TEST_MSG_LEN - 8) != 1;
    }
    if (err == 0) {
        err = EVP_DigestSignFinal(copy, NULL, &sigLen) != 1;
    }
    if (err == 0) {
        sig = (unsigned char*)OPENSSL_malloc(sigLen);
        err = (sig == NULL);
    }
    if (err == 0) {
        err = EVP_DigestSignFinal(copy, sig, &sigLen) != 1;
    }
    if (err == 0) {
        err = !slhdsa_verify_msg(key, slhdsa_test_msg, SLHDSA_TEST_MSG_LEN,
            sig, sigLen);
    }

    OPENSSL_free(sig);
    EVP_MD_CTX_free(copy);
    EVP_MD_CTX_free(mdctx);
    EVP_PKEY_free(key);
    return err;
}

/**
 * Test the one-shot EVP_PKEY_sign/verify API (no digest context).
 */
int test_slhdsa_oneshot_sign_verify(void* data)
{
    int err = 0;
    EVP_PKEY* key = NULL;
    EVP_PKEY_CTX* ctx = NULL;
    unsigned char* sig = NULL;
    size_t sigLen = 0;

    (void)data;

    PRINT_MSG("One-shot sign/verify %s", slhdsa_sets[0].name);

    err = slhdsa_keygen(slhdsa_sets[0].name, &key);
    if (err == 0) {
        ctx = EVP_PKEY_CTX_new_from_pkey(wpLibCtx, key, NULL);
        err = (ctx == NULL);
    }
    if (err == 0) {
        err = EVP_PKEY_sign_init(ctx) != 1;
    }
    if (err == 0) {
        err = EVP_PKEY_sign(ctx, NULL, &sigLen, slhdsa_test_msg,
            SLHDSA_TEST_MSG_LEN) != 1;
    }
    if (err == 0) {
        sig = (unsigned char*)OPENSSL_malloc(sigLen);
        err = (sig == NULL);
    }
    if (err == 0) {
        err = EVP_PKEY_sign(ctx, sig, &sigLen, slhdsa_test_msg,
            SLHDSA_TEST_MSG_LEN) != 1;
    }
    EVP_PKEY_CTX_free(ctx); ctx = NULL;
    if (err == 0) {
        ctx = EVP_PKEY_CTX_new_from_pkey(wpLibCtx, key, NULL);
        err = (ctx == NULL);
    }
    if (err == 0) {
        err = EVP_PKEY_verify_init(ctx) != 1;
    }
    if (err == 0) {
        err = EVP_PKEY_verify(ctx, sig, sigLen, slhdsa_test_msg,
            SLHDSA_TEST_MSG_LEN) != 1;
    }

    OPENSSL_free(sig);
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(key);
    return err;
}

/* Test the OpenSSL 3.6 message API and its staged-signature parameter. */
int test_slhdsa_message_api(void* data)
{
    int err = 0;
    EVP_PKEY* key = NULL;
    EVP_PKEY_CTX* signCtx = NULL;
    EVP_PKEY_CTX* verifyCtx = NULL;
    EVP_SIGNATURE* algorithm = NULL;
    unsigned char* sig = NULL;
    size_t sigLen = 0;

    (void)data;

    PRINT_MSG("Message API %s", slhdsa_sets[0].name);
    err = slhdsa_keygen(slhdsa_sets[0].name, &key);
    if (err == 0) {
        algorithm = EVP_SIGNATURE_fetch(wpLibCtx, slhdsa_sets[0].name, NULL);
        signCtx = EVP_PKEY_CTX_new_from_pkey(wpLibCtx, key, NULL);
        err = (algorithm == NULL) || (signCtx == NULL);
    }
    if (err == 0) {
        err = EVP_PKEY_sign_message_init(signCtx, algorithm, NULL) != 1;
    }
    if (err == 0) {
        err = EVP_PKEY_sign_message_update(signCtx, slhdsa_test_msg, 8) != 1;
    }
    if (err == 0) {
        err = EVP_PKEY_sign_message_update(signCtx, slhdsa_test_msg + 8,
            SLHDSA_TEST_MSG_LEN - 8) != 1;
    }
    if (err == 0) {
        err = EVP_PKEY_sign_message_final(signCtx, NULL, &sigLen) != 1;
    }
    if (err == 0) {
        sig = (unsigned char*)OPENSSL_malloc(sigLen);
        err = (sig == NULL);
    }
    if (err == 0) {
        err = EVP_PKEY_sign_message_final(signCtx, sig, &sigLen) != 1;
    }
    if (err == 0) {
        verifyCtx = EVP_PKEY_CTX_new_from_pkey(wpLibCtx, key, NULL);
        err = (verifyCtx == NULL);
    }
    if (err == 0) {
        err = EVP_PKEY_verify_message_init(verifyCtx, algorithm, NULL) != 1;
    }
    if (err == 0) {
        err = EVP_PKEY_CTX_set_signature(verifyCtx, sig, sigLen) != 1;
    }
    if (err == 0) {
        err = EVP_PKEY_verify_message_update(verifyCtx, slhdsa_test_msg,
            SLHDSA_TEST_MSG_LEN) != 1;
    }
    if (err == 0) {
        err = EVP_PKEY_verify_message_final(verifyCtx) != 1;
    }
    if (err == 0) {
        err = EVP_PKEY_verify_message_final(verifyCtx) == 1;
        if (err) {
            PRINT_ERR_MSG("Staged signature was reused after final");
        }
        ERR_clear_error();
    }

    OPENSSL_free(sig);
    EVP_PKEY_CTX_free(verifyCtx);
    EVP_PKEY_CTX_free(signCtx);
    EVP_SIGNATURE_free(algorithm);
    EVP_PKEY_free(key);
    return err;
}

/* Test that pure SLH-DSA rejects the distinct pre-hash API. */
int test_slhdsa_reject_digest(void* data)
{
    int err = 0;
    EVP_PKEY* key = NULL;
    EVP_MD_CTX* signCtx = NULL;
    EVP_MD_CTX* verifyCtx = NULL;

    (void)data;

    PRINT_MSG("Reject named digest %s", slhdsa_sets[0].name);
    err = slhdsa_keygen(slhdsa_sets[0].name, &key);
    if (err == 0) {
        signCtx = EVP_MD_CTX_new();
        verifyCtx = EVP_MD_CTX_new();
        err = (signCtx == NULL) || (verifyCtx == NULL);
    }
    if (err == 0) {
        err = EVP_DigestSignInit_ex(signCtx, NULL, "SHA256", wpLibCtx, NULL,
            key, NULL) == 1;
        if (err) {
            PRINT_ERR_MSG("Pure SLH-DSA accepted a named digest");
        }
    }
    if (err == 0) {
        err = EVP_DigestVerifyInit_ex(verifyCtx, NULL, "SHA256", wpLibCtx,
            NULL, key, NULL) == 1;
        if (err) {
            PRINT_ERR_MSG("Pure SLH-DSA verify accepted a named digest");
        }
    }

    EVP_MD_CTX_free(verifyCtx);
    EVP_MD_CTX_free(signCtx);
    EVP_PKEY_free(key);
    ERR_clear_error();
    return err;
}

/**
 * Test the SLH-DSA key parameters reported to OpenSSL.
 */
int test_slhdsa_get_params(void* data)
{
    int err = 0;
    size_t i;
    EVP_PKEY* key = NULL;

    (void)data;

    for (i = 0; (err == 0) && (i < SLHDSA_SET_COUNT); i++) {
        const slhdsa_test_set* set = &slhdsa_sets[i];
        int bits = 0;
        int secBits = 0;
        int cat = 0;
        int maxSize = 0;

        PRINT_MSG("Get params %s", set->name);

        err = slhdsa_keygen(set->name, &key);
        if (err == 0) {
            err = EVP_PKEY_get_int_param(key, OSSL_PKEY_PARAM_BITS,
                &bits) != 1;
        }
        if (err == 0) {
            err = (bits != (int)set->pubKeySize * 8);
        }
        if (err == 0) {
            err = EVP_PKEY_get_int_param(key, OSSL_PKEY_PARAM_SECURITY_BITS,
                &secBits) != 1;
        }
        if (err == 0) {
            err = (secBits != set->securityBits);
        }
        if (err == 0) {
            err = EVP_PKEY_get_int_param(key,
                OSSL_PKEY_PARAM_SECURITY_CATEGORY, &cat) != 1;
        }
        if (err == 0) {
            err = (cat != set->securityCategory);
        }
        if (err == 0) {
            err = EVP_PKEY_get_int_param(key, OSSL_PKEY_PARAM_MAX_SIZE,
                &maxSize) != 1;
        }
        if (err == 0) {
            err = (maxSize != (int)set->sigSize);
        }
        if (err == 0) {
            err = EVP_PKEY_get_size(key) != (int)set->sigSize;
        }
        if (err == 0) {
            char mdName[20];

            err = EVP_PKEY_get_default_digest_name(key, mdName,
                sizeof(mdName)) != 2;
            if (err) {
                PRINT_ERR_MSG("SLH-DSA did not report a mandatory digest");
            }
        }

        EVP_PKEY_free(key); key = NULL;
    }
    return err;
}

/**
 * Test that a public-only key cannot sign.
 */
int test_slhdsa_pubonly_sign_fails(void* data)
{
    int err = 0;
    EVP_PKEY* key = NULL;
    EVP_PKEY* pubOnly = NULL;
    EVP_PKEY_CTX* ctx = NULL;
    OSSL_PARAM* params = NULL;
    OSSL_PARAM_BLD* bld = NULL;
    EVP_MD_CTX* mdctx = NULL;
    unsigned char* pub = NULL;
    size_t pubLen = 0;

    (void)data;

    PRINT_MSG("Public-only key cannot sign");

    err = slhdsa_keygen(slhdsa_sets[0].name, &key);
    if (err == 0) {
        err = slhdsa_get_pub(key, &pub, &pubLen);
    }
    if (err == 0) {
        bld = OSSL_PARAM_BLD_new();
        err = (bld == NULL);
    }
    if (err == 0) {
        err = OSSL_PARAM_BLD_push_octet_string(bld, OSSL_PKEY_PARAM_PUB_KEY,
            pub, pubLen) != 1;
    }
    if (err == 0) {
        params = OSSL_PARAM_BLD_to_param(bld);
        err = (params == NULL);
    }
    if (err == 0) {
        ctx = EVP_PKEY_CTX_new_from_name(wpLibCtx, slhdsa_sets[0].name, NULL);
        err = (ctx == NULL);
    }
    if (err == 0) {
        err = EVP_PKEY_fromdata_init(ctx) != 1;
    }
    if (err == 0) {
        err = EVP_PKEY_fromdata(ctx, &pubOnly, EVP_PKEY_PUBLIC_KEY,
            params) != 1;
    }
    if (err == 0) {
        size_t privLen = 0;

        err = EVP_PKEY_get_octet_string_param(pubOnly,
            OSSL_PKEY_PARAM_PRIV_KEY, NULL, 0, &privLen) == 1;
        if (err) {
            PRINT_ERR_MSG("Public-only key reported a private component");
        }
    }
    if (err == 0) {
        EVP_PKEY_CTX_free(ctx);
        ctx = EVP_PKEY_CTX_new_from_pkey(wpLibCtx, pubOnly, NULL);
        err = (ctx == NULL);
    }
    if (err == 0) {
        err = EVP_PKEY_public_check(ctx) != 1;
    }
    if (err == 0) {
        err = EVP_PKEY_pairwise_check(ctx) == 1;
        if (err) {
            PRINT_ERR_MSG("Public-only key passed pairwise validation");
        }
        ERR_clear_error();
    }
    /* Signing must fail: either at init or at the sign call. */
    if (err == 0) {
        size_t sigLen = 0;
        unsigned char* sig = NULL;

        mdctx = EVP_MD_CTX_new();
        err = (mdctx == NULL);
        if (err == 0) {
            if (EVP_DigestSignInit_ex(mdctx, NULL, NULL, wpLibCtx, NULL,
                    pubOnly, NULL) == 1) {
                /* A real buffer: if the sign ever stops failing, it must not
                 * write a multi-kilobyte signature over the message array. */
                if (EVP_DigestSign(mdctx, NULL, &sigLen, slhdsa_test_msg,
                        SLHDSA_TEST_MSG_LEN) == 1) {
                    sig = OPENSSL_malloc(sigLen);
                    err = (sig == NULL);
                    if (err == 0) {
                        err = EVP_DigestSign(mdctx, sig, &sigLen,
                            slhdsa_test_msg, SLHDSA_TEST_MSG_LEN) == 1;
                        if (err) {
                            PRINT_ERR_MSG("Public-only key produced a signature");
                        }
                    }
                }
                OPENSSL_free(sig);
            }
        }
    }

    EVP_MD_CTX_free(mdctx);
    OPENSSL_free(pub);
    OSSL_PARAM_free(params);
    OSSL_PARAM_BLD_free(bld);
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pubOnly);
    EVP_PKEY_free(key);
    return err;
}

/**
 * Test that importing a mismatched public/private pair is rejected.
 */
int test_slhdsa_import_mismatched_pubpriv(void* data)
{
    int err = 0;
    size_t i;

    (void)data;

    for (i = 0; (err == 0) && (i < SLHDSA_SET_COUNT); i++) {
        const slhdsa_test_set* set = &slhdsa_sets[i];
        EVP_PKEY* k1 = NULL;
        EVP_PKEY* k2 = NULL;
        EVP_PKEY* bad = NULL;
        EVP_PKEY_CTX* ctx = NULL;
        OSSL_PARAM* params = NULL;
        OSSL_PARAM_BLD* bld = NULL;
        unsigned char* pub = NULL;
        unsigned char* priv = NULL;
        size_t pubLen = 0, privLen = 0;

        PRINT_MSG("Mismatched pub/priv %s", set->name);

        err = slhdsa_keygen(set->name, &k1);
        if (err == 0) {
            err = slhdsa_keygen(set->name, &k2);
        }
        /* Public from one key, private from another. */
        if (err == 0) {
            err = slhdsa_get_pub(k1, &pub, &pubLen);
        }
        if (err == 0) {
            err = slhdsa_get_raw(k2, OSSL_PKEY_PARAM_PRIV_KEY, &priv,
                &privLen);
        }
        if (err == 0) {
            bld = OSSL_PARAM_BLD_new();
            err = (bld == NULL);
        }
        if (err == 0) {
            err = OSSL_PARAM_BLD_push_octet_string(bld,
                OSSL_PKEY_PARAM_PUB_KEY, pub, pubLen) != 1;
        }
        if (err == 0) {
            err = OSSL_PARAM_BLD_push_octet_string(bld,
                OSSL_PKEY_PARAM_PRIV_KEY, priv, privLen) != 1;
        }
        if (err == 0) {
            params = OSSL_PARAM_BLD_to_param(bld);
            err = (params == NULL);
        }
        if (err == 0) {
            ctx = EVP_PKEY_CTX_new_from_name(wpLibCtx, set->name, NULL);
            err = (ctx == NULL);
        }
        if (err == 0) {
            err = EVP_PKEY_fromdata_init(ctx) != 1;
        }
        if (err == 0) {
            err = EVP_PKEY_fromdata(ctx, &bad, EVP_PKEY_KEYPAIR,
                params) == 1;
            if (err) {
                PRINT_ERR_MSG("Mismatched pub/priv was accepted");
            }
        }

        OPENSSL_free(pub);
        OPENSSL_free(priv);
        OSSL_PARAM_free(params);
        OSSL_PARAM_BLD_free(bld);
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(bad);
        EVP_PKEY_free(k1);
        EVP_PKEY_free(k2);
    }
    return err;
}

/**
 * Test signing an empty message, which FIPS 205 permits.
 */
int test_slhdsa_empty_message(void* data)
{
    int err = 0;
    EVP_PKEY* key = NULL;
    unsigned char* sig = NULL;
    size_t sigLen = 0;

    (void)data;

    PRINT_MSG("Empty message %s", slhdsa_sets[0].name);

    err = slhdsa_keygen(slhdsa_sets[0].name, &key);
    if (err == 0) {
        err = slhdsa_sign_msg(key, (const unsigned char*)"", 0, &sig, &sigLen);
    }
    if (err == 0) {
        err = !slhdsa_verify_msg(key, (const unsigned char*)"", 0, sig,
            sigLen);
    }
    /* A non-empty message must not verify under the empty-message signature. */
    if (err == 0) {
        err = slhdsa_verify_msg(key, slhdsa_test_msg, SLHDSA_TEST_MSG_LEN,
            sig, sigLen);
    }

    OPENSSL_free(sig);
    EVP_PKEY_free(key);
    return err;
}

/**
 * Test that re-init with a NULL key reuses the key already on the context.
 */
int test_slhdsa_reinit_null_key(void* data)
{
    int err = 0;
    EVP_PKEY* key = NULL;
    EVP_MD_CTX* mdctx = NULL;
    EVP_MD_CTX* verifyCtx = NULL;
    unsigned char* sig = NULL;
    unsigned char* sig2 = NULL;
    size_t sigLen = 0;
    size_t sig2Len = 0;
    unsigned char entropy[32];
    OSSL_PARAM params[5];
    OSSL_PARAM verifyParams[3];
    int detOn = 1;
    int encRaw = 0;
    size_t n;

    (void)data;

    PRINT_MSG("Reinit with NULL key reuses context key");

    err = slhdsa_keygen(slhdsa_sets[0].name, &key);
    if (err == 0) {
        mdctx = EVP_MD_CTX_new();
        err = (mdctx == NULL);
    }
    if (err == 0) {
        n = (size_t)(slhdsa_sets[0].pubKeySize / 2);
        XMEMSET(entropy, 0xA5, sizeof(entropy));
        params[0] = OSSL_PARAM_construct_octet_string(
            OSSL_SIGNATURE_PARAM_CONTEXT_STRING, (void*)"ctx-A", 5);
        params[1] = OSSL_PARAM_construct_octet_string(
            OSSL_SIGNATURE_PARAM_TEST_ENTROPY, entropy, n);
        params[2] = OSSL_PARAM_construct_int(
            OSSL_SIGNATURE_PARAM_DETERMINISTIC, &detOn);
        params[3] = OSSL_PARAM_construct_int(
            OSSL_SIGNATURE_PARAM_MESSAGE_ENCODING, &encRaw);
        params[4] = OSSL_PARAM_construct_end();
        err = EVP_DigestSignInit_ex(mdctx, NULL, NULL, wpLibCtx, NULL, key,
            params) != 1;
    }
    if (err == 0) {
        err = EVP_DigestSign(mdctx, NULL, &sigLen, slhdsa_test_msg,
            SLHDSA_TEST_MSG_LEN) != 1;
    }
    if (err == 0) {
        sig = (unsigned char*)OPENSSL_malloc(sigLen);
        err = (sig == NULL);
    }
    if (err == 0) {
        err = EVP_DigestSign(mdctx, sig, &sigLen, slhdsa_test_msg,
            SLHDSA_TEST_MSG_LEN) != 1;
    }
    /* Re-init reuses the key and preserves configured signature parameters. */
    if (err == 0) {
        err = EVP_DigestSignInit_ex(mdctx, NULL, NULL, wpLibCtx, NULL, NULL,
            NULL) != 1;
    }
    /* Failed updates must not partially replace the retained parameters. */
    if (err == 0) {
        OSSL_PARAM bad[3];
        int encBad = 2;

        bad[0] = OSSL_PARAM_construct_octet_string(
            OSSL_SIGNATURE_PARAM_CONTEXT_STRING, (void*)"ctx-B", 5);
        bad[1] = OSSL_PARAM_construct_int(
            OSSL_SIGNATURE_PARAM_MESSAGE_ENCODING, &encBad);
        bad[2] = OSSL_PARAM_construct_end();
        err = EVP_PKEY_CTX_set_params(EVP_MD_CTX_get_pkey_ctx(mdctx), bad)
            == 1;
        if (err) {
            PRINT_ERR_MSG("Invalid parameter set was accepted");
        }
    }
    if (err == 0) {
        OSSL_PARAM bad[2];

        bad[0] = OSSL_PARAM_construct_octet_string(
            OSSL_SIGNATURE_PARAM_TEST_ENTROPY, entropy, n - 1);
        bad[1] = OSSL_PARAM_construct_end();
        err = EVP_PKEY_CTX_set_params(EVP_MD_CTX_get_pkey_ctx(mdctx), bad)
            == 1;
        if (err) {
            PRINT_ERR_MSG("Invalid test entropy was accepted");
        }
    }
    if (err == 0) {
        err = EVP_DigestSignInit_ex(mdctx, NULL, NULL, wpLibCtx, NULL, NULL,
            NULL) != 1;
    }
    if (err == 0) {
        err = EVP_DigestSign(mdctx, NULL, &sig2Len, slhdsa_test_msg,
            SLHDSA_TEST_MSG_LEN) != 1;
    }
    if (err == 0) {
        sig2 = (unsigned char*)OPENSSL_malloc(sig2Len);
        err = (sig2 == NULL);
    }
    if (err == 0) {
        err = EVP_DigestSign(mdctx, sig2, &sig2Len, slhdsa_test_msg,
            SLHDSA_TEST_MSG_LEN) != 1;
    }
    if (err == 0) {
        err = (sigLen != sig2Len) || (XMEMCMP(sig, sig2, sigLen) != 0);
        if (err) {
            PRINT_ERR_MSG("Reinit did not retain SLH-DSA parameters");
        }
    }
    if (err == 0) {
        verifyCtx = EVP_MD_CTX_new();
        err = (verifyCtx == NULL);
    }
    if (err == 0) {
        verifyParams[0] = OSSL_PARAM_construct_octet_string(
            OSSL_SIGNATURE_PARAM_CONTEXT_STRING, (void*)"ctx-A", 5);
        verifyParams[1] = OSSL_PARAM_construct_int(
            OSSL_SIGNATURE_PARAM_MESSAGE_ENCODING, &encRaw);
        verifyParams[2] = OSSL_PARAM_construct_end();
        err = EVP_DigestVerifyInit_ex(verifyCtx, NULL, NULL, wpLibCtx, NULL,
            key, verifyParams) != 1;
    }
    if (err == 0) {
        err = EVP_DigestVerify(verifyCtx, sig, sigLen, slhdsa_test_msg,
            SLHDSA_TEST_MSG_LEN) != 1;
    }

    OPENSSL_free(sig);
    OPENSSL_free(sig2);
    EVP_MD_CTX_free(verifyCtx);
    EVP_MD_CTX_free(mdctx);
    EVP_PKEY_free(key);
    return err;
}

/**
 * Test PEM encode/decode round-trip for both SPKI and PKCS#8, and that a
 * key reloaded from PEM still signs and verifies.
 */
int test_slhdsa_encode_decode(void* data)
{
    int err = 0;
    size_t i;

    (void)data;

    for (i = 0; (err == 0) && (i < SLHDSA_SET_COUNT); i++) {
        const slhdsa_test_set* set = &slhdsa_sets[i];
        EVP_PKEY* key = NULL;
        EVP_PKEY* privKey = NULL;
        EVP_PKEY* pubKey = NULL;
        EVP_PKEY* rawKey = NULL;
        OSSL_DECODER_CTX* dctx = NULL;
        BIO* bio = NULL;
        unsigned char* rawPub = NULL;
        const unsigned char* rawData = NULL;
        size_t rawLen = 0;
        size_t rawDataLen = 0;
        unsigned char* sig = NULL;
        size_t sigLen = 0;

        PRINT_MSG("Encode/decode %s", set->name);

        err = slhdsa_keygen(set->name, &key);

        /* A SubjectPublicKeyInfo decoder must not accept a bare raw key. */
        if (err == 0) {
            err = slhdsa_get_pub(key, &rawPub, &rawLen);
        }
        if (err == 0) {
            /* Exercise the raw-key/SPKI ambiguity deterministically. */
            rawPub[0] = 0x30;
            rawData = rawPub;
            rawDataLen = rawLen;
            dctx = OSSL_DECODER_CTX_new_for_pkey(&rawKey, "DER",
                "SubjectPublicKeyInfo", set->name,
                OSSL_KEYMGMT_SELECT_PUBLIC_KEY, wpLibCtx, NULL);
            err = (dctx == NULL);
        }
        if (err == 0) {
            err = OSSL_DECODER_from_data(dctx, &rawData, &rawDataLen) == 1;
            if (err) {
                PRINT_ERR_MSG("SPKI decoder accepted a raw public key");
            }
            ERR_clear_error();
        }
        OSSL_DECODER_CTX_free(dctx); dctx = NULL;
        EVP_PKEY_free(rawKey); rawKey = NULL;
        OPENSSL_free(rawPub); rawPub = NULL;

        /* PKCS#8 private key round-trip. */
        if (err == 0) {
            bio = BIO_new(BIO_s_mem());
            err = (bio == NULL);
        }
        if (err == 0) {
            err = PEM_write_bio_PrivateKey(bio, key, NULL, NULL, 0, NULL,
                NULL) != 1;
        }
        if (err == 0) {
            privKey = PEM_read_bio_PrivateKey_ex(bio, NULL, NULL, NULL,
                wpLibCtx, NULL);
            err = (privKey == NULL);
        }
        BIO_free(bio); bio = NULL;

        /* SubjectPublicKeyInfo round-trip. */
        if (err == 0) {
            bio = BIO_new(BIO_s_mem());
            err = (bio == NULL);
        }
        if (err == 0) {
            err = PEM_write_bio_PUBKEY(bio, key) != 1;
        }
        if (err == 0) {
            pubKey = PEM_read_bio_PUBKEY_ex(bio, NULL, NULL, NULL, wpLibCtx,
                NULL);
            err = (pubKey == NULL);
        }
        BIO_free(bio); bio = NULL;

        /* The reloaded private signs; the reloaded public verifies. */
        if (err == 0) {
            err = slhdsa_sign_msg(privKey, slhdsa_test_msg,
                SLHDSA_TEST_MSG_LEN, &sig, &sigLen);
        }
        if (err == 0) {
            err = !slhdsa_verify_msg(pubKey, slhdsa_test_msg,
                SLHDSA_TEST_MSG_LEN, sig, sigLen);
        }
        if (err == 0) {
            err = EVP_PKEY_eq(key, pubKey) != 1;
        }

        OPENSSL_free(sig);
        OSSL_DECODER_CTX_free(dctx);
        EVP_PKEY_free(rawKey);
        OPENSSL_free(rawPub);
        EVP_PKEY_free(pubKey);
        EVP_PKEY_free(privKey);
        EVP_PKEY_free(key);
    }
    return err;
}

/**
 * Test signing and verifying an X.509 certificate with an SLH-DSA key.
 */
/* Sign the standard message with the supplied signature params. */
static int slhdsa_sign_with_ex(OSSL_LIB_CTX* libCtx, EVP_PKEY* key,
    const OSSL_PARAM* params, unsigned char** sig, size_t* sigLen)
{
    int err;
    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();

    *sig = NULL;
    *sigLen = 0;
    err = (mdctx == NULL);
    if (err == 0) {
        err = EVP_DigestSignInit_ex(mdctx, NULL, NULL, libCtx, NULL, key,
            params) != 1;
    }
    if (err == 0) {
        err = EVP_DigestSign(mdctx, NULL, sigLen, slhdsa_test_msg,
            SLHDSA_TEST_MSG_LEN) != 1;
    }
    if (err == 0) {
        *sig = (unsigned char*)OPENSSL_malloc(*sigLen);
        err = (*sig == NULL);
    }
    if (err == 0) {
        err = EVP_DigestSign(mdctx, *sig, sigLen, slhdsa_test_msg,
            SLHDSA_TEST_MSG_LEN) != 1;
    }
    if (err != 0) {
        OPENSSL_free(*sig);
        *sig = NULL;
    }
    EVP_MD_CTX_free(mdctx);
    return err;
}

static int slhdsa_sign_with(EVP_PKEY* key, const OSSL_PARAM* params,
    unsigned char** sig, size_t* sigLen)
{
    return slhdsa_sign_with_ex(wpLibCtx, key, params, sig, sigLen);
}

/* Verify the standard message with the supplied signature params. */
static int slhdsa_verify_with_ex(OSSL_LIB_CTX* libCtx, EVP_PKEY* key,
    const OSSL_PARAM* params, const unsigned char* sig, size_t sigLen)
{
    int rc = 0;
    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();

    if (mdctx != NULL) {
        if (EVP_DigestVerifyInit_ex(mdctx, NULL, NULL, libCtx, NULL, key,
                params) == 1) {
            rc = EVP_DigestVerify(mdctx, sig, sigLen, slhdsa_test_msg,
                SLHDSA_TEST_MSG_LEN);
        }
    }
    EVP_MD_CTX_free(mdctx);
    return rc;
}

static int slhdsa_verify_with(EVP_PKEY* key, const OSSL_PARAM* params,
    const unsigned char* sig, size_t sigLen)
{
    return slhdsa_verify_with_ex(wpLibCtx, key, params, sig, sigLen);
}

int test_slhdsa_all_set_metadata(void* data)
{
    int err = 0;
    size_t i;

    (void)data;

    for (i = 0; (err == 0) && (i < SLHDSA_ALL_SET_COUNT); i++) {
        const slhdsa_test_set* set = &slhdsa_all_sets[i];
        EVP_PKEY* key = NULL;
        int bits = 0;
        int secBits = 0;
        int category = 0;
        int maxSize = 0;

        PRINT_MSG("Registration and metadata %s", set->name);
        err = slhdsa_keygen(set->name, &key);
        if (err == 0) {
            err = EVP_PKEY_get_int_param(key, OSSL_PKEY_PARAM_BITS,
                &bits) != 1;
        }
        if (err == 0) {
            err = EVP_PKEY_get_int_param(key, OSSL_PKEY_PARAM_SECURITY_BITS,
                &secBits) != 1;
        }
        if (err == 0) {
            err = EVP_PKEY_get_int_param(key,
                OSSL_PKEY_PARAM_SECURITY_CATEGORY, &category) != 1;
        }
        if (err == 0) {
            err = EVP_PKEY_get_int_param(key, OSSL_PKEY_PARAM_MAX_SIZE,
                &maxSize) != 1;
        }
        if (err == 0) {
            err = (bits != (int)(8 * set->pubKeySize)) ||
                (secBits != set->securityBits) ||
                (category != set->securityCategory) ||
                (maxSize != (int)set->sigSize) ||
                (EVP_PKEY_get_size(key) != (int)set->sigSize);
            if (err) {
                PRINT_ERR_MSG("Unexpected metadata for %s", set->name);
            }
        }
        EVP_PKEY_free(key);
    }
    return err;
}

static int slhdsa_provider_ab_set(const slhdsa_test_set* set)
{
    int err = 0;
    EVP_PKEY* wpKey = NULL;
    EVP_PKEY* osslKey = NULL;
    unsigned char seed[3 * 32];
    unsigned char* wpPub = NULL;
    unsigned char* osslPub = NULL;
    unsigned char* wpPriv = NULL;
    unsigned char* osslPriv = NULL;
    unsigned char* wpSig = NULL;
    unsigned char* osslSig = NULL;
    unsigned char* wpSig2 = NULL;
    unsigned char* osslSig2 = NULL;
    unsigned char* wpSig3 = NULL;
    unsigned char* osslSig3 = NULL;
    unsigned char entropy[32];
    size_t seedLen = (set->pubKeySize / 2) * 3;
    size_t entLen = set->pubKeySize / 2;
    size_t wpPubLen = 0;
    size_t osslPubLen = 0;
    size_t wpPrivLen = 0;
    size_t osslPrivLen = 0;
    size_t wpSigLen = 0;
    size_t osslSigLen = 0;
    size_t wpSig2Len = 0;
    size_t osslSig2Len = 0;
    size_t wpSig3Len = 0;
    size_t osslSig3Len = 0;
    OSSL_PARAM params[2];
    OSSL_PARAM ctxParams[3];
    OSSL_PARAM entParams[3];
    int deterministic = 1;
    int encRaw = 0;
    size_t i;

    PRINT_MSG("wolfProvider/OpenSSL A/B %s", set->name);
    if ((seedLen > sizeof(seed)) || (entLen > sizeof(entropy))) {
        err = 1;
    }
    if (err == 0) {
        for (i = 0; i < seedLen; i++) {
            seed[i] = (unsigned char)i;
        }
    }
    if (err == 0) {
        err = slhdsa_keygen_ex(wpLibCtx, NULL, set->name, seed, seedLen,
            &wpKey);
    }
    if (err == 0) {
        err = slhdsa_keygen_ex(osslLibCtx, "provider=default", set->name,
            seed, seedLen, &osslKey);
    }
    if (err == 0) {
        err = slhdsa_get_pub(wpKey, &wpPub, &wpPubLen);
    }
    if (err == 0) {
        err = slhdsa_get_pub(osslKey, &osslPub, &osslPubLen);
    }
    if (err == 0) {
        err = slhdsa_get_raw(wpKey, OSSL_PKEY_PARAM_PRIV_KEY, &wpPriv,
            &wpPrivLen);
    }
    if (err == 0) {
        err = slhdsa_get_raw(osslKey, OSSL_PKEY_PARAM_PRIV_KEY, &osslPriv,
            &osslPrivLen);
    }
    if (err == 0) {
        err = (wpPubLen != osslPubLen) ||
            (XMEMCMP(wpPub, osslPub, wpPubLen) != 0) ||
            (wpPrivLen != osslPrivLen) ||
            (XMEMCMP(wpPriv, osslPriv, wpPrivLen) != 0);
        if (err) {
            PRINT_ERR_MSG("Seeded wolfProvider/OpenSSL keys differ");
        }
    }

    params[0] = OSSL_PARAM_construct_int(
        OSSL_SIGNATURE_PARAM_DETERMINISTIC, &deterministic);
    params[1] = OSSL_PARAM_construct_end();
    if (err == 0) {
        err = slhdsa_sign_with_ex(wpLibCtx, wpKey, params, &wpSig,
            &wpSigLen);
    }
    if (err == 0) {
        err = slhdsa_sign_with_ex(osslLibCtx, osslKey, params, &osslSig,
            &osslSigLen);
    }
    if (err == 0) {
        err = (wpSigLen != osslSigLen) ||
            (XMEMCMP(wpSig, osslSig, wpSigLen) != 0);
        if (err) {
            PRINT_ERR_MSG("Deterministic wolfProvider/OpenSSL signatures differ");
        }
    }
    if (err == 0) {
        err = slhdsa_verify_with_ex(osslLibCtx, osslKey, NULL, wpSig,
            wpSigLen) != 1;
    }
    if (err == 0) {
        err = slhdsa_verify_with_ex(wpLibCtx, wpKey, NULL, osslSig,
            osslSigLen) != 1;
    }

    /* Context string is only applied in encoded mode, so exercise it without
     * MESSAGE_ENCODING and require it to match OpenSSL. */
    if (err == 0) {
        ctxParams[0] = OSSL_PARAM_construct_octet_string(
            OSSL_SIGNATURE_PARAM_CONTEXT_STRING, (void*)"ctx-A", 5);
        ctxParams[1] = OSSL_PARAM_construct_int(
            OSSL_SIGNATURE_PARAM_DETERMINISTIC, &deterministic);
        ctxParams[2] = OSSL_PARAM_construct_end();
        err = slhdsa_sign_with_ex(wpLibCtx, wpKey, ctxParams, &wpSig2,
            &wpSig2Len);
    }
    if (err == 0) {
        err = slhdsa_sign_with_ex(osslLibCtx, osslKey, ctxParams, &osslSig2,
            &osslSig2Len);
    }
    if (err == 0) {
        err = (wpSig2Len != osslSig2Len) ||
            (XMEMCMP(wpSig2, osslSig2, wpSig2Len) != 0);
        if (err) {
            PRINT_ERR_MSG("Context-string wolfProvider/OpenSSL signatures differ");
        }
    }

    /* The raw-message test-entropy path must also match OpenSSL. */
    if (err == 0) {
        XMEMSET(entropy, 0xA5, sizeof(entropy));
        entParams[0] = OSSL_PARAM_construct_octet_string(
            OSSL_SIGNATURE_PARAM_TEST_ENTROPY, entropy, entLen);
        entParams[1] = OSSL_PARAM_construct_int(
            OSSL_SIGNATURE_PARAM_MESSAGE_ENCODING, &encRaw);
        entParams[2] = OSSL_PARAM_construct_end();
        err = slhdsa_sign_with_ex(wpLibCtx, wpKey, entParams, &wpSig3,
            &wpSig3Len);
    }
    if (err == 0) {
        err = slhdsa_sign_with_ex(osslLibCtx, osslKey, entParams, &osslSig3,
            &osslSig3Len);
    }
    if (err == 0) {
        err = (wpSig3Len != osslSig3Len) ||
            (XMEMCMP(wpSig3, osslSig3, wpSig3Len) != 0);
        if (err) {
            PRINT_ERR_MSG("Test-entropy wolfProvider/OpenSSL signatures differ");
        }
    }

    OPENSSL_free(wpSig);
    OPENSSL_free(osslSig);
    OPENSSL_free(wpSig2);
    OPENSSL_free(osslSig2);
    OPENSSL_free(wpSig3);
    OPENSSL_free(osslSig3);
    OPENSSL_clear_free(wpPriv, wpPrivLen);
    OPENSSL_clear_free(osslPriv, osslPrivLen);
    OPENSSL_free(wpPub);
    OPENSSL_free(osslPub);
    EVP_PKEY_free(wpKey);
    EVP_PKEY_free(osslKey);
    return err;
}

int test_slhdsa_provider_ab(void* data)
{
    int err = 0;
    size_t i;

    (void)data;

    for (i = 0; (err == 0) && (i < SLHDSA_SET_COUNT); i++) {
        err = slhdsa_provider_ab_set(&slhdsa_sets[i]);
    }
    return err;
}

int test_slhdsa_sig_params(void* data)
{
    int err = 0;
    EVP_PKEY* key = NULL;
    unsigned char* sigA = NULL;
    unsigned char* sigB = NULL;
    size_t lenA = 0;
    size_t lenB = 0;
    unsigned char entropy[32];
    OSSL_PARAM ctxParams[2];
    OSSL_PARAM detParams[2];
    OSSL_PARAM entParams[2];
    OSSL_PARAM rawParams[2];
    int detOn = 1;
    int encRaw = 0;
    size_t n;

    (void)data;

    err = slhdsa_keygen(slhdsa_sets[0].name, &key);

    /* Context string: a signature made under one context must not verify
     * under another. */
    if (err == 0) {
        PRINT_MSG("Context string affects the signature");
        ctxParams[0] = OSSL_PARAM_construct_octet_string(
            OSSL_SIGNATURE_PARAM_CONTEXT_STRING, (void*)"ctx-A", 5);
        ctxParams[1] = OSSL_PARAM_construct_end();
        err = slhdsa_sign_with(key, ctxParams, &sigA, &lenA);
    }
    if (err == 0) {
        err = slhdsa_verify_with(key, ctxParams, sigA, lenA) != 1;
    }
    if (err == 0) {
        OSSL_PARAM other[2];
        other[0] = OSSL_PARAM_construct_octet_string(
            OSSL_SIGNATURE_PARAM_CONTEXT_STRING, (void*)"ctx-B", 5);
        other[1] = OSSL_PARAM_construct_end();
        err = slhdsa_verify_with(key, other, sigA, lenA) == 1;
        if (err) {
            PRINT_ERR_MSG("Signature verified under the wrong context");
        }
    }
    OPENSSL_free(sigA); sigA = NULL;

    /* Deterministic: same key and message must give byte-identical output. */
    if (err == 0) {
        PRINT_MSG("Deterministic signing is reproducible");
        detParams[0] = OSSL_PARAM_construct_int(
            OSSL_SIGNATURE_PARAM_DETERMINISTIC, &detOn);
        detParams[1] = OSSL_PARAM_construct_end();
        err = slhdsa_sign_with(key, detParams, &sigA, &lenA);
    }
    if (err == 0) {
        err = slhdsa_sign_with(key, detParams, &sigB, &lenB);
    }
    if (err == 0) {
        err = (lenA != lenB) || (XMEMCMP(sigA, sigB, lenA) != 0);
        if (err) {
            PRINT_ERR_MSG("Deterministic signatures differ");
        }
    }
    if (err == 0) {
        err = slhdsa_verify_with(key, NULL, sigA, lenA) != 1;
    }
    OPENSSL_free(sigA); sigA = NULL;
    OPENSSL_free(sigB); sigB = NULL;

    /* Test entropy: fixing the randomizer must also be reproducible, and the
     * length is tied to the parameter set's n. */
    if (err == 0) {
        PRINT_MSG("Test entropy is reproducible");
        n = (size_t)(slhdsa_sets[0].pubKeySize / 2);
        XMEMSET(entropy, 0xA5, sizeof(entropy));
        entParams[0] = OSSL_PARAM_construct_octet_string(
            OSSL_SIGNATURE_PARAM_TEST_ENTROPY, entropy, n);
        entParams[1] = OSSL_PARAM_construct_end();
        err = slhdsa_sign_with(key, entParams, &sigA, &lenA);
    }
    if (err == 0) {
        err = slhdsa_sign_with(key, entParams, &sigB, &lenB);
    }
    if (err == 0) {
        err = (lenA != lenB) || (XMEMCMP(sigA, sigB, lenA) != 0);
        if (err) {
            PRINT_ERR_MSG("Fixed-entropy signatures differ");
        }
    }
    if (err == 0) {
        err = slhdsa_verify_with(key, NULL, sigA, lenA) != 1;
    }
    OPENSSL_free(sigA); sigA = NULL;
    OPENSSL_free(sigB); sigB = NULL;

    /* A wrong-length randomizer must be refused, not silently padded. */
    if (err == 0) {
        OSSL_PARAM bad[2];
        bad[0] = OSSL_PARAM_construct_octet_string(
            OSSL_SIGNATURE_PARAM_TEST_ENTROPY, entropy, n - 1);
        bad[1] = OSSL_PARAM_construct_end();
        err = slhdsa_sign_with(key, bad, &sigA, &lenA) == 0;
        if (err) {
            PRINT_ERR_MSG("Undersized test entropy was accepted");
        }
        OPENSSL_free(sigA); sigA = NULL;
    }

    /* Raw message encoding: the caller supplies M' itself. Sign and verify
     * must agree with each other under the same encoding. */
    if (err == 0) {
        PRINT_MSG("Raw message encoding round-trips");
        rawParams[0] = OSSL_PARAM_construct_int(
            OSSL_SIGNATURE_PARAM_MESSAGE_ENCODING, &encRaw);
        rawParams[1] = OSSL_PARAM_construct_end();
        err = slhdsa_sign_with(key, rawParams, &sigA, &lenA);
    }
    if (err == 0) {
        err = slhdsa_verify_with(key, rawParams, sigA, lenA) != 1;
    }
    /* Pure mode must not accept a raw-mode signature: different domain. */
    if (err == 0) {
        err = slhdsa_verify_with(key, NULL, sigA, lenA) == 1;
        if (err) {
            PRINT_ERR_MSG("Raw signature verified in pure mode");
        }
    }
    OPENSSL_free(sigA); sigA = NULL;

    EVP_PKEY_free(key);
    return err;
}

int test_slhdsa_undersized_sig(void* data)
{
    int err = 0;
    EVP_PKEY* key = NULL;
    EVP_PKEY_CTX* signCtx = NULL;
    EVP_SIGNATURE* algorithm = NULL;
    unsigned char* sig = NULL;
    size_t sigLen = 0;
    size_t shortLen = 0;

    (void)data;

    PRINT_MSG("Undersized signature buffer %s", slhdsa_sets[0].name);
    err = slhdsa_keygen(slhdsa_sets[0].name, &key);
    if (err == 0) {
        algorithm = EVP_SIGNATURE_fetch(wpLibCtx, slhdsa_sets[0].name, NULL);
        signCtx = EVP_PKEY_CTX_new_from_pkey(wpLibCtx, key, NULL);
        err = (algorithm == NULL) || (signCtx == NULL);
    }
    if (err == 0) {
        err = EVP_PKEY_sign_message_init(signCtx, algorithm, NULL) != 1;
    }
    if (err == 0) {
        err = EVP_PKEY_sign_message_update(signCtx, slhdsa_test_msg,
            SLHDSA_TEST_MSG_LEN) != 1;
    }
    if (err == 0) {
        err = EVP_PKEY_sign_message_final(signCtx, NULL, &sigLen) != 1;
    }
    if (err == 0) {
        sig = (unsigned char*)OPENSSL_malloc(sigLen);
        err = (sig == NULL);
    }
    /* A buffer one byte short of the signature must be refused before wolfSSL
     * writes, so the capacity guard in wp_slhdsa_sign actually runs. */
    if (err == 0) {
        XMEMSET(sig, 0xA5, sigLen);
        shortLen = sigLen - 1;
        err = EVP_PKEY_sign_message_final(signCtx, sig, &shortLen) == 1;
        if (err) {
            PRINT_ERR_MSG("Undersized signature buffer was accepted");
        }
        ERR_clear_error();
    }
    if (err == 0) {
        err = (sig[0] != 0xA5);
        if (err) {
            PRINT_ERR_MSG("Rejected signing wrote into the buffer");
        }
    }

    OPENSSL_free(sig);
    EVP_PKEY_CTX_free(signCtx);
    EVP_SIGNATURE_free(algorithm);
    EVP_PKEY_free(key);
    return err;
}

int test_slhdsa_midstream_params(void* data)
{
    int err = 0;
    EVP_PKEY* key = NULL;
    EVP_PKEY_CTX* signCtx = NULL;
    EVP_SIGNATURE* algorithm = NULL;
    OSSL_PARAM ctxParams[2];
    OSSL_PARAM encParams[2];
    int enc = 0;

    (void)data;

    PRINT_MSG("Mid-stream domain change is refused %s", slhdsa_sets[0].name);
    err = slhdsa_keygen(slhdsa_sets[0].name, &key);
    if (err == 0) {
        algorithm = EVP_SIGNATURE_fetch(wpLibCtx, slhdsa_sets[0].name, NULL);
        signCtx = EVP_PKEY_CTX_new_from_pkey(wpLibCtx, key, NULL);
        err = (algorithm == NULL) || (signCtx == NULL);
    }
    if (err == 0) {
        err = EVP_PKEY_sign_message_init(signCtx, algorithm, NULL) != 1;
    }
    if (err == 0) {
        err = EVP_PKEY_sign_message_update(signCtx, slhdsa_test_msg,
            SLHDSA_TEST_MSG_LEN) != 1;
    }
    /* Changing the context string after bytes are accumulated must be refused;
     * it would sign a different M' than streaming began under. */
    if (err == 0) {
        ctxParams[0] = OSSL_PARAM_construct_octet_string(
            OSSL_SIGNATURE_PARAM_CONTEXT_STRING, (void*)"late", 4);
        ctxParams[1] = OSSL_PARAM_construct_end();
        err = EVP_PKEY_CTX_set_params(signCtx, ctxParams) == 1;
        if (err) {
            PRINT_ERR_MSG("Mid-stream context string was accepted");
        }
        ERR_clear_error();
    }
    /* Same for the message encoding: pure and raw M' cannot switch mid-stream. */
    if (err == 0) {
        encParams[0] = OSSL_PARAM_construct_int(
            OSSL_SIGNATURE_PARAM_MESSAGE_ENCODING, &enc);
        encParams[1] = OSSL_PARAM_construct_end();
        err = EVP_PKEY_CTX_set_params(signCtx, encParams) == 1;
        if (err) {
            PRINT_ERR_MSG("Mid-stream message encoding was accepted");
        }
        ERR_clear_error();
    }

    EVP_PKEY_CTX_free(signCtx);
    EVP_SIGNATURE_free(algorithm);
    EVP_PKEY_free(key);
    return err;
}

int test_slhdsa_keygen_seed(void* data)
{
    int err = 0;
    EVP_PKEY* keyA = NULL;
    EVP_PKEY* keyB = NULL;
    EVP_PKEY_CTX* ctx = NULL;
    unsigned char seed[(3 * 32) + 1];
    unsigned char pubA[128];
    unsigned char pubB[128];
    size_t pubALen = 0;
    size_t pubBLen = 0;
    OSSL_PARAM params[2];
    size_t seedLen;
    size_t badSeedLens[2];
    size_t i;

    (void)data;

    PRINT_MSG("Seeded keygen is reproducible %s", slhdsa_sets[0].name);

    /* FIPS 205 seeds SK.seed || SK.prf || PK.seed, each n bytes. */
    seedLen = (slhdsa_sets[0].pubKeySize / 2) * 3;
    for (i = 0; i < sizeof(seed); i++) {
        seed[i] = (unsigned char)i;
    }
    params[0] = OSSL_PARAM_construct_octet_string(
        OSSL_PKEY_PARAM_SLH_DSA_SEED, seed, seedLen);
    params[1] = OSSL_PARAM_construct_end();

    for (i = 0; (err == 0) && (i < 2); i++) {
        EVP_PKEY** out = (i == 0) ? &keyA : &keyB;

        ctx = EVP_PKEY_CTX_new_from_name(wpLibCtx, slhdsa_sets[0].name, NULL);
        err = (ctx == NULL);
        if (err == 0) {
            err = EVP_PKEY_keygen_init(ctx) != 1;
        }
        if (err == 0) {
            err = EVP_PKEY_CTX_set_params(ctx, params) != 1;
        }
        if (err == 0) {
            err = EVP_PKEY_keygen(ctx, out) != 1;
        }
        EVP_PKEY_CTX_free(ctx); ctx = NULL;
    }
    if (err == 0) {
        err = EVP_PKEY_get_octet_string_param(keyA, OSSL_PKEY_PARAM_PUB_KEY,
            pubA, sizeof(pubA), &pubALen) != 1;
    }
    if (err == 0) {
        err = EVP_PKEY_get_octet_string_param(keyB, OSSL_PKEY_PARAM_PUB_KEY,
            pubB, sizeof(pubB), &pubBLen) != 1;
    }
    if (err == 0) {
        err = (pubALen != pubBLen) || (XMEMCMP(pubA, pubB, pubALen) != 0);
        if (err) {
            PRINT_ERR_MSG("Same seed produced different keys");
        }
    }

    EVP_PKEY_free(keyA); keyA = NULL;
    EVP_PKEY_free(keyB); keyB = NULL;

    if (err == 0) {
        PRINT_MSG("Wrong-length keygen seeds are rejected");
        badSeedLens[0] = seedLen - 1;
        badSeedLens[1] = seedLen + 1;
    }
    for (i = 0; (err == 0) && (i < 2); i++) {
        ctx = EVP_PKEY_CTX_new_from_name(wpLibCtx, slhdsa_sets[0].name, NULL);
        err = (ctx == NULL);
        if (err == 0) {
            err = EVP_PKEY_keygen_init(ctx) != 1;
        }
        if (err == 0) {
            params[0] = OSSL_PARAM_construct_octet_string(
                OSSL_PKEY_PARAM_SLH_DSA_SEED, seed, badSeedLens[i]);
            err = EVP_PKEY_CTX_set_params(ctx, params) == 1;
            if (err) {
                PRINT_ERR_MSG("Wrong-length keygen seed was accepted");
            }
        }
        EVP_PKEY_CTX_free(ctx); ctx = NULL;
    }

    if (err == 0) {
        PRINT_MSG("Rejected seed does not persist in keygen context");
        params[0] = OSSL_PARAM_construct_octet_string(
            OSSL_PKEY_PARAM_SLH_DSA_SEED, NULL, seedLen);
    }
    for (i = 0; (err == 0) && (i < 2); i++) {
        EVP_PKEY** out = (i == 0) ? &keyA : &keyB;

        ctx = EVP_PKEY_CTX_new_from_name(wpLibCtx, slhdsa_sets[0].name, NULL);
        err = (ctx == NULL);
        if (err == 0) {
            err = EVP_PKEY_keygen_init(ctx) != 1;
        }
        if (err == 0) {
            err = EVP_PKEY_CTX_set_params(ctx, params) == 1;
        }
        if (err == 0) {
            err = EVP_PKEY_keygen(ctx, out) != 1;
        }
        EVP_PKEY_CTX_free(ctx); ctx = NULL;
    }
    if (err == 0) {
        err = EVP_PKEY_get_octet_string_param(keyA, OSSL_PKEY_PARAM_PUB_KEY,
            pubA, sizeof(pubA), &pubALen) != 1;
    }
    if (err == 0) {
        err = EVP_PKEY_get_octet_string_param(keyB, OSSL_PKEY_PARAM_PUB_KEY,
            pubB, sizeof(pubB), &pubBLen) != 1;
    }
    if (err == 0) {
        err = (pubALen == pubBLen) &&
            (XMEMCMP(pubA, pubB, pubALen) == 0);
        if (err) {
            PRINT_ERR_MSG("Rejected seed produced deterministic keys");
        }
    }

    EVP_PKEY_free(keyA);
    EVP_PKEY_free(keyB);
    return err;
}

static int slhdsa_check_alg_id(EVP_PKEY* key, byte arc)
{
    static const byte prefix[] = {
        0x30, 0x0b, 0x06, 0x09, 0x60, 0x86, 0x48,
        0x01, 0x65, 0x03, 0x04, 0x03
    };
    int err = 0;
    EVP_MD_CTX* mdCtx = NULL;
    EVP_PKEY_CTX* keyCtx = NULL;
    byte expected[sizeof(prefix) + 1];
    byte actual[sizeof(expected)];
    OSSL_PARAM params[2];

    XMEMCPY(expected, prefix, sizeof(prefix));
    expected[sizeof(prefix)] = arc;
    mdCtx = EVP_MD_CTX_new();
    err = (mdCtx == NULL);
    if (err == 0) {
        err = EVP_DigestSignInit_ex(mdCtx, &keyCtx, NULL, wpLibCtx, NULL,
            key, NULL) != 1;
    }
    if (err == 0) {
        params[0] = OSSL_PARAM_construct_octet_string(
            OSSL_SIGNATURE_PARAM_ALGORITHM_ID, actual, sizeof(actual));
        params[1] = OSSL_PARAM_construct_end();
        err = EVP_PKEY_CTX_get_params(keyCtx, params) != 1;
    }
    if (err == 0) {
        err = (params[0].return_size != sizeof(expected)) ||
            (XMEMCMP(actual, expected, sizeof(expected)) != 0);
    }

    EVP_MD_CTX_free(mdCtx);
    return err;
}

int test_slhdsa_x509_sign_verify(void* data)
{
    int err = 0;
    size_t i;

    (void)data;

    for (i = 0; (err == 0) && (i < SLHDSA_SET_COUNT); i++) {
        const slhdsa_test_set* set = &slhdsa_sets[i];
        EVP_PKEY* key = NULL;
        X509* cert = NULL;
        X509_NAME* name = NULL;

        PRINT_MSG("X509 sign/verify %s", set->name);

        err = slhdsa_keygen(set->name, &key);
        if ((err == 0) && (XSTRCMP(set->name, "SLH-DSA-SHA2-128f") == 0)) {
            err = slhdsa_check_alg_id(key, 0x15);
        }
        if ((err == 0) &&
                (XSTRCMP(set->name, "SLH-DSA-SHAKE-128f") == 0)) {
            err = slhdsa_check_alg_id(key, 0x1b);
        }
        if (err == 0) {
            cert = X509_new_ex(wpLibCtx, NULL);
            err = (cert == NULL);
        }
        if (err == 0) {
            err = X509_set_version(cert, X509_VERSION_3) != 1;
        }
        if (err == 0) {
            err = ASN1_INTEGER_set(X509_get_serialNumber(cert), 1) != 1;
        }
        if (err == 0) {
            err = X509_gmtime_adj(X509_getm_notBefore(cert), 0) == NULL;
        }
        if (err == 0) {
            err = X509_gmtime_adj(X509_getm_notAfter(cert), 31536000L) == NULL;
        }
        if (err == 0) {
            err = X509_set_pubkey(cert, key) != 1;
        }
        if (err == 0) {
            name = X509_get_subject_name(cert);
            err = X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                (const unsigned char*)"wolfProvider SLH-DSA", -1, -1, 0) != 1;
        }
        if (err == 0) {
            err = X509_set_issuer_name(cert, name) != 1;
        }
        if (err == 0) {
            err = X509_sign(cert, key, NULL) == 0;
        }
        if (err == 0) {
            err = X509_verify(cert, key) != 1;
        }

        X509_free(cert);
        EVP_PKEY_free(key);
    }
    return err;
}

#ifdef WP_HAVE_EPKI_TEST
/**
 * Test encrypted PKCS#8 encode/decode round-trip.
 */
int test_slhdsa_encode_epki(void* data)
{
    int err = 0;
    EVP_PKEY* key = NULL;
    EVP_PKEY* dec = NULL;
    BIO* bio = NULL;
    const char* pw = "wolfprov-slhdsa";

    (void)data;

    PRINT_MSG("Encode EPKI %s", slhdsa_sets[0].name);

    err = slhdsa_keygen(slhdsa_sets[0].name, &key);
    if (err == 0) {
        bio = BIO_new(BIO_s_mem());
        err = (bio == NULL);
    }
    if (err == 0) {
        err = PEM_write_bio_PrivateKey(bio, key,
            EVP_aes_256_cbc(), (unsigned char*)pw, (int)XSTRLEN(pw), NULL,
            NULL) != 1;
    }
    if (err == 0) {
        dec = PEM_read_bio_PrivateKey_ex(bio, NULL, NULL, (void*)pw, wpLibCtx,
            NULL);
        err = (dec == NULL);
    }
    if (err == 0) {
        err = EVP_PKEY_eq(key, dec) != 1;
    }
    if (err == 0) {
        PRINT_MSG("PrivateKeyInfo DER with cipher set must encrypt");
        err = test_pki_cipher_encrypts(key, "DER", "provider=libwolfprov",
            wpLibCtx, 1);
    }
    if (err == 0) {
        PRINT_MSG("PrivateKeyInfo PEM with cipher set must encrypt");
        err = test_pki_cipher_encrypts(key, "PEM", "provider=libwolfprov",
            wpLibCtx, 1);
    }

    BIO_free(bio);
    EVP_PKEY_free(dec);
    EVP_PKEY_free(key);
    return err;
}
#endif /* WP_HAVE_EPKI_TEST */

#endif /* WP_HAVE_SLHDSA_PRIVATE */
#endif /* WP_HAVE_SLHDSA && WP_SLHDSA_TEST_SETS */
