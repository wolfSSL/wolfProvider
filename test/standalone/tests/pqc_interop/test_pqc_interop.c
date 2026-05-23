/* test_pqc_interop.c
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

/* PQC three-way interop validator.
 *
 * Three independent code paths exercised against each other:
 *   1. wolfProvider (via EVP_PKEY API)
 *   2. OpenSSL default provider (native ML-KEM / ML-DSA in OpenSSL 3.5+)
 *   3. wolfSSL direct (wc_MlKemKey_* / wc_dilithium_* APIs, no provider)
 *
 * For each algorithm at each NIST level, every cross-pair is tested:
 *   wolfProv enc/sign    -> default     dec/verify
 *   default  enc/sign    -> wolfProv    dec/verify
 *   wolfProv enc/sign    -> wolfssl-dir dec/verify
 *   wolfssl-dir enc/sign -> wolfProv    dec/verify
 *
 * Passing all three pairings proves the raw-key, ciphertext, and signature
 * byte encodings are standards-compliant end-to-end -- not just internally
 * round-trippable.
 *
 * Usage: test_pqc_interop [provider_path]
 *   provider_path defaults to ".libs" (relative to current dir).
 *   Set WOLFPROV_PATH env var to override.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef WOLFPROV_USER_SETTINGS
#include <user_settings.h>
#endif
#include <wolfssl/options.h>

#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/provider.h>
#include <openssl/core_names.h>
#include <openssl/params.h>

#include <wolfprovider/settings.h>

#if defined(WP_HAVE_MLKEM) && defined(WP_HAVE_MLDSA)

#include <wolfssl/wolfcrypt/mlkem.h>
#include <wolfssl/wolfcrypt/wc_mlkem.h>
#include <wolfssl/wolfcrypt/dilithium.h>
#include <wolfssl/wolfcrypt/random.h>

#define WP_NAME "libwolfprov"

static OSSL_LIB_CTX* wp_ctx;
static OSSL_LIB_CTX* oss_ctx;
static OSSL_PROVIDER* wp_prov;
static OSSL_PROVIDER* def_prov;
static WC_RNG g_rng;

static int load_all(const char* wp_path)
{
    wp_ctx = OSSL_LIB_CTX_new();
    oss_ctx = OSSL_LIB_CTX_new();
    if (wp_ctx == NULL || oss_ctx == NULL) return 0;

    OSSL_PROVIDER_set_default_search_path(wp_ctx, wp_path);
    wp_prov = OSSL_PROVIDER_load(wp_ctx, WP_NAME);
    if (wp_prov == NULL) {
        fprintf(stderr, "Failed to load wolfProvider\n");
        ERR_print_errors_fp(stderr);
        return 0;
    }
    def_prov = OSSL_PROVIDER_load(oss_ctx, "default");
    if (def_prov == NULL) {
        fprintf(stderr, "Failed to load OpenSSL default provider\n");
        return 0;
    }
    if (wc_InitRng(&g_rng) != 0) {
        fprintf(stderr, "wc_InitRng failed\n");
        return 0;
    }
    return 1;
}

static void unload_all(void)
{
    wc_FreeRng(&g_rng);
    if (wp_prov) OSSL_PROVIDER_unload(wp_prov);
    if (def_prov) OSSL_PROVIDER_unload(def_prov);
    if (wp_ctx) OSSL_LIB_CTX_free(wp_ctx);
    if (oss_ctx) OSSL_LIB_CTX_free(oss_ctx);
}

/* Map "ML-KEM-512/768/1024" to wolfSSL type enum. */
static int mlkem_name_to_type(const char* alg)
{
    if (strcmp(alg, "ML-KEM-512") == 0)  return WC_ML_KEM_512;
    if (strcmp(alg, "ML-KEM-768") == 0)  return WC_ML_KEM_768;
    if (strcmp(alg, "ML-KEM-1024") == 0) return WC_ML_KEM_1024;
    return -1;
}

/* Map "ML-DSA-44/65/87" to wolfSSL level byte. */
static byte mldsa_name_to_level(const char* alg)
{
    if (strcmp(alg, "ML-DSA-44") == 0) return WC_ML_DSA_44;
    if (strcmp(alg, "ML-DSA-65") == 0) return WC_ML_DSA_65;
    if (strcmp(alg, "ML-DSA-87") == 0) return WC_ML_DSA_87;
    return 0;
}

/* Pull raw pub/priv bytes out of an EVP_PKEY. priv is optional. */
static int evp_pkey_export_raw(EVP_PKEY* src, unsigned char** pub,
    size_t* pubLen, unsigned char** priv, size_t* privLen)
{
    *pub = NULL; *pubLen = 0;
    if (priv != NULL) { *priv = NULL; *privLen = 0; }

    if (EVP_PKEY_get_octet_string_param(src, OSSL_PKEY_PARAM_PUB_KEY, NULL, 0,
            pubLen) != 1) {
        return 0;
    }
    *pub = OPENSSL_malloc(*pubLen);
    if (*pub == NULL) {
        return 0;
    }
    if (EVP_PKEY_get_octet_string_param(src, OSSL_PKEY_PARAM_PUB_KEY, *pub,
            *pubLen, pubLen) != 1) {
        OPENSSL_free(*pub); *pub = NULL; *pubLen = 0;
        return 0;
    }
    if (priv != NULL) {
        if (EVP_PKEY_get_octet_string_param(src, OSSL_PKEY_PARAM_PRIV_KEY,
                NULL, 0, privLen) == 1) {
            *priv = OPENSSL_malloc(*privLen);
            if (*priv == NULL) {
                OPENSSL_free(*pub); *pub = NULL; *pubLen = 0;
                *privLen = 0;
                return 0;
            }
            if (EVP_PKEY_get_octet_string_param(src, OSSL_PKEY_PARAM_PRIV_KEY,
                    *priv, *privLen, privLen) != 1) {
                OPENSSL_free(*priv); *priv = NULL; *privLen = 0;
            }
        }
    }
    return 1;
}

/* Build an EVP_PKEY from raw pub (and optional priv) on the given lib ctx. */
static EVP_PKEY* evp_pkey_import_raw(OSSL_LIB_CTX* lib, const char* alg,
    const unsigned char* pub, size_t pubLen,
    const unsigned char* priv, size_t privLen)
{
    EVP_PKEY* dst = NULL;
    EVP_PKEY_CTX* dctx = NULL;
    OSSL_PARAM params[3];
    int n = 0;

    dctx = EVP_PKEY_CTX_new_from_name(lib, alg, NULL);
    if (dctx == NULL) return NULL;
    if (EVP_PKEY_fromdata_init(dctx) != 1) goto end;

    if (pub != NULL) {
        params[n++] = OSSL_PARAM_construct_octet_string(
            OSSL_PKEY_PARAM_PUB_KEY, (void*)pub, pubLen);
    }
    if (priv != NULL) {
        params[n++] = OSSL_PARAM_construct_octet_string(
            OSSL_PKEY_PARAM_PRIV_KEY, (void*)priv, privLen);
    }
    params[n] = OSSL_PARAM_construct_end();

    if (EVP_PKEY_fromdata(dctx, &dst, EVP_PKEY_KEYPAIR, params) != 1) {
        dst = NULL;
    }

end:
    if (dst == NULL) ERR_print_errors_fp(stderr);
    EVP_PKEY_CTX_free(dctx);
    return dst;
}

/*
 * ML-KEM helpers
 */

/* wolfProvider keygen for ML-KEM, returns EVP_PKEY in wp_ctx. */
static EVP_PKEY* mlkem_wp_keygen(const char* alg)
{
    EVP_PKEY* k = NULL;
    EVP_PKEY_CTX* g = EVP_PKEY_CTX_new_from_name(wp_ctx, alg, NULL);
    if (g && EVP_PKEY_keygen_init(g) == 1) EVP_PKEY_keygen(g, &k);
    EVP_PKEY_CTX_free(g);
    return k;
}

/* EVP encapsulate (lib determines which provider runs). */
static int evp_encap(OSSL_LIB_CTX* lib, EVP_PKEY* k, unsigned char** ct,
    size_t* ctLen, unsigned char* ss, size_t* ssLen)
{
    int ok = 0;
    EVP_PKEY_CTX* e = EVP_PKEY_CTX_new_from_pkey(lib, k, NULL);
    if (!e || EVP_PKEY_encapsulate_init(e, NULL) != 1) goto end;
    if (EVP_PKEY_encapsulate(e, NULL, ctLen, NULL, ssLen) != 1) goto end;
    *ct = OPENSSL_malloc(*ctLen);
    if (*ct == NULL) goto end;
    ok = (EVP_PKEY_encapsulate(e, *ct, ctLen, ss, ssLen) == 1);
    if (!ok) {
        OPENSSL_free(*ct);
        *ct = NULL;
    }
end:
    EVP_PKEY_CTX_free(e);
    return ok;
}

/* EVP decapsulate. */
static int evp_decap(OSSL_LIB_CTX* lib, EVP_PKEY* k, unsigned char* ss,
    size_t* ssLen, const unsigned char* ct, size_t ctLen)
{
    int ok = 0;
    EVP_PKEY_CTX* d = EVP_PKEY_CTX_new_from_pkey(lib, k, NULL);
    if (!d || EVP_PKEY_decapsulate_init(d, NULL) != 1) goto end;
    ok = (EVP_PKEY_decapsulate(d, ss, ssLen, ct, ctLen) == 1);
end:
    EVP_PKEY_CTX_free(d);
    return ok;
}

/* wolfSSL-direct encapsulate using wc_* APIs (no provider involved).
 * Pub bytes loaded from raw, ct + ss returned. */
static int wc_mlkem_encap_direct(const char* alg, const unsigned char* pub,
    size_t pubLen, unsigned char** ct, size_t* ctLen,
    unsigned char* ss, size_t ssCap)
{
    MlKemKey key;
    int rc;
    word32 ctSize = 0;
    int type = mlkem_name_to_type(alg);

    if (wc_MlKemKey_Init(&key, type, NULL, INVALID_DEVID) != 0) return 0;
    rc = wc_MlKemKey_DecodePublicKey(&key, pub, (word32)pubLen);
    if (rc != 0) { wc_MlKemKey_Free(&key); return 0; }
    rc = wc_MlKemKey_CipherTextSize(&key, &ctSize);
    if (rc != 0) { wc_MlKemKey_Free(&key); return 0; }
    if (ssCap < WC_ML_KEM_SS_SZ) { wc_MlKemKey_Free(&key); return 0; }
    *ct = OPENSSL_malloc(ctSize);
    if (*ct == NULL) { wc_MlKemKey_Free(&key); return 0; }
    *ctLen = ctSize;
    rc = wc_MlKemKey_Encapsulate(&key, *ct, ss, &g_rng);
    wc_MlKemKey_Free(&key);
    if (rc != 0) {
        OPENSSL_free(*ct);
        *ct = NULL;
        return 0;
    }
    return 1;
}

/* wolfSSL-direct decapsulate. */
static int wc_mlkem_decap_direct(const char* alg, const unsigned char* priv,
    size_t privLen, const unsigned char* ct, size_t ctLen,
    unsigned char* ss, size_t ssCap)
{
    MlKemKey key;
    int rc;
    int type = mlkem_name_to_type(alg);

    if (wc_MlKemKey_Init(&key, type, NULL, INVALID_DEVID) != 0) return 0;
    rc = wc_MlKemKey_DecodePrivateKey(&key, priv, (word32)privLen);
    if (rc != 0) { wc_MlKemKey_Free(&key); return 0; }
    if (ssCap < WC_ML_KEM_SS_SZ) { wc_MlKemKey_Free(&key); return 0; }
    rc = wc_MlKemKey_Decapsulate(&key, ss, ct, (word32)ctLen);
    wc_MlKemKey_Free(&key);
    return rc == 0;
}

/*
 * ML-DSA helpers
 */

static EVP_PKEY* mldsa_wp_keygen(const char* alg)
{
    EVP_PKEY* k = NULL;
    EVP_PKEY_CTX* g = EVP_PKEY_CTX_new_from_name(wp_ctx, alg, NULL);
    if (g && EVP_PKEY_keygen_init(g) == 1) EVP_PKEY_keygen(g, &k);
    EVP_PKEY_CTX_free(g);
    return k;
}

static int evp_sign(OSSL_LIB_CTX* lib, EVP_PKEY* k, const unsigned char* msg,
    size_t msgLen, unsigned char** sig, size_t* sigLen)
{
    int ok = 0;
    EVP_MD_CTX* s = EVP_MD_CTX_new();
    if (s == NULL) return 0;
    if (EVP_DigestSignInit_ex(s, NULL, NULL, lib, NULL, k, NULL) != 1) goto end;
    if (EVP_DigestSign(s, NULL, sigLen, msg, msgLen) != 1) goto end;
    *sig = OPENSSL_malloc(*sigLen);
    if (*sig == NULL) goto end;
    ok = (EVP_DigestSign(s, *sig, sigLen, msg, msgLen) == 1);
    if (!ok) {
        OPENSSL_free(*sig);
        *sig = NULL;
    }
end:
    EVP_MD_CTX_free(s);
    return ok;
}

static int evp_verify(OSSL_LIB_CTX* lib, EVP_PKEY* k, const unsigned char* msg,
    size_t msgLen, const unsigned char* sig, size_t sigLen)
{
    int ok = 0;
    EVP_MD_CTX* v = EVP_MD_CTX_new();
    if (v == NULL) return 0;
    if (EVP_DigestVerifyInit_ex(v, NULL, NULL, lib, NULL, k, NULL) != 1)
        goto end;
    ok = (EVP_DigestVerify(v, sig, sigLen, msg, msgLen) == 1);
end:
    EVP_MD_CTX_free(v);
    return ok;
}

/* wolfSSL-direct sign using wc_dilithium_sign_ctx_msg with empty context
 * (FIPS 204 pure ML-DSA). */
static int wc_mldsa_sign_direct(const char* alg, const unsigned char* priv,
    size_t privLen, const unsigned char* msg, size_t msgLen,
    unsigned char** sig, size_t* sigLen)
{
    dilithium_key key;
    int rc;
    word32 outLen;
    int sigSz;
    byte level = mldsa_name_to_level(alg);

    if (wc_dilithium_init_ex(&key, NULL, INVALID_DEVID) != 0) return 0;
    if (wc_dilithium_set_level(&key, level) != 0) {
        wc_dilithium_free(&key); return 0;
    }
    rc = wc_dilithium_import_private(priv, (word32)privLen, &key);
    if (rc != 0) { wc_dilithium_free(&key); return 0; }
    sigSz = wc_dilithium_sig_size(&key);
    if (sigSz <= 0) { wc_dilithium_free(&key); return 0; }
    *sig = OPENSSL_malloc(sigSz);
    if (*sig == NULL) { wc_dilithium_free(&key); return 0; }
    outLen = (word32)sigSz;
    rc = wc_dilithium_sign_ctx_msg(NULL, 0, msg, (word32)msgLen, *sig, &outLen,
        &key, &g_rng);
    wc_dilithium_free(&key);
    if (rc != 0) { OPENSSL_free(*sig); *sig = NULL; return 0; }
    *sigLen = outLen;
    return 1;
}

/* wolfSSL-direct verify. */
static int wc_mldsa_verify_direct(const char* alg, const unsigned char* pub,
    size_t pubLen, const unsigned char* msg, size_t msgLen,
    const unsigned char* sig, size_t sigLen)
{
    dilithium_key key;
    int rc;
    int res = 0;
    byte level = mldsa_name_to_level(alg);

    if (wc_dilithium_init_ex(&key, NULL, INVALID_DEVID) != 0) return 0;
    if (wc_dilithium_set_level(&key, level) != 0) {
        wc_dilithium_free(&key); return 0;
    }
    rc = wc_dilithium_import_public(pub, (word32)pubLen, &key);
    if (rc != 0) { wc_dilithium_free(&key); return 0; }
    rc = wc_dilithium_verify_ctx_msg(sig, (word32)sigLen, NULL, 0, msg,
        (word32)msgLen, &res, &key);
    wc_dilithium_free(&key);
    return rc == 0 && res == 1;
}

/*
 * Test cases - each is one cross-pair.
 */

/* wolfProvider encap -> partner decap (partner=default OR direct). */
static int test_mlkem_pair_wp_to(const char* alg, const char* partner)
{
    int ok = 0;
    EVP_PKEY* wp_key = mlkem_wp_keygen(alg);
    EVP_PKEY* part_key = NULL;
    unsigned char* pub = NULL;
    unsigned char* priv = NULL;
    unsigned char* ct = NULL;
    unsigned char ss1[32], ss2[32];
    size_t pubLen = 0, privLen = 0, ctLen = 0;
    size_t ss1Len = sizeof(ss1), ss2Len = sizeof(ss2);

    if (!wp_key) goto end;
    if (!evp_pkey_export_raw(wp_key, &pub, &pubLen, &priv, &privLen)) goto end;

    /* wolfProvider encapsulates. */
    if (!evp_encap(wp_ctx, wp_key, &ct, &ctLen, ss1, &ss1Len)) goto end;

    if (strcmp(partner, "default") == 0) {
        part_key = evp_pkey_import_raw(oss_ctx, alg, pub, pubLen, priv,
            privLen);
        if (!part_key) goto end;
        if (!evp_decap(oss_ctx, part_key, ss2, &ss2Len, ct, ctLen)) goto end;
    }
    else { /* direct */
        if (!wc_mlkem_decap_direct(alg, priv, privLen, ct, ctLen, ss2,
                sizeof(ss2))) goto end;
        ss2Len = WC_ML_KEM_SS_SZ;
    }
    ok = (ss1Len == ss2Len) && memcmp(ss1, ss2, ss1Len) == 0;

end:
    if (!ok) ERR_print_errors_fp(stderr);
    printf("  %-12s wolfProv enc -> %-7s dec : %s\n", alg, partner,
        ok ? "PASS" : "FAIL");
    OPENSSL_free(pub);
    OPENSSL_clear_free(priv, privLen);
    OPENSSL_free(ct);
    EVP_PKEY_free(wp_key);
    EVP_PKEY_free(part_key);
    return ok;
}

/* partner encap -> wolfProvider decap. */
static int test_mlkem_pair_to_wp(const char* alg, const char* partner)
{
    int ok = 0;
    EVP_PKEY* wp_key = mlkem_wp_keygen(alg);
    EVP_PKEY* part_key = NULL;
    unsigned char* pub = NULL;
    unsigned char* priv = NULL;
    unsigned char* ct = NULL;
    unsigned char ss1[32], ss2[32];
    size_t pubLen = 0, privLen = 0, ctLen = 0;
    size_t ss1Len = sizeof(ss1), ss2Len = sizeof(ss2);

    if (!wp_key) goto end;
    if (!evp_pkey_export_raw(wp_key, &pub, &pubLen, &priv, &privLen)) goto end;

    if (strcmp(partner, "default") == 0) {
        part_key = evp_pkey_import_raw(oss_ctx, alg, pub, pubLen, NULL, 0);
        if (!part_key) goto end;
        if (!evp_encap(oss_ctx, part_key, &ct, &ctLen, ss1, &ss1Len)) goto end;
    }
    else { /* direct */
        if (!wc_mlkem_encap_direct(alg, pub, pubLen, &ct, &ctLen, ss1,
                sizeof(ss1))) goto end;
        ss1Len = WC_ML_KEM_SS_SZ;
    }

    if (!evp_decap(wp_ctx, wp_key, ss2, &ss2Len, ct, ctLen)) goto end;
    ok = (ss1Len == ss2Len) && memcmp(ss1, ss2, ss1Len) == 0;

end:
    if (!ok) ERR_print_errors_fp(stderr);
    printf("  %-12s %-7s enc  -> wolfProv dec : %s\n", alg, partner,
        ok ? "PASS" : "FAIL");
    OPENSSL_free(pub);
    OPENSSL_clear_free(priv, privLen);
    OPENSSL_free(ct);
    EVP_PKEY_free(wp_key);
    EVP_PKEY_free(part_key);
    return ok;
}

static const char* mldsa_msg =
    "wolfProvider three-way ML-DSA interop validation message";

/* wolfProvider sign -> partner verify. */
static int test_mldsa_pair_wp_to(const char* alg, const char* partner)
{
    int ok = 0;
    EVP_PKEY* wp_key = mldsa_wp_keygen(alg);
    EVP_PKEY* part_key = NULL;
    unsigned char* pub = NULL;
    unsigned char* priv = NULL;
    unsigned char* sig = NULL;
    size_t pubLen = 0, privLen = 0, sigLen = 0;
    size_t msgLen = strlen(mldsa_msg);

    if (!wp_key) goto end;
    if (!evp_pkey_export_raw(wp_key, &pub, &pubLen, &priv, &privLen)) goto end;

    if (!evp_sign(wp_ctx, wp_key, (const unsigned char*)mldsa_msg, msgLen,
            &sig, &sigLen)) goto end;

    if (strcmp(partner, "default") == 0) {
        part_key = evp_pkey_import_raw(oss_ctx, alg, pub, pubLen, NULL, 0);
        if (!part_key) goto end;
        ok = evp_verify(oss_ctx, part_key, (const unsigned char*)mldsa_msg,
            msgLen, sig, sigLen);
    }
    else { /* direct */
        ok = wc_mldsa_verify_direct(alg, pub, pubLen,
            (const unsigned char*)mldsa_msg, msgLen, sig, sigLen);
    }

end:
    if (!ok) ERR_print_errors_fp(stderr);
    printf("  %-12s wolfProv sign -> %-7s vrfy: %s\n", alg, partner,
        ok ? "PASS" : "FAIL");
    OPENSSL_free(pub);
    OPENSSL_clear_free(priv, privLen);
    OPENSSL_free(sig);
    EVP_PKEY_free(wp_key);
    EVP_PKEY_free(part_key);
    return ok;
}

/* partner sign -> wolfProvider verify. */
static int test_mldsa_pair_to_wp(const char* alg, const char* partner)
{
    int ok = 0;
    EVP_PKEY* wp_key = mldsa_wp_keygen(alg);
    EVP_PKEY* part_key = NULL;
    unsigned char* pub = NULL;
    unsigned char* priv = NULL;
    unsigned char* sig = NULL;
    size_t pubLen = 0, privLen = 0, sigLen = 0;
    size_t msgLen = strlen(mldsa_msg);

    if (!wp_key) goto end;
    if (!evp_pkey_export_raw(wp_key, &pub, &pubLen, &priv, &privLen)) goto end;

    if (strcmp(partner, "default") == 0) {
        part_key = evp_pkey_import_raw(oss_ctx, alg, pub, pubLen, priv,
            privLen);
        if (!part_key) goto end;
        if (!evp_sign(oss_ctx, part_key, (const unsigned char*)mldsa_msg,
                msgLen, &sig, &sigLen)) goto end;
    }
    else { /* direct */
        if (!wc_mldsa_sign_direct(alg, priv, privLen,
                (const unsigned char*)mldsa_msg, msgLen, &sig, &sigLen))
            goto end;
    }

    ok = evp_verify(wp_ctx, wp_key, (const unsigned char*)mldsa_msg, msgLen,
        sig, sigLen);

end:
    if (!ok) ERR_print_errors_fp(stderr);
    printf("  %-12s %-7s sign  -> wolfProv vrfy: %s\n", alg, partner,
        ok ? "PASS" : "FAIL");
    OPENSSL_free(pub);
    OPENSSL_clear_free(priv, privLen);
    OPENSSL_free(sig);
    EVP_PKEY_free(wp_key);
    EVP_PKEY_free(part_key);
    return ok;
}


int main(int argc, char* argv[])
{
    int fail = 0;
    const char* mlkem[] = { "ML-KEM-512", "ML-KEM-768", "ML-KEM-1024" };
    const char* mldsa[] = { "ML-DSA-44", "ML-DSA-65", "ML-DSA-87" };
    const char* wp_path = ".libs";
    const char* env_path;
    size_t i;

    if (argc > 1) {
        wp_path = argv[1];
    }
    else {
        env_path = getenv("WOLFPROV_PATH");
        if (env_path != NULL) {
            wp_path = env_path;
        }
    }

    if (!load_all(wp_path)) return 1;

    printf("ML-KEM three-way interop:\n");
    printf("  (wolfProvider) <-> (OpenSSL default) and <-> (wolfSSL direct)\n");
    for (i = 0; i < 3; i++) {
        if (!test_mlkem_pair_wp_to(mlkem[i], "default")) fail++;
        if (!test_mlkem_pair_to_wp(mlkem[i], "default")) fail++;
        if (!test_mlkem_pair_wp_to(mlkem[i], "direct"))  fail++;
        if (!test_mlkem_pair_to_wp(mlkem[i], "direct"))  fail++;
    }

    printf("\nML-DSA three-way interop:\n");
    printf("  (wolfProvider) <-> (OpenSSL default) and <-> (wolfSSL direct)\n");
    for (i = 0; i < 3; i++) {
        if (!test_mldsa_pair_wp_to(mldsa[i], "default")) fail++;
        if (!test_mldsa_pair_to_wp(mldsa[i], "default")) fail++;
        if (!test_mldsa_pair_wp_to(mldsa[i], "direct"))  fail++;
        if (!test_mldsa_pair_to_wp(mldsa[i], "direct"))  fail++;
    }

    unload_all();
    printf("\n%s: %d failure(s)\n", fail == 0 ? "ALL PASS" : "FAILED", fail);
    return fail ? 1 : 0;
}

#else /* !WP_HAVE_MLKEM || !WP_HAVE_MLDSA */

int main(void)
{
    printf("PQC interop test skipped: wolfProvider built without ML-KEM and "
           "ML-DSA support.\n");
    return 0;
}

#endif /* WP_HAVE_MLKEM && WP_HAVE_MLDSA */
