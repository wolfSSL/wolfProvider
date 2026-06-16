/* test_mldsa.c
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
#include <openssl/encoder.h>
#include <openssl/decoder.h>
#include <openssl/x509.h>

#ifdef WP_HAVE_MLDSA

#include <wolfssl/wolfcrypt/wc_mldsa.h>

/* Per-level metadata. */
typedef struct mldsa_test_level {
    const char* name;
    size_t pubKeySize;
    size_t sigSize;
} mldsa_test_level;

static const mldsa_test_level mldsa_levels[] = {
    { "ML-DSA-44", ML_DSA_LEVEL2_PUB_KEY_SIZE, ML_DSA_LEVEL2_SIG_SIZE },
    { "ML-DSA-65", ML_DSA_LEVEL3_PUB_KEY_SIZE, ML_DSA_LEVEL3_SIG_SIZE },
    { "ML-DSA-87", ML_DSA_LEVEL5_PUB_KEY_SIZE, ML_DSA_LEVEL5_SIG_SIZE },
};
#define MLDSA_LEVEL_COUNT (sizeof(mldsa_levels) / sizeof(mldsa_levels[0]))


static const unsigned char mldsa_test_msg[] =
    "wolfProvider ML-DSA test message bytes for FIPS 204 sign/verify";
#define MLDSA_TEST_MSG_LEN (sizeof(mldsa_test_msg) - 1)


/**
 * Generate an ML-DSA key pair via wolfProvider.
 *
 * @param [in]  name  Algorithm name (e.g. "ML-DSA-44").
 * @param [out] pkey  Generated EVP_PKEY (caller frees).
 * @return  0 on success, non-zero on failure.
 */
static int mldsa_keygen(const char* name, EVP_PKEY** pkey)
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
 * Extract the raw public key bytes from an ML-DSA EVP_PKEY.
 */
static int mldsa_get_pub(EVP_PKEY* pkey, unsigned char** out, size_t* len)
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
 * Sign a message with the given ML-DSA EVP_PKEY using the digest-sign API
 * (which for ML-DSA passes the whole message to the one-shot signer).
 */
static int mldsa_sign_msg(EVP_PKEY* pkey, const unsigned char* msg,
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
 * Verify a signature on a message with the given ML-DSA EVP_PKEY.
 *
 * @return  1 if verified, 0 if not (does not set err on bad sig).
 */
static int mldsa_verify_msg(EVP_PKEY* pkey, const unsigned char* msg,
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
 * Test ML-DSA key generation; verify pub-key size and that two keys differ.
 */
int test_mldsa_keygen(void* data)
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

    for (i = 0; (err == 0) && (i < MLDSA_LEVEL_COUNT); i++) {
        const mldsa_test_level* lvl = &mldsa_levels[i];
        PRINT_MSG("Keygen %s", lvl->name);

        err = mldsa_keygen(lvl->name, &k1);
        if (err == 0) {
            err = mldsa_keygen(lvl->name, &k2);
        }
        if (err == 0) {
            err = mldsa_get_pub(k1, &p1, &p1Len);
        }
        if (err == 0) {
            err = mldsa_get_pub(k2, &p2, &p2Len);
        }
        if (err == 0) {
            err = (p1Len != lvl->pubKeySize);
            if (err) {
                PRINT_ERR_MSG("Unexpected pub key size %zu vs %zu",
                    p1Len, lvl->pubKeySize);
            }
        }
        if (err == 0) {
            err = (memcmp(p1, p2, p1Len) == 0);
        }

        OPENSSL_free(p1); p1 = NULL;
        OPENSSL_free(p2); p2 = NULL;
        EVP_PKEY_free(k1); k1 = NULL;
        EVP_PKEY_free(k2); k2 = NULL;
    }
    return err;
}

/**
 * Test ML-DSA raw key import/export round-trip.
 *
 * For each level: keygen, export both pub and priv, import into a fresh
 * EVP_PKEY, re-export, and verify the bytes match exactly.
 */
int test_mldsa_import_export_roundtrip(void* data)
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

    for (i = 0; (err == 0) && (i < MLDSA_LEVEL_COUNT); i++) {
        const mldsa_test_level* lvl = &mldsa_levels[i];
        PRINT_MSG("Import/export roundtrip %s", lvl->name);

        err = mldsa_keygen(lvl->name, &k1);
        if (err == 0) {
            err = mldsa_get_pub(k1, &pub1, &pub1Len);
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
            err = mldsa_get_pub(k2, &pub2, &pub2Len);
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
 * Test ML-DSA sign / verify round-trip via the digest-sign EVP API.
 */
int test_mldsa_sign_verify(void* data)
{
    int err = 0;
    size_t i;
    EVP_PKEY* pkey = NULL;
    unsigned char* sig = NULL;
    size_t sigLen = 0;

    (void)data;

    for (i = 0; (err == 0) && (i < MLDSA_LEVEL_COUNT); i++) {
        const mldsa_test_level* lvl = &mldsa_levels[i];
        PRINT_MSG("Sign/verify %s", lvl->name);

        err = mldsa_keygen(lvl->name, &pkey);
        if (err == 0) {
            err = mldsa_sign_msg(pkey, mldsa_test_msg, MLDSA_TEST_MSG_LEN,
                &sig, &sigLen);
        }
        if (err == 0) {
            err = (sigLen > lvl->sigSize);
            if (err) {
                PRINT_ERR_MSG("Sig len %zu exceeds expected max %zu",
                    sigLen, lvl->sigSize);
            }
        }
        if (err == 0) {
            err = mldsa_verify_msg(pkey, mldsa_test_msg, MLDSA_TEST_MSG_LEN,
                sig, sigLen) != 1;
        }

        OPENSSL_free(sig); sig = NULL;
        EVP_PKEY_free(pkey); pkey = NULL;
    }
    return err;
}

/**
 * Test ML-DSA verify with a single-bit-flipped signature: must fail.
 */
int test_mldsa_verify_tampered_sig(void* data)
{
    int err = 0;
    size_t i;
    EVP_PKEY* pkey = NULL;
    unsigned char* sig = NULL;
    size_t sigLen = 0;

    (void)data;

    for (i = 0; (err == 0) && (i < MLDSA_LEVEL_COUNT); i++) {
        const mldsa_test_level* lvl = &mldsa_levels[i];
        PRINT_MSG("Tampered sig %s", lvl->name);

        err = mldsa_keygen(lvl->name, &pkey);
        if (err == 0) {
            err = mldsa_sign_msg(pkey, mldsa_test_msg, MLDSA_TEST_MSG_LEN,
                &sig, &sigLen);
        }
        if (err == 0) {
            sig[0] ^= 0x01;
            err = mldsa_verify_msg(pkey, mldsa_test_msg, MLDSA_TEST_MSG_LEN,
                sig, sigLen) == 1;
            if (err) {
                PRINT_ERR_MSG("Tampered signature verified");
            }
        }

        OPENSSL_free(sig); sig = NULL;
        EVP_PKEY_free(pkey); pkey = NULL;
    }
    return err;
}

/**
 * Test ML-DSA verify with a single-bit-flipped message: must fail.
 */
int test_mldsa_verify_tampered_msg(void* data)
{
    int err = 0;
    size_t i;
    EVP_PKEY* pkey = NULL;
    unsigned char* sig = NULL;
    size_t sigLen = 0;
    unsigned char tampered[MLDSA_TEST_MSG_LEN];

    (void)data;

    for (i = 0; (err == 0) && (i < MLDSA_LEVEL_COUNT); i++) {
        const mldsa_test_level* lvl = &mldsa_levels[i];
        PRINT_MSG("Tampered msg %s", lvl->name);

        err = mldsa_keygen(lvl->name, &pkey);
        if (err == 0) {
            err = mldsa_sign_msg(pkey, mldsa_test_msg, MLDSA_TEST_MSG_LEN,
                &sig, &sigLen);
        }
        if (err == 0) {
            memcpy(tampered, mldsa_test_msg, MLDSA_TEST_MSG_LEN);
            tampered[0] ^= 0x01;
            err = mldsa_verify_msg(pkey, tampered, MLDSA_TEST_MSG_LEN,
                sig, sigLen) == 1;
            if (err) {
                PRINT_ERR_MSG("Tampered message verified");
            }
        }

        OPENSSL_free(sig); sig = NULL;
        EVP_PKEY_free(pkey); pkey = NULL;
    }
    return err;
}

/**
 * Test ML-DSA verify with a different key: must fail.
 */
int test_mldsa_verify_wrong_key(void* data)
{
    int err = 0;
    size_t i;
    EVP_PKEY* keyA = NULL;
    EVP_PKEY* keyB = NULL;
    unsigned char* sig = NULL;
    size_t sigLen = 0;

    (void)data;

    for (i = 0; (err == 0) && (i < MLDSA_LEVEL_COUNT); i++) {
        const mldsa_test_level* lvl = &mldsa_levels[i];
        PRINT_MSG("Wrong key %s", lvl->name);

        err = mldsa_keygen(lvl->name, &keyA);
        if (err == 0) {
            err = mldsa_keygen(lvl->name, &keyB);
        }
        if (err == 0) {
            err = mldsa_sign_msg(keyA, mldsa_test_msg, MLDSA_TEST_MSG_LEN,
                &sig, &sigLen);
        }
        if (err == 0) {
            err = mldsa_verify_msg(keyB, mldsa_test_msg, MLDSA_TEST_MSG_LEN,
                sig, sigLen) == 1;
            if (err) {
                PRINT_ERR_MSG("Wrong key verified");
            }
        }

        OPENSSL_free(sig); sig = NULL;
        EVP_PKEY_free(keyA); keyA = NULL;
        EVP_PKEY_free(keyB); keyB = NULL;
    }
    return err;
}

/* Helper: digest_sign-only short message sign, returns sig (caller frees). */
static int mldsa_dsign_short(EVP_PKEY* k, const unsigned char* msg,
    size_t msgLen, unsigned char** sig, size_t* sigLen)
{
    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    int err = (mdctx == NULL);

    if (err == 0) {
        err = EVP_DigestSignInit_ex(mdctx, NULL, NULL, wpLibCtx, NULL, k,
            NULL) != 1;
    }
    if (err == 0) {
        err = EVP_DigestSign(mdctx, NULL, sigLen, msg, msgLen) != 1;
    }
    if (err == 0) {
        *sig = (unsigned char*)OPENSSL_malloc(*sigLen);
        err = (*sig == NULL);
    }
    if (err == 0) {
        err = EVP_DigestSign(mdctx, *sig, sigLen, msg, msgLen) != 1;
    }
    EVP_MD_CTX_free(mdctx);
    return err;
}

/* EVP_PKEY_dup roundtrip: dup pub matches; sign with dup, verify with orig. */
int test_mldsa_dup(void* data)
{
    static const unsigned char msg[32] = "ML-DSA dup test message vector!";
    int err = 0;
    size_t i;
    EVP_PKEY* k = NULL;
    EVP_PKEY* d = NULL;
    unsigned char* pub1 = NULL;
    unsigned char* pub2 = NULL;
    size_t pub1Len = 0;
    size_t pub2Len = 0;
    unsigned char* sig = NULL;
    size_t sigLen = 0;

    (void)data;
    for (i = 0; (err == 0) && (i < MLDSA_LEVEL_COUNT); i++) {
        const mldsa_test_level* lvl = &mldsa_levels[i];
        PRINT_MSG("Dup %s", lvl->name);

        err = mldsa_keygen(lvl->name, &k);
        if (err == 0) {
            d = EVP_PKEY_dup(k);
            err = (d == NULL);
        }
        if (err == 0) {
            err = mldsa_get_pub(k, &pub1, &pub1Len);
        }
        if (err == 0) {
            err = mldsa_get_pub(d, &pub2, &pub2Len);
        }
        if (err == 0) {
            err = (pub1Len != pub2Len) || (memcmp(pub1, pub2, pub1Len) != 0);
            if (err) PRINT_ERR_MSG("Dup pub byte mismatch");
        }
        if (err == 0) {
            err = mldsa_dsign_short(d, msg, sizeof(msg), &sig, &sigLen);
        }
        if (err == 0) {
            err = mldsa_verify_msg(k, msg, sizeof(msg), sig, sigLen) != 1;
            if (err) PRINT_ERR_MSG("Verify-with-orig of dup-sig failed");
        }

        OPENSSL_free(pub1); pub1 = NULL; pub1Len = 0;
        OPENSSL_free(pub2); pub2 = NULL; pub2Len = 0;
        OPENSSL_free(sig); sig = NULL; sigLen = 0;
        EVP_PKEY_free(d); d = NULL;
        EVP_PKEY_free(k); k = NULL;
    }
    return err;
}

/* EVP_PKEY_eq for ML-DSA. */
int test_mldsa_match(void* data)
{
    int err = 0;
    size_t i;
    EVP_PKEY* k1 = NULL;
    EVP_PKEY* k2 = NULL;
    EVP_PKEY* k3 = NULL;

    (void)data;
    for (i = 0; (err == 0) && (i < MLDSA_LEVEL_COUNT); i++) {
        PRINT_MSG("Match %s", mldsa_levels[i].name);

        err = mldsa_keygen(mldsa_levels[i].name, &k1);
        if (err == 0) {
            err = mldsa_keygen(mldsa_levels[i].name, &k2);
        }
        if (err == 0) {
            err = EVP_PKEY_eq(k1, k1) != 1;
            if (err) PRINT_ERR_MSG("Self-eq failed");
        }
        if (err == 0) {
            err = EVP_PKEY_eq(k1, k2) == 1;
            if (err) PRINT_ERR_MSG("Distinct keys reported equal");
        }
        if ((err == 0) && (i + 1 < MLDSA_LEVEL_COUNT)) {
            err = mldsa_keygen(mldsa_levels[i + 1].name, &k3);
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

/* EVP_MD_CTX_copy_ex on a partial digest_sign accumulator. Both ctxs must
 * produce signatures that verify under the original key. */
int test_mldsa_dupctx(void* data)
{
    static const unsigned char part1[16] = "mldsa-dupctx-pt1";
    static const unsigned char part2[16] = "mldsa-dupctx-pt2";
    int err = 0;
    size_t i;
    EVP_PKEY* k = NULL;
    EVP_MD_CTX* a = NULL;
    EVP_MD_CTX* b = NULL;
    unsigned char* sigA = NULL;
    unsigned char* sigB = NULL;
    size_t sigALen = 0;
    size_t sigBLen = 0;
    unsigned char msg[32];

    (void)data;
    XMEMCPY(msg, part1, 16);
    XMEMCPY(msg + 16, part2, 16);

    for (i = 0; (err == 0) && (i < MLDSA_LEVEL_COUNT); i++) {
        PRINT_MSG("Dupctx %s", mldsa_levels[i].name);

        err = mldsa_keygen(mldsa_levels[i].name, &k);
        if (err == 0) {
            a = EVP_MD_CTX_new();
            err = (a == NULL);
        }
        if (err == 0) {
            err = EVP_DigestSignInit_ex(a, NULL, NULL, wpLibCtx, NULL, k,
                NULL) != 1;
        }
        if (err == 0) {
            err = EVP_DigestSignUpdate(a, part1, sizeof(part1)) != 1;
        }
        if (err == 0) {
            b = EVP_MD_CTX_new();
            err = (b == NULL);
        }
        if (err == 0) {
            err = EVP_MD_CTX_copy_ex(b, a) != 1;
        }
        if (err == 0) {
            err = EVP_DigestSignUpdate(a, part2, sizeof(part2)) != 1
                || EVP_DigestSignUpdate(b, part2, sizeof(part2)) != 1;
        }
        if (err == 0) {
            err = EVP_DigestSignFinal(a, NULL, &sigALen) != 1
                || EVP_DigestSignFinal(b, NULL, &sigBLen) != 1;
        }
        if (err == 0) {
            sigA = (unsigned char*)OPENSSL_malloc(sigALen);
            sigB = (unsigned char*)OPENSSL_malloc(sigBLen);
            err = (sigA == NULL) || (sigB == NULL);
        }
        if (err == 0) {
            err = EVP_DigestSignFinal(a, sigA, &sigALen) != 1
                || EVP_DigestSignFinal(b, sigB, &sigBLen) != 1;
        }
        if (err == 0) {
            err = mldsa_verify_msg(k, msg, sizeof(msg), sigA, sigALen) != 1
                || mldsa_verify_msg(k, msg, sizeof(msg), sigB, sigBLen) != 1;
            if (err) PRINT_ERR_MSG("Dupctx sig verify failed");
        }

        EVP_MD_CTX_free(a); a = NULL;
        EVP_MD_CTX_free(b); b = NULL;
        OPENSSL_free(sigA); sigA = NULL; sigALen = 0;
        OPENSSL_free(sigB); sigB = NULL; sigBLen = 0;
        EVP_PKEY_free(k); k = NULL;
    }
    return err;
}

/* One-shot EVP_PKEY_sign / EVP_PKEY_verify path (not digest_sign). */
int test_mldsa_oneshot_sign_verify(void* data)
{
    static const unsigned char msg[16] = "mldsa-one-shot!!";
    int err = 0;
    size_t i;
    EVP_PKEY* k = NULL;
    EVP_PKEY_CTX* sctx = NULL;
    EVP_PKEY_CTX* vctx = NULL;
    unsigned char* sig = NULL;
    size_t sigLen = 0;

    (void)data;
    for (i = 0; (err == 0) && (i < MLDSA_LEVEL_COUNT); i++) {
        PRINT_MSG("One-shot sign/verify %s", mldsa_levels[i].name);

        err = mldsa_keygen(mldsa_levels[i].name, &k);
        if (err == 0) {
            sctx = EVP_PKEY_CTX_new_from_pkey(wpLibCtx, k, NULL);
            err = (sctx == NULL) || (EVP_PKEY_sign_init(sctx) != 1);
        }
        if (err == 0) {
            sigLen = 0;
            err = EVP_PKEY_sign(sctx, NULL, &sigLen, msg, sizeof(msg)) != 1;
        }
        if (err == 0) {
            sig = (unsigned char*)OPENSSL_malloc(sigLen);
            err = (sig == NULL);
        }
        if (err == 0) {
            err = EVP_PKEY_sign(sctx, sig, &sigLen, msg, sizeof(msg)) != 1;
        }
        if (err == 0) {
            vctx = EVP_PKEY_CTX_new_from_pkey(wpLibCtx, k, NULL);
            err = (vctx == NULL) || (EVP_PKEY_verify_init(vctx) != 1);
        }
        if (err == 0) {
            err = EVP_PKEY_verify(vctx, sig, sigLen, msg, sizeof(msg)) != 1;
        }

        OPENSSL_free(sig); sig = NULL; sigLen = 0;
        EVP_PKEY_CTX_free(sctx); sctx = NULL;
        EVP_PKEY_CTX_free(vctx); vctx = NULL;
        EVP_PKEY_free(k); k = NULL;
    }
    return err;
}

/* BITS / SECURITY_BITS / MAX_SIZE getters. */
int test_mldsa_get_params(void* data)
{
    /* FIPS 204: ML-DSA-44 -> 128 sec bits, -65 -> 192, -87 -> 256 */
    static const int secBits[] = { 128, 192, 256 };
    int err = 0;
    size_t i;
    EVP_PKEY* k = NULL;

    (void)data;
    for (i = 0; (err == 0) && (i < MLDSA_LEVEL_COUNT); i++) {
        const mldsa_test_level* lvl = &mldsa_levels[i];
        PRINT_MSG("Params %s", lvl->name);

        err = mldsa_keygen(lvl->name, &k);
        if (err == 0) {
            err = EVP_PKEY_get_bits(k) != (int)(lvl->pubKeySize * 8);
            if (err) PRINT_ERR_MSG("Wrong BITS");
        }
        if (err == 0) {
            err = EVP_PKEY_get_security_bits(k) != secBits[i];
            if (err) PRINT_ERR_MSG("Wrong SECURITY_BITS");
        }
        if (err == 0) {
            err = EVP_PKEY_get_size(k) != (int)lvl->sigSize;
            if (err) PRINT_ERR_MSG("Wrong MAX_SIZE");
        }
        EVP_PKEY_free(k); k = NULL;
    }
    return err;
}

/* DigestSignInit with non-empty mdName must fail (ML-DSA is pure). */
int test_mldsa_digest_sign_prehash(void* data)
{
    int err = 0;
    EVP_PKEY* k = NULL;
    EVP_MD_CTX* mdctx = NULL;
    unsigned char sig[5000];
    size_t sigLen = sizeof(sig);
    const unsigned char msg[] = "wolfProvider ML-DSA pre-hash message";
    int rc;

    (void)data;
    PRINT_MSG("DigestSign/Verify pre-hash (HashML-DSA) round-trip");

    err = mldsa_keygen("ML-DSA-65", &k);
    if (err == 0) {
        mdctx = EVP_MD_CTX_new();
        err = (mdctx == NULL);
    }
    /* A digest name selects FIPS 204 HashML-DSA; signing must succeed. */
    if (err == 0) {
        rc = EVP_DigestSignInit_ex(mdctx, NULL, "SHA-256", wpLibCtx, NULL, k,
            NULL);
        err = (rc != 1);
        if (err) PRINT_ERR_MSG("DigestSignInit with mdName failed");
    }
    if (err == 0) {
        err = EVP_DigestSign(mdctx, sig, &sigLen, msg, sizeof(msg)) != 1;
        if (err) PRINT_ERR_MSG("EVP_DigestSign (pre-hash) failed");
    }
    EVP_MD_CTX_free(mdctx);
    mdctx = NULL;
    if (err == 0) {
        mdctx = EVP_MD_CTX_new();
        err = (mdctx == NULL);
    }
    if (err == 0) {
        rc = EVP_DigestVerifyInit_ex(mdctx, NULL, "SHA-256", wpLibCtx, NULL, k,
            NULL);
        err = (rc != 1);
    }
    if (err == 0) {
        err = EVP_DigestVerify(mdctx, sig, sigLen, msg, sizeof(msg)) != 1;
        if (err) PRINT_ERR_MSG("EVP_DigestVerify (pre-hash) failed");
    }
    EVP_MD_CTX_free(mdctx);
    mdctx = NULL;
    /* A weak/legacy digest is not allowed for HashML-DSA. */
    if (err == 0) {
        mdctx = EVP_MD_CTX_new();
        err = (mdctx == NULL);
    }
    if (err == 0) {
        rc = EVP_DigestSignInit_ex(mdctx, NULL, "SHA-1", wpLibCtx, NULL, k,
            NULL);
        err = (rc == 1);
        if (err) PRINT_ERR_MSG("DigestSignInit accepted SHA-1 for ML-DSA");
    }
    EVP_MD_CTX_free(mdctx);
    EVP_PKEY_free(k);
    return err;
}

/* Negative: import priv + mutated pub. Expect fromdata to FAIL. */
int test_mldsa_import_mismatched_pubpriv(void* data)
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
    for (i = 0; (err == 0) && (i < MLDSA_LEVEL_COUNT); i++) {
        const mldsa_test_level* lvl = &mldsa_levels[i];
        PRINT_MSG("Mismatched pub/priv %s", lvl->name);

        err = mldsa_keygen(lvl->name, &k);
        if (err == 0) {
            err = mldsa_get_pub(k, &pub, &pubLen);
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

/* FIPS 204 permits an empty message: sign and verify zero-length input. */
int test_mldsa_empty_message(void* data)
{
    int err = 0;
    size_t i;
    EVP_PKEY* k = NULL;
    EVP_MD_CTX* mdctx = NULL;
    unsigned char* sig = NULL;
    size_t sigLen = 0;

    (void)data;
    for (i = 0; (err == 0) && (i < MLDSA_LEVEL_COUNT); i++) {
        PRINT_MSG("Empty message %s", mldsa_levels[i].name);

        err = mldsa_keygen(mldsa_levels[i].name, &k);
        if (err == 0) {
            mdctx = EVP_MD_CTX_new();
            err = (mdctx == NULL);
        }
        if (err == 0) {
            err = EVP_DigestSignInit_ex(mdctx, NULL, NULL, wpLibCtx, NULL, k,
                NULL) != 1;
        }
        /* No update calls: message is the empty string. */
        if (err == 0) {
            err = EVP_DigestSign(mdctx, NULL, &sigLen, NULL, 0) != 1;
        }
        if (err == 0) {
            sig = (unsigned char*)OPENSSL_malloc(sigLen);
            err = (sig == NULL);
        }
        if (err == 0) {
            err = EVP_DigestSign(mdctx, sig, &sigLen, NULL, 0) != 1;
            if (err) PRINT_ERR_MSG("Empty-message sign failed");
        }
        if (err == 0) {
            err = mldsa_verify_msg(k, NULL, 0, sig, sigLen) != 1;
            if (err) PRINT_ERR_MSG("Empty-message verify failed");
        }

        OPENSSL_free(sig); sig = NULL; sigLen = 0;
        EVP_MD_CTX_free(mdctx); mdctx = NULL;
        EVP_PKEY_free(k); k = NULL;
    }
    return err;
}

/* Reinitialize a sign context with a NULL key: the key already on the
 * context must be reused (OpenSSL reinit contract). */
int test_mldsa_reinit_null_key(void* data)
{
    static const unsigned char msg[16] = "mldsa-reinit-msg";
    int err = 0;
    EVP_PKEY* k = NULL;
    EVP_MD_CTX* mdctx = NULL;
    unsigned char* sig = NULL;
    size_t sigLen = 0;

    (void)data;
    PRINT_MSG("Reinit with NULL key reuses context key");

    err = mldsa_keygen("ML-DSA-44", &k);
    if (err == 0) {
        mdctx = EVP_MD_CTX_new();
        err = (mdctx == NULL);
    }
    if (err == 0) {
        err = EVP_DigestSignInit_ex(mdctx, NULL, NULL, wpLibCtx, NULL, k,
            NULL) != 1;
    }
    /* Reinit with NULL pkey: reuse the key already attached. */
    if (err == 0) {
        err = EVP_DigestSignInit_ex(mdctx, NULL, NULL, wpLibCtx, NULL, NULL,
            NULL) != 1;
        if (err) PRINT_ERR_MSG("Reinit with NULL key failed");
    }
    if (err == 0) {
        err = EVP_DigestSign(mdctx, NULL, &sigLen, msg, sizeof(msg)) != 1;
    }
    if (err == 0) {
        sig = (unsigned char*)OPENSSL_malloc(sigLen);
        err = (sig == NULL);
    }
    if (err == 0) {
        err = EVP_DigestSign(mdctx, sig, &sigLen, msg, sizeof(msg)) != 1;
    }
    if (err == 0) {
        err = mldsa_verify_msg(k, msg, sizeof(msg), sig, sigLen) != 1;
        if (err) PRINT_ERR_MSG("Sign after NULL-key reinit did not verify");
    }

    OPENSSL_free(sig);
    EVP_MD_CTX_free(mdctx);
    EVP_PKEY_free(k);
    return err;
}

/* Encode a key to PEM in wpLibCtx for the given selection/structure, then
 * decode it back via the wolfProvider decoder. The decoded key signs a
 * message that the original public key must verify. */
int test_mldsa_encode_decode(void* data)
{
    static const unsigned char msg[24] = "mldsa-encode-decode-msg!";
    int err = 0;
    size_t i;
    EVP_PKEY* k = NULL;
    EVP_PKEY* privDec = NULL;
    EVP_PKEY* pubDec = NULL;
    OSSL_ENCODER_CTX* ectx = NULL;
    OSSL_DECODER_CTX* dctx = NULL;
    unsigned char* privPem = NULL;
    unsigned char* pubPem = NULL;
    const unsigned char* p = NULL;
    size_t privPemLen = 0;
    size_t pubPemLen = 0;
    unsigned char* sig = NULL;
    size_t sigLen = 0;

    (void)data;
    for (i = 0; (err == 0) && (i < MLDSA_LEVEL_COUNT); i++) {
        const mldsa_test_level* lvl = &mldsa_levels[i];
        PRINT_MSG("Encode/decode %s", lvl->name);

        err = mldsa_keygen(lvl->name, &k);

        /* Private-key PEM (PrivateKeyInfo) round-trip. */
        if (err == 0) {
            ectx = OSSL_ENCODER_CTX_new_for_pkey(k,
                EVP_PKEY_KEYPAIR, "PEM", "PrivateKeyInfo", NULL);
            err = (ectx == NULL);
        }
        if (err == 0) {
            err = OSSL_ENCODER_to_data(ectx, &privPem, &privPemLen) != 1;
            if (err) PRINT_ERR_MSG("Private PEM encode failed");
        }
        if (err == 0) {
            p = privPem;
            dctx = OSSL_DECODER_CTX_new_for_pkey(&privDec, "PEM", NULL,
                lvl->name, EVP_PKEY_KEYPAIR, wpLibCtx, NULL);
            err = (dctx == NULL);
        }
        if (err == 0) {
            err = OSSL_DECODER_from_data(dctx, &p, &privPemLen) != 1;
            if (err) PRINT_ERR_MSG("Private PEM decode failed");
        }
        if (err == 0) {
            err = (privDec == NULL);
        }
        if (err == 0) {
            err = mldsa_dsign_short(privDec, msg, sizeof(msg), &sig, &sigLen);
            if (err) PRINT_ERR_MSG("Sign with decoded private key failed");
        }
        if (err == 0) {
            err = mldsa_verify_msg(k, msg, sizeof(msg), sig, sigLen) != 1;
            if (err) PRINT_ERR_MSG("Decoded private key sig did not verify");
        }
        OSSL_ENCODER_CTX_free(ectx); ectx = NULL;
        OSSL_DECODER_CTX_free(dctx); dctx = NULL;
        OPENSSL_free(privPem); privPem = NULL; privPemLen = 0;
        OPENSSL_free(sig); sig = NULL; sigLen = 0;

        /* Public-key PEM (SubjectPublicKeyInfo) round-trip. */
        if (err == 0) {
            ectx = OSSL_ENCODER_CTX_new_for_pkey(k,
                OSSL_KEYMGMT_SELECT_PUBLIC_KEY, "PEM", "SubjectPublicKeyInfo",
                NULL);
            err = (ectx == NULL);
        }
        if (err == 0) {
            err = OSSL_ENCODER_to_data(ectx, &pubPem, &pubPemLen) != 1;
            if (err) PRINT_ERR_MSG("Public PEM encode failed");
        }
        if (err == 0) {
            p = pubPem;
            dctx = OSSL_DECODER_CTX_new_for_pkey(&pubDec, "PEM", NULL,
                lvl->name, OSSL_KEYMGMT_SELECT_PUBLIC_KEY, wpLibCtx, NULL);
            err = (dctx == NULL);
        }
        if (err == 0) {
            err = OSSL_DECODER_from_data(dctx, &p, &pubPemLen) != 1;
            if (err) PRINT_ERR_MSG("Public PEM decode failed");
        }
        if (err == 0) {
            err = (pubDec == NULL);
        }
        /* Sign with the original private key, verify with the decoded pub. */
        if (err == 0) {
            err = mldsa_dsign_short(k, msg, sizeof(msg), &sig, &sigLen);
        }
        if (err == 0) {
            err = mldsa_verify_msg(pubDec, msg, sizeof(msg), sig, sigLen) != 1;
            if (err) PRINT_ERR_MSG("Decoded public key did not verify sig");
        }

        OSSL_ENCODER_CTX_free(ectx); ectx = NULL;
        OSSL_DECODER_CTX_free(dctx); dctx = NULL;
        OPENSSL_free(pubPem); pubPem = NULL; pubPemLen = 0;
        OPENSSL_free(sig); sig = NULL; sigLen = 0;
        EVP_PKEY_free(privDec); privDec = NULL;
        EVP_PKEY_free(pubDec); pubDec = NULL;
        EVP_PKEY_free(k); k = NULL;
    }
    return err;
}

/* Build a minimal self-signed X509 with an ML-DSA key, sign it via the
 * provider (driving the signature AlgorithmIdentifier), and verify it. */
int test_mldsa_x509_sign_verify(void* data)
{
    int err = 0;
    size_t i;
    EVP_PKEY* k = NULL;
    X509* cert = NULL;
    EVP_MD_CTX* mdctx = NULL;
    X509_NAME* name = NULL;
    ASN1_INTEGER* serial = NULL;
    int rc;

    (void)data;
    for (i = 0; (err == 0) && (i < MLDSA_LEVEL_COUNT); i++) {
        const mldsa_test_level* lvl = &mldsa_levels[i];
        PRINT_MSG("X509 sign/verify %s", lvl->name);

        err = mldsa_keygen(lvl->name, &k);
        if (err == 0) {
            cert = X509_new();
            err = (cert == NULL);
        }
        if (err == 0) {
            err = X509_set_version(cert, 2) != 1;
        }
        if (err == 0) {
            serial = ASN1_INTEGER_new();
            err = (serial == NULL) || (ASN1_INTEGER_set(serial, 1) != 1)
                || (X509_set_serialNumber(cert, serial) != 1);
        }
        if (err == 0) {
            err = (X509_gmtime_adj(X509_getm_notBefore(cert), 0) == NULL);
        }
        if (err == 0) {
            err = (X509_gmtime_adj(X509_getm_notAfter(cert),
                60L * 60L * 24L) == NULL);
        }
        if (err == 0) {
            err = X509_set_pubkey(cert, k) != 1;
        }
        if (err == 0) {
            name = X509_get_subject_name(cert);
            err = (name == NULL) || (X509_NAME_add_entry_by_txt(name, "CN",
                MBSTRING_ASC, (const unsigned char*)"mldsa-test", -1, -1, 0)
                != 1);
        }
        if (err == 0) {
            err = X509_set_issuer_name(cert, name) != 1;
        }
        if (err == 0) {
            mdctx = EVP_MD_CTX_new();
            err = (mdctx == NULL);
        }
        if (err == 0) {
            err = EVP_DigestSignInit_ex(mdctx, NULL, NULL, wpLibCtx, NULL, k,
                NULL) != 1;
        }
        if (err == 0) {
            rc = X509_sign_ctx(cert, mdctx);
            err = (rc <= 0);
            if (err) PRINT_ERR_MSG("X509_sign_ctx failed");
        }
        if (err == 0) {
            err = X509_verify(cert, k) != 1;
            if (err) PRINT_ERR_MSG("X509_verify failed");
        }

        ASN1_INTEGER_free(serial); serial = NULL;
        EVP_MD_CTX_free(mdctx); mdctx = NULL;
        X509_free(cert); cert = NULL;
        EVP_PKEY_free(k); k = NULL;
    }
    return err;
}

#endif /* WP_HAVE_MLDSA */
