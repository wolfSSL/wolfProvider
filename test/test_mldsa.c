/* test_mldsa.c
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

#include "unit.h"

#include <openssl/core_names.h>

#ifdef WP_HAVE_MLDSA

#include <wolfssl/wolfcrypt/dilithium.h>

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

#endif /* WP_HAVE_MLDSA */
