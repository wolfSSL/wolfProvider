/* test_tls_cbc.c
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

#if defined(WP_HAVE_AESCBC) && defined(WP_HAVE_RSA) && \
    defined(WP_HAVE_ECDH) && defined(WP_HAVE_SHA384)

/*
 * Direct EVP-level test for TLS 1.2 CBC OSSL_CIPHER_PARAM_TLS_MAC handling.
 * Exercises the same EVP calls the TLS record layer makes for provided CBC
 * ciphers: set TLS_VERSION + TLS_MAC_SIZE, encrypt/decrypt in-place, then
 * retrieve the MAC via TLS_MAC get_params.
 */

/* 37-byte plaintext, intentionally not block-aligned */
static const unsigned char testPlain[] = "Hello TLS 1.2 CBC test from wolfProv!";

#define BS  AES_BLOCK_SIZE

/* Encrypt a TLS 1.2 CBC record in-place. Returns 0 on success. */
static int test_tls_cbc_enc(EVP_CIPHER *cipher, const unsigned char *key,
    const unsigned char *iv, const unsigned char *pt, int ptLen,
    const unsigned char *mac, int macSize, unsigned char *buf, int *outLen)
{
    int err = 0;
    EVP_CIPHER_CTX *ctx = NULL;
    OSSL_PARAM params[3];
    unsigned int tlsVer = TLS1_2_VERSION;
    size_t macSz = (size_t)macSize;
    int inLen = BS + ptLen + macSize;

    /* Build in-place buffer: [explicit_IV][plaintext][MAC] */
    memcpy(buf, iv, BS);
    memcpy(buf + BS, pt, ptLen);
    memcpy(buf + BS + ptLen, mac, macSize);

    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        err = 1;
    }
    if (err == 0) {
        err = EVP_CipherInit_ex(ctx, cipher, NULL, key, iv, 1) != 1;
    }
    if (err == 0) {
        params[0] = OSSL_PARAM_construct_uint(OSSL_CIPHER_PARAM_TLS_VERSION,
                                              &tlsVer);
        params[1] = OSSL_PARAM_construct_size_t(OSSL_CIPHER_PARAM_TLS_MAC_SIZE,
                                                &macSz);
        params[2] = OSSL_PARAM_construct_end();
        err = EVP_CIPHER_CTX_set_params(ctx, params) != 1;
    }
    if (err == 0) {
        err = EVP_CipherUpdate(ctx, buf, outLen, buf, inLen) != 1;
    }

    EVP_CIPHER_CTX_free(ctx);
    return err;
}

/*
 * Decrypt a TLS 1.2 CBC record in-place and verify:
 *   - outLen == ptLen
 *   - plaintext at buf+BS matches original
 *   - TLS_MAC get_params returns non-NULL pointer matching original MAC
 */
static int test_tls_cbc_dec(EVP_CIPHER *cipher, const unsigned char *key,
    const unsigned char *iv, const unsigned char *origPt, int ptLen,
    const unsigned char *origMac, int macSize, unsigned char *buf, int encLen)
{
    int err = 0;
    EVP_CIPHER_CTX *ctx = NULL;
    OSSL_PARAM params[3];
    OSSL_PARAM getParams[2];
    unsigned int tlsVer = TLS1_2_VERSION;
    size_t macSz = (size_t)macSize;
    int outLen = 0;
    unsigned char *tlsMac = NULL;

    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        err = 1;
    }
    if (err == 0) {
        err = EVP_CipherInit_ex(ctx, cipher, NULL, key, iv, 0) != 1;
    }
    if (err == 0) {
        params[0] = OSSL_PARAM_construct_uint(OSSL_CIPHER_PARAM_TLS_VERSION,
                                              &tlsVer);
        params[1] = OSSL_PARAM_construct_size_t(OSSL_CIPHER_PARAM_TLS_MAC_SIZE,
                                                &macSz);
        params[2] = OSSL_PARAM_construct_end();
        err = EVP_CIPHER_CTX_set_params(ctx, params) != 1;
    }
    if (err == 0) {
        err = EVP_CipherUpdate(ctx, buf, &outLen, buf, encLen) != 1;
    }

    /* Verify output length matches plaintext length */
    if (err == 0 && outLen != ptLen) {
        PRINT_ERR_MSG("dec outLen mismatch: got %d, expected %d", outLen,
                      ptLen);
        err = 1;
    }

    /* Verify plaintext at buf+BS (past explicit IV) */
    if (err == 0 && memcmp(buf + BS, origPt, ptLen) != 0) {
        PRINT_ERR_MSG("dec plaintext mismatch");
        err = 1;
    }

    /* Retrieve and verify TLS_MAC */
    if (err == 0) {
        getParams[0] = OSSL_PARAM_construct_octet_ptr(
            OSSL_CIPHER_PARAM_TLS_MAC, (void **)&tlsMac, macSize);
        getParams[1] = OSSL_PARAM_construct_end();
        err = EVP_CIPHER_CTX_get_params(ctx, getParams) != 1;
    }
    if (err == 0 && (tlsMac == NULL || memcmp(tlsMac, origMac, macSize) != 0)) {
        PRINT_ERR_MSG("dec MAC mismatch or NULL");
        err = 1;
    }

    EVP_CIPHER_CTX_free(ctx);
    return err;
}

/* Encrypt with encCtx provider, decrypt with decCtx provider. */
static int test_tls_cbc_interop(OSSL_LIB_CTX *encCtx, OSSL_LIB_CTX *decCtx,
    const char *cipherName, int keyLen, int macSize)
{
    int err = 0;
    EVP_CIPHER *encCipher = NULL;
    EVP_CIPHER *decCipher = NULL;
    unsigned char key[32];
    unsigned char iv[BS];
    unsigned char mac[48];
    unsigned char buf[BS + sizeof(testPlain) + 48 + BS];
    int encLen = 0;

    encCipher = EVP_CIPHER_fetch(encCtx, cipherName, "");
    decCipher = EVP_CIPHER_fetch(decCtx, cipherName, "");
    if (encCipher == NULL || decCipher == NULL) {
        err = 1;
    }

    if (err == 0) {
        memset(key, 0xAA, keyLen);
        memset(iv, 0xBB, BS);
        memset(mac, 0xCC, macSize);
    }
    if (err == 0) {
        err = test_tls_cbc_enc(encCipher, key, iv, testPlain,
                               sizeof(testPlain), mac, macSize, buf, &encLen);
    }
    if (err == 0) {
        err = test_tls_cbc_dec(decCipher, key, iv, testPlain,
                               sizeof(testPlain), mac, macSize, buf, encLen);
    }

    EVP_CIPHER_free(encCipher);
    EVP_CIPHER_free(decCipher);
    return err;
}

static const struct {
    const char *cipher;
    int keyLen;
    int macSize;
} tlsCbcTests[] = {
    { "AES-256-CBC", 32, 48 },  /* ECDHE-RSA-AES256-SHA384 */
    { "AES-128-CBC", 16, 32 },  /* ECDHE-RSA-AES128-SHA256 */
};
#define TLS_CBC_TEST_CNT \
    (int)(sizeof(tlsCbcTests) / sizeof(tlsCbcTests[0]))

int test_tls12_cbc(void *data)
{
    int err = 0;
    int i;

    (void)data;

    for (i = 0; i < TLS_CBC_TEST_CNT && err == 0; i++) {
        PRINT_MSG("TLS 1.2 CBC (OpenSSL -> wolfProvider): %s mac=%d",
                  tlsCbcTests[i].cipher, tlsCbcTests[i].macSize);
        err = test_tls_cbc_interop(osslLibCtx, wpLibCtx,
                                   tlsCbcTests[i].cipher,
                                   tlsCbcTests[i].keyLen,
                                   tlsCbcTests[i].macSize);
        if (err == 0) {
            PRINT_MSG("TLS 1.2 CBC (wolfProvider -> OpenSSL): %s mac=%d",
                      tlsCbcTests[i].cipher, tlsCbcTests[i].macSize);
            err = test_tls_cbc_interop(wpLibCtx, osslLibCtx,
                                       tlsCbcTests[i].cipher,
                                       tlsCbcTests[i].keyLen,
                                       tlsCbcTests[i].macSize);
        }
    }

    return err;
}

int test_tls12_cbc_ossl(void *data)
{
    int err = 0;
    int i;

    (void)data;

    for (i = 0; i < TLS_CBC_TEST_CNT && err == 0; i++) {
        PRINT_MSG("TLS 1.2 CBC (OpenSSL baseline): %s mac=%d",
                  tlsCbcTests[i].cipher, tlsCbcTests[i].macSize);
        err = test_tls_cbc_interop(osslLibCtx, osslLibCtx,
                                   tlsCbcTests[i].cipher,
                                   tlsCbcTests[i].keyLen,
                                   tlsCbcTests[i].macSize);
    }

    return err;
}

/*
 * AES TLS CBC negative padding test.
 *
 * MtE TLS with macSize > 0 always returns success from decryption -- bad
 * padding causes a random MAC substitution (preventing padding oracle).
 * Verify the extracted MAC does NOT match the original.
 */
static int test_aes_tls_cbc_bad_pad_helper(OSSL_LIB_CTX *libCtx,
    const char *cipherName, int keyLen, int macSize)
{
    int err = 0;
    EVP_CIPHER *cipher = NULL;
    EVP_CIPHER_CTX *ctx = NULL;
    OSSL_PARAM params[3];
    OSSL_PARAM getParams[2];
    unsigned int tlsVer = TLS1_2_VERSION;
    size_t macSz = (size_t)macSize;
    unsigned char key[32];
    unsigned char iv[BS];
    unsigned char mac[48];
    unsigned char buf[BS + sizeof(testPlain) + 48 + BS];
    int encLen = 0;
    int decLen = 0;
    int ptLen = (int)sizeof(testPlain);
    unsigned char *tlsMac = NULL;

    memset(key, 0xAA, keyLen);
    memset(iv, 0xBB, BS);
    memset(mac, 0xCC, macSize);

    cipher = EVP_CIPHER_fetch(libCtx, cipherName, "");
    if (cipher == NULL) {
        err = 1;
    }

    /* Encrypt a valid TLS record. */
    if (err == 0) {
        err = test_tls_cbc_enc(cipher, key, iv, testPlain, ptLen,
                               mac, macSize, buf, &encLen);
    }

    /* CBC bit-flip: corrupt second-to-last byte in second-to-last ciphertext
     * block, flipping a padding byte in the last plaintext block. */
    if (err == 0) {
        int corruptOffset = encLen - BS - 2;
        buf[corruptOffset] ^= 0x01;
    }

    /* Decrypt -- MtE TLS returns success but substitutes a random MAC. */
    if (err == 0) {
        ctx = EVP_CIPHER_CTX_new();
        if (ctx == NULL) {
            err = 1;
        }
    }
    if (err == 0) {
        err = EVP_CipherInit_ex(ctx, cipher, NULL, key, iv, 0) != 1;
    }
    if (err == 0) {
        params[0] = OSSL_PARAM_construct_uint(OSSL_CIPHER_PARAM_TLS_VERSION,
                                              &tlsVer);
        params[1] = OSSL_PARAM_construct_size_t(OSSL_CIPHER_PARAM_TLS_MAC_SIZE,
                                                &macSz);
        params[2] = OSSL_PARAM_construct_end();
        err = EVP_CIPHER_CTX_set_params(ctx, params) != 1;
    }
    if (err == 0) {
        err = EVP_CipherUpdate(ctx, buf, &decLen, buf, encLen) != 1;
    }

    /* Bad padding should have triggered random MAC substitution. */
    if (err == 0) {
        getParams[0] = OSSL_PARAM_construct_octet_ptr(
            OSSL_CIPHER_PARAM_TLS_MAC, (void **)&tlsMac, macSize);
        getParams[1] = OSSL_PARAM_construct_end();
        err = EVP_CIPHER_CTX_get_params(ctx, getParams) != 1;
    }
    if (err == 0) {
        if (tlsMac != NULL && memcmp(tlsMac, mac, macSize) == 0) {
            PRINT_ERR_MSG("TLS CBC bad-pad: MAC should have been randomized "
                          "but matches original (%s)", cipherName);
            err = 1;
        }
    }

    EVP_CIPHER_CTX_free(ctx);
    EVP_CIPHER_free(cipher);
    return err;
}

/*
 * Decrypt a TLS 1.2 CBC record split across two EVP_CipherUpdate calls so the
 * second completes a buffered block. Exercises the buffered-block path that
 * advanced the output pointer before the record's IV/padding processing.
 */
static int test_aes_tls_cbc_split_helper(OSSL_LIB_CTX *libCtx,
    const char *cipherName, int keyLen, int macSize)
{
    int err = 0;
    EVP_CIPHER *cipher = NULL;
    EVP_CIPHER_CTX *ctx = NULL;
    OSSL_PARAM params[3];
    unsigned int tlsVer = TLS1_2_VERSION;
    size_t macSz = (size_t)macSize;
    unsigned char key[32];
    unsigned char iv[BS];
    unsigned char mac[48];
    unsigned char buf[BS + sizeof(testPlain) + 48 + BS];
    unsigned char *out = NULL;
    int encLen = 0;
    int l1 = 0;
    int l2 = 0;
    int split = BS + 1; /* leave one byte buffered after the first update */

    memset(key, 0xAA, keyLen);
    memset(iv, 0xBB, BS);
    memset(mac, 0xCC, macSize);

    cipher = EVP_CIPHER_fetch(libCtx, cipherName, "");
    if (cipher == NULL) {
        err = 1;
    }
    if (err == 0) {
        err = test_tls_cbc_enc(cipher, key, iv, testPlain, sizeof(testPlain),
                               mac, macSize, buf, &encLen);
    }
    /* Output buffer sized to the produced plaintext so an overread past the
     * written region is caught. */
    if (err == 0) {
        out = OPENSSL_malloc((size_t)(encLen - BS));
        err = out == NULL;
    }
    if (err == 0) {
        ctx = EVP_CIPHER_CTX_new();
        err = ctx == NULL;
    }
    if (err == 0) {
        err = EVP_CipherInit_ex(ctx, cipher, NULL, key, iv, 0) != 1;
    }
    if (err == 0) {
        params[0] = OSSL_PARAM_construct_uint(OSSL_CIPHER_PARAM_TLS_VERSION,
                                              &tlsVer);
        params[1] = OSSL_PARAM_construct_size_t(OSSL_CIPHER_PARAM_TLS_MAC_SIZE,
                                                &macSz);
        params[2] = OSSL_PARAM_construct_end();
        err = EVP_CIPHER_CTX_set_params(ctx, params) != 1;
    }
    if (err == 0) {
        /* Only the second update completes the split record and must succeed. */
        (void)EVP_CipherUpdate(ctx, out, &l1, buf, split);
        err = EVP_CipherUpdate(ctx, out + l1, &l2, buf + split,
                               encLen - split) != 1;
    }

    OPENSSL_free(out);
    EVP_CIPHER_CTX_free(ctx);
    EVP_CIPHER_free(cipher);
    return err;
}

int test_aes_tls_cbc_split(void *data)
{
    int err = 0;

    (void)data;

    PRINT_MSG("TLS 1.2 AES-256-CBC split-record decrypt (wolfProvider)");
    err = test_aes_tls_cbc_split_helper(wpLibCtx, "AES-256-CBC", 32, 48);
    if (err == 0) {
        PRINT_MSG("TLS 1.2 AES-128-CBC split-record decrypt (wolfProvider)");
        err = test_aes_tls_cbc_split_helper(wpLibCtx, "AES-128-CBC", 16, 32);
    }

    return err;
}

int test_aes_tls_cbc_bad_pad(void *data)
{
    int err = 0;

    (void)data;

    PRINT_MSG("TLS 1.2 AES-256-CBC negative padding (wolfProvider)");
    err = test_aes_tls_cbc_bad_pad_helper(wpLibCtx, "AES-256-CBC", 32, 48);
    if (err == 0) {
        PRINT_MSG("TLS 1.2 AES-128-CBC negative padding (wolfProvider)");
        err = test_aes_tls_cbc_bad_pad_helper(wpLibCtx, "AES-128-CBC", 16, 32);
    }

    return err;
}

#endif /* WP_HAVE_AESCBC && WP_HAVE_RSA && WP_HAVE_ECDH && WP_HAVE_SHA384 */

#ifdef WP_HAVE_DES3CBC
#if !defined(HAVE_FIPS) || defined(WP_ALLOW_NON_FIPS)

#define DES3_BS 8

/* New DES3 TLS cipher ctx at tlsVer. A NULL macLen omits TLS_MAC_SIZE
 * entirely, as an ETM/no-MAC record layer does; passing it exercises the MtE
 * path. Returns NULL on failure. */
static EVP_CIPHER_CTX *des3_tls_ctx(EVP_CIPHER *cipher,
    const unsigned char *key, const unsigned char *iv, unsigned int tlsVer,
    const size_t *macLen, int enc)
{
    int err = 0;
    EVP_CIPHER_CTX *ctx = NULL;
    OSSL_PARAM params[3];
    size_t macSz = 0;
    int n = 0;

    ctx = EVP_CIPHER_CTX_new();
    err = ctx == NULL;

    if (err == 0) {
        err = EVP_CipherInit_ex(ctx, cipher, NULL, key, iv, enc) != 1;
    }
    if (err == 0) {
        params[n++] = OSSL_PARAM_construct_uint(OSSL_CIPHER_PARAM_TLS_VERSION,
                                                &tlsVer);
        if (macLen != NULL) {
            macSz = *macLen;
            params[n++] = OSSL_PARAM_construct_size_t(
                OSSL_CIPHER_PARAM_TLS_MAC_SIZE, &macSz);
        }
        params[n] = OSSL_PARAM_construct_end();
        err = EVP_CIPHER_CTX_set_params(ctx, params) != 1;
    }
    if (err != 0) {
        EVP_CIPHER_CTX_free(ctx);
        ctx = NULL;
    }

    return ctx;
}

/* Encrypt a TLS 1.2 record [explicit_IV][pt][mac] into buf. A NULL mac builds
 * an ETM/no-MAC record. Returns 0 on success with encLen set. */
static int des3_tls_record(EVP_CIPHER *cipher, const unsigned char *key,
    const unsigned char *iv, const unsigned char *pt, size_t ptLen,
    const unsigned char *mac, size_t macLen, unsigned char *buf, int *encLen)
{
    int err = 0;
    EVP_CIPHER_CTX *ctx = NULL;
    int inLen = DES3_BS + (int)ptLen;

    ctx = des3_tls_ctx(cipher, key, iv, TLS1_2_VERSION,
                       mac != NULL ? &macLen : NULL, 1);
    err = ctx == NULL;

    if (err == 0) {
        memcpy(buf, iv, DES3_BS);
        if (ptLen > 0) {
            memcpy(buf + DES3_BS, pt, ptLen);
        }
        if (mac != NULL) {
            memcpy(buf + DES3_BS + ptLen, mac, macLen);
            inLen += (int)macLen;
        }
        err = EVP_CipherUpdate(ctx, buf, encLen, buf, inLen) != 1;
    }

    EVP_CIPHER_CTX_free(ctx);
    return err;
}

/* DES3 TLS CBC bad padding: MtE (macSize>0) must return success and substitute
 * a random MAC (padding oracle defense), so the extracted TLS_MAC must not
 * match the original. */
static int test_des3_tls_cbc_bad_pad_helper(OSSL_LIB_CTX *libCtx)
{
    int err = 0;
    EVP_CIPHER *cipher = NULL;
    EVP_CIPHER_CTX *ctx = NULL;
    OSSL_PARAM getParams[2];
    int macSize = 20;
    size_t macSz = (size_t)macSize;
    unsigned char key[24];
    unsigned char iv[DES3_BS];
    unsigned char mac[20];
    /* 16 bytes plaintext: record is [IV(8)][pt(16)][MAC(20)] = 44, pads to 48. */
    unsigned char pt[16];
    unsigned char buf[64];
    int encLen = 0;
    int decLen = 0;
    unsigned char *tlsMac = NULL;

    memset(key, 0xAA, sizeof(key));
    memset(iv, 0xBB, sizeof(iv));
    memset(mac, 0xCC, sizeof(mac));
    memset(pt, 0x42, sizeof(pt));

    cipher = EVP_CIPHER_fetch(libCtx, "DES-EDE3-CBC", "");
    if (cipher == NULL) {
        err = 1;
    }

    /* Encrypt a valid TLS record: [explicit_IV][plaintext][MAC]. */
    if (err == 0) {
        err = des3_tls_record(cipher, key, iv, pt, sizeof(pt), mac, sizeof(mac),
                              buf, &encLen);
    }

    /* CBC bit-flip: corrupt a padding byte in the last plaintext block
     * without touching the pad-length byte at the final position. */
    if (err == 0) {
        buf[encLen - DES3_BS - 2] ^= 0x01;
    }

    /* Decrypt -- MtE TLS returns success but substitutes a random MAC. */
    if (err == 0) {
        ctx = des3_tls_ctx(cipher, key, iv, TLS1_2_VERSION, &macSz, 0);
        err = ctx == NULL;
    }
    if (err == 0) {
        if (EVP_CipherUpdate(ctx, buf, &decLen, buf, encLen) != 1) {
            PRINT_ERR_MSG("DES3 TLS CBC bad-pad: decryption should have "
                          "succeeded with a randomized MAC but failed");
            err = 1;
        }
    }

    /* Bad padding should have triggered random MAC substitution. */
    if (err == 0) {
        getParams[0] = OSSL_PARAM_construct_octet_ptr(
            OSSL_CIPHER_PARAM_TLS_MAC, (void **)&tlsMac, macSize);
        getParams[1] = OSSL_PARAM_construct_end();
        err = EVP_CIPHER_CTX_get_params(ctx, getParams) != 1;
    }
    if (err == 0) {
        if (tlsMac == NULL) {
            PRINT_ERR_MSG("DES3 TLS CBC bad-pad: TLS_MAC must be a non-NULL "
                          "randomized MAC");
            err = 1;
        }
        else if (memcmp(tlsMac, mac, macSize) == 0) {
            PRINT_ERR_MSG("DES3 TLS CBC bad-pad: MAC should have been "
                          "randomized but matches original");
            err = 1;
        }
    }

    EVP_CIPHER_CTX_free(ctx);
    EVP_CIPHER_free(cipher);
    return err;
}

int test_des3_tls_cbc_bad_pad(void *data)
{
    (void)data;

    PRINT_MSG("DES3 TLS 1.2 CBC negative padding (wolfProvider)");
    return test_des3_tls_cbc_bad_pad_helper(wpLibCtx);
}

/*
 * Positive DES3 TLS 1.2 CBC decrypt of a valid record split across two
 * EVP_CipherUpdate calls, so the second update completes a buffered block and
 * advances the output pointer past the record base. This exercises the
 * record-base-pointer padding strip; a valid record must decrypt successfully.
 */
int test_des3_tls_cbc_dec(void *data)
{
    int err = 0;
    EVP_CIPHER *cipher = NULL;
    EVP_CIPHER_CTX *ctx = NULL;
    unsigned char key[24];
    unsigned char iv[DES3_BS];
    /* 37 bytes: not block-aligned, so padding is non-trivial. */
    unsigned char pt[37];
    unsigned char buf[64];
    unsigned char *out = NULL;
    int encLen = 0;
    int l1 = 0;
    int l2 = 0;
    int split = DES3_BS + 1; /* one byte left buffered after update 1 */

    (void)data;

    memset(key, 0xAA, sizeof(key));
    memset(iv, 0xBB, sizeof(iv));
    memset(pt, 0x42, sizeof(pt));

    PRINT_MSG("DES3 TLS 1.2 CBC split-record decrypt (wolfProvider)");

    cipher = EVP_CIPHER_fetch(wpLibCtx, "DES-EDE3-CBC", "");
    if (cipher == NULL) {
        err = 1;
    }

    /* Encrypt the record [explicit_IV][plaintext] in TLS mode. */
    if (err == 0) {
        err = des3_tls_record(cipher, key, iv, pt, sizeof(pt), NULL, 0, buf,
                              &encLen);
    }

    /* Output buffer sized to the produced plaintext so an overread past the
     * written region is caught under sanitizers. */
    if (err == 0) {
        out = OPENSSL_malloc((size_t)(encLen - DES3_BS));
        err = out == NULL;
    }

    /* Decrypt in TLS mode split across two updates. */
    if (err == 0) {
        ctx = des3_tls_ctx(cipher, key, iv, TLS1_2_VERSION, NULL, 0);
        err = ctx == NULL;
    }
    if (err == 0) {
        /* Only the second update completes the record; must succeed. */
        (void)EVP_CipherUpdate(ctx, out, &l1, buf, split);
        err = EVP_CipherUpdate(ctx, out + l1, &l2, buf + split,
                               encLen - split) != 1;
    }

    OPENSSL_free(out);
    EVP_CIPHER_CTX_free(ctx);
    EVP_CIPHER_free(cipher);
    return err;
}

/* DES3 MtE (macSize>0) TLS 1.2 CBC decrypt of a valid record: verifies the
 * recovered plaintext, its length, and that the extracted TLS_MAC equals the
 * original MAC. */
int test_des3_tls_cbc_mte(void *data)
{
    int err = 0;
    EVP_CIPHER *cipher = NULL;
    EVP_CIPHER_CTX *ctx = NULL;
    OSSL_PARAM getParams[2];
    int macSize = 20;
    size_t macSz = (size_t)macSize;
    unsigned char key[24];
    unsigned char iv[DES3_BS];
    unsigned char mac[20];
    unsigned char pt[16];
    unsigned char buf[64];
    unsigned char *tlsMac = NULL;
    int encLen = 0;
    int decLen = 0;

    (void)data;

    memset(key, 0xAA, sizeof(key));
    memset(iv, 0xBB, sizeof(iv));
    memset(mac, 0xCC, sizeof(mac));
    memset(pt, 0x42, sizeof(pt));

    PRINT_MSG("DES3 TLS 1.2 CBC MtE decrypt (wolfProvider)");

    cipher = EVP_CIPHER_fetch(wpLibCtx, "DES-EDE3-CBC", "");
    if (cipher == NULL) {
        err = 1;
    }

    /* Encrypt a valid record: [explicit_IV][plaintext][MAC]. */
    if (err == 0) {
        err = des3_tls_record(cipher, key, iv, pt, sizeof(pt), mac, sizeof(mac),
                              buf, &encLen);
    }

    /* Decrypt the whole record in one update; must succeed. */
    if (err == 0) {
        ctx = des3_tls_ctx(cipher, key, iv, TLS1_2_VERSION, &macSz, 0);
        err = ctx == NULL;
    }
    if (err == 0) {
        err = EVP_CipherUpdate(ctx, buf, &decLen, buf, encLen) != 1;
    }

    /* Length excludes the explicit IV, MAC and padding. */
    if (err == 0 && decLen != (int)sizeof(pt)) {
        PRINT_ERR_MSG("DES3 TLS CBC MtE: unexpected plaintext length %d",
                      decLen);
        err = 1;
    }
    /* Recovered plaintext sits after the explicit IV block. */
    if (err == 0 && memcmp(buf + DES3_BS, pt, sizeof(pt)) != 0) {
        PRINT_ERR_MSG("DES3 TLS CBC MtE: recovered plaintext mismatch");
        err = 1;
    }

    /* Valid padding: extracted MAC must equal the original. */
    if (err == 0) {
        getParams[0] = OSSL_PARAM_construct_octet_ptr(
            OSSL_CIPHER_PARAM_TLS_MAC, (void **)&tlsMac, macSize);
        getParams[1] = OSSL_PARAM_construct_end();
        err = EVP_CIPHER_CTX_get_params(ctx, getParams) != 1;
    }
    if (err == 0) {
        if (tlsMac == NULL || memcmp(tlsMac, mac, macSize) != 0) {
            PRINT_ERR_MSG("DES3 TLS CBC MtE: extracted MAC does not match "
                          "original");
            err = 1;
        }
    }

    EVP_CIPHER_CTX_free(ctx);
    EVP_CIPHER_free(cipher);
    return err;
}

/* DES3 ETM/no-MAC (macSize==0) TLS 1.2 CBC decrypt of a valid record in a
 * single update: asserts the recovered payload length and content once the
 * explicit IV is stripped and padding removed. */
int test_des3_tls_cbc_etm(void *data)
{
    int err = 0;
    EVP_CIPHER *cipher = NULL;
    EVP_CIPHER_CTX *ctx = NULL;
    unsigned char key[24];
    unsigned char iv[DES3_BS];
    /* 37 bytes: not block-aligned, so padding is non-trivial. */
    unsigned char pt[37];
    unsigned char buf[64];
    int ptLen = (int)sizeof(pt);
    int encLen = 0;
    int decLen = 0;
    int i;

    (void)data;

    memset(key, 0xAA, sizeof(key));
    memset(iv, 0xBB, sizeof(iv));
    /* Distinct bytes so a wrong recovery offset is caught, not just a length. */
    for (i = 0; i < ptLen; i++) {
        pt[i] = (unsigned char)(i + 1);
    }

    PRINT_MSG("DES3 TLS 1.2 CBC ETM/no-MAC decrypt (wolfProvider)");

    cipher = EVP_CIPHER_fetch(wpLibCtx, "DES-EDE3-CBC", "");
    if (cipher == NULL) {
        err = 1;
    }

    /* Encrypt the record [explicit_IV][plaintext] in TLS mode with no MAC. */
    if (err == 0) {
        err = des3_tls_record(cipher, key, iv, pt, sizeof(pt), NULL, 0, buf,
                              &encLen);
    }

    /* Decrypt the whole record in one update; must succeed. */
    if (err == 0) {
        ctx = des3_tls_ctx(cipher, key, iv, TLS1_2_VERSION, NULL, 0);
        err = ctx == NULL;
    }
    if (err == 0) {
        err = EVP_CipherUpdate(ctx, buf, &decLen, buf, encLen) != 1;
    }

    /* Length excludes the explicit IV and padding (no MAC in ETM mode). */
    if (err == 0 && decLen != ptLen) {
        PRINT_ERR_MSG("DES3 TLS CBC ETM: unexpected plaintext length %d",
                      decLen);
        err = 1;
    }
    /* Recovered plaintext sits after the explicit IV block. */
    if (err == 0 && memcmp(buf + DES3_BS, pt, ptLen) != 0) {
        PRINT_ERR_MSG("DES3 TLS CBC ETM: recovered plaintext mismatch");
        err = 1;
    }

    EVP_CIPHER_CTX_free(ctx);
    EVP_CIPHER_free(cipher);
    return err;
}

/* DES3 ETM/no-MAC (macSize==0) TLS 1.2 CBC decrypt with corrupted padding:
 * unlike MtE (random-MAC substitution), no-MAC mode has no padding-oracle
 * concern, so bad padding must make decryption fail. */
int test_des3_tls_cbc_etm_bad_pad(void *data)
{
    int err = 0;
    EVP_CIPHER *cipher = NULL;
    EVP_CIPHER_CTX *ctx = NULL;
    unsigned char key[24];
    unsigned char iv[DES3_BS];
    /* 37 bytes: not block-aligned, matching the positive ETM test's record. */
    unsigned char pt[37];
    unsigned char buf[64];
    int encLen = 0;
    int decLen = 0;

    (void)data;

    memset(key, 0xAA, sizeof(key));
    memset(iv, 0xBB, sizeof(iv));
    memset(pt, 0x42, sizeof(pt));

    PRINT_MSG("DES3 TLS 1.2 CBC ETM/no-MAC bad padding (wolfProvider)");

    cipher = EVP_CIPHER_fetch(wpLibCtx, "DES-EDE3-CBC", "");
    if (cipher == NULL) {
        err = 1;
    }

    /* Encrypt a valid record [explicit_IV][plaintext] with no MAC. */
    if (err == 0) {
        err = des3_tls_record(cipher, key, iv, pt, sizeof(pt), NULL, 0, buf,
                              &encLen);
    }

    /* CBC bit-flip: corrupt a padding byte in the last plaintext block
     * without touching the pad-length byte at the final position. */
    if (err == 0) {
        buf[encLen - DES3_BS - 2] ^= 0x01;
    }

    /* Decrypt in ETM mode: bad padding must fail, not substitute a MAC. */
    if (err == 0) {
        ctx = des3_tls_ctx(cipher, key, iv, TLS1_2_VERSION, NULL, 0);
        err = ctx == NULL;
    }
    if (err == 0) {
        if (EVP_CipherUpdate(ctx, buf, &decLen, buf, encLen) == 1) {
            PRINT_ERR_MSG("DES3 TLS CBC ETM bad-pad: decryption should have "
                          "failed but succeeded");
            err = 1;
        }
    }

    EVP_CIPHER_CTX_free(ctx);
    EVP_CIPHER_free(cipher);
    return err;
}

/* Copying a DES3 TLS ctx after an MtE decrypt must deep-copy the extracted
 * MAC: a shallow copy would share one buffer and double-free on cleanup. */
int test_des3_tls_cbc_dup(void *data)
{
    int err = 0;
    EVP_CIPHER *cipher = NULL;
    EVP_CIPHER_CTX *ctx = NULL;
    EVP_CIPHER_CTX *dup = NULL;
    OSSL_PARAM getParams[2];
    int macSize = 20;
    size_t macSz = (size_t)macSize;
    unsigned char key[24];
    unsigned char iv[DES3_BS];
    unsigned char mac[20];
    unsigned char pt[16];
    unsigned char buf[64];
    unsigned char *srcMac = NULL;
    unsigned char *dupMac = NULL;
    int encLen = 0;
    int decLen = 0;

    (void)data;

    memset(key, 0xAA, sizeof(key));
    memset(iv, 0xBB, sizeof(iv));
    memset(mac, 0xCC, sizeof(mac));
    memset(pt, 0x42, sizeof(pt));

    PRINT_MSG("DES3 TLS 1.2 CBC ctx copy deep-copies the extracted MAC");

    cipher = EVP_CIPHER_fetch(wpLibCtx, "DES-EDE3-CBC", "");
    if (cipher == NULL) {
        err = 1;
    }
    if (err == 0) {
        err = des3_tls_record(cipher, key, iv, pt, sizeof(pt), mac, sizeof(mac),
                              buf, &encLen);
    }

    /* Decrypt so the ctx holds a heap-allocated tlsmac. */
    if (err == 0) {
        ctx = des3_tls_ctx(cipher, key, iv, TLS1_2_VERSION, &macSz, 0);
        err = ctx == NULL;
    }
    if (err == 0) {
        err = EVP_CipherUpdate(ctx, buf, &decLen, buf, encLen) != 1;
    }
    if (err == 0) {
        getParams[0] = OSSL_PARAM_construct_octet_ptr(
            OSSL_CIPHER_PARAM_TLS_MAC, (void **)&srcMac, macSize);
        getParams[1] = OSSL_PARAM_construct_end();
        err = EVP_CIPHER_CTX_get_params(ctx, getParams) != 1;
    }
    if (err == 0 && (srcMac == NULL || memcmp(srcMac, mac, macSize) != 0)) {
        PRINT_ERR_MSG("DES3 TLS CBC dup: source MAC does not match original");
        err = 1;
    }

    /* Copy the ctx and read the MAC back out of the copy. */
    if (err == 0) {
        dup = EVP_CIPHER_CTX_new();
        err = dup == NULL;
    }
    if (err == 0) {
        err = EVP_CIPHER_CTX_copy(dup, ctx) != 1;
    }
    if (err == 0) {
        getParams[0] = OSSL_PARAM_construct_octet_ptr(
            OSSL_CIPHER_PARAM_TLS_MAC, (void **)&dupMac, macSize);
        getParams[1] = OSSL_PARAM_construct_end();
        err = EVP_CIPHER_CTX_get_params(dup, getParams) != 1;
    }
    if (err == 0 && (dupMac == NULL || memcmp(dupMac, mac, macSize) != 0)) {
        PRINT_ERR_MSG("DES3 TLS CBC dup: copied MAC does not match original");
        err = 1;
    }
    /* A shallow copy would hand back the source's own buffer. */
    if (err == 0 && dupMac == srcMac) {
        PRINT_ERR_MSG("DES3 TLS CBC dup: MAC buffer shared with source");
        err = 1;
    }

    EVP_CIPHER_CTX_free(dup);
    EVP_CIPHER_CTX_free(ctx);
    EVP_CIPHER_free(cipher);
    return err;
}

/* Records the decrypt must reject up front: an oversized TLS MAC size, which
 * would otherwise overrun the internal randMac buffer, and a record too short
 * to hold the explicit IV, MAC and pad-length byte. */
int test_des3_tls_cbc_bad_len(void *data)
{
    int err = 0;
    EVP_CIPHER *cipher = NULL;
    EVP_CIPHER_CTX *ctx = NULL;
    size_t bigMacSz = (size_t)EVP_MAX_MD_SIZE + 1;
    size_t macSz = 20;
    unsigned char key[24];
    unsigned char iv[DES3_BS];
    unsigned char buf[64];
    int decLen = 0;

    (void)data;

    memset(key, 0xAA, sizeof(key));
    memset(iv, 0xBB, sizeof(iv));
    memset(buf, 0x00, sizeof(buf));

    PRINT_MSG("DES3 TLS 1.2 CBC decrypt rejects an oversized MAC size");

    cipher = EVP_CIPHER_fetch(wpLibCtx, "DES-EDE3-CBC", "");
    if (cipher == NULL) {
        err = 1;
    }
    if (err == 0) {
        ctx = des3_tls_ctx(cipher, key, iv, TLS1_2_VERSION, &bigMacSz, 0);
        err = ctx == NULL;
    }
    if (err == 0 && EVP_CipherUpdate(ctx, buf, &decLen, buf, 48) == 1) {
        PRINT_ERR_MSG("DES3 TLS CBC: oversized MAC size was accepted");
        err = 1;
    }
    EVP_CIPHER_CTX_free(ctx);
    ctx = NULL;

    PRINT_MSG("DES3 TLS 1.2 CBC decrypt rejects a too-short record");

    /* The sub-test above decrypted buf in place; start from a known state. */
    memset(buf, 0x00, sizeof(buf));

    if (err == 0) {
        ctx = des3_tls_ctx(cipher, key, iv, TLS1_2_VERSION, &macSz, 0);
        err = ctx == NULL;
    }
    /* 24 < DES3_BS + 20 + 1: too short to hold IV, MAC and pad length. */
    if (err == 0 && EVP_CipherUpdate(ctx, buf, &decLen, buf, 24) == 1) {
        PRINT_ERR_MSG("DES3 TLS CBC: too-short record was accepted");
        err = 1;
    }

    EVP_CIPHER_CTX_free(ctx);
    EVP_CIPHER_free(cipher);
    return err;
}

/* Below TLS 1.1 there is no explicit per-record IV. The decrypt strips one
 * unconditionally, so these versions must be rejected, not silently
 * stripped of 8 bytes of payload. */
int test_des3_tls_cbc_old_version(void *data)
{
    int err = 0;
    EVP_CIPHER *cipher = NULL;
    EVP_CIPHER_CTX *ctx = NULL;
    size_t macSz = 20;
    unsigned char key[24];
    unsigned char iv[DES3_BS];
    unsigned char mac[20];
    unsigned char pt[16];
    unsigned char buf[64];
    int encLen = 0;
    int decLen = 0;

    (void)data;

    memset(key, 0xAA, sizeof(key));
    memset(iv, 0xBB, sizeof(iv));
    memset(mac, 0xCC, sizeof(mac));
    memset(pt, 0x42, sizeof(pt));

    PRINT_MSG("DES3 TLS CBC decrypt rejects TLS 1.0 and SSLv3");

    cipher = EVP_CIPHER_fetch(wpLibCtx, "DES-EDE3-CBC", "");
    if (cipher == NULL) {
        err = 1;
    }
    /* A well-formed record; only the version makes it unacceptable. */
    if (err == 0) {
        err = des3_tls_record(cipher, key, iv, pt, sizeof(pt), mac, sizeof(mac),
                              buf, &encLen);
    }

    if (err == 0) {
        ctx = des3_tls_ctx(cipher, key, iv, TLS1_VERSION, &macSz, 0);
        err = ctx == NULL;
    }
    if (err == 0 && EVP_CipherUpdate(ctx, buf, &decLen, buf, encLen) == 1) {
        PRINT_ERR_MSG("DES3 TLS CBC: TLS 1.0 record was accepted");
        err = 1;
    }
    EVP_CIPHER_CTX_free(ctx);
    ctx = NULL;

    if (err == 0) {
        ctx = des3_tls_ctx(cipher, key, iv, SSL3_VERSION, &macSz, 0);
        err = ctx == NULL;
    }
    if (err == 0 && EVP_CipherUpdate(ctx, buf, &decLen, buf, encLen) == 1) {
        PRINT_ERR_MSG("DES3 TLS CBC: SSLv3 record was accepted");
        err = 1;
    }

    EVP_CIPHER_CTX_free(ctx);
    EVP_CIPHER_free(cipher);
    return err;
}

/* Minimal MtE record with an empty payload, [IV 8][pt 0][MAC 20]: drives the
 * output length to 0 and the MAC start to 0, the tightest decrypt boundary. */
int test_des3_tls_cbc_empty_pt(void *data)
{
    int err = 0;
    EVP_CIPHER *cipher = NULL;
    EVP_CIPHER_CTX *ctx = NULL;
    OSSL_PARAM getParams[2];
    int macSize = 20;
    size_t macSz = (size_t)macSize;
    unsigned char key[24];
    unsigned char iv[DES3_BS];
    unsigned char mac[20];
    unsigned char buf[64];
    unsigned char *tlsMac = NULL;
    int encLen = 0;
    int decLen = 0;

    (void)data;

    memset(key, 0xAA, sizeof(key));
    memset(iv, 0xBB, sizeof(iv));
    memset(mac, 0xCC, sizeof(mac));

    PRINT_MSG("DES3 TLS 1.2 CBC MtE decrypt of an empty payload");

    cipher = EVP_CIPHER_fetch(wpLibCtx, "DES-EDE3-CBC", "");
    if (cipher == NULL) {
        err = 1;
    }
    if (err == 0) {
        err = des3_tls_record(cipher, key, iv, NULL, 0, mac, sizeof(mac), buf,
                              &encLen);
    }
    if (err == 0) {
        ctx = des3_tls_ctx(cipher, key, iv, TLS1_2_VERSION, &macSz, 0);
        err = ctx == NULL;
    }
    if (err == 0) {
        err = EVP_CipherUpdate(ctx, buf, &decLen, buf, encLen) != 1;
    }
    if (err == 0 && decLen != 0) {
        PRINT_ERR_MSG("DES3 TLS CBC empty payload: unexpected length %d",
                      decLen);
        err = 1;
    }
    /* The MAC must still be extracted correctly with macStart at 0. */
    if (err == 0) {
        getParams[0] = OSSL_PARAM_construct_octet_ptr(
            OSSL_CIPHER_PARAM_TLS_MAC, (void **)&tlsMac, macSize);
        getParams[1] = OSSL_PARAM_construct_end();
        err = EVP_CIPHER_CTX_get_params(ctx, getParams) != 1;
    }
    if (err == 0 && (tlsMac == NULL || memcmp(tlsMac, mac, macSize) != 0)) {
        PRINT_ERR_MSG("DES3 TLS CBC empty payload: extracted MAC mismatch");
        err = 1;
    }

    EVP_CIPHER_CTX_free(ctx);
    EVP_CIPHER_free(cipher);
    return err;
}

/* Growing TLS_MAC_SIZE after a decrypt must drop the stored MAC: it was sized
 * for the old value, so readers trusting the new size would over-read it. */
int test_des3_tls_cbc_macsize_change(void *data)
{
    int err = 0;
    EVP_CIPHER *cipher = NULL;
    EVP_CIPHER_CTX *ctx = NULL;
    EVP_CIPHER_CTX *dup = NULL;
    OSSL_PARAM params[2];
    OSSL_PARAM getParams[2];
    size_t macSz = 20;
    size_t bigMacSz = 48;
    unsigned char key[24];
    unsigned char iv[DES3_BS];
    unsigned char mac[20];
    unsigned char pt[16];
    unsigned char buf[64];
    unsigned char sentinel = 0;
    unsigned char *tlsMac = &sentinel;
    int encLen = 0;
    int decLen = 0;

    (void)data;

    memset(key, 0xAA, sizeof(key));
    memset(iv, 0xBB, sizeof(iv));
    memset(mac, 0xCC, sizeof(mac));
    memset(pt, 0x42, sizeof(pt));

    PRINT_MSG("DES3 TLS 1.2 CBC MAC size change drops the stale MAC");

    cipher = EVP_CIPHER_fetch(wpLibCtx, "DES-EDE3-CBC", "");
    if (cipher == NULL) {
        err = 1;
    }
    if (err == 0) {
        err = des3_tls_record(cipher, key, iv, pt, sizeof(pt), mac, sizeof(mac),
                              buf, &encLen);
    }

    /* Decrypt with a 20-byte MAC size: tlsmac is a 20-byte allocation. */
    if (err == 0) {
        ctx = des3_tls_ctx(cipher, key, iv, TLS1_2_VERSION, &macSz, 0);
        err = ctx == NULL;
    }
    if (err == 0) {
        err = EVP_CipherUpdate(ctx, buf, &decLen, buf, encLen) != 1;
    }

    /* Grow the MAC size; the 20-byte MAC must not survive as a 48-byte one. */
    if (err == 0) {
        params[0] = OSSL_PARAM_construct_size_t(OSSL_CIPHER_PARAM_TLS_MAC_SIZE,
                                                &bigMacSz);
        params[1] = OSSL_PARAM_construct_end();
        err = EVP_CIPHER_CTX_set_params(ctx, params) != 1;
    }
    if (err == 0) {
        getParams[0] = OSSL_PARAM_construct_octet_ptr(
            OSSL_CIPHER_PARAM_TLS_MAC, (void **)&tlsMac, 0);
        getParams[1] = OSSL_PARAM_construct_end();
        err = EVP_CIPHER_CTX_get_params(ctx, getParams) != 1;
    }
    if (err == 0 && tlsMac != NULL) {
        PRINT_ERR_MSG("DES3 TLS CBC: stale MAC survived a MAC size change");
        err = 1;
    }
    /* Copying now must not read the new size out of the old allocation. */
    if (err == 0) {
        dup = EVP_CIPHER_CTX_new();
        err = dup == NULL;
    }
    if (err == 0) {
        err = EVP_CIPHER_CTX_copy(dup, ctx) != 1;
    }

    EVP_CIPHER_CTX_free(dup);
    EVP_CIPHER_CTX_free(ctx);
    EVP_CIPHER_free(cipher);
    return err;
}

#undef DES3_BS

/*
 * Test DES3 CBC padding validation (exercises fix #838 constant-time padding).
 * Encrypts data of various sizes and verifies decrypt roundtrip works,
 * exercising all padding byte values (1-8 for DES block size).
 */
static int test_des3_cbc_pad_roundtrip(OSSL_LIB_CTX *encCtx,
    OSSL_LIB_CTX *decCtx)
{
    int err = 0;
    EVP_CIPHER *encCipher = NULL;
    EVP_CIPHER *decCipher = NULL;
    unsigned char key[24];
    unsigned char iv[8];
    unsigned char pt[64];
    unsigned char ct[128];
    unsigned char dec[128];
    int ctLen, decLen, finalLen;
    int i;

    encCipher = EVP_CIPHER_fetch(encCtx, "DES-EDE3-CBC", "");
    decCipher = EVP_CIPHER_fetch(decCtx, "DES-EDE3-CBC", "");
    if (encCipher == NULL || decCipher == NULL) {
        err = 1;
    }

    memset(key, 0xAA, sizeof(key));
    memset(iv, 0xBB, sizeof(iv));
    if (RAND_bytes(pt, sizeof(pt)) != 1) {
        err = 1;
    }

    /* Test various plaintext sizes to exercise all padding values (1-8). */
    for (i = 1; i <= 8 && err == 0; i++) {
        int ptLen = 8 + i; /* 9..16 bytes, padding will be 7..0+8 */
        EVP_CIPHER_CTX *ctx;

        /* Encrypt */
        ctx = EVP_CIPHER_CTX_new();
        if (ctx == NULL) { err = 1; break; }
        if (EVP_EncryptInit_ex(ctx, encCipher, NULL, key, iv) != 1) {
            err = 1;
        }
        ctLen = 0;
        if (err == 0 && EVP_EncryptUpdate(ctx, ct, &ctLen, pt, ptLen) != 1) {
            err = 1;
        }
        finalLen = 0;
        if (err == 0 && EVP_EncryptFinal_ex(ctx, ct + ctLen, &finalLen) != 1) {
            err = 1;
        }
        ctLen += finalLen;
        EVP_CIPHER_CTX_free(ctx);

        if (err != 0) break;

        /* Decrypt */
        ctx = EVP_CIPHER_CTX_new();
        if (ctx == NULL) { err = 1; break; }
        if (EVP_DecryptInit_ex(ctx, decCipher, NULL, key, iv) != 1) {
            err = 1;
        }
        decLen = 0;
        if (err == 0 && EVP_DecryptUpdate(ctx, dec, &decLen, ct, ctLen) != 1) {
            err = 1;
        }
        finalLen = 0;
        if (err == 0 && EVP_DecryptFinal_ex(ctx, dec + decLen, &finalLen) != 1) {
            PRINT_ERR_MSG("DES3 DecryptFinal failed for ptLen=%d", ptLen);
            err = 1;
        }
        decLen += finalLen;
        EVP_CIPHER_CTX_free(ctx);

        if (err == 0 && (decLen != ptLen ||
                         memcmp(dec, pt, ptLen) != 0)) {
            PRINT_ERR_MSG("DES3 roundtrip mismatch for ptLen=%d", ptLen);
            err = 1;
        }
    }

    EVP_CIPHER_free(encCipher);
    EVP_CIPHER_free(decCipher);
    return err;
}

int test_des3_tls_cbc(void *data)
{
    int err = 0;

    (void)data;

    PRINT_MSG("DES3 CBC padding roundtrip (OpenSSL -> wolfProvider)");
    err = test_des3_cbc_pad_roundtrip(osslLibCtx, wpLibCtx);
    if (err == 0) {
        PRINT_MSG("DES3 CBC padding roundtrip (wolfProvider -> OpenSSL)");
        err = test_des3_cbc_pad_roundtrip(wpLibCtx, osslLibCtx);
    }
    if (err == 0) {
        PRINT_MSG("DES3 CBC padding roundtrip (wolfProvider -> wolfProvider)");
        err = test_des3_cbc_pad_roundtrip(wpLibCtx, wpLibCtx);
    }

    return err;
}

#endif /* !HAVE_FIPS || WP_ALLOW_NON_FIPS */
#endif /* WP_HAVE_DES3CBC */
