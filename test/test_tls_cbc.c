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

/*
 * DES3 TLS CBC negative padding test.
 * Exercises wp_ct_byte_mask_ne in the DES3 TLS constant-time padding path.
 * DES3 TLS does not use TLS_MAC_SIZE/TLS_MAC -- it only validates padding.
 */
static int test_des3_tls_cbc_bad_pad_helper(OSSL_LIB_CTX *libCtx)
{
    int err = 0;
    EVP_CIPHER *cipher = NULL;
    EVP_CIPHER_CTX *ctx = NULL;
    OSSL_PARAM params[2];
    unsigned int tlsVer = TLS1_2_VERSION;
    unsigned char key[24];
    unsigned char iv[DES3_BS];
    /* 10 bytes of plaintext. Padding: off=10%8=2, pad=8-2-1=5, padded=16. */
    unsigned char pt[10];
    unsigned char buf[64];
    int encLen = 0;
    int decLen = 0;

    memset(key, 0xAA, sizeof(key));
    memset(iv, 0xBB, sizeof(iv));
    memset(pt, 0x42, sizeof(pt));

    cipher = EVP_CIPHER_fetch(libCtx, "DES-EDE3-CBC", "");
    if (cipher == NULL) {
        err = 1;
    }

    /* Encrypt in TLS mode. */
    if (err == 0) {
        ctx = EVP_CIPHER_CTX_new();
        if (ctx == NULL) {
            err = 1;
        }
    }
    if (err == 0) {
        err = EVP_CipherInit_ex(ctx, cipher, NULL, key, iv, 1) != 1;
    }
    if (err == 0) {
        params[0] = OSSL_PARAM_construct_uint(OSSL_CIPHER_PARAM_TLS_VERSION,
                                              &tlsVer);
        params[1] = OSSL_PARAM_construct_end();
        err = EVP_CIPHER_CTX_set_params(ctx, params) != 1;
    }
    if (err == 0) {
        /* Copy plaintext into buf; the provider pads in-place in the output. */
        memcpy(buf, pt, sizeof(pt));
        err = EVP_CipherUpdate(ctx, buf, &encLen, buf, (int)sizeof(pt)) != 1;
    }
    EVP_CIPHER_CTX_free(ctx);
    ctx = NULL;

    /* CBC bit-flip: corrupt a padding byte in the last plaintext block
     * without touching the pad-length byte at the final position. */
    if (err == 0) {
        buf[encLen - DES3_BS - 2] ^= 0x01;
    }

    /* Decrypt -- should fail due to bad padding. */
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
        params[1] = OSSL_PARAM_construct_end();
        err = EVP_CIPHER_CTX_set_params(ctx, params) != 1;
    }
    if (err == 0) {
        int ret = EVP_CipherUpdate(ctx, buf, &decLen, buf, encLen);
        if (ret == 1) {
            PRINT_ERR_MSG("DES3 TLS CBC bad-pad: decryption should have failed "
                          "but succeeded");
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

#undef DES3_BS

#endif /* !HAVE_FIPS || WP_ALLOW_NON_FIPS */
#endif /* WP_HAVE_DES3CBC */
