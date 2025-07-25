/* test_cipher.c
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

#if defined(WP_HAVE_DES3CBC) || defined(WP_HAVE_AESCBC) || \
    defined(WP_HAVE_AESECB) || defined(WP_HAVE_AESCTR) || \
    defined(WP_HAVE_AESCFB) || defined(WP_HAVE_AESCTS)

static int test_cipher_enc(const EVP_CIPHER *cipher,
                           unsigned char *key, unsigned char *iv,
                           unsigned char *msg, int len, unsigned char *enc,
                           int pad)
{
    int err;
    EVP_CIPHER_CTX *ctx;
    int encLen;
    int fLen = 0;

    err = (ctx = EVP_CIPHER_CTX_new()) == NULL;
    if (err == 0) {
       err = EVP_EncryptInit(ctx, cipher, key, iv) != 1;
    }
    if (err == 0) {
        err = EVP_CIPHER_CTX_set_padding(ctx, pad) != 1;
    }
    if (err == 0) {
        err = EVP_EncryptUpdate(ctx, enc, &encLen, msg, len) != 1;
    }
    if (err == 0) {
        err = EVP_EncryptFinal_ex(ctx, enc + encLen, &fLen) != 1;
    }

    if (err == 0) {
        PRINT_BUFFER("Encrypted", enc, encLen + fLen);
    }

    EVP_CIPHER_CTX_free(ctx);

    return err;
}

#endif

#if defined(WP_HAVE_DES3CBC) || defined(WP_HAVE_AESCBC) || \
    defined(WP_HAVE_AESECB)

static int test_cipher_dec(const EVP_CIPHER *cipher,
                           unsigned char *key, unsigned char *iv,
                           unsigned char *msg, int len, unsigned char *enc,
                           int encLen, unsigned char *dec, int pad)
{
    int err;
    EVP_CIPHER_CTX *ctx;
    int decLen;
    int fLen;

    err = (ctx = EVP_CIPHER_CTX_new()) == NULL;
    if (err == 0) {
        err = EVP_DecryptInit(ctx, cipher, key, iv) != 1;
    }
    if (err == 0) {
        err = EVP_CIPHER_CTX_set_padding(ctx, pad) != 1;
    }
    if (err == 0) {
        err = EVP_DecryptUpdate(ctx, dec, &decLen, enc, encLen) != 1;
    }
    if (err == 0) {
        err = EVP_DecryptFinal_ex(ctx, dec + decLen, &fLen) != 1;
    }

    if (err == 0) {
        PRINT_BUFFER("Decrypted", dec, decLen + fLen);

        if (decLen + fLen != (int)len || memcmp(dec, msg, len) != 0) {
            err = 1;
        }
    }

    EVP_CIPHER_CTX_free(ctx);

    return err;
}

static int test_cipher_enc_dec(void *data, const char *cipher, int keyLen,
    int ivLen)
{
    int err = 0;
    unsigned char msg[16] = "Test pattern";
    unsigned char key[32];
    unsigned char iv[16];
    unsigned char enc[sizeof(msg) + 16];
    unsigned char dec[sizeof(msg) + 16];
    EVP_CIPHER *ocipher;
    EVP_CIPHER *wcipher;

    (void)data;

    ocipher = EVP_CIPHER_fetch(osslLibCtx, cipher, "");
    wcipher = EVP_CIPHER_fetch(wpLibCtx, cipher, "");

    if (RAND_bytes(key, keyLen) != 1) {
        err = 1;
    }
    if (err == 0) {
        if (RAND_bytes(iv, ivLen) != 1) {
            err = 1;
        }
    }

    if (err == 0) {
        PRINT_BUFFER("Key", key, keyLen);
        PRINT_BUFFER("IV", iv, ivLen);
        PRINT_BUFFER("Message", msg, sizeof(msg));
    }

    if (err == 0) {
        PRINT_MSG("Encrypt with OpenSSL - padding");
        err = test_cipher_enc(ocipher, key, iv, msg, sizeof(msg), enc, 1);
    }
    if (err == 0) {
        PRINT_MSG("Decrypt with wolfprovider - padding");
        err = test_cipher_dec(wcipher, key, iv, msg, sizeof(msg), enc,
                              sizeof(msg) + ivLen, dec, 1);
    }

    if (err == 0) {
        PRINT_MSG("Encrypt with wolfprovider - padding");
        err = test_cipher_enc(wcipher, key, iv, msg, sizeof(msg), enc, 1);
    }
    if (err == 0) {
        PRINT_MSG("Decrypt with OpenSSL - padding");
        err = test_cipher_dec(ocipher, key, iv, msg, sizeof(msg), enc,
                              sizeof(msg) + ivLen, dec, 1);
    }

    if (err == 0) {
        PRINT_MSG("Encrypt with OpenSSL - no pad");
        err = test_cipher_enc(ocipher, key, iv, msg, sizeof(msg), enc, 0);
    }
    if (err == 0) {
        PRINT_MSG("Decrypt with wolfprovider - no pad");
        err = test_cipher_dec(wcipher, key, iv, msg, sizeof(msg), enc,
                              sizeof(msg), dec, 0);
    }

    if (err == 0) {
        PRINT_MSG("Encrypt with wolfprovider - no pad");
        err = test_cipher_enc(wcipher, key, iv, msg, sizeof(msg), enc, 0);
    }
    if (err == 0) {
        PRINT_MSG("Decrypt with OpenSSL - no pad");
        err = test_cipher_dec(ocipher, key, iv, msg, sizeof(msg), enc,
                              sizeof(msg), dec, 0);
    }

    EVP_CIPHER_free(wcipher);
    EVP_CIPHER_free(ocipher);

    return err;
}

#endif

#if defined(WP_HAVE_DES3CBC) || defined(WP_HAVE_AESCBC) || \
    defined(WP_HAVE_AESECB) || defined(WP_HAVE_AESCTR) || \
    defined(WP_HAVE_AESCFB) || defined(WP_HAVE_AESCTS)


/******************************************************************************/

static int test_stream_enc(const EVP_CIPHER *cipher,
                           unsigned char *key, unsigned char *iv,
                           unsigned char *msg, int len, unsigned char *enc,
                           unsigned char *encExp, int expLen)
{
    int err;
    EVP_CIPHER_CTX *ctx;
    int eLen = 0;
    int encLen;
    int i;
    int j;

    err = (ctx = EVP_CIPHER_CTX_new()) == NULL;
    for (i = 1; (err == 0) && (i <= (int)len); i++) {
        eLen = 0;
        err = EVP_EncryptInit(ctx, cipher, key, iv) != 1;

        for (j = 0; (err == 0) && (j < (int)len); j += i) {
            int l = len - j;
            if (i < l)
                l = i;
            err = EVP_EncryptUpdate(ctx, enc + eLen, &encLen, msg + j, l) != 1;
            if (err == 0) {
                eLen += encLen;
            }
        }

        if (err == 0) {
            err = EVP_EncryptFinal_ex(ctx, enc + eLen, &encLen) != 1;
            if (err == 0) {
                eLen += encLen;
            }
        }
        if (err == 0 && (eLen != expLen || memcmp(enc, encExp, expLen) != 0)) {
            err = 1;
        }
    }
    if (err == 0) {
        PRINT_BUFFER("Encrypted", enc, eLen);
    }

    EVP_CIPHER_CTX_free(ctx);

    return err;
}

static int test_stream_dec(const EVP_CIPHER *cipher,
                           unsigned char *key, unsigned char *iv,
                           unsigned char *msg, int len, unsigned char *enc,
                           int encLen, unsigned char *dec)
{
    int err;
    EVP_CIPHER_CTX *ctx;
    int dLen;
    int decLen = 0;
    int i;
    int j;

    err = (ctx = EVP_CIPHER_CTX_new()) == NULL;
    for (i = 1; (err == 0) && (i <= (int)encLen); i++) {
        dLen = 0;
        err = EVP_DecryptInit(ctx, cipher, key, iv) != 1;

        for (j = 0; (err == 0) && (j < (int)encLen); j += i) {
            int l = encLen - j;
            if (i < l)
                l = i;
            err = EVP_DecryptUpdate(ctx, dec + dLen, &decLen, enc + j, l) != 1;
            if (err == 0) {
                dLen += decLen;
            }
        }

        if (err == 0) {
            err = EVP_DecryptFinal_ex(ctx, dec + dLen, &decLen) != 1;
            if (err == 0) {
                dLen += decLen;
            }
        }
        if ((err == 0) && ((dLen != len) || (memcmp(dec, msg, len) != 0))) {
            PRINT_BUFFER("Decrypted", dec, dLen);
            err = 1;
        }
    }
    if (err == 0) {
        PRINT_BUFFER("Decrypted", dec, len);
    }

    EVP_CIPHER_CTX_free(ctx);

    return err;
}

static int test_stream_enc_dec(void *data, const char *cipher, int keyLen,
    int ivLen, int msgLen, int pad)
{
    int err = 0;
    unsigned char msg[16] = "Test pattern";
    unsigned char key[32];
    unsigned char iv[16];
    unsigned char enc[sizeof(msg) + 16];
    unsigned char encExp[sizeof(msg) + 16];
    unsigned char dec[sizeof(msg) + 16];
    int encLen;
    EVP_CIPHER *ocipher;
    EVP_CIPHER *wcipher;

    ocipher = EVP_CIPHER_fetch(osslLibCtx, cipher, "");
    wcipher = EVP_CIPHER_fetch(wpLibCtx, cipher, "");

    if (pad) {
        encLen = (msgLen + ivLen) & (~(ivLen-1));
    }
    else {
        encLen = msgLen;
    }

    (void)data;

    if (RAND_bytes(key, keyLen) != 1) {
        printf("generate key failed\n");
        err = 1;
    }
    if (err == 0) {
        if (RAND_bytes(iv, ivLen) != 1) {
            printf("generate iv failed\n");
            err = 1;
        }
    }

    if (err == 0) {
        PRINT_BUFFER("Key", key, keyLen);
        PRINT_BUFFER("IV", iv, ivLen);
        PRINT_BUFFER("Message", msg, sizeof(msg));
    }

    if (err == 0) {
        PRINT_MSG("Encrypt with OpenSSL");
        err = test_cipher_enc(ocipher, key, iv, msg, msgLen, encExp, 1);
    }

    if (err == 0) {
        PRINT_MSG("Encrypt Stream with wolfprovider");
        err = test_stream_enc(wcipher, key, iv, msg, msgLen, enc, encExp,
                              encLen);
    }
    if (err == 0) {
        PRINT_MSG("Decrypt Stream with wolfprovider");
        err = test_stream_dec(wcipher, key, iv, msg, msgLen, enc, encLen,
                              dec);
    }

    EVP_CIPHER_free(wcipher);
    EVP_CIPHER_free(ocipher);

    return err;
}

static int test_cipher_null_zero_ex(void *data, const char *cipher, int keyLen,
    int ivLen)
{
    int err = 0;
    unsigned char msg[16] = "Test pattern";
    unsigned char key[32];
    unsigned char iv[16];
    unsigned char enc[sizeof(msg) + 16];
    EVP_CIPHER *ocipher;
    EVP_CIPHER *wcipher;
    EVP_CIPHER_CTX *ctx;

    (void)data;

    ocipher = EVP_CIPHER_fetch(osslLibCtx, cipher, "");
    wcipher = EVP_CIPHER_fetch(wpLibCtx, cipher, "");

    if (RAND_bytes(key, keyLen) != 1) {
        err = 1;
    }
    if (err == 0) {
        if (RAND_bytes(iv, ivLen) != 1) {
            err = 1;
        }
    }

    /* Test that a final call with NULL/NULL/0 yields the correct return
     * value, flow mimics that of libssh2 */
    err = (ctx = EVP_CIPHER_CTX_new()) == NULL;
    if (err == 0) {
       err = EVP_CipherInit(ctx, ocipher, key, iv, 1) != 1;
    }
    if (err == 0) {
        err = EVP_Cipher(ctx, enc, msg, sizeof(msg)) <= 0;
    }
    /* Return is 0, not negative value for NULL/NULL/0 input */
    if (err == 0) {
        err = EVP_Cipher(ctx, NULL, NULL, 0) != 0;
    }
    EVP_CIPHER_CTX_free(ctx);

    err = (ctx = EVP_CIPHER_CTX_new()) == NULL;
    if (err == 0) {
       err = EVP_CipherInit(ctx, wcipher, key, iv, 1) != 1;
    }
    if (err == 0) {
        err = EVP_Cipher(ctx, enc, msg, sizeof(msg)) <= 0;
    }
    /* Return is 0, not negative value for NULL/NULL/0 input */
    if (err == 0) {
        err = EVP_Cipher(ctx, NULL, NULL, 0) != 0;
    }
    EVP_CIPHER_CTX_free(ctx);

    EVP_CIPHER_free(wcipher);
    EVP_CIPHER_free(ocipher);

    return err;
}

int test_cipher_null_zero(void *data)
{
    int err = 0;

#ifdef WP_HAVE_AESECB
    err = test_cipher_null_zero_ex(data, "AES-256-ECB", 32, 16);
#endif
#ifdef WP_HAVE_AESCBC
    if (err == 0) {
        err = test_cipher_null_zero_ex(data, "AES-256-CBC", 32, 16);
    }
#endif
#ifdef WP_HAVE_AESCTR
    if (err == 0) {
        err = test_cipher_null_zero_ex(data, "AES-256-CTR", 32, 16);
    }
#endif
#ifdef WP_HAVE_AESCFB
    if (err == 0) {
        err = test_cipher_null_zero_ex(data, "AES-256-CFB", 32, 16);
    }
#endif

    return err;
}

#endif /* WP_HAVE_DES3CBC || WP_HAVE_AESCBC */

/******************************************************************************/

#ifdef WP_HAVE_DES3CBC


int test_des3_cbc(void *data)
{
    return test_cipher_enc_dec(data, "DES-EDE3-CBC", 24, 8);
}

/******************************************************************************/

int test_des3_cbc_stream(void *data)
{
    int err;

    err = test_stream_enc_dec(data, "DES-EDE3-CBC", 24, 8, 16, 1);
    if (err == 0)
        err = test_stream_enc_dec(data, "DES-EDE3-CBC", 24, 8, 1, 1);
    if (err == 0)
        err = test_stream_enc_dec(data, "DES-EDE3-CBC", 24, 8, 7, 1);

    return err;
}

#endif /* WP_HAVE_DES3CBC */

/******************************************************************************/

#ifdef WP_HAVE_AESECB

int test_aes128_ecb(void *data)
{
    return test_cipher_enc_dec(data, "AES-128-ECB", 16, 16);
}

/******************************************************************************/

int test_aes192_ecb(void *data)
{
    return test_cipher_enc_dec(data, "AES-192-ECB", 24, 16);
}

/******************************************************************************/

int test_aes256_ecb(void *data)
{
    return test_cipher_enc_dec(data, "AES-256-ECB", 32, 16);
}

/******************************************************************************/

int test_aes128_ecb_stream(void *data)
{
    int err;

    err = test_stream_enc_dec(data, "AES-128-ECB", 16, 16, 16, 1);
    if (err == 0)
        err = test_stream_enc_dec(data, "AES-128-ECB", 16, 16, 1, 1);

    return err;
}

/******************************************************************************/

int test_aes192_ecb_stream(void *data)
{
    int err;

    err = test_stream_enc_dec(data, "AES-192-ECB", 24, 16, 15, 1);
    if (err == 0)
        err = test_stream_enc_dec(data, "AES-192-ECB", 24, 16, 2, 1);

    return err;
}

/******************************************************************************/

int test_aes256_ecb_stream(void *data)
{
    int err;

    err = test_stream_enc_dec(data, "AES-256-ECB", 32, 16, 14, 1);
    if (err == 0)
        err = test_stream_enc_dec(data, "AES-256-ECB", 32, 16, 3, 1);

    return err;
}

#endif /* WP_HAVE_AESECB */

/******************************************************************************/

#ifdef WP_HAVE_AESCBC

int test_aes128_cbc(void *data)
{
    return test_cipher_enc_dec(data, "AES-128-CBC", 16, 16);
}

/******************************************************************************/

int test_aes192_cbc(void *data)
{
    return test_cipher_enc_dec(data, "AES-192-CBC", 24, 16);
}

/******************************************************************************/

int test_aes256_cbc(void *data)
{
    return test_cipher_enc_dec(data, "AES-256-CBC", 32, 16);
}

/******************************************************************************/

int test_aes128_cbc_stream(void *data)
{
    int err;

    err = test_stream_enc_dec(data, "AES-128-CBC", 16, 16, 16, 1);
    if (err == 0)
        err = test_stream_enc_dec(data, "AES-128-CBC", 16, 16, 1, 1);

    return err;
}

/******************************************************************************/

int test_aes192_cbc_stream(void *data)
{
    int err;

    err = test_stream_enc_dec(data, "AES-192-CBC", 24, 16, 15, 1);
    if (err == 0)
        err = test_stream_enc_dec(data, "AES-192-CBC", 24, 16, 2, 1);

    return err;
}

/******************************************************************************/

int test_aes256_cbc_stream(void *data)
{
    int err;

    err = test_stream_enc_dec(data, "AES-256-CBC", 32, 16, 14, 1);
    if (err == 0)
        err = test_stream_enc_dec(data, "AES-256-CBC", 32, 16, 3, 1);

    return err;
}

#endif /* WP_HAVE_AESCBC */

/******************************************************************************/

#ifdef WP_HAVE_AESCTR

int test_aes128_ctr_stream(void *data)
{
    int err;

    err = test_stream_enc_dec(data, "AES-128-CTR", 16, 16, 16, 0);
    if (err == 0)
        err = test_stream_enc_dec(data, "AES-128-CTR", 16, 16, 1, 0);

    return err;
}

/******************************************************************************/

int test_aes192_ctr_stream(void *data)
{
    int err;

    err = test_stream_enc_dec(data, "AES-192-CTR", 24, 16, 15, 0);
    if (err == 0)
        err = test_stream_enc_dec(data, "AES-192-CTR", 24, 16, 2, 0);

    return err;
}

/******************************************************************************/

int test_aes256_ctr_stream(void *data)
{
    int err;

    err = test_stream_enc_dec(data, "AES-256-CTR", 32, 16, 14, 0);
    if (err == 0)
        err = test_stream_enc_dec(data, "AES-256-CTR", 32, 16, 3, 0);

    return err;
}

#endif /* WP_HAVE_AESCTR */

#ifdef WP_HAVE_AESCFB

int test_aes128_cfb_stream(void *data)
{
    int err;

    err = test_stream_enc_dec(data, "AES-128-CFB", 16, 16, 16, 0);
    if (err == 0)
        err = test_stream_enc_dec(data, "AES-128-CFB", 16, 16, 1, 0);

    return err;
}

/******************************************************************************/

int test_aes192_cfb_stream(void *data)
{
    int err;

    err = test_stream_enc_dec(data, "AES-192-CFB", 24, 16, 15, 0);
    if (err == 0)
        err = test_stream_enc_dec(data, "AES-192-CFB", 24, 16, 2, 0);

    return err;
}

/******************************************************************************/

int test_aes256_cfb_stream(void *data)
{
    int err;

    err = test_stream_enc_dec(data, "AES-256-CFB", 32, 16, 14, 0);
    if (err == 0)
        err = test_stream_enc_dec(data, "AES-256-CFB", 32, 16, 3, 0);

    return err;
}

#endif /* WP_HAVE_AESCFB */

#ifdef WP_HAVE_AESCTS

static int test_cipher_cts_enc_err_cases(const EVP_CIPHER *cipher,
                           unsigned char *key, unsigned char *iv,
                           unsigned char *msg, int len, unsigned char *enc)
{
    int err;
    EVP_CIPHER_CTX *ctx;
    int encLen;
    int ret;

    (void)len; /* Length from caller not used in error cases */

    /* Test case 1: Input less than block length - should fail */
    err = (ctx = EVP_CIPHER_CTX_new()) == NULL;
    if (err == 0) {
       err = EVP_EncryptInit(ctx, cipher, key, iv) != 1;
    }
    if (err == 0) {
        err = EVP_CIPHER_CTX_set_padding(ctx, 0) != 1;
    }
    if (err == 0) {
        /* Try to encrypt 5 bytes - should fail */
        ret = EVP_EncryptUpdate(ctx, enc, &encLen, msg, 5);
        if (ret == 1) {
            PRINT_MSG("ERROR: Encryption succeeded with short message when it should fail");
            err = 1;
        }
        else {
            PRINT_MSG("SUCCESS: Encryption correctly failed with short message");
        }
    }
    EVP_CIPHER_CTX_free(ctx);

    /* Test case 2: Double update not allowed */
    if (err == 0) {
        err = (ctx = EVP_CIPHER_CTX_new()) == NULL;
    }
    if (err == 0) {
       err = EVP_EncryptInit(ctx, cipher, key, iv) != 1;
    }
    if (err == 0) {
        err = EVP_CIPHER_CTX_set_padding(ctx, 0) != 1;
    }
    /* First update should succeed */
    if (err == 0) {
        err = EVP_EncryptUpdate(ctx, enc, &encLen, msg, 17) != 1;
        PRINT_MSG("First update of 17 bytes succeeded as expected");
    }
    /* Second update should fail */
    if (err == 0) {
        ret = EVP_EncryptUpdate(ctx, enc + encLen, &encLen, msg + 17, 17);
        if (ret == 1) {
            PRINT_MSG("ERROR: Second update succeeded when it should fail");
            err = 1;
        }
        else {
            PRINT_MSG("SUCCESS: Second update correctly failed");
        }
    }
    EVP_CIPHER_CTX_free(ctx);

    return err;
}

static int test_cipher_cts_krb_enc(const EVP_CIPHER *cipher,
                           unsigned char *key, unsigned char *iv,
                           unsigned char *msg, int len, unsigned char *enc)
{
    int err;
    EVP_CIPHER_CTX *ctx;
    int outlen, total_len = 0;
    unsigned char iv_cts[16];
    OSSL_PARAM params[2];

    memset(iv_cts, 0, sizeof(iv_cts));
    if (iv != NULL) {
        memcpy(iv_cts, iv, sizeof(iv_cts));
    }

    /* First encryption run */
    err = (ctx = EVP_CIPHER_CTX_new()) == NULL;
    if (err == 0) {
        /* Set up parameters for CS3 mode */
        params[0] = OSSL_PARAM_construct_utf8_string(OSSL_CIPHER_PARAM_CTS_MODE,
                                                    (char *)"CS3", 0);
        params[1] = OSSL_PARAM_construct_end();

        /* Initialize with cipher and key only first */
        err = EVP_CipherInit_ex2(ctx, cipher, key, NULL, 1, params) != 1;
    }
    if (err == 0) {
        /* Set IV and get updated IV */
        err = EVP_CipherUpdate(ctx, enc, &outlen, msg, len) != 1;
        total_len = outlen;
    }
    if (err == 0) {
        err = EVP_CipherFinal_ex(ctx, enc + total_len, &outlen) != 1;
        total_len += outlen;
    }
    if (err == 0) {
        /* Get the updated IV */
        err = EVP_CIPHER_CTX_get_updated_iv(ctx, iv_cts, sizeof(iv_cts)) != 1;
    }

    EVP_CIPHER_CTX_free(ctx);
    ctx = NULL;

    if (err == 0) {
        PRINT_BUFFER("KRB CTS Encrypted", enc, total_len);
        if (iv != NULL) {
            PRINT_BUFFER("Updated IV", iv_cts, sizeof(iv_cts));
        }
    }

    return err;
}

static int test_cipher_cts_krb_dec(const EVP_CIPHER *cipher,
                           unsigned char *key, unsigned char *iv,
                           unsigned char *msg, int len, unsigned char *enc,
                           int encLen, unsigned char *dec)
{
    int err;
    EVP_CIPHER_CTX *ctx;
    int outlen, total_len = 0;
    unsigned char iv_cts[16];
    OSSL_PARAM params[2];

    memset(iv_cts, 0, sizeof(iv_cts));
    if (iv != NULL) {
        memcpy(iv_cts, iv, sizeof(iv_cts));
    }

    err = (ctx = EVP_CIPHER_CTX_new()) == NULL;
    if (err == 0) {
        /* Set up parameters for CS3 mode */
        params[0] = OSSL_PARAM_construct_utf8_string(OSSL_CIPHER_PARAM_CTS_MODE,
                                                    (char *)"CS3", 0);
        params[1] = OSSL_PARAM_construct_end();

        /* Initialize with cipher and key only first */
        err = EVP_CipherInit_ex2(ctx, cipher, key, NULL, 0, params) != 1;
    }
    if (err == 0) {
        /* Set IV and decrypt */
        err = EVP_CipherUpdate(ctx, dec, &outlen, enc, encLen) != 1;
        total_len = outlen;
    }
    if (err == 0) {
        err = EVP_CipherFinal_ex(ctx, dec + total_len, &outlen) != 1;
        total_len += outlen;
    }
    if (err == 0) {
        /* Get the updated IV if needed */
        err = EVP_CIPHER_CTX_get_updated_iv(ctx, iv_cts, sizeof(iv_cts)) != 1;
    }

    if (err == 0) {
        PRINT_BUFFER("KRB CTS Decrypted", dec, total_len);
        if (iv != NULL) {
            PRINT_BUFFER("Updated IV", iv_cts, sizeof(iv_cts));
        }

        if (total_len != len || memcmp(dec, msg, len) != 0) {
            PRINT_MSG("KRB CTS Decryption mismatch");
            err = 1;
        }
    }

    EVP_CIPHER_CTX_free(ctx);

    return err;
}

static int test_cipher_cts_kat(const EVP_CIPHER* cipher, unsigned char* key)
{
    int err = 0;
    /* Test vectors taken from RFC3962 Appendix B */
    const struct {
        const char* input;
        const char* output;
        size_t inLen;
        size_t outLen;
    } vects[] = {
        {
            "\x49\x20\x77\x6f\x75\x6c\x64\x20\x6c\x69\x6b\x65\x20\x74\x68\x65"
            "\x20",
            "\xc6\x35\x35\x68\xf2\xbf\x8c\xb4\xd8\xa5\x80\x36\x2d\xa7\xff\x7f"
            "\x97",
            17, 17
        },
        {
            "\x49\x20\x77\x6f\x75\x6c\x64\x20\x6c\x69\x6b\x65\x20\x74\x68\x65"
            "\x20\x47\x65\x6e\x65\x72\x61\x6c\x20\x47\x61\x75\x27\x73\x20",
            "\xfc\x00\x78\x3e\x0e\xfd\xb2\xc1\xd4\x45\xd4\xc8\xef\xf7\xed\x22"
            "\x97\x68\x72\x68\xd6\xec\xcc\xc0\xc0\x7b\x25\xe2\x5e\xcf\xe5",
            31, 31
        },
        {
            "\x49\x20\x77\x6f\x75\x6c\x64\x20\x6c\x69\x6b\x65\x20\x74\x68\x65"
            "\x20\x47\x65\x6e\x65\x72\x61\x6c\x20\x47\x61\x75\x27\x73\x20\x43",
            "\x39\x31\x25\x23\xa7\x86\x62\xd5\xbe\x7f\xcb\xcc\x98\xeb\xf5\xa8"
            "\x97\x68\x72\x68\xd6\xec\xcc\xc0\xc0\x7b\x25\xe2\x5e\xcf\xe5\x84",
            32, 32
        },
        {
            "\x49\x20\x77\x6f\x75\x6c\x64\x20\x6c\x69\x6b\x65\x20\x74\x68\x65"
            "\x20\x47\x65\x6e\x65\x72\x61\x6c\x20\x47\x61\x75\x27\x73\x20\x43"
            "\x68\x69\x63\x6b\x65\x6e\x2c\x20\x70\x6c\x65\x61\x73\x65\x2c",
            "\x97\x68\x72\x68\xd6\xec\xcc\xc0\xc0\x7b\x25\xe2\x5e\xcf\xe5\x84"
            "\xb3\xff\xfd\x94\x0c\x16\xa1\x8c\x1b\x55\x49\xd2\xf8\x38\x02\x9e"
            "\x39\x31\x25\x23\xa7\x86\x62\xd5\xbe\x7f\xcb\xcc\x98\xeb\xf5",
            47, 47
        },
        {
            "\x49\x20\x77\x6f\x75\x6c\x64\x20\x6c\x69\x6b\x65\x20\x74\x68\x65"
            "\x20\x47\x65\x6e\x65\x72\x61\x6c\x20\x47\x61\x75\x27\x73\x20\x43"
            "\x68\x69\x63\x6b\x65\x6e\x2c\x20\x70\x6c\x65\x61\x73\x65\x2c\x20",
            "\x97\x68\x72\x68\xd6\xec\xcc\xc0\xc0\x7b\x25\xe2\x5e\xcf\xe5\x84"
            "\x9d\xad\x8b\xbb\x96\xc4\xcd\xc0\x3b\xc1\x03\xe1\xa1\x94\xbb\xd8"
            "\x39\x31\x25\x23\xa7\x86\x62\xd5\xbe\x7f\xcb\xcc\x98\xeb\xf5\xa8",
            48, 48
        },
        {
            "\x49\x20\x77\x6f\x75\x6c\x64\x20\x6c\x69\x6b\x65\x20\x74\x68\x65"
            "\x20\x47\x65\x6e\x65\x72\x61\x6c\x20\x47\x61\x75\x27\x73\x20\x43"
            "\x68\x69\x63\x6b\x65\x6e\x2c\x20\x70\x6c\x65\x61\x73\x65\x2c\x20"
            "\x61\x6e\x64\x20\x77\x6f\x6e\x74\x6f\x6e\x20\x73\x6f\x75\x70\x2e",
            "\x97\x68\x72\x68\xd6\xec\xcc\xc0\xc0\x7b\x25\xe2\x5e\xcf\xe5\x84"
            "\x39\x31\x25\x23\xa7\x86\x62\xd5\xbe\x7f\xcb\xcc\x98\xeb\xf5\xa8"
            "\x48\x07\xef\xe8\x36\xee\x89\xa5\x26\x73\x0d\xbc\x2f\x7b\xc8\x40"
            "\x9d\xad\x8b\xbb\x96\xc4\xcd\xc0\x3b\xc1\x03\xe1\xa1\x94\xbb\xd8",
            64, 64
        }
    };
    unsigned char iv[16] = {0};
    unsigned char iv2[16] = {0};
    unsigned char enc[64];  /* Large enough for biggest test vector */
    unsigned char dec[64];  /* Large enough for biggest test vector */
    int outlen, total_len = 0;
    EVP_CIPHER_CTX *ctx;
    OSSL_PARAM params[2];
    unsigned char iv_cts[16] = {0};
    size_t i;

    PRINT_MSG("Running CTS Known Answer Tests");

    /* Run through all test vectors */
    for (i = 0; i < sizeof(vects)/sizeof(vects[0]); i++) {
        PRINT_MSG("\nTest Vector %zu", i + 1);
        PRINT_BUFFER("Input", (unsigned char*)vects[i].input, vects[i].inLen);

        /* Reset IVs for each test */
        memset(iv, 0, sizeof(iv));
        memset(iv2, 0, sizeof(iv2));
        memset(iv_cts, 0, sizeof(iv_cts));

        err = (ctx = EVP_CIPHER_CTX_new()) == NULL;
        if (err == 0) {
            /* Set up parameters for CS3 mode */
            params[0] = OSSL_PARAM_construct_utf8_string(OSSL_CIPHER_PARAM_CTS_MODE,
                                                        (char *)"CS3", 0);
            params[1] = OSSL_PARAM_construct_end();

            /* Initialize with cipher and key only first */
            err = EVP_CipherInit_ex2(ctx, cipher, key, iv, 1, params) != 1;
        }
        if (err == 0) {
            /* Set IV and encrypt */
            err = EVP_CipherUpdate(ctx, enc, &outlen,
                                 (unsigned char*)vects[i].input,
                                 (int)vects[i].inLen) != 1;
            total_len = outlen;
        }
        if (err == 0) {
            err = EVP_CipherFinal_ex(ctx, enc + total_len, &outlen) != 1;
            total_len += outlen;
        }

        if (err == 0) {
            PRINT_BUFFER("Output", enc, total_len);
            PRINT_BUFFER("Expected", (unsigned char*)vects[i].output, vects[i].outLen);

            /* Compare results */
            if (total_len != (int)vects[i].outLen ||
                memcmp(enc, vects[i].output, vects[i].outLen) != 0) {
                PRINT_MSG("KAT Encryption output mismatch for vector %zu", i + 1);
                err = 1;
                break;
            }
        }

        EVP_CIPHER_CTX_free(ctx);
        ctx = NULL;

        /* Now test decryption */
        if (err == 0) {
            err = (ctx = EVP_CIPHER_CTX_new()) == NULL;
        }
        if (err == 0) {
            params[0] = OSSL_PARAM_construct_utf8_string(OSSL_CIPHER_PARAM_CTS_MODE,
                                                        (char *)"CS3", 0);
            params[1] = OSSL_PARAM_construct_end();
            err = EVP_CipherInit_ex2(ctx, cipher, key, iv2, 0, params) != 1;
        }
        if (err == 0) {
            err = EVP_CipherUpdate(ctx, dec, &outlen,
                                 (unsigned char*)vects[i].output,
                                 (int)vects[i].outLen) != 1;
            total_len = outlen;
        }
        if (err == 0) {
            err = EVP_CipherFinal_ex(ctx, dec + total_len, &outlen) != 1;
            total_len += outlen;
        }

        if (err == 0) {
            PRINT_BUFFER("Decrypted", dec, total_len);

            /* Compare decryption results */
            if (total_len != (int)vects[i].inLen ||
                memcmp(dec, vects[i].input, vects[i].inLen) != 0) {
                PRINT_MSG("KAT Decryption mismatch for vector %zu", i + 1);
                err = 1;
                break;
            }
        }

        EVP_CIPHER_CTX_free(ctx);
        ctx = NULL;

        if (err != 0) break;
    }

    return err;
}

static int test_cipher_cts(void *data, const char *cipher, int keyLen)
{
    int err = 0;
    /* Test messages of different sizes:
     * 1. Known Answer Test
     * 2. One block plus one byte (17 bytes)
     * 3. More than two blocks with partial last block (37 bytes)
     * 4. Exactly four blocks (64 bytes)
     * 5. Error cases
     */
    unsigned char msg1[17];  /* One block plus one byte */
    unsigned char msg2[37];  /* More than two blocks with partial last block */
    unsigned char msg3[64];  /* Exactly four blocks */
    unsigned char key[32];
    unsigned char iv[16];
    /* Buffer large enough for largest message */
    unsigned char enc[sizeof(msg3)];
    unsigned char dec[sizeof(msg3)];
    EVP_CIPHER* ocipher;
    EVP_CIPHER* wcipher;

    (void)data;

    ocipher = EVP_CIPHER_fetch(osslLibCtx, cipher, "");
    wcipher = EVP_CIPHER_fetch(wpLibCtx, cipher, "");

    /* Set up KAT key */
    unsigned char kat_key[] = {
        0x63, 0x68, 0x69, 0x63, 0x6b, 0x65, 0x6e, 0x20,
        0x74, 0x65, 0x72, 0x69, 0x79, 0x61, 0x6b, 0x69
    };

    /* Generate random key, IV and messages */
    if (RAND_bytes(key, keyLen) != 1) {
        err = 1;
    }
    if (err == 0) {
        if (RAND_bytes(iv, sizeof(iv)) != 1) {
            err = 1;
        }
    }
    if (err == 0) {
        if (RAND_bytes(msg1, sizeof(msg1)) != 1) {
            err = 1;
        }
    }
    if (err == 0) {
        if (RAND_bytes(msg2, sizeof(msg2)) != 1) {
            err = 1;
        }
    }
    if (err == 0) {
        if (RAND_bytes(msg3, sizeof(msg3)) != 1) {
            err = 1;
        }
    }

    if (err == 0) {
        PRINT_BUFFER("Key", key, keyLen);
        PRINT_BUFFER("IV", iv, sizeof(iv));
        PRINT_BUFFER("Message 1", msg1, sizeof(msg1));
        PRINT_BUFFER("Message 2", msg2, sizeof(msg2));
        PRINT_BUFFER("Message 3", msg3, sizeof(msg3));
    }

    /* Run Known Answer Test first */
    if (keyLen == 16) {
        if (err == 0) {
            PRINT_MSG("Running Known Answer Test with OpenSSL");
            err = test_cipher_cts_kat(ocipher, kat_key);
        }
        if (err == 0) {
            PRINT_MSG("Running Known Answer Test with wolfProvider");
            err = test_cipher_cts_kat(wcipher, kat_key);
        }
    }

    /* Interop cipher testing with different lengths */
    if (err == 0) {
        PRINT_MSG("CTS Encrypt with OpenSSL (KRB-style)");
        err = test_cipher_cts_krb_enc(ocipher, key, iv, msg1, sizeof(msg1), enc);
    }
    if (err == 0) {
        PRINT_MSG("CTS Decrypt with wolfProvider (KRB-style)");
        err = test_cipher_cts_krb_dec(wcipher, key, iv, msg1, sizeof(msg1), enc,
                              sizeof(msg1), dec);
    }
    if (err == 0) {
        PRINT_MSG("CTS Encrypt with wolfProvider (KRB-style)");
        err = test_cipher_cts_krb_enc(wcipher, key, iv, msg1, sizeof(msg1), enc);
    }
    if (err == 0) {
        PRINT_MSG("CTS Decrypt with OpenSSL (KRB-style)");
        err = test_cipher_cts_krb_dec(ocipher, key, iv, msg1, sizeof(msg1), enc,
                              sizeof(msg1), dec);
    }

    if (err == 0) {
        PRINT_MSG("CTS Encrypt with OpenSSL (KRB-style)");
        err = test_cipher_cts_krb_enc(ocipher, key, iv, msg2, sizeof(msg2), enc);
    }
    if (err == 0) {
        PRINT_MSG("CTS Decrypt with wolfProvider (KRB-style)");
        err = test_cipher_cts_krb_dec(wcipher, key, iv, msg2, sizeof(msg2), enc,
                              sizeof(msg2), dec);
    }
    if (err == 0) {
        PRINT_MSG("CTS Encrypt with wolfProvider (KRB-style)");
        err = test_cipher_cts_krb_enc(wcipher, key, iv, msg2, sizeof(msg2), enc);
    }
    if (err == 0) {
        PRINT_MSG("CTS Decrypt with OpenSSL (KRB-style)");
        err = test_cipher_cts_krb_dec(ocipher, key, iv, msg2, sizeof(msg2), enc,
                              sizeof(msg2), dec);
    }

    if (err == 0) {
        PRINT_MSG("CTS Encrypt with OpenSSL (KRB-style)");
        err = test_cipher_cts_krb_enc(ocipher, key, iv, msg3, sizeof(msg3), enc);
    }
    if (err == 0) {
        PRINT_MSG("CTS Decrypt with wolfProvider (KRB-style)");
        err = test_cipher_cts_krb_dec(wcipher, key, iv, msg3, sizeof(msg3), enc,
                              sizeof(msg3), dec);
    }
    if (err == 0) {
        PRINT_MSG("CTS Encrypt with wolfProvider (KRB-style)");
        err = test_cipher_cts_krb_enc(wcipher, key, iv, msg3, sizeof(msg3), enc);
    }
    if (err == 0) {
        PRINT_MSG("CTS Decrypt with OpenSSL (KRB-style)");
        err = test_cipher_cts_krb_dec(ocipher, key, iv, msg3, sizeof(msg3), enc,
                              sizeof(msg3), dec);
    }

    /* Error cases */
    if (err == 0) {
        PRINT_MSG("CTS Error cases with OpenSSL");
        err = test_cipher_cts_enc_err_cases(ocipher, key, iv, msg2, sizeof(msg2), enc);
    }
    if (err == 0) {
        PRINT_MSG("CTS Error cases with wolfProvider");
        err = test_cipher_cts_enc_err_cases(wcipher, key, iv, msg2, sizeof(msg2), enc);
    }

    EVP_CIPHER_free(wcipher);
    EVP_CIPHER_free(ocipher);

    return err;
}

int test_aes128_cts(void *data)
{
    return test_cipher_cts(data, "AES-128-CBC-CTS", 16);
}

int test_aes256_cts(void *data)
{
    return test_cipher_cts(data, "AES-256-CBC-CTS", 32);
}

#endif /* WP_HAVE_AESCTS */

#ifdef WP_HAVE_AESCBC

int test_aes256_cbc_multiple(void *data)
{
    /* Test vector from libmemcached/libhashkit */
    static const unsigned char key_data[] = {
        0x5f, 0x5f, 0x5f, 0x5f, 0x43, 0x5f, 0x41, 0x5f,
        0x54, 0x5f, 0x43, 0x5f, 0x48, 0x5f, 0x5f, 0x5f,
        0x5f, 0x54, 0x5f, 0x45, 0x5f, 0x53, 0x5f, 0x54,
        0x5f, 0x5f, 0x5f, 0x5f, 0x30, 0x00, 0x00, 0x00
    };

    static const unsigned char plain_text[] = {
        0x72, 0x65, 0x70, 0x6c, 0x61, 0x63, 0x65, 0x64,
        0x20, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x2c, 0x20,
        0x74, 0x68, 0x69, 0x63, 0x68, 0x20, 0x69, 0x73,
        0x20, 0x6c, 0x6f, 0x6e, 0x67, 0x65, 0x72, 0x20,
        0x74, 0x68, 0x61, 0x6e, 0x20, 0x41, 0x45, 0x53,
        0x5f, 0x42, 0x4c, 0x4f, 0x43, 0x4b, 0x5f, 0x53,
        0x49, 0x5a, 0x45
    };
    static const int plain_text_len = sizeof(plain_text);

    static const unsigned char aes_iv[] = {
        0x44, 0x63, 0xff, 0xd3, 0x79, 0xcf, 0x04, 0x74,
        0x9e, 0x75, 0xa2, 0x71, 0xa4, 0x2c, 0xc7, 0x0a
    };

    static const unsigned char ciphertext_exp[] = {
        0x75, 0xdd, 0x24, 0xf5, 0xc1, 0x5c, 0x34, 0x65,
        0xaf, 0xd3, 0xa9, 0x82, 0x74, 0xe2, 0xf3, 0xa1,
        0x35, 0x95, 0x5a, 0x89, 0x6f, 0x59, 0xb9, 0xa2,
        0x84, 0xec, 0xa8, 0x54, 0x9f, 0xcc, 0x6d, 0xe3,
        0x99, 0xfc, 0xf0, 0xa3, 0xc4, 0x03, 0xc3, 0x56,
        0xec, 0x6d, 0x1c, 0xcd, 0xe1, 0xc2, 0x17, 0xa0,
        0x51, 0x0b, 0x00, 0x87, 0xde, 0x43, 0x8a, 0xf6,
        0x1b, 0x03, 0x2c, 0x7f, 0x68, 0x67, 0x11, 0x72
    };

    (void)data;
    int err = 0;

    EVP_CIPHER_CTX *ctx_enc = NULL;
    EVP_CIPHER_CTX *ctx_dec = NULL;

    if (err == 0) {
        ctx_enc = EVP_CIPHER_CTX_new();
        ctx_dec = EVP_CIPHER_CTX_new();
        if (ctx_dec == NULL || ctx_enc == NULL) {
            PRINT_MSG("EVP_CIPHER_CTX_new failed");
            err = 1;
        }
        else {
            PRINT_MSG("CTXs created");
        }
    }

    if (err == 0) {
        if (EVP_EncryptInit_ex(ctx_enc, EVP_aes_256_cbc(), NULL, key_data, aes_iv) != 1
            || EVP_DecryptInit_ex(ctx_dec, EVP_aes_256_cbc(), NULL, key_data, aes_iv) != 1) {
            PRINT_MSG("EVP_EncryptInit_ex or EVP_DecryptInit_ex failed");
            err = 1;
        }
        else {
            PRINT_MSG("EVP_EncryptInit_ex and EVP_DecryptInit_ex succeeded");
        }
    }

    /* Test that we can encrypt and decrypt multiple times without creating 
     * a new context. We should get the same result each time: same ciphertext
     * when encrypting and same plaintext when decrypting. */
    for (int i = 0; i < 8; i++) {
        int cipher_text_len = plain_text_len + EVP_CIPHER_CTX_block_size(ctx_enc);
        int decrypted_text_len = 0;
        int final_len = 0;
        unsigned char* cipher_text = malloc(cipher_text_len);
        unsigned char* decrypted_text = malloc(plain_text_len);

        PRINT_MSG("Test iteration: %d", i);

        if (cipher_text == NULL || decrypted_text == NULL) {
            PRINT_MSG("Memory allocation failed");
            err = 1;
        }

        if (err == 0) {
            if (EVP_EncryptInit_ex(ctx_enc, NULL, NULL, NULL, NULL) != 1
                || EVP_EncryptUpdate(ctx_enc, cipher_text, &cipher_text_len, plain_text, plain_text_len) != 1
                || EVP_EncryptFinal_ex(ctx_enc, cipher_text + cipher_text_len, &final_len) != 1) {
                PRINT_MSG("Encrypt failed");
                err = 1;
            }
            else {
                cipher_text_len += final_len;
                PRINT_BUFFER("Plain text    ", plain_text, plain_text_len);
                PRINT_BUFFER("Cipher text   ", cipher_text, cipher_text_len);
            }
        }

        if (err == 0) {
            if (cipher_text_len != sizeof(ciphertext_exp)) {
                PRINT_MSG("Cipher text length does not match expected value");
                err = 1;
            }
        }

        if (err == 0) {
            if (memcmp(cipher_text, ciphertext_exp, sizeof(ciphertext_exp)) != 0) {
                PRINT_MSG("Cipher text does not match expected value");
                err = 1;
            } else {
                PRINT_MSG("Cipher text matches expected value");
            }
        }

        if (err == 0) {
            if (EVP_DecryptInit_ex(ctx_dec, NULL, NULL, NULL, NULL) != 1
                || EVP_DecryptUpdate(ctx_dec, decrypted_text, &decrypted_text_len, cipher_text, cipher_text_len) != 1
                || EVP_DecryptFinal_ex(ctx_dec, decrypted_text + decrypted_text_len, &final_len) != 1) {
                PRINT_MSG("Decrypt failed");
                err = 1;
            }
            else {
                decrypted_text_len += final_len;
                PRINT_BUFFER("Decrypted text", decrypted_text, decrypted_text_len);
            }
        }

        if (err == 0) {
            if (plain_text_len != decrypted_text_len) {
                PRINT_MSG("Decrypted text length does not match original");
                err = 1;
            }
        }

        if (err == 0) {
            int res = memcmp(plain_text, decrypted_text, plain_text_len);
            if (res != 0) {
                PRINT_MSG("Decrypted text does not match original");
                err = 1;
            } else {
                PRINT_MSG("Cipher test passed successfully");
            }
        }

        free(cipher_text);
        free(decrypted_text);
    }

    EVP_CIPHER_CTX_free(ctx_enc);
    EVP_CIPHER_CTX_free(ctx_dec);

    return err;
}
#endif /* WP_HAVE_AESCBC */
