/* test_cipher.c
 *
 * Copyright (C) 2021 wolfSSL Inc.
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
 * along with wolfProvider.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "unit.h"

#if defined(WP_HAVE_DES3CBC) || defined(WP_HAVE_AESCBC) || \
    defined(WP_HAVE_AESECB) || defined(WP_HAVE_AESCTR)

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
    defined(WP_HAVE_AESECB) || defined(WP_HAVE_AESCTR)


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

