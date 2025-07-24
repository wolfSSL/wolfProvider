/* test_aestag.c
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

#ifndef EVP_CCM_TLS_FIXED_IV_LEN
#define EVP_CCM_TLS_FIXED_IV_LEN        EVP_GCM_TLS_FIXED_IV_LEN
#endif
#ifndef EVP_CCM_TLS_TAG_LEN
#define EVP_CCM_TLS_TAG_LEN             EVP_GCM_TLS_TAG_LEN
#endif

#if defined(WP_HAVE_AESGCM) || defined(WP_HAVE_AESCCM)

static int test_aes_tag_enc(const EVP_CIPHER *cipher,
                            unsigned char *key, unsigned char *iv, int ivLen,
                            unsigned char *aad, unsigned char *msg, int len,
                            unsigned char *enc, unsigned char *tag, int ccm,
                            int ccmL)
{
    int err;
    EVP_CIPHER_CTX *ctx;
    int encLen;
    unsigned int tagLen = 16;

    err = (ctx = EVP_CIPHER_CTX_new()) == NULL;
    if (err == 0) {
        err = EVP_EncryptInit(ctx, cipher, NULL, NULL) != 1;
    }
    if (err == 0 && ccm && ccmL != 0) {
        /* Applications can set CCM length field (L), default is 8 if unset. */
        err = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_L, ccmL, NULL) != 1;
    }
    if (err == 0) {
        if (ccm && ccmL != 0) {
            /* adjust IV based on L, should be 15-L */
            ivLen = 15-ccmL;
        }
        err = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, ivLen,
                                  NULL) != 1;
    }
    if (err == 0 && ccm) {
        /* Only CCM needs tag length set before encryption. */
        err = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, tagLen,
                                  NULL) != 1;
    }
    if (err == 0) {
        err = EVP_EncryptInit(ctx, NULL, key, iv) != 1;
    }
    if ((err == 0) && ccm) {
        /* OpenSSL's CCM needs the length of plaintext set. */
        err = EVP_EncryptUpdate(ctx, NULL, &encLen, NULL, len) != 1;
        if (encLen != len) {
            /* Should return length */
            err = 1;
        }
    }
    if ((err == 0) && ccm) {
        /* No AAD streaming available in OpenSSL CCM mode. */
        err = EVP_EncryptUpdate(ctx, NULL, &encLen, aad,
                                (int)strlen((char *)aad)) != 1;
        if (encLen != (int)strlen((char *)aad)) {
            /* Should return length of AAD data added */
            err = 1;
        }
    }
    if ((err == 0) && !ccm) {
        /* AAD streaming available in OpenSSL GCM mode - part 1. */
        err = EVP_EncryptUpdate(ctx, NULL, &encLen, aad, 1) != 1;
        if (err == 0 && (encLen != 1)) {
            PRINT_MSG("EVP_EncryptUpdate did not return correct size of AAD");
            err = 1;
        }
    }
    if ((err == 0) && !ccm) {
        /* AAD streaming available in OpenSSL GCM mode - part 2. */
        err = EVP_EncryptUpdate(ctx, NULL, &encLen, aad + 1,
                                (int)strlen((char *)aad) - 1) != 1;
        if (err == 0 && (encLen != (int)strlen((char *)aad) - 1)) {
            PRINT_MSG("EVP_EncryptUpdate did not return correct size of AAD");
            err = 1;
        }
    }
    if (err == 0 && len > 0) {
        /* Update with msg, if len > 0 (not GMAC) */
        err = EVP_EncryptUpdate(ctx, enc, &encLen, msg, len) != 1;
        if (encLen != len) {
            err = 1;
        }
    }
    if (err == 0) {
        err = EVP_EncryptFinal_ex(ctx, enc + encLen, &encLen) != 1;
        if (encLen != 0) {
            /* should be no more data left */
            err = 1;
        }
    }
    if (err == 0) {
        err = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, tagLen, tag) != 1;
    }

    if (err == 0) {
        PRINT_BUFFER("Encrypted", enc, len);
        PRINT_BUFFER("Tag", tag, 16);
    }

    EVP_CIPHER_CTX_free(ctx);

    return err;
}

static int test_aes_tag_dec(const EVP_CIPHER *cipher,
                            unsigned char *key, unsigned char *iv, int ivLen,
                            unsigned char *aad, unsigned char *msg, int len,
                            unsigned char *enc, unsigned char *tag,
                            unsigned char *dec, int ccm, int ccmL)
{
    int err;
    EVP_CIPHER_CTX *ctx;
    int decLen;
    unsigned int tagLen = 16;

    err = (ctx = EVP_CIPHER_CTX_new()) == NULL;
    if (err == 0) {
        err = EVP_DecryptInit(ctx, cipher, NULL, NULL) != 1;
    }
    if (err == 0 && ccm && ccmL != 0) {
        /* Applications can set CCM length field (L), default is 8 if unset. */
        err = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_L, ccmL, NULL) != 1;
    }
    if (err == 0) {
        if (ccm && ccmL != 0) {
            /* adjust IV based on L, should be 15-L */
            ivLen = 15-ccmL;
        }
        err = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, ivLen,
                                  NULL) != 1;
    }
    if (err == 0) {
        err = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, tagLen,
                                  (void *)tag) != 1;
    }
    if (err == 0) {
        err = EVP_DecryptInit(ctx, NULL, key, iv) != 1;
    }
    if ((err == 0) && ccm) {
        /* OpenSSL's CCM needs the length of plaintext set. */
        err = EVP_DecryptUpdate(ctx, NULL, &decLen, NULL, len) != 1;
    }
    if (err == 0) {
        err = EVP_DecryptUpdate(ctx, NULL, &decLen, aad,
                                (int)strlen((char *)aad)) != 1;
        if (err == 0 && (decLen != (int)strlen((char *)aad))) {
            PRINT_MSG("EVP_DecryptUpdate did not return correct size of AAD");
            err = 1;
        }
    }
    if (err == 0 && len > 0) {
        /* Not used in GMAC test (len == 0) */
        err = EVP_DecryptUpdate(ctx, dec, &decLen, enc, len) != 1;
    } else {
        /* Reset decLen, represented AAD length above */
        decLen = 0;
    }
    if (err == 0) {
        err = EVP_DecryptFinal_ex(ctx, dec + decLen, &decLen) != 1;
    }

    if (err == 0 && dec != NULL && msg != NULL) {
        PRINT_BUFFER("Decrypted", dec, len);

        if (memcmp(dec, msg, len) != 0) {
            err = 1;
        }
    }

    EVP_CIPHER_CTX_free(ctx);

    return err;
}

static int test_aes_tag_dec_multi(const EVP_CIPHER *cipher,
                            unsigned char *key, unsigned char *iv, int ivLen,
                            unsigned char *aad, unsigned char *msg, int len,
                            unsigned char *enc, unsigned char *tag,
                            unsigned char *dec)
{
    int err;
    EVP_CIPHER_CTX *ctx;
    int decLen;
    unsigned int tagLen = 16;

    err = (ctx = EVP_CIPHER_CTX_new()) == NULL;
    if (err == 0) {
        err = EVP_DecryptInit(ctx, cipher, NULL, NULL) != 1;
    }
    if (err == 0) {
        err = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, ivLen,
                                  NULL) != 1;
    }
    if (err == 0) {
        err = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, tagLen,
                                  (void *)tag) != 1;
    }
    if (err == 0) {
        err = EVP_DecryptInit(ctx, NULL, key, iv) != 1;
    }
    if (err == 0) {
        err = EVP_DecryptUpdate(ctx, NULL, &decLen, aad,
                                (int)strlen((char *)aad)) != 1;
        if (err == 0 && (decLen != (int)strlen((char *)aad))) {
            PRINT_MSG("EVP_DecryptUpdate did not return correct size of AAD");
            err = 1;
        }
    }
    if (err == 0) {
        err = EVP_DecryptUpdate(ctx, dec, &decLen, enc, 1) != 1;
    }
    if (err == 0) {
        err = EVP_DecryptUpdate(ctx, dec + 1, &decLen, enc + 1, len - 1) != 1;
    }
    if (err == 0) {
        err = EVP_DecryptFinal_ex(ctx, dec + 1 + decLen, &decLen) != 1;
    }

    if (err == 0 && dec != NULL && msg != NULL) {
        PRINT_BUFFER("Decrypted", dec, len);

        if (memcmp(dec, msg, len) != 0) {
            err = 1;
        }
    }

    EVP_CIPHER_CTX_free(ctx);

    return err;
}

static int test_aes_tag(void *data, const char *cipher,
                        int keyLen, int ivLen, int ccm, int ccmL)
{
    int err = 0;
    unsigned char msg[] = "Test pattern";
    unsigned char key[32];
    unsigned char iv[AES_BLOCK_SIZE];
    unsigned char aad[] = "AAD";
    unsigned char enc[sizeof(msg)];
    unsigned char tag[AES_BLOCK_SIZE];
    unsigned char dec[sizeof(msg)];
    EVP_CIPHER* ocipher;
    EVP_CIPHER* wcipher;

    (void)data;

    ocipher = EVP_CIPHER_fetch(osslLibCtx, cipher, "");
    wcipher = EVP_CIPHER_fetch(wpLibCtx, cipher, "");

    memset(key, 0, keyLen);
    memset(iv, 0, ivLen);

    if (err == 0) {
        PRINT_BUFFER("Key", key, keyLen);
        PRINT_BUFFER("IV", iv, ivLen);
        PRINT_BUFFER("Message", msg, sizeof(msg));
    }

    if (err == 0) {
        PRINT_MSG("Encrypt with OpenSSL");
        err = test_aes_tag_enc(ocipher, key, iv, ivLen, aad, msg,
                               sizeof(msg), enc, tag, ccm, ccmL);
    }
    if (err == 0) {
        PRINT_MSG("Decrypt with wolfprovider");
        err = test_aes_tag_dec(wcipher, key, iv, ivLen, aad, msg, sizeof(msg),
                               enc, tag, dec, ccm, ccmL);
    }
    if (err == 0) {
        PRINT_MSG("Encrypt with wolfprovider");
        err = test_aes_tag_enc(wcipher, key, iv, ivLen, aad, msg, sizeof(msg),
                               enc, tag, ccm, ccmL);
    }
    if (err == 0) {
        PRINT_MSG("Decrypt with OpenSSL");
        err = test_aes_tag_dec(ocipher, key, iv, ivLen, aad, msg,
                               sizeof(msg), enc, tag, dec, ccm, ccmL);
    }

    EVP_CIPHER_free(wcipher);
    EVP_CIPHER_free(ocipher);

    return err;
}

#ifdef WP_HAVE_AESGCM

/* AES-GCM GMAC test, empty plaintext, operation only outputs tag value */
static int test_aes_gcm_gmac(void* data, const char* cipher,
                             int keyLen, int ivLen)
{
    int err = 0;
    unsigned char key[32];
    unsigned char iv[AES_BLOCK_SIZE];
    unsigned char aad[] = "AAD";
    unsigned char tag[AES_BLOCK_SIZE];
    EVP_CIPHER* ocipher;
    EVP_CIPHER* wcipher;

    (void)data;

    ocipher = EVP_CIPHER_fetch(osslLibCtx, cipher, "");
    wcipher = EVP_CIPHER_fetch(wpLibCtx, cipher, "");

    memset(key, 0, keyLen);
    memset(iv, 0, ivLen);

    PRINT_BUFFER("Key", key, keyLen);
    PRINT_BUFFER("IV", iv, ivLen);

    if (err == 0) {
        PRINT_MSG("Encrypt with OpenSSL");
        err = test_aes_tag_enc(ocipher, key, iv, ivLen, aad, NULL,
                               0, NULL, tag, 0, 0);
    }
    if (err == 0) {
        PRINT_MSG("Decrypt with wolfprovider");
        err = test_aes_tag_dec(wcipher, key, iv, ivLen, aad, NULL, 0,
                               NULL, tag, NULL, 0, 0);
    }
    if (err == 0) {
        PRINT_MSG("Encrypt with wolfprovider");
        err = test_aes_tag_enc(wcipher, key, iv, ivLen, aad, NULL, 0,
                               NULL, tag, 0, 0);
    }
    if (err == 0) {
        PRINT_MSG("Decrypt with OpenSSL");
        err = test_aes_tag_dec(ocipher, key, iv, ivLen, aad, NULL,
                               0, NULL, tag, NULL, 0, 0);
    }

    EVP_CIPHER_free(wcipher);
    EVP_CIPHER_free(ocipher);

    return err;
}

#endif

/******************************************************************************/

#ifdef WP_HAVE_AESGCM

static int test_aes_tag_fixed_enc(const EVP_CIPHER *cipher,
    unsigned char *key, unsigned char *iv, int ivFixedLen, int ivLen,
    unsigned char *aad, unsigned char *msg, int len, unsigned char *enc,
    unsigned char *tag)
{
    int err;
    EVP_CIPHER_CTX *ctx;
    int encLen = len;
    unsigned int tagLen = 16;

    err = (ctx = EVP_CIPHER_CTX_new()) == NULL;
    if (err == 0) {
       err = EVP_EncryptInit(ctx, cipher, key, NULL) != 1;
    }
    if (err == 0) {
       err = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IV_FIXED, ivFixedLen,
                                 iv) != 1;
    }
    if (err == 0) {
       memcpy(iv, EVP_CIPHER_CTX_iv(ctx), ivLen);
       err = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_IV_GEN, ivLen, iv) != 1;
    }
    if (err == 0) {
        err = EVP_EncryptUpdate(ctx, NULL, &encLen, aad,
                                (int)strlen((char *)aad)) != 1;
    }
    if (err == 0) {
        err = EVP_EncryptUpdate(ctx, enc, &encLen, msg, len) != 1;
    }
    if (err == 0) {
        err = EVP_EncryptFinal_ex(ctx, enc + encLen, &encLen) != 1;
    }
    if (err == 0) {
        err = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, tagLen, tag) != 1;
    }
    if (err == 0) {
    }

    if (err == 0) {
        PRINT_BUFFER("Encrypted", enc, len);
        PRINT_BUFFER("Tag", tag, 16);
    }

    EVP_CIPHER_CTX_free(ctx);

    return err;
}

static int test_aes_tag_fixed_enc_multi(const EVP_CIPHER *cipher,
    unsigned char *key, unsigned char *iv, int ivFixedLen, int ivLen,
    unsigned char *aad, unsigned char *msg, int len, unsigned char *enc,
    unsigned char *tag)
{
    int err;
    EVP_CIPHER_CTX *ctx;
    int encLen = len;
    unsigned int tagLen = 16;

    err = (ctx = EVP_CIPHER_CTX_new()) == NULL;
    if (err == 0) {
       err = EVP_EncryptInit(ctx, cipher, key, NULL) != 1;
    }
    if (err == 0) {
       err = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IV_FIXED, ivFixedLen,
                                 iv) != 1;
    }
    if (err == 0) {
       memcpy(iv, EVP_CIPHER_CTX_iv(ctx), ivLen);
       err = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_IV_GEN, ivLen, iv) != 1;
    }
    if (err == 0) {
        err = EVP_EncryptUpdate(ctx, NULL, &encLen, aad,
                                (int)strlen((char *)aad)) != 1;
    }
    if (err == 0) {
        err = EVP_EncryptUpdate(ctx, enc, &encLen, msg, 1) != 1;
    }
    if (err == 0) {
        err = EVP_EncryptUpdate(ctx, enc + 1, &encLen, msg + 1, len - 1) != 1;
    }
    if (err == 0) {
        err = EVP_EncryptFinal_ex(ctx, enc + 1 + encLen, &encLen) != 1;
    }
    if (err == 0) {
        err = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, tagLen, tag) != 1;
    }
    if (err == 0) {
    }

    if (err == 0) {
        PRINT_BUFFER("Encrypted", enc, len);
        PRINT_BUFFER("Tag", tag, 16);
    }

    EVP_CIPHER_CTX_free(ctx);

    return err;
}

static int test_aes_tag_enc_ossh(const EVP_CIPHER *cipher,
    unsigned char *key, unsigned char *iv,
    unsigned char *aad, unsigned char *msg, int len, unsigned char *enc,
    unsigned char *tag)
{
    int err;
    EVP_CIPHER_CTX *encCtx;
    unsigned int tagLen = 16;
    char lastiv[1];

    /* Test encryption flow used by openSSH */
    err = (encCtx = EVP_CIPHER_CTX_new()) == NULL;
    if (err == 0) {
       err = EVP_CipherInit(encCtx, cipher, NULL, iv, 1) != 1;
    }
    if (err == 0) {
       err = EVP_CIPHER_CTX_ctrl(encCtx, EVP_CTRL_GCM_SET_IV_FIXED, -1,
                                 iv) != 1;
    }
    if (err == 0) {
       err = EVP_CipherInit(encCtx, NULL, key, NULL, -1) != 1;
    }
    if (err == 0) {
       err = EVP_CIPHER_CTX_ctrl(encCtx, EVP_CTRL_GCM_IV_GEN, 1,
                                 lastiv) != 1;
    }
    if (err == 0) {
       err = EVP_Cipher(encCtx, NULL, aad, (int)strlen((char *)aad)) <= 0;
    }
    if (err == 0) {
       err = EVP_Cipher(encCtx, enc, msg, len) <= 0;
    }
    if (err == 0) {
       err = EVP_Cipher(encCtx, NULL, NULL, 0) < 0;
    }
    if (err == 0) {
       err = EVP_CIPHER_CTX_ctrl(encCtx, EVP_CTRL_GCM_GET_TAG, tagLen,
                                 tag) != 1;
    }
    if (err == 0) {
        PRINT_BUFFER("Encrypted", enc, len);
        PRINT_BUFFER("Tag", tag, 16);
    }

    EVP_CIPHER_CTX_free(encCtx);
    return err;
}

static int test_aes_tag_enc_ossh_multi(const EVP_CIPHER *cipher,
    unsigned char *key, unsigned char *iv,
    unsigned char *aad, unsigned char *msg, int len, unsigned char *enc,
    unsigned char *tag)
{
    int err;
    EVP_CIPHER_CTX *encCtx;
    unsigned int tagLen = 16;
    char lastiv[1];

    /* Test encryption flow used by openSSH */
    err = (encCtx = EVP_CIPHER_CTX_new()) == NULL;
    if (err == 0) {
       err = EVP_CipherInit(encCtx, cipher, NULL, iv, 1) != 1;
    }
    if (err == 0) {
       err = EVP_CIPHER_CTX_ctrl(encCtx, EVP_CTRL_GCM_SET_IV_FIXED, -1,
                                 iv) != 1;
    }
    if (err == 0) {
       err = EVP_CipherInit(encCtx, NULL, key, NULL, -1) != 1;
    }
    if (err == 0) {
       err = EVP_CIPHER_CTX_ctrl(encCtx, EVP_CTRL_GCM_IV_GEN, 1,
                                 lastiv) != 1;
    }
    if (err == 0) {
       err = EVP_Cipher(encCtx, NULL, aad, (int)strlen((char *)aad)) <= 0;
    }
    if (err == 0) {
       err = EVP_Cipher(encCtx, enc, msg, 1) != 1;
    }
    if (err == 0) {
        err = EVP_Cipher(encCtx, enc + 1, msg + 1, len - 1) != (len - 1);
    }
    if (err == 0) {
       err = EVP_Cipher(encCtx, NULL, NULL, 0) < 0;
    }
    if (err == 0) {
       err = EVP_CIPHER_CTX_ctrl(encCtx, EVP_CTRL_GCM_GET_TAG, tagLen,
                                 tag) != 1;
    }
    if (err == 0) {
        PRINT_BUFFER("Encrypted", enc, len);
        PRINT_BUFFER("Tag", tag, 16);
    }

    EVP_CIPHER_CTX_free(encCtx);
    return err;
}

static int test_aes_tag_dec_ossh(const EVP_CIPHER *cipher,
    unsigned char *key, unsigned char *iv,
    unsigned char *aad, unsigned char *msg, int len, unsigned char *enc,
    unsigned char *tag, unsigned char *dec)
{
    int err;
    EVP_CIPHER_CTX *decCtx;
    unsigned int tagLen = 16;
    char lastiv[1];

    /* Test decryption flow used by openSSH */
    err = (decCtx = EVP_CIPHER_CTX_new()) == NULL;
    if (err == 0) {
       err = EVP_CipherInit(decCtx, cipher, NULL, iv, 0) != 1;
    }
    if (err == 0) {
       err = EVP_CIPHER_CTX_ctrl(decCtx, EVP_CTRL_GCM_SET_IV_FIXED, -1,
                                 iv) != 1;
    }
    if (err == 0) {
       err = EVP_CipherInit(decCtx, NULL, key, NULL, -1) != 1;
    }
    if (err == 0) {
       err = EVP_CIPHER_CTX_ctrl(decCtx, EVP_CTRL_GCM_IV_GEN, 1,
                                 lastiv) != 1;
    }
    if (err == 0) {
       err = EVP_CIPHER_CTX_ctrl(decCtx, EVP_CTRL_GCM_SET_TAG, tagLen,
                                 tag) != 1;
    }
    if (err == 0) {
        err = EVP_Cipher(decCtx, NULL, aad, (int)strlen((char *)aad)) <= 0;
    }
    if (err == 0) {
       err = EVP_Cipher(decCtx, dec, enc, len) != len;
    }
    if (err == 0) {
       err = EVP_Cipher(decCtx, NULL, NULL, 0) < 0;
    }
    if (err == 0 && dec != NULL && msg != NULL) {
        PRINT_BUFFER("Decrypted", dec, len);

        if (memcmp(dec, msg, len) != 0) {
            err = 1;
        }
    }

    EVP_CIPHER_CTX_free(decCtx);
    return err;
}

static int test_aes_tag_dec_ossh_multi(const EVP_CIPHER *cipher,
    unsigned char *key, unsigned char *iv,
    unsigned char *aad, unsigned char *msg, int len, unsigned char *enc,
    unsigned char *tag, unsigned char *dec)
{
    int err;
    EVP_CIPHER_CTX *decCtx;
    unsigned int tagLen = 16;
    char lastiv[1];

    /* Test decryption flow used by openSSH */
    err = (decCtx = EVP_CIPHER_CTX_new()) == NULL;
    if (err == 0) {
       err = EVP_CipherInit(decCtx, cipher, NULL, iv, 0) != 1;
    }
    if (err == 0) {
       err = EVP_CIPHER_CTX_ctrl(decCtx, EVP_CTRL_GCM_SET_IV_FIXED, -1,
                                 iv) != 1;
    }
    if (err == 0) {
       err = EVP_CipherInit(decCtx, NULL, key, NULL, -1) != 1;
    }
    if (err == 0) {
       err = EVP_CIPHER_CTX_ctrl(decCtx, EVP_CTRL_GCM_IV_GEN, 1,
                                 lastiv) != 1;
    }
    if (err == 0) {
       err = EVP_CIPHER_CTX_ctrl(decCtx, EVP_CTRL_GCM_SET_TAG, tagLen,
                                 tag) != 1;
    }
    if (err == 0) {
        err = EVP_Cipher(decCtx, NULL, aad, (int)strlen((char *)aad)) <= 0;
    }
    if (err == 0) {
       err = EVP_Cipher(decCtx, dec, enc, 1) != 1;
    }
    if (err == 0) {
        err = EVP_Cipher(decCtx, dec + 1, enc + 1, len - 1) != (len - 1);
    }
    if (err == 0) {
       err = EVP_Cipher(decCtx, NULL, NULL, 0) < 0;
    }
    if (err == 0 && dec != NULL && msg != NULL) {
        PRINT_BUFFER("Decrypted", dec, len);

        if (memcmp(dec, msg, len) != 0) {
            err = 1;
        }
    }

    EVP_CIPHER_CTX_free(decCtx);
    return err;
}

static int test_aes_tag_fixed(void *data, const char *cipher,
                              int keyLen, int ivFixedLen, int ivLen)
{
    int err = 0;
    unsigned char msg[] = "Test pattern";
    unsigned char key[32];
    unsigned char iv[12];
    unsigned char aad[] = "AAD";
    unsigned char enc[sizeof(msg)];
    unsigned char tag[AES_BLOCK_SIZE];
    unsigned char dec[sizeof(msg)];
    EVP_CIPHER* ocipher;
    EVP_CIPHER* wcipher;

    (void)data;

    ocipher = EVP_CIPHER_fetch(osslLibCtx, cipher, "");
    wcipher = EVP_CIPHER_fetch(wpLibCtx, cipher, "");

    if (RAND_bytes(key, keyLen) == 0) {
        err = 1;
    }
    if (err == 0) {
        if (RAND_bytes(iv, sizeof(iv)) == 0) {
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
        err = test_aes_tag_fixed_enc(ocipher, key, iv, ivFixedLen, ivLen,
                                     aad, msg, sizeof(msg), enc, tag);
    }
    if (err == 0) {
        PRINT_MSG("Decrypt with wolfprovider");
        err = test_aes_tag_dec(wcipher, key, iv, ivLen, aad, msg, sizeof(msg),
                               enc, tag, dec, 0, 0);
    }
    if (err == 0) {
        PRINT_MSG("Encrypt with wolfprovider");
        err = test_aes_tag_fixed_enc(wcipher, key, iv, ivFixedLen, ivLen, aad,
                                     msg, sizeof(msg), enc, tag);
    }
    if (err == 0) {
        PRINT_MSG("Decrypt with OpenSSL");
        err = test_aes_tag_dec(ocipher, key, iv, ivLen, aad, msg,
                               sizeof(msg), enc, tag, dec, 0, 0);
    }
    if (err == 0) {
        PRINT_MSG("Encrypt with OpenSSL (multiple updates)");
        err = test_aes_tag_fixed_enc_multi(ocipher, key, iv, ivFixedLen, ivLen,
                                     aad, msg, sizeof(msg), enc, tag);
    }
    if (err == 0) {
        PRINT_MSG("Decrypt with wolfprovider (multiple updates)");
        err = test_aes_tag_dec_multi(wcipher, key, iv, ivLen, aad, msg, sizeof(msg),
                               enc, tag, dec);
    }
    if (err == 0) {
        PRINT_MSG("Encrypt with wolfprovider (multiple updates)");
        err = test_aes_tag_fixed_enc_multi(wcipher, key, iv, ivFixedLen, ivLen, aad,
                                     msg, sizeof(msg), enc, tag);
    }
    if (err == 0) {
        PRINT_MSG("Decrypt with OpenSSL (multiple updates)");
        err = test_aes_tag_dec_multi(ocipher, key, iv, ivLen, aad, msg,
                               sizeof(msg), enc, tag, dec);
    }
    if (err == 0) {
        PRINT_MSG("Encrypt with wolfprovider");
        err = test_aes_tag_enc_ossh(wcipher, key, iv,
                              aad, msg, sizeof(msg), enc, tag);
    }
    if (err == 0) {
        PRINT_MSG("Decrypt with OpenSSL");
        err = test_aes_tag_dec_ossh(ocipher, key, iv,
                              aad, msg, sizeof(msg), enc, tag, dec);
    }
    if (err == 0) {
        PRINT_MSG("Encrypt with OpenSSL");
        err = test_aes_tag_enc_ossh(ocipher, key, iv,
                              aad, msg, sizeof(msg), enc, tag);
    }
    if (err == 0) {
        PRINT_MSG("Decrypt with wolfprovider");
        err = test_aes_tag_dec_ossh(wcipher, key, iv,
                              aad, msg, sizeof(msg), enc, tag, dec);
    }
    if (err == 0) {
        PRINT_MSG("Encrypt with wolfprovider (multiple updates)");
        err = test_aes_tag_enc_ossh_multi(wcipher, key, iv,
                              aad, msg, sizeof(msg), enc, tag);
    }
    if (err == 0) {
        PRINT_MSG("Decrypt with OpenSSL (multiple updates)");
        err = test_aes_tag_dec_ossh_multi(ocipher, key, iv,
                              aad, msg, sizeof(msg), enc, tag, dec);
    }
    if (err == 0) {
        PRINT_MSG("Encrypt with OpenSSL (multiple updates)");
        err = test_aes_tag_enc_ossh_multi(ocipher, key, iv,
                              aad, msg, sizeof(msg), enc, tag);
    }
    if (err == 0) {
        PRINT_MSG("Decrypt with wolfprovider (multiple updates)");
        err = test_aes_tag_dec_ossh_multi(wcipher, key, iv,
                              aad, msg, sizeof(msg), enc, tag, dec);
    }

    EVP_CIPHER_free(wcipher);
    EVP_CIPHER_free(ocipher);

    return err;
}

#endif

/******************************************************************************/

static int test_aes_tag_tls_enc(const EVP_CIPHER *cipher,
                                unsigned char *key, unsigned char *iv,
                                int ivLen, unsigned char *aad,
                                unsigned char *msg, int len, int ccm)
{
    int err;
    EVP_CIPHER_CTX *ctx;
    int tagLen;
    int outLen;

    err = (ctx = EVP_CIPHER_CTX_new()) == NULL;
    if (err == 0) {
       err = EVP_EncryptInit(ctx, cipher, ccm ? NULL : key, NULL) != 1;
    }
    if ((err == 0) && ccm) {
        err = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, 12, NULL) != 1;
    }
    if ((err == 0) && ccm) {
        err = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 16, NULL) != 1;
    }
    if (err == 0) {
       err = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IV_FIXED, ivLen,
                                 iv) != 1;
    }
    if ((err == 0) && ccm) {
        err = EVP_EncryptInit(ctx, NULL, key, NULL) != 1;
    }
    if (err == 0) {
       tagLen = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_TLS1_AAD,
                                    EVP_AEAD_TLS1_AAD_LEN, aad);
       if (ccm) {
           err = (tagLen != EVP_CCM_TLS_TAG_LEN);
       }
       else {
           err = (tagLen != EVP_GCM_TLS_TAG_LEN);
       }
    }
    if (err == 0) {
        err = EVP_CipherUpdate(ctx, msg, &outLen, msg, len) != 1;
    }
    if (err == 0) {
        err = outLen != len;
    }

    if (err == 0) {
        int eLen = len - EVP_GCM_TLS_EXPLICIT_IV_LEN - EVP_GCM_TLS_TAG_LEN;
        PRINT_BUFFER("Message Buffer", msg, len);
        PRINT_BUFFER("Explicit IV", msg, EVP_GCM_TLS_EXPLICIT_IV_LEN);
        PRINT_BUFFER("Encrypted", msg + EVP_GCM_TLS_EXPLICIT_IV_LEN, eLen);
        PRINT_BUFFER("Tag", msg + (len - 16), 16);
        (void)eLen;
    }

    EVP_CIPHER_CTX_free(ctx);

    return err;
}

static int test_aes_tag_tls_dec(const EVP_CIPHER *cipher,
                                unsigned char *key, unsigned char *iv,
                                int ivLen, unsigned char *aad,
                                unsigned char *msg, int len, int ccm)
{
    int err;
    EVP_CIPHER_CTX *ctx;
    int dLen = len - EVP_GCM_TLS_EXPLICIT_IV_LEN - EVP_GCM_TLS_TAG_LEN;

    err = (ctx = EVP_CIPHER_CTX_new()) == NULL;
    if (err == 0) {
       err = EVP_DecryptInit(ctx, cipher, NULL, NULL) != 1;
    }
    if ((err == 0) && ccm) {
        err = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, 12, NULL) != 1;
    }
    if ((err == 0) && ccm) {
        err = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 16, NULL) != 1;
    }
    if (err == 0) {
       err = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IV_FIXED, ivLen,
                                 iv) != 1;
    }
    if (err == 0) {
        err = EVP_DecryptInit(ctx, NULL, key, NULL) != 1;
    }
    if (err == 0) {
       err = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_TLS1_AAD,
                                 EVP_AEAD_TLS1_AAD_LEN,
                                 aad) != EVP_GCM_TLS_TAG_LEN;
    }
    if (err == 0) {
        int decLen;
        err = EVP_CipherUpdate(ctx, msg, &decLen, msg, len) != 1;
        err = decLen != dLen;
    }

    if (err == 0) {
        PRINT_BUFFER("Decrypted", msg + EVP_GCM_TLS_EXPLICIT_IV_LEN, dLen);
        (void)dLen;
    }

    EVP_CIPHER_CTX_free(ctx);

    return err;
}

static int test_aes_tag_tls(void *data, const char *cipher,
                            int keyLen, int ivLen, int ccm)
{
    int err = 0;
    unsigned char aad[EVP_AEAD_TLS1_AAD_LEN] = {0,};
    unsigned char msg[24];
    unsigned char buf[48] = {0,};
    unsigned char key[32];
    unsigned char iv[EVP_GCM_TLS_FIXED_IV_LEN];
    int dataLen = sizeof(msg);
    EVP_CIPHER* ocipher;
    EVP_CIPHER* wcipher;

    (void)data;

    ocipher = EVP_CIPHER_fetch(osslLibCtx, cipher, "");
    wcipher = EVP_CIPHER_fetch(wpLibCtx, cipher, "");

    aad[8]  = 23; /* Content type */
    aad[9]  = 3;  /* Protocol major version */
    aad[10] = 2;  /* Protocol minor version */

    if (RAND_bytes(key, keyLen) == 0) {
        err = 1;
    }
    if (err == 0) {
        if (RAND_bytes(iv, ivLen) == 0) {
            err = 1;
        }
    }
    if (err == 0) {
        if (RAND_bytes(msg, dataLen) == 0) {
            err = 1;
        }
    }

    if (err == 0) {
        memcpy(buf + EVP_GCM_TLS_EXPLICIT_IV_LEN, msg, dataLen);

        PRINT_BUFFER("Key", key, keyLen);
        PRINT_BUFFER("Implicit IV", iv, sizeof(iv));
        PRINT_BUFFER("Message Buffer", buf, sizeof(buf));
        PRINT_BUFFER("Message", msg, dataLen);

        PRINT_MSG("Encrypt with OpenSSL - TLS");
        aad[12] = sizeof(buf) - EVP_GCM_TLS_TAG_LEN;
        err = test_aes_tag_tls_enc(ocipher, key, iv, ivLen, aad, buf,
                                   sizeof(buf), ccm);
    }
    if (err == 0) {
        PRINT_MSG("Decrypt with wolfprovider - TLS");
        aad[12] = sizeof(buf);
        err = test_aes_tag_tls_dec(wcipher, key, iv, ivLen, aad, buf,
                                   sizeof(buf), ccm);
    }

    if (err == 0) {
        memset(buf, 0, sizeof(buf));
        memcpy(buf + EVP_GCM_TLS_EXPLICIT_IV_LEN, msg, dataLen);

        PRINT_BUFFER("Message Buffer", buf, sizeof(buf));

        aad[12] = sizeof(buf) - EVP_GCM_TLS_TAG_LEN;
        PRINT_MSG("Encrypt with wolfprovider - TLS");
        err = test_aes_tag_tls_enc(wcipher, key, iv, ivLen, aad, buf,
                                   sizeof(buf), ccm);
    }
    if (err == 0) {
        PRINT_MSG("Decrypt with OpenSSL - TLS");
        aad[12] = sizeof(buf);
        err = test_aes_tag_tls_dec(ocipher, key, iv, ivLen, aad, buf,
                                   sizeof(buf), ccm);
    }

    EVP_CIPHER_free(wcipher);
    EVP_CIPHER_free(ocipher);

    return err;
}

#endif /* WP_HAVE_AESGCM || WP_HAVE_AESCCM */

#ifdef WP_HAVE_AESGCM

int test_aes128_gcm(void *data)
{
    int err = 0;

    err = test_aes_tag(data, "AES-128-GCM", 16, 12, 0, 0);

    if (err == 0) {
        err = test_aes_gcm_gmac(data, "AES-128-GCM", 16, 12);
    }

    return err;
}

/******************************************************************************/

int test_aes192_gcm(void *data)
{
    int err = 0;

    err = test_aes_tag(data, "AES-192-GCM", 24, 12, 0, 0);

    if (err == 0) {
        err = test_aes_gcm_gmac(data, "AES-192-GCM", 24, 12);
    }

    return err;
}

/******************************************************************************/

int test_aes256_gcm(void *data)
{
    int err = 0;

    err = test_aes_tag(data, "AES-256-GCM", 32, 12, 0, 0);

    if (err == 0) {
        err = test_aes_gcm_gmac(data, "AES-256-GCM", 32, 12);
    }

    return err;
}

/******************************************************************************/

int test_aes128_gcm_fixed(void *data)
{
    return test_aes_tag_fixed(data, "AES-128-GCM", 16,
                              EVP_GCM_TLS_FIXED_IV_LEN, 12);
}

/******************************************************************************/

int test_aes128_gcm_tls(void *data)
{
    return test_aes_tag_tls(data, "AES-128-GCM", 16,
                            EVP_GCM_TLS_FIXED_IV_LEN, 0);
}

#endif /* WP_HAVE_AESGCM */

/******************************************************************************/

#ifdef WP_HAVE_AESCCM

int test_aes128_ccm(void *data)
{
    int err = 0;

    /* test with default length field (L) */
    err = test_aes_tag(data, "AES-128-CCM", 16, 13, 1, 0);

    return err;
}

/******************************************************************************/

int test_aes192_ccm(void *data)
{
    int err = 0;

    /* test with default length field (L) */
    err = test_aes_tag(data, "AES-192-CCM", 24, 13, 1, 0);

    return err;
}

/******************************************************************************/

int test_aes256_ccm(void *data)
{
    int err = 0;

    /* test with default length field (L) */
    err = test_aes_tag(data, "AES-256-CCM", 32, 13, 1, 0);

    return err;
}

/******************************************************************************/

/* Older versions don't support TLS ops with CCM. */
int test_aes128_ccm_tls(void *data)
{
    return test_aes_tag_tls(data, "AES-128-CCM", 16,
                            EVP_CCM_TLS_FIXED_IV_LEN, 1);
}

#endif /* WP_HAVE_AESCCM */

