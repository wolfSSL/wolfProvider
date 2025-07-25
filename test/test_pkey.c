/* test_pkey.c
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

int test_digest_sign(EVP_PKEY *pkey, OSSL_LIB_CTX* libCtx, unsigned char *data,
    size_t len, const char *md, unsigned char *sig, size_t *sigLen,
    int padMode)
{
    int err;
    EVP_MD_CTX *mdCtx = NULL;
    EVP_PKEY_CTX *pkeyCtx = NULL;

    err = (mdCtx = EVP_MD_CTX_new()) == NULL;
    if (err == 0) {
        err = EVP_DigestSignInit_ex(mdCtx, &pkeyCtx, md, libCtx, NULL, pkey,
            NULL) != 1;
    }
    if ((err == 0) && padMode) {
        err = EVP_PKEY_CTX_set_rsa_padding(pkeyCtx, padMode) <= 0;
    }
    if ((err == 0) && padMode == RSA_PKCS1_PSS_PADDING) {
        err = EVP_PKEY_CTX_set_rsa_pss_saltlen(pkeyCtx, -1) <= 0;
    }
    if (err == 0) {
        err = EVP_DigestSign(mdCtx, sig, sigLen, data, len) != 1;
    }
    if (err == 0) {
        PRINT_BUFFER("Signature", sig, *sigLen);
    }

    EVP_MD_CTX_free(mdCtx);

    return err;
}

int test_digest_verify(EVP_PKEY *pkey, OSSL_LIB_CTX* libCtx,
    unsigned char *data, size_t len, const char *md, unsigned char *sig,
    size_t sigLen, int padMode)
{
    int err;
    EVP_MD_CTX *mdCtx = NULL;
    EVP_PKEY_CTX *pkeyCtx = NULL;

    err = (mdCtx = EVP_MD_CTX_new()) == NULL;
    if (err == 0) {
        err = EVP_DigestVerifyInit_ex(mdCtx, &pkeyCtx, md, libCtx, NULL, pkey,
            NULL) != 1;
    }
    if ((err == 0) && padMode) {
        err = EVP_PKEY_CTX_set_rsa_padding(pkeyCtx, padMode) <= 0;
    }
    if ((err == 0) && padMode == RSA_PKCS1_PSS_PADDING) {
        err = EVP_PKEY_CTX_set_rsa_pss_saltlen(pkeyCtx, -1) < 0;
    }
    if (err == 0) {
        err = EVP_DigestVerify(mdCtx, sig, sigLen, data, len) != 1;
    }
    if (err == 0) {
        PRINT_MSG("Signature verified");
    }
    else {
        PRINT_MSG("Signature not verified");
    }

    EVP_MD_CTX_free(mdCtx);

    return err;
}

int test_pkey_sign(EVP_PKEY *pkey, OSSL_LIB_CTX* libCtx, unsigned char *hash,
    size_t hashLen, unsigned char *sig, size_t *sigLen, int padMode,
    const EVP_MD *rsaMd, const EVP_MD *rsaMgf1Md)
{
    int err;
    EVP_PKEY_CTX *ctx = NULL;

    err = (ctx = EVP_PKEY_CTX_new_from_pkey(libCtx, pkey, NULL)) == NULL;
    if (err == 0) {
        err = EVP_PKEY_sign_init(ctx) != 1;
    }
    /* Signature MD MUST be set before padding for ossl x931 */
    if ((err == 0) && (padMode == RSA_PKCS1_PSS_PADDING ||
            padMode == RSA_X931_PADDING) && rsaMd != NULL) {
        err = EVP_PKEY_CTX_set_signature_md(ctx, rsaMd) <= 0;
    }
    if ((err == 0) && padMode) {
        err = EVP_PKEY_CTX_set_rsa_padding(ctx, padMode) <= 0;
    }
    if ((err == 0) && padMode == RSA_PKCS1_PSS_PADDING) {
        err = EVP_PKEY_CTX_set_rsa_pss_saltlen(ctx, -1) < 0;
    }
    if ((err == 0) && padMode == RSA_PKCS1_PSS_PADDING && rsaMgf1Md != NULL) {
        err = EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, rsaMgf1Md) <= 0;
    }
    if (err == 0) {
        err = EVP_PKEY_sign(ctx, sig, sigLen, hash, hashLen) != 1;
    }
    if (err == 0) {
        PRINT_BUFFER("Signature", sig, *sigLen);
    }

    EVP_PKEY_CTX_free(ctx);

    return err;
}

int test_pkey_verify(EVP_PKEY *pkey, OSSL_LIB_CTX* libCtx, unsigned char *hash,
    size_t hashLen, unsigned char *sig, size_t sigLen, int padMode,
    const EVP_MD *rsaMd, const EVP_MD *rsaMgf1Md)
{
    int err;
    EVP_PKEY_CTX *ctx = NULL;

    err = (ctx = EVP_PKEY_CTX_new_from_pkey(libCtx, pkey, NULL)) == NULL;
    if (err == 0) {
        err = EVP_PKEY_verify_init(ctx) != 1;
    }
    /* Signature MD MUST be set before padding for ossl x931 */
    if ((err == 0) && (padMode == RSA_PKCS1_PSS_PADDING ||
        padMode == RSA_X931_PADDING) && rsaMd != NULL) {
        err = EVP_PKEY_CTX_set_signature_md(ctx, rsaMd) <= 0;
    }
    if ((err == 0) && padMode) {
        err = EVP_PKEY_CTX_set_rsa_padding(ctx, padMode) <= 0;
    }
    if ((err == 0) && padMode == RSA_PKCS1_PSS_PADDING) {
        err = EVP_PKEY_CTX_set_rsa_pss_saltlen(ctx, -1) < 0;
    }
    if ((err == 0) && padMode == RSA_PKCS1_PSS_PADDING && rsaMgf1Md != NULL) {
        err = EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, rsaMgf1Md) <= 0;
    }
    if (err == 0) {
        err = EVP_PKEY_verify(ctx, sig, sigLen, hash, hashLen) != 1;
    }
    if (err == 0) {
        PRINT_MSG("Signature verified");
    }
    else {
        PRINT_MSG("Signature not verified");
    }

    EVP_PKEY_CTX_free(ctx);

    return err;
}

int test_pkey_verify_recover(EVP_PKEY *pkey, OSSL_LIB_CTX* libCtx, unsigned char *hash,
    size_t hashLen, unsigned char *sig, size_t sigLen, int padMode)
{
    int err;
    EVP_PKEY_CTX *ctx = NULL;
    unsigned char rout[512];
    size_t routLen = 512;

    err = (ctx = EVP_PKEY_CTX_new_from_pkey(libCtx, pkey, NULL)) == NULL;
    if (err == 0) {
        err = EVP_PKEY_verify_recover_init(ctx) != 1;
    }
    if ((err == 0) && padMode) {
        err = EVP_PKEY_CTX_set_rsa_padding(ctx, padMode) <= 0;
    }
    if (err == 0) {
        err = EVP_PKEY_verify_recover(ctx, rout, &routLen, sig, sigLen) != 1;
    }
    if (err == 0) {
        if ((routLen != hashLen) ||
            (memcmp(rout, hash, hashLen) != 0)) {
                err = 1;
        }
    }
    if (err == 0) {
        PRINT_MSG("Signature verified");
    }
    else {
        PRINT_MSG("Signature not verified");
    }

    EVP_PKEY_CTX_free(ctx);

    return err;
}

int test_pkey_enc(EVP_PKEY *pkey, OSSL_LIB_CTX* libCtx, unsigned char *msg,
    size_t msgLen, unsigned char *ciphertext, size_t cipherLen, int padMode,
    const EVP_MD *rsaMd, const EVP_MD *rsaMgf1Md)
{
    int err;
    EVP_PKEY_CTX *ctx = NULL;
    size_t len;

    err = (ctx = EVP_PKEY_CTX_new_from_pkey(libCtx, pkey, NULL)) == NULL;
    if (err == 0) {
        err = EVP_PKEY_encrypt_init(ctx) != 1;
    }
    if ((err == 0) && padMode) {
        err = EVP_PKEY_CTX_set_rsa_padding(ctx, padMode) <= 0;
    }
    if ((err == 0) && padMode == RSA_PKCS1_OAEP_PADDING && rsaMd != NULL) {
        err = EVP_PKEY_CTX_set_rsa_oaep_md(ctx, rsaMd) <= 0;
    }
    if ((err == 0) && padMode == RSA_PKCS1_OAEP_PADDING && rsaMgf1Md != NULL) {
        err = EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, rsaMgf1Md) <= 0;
    }
    if (err == 0) {
        err = EVP_PKEY_encrypt(ctx, NULL, &len, msg, msgLen) != 1;
    }
    if (err == 0) {
        err = (len != cipherLen);
    }
    if (err == 0) {
        err = EVP_PKEY_encrypt(ctx, ciphertext, &cipherLen, msg, msgLen) != 1;
    }

    EVP_PKEY_CTX_free(ctx);

    return err;
}

int test_pkey_dec(EVP_PKEY *pkey, OSSL_LIB_CTX* libCtx, unsigned char *msg,
    size_t msgLen, unsigned char *ciphertext, size_t cipherLen, int padMode,
    const EVP_MD *rsaMd, const EVP_MD *rsaMgf1Md)
{
    int err = 0;
    EVP_PKEY_CTX *ctx = NULL;
    size_t len = cipherLen;
    unsigned char *buf;

    buf = (unsigned char*)OPENSSL_zalloc(cipherLen);
    if (buf == NULL) {
        err = 1;
    }

    if (err == 0) {
        err = (ctx = EVP_PKEY_CTX_new_from_pkey(libCtx, pkey, NULL)) == NULL;
    }
    if (err == 0) {
        err = EVP_PKEY_decrypt_init(ctx) != 1;
    }
    if ((err == 0) && padMode) {
        err = EVP_PKEY_CTX_set_rsa_padding(ctx, padMode) <= 0;
    }
    if ((err == 0) && padMode == RSA_PKCS1_OAEP_PADDING && rsaMd != NULL) {
        err = EVP_PKEY_CTX_set_rsa_oaep_md(ctx, rsaMd) <= 0;
    }
    if ((err == 0) && padMode == RSA_PKCS1_OAEP_PADDING && rsaMgf1Md != NULL) {
        err = EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, rsaMgf1Md) <= 0;
    }
    if (err == 0) {
        err = EVP_PKEY_decrypt(ctx, buf, &len, ciphertext, cipherLen) != 1;
    }
    if (err == 0) {
        err = (len != msgLen);
    }
    if (err == 0) {
        err = memcmp(buf, msg, len) != 0;
    }

    EVP_PKEY_CTX_free(ctx);
    if (buf != NULL) {
        OPENSSL_free(buf);
    }

    return err;
}

