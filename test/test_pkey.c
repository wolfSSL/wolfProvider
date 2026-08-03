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
#include <openssl/encoder.h>
#include <openssl/decoder.h>
#include <openssl/err.h>

int test_digest_sign(EVP_PKEY *pkey, OSSL_LIB_CTX* libCtx, unsigned char *data,
    size_t len, const char *md, const EVP_MD *mgf1Md, unsigned char *sig,
    size_t *sigLen, int padMode, int saltlen)
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
        err = EVP_PKEY_CTX_set_rsa_pss_saltlen(pkeyCtx, saltlen) <= 0;
    }
    if ((err == 0) && mgf1Md != NULL &&
            (padMode == RSA_PKCS1_PSS_PADDING ||
            padMode == RSA_PKCS1_OAEP_PADDING)) {
        err = EVP_PKEY_CTX_set_rsa_mgf1_md(pkeyCtx, mgf1Md) <= 0;
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
    unsigned char *data, size_t len, const char *md, const EVP_MD *mgf1Md,
    unsigned char *sig, size_t sigLen, int padMode, int saltlen)
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
        err = EVP_PKEY_CTX_set_rsa_pss_saltlen(pkeyCtx, saltlen) <= 0;
    }
    if ((err == 0) && mgf1Md != NULL &&
            (padMode == RSA_PKCS1_PSS_PADDING ||
            padMode == RSA_PKCS1_OAEP_PADDING)) {
        err = EVP_PKEY_CTX_set_rsa_mgf1_md(pkeyCtx, mgf1Md) <= 0;
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
    if ((err == 0) && rsaMgf1Md != NULL &&
            (padMode == RSA_PKCS1_PSS_PADDING ||
            padMode == RSA_PKCS1_OAEP_PADDING)) {
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
    if ((err == 0) && rsaMgf1Md != NULL &&
            (padMode == RSA_PKCS1_PSS_PADDING ||
            padMode == RSA_PKCS1_OAEP_PADDING)) {
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

/**
 * Check that a cipher set on a PrivateKeyInfo encoder actually encrypts.
 *
 * This is the path "openssl pkey -aes256" takes: the structure stays
 * PrivateKeyInfo and the cipher is set on the encoder.
 *
 * @param [in] pkey       Key to encode.
 * @param [in] fmt        "DER" or "PEM".
 * @param [in] encProp    Property query selecting the encoding provider.
 * @param [in] decLibCtx  Library context used to decode.
 * @param [in] cmpKey     Compare the decoded key with the original.
 * @return  0 on success, non-zero on failure.
 */
int test_pki_cipher_encrypts(EVP_PKEY* pkey, const char* fmt,
    const char* encProp, OSSL_LIB_CTX* decLibCtx, int cmpKey)
{
#ifndef WP_HAVE_PKCS8_ENC
    /* wolfSSL lacks the PKCS#8 encrypt helpers, so the encoder writes the
     * plaintext form and there is nothing to assert. */
    (void)pkey;
    (void)fmt;
    (void)encProp;
    (void)decLibCtx;
    (void)cmpKey;
    return 0;
#else
    int err = 0;
    EVP_PKEY* pkey2 = NULL;
    EVP_PKEY* badKey = NULL;
    OSSL_ENCODER_CTX* ectx = NULL;
    OSSL_DECODER_CTX* dctx = NULL;
    OSSL_DECODER_CTX* bctx = NULL;
    unsigned char* data = NULL;
    size_t dataLen = 0;
    size_t encLen = 0;
    const unsigned char* pp;
    const char* pass = "wolfprov-test-pass";
    const char* badPass = "wrong-passphrase";
    size_t passLen = XSTRLEN(pass);
    static const char epkiHdr[] = "-----BEGIN ENCRYPTED PRIVATE KEY-----";

    ectx = OSSL_ENCODER_CTX_new_for_pkey(pkey, EVP_PKEY_KEYPAIR, fmt,
        "PrivateKeyInfo", encProp);
    err = (ectx == NULL);
    if (err == 0) {
        err = OSSL_ENCODER_CTX_set_cipher(ectx, "AES-256-CBC", NULL) != 1;
    }
    if (err == 0) {
        err = OSSL_ENCODER_CTX_set_passphrase(ectx, (const unsigned char*)pass,
            passLen) != 1;
    }
    if (err == 0) {
        err = OSSL_ENCODER_to_data(ectx, &data, &dataLen) != 1;
    }
    if (err == 0) {
        encLen = dataLen;
    }
    /* PEM names the container outright. DER has no header, so the plaintext
     * form is ruled out by requiring the wrong passphrase to fail below. */
    if ((err == 0) && (XSTRCMP(fmt, "PEM") == 0)) {
        err = (dataLen < sizeof(epkiHdr) - 1) ||
              (XMEMCMP(data, epkiHdr, sizeof(epkiHdr) - 1) != 0);
        if (err) {
            PRINT_ERR_MSG("Cipher set but key was not encrypted");
        }
    }
    /* The encrypted key must still decode back to the same key. */
    if (err == 0) {
        pp = data;
        dctx = OSSL_DECODER_CTX_new_for_pkey(&pkey2, fmt, NULL,
            EVP_PKEY_get0_type_name(pkey), EVP_PKEY_KEYPAIR, decLibCtx, NULL);
        err = (dctx == NULL);
    }
    if (err == 0) {
        err = OSSL_DECODER_CTX_set_passphrase(dctx, (const unsigned char*)pass,
            passLen) != 1;
    }
    if (err == 0) {
        err = OSSL_DECODER_from_data(dctx, &pp, &dataLen) != 1;
    }
    if (err == 0) {
        err = (pkey2 == NULL);
    }
    if ((err == 0) && cmpKey) {
        err = EVP_PKEY_eq(pkey, pkey2) != 1;
        if (err) {
            PRINT_ERR_MSG("Decoded key does not match the original");
        }
    }
    /* A wrong passphrase must not recover a key. This is what rules out an
     * unencrypted DER body, which no passphrase would be needed to read. */
    if (err == 0) {
        pp = data;
        dataLen = encLen;
        bctx = OSSL_DECODER_CTX_new_for_pkey(&badKey, fmt, NULL,
            EVP_PKEY_get0_type_name(pkey), EVP_PKEY_KEYPAIR, decLibCtx, NULL);
        err = (bctx == NULL);
    }
    if (err == 0) {
        err = OSSL_DECODER_CTX_set_passphrase(bctx,
            (const unsigned char*)badPass, XSTRLEN(badPass)) != 1;
    }
    if (err == 0) {
        if ((OSSL_DECODER_from_data(bctx, &pp, &dataLen) == 1) &&
                (badKey != NULL)) {
            PRINT_ERR_MSG("Wrong passphrase recovered the key");
            err = 1;
        }
        ERR_clear_error();
    }

    OSSL_DECODER_CTX_free(bctx);
    OSSL_DECODER_CTX_free(dctx);
    OSSL_ENCODER_CTX_free(ectx);
    OPENSSL_free(data);
    EVP_PKEY_free(badKey);
    EVP_PKEY_free(pkey2);

    return err;
#endif /* WP_HAVE_PKCS8_ENC */
}

/* Encode as EncryptedPrivateKeyInfo with encProp, decode with decLibCtx and
 * check it matches; a wrong passphrase must fail. Drives both directions. */
int test_epki_encode_decode(EVP_PKEY* pkey, const char* fmt,
    const char* encProp, OSSL_LIB_CTX* decLibCtx)
{
    int err = 0;
    EVP_PKEY* pkey2 = NULL;
    EVP_PKEY* badKey = NULL;
    OSSL_ENCODER_CTX* ectx = NULL;
    OSSL_DECODER_CTX* dctx = NULL;
    OSSL_DECODER_CTX* bctx = NULL;
    unsigned char* data = NULL;
    size_t dataLen = 0;
    size_t encLen = 0;
    const unsigned char* pp;
    const char* pass = "wolfprov-test-pass";
    const char* badPass = "wrong-passphrase";
    size_t passLen = XSTRLEN(pass);

    /* Encode as EncryptedPrivateKeyInfo with the requested provider. */
    ectx = OSSL_ENCODER_CTX_new_for_pkey(pkey, EVP_PKEY_KEYPAIR, fmt,
        "EncryptedPrivateKeyInfo", encProp);
    err = (ectx == NULL);
    if (err == 0) {
        err = OSSL_ENCODER_CTX_set_cipher(ectx, "AES-256-CBC", NULL) != 1;
    }
    if (err == 0) {
        err = OSSL_ENCODER_CTX_set_passphrase(ectx, (const unsigned char*)pass,
            passLen) != 1;
    }
    if (err == 0) {
        err = OSSL_ENCODER_to_data(ectx, &data, &dataLen) != 1;
    }
    if (err == 0) {
        /* Save the encoded length; OSSL_DECODER_from_data consumes it. */
        encLen = dataLen;
    }

    /* Decode with the requested library context and the correct passphrase. */
    if (err == 0) {
        pp = data;
        dctx = OSSL_DECODER_CTX_new_for_pkey(&pkey2, fmt, NULL,
            EVP_PKEY_get0_type_name(pkey), EVP_PKEY_KEYPAIR, decLibCtx, NULL);
        err = (dctx == NULL);
    }
    if (err == 0) {
        err = OSSL_DECODER_CTX_set_passphrase(dctx, (const unsigned char*)pass,
            passLen) != 1;
    }
    if (err == 0) {
        err = OSSL_DECODER_from_data(dctx, &pp, &dataLen) != 1;
    }
    if (err == 0) {
        err = (pkey2 == NULL);
    }
    if (err == 0) {
        err = EVP_PKEY_eq(pkey, pkey2) != 1;
    }

    /* Negative case: a wrong passphrase must not yield a key. */
    if (err == 0) {
        pp = data;
        dataLen = encLen;
        bctx = OSSL_DECODER_CTX_new_for_pkey(&badKey, fmt, NULL,
            EVP_PKEY_get0_type_name(pkey), EVP_PKEY_KEYPAIR, decLibCtx, NULL);
        err = (bctx == NULL);
    }
    if (err == 0) {
        err = OSSL_DECODER_CTX_set_passphrase(bctx,
            (const unsigned char*)badPass, XSTRLEN(badPass)) != 1;
    }
    if (err == 0) {
        /* Decode is expected to fail; success with a recovered key is wrong. */
        if ((OSSL_DECODER_from_data(bctx, &pp, &dataLen) == 1) &&
                (badKey != NULL)) {
            err = 1;
        }
        /* The failed decrypt leaves an expected error on the queue. */
        ERR_clear_error();
    }

    OSSL_DECODER_CTX_free(bctx);
    OSSL_DECODER_CTX_free(dctx);
    OSSL_ENCODER_CTX_free(ectx);
    OPENSSL_free(data);
    EVP_PKEY_free(badKey);
    EVP_PKEY_free(pkey2);

    return err;
}
