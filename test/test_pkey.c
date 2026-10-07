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
#include <openssl/core_dispatch.h>
#include <openssl/params.h>
#include <openssl/bn.h>

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
    OSSL_ENCODER_CTX* badEctx = NULL;
    OSSL_ENCODER_CTX* stateEctx = NULL;
    OSSL_DECODER_CTX* dctx = NULL;
    OSSL_DECODER_CTX* bctx = NULL;
    unsigned char* data = NULL;
    unsigned char* stateData = NULL;
    size_t dataLen = 0;
    size_t encLen = 0;
    const unsigned char* pp;
    const char* pass = "wolfprov-test-pass";
    const char* badPass = "wrong-passphrase";
    size_t passLen = XSTRLEN(pass);
    static const char epkiHdr[] = "-----BEGIN ENCRYPTED PRIVATE KEY-----";
    static const char pkiHdr[] = "-----BEGIN PRIVATE KEY-----";

    ectx = OSSL_ENCODER_CTX_new_for_pkey(pkey, EVP_PKEY_KEYPAIR, fmt,
        "PrivateKeyInfo", encProp);
    err = (ectx == NULL);
    if (err == 0) {
        /* Unsupported ciphers must be rejected instead of falling back to
         * plaintext output. */
        badEctx = OSSL_ENCODER_CTX_new_for_pkey(pkey, EVP_PKEY_KEYPAIR, fmt,
            "PrivateKeyInfo", encProp);
        err = (badEctx == NULL) ||
            (OSSL_ENCODER_CTX_set_cipher(badEctx, "unsupported-cipher",
                NULL) == 1);
        if (err) {
            PRINT_ERR_MSG("Unsupported PKCS8 cipher was accepted");
        }
    }
    OSSL_ENCODER_CTX_free(badEctx);
    if ((err == 0) && (XSTRCMP(fmt, "PEM") == 0)) {
        int badType = 1;
        OSSL_PARAM badParams[] = {
            OSSL_PARAM_int(OSSL_ENCODER_PARAM_CIPHER, &badType),
            OSSL_PARAM_END
        };
        size_t stateLen = 0;

        stateEctx = OSSL_ENCODER_CTX_new_for_pkey(pkey, EVP_PKEY_KEYPAIR,
            fmt, "PrivateKeyInfo", encProp);
        err = (stateEctx == NULL) ||
            (OSSL_ENCODER_CTX_set_cipher(stateEctx, "AES-256-CBC", NULL) != 1) ||
            (OSSL_ENCODER_CTX_set_params(stateEctx, badParams) == 1);
        ERR_clear_error();
        if (err == 0) {
            err = (OSSL_ENCODER_to_data(stateEctx, &stateData, &stateLen) != 1) ||
                (stateLen < sizeof(pkiHdr) - 1) ||
                (XMEMCMP(stateData, pkiHdr, sizeof(pkiHdr) - 1) != 0);
            if (err) {
                PRINT_ERR_MSG("Rejected cipher parameter retained stale state");
            }
        }
    }
    OSSL_ENCODER_CTX_free(stateEctx);
    OPENSSL_free(stateData);
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
        if (OSSL_DECODER_from_data(bctx, &pp, &dataLen) == 1) {
            PRINT_ERR_MSG("Wrong passphrase was accepted");
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
        if (err) {
            PRINT_ERR_MSG("Failed to decode encrypted private key");
            ERR_print_errors_fp(stderr);
        }
    }
    if (err == 0) {
        err = (pkey2 == NULL);
        if (err) {
            PRINT_ERR_MSG("Encrypted private key decode returned no key");
        }
    }
    if (err == 0) {
        err = EVP_PKEY_eq(pkey, pkey2) != 1;
        if (err) {
            PRINT_ERR_MSG("Decoded encrypted private key does not match");
        }
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

/**
 * Find an implementation in a provider's operation table.
 *
 * @param [in] prov   Provider to query.
 * @param [in] opId   Operation identifier, e.g. OSSL_OP_ENCODER.
 * @param [in] name   Algorithm name to match, e.g. "RSA".
 * @param [in] props  Substring the properties must contain. May be NULL.
 * @return  Dispatch table of the implementation on success.
 * @return  NULL when no implementation matches.
 */
static const OSSL_DISPATCH* test_prov_find(OSSL_PROVIDER* prov, int opId,
    const char* name, const char* props)
{
    const OSSL_DISPATCH* impl = NULL;
    const OSSL_ALGORITHM* algs;
    const OSSL_ALGORITHM* alg;
    int noCache = 0;
    size_t nameLen = XSTRLEN(name);
    const char* p;

    algs = OSSL_PROVIDER_query_operation(prov, opId, &noCache);
    for (alg = algs; (impl == NULL) && (alg != NULL) &&
            (alg->algorithm_names != NULL); alg++) {
        if ((props != NULL) && ((alg->property_definition == NULL) ||
                (strstr(alg->property_definition, props) == NULL))) {
            continue;
        }
        /* Algorithm names are a colon separated list - match one whole name. */
        for (p = alg->algorithm_names; p != NULL; p = strchr(p, ':')) {
            if (p[0] == ':') {
                p++;
            }
            if ((strncmp(p, name, nameLen) == 0) &&
                    ((p[nameLen] == '\0') || (p[nameLen] == ':'))) {
                impl = alg->implementation;
                break;
            }
        }
    }
    if (algs != NULL) {
        OSSL_PROVIDER_unquery_operation(prov, opId, algs);
    }

    return impl;
}

/**
 * Get a function out of a dispatch table.
 *
 * @param [in] disp  Dispatch table to search.
 * @param [in] id    Function identifier to find.
 * @return  Function pointer on success.
 * @return  NULL when not in the table.
 */
static void (*test_disp_get(const OSSL_DISPATCH* disp, int id))(void)
{
    void (*fp)(void) = NULL;

    for (; (fp == NULL) && (disp != NULL) && (disp->function_id != 0); disp++) {
        if (disp->function_id == id) {
            fp = disp->function;
        }
    }

    return fp;
}

/** Parameters holding key material, which the imported key must give back. */
static const char* test_key_material[] = {
    OSSL_PKEY_PARAM_PUB_KEY,
    OSSL_PKEY_PARAM_PRIV_KEY,
    OSSL_PKEY_PARAM_RSA_N,
    OSSL_PKEY_PARAM_RSA_E,
    OSSL_PKEY_PARAM_RSA_D,
};
#define TEST_KEY_MATERIAL_CNT \
    (int)(sizeof(test_key_material) / sizeof(*test_key_material))

/** Comparison state passed to the key-management export callback. */
typedef struct {
    /** Parameters the key was imported from. */
    const OSSL_PARAM* expected;
    /** Bit per test_key_material entry that was exported and matched. */
    int matchedMaterial;
    /** Number of parameters that were compared and matched. */
    int matched;
    /** Set when an exported parameter differs from the imported one. */
    int err;
} TEST_EXPORT_CMP;

/**
 * Check an uncompressed and a compressed SEC1 encoding hold the same EC point.
 *
 * @param [in] full     Uncompressed encoding: 0x04 || X || Y.
 * @param [in] fullLen  Length of the uncompressed encoding in bytes.
 * @param [in] comp     Compressed encoding: 0x02 or 0x03 || X.
 * @param [in] compLen  Length of the compressed encoding in bytes.
 * @return  1 when both encode the same point, 0 otherwise.
 */
static int test_ec_point_same(const unsigned char* full, size_t fullLen,
    const unsigned char* comp, size_t compLen)
{
    int same = 0;
    size_t coordLen;

    if ((compLen >= 2) && (fullLen == (2 * compLen) - 1) &&
            (full[0] == 0x04) && ((comp[0] == 0x02) || (comp[0] == 0x03))) {
        coordLen = compLen - 1;
        /* The compressed prefix carries the low bit of Y. */
        same = (memcmp(full + 1, comp + 1, coordLen) == 0) &&
               ((full[fullLen - 1] & 1) == (comp[0] & 1));
    }

    return same;
}

/**
 * Compare one exported parameter with the value it was imported from.
 *
 * @param [in] got  Exported parameter.
 * @param [in] exp  Parameter the key was imported from.
 * @return  1 when the values match.
 * @return  0 when the values differ.
 * @return  -1 when the parameter type is not compared.
 */
static int test_param_cmp(const OSSL_PARAM* got, const OSSL_PARAM* exp)
{
    int same = -1;
    int64_t gotInt = 0;
    int64_t expInt = 0;
    BIGNUM* gotBn = NULL;
    BIGNUM* expBn = NULL;

    if (got->data_type == OSSL_PARAM_INTEGER) {
        same = (OSSL_PARAM_get_int64(got, &gotInt) == 1) &&
               (OSSL_PARAM_get_int64(exp, &expInt) == 1) &&
               (gotInt == expInt);
    }
    else if (got->data_type == OSSL_PARAM_UNSIGNED_INTEGER) {
        same = (OSSL_PARAM_get_BN(got, &gotBn) == 1) &&
               (OSSL_PARAM_get_BN(exp, &expBn) == 1) &&
               (BN_cmp(gotBn, expBn) == 0);
        BN_free(gotBn);
        BN_free(expBn);
    }
    else if ((got->data_type == OSSL_PARAM_OCTET_STRING) ||
             (got->data_type == OSSL_PARAM_UTF8_STRING)) {
        /* A zero size means the string is NUL terminated - not a match. */
        same = (got->data_size != 0) && (got->data_size == exp->data_size) &&
               (memcmp(got->data, exp->data, got->data_size) == 0);
        /* OpenSSL before 3.0.8 exports the EC public key compressed. */
        if ((!same) && (got->data_type == OSSL_PARAM_OCTET_STRING) &&
                (XSTRCMP(got->key, OSSL_PKEY_PARAM_PUB_KEY) == 0)) {
            same = test_ec_point_same((const unsigned char*)got->data,
                got->data_size, (const unsigned char*)exp->data,
                exp->data_size);
        }
    }

    return same;
}

/**
 * Key-management export callback - compare against the imported parameters.
 *
 * @param [in] params  Parameters exported from the imported key.
 * @param [in] arg     Comparison state.
 * @return  1 always - failures are recorded in the comparison state.
 */
static int test_export_cmp_cb(const OSSL_PARAM params[], void* arg)
{
    TEST_EXPORT_CMP* cmp = (TEST_EXPORT_CMP*)arg;
    const OSSL_PARAM* exp;
    int same;
    int i;
    int j;

    for (i = 0; (params != NULL) && (params[i].key != NULL); i++) {
        exp = OSSL_PARAM_locate_const(cmp->expected, params[i].key);
        if ((exp == NULL) || (exp->data_type != params[i].data_type)) {
            continue;
        }
        same = test_param_cmp(&params[i], exp);
        if (same == 0) {
            PRINT_ERR_MSG("Imported key parameter differs: %s", params[i].key);
            cmp->err = 1;
        }
        else if (same == 1) {
            cmp->matched++;
            for (j = 0; j < TEST_KEY_MATERIAL_CNT; j++) {
                if (XSTRCMP(params[i].key, test_key_material[j]) == 0) {
                    cmp->matchedMaterial |= 1 << j;
                }
            }
        }
    }

    return 1;
}

/**
 * Check that every key-material parameter in the source was matched.
 *
 * @param [in] params  Parameters the key was imported from.
 * @param [in] cmp     Comparison state after the export.
 * @return  0 when all key material came back, non-zero otherwise.
 */
static int test_key_material_missing(const OSSL_PARAM* params,
    const TEST_EXPORT_CMP* cmp)
{
    int err = 0;
    int j;

    for (j = 0; j < TEST_KEY_MATERIAL_CNT; j++) {
        if ((OSSL_PARAM_locate_const(params, test_key_material[j]) != NULL) &&
                ((cmp->matchedMaterial & (1 << j)) == 0)) {
            PRINT_ERR_MSG("Imported key lost parameter: %s",
                test_key_material[j]);
            err = 1;
        }
    }

    return err;
}

/**
 * Run an encoder's OSSL_FUNC_ENCODER_IMPORT_OBJECT on another provider's key.
 *
 * Hands import-object the selection and parameters OpenSSL's encoder passes
 * when the key's provider differs from the encoder's, then checks the result
 * against the selected parts of the key.
 *
 * @param [in] algName    Algorithm name of the encoder, e.g. "RSA".
 * @param [in] encProps   Substring of the encoder properties selecting the
 *                        structure and output, in the order the provider
 *                        registers them,
 *                        e.g. "output=pem,structure=SubjectPublicKeyInfo".
 * @param [in] pkey       Key held by another provider.
 * @param [in] selection  Parts of the key to encode.
 * @param [in] expectKey  1 when import must return a key holding the key
 *                        data, 0 when import must return NULL.
 * @return  0 on success, non-zero on failure.
 */
static int test_encoder_import_object_ex(const char* algName,
    const char* encProps, EVP_PKEY* pkey, int selection, int expectKey)
{
    int err = 0;
    const OSSL_DISPATCH* encDisp = NULL;
    const OSSL_DISPATCH* kmDisp = NULL;
    OSSL_FUNC_encoder_newctx_fn* newCtx = NULL;
    OSSL_FUNC_encoder_freectx_fn* freeCtx = NULL;
    OSSL_FUNC_encoder_import_object_fn* importObj = NULL;
    OSSL_FUNC_encoder_free_object_fn* freeObj = NULL;
    OSSL_FUNC_keymgmt_export_fn* kmExport = NULL;
    OSSL_PARAM* params = NULL;
    OSSL_PARAM* expected = NULL;
    void* encCtx = NULL;
    void* key = NULL;
    int keyOk = 0;
    int exportSel = selection;
    TEST_EXPORT_CMP cmp;

    XMEMSET(&cmp, 0, sizeof(cmp));

    PRINT_MSG("Encoder import-object %s: %s (%s)",
        expectKey ? "accepts" : "rejects", algName, encProps);

    /* OpenSSL exports a private key with its public key, but passes
     * import-object the caller's selection. */
    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0) {
        exportSel |= OSSL_KEYMGMT_SELECT_PUBLIC_KEY;
    }

    encDisp = test_prov_find(wpProv, OSSL_OP_ENCODER, algName, encProps);
    err = (encDisp == NULL);
    if (err) {
        PRINT_ERR_MSG("No %s encoder with properties %s", algName, encProps);
    }
    if (err == 0) {
        kmDisp = test_prov_find(wpProv, OSSL_OP_KEYMGMT, algName, NULL);
        err = (kmDisp == NULL);
        if (err) {
            PRINT_ERR_MSG("No %s key management", algName);
        }
    }
    if (err == 0) {
        newCtx = (OSSL_FUNC_encoder_newctx_fn*)test_disp_get(encDisp,
            OSSL_FUNC_ENCODER_NEWCTX);
        freeCtx = (OSSL_FUNC_encoder_freectx_fn*)test_disp_get(encDisp,
            OSSL_FUNC_ENCODER_FREECTX);
        importObj = (OSSL_FUNC_encoder_import_object_fn*)test_disp_get(encDisp,
            OSSL_FUNC_ENCODER_IMPORT_OBJECT);
        freeObj = (OSSL_FUNC_encoder_free_object_fn*)test_disp_get(encDisp,
            OSSL_FUNC_ENCODER_FREE_OBJECT);
        kmExport = (OSSL_FUNC_keymgmt_export_fn*)test_disp_get(kmDisp,
            OSSL_FUNC_KEYMGMT_EXPORT);
        err = (newCtx == NULL) || (freeCtx == NULL) || (importObj == NULL) ||
              (freeObj == NULL) || (kmExport == NULL);
        if (err) {
            PRINT_ERR_MSG("Encoder is missing a dispatch entry");
        }
    }
    /* The parameters OpenSSL hands to import-object come from the other
     * provider's key management export. */
    if (err == 0) {
        err = EVP_PKEY_todata(pkey, exportSel, &params) != 1;
        if (err) {
            PRINT_ERR_MSG("Failed to get key data");
        }
    }
    if ((err == 0) && expectKey) {
        expected = params;
        if (exportSel != selection) {
            err = EVP_PKEY_todata(pkey, selection, &expected) != 1;
            if (err) {
                PRINT_ERR_MSG("Failed to get selected key data");
            }
        }
    }
    if (err == 0) {
        encCtx = newCtx(OSSL_PROVIDER_get0_provider_ctx(wpProv));
        err = (encCtx == NULL);
        if (err) {
            PRINT_ERR_MSG("Failed to create encoder context");
        }
    }
    if (err == 0) {
        key = importObj(encCtx, selection, params);
        /* A key-management import returning 1/0 lands here as 1, and the
         * encoder context is not a key object either. */
        keyOk = (key != NULL) && (key != encCtx) && (key != (void*)1);
        if ((!expectKey) && (key != NULL)) {
            PRINT_ERR_MSG("Import object returned a key it cannot hold");
            err = 1;
        }
        else if (expectKey && (!keyOk)) {
            PRINT_ERR_MSG("Import object did not return a key object");
            err = 1;
        }
    }
    if ((err == 0) && expectKey) {
        cmp.expected = expected;
        err = kmExport(key, selection, test_export_cmp_cb, &cmp) != 1;
        if (err) {
            PRINT_ERR_MSG("Failed to export the imported key");
        }
    }
    if ((err == 0) && expectKey) {
        err = cmp.err || (cmp.matched == 0) ||
              test_key_material_missing(expected, &cmp);
        if (err) {
            PRINT_ERR_MSG("Imported key does not hold the key data");
        }
    }

    if (keyOk) {
        freeObj(key);
    }
    if (encCtx != NULL) {
        freeCtx(encCtx);
    }
    if (expected != params) {
        OSSL_PARAM_free(expected);
    }
    OSSL_PARAM_free(params);
    if (err) {
        ERR_print_errors_fp(stderr);
    }
    else {
        ERR_clear_error();
    }

    return err;
}

/** Encoder properties for the public key structure. */
#define TEST_ENC_SPKI   "output=der,structure=SubjectPublicKeyInfo"
/** Encoder properties for the private key structure. */
#define TEST_ENC_PKI    "output=der,structure=PrivateKeyInfo"

/**
 * Check an algorithm's encoders build a key from another provider's key pair,
 * for both the public and the private key structure.
 *
 * @param [in] algName  Algorithm name of the encoders, e.g. "RSA".
 * @param [in] pkey     Key pair held by another provider.
 * @return  0 on success, non-zero on failure.
 */
int test_encoder_import_object(const char* algName, EVP_PKEY* pkey)
{
    int err;

    err = test_encoder_import_object_ex(algName, TEST_ENC_SPKI, pkey,
        EVP_PKEY_PUBLIC_KEY, 1);
    if (err == 0) {
        err = test_encoder_import_object_ex(algName, TEST_ENC_PKI, pkey,
            EVP_PKEY_KEYPAIR, 1);
    }

    return err;
}

/**
 * Check an algorithm's public key encoder returns NULL from import-object for
 * a key it cannot hold.
 *
 * @param [in] algName  Algorithm name of the encoder, e.g. "RSA".
 * @param [in] pkey     Key held by another provider; may be public only.
 * @return  0 on success, non-zero on failure.
 */
int test_encoder_import_object_rejected(const char* algName, EVP_PKEY* pkey)
{
    return test_encoder_import_object_ex(algName, TEST_ENC_SPKI, pkey,
        EVP_PKEY_PUBLIC_KEY, 0);
}

/**
 * Generate a key with the given key generation parameters.
 *
 * @param [in]  libCtx  Library context to generate in.
 * @param [in]  name    Key type, e.g. "RSA-PSS".
 * @param [in]  params  Key generation parameters.
 * @param [out] pkey    Generated key.
 * @return  0 on success, non-zero on failure.
 */
int test_pkey_keygen_params(OSSL_LIB_CTX* libCtx, const char* name,
    const OSSL_PARAM params[], EVP_PKEY** pkey)
{
    int err;
    EVP_PKEY_CTX* ctx = NULL;

    err = (ctx = EVP_PKEY_CTX_new_from_name(libCtx, name, NULL)) == NULL;
    if (err == 0) {
        err = EVP_PKEY_keygen_init(ctx) != 1;
    }
    if (err == 0) {
        err = EVP_PKEY_CTX_set_params(ctx, params) != 1;
    }
    if (err == 0) {
        err = EVP_PKEY_generate(ctx, pkey) != 1;
    }
    if (err) {
        PRINT_ERR_MSG("Failed to generate %s key", name);
    }

    EVP_PKEY_CTX_free(ctx);
    return err;
}
